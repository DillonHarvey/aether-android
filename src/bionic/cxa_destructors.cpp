#include "cxa_destructors.hpp"
#include "threads.hpp"
#include "aether/common/thread_exit.hpp"
#include <new>
#include <optional>
#include <utility>

namespace aether::bionic {
namespace {
using a64::Fault;
constexpr std::size_t pending_limit=4096;
constexpr std::uint64_t tick_limit=1'000'000,attempt_limit=4096;
constexpr std::uint64_t scan_limit=pending_limit*attempt_limit;
}

void NativeCxaDestructors::runner(GuestPosixServices::CxaRunner value){runner_=std::move(value);}

Fault NativeCxaDestructors::reject(std::string_view reason,Fault fault) noexcept {
    if(campaign_fault_==Fault::none){campaign_fault_=fault;campaign_reason_=reason;}
    rejection_=campaign_reason_;
    return campaign_fault_;
}

Fault NativeCxaDestructors::guard() noexcept {
    if(std::this_thread::get_id()!=owner_)return reject("__cxa: callback registry belongs to another host owner");
    if(!app_.process_state)return reject("__cxa: process state is unavailable");
    if(app_.process_state->exit_status()){
        reject("__cxa: process has terminated",Fault::process_exit);
        return Fault::process_exit;
    }
    if(!threads_.tid() || !threads_.tls())return reject("__cxa: current logical thread is unavailable");
    if(threads_.exit_value(threads_.tls())){
        reject("__cxa: logical thread has terminated",Fault::thread_exit);
        return Fault::thread_exit;
    }
    return Fault::none;
}

Fault NativeCxaDestructors::register_callback(std::array<std::uint64_t,31> &registers) noexcept {
    if(!depth_){campaign_fault_=Fault::none;campaign_reason_={};rejection_={};}
    const auto checked=guard();if(checked!=Fault::none)return checked;
    if(!registers[0] || records_.size()==pending_limit){registers[0]=UINT64_MAX;return Fault::none;}
    try{
        // No callback admission or argument/DSO dereference at registration.
        // POD vector growth has a strong guarantee: failure publishes no entry.
        records_.push_back({registers[0],registers[1],registers[2]});
        registers[0]=0;return Fault::none;
    }catch(const std::bad_alloc &){registers[0]=UINT64_MAX;return Fault::none;}
    catch(...){return reject("__cxa_atexit: trusted registration failed",Fault::windows_service);}
}

Fault NativeCxaDestructors::finalize(a64::ServiceState &state,bool full_frame) noexcept {
    if(!depth_){charged_=0;attempts_=0;scans_=0;campaign_fault_=Fault::none;campaign_reason_={};rejection_={};}
    std::uint32_t owner=0;a64::Address tls=0;
    const auto exception_terminal=[&](){
        // A trusted runner may commit a terminal cause before throwing. Keep
        // process termination canonical, and never mark a replacement TLS.
        if(app_.process_state && app_.process_state->exit_status()){
            reject("__cxa_finalize: callback terminated the process",Fault::process_exit);return Fault::process_exit;
        }
        if(!owner || !tls || threads_.tid()!=owner || threads_.tls()!=tls)
            return reject("__cxa_finalize: callback did not restore its logical thread binding");
        if(threads_.exit_value(tls)){
            reject("__cxa_finalize: callback terminated its logical thread",Fault::thread_exit);return Fault::thread_exit;
        }
        return Fault::none;
    };
    try{
        const auto checked=guard();if(checked!=Fault::none)return checked;
        owner=threads_.tid();tls=threads_.tls();
        if(campaign_fault_!=Fault::none){rejection_=campaign_reason_;return campaign_fault_;}
        const auto selector=state.registers[0],stack=state.stack_pointer;
        const auto selected=[&]() -> std::optional<std::size_t> {
            for(auto index=records_.size();index;--index){
                if(scans_==scan_limit){reject("__cxa_finalize: callback campaign scan limit exhausted",Fault::budget);return {};}
                ++scans_;
                if(!selector || records_[index-1].dso==selector)return index;
            }
            return 0;
        };
        const auto first=selected();if(!first)return campaign_fault_;
        if(!*first)return Fault::none;
        if(!full_frame)return reject("__cxa_finalize: callbacks require a trusted full guest frame");
        if(!runner_)return reject("__cxa_finalize: owned callback runner is unavailable");
        const auto writable_stack=[&](){return stack>=16 && stack%16==0 && state.stack_top &&
            stack<=state.stack_top && memory_.accessible(stack-16,16,a64::Permission::write);};
        if(!writable_stack())return reject("__cxa_finalize: active guest stack lacks aligned writable callback space",Fault::write);
        if(depth_==16)return reject("__cxa_finalize: callback nesting exceeds 16",Fault::nesting_limit);
        // Reentry may replace the configured runner or grow/erase the registry.
        // Never retain references or iterators into either across a callback.
        const auto run=runner_;
        ++depth_;
        struct Scope {unsigned &depth;~Scope(){--depth;}} scope{depth_};
        for(;;){
            const auto current=guard();if(current!=Fault::none)return current;
            if(threads_.tid()!=owner || threads_.tls()!=tls)return reject("__cxa_finalize: callback changed its logical thread binding");
            if(campaign_fault_!=Fault::none){rejection_=campaign_reason_;return campaign_fault_;}
            const auto selected_index=selected();if(!selected_index)return campaign_fault_;
            const auto index=*selected_index;if(!index)return Fault::none;
            if(charged_==tick_limit || attempts_==attempt_limit)return reject("__cxa_finalize: callback campaign budget exhausted",Fault::budget);
            if(!writable_stack())return reject("__cxa_finalize: callback stack is no longer writable",Fault::write);
            const auto entry=records_[index-1];
            records_.erase(records_.begin()+static_cast<std::ptrdiff_t>(index-1));
            ++attempts_;
            // Consumption precedes admission/execution, including bad code.
            if(entry.function%4 || !memory_.accessible(entry.function,4,a64::Permission::execute))
                return reject("__cxa_finalize: callback is not aligned executable guest code",Fault::execute);
            const auto charged_before=charged_,available=tick_limit-charged_;
            const auto execution=run(entry.function,entry.argument,stack,tls,available);
            if(execution.result.fault==Fault::process_exit)app_.process_state->request_exit(execution.result.detail);
            if(app_.process_state->exit_status()){reject("__cxa_finalize: callback terminated the process",Fault::process_exit);return Fault::process_exit;}
            if(threads_.tid()!=owner || threads_.tls()!=tls)return reject("__cxa_finalize: callback did not restore its logical thread binding");
            if(execution.result.fault==Fault::thread_exit)threads_.request_exit(execution.result.registers[0]);
            if(threads_.exit_value(tls)){reject("__cxa_finalize: callback terminated its logical thread",Fault::thread_exit);return Fault::thread_exit;}
            // Runner ticks include nested callbacks. Nested finalize has already
            // charged those ticks to this campaign; debit only the remainder.
            const auto nested=charged_-charged_before;
            if(execution.ticks<nested)return reject("__cxa_finalize: callback returned inconsistent inclusive ticks",Fault::invalid_call);
            const auto uncharged=execution.ticks-nested;
            if(uncharged>tick_limit-charged_){charged_=tick_limit;return reject("__cxa_finalize: callback exceeded its campaign budget",Fault::budget);}
            charged_+=uncharged;
            if(campaign_fault_!=Fault::none){rejection_=campaign_reason_;return campaign_fault_;}
            if(execution.result.fault!=Fault::none)return reject("__cxa_finalize: callback execution failed",execution.result.fault);
            if(!execution.result.returned)return reject("__cxa_finalize: callback did not return",Fault::invalid_call);
            // Rescan the live registry newest-first: recursive drains and new
            // registrations are visible, and extracted entries never replay.
        }
    }catch(const ThreadExit &exit){
        const auto terminal=exception_terminal();if(terminal!=Fault::none)return terminal;
        threads_.request_exit(exit.value);reject("__cxa_finalize: callback exited its logical thread",Fault::thread_exit);return Fault::thread_exit;
    }catch(const ProcessExit &exit){
        if(app_.process_state){if(exit.signal)app_.process_state->request_signal(exit.signal);else app_.process_state->request_exit(exit.status);}
        reject("__cxa_finalize: callback exited the process",Fault::process_exit);return Fault::process_exit;
    }catch(...){
        const auto terminal=exception_terminal();if(terminal!=Fault::none)return terminal;
        return reject("__cxa_finalize: trusted callback operation failed",Fault::windows_service);
    }
}
}
