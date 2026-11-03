#include "polling.hpp"
#include "descriptors.hpp"
#include "threads.hpp"
#include "signals.hpp"
#include "aether/common/thread_exit.hpp"
#include <algorithm>
#include <chrono>
#include <thread>
#include <utility>
namespace aether::bionic {
namespace {
template<std::size_t N> std::array<std::uint8_t,N> bytes(std::uint64_t value){std::array<std::uint8_t,N> result{};for(unsigned i=0;i<N;++i)result[i]=static_cast<std::uint8_t>(value>>(8*i));return result;}
std::uint64_t word(std::span<const std::uint8_t> input){std::uint64_t result=0;for(unsigned i=0;i<input.size();++i)result|=std::uint64_t{input[i]}<<(8*i);return result;}
}
struct NativePolling::DeferredPoll final : a64::DeferredService {
    using Clock=std::chrono::steady_clock;using Fault=a64::Fault;
    NativePolling &p;std::shared_ptr<ProcessState> process;
    std::shared_ptr<a64::ThreadRegisterState> owner;
    a64::Address error,address,tls,stack_top;std::uint32_t tid,count;
    std::uint64_t invocation;std::int32_t timeout;Clock::time_point until;
    std::array<Watch,256> watches;
    DeferredPoll(NativePolling &p,a64::Address error,a64::Address address,std::uint32_t count,std::int32_t timeout,
                 Clock::time_point until,const std::array<Watch,256> &watches,const a64::ServiceState &frame,
                 std::shared_ptr<ProcessState> process):
        p(p),process(std::move(process)),owner(p.threads_.thread_register_state(frame.trusted_tls)),
        error(error),address(address),tls(frame.trusted_tls),stack_top(frame.stack_top),tid(p.threads_.tid()),count(count),
        invocation(frame.invocation),timeout(timeout),until(until),watches(watches) {}
    std::uint16_t events(const Watch &watch) const noexcept {
        if(watch.fd<0)return 0;
        const auto original=watch.description.lock();
        const auto current=p.files_.descriptor_identity(watch.fd);
        if(!watch.originally_valid || !original || original!=current)return 0x20;
        return p.files_.readiness(watch.fd,watch.events);
    }
    bool outputs_valid() const noexcept {
        for(std::size_t i=0;i<count;++i)
            if(!p.memory_.accessible(address+i*8+6,2,a64::Permission::write))return false;
        return true;
    }
    bool ready() const noexcept override {
        if(process->exit_status() || !p.threads_.signal_snapshot(tid,owner) || !outputs_valid())return true;
        if(timeout==0 || (timeout>0 && Clock::now()>=until) || p.signals_.wait_ready(tid,owner))return true;
        for(std::size_t i=0;i<count;++i)if(events(watches[i]))return true;
        return false;
    }
    std::optional<Clock::time_point> deadline() const noexcept override {
        if(!p.threads_.signal_snapshot(tid,owner))return {};
        auto next=timeout>=0?std::optional<Clock::time_point>{until}:std::nullopt;
        const auto alarm=p.signals_.wait_deadline(tid,owner);
        if(alarm && (!next || *alarm<*next))next=alarm;
        return next;
    }
    Fault errno_result(a64::ServiceState &frame,unsigned code) const noexcept {
        if(!p.memory_.write(error,bytes<4>(code)))return Fault::write;
        frame.registers[0]=UINT64_MAX;return Fault::none;
    }
    a64::DeferredServiceResult resume(a64::ServiceState &frame) noexcept override {
        try {
            if(process->exit_status())return {Fault::process_exit,true};
            if(p.threads_.exit_value(tls))return {Fault::thread_exit,true};
            if(!owner || p.threads_.tid()!=tid || p.threads_.tls()!=tls || frame.trusted_tls!=tls ||
               frame.invocation!=invocation || frame.stack_top!=stack_top ||
               p.threads_.thread_register_state(tls)!=owner)return {Fault::invalid_call,true};
            if(!outputs_valid())return {errno_result(frame,14),true};
            unsigned available=0;
            for(std::size_t i=0;i<count;++i){watches[i].revents=events(watches[i]);if(watches[i].revents)++available;}
            if(available || timeout==0 || (timeout>0 && Clock::now()>=until)) {
                // Every destination was checked before any result is published;
                // no guest callback or scheduling occurs in this commit.
                for(std::size_t i=0;i<count;++i)
                    if(!p.memory_.write(address+i*8+6,bytes<2>(watches[i].revents)))return {errno_result(frame,14),true};
                frame.registers[0]=available;return {Fault::none,true};
            }
            if(p.signals_.wait_ready(tid,owner)) {
                const auto serial=p.signals_.delivery_serial();
                const auto signal=p.signals_.io_interruption();
                const bool framed=signal && p.signals_.io_frame_ready(*signal,frame);
                if(framed){const auto fault=errno_result(frame,4);if(fault!=Fault::none)return {fault,true};}
                const auto fault=(signal?p.signals_.deliver_pending(frame,true,std::uint64_t{1}<<(signal->signal-1)):Fault::none);
                if(fault!=Fault::none)return {fault,true};
                if(frame.resume)return {Fault::none,true}; // No write after an authenticated transfer.
                if(p.signals_.delivery_serial()!=serial)
                    return {framed?Fault::none:errno_result(frame,4),true};
            }
            return {Fault::none,false};
        } catch(const ProcessExit &exit) {
            if(exit.signal)process->request_signal(exit.signal);else process->request_exit(exit.status);
            return {Fault::process_exit,true};
        } catch(const ThreadExit &exit){p.threads_.request_exit(exit.value);return {Fault::thread_exit,true};}
        catch(...){return {Fault::unsupported_service,true};}
    }
};
a64::Fault NativePolling::invoke(a64::Address error,std::array<std::uint64_t,31> &r,bool full_frame,a64::ServiceState *frame,
                                bool allow_deferred,std::shared_ptr<ProcessState> process) {
    using a64::Fault;using Clock=std::chrono::steady_clock;
    const auto fail=[&](unsigned code){if(!memory_.write(error,bytes<4>(code)))return Fault::write;r[0]=UINT64_MAX;return Fault::none;};
    const auto address=r[0];const auto count=static_cast<std::uint32_t>(r[1]);const auto timeout=static_cast<std::int32_t>(r[2]);
    if(count>256)return fail(22);
    std::array<Watch,256> watches{};
    for(std::size_t i=0;i<count;++i){
        std::array<std::uint8_t,8> input{};
        if(address>=a64::GuestMemory::address_limit || i*8>=a64::GuestMemory::address_limit-address ||
           !memory_.read(address+i*8,input) || !memory_.accessible(address+i*8+6,2,a64::Permission::write))return fail(14);
        watches[i].fd=static_cast<std::int32_t>(word(std::span{input}.first<4>()));
        watches[i].events=static_cast<std::uint16_t>(word(std::span{input}.subspan<4,2>()));
    }
    const auto deadline=Clock::now()+std::chrono::milliseconds(timeout>0?timeout:0);
    if(threads_.factory_execution_active() && allow_deferred) {
        if(!process || !full_frame || !frame || &frame->registers!=&r || !frame->invocation ||
           frame->trusted_tls!=threads_.tls() ||
           !threads_.signal_snapshot(threads_.tid(),threads_.thread_register_state(frame->trusted_tls)))return Fault::invalid_call;
        for(std::size_t i=0;i<count;++i)if(watches[i].fd>=0) {
            const auto identity=files_.descriptor_identity(watches[i].fd);
            watches[i].originally_valid=bool(identity);watches[i].description=identity;
        }
        // All allocation and input copying precede the first wait/result effect.
        frame->deferred=std::make_shared<DeferredPoll>(*this,error,address,count,timeout,deadline,watches,*frame,std::move(process));
        return Fault::none;
    }
    std::uint64_t budget=1000000;
    for(;;){
        unsigned ready=0;
        for(std::size_t i=0;i<count;++i){auto &watch=watches[i];watch.revents=files_.readiness(watch.fd,watch.events);if(watch.revents)++ready;}
        if(ready || timeout==0 || (timeout>0 && Clock::now()>=deadline)){
            // Nested work can free the original table. Validate all outputs before publishing any.
            for(std::size_t i=0;i<count;++i)if(!memory_.accessible(address+i*8+6,2,a64::Permission::write))return fail(14);
            for(std::size_t i=0;i<count;++i)if(!memory_.write(address+i*8+6,bytes<2>(watches[i].revents)))return fail(14);
            r[0]=ready;return Fault::none;
        }
        if(!full_frame || threads_.factory_execution_active())return fail(95);
        if(signals_.ready()){
            a64::ServiceState empty;const auto deliveries=signals_.delivery_serial();
            const auto signal=signals_.io_interruption();
            const bool framed=frame && signal && signals_.io_frame_ready(*signal,*frame);
            // The saved user context observes the completed EINTR result.
            if(framed){const auto fault=fail(4);if(fault!=Fault::none)return fault;}
            const auto fault=(signal?signals_.deliver_pending(frame?*frame:empty,frame!=nullptr,std::uint64_t{1}<<(signal->signal-1)):Fault::none);
            if(fault!=Fault::none)return fault;
            if(frame && frame->resume)return Fault::none;
            if(signals_.delivery_serial()!=deliveries)return framed?Fault::none:fail(4);
        }
        if(threads_.has_runnable()){
            if(!budget)return Fault::budget;
            std::uint64_t spent=0;const auto fault=threads_.run_next(budget,spent);budget=spent>=budget?0:budget-spent;
            if(fault!=Fault::none)return fault;
            continue;
        }
        const auto alarm=signals_.alarm_deadline();
        if(timeout<0 && !alarm)return fail(95); // No continuation or external producer exists in this profile.
        // All current descriptor kinds change readiness only via owned queued work;
        // a finite idle timeout is a genuine monotonic Windows-hosted wait.
        std::this_thread::sleep_until(timeout<0?*alarm:(alarm?std::min(deadline,*alarm):deadline));
    }
}
}
