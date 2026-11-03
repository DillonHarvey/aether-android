#include "once.hpp"
#include "threads.hpp"
#include "aether/common/thread_exit.hpp"
#include <utility>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
std::uint32_t control_value(const std::array<std::uint8_t,4> &bytes) noexcept {
    std::uint32_t value=0;
    for(unsigned i=0;i<bytes.size();++i)value|=std::uint32_t{bytes[i]}<<(8*i);
    return value;
}
constexpr std::array<std::uint8_t,4> underway{1,0,0,0},complete_word{2,0,0,0};
}

void NativeOnce::runner(GuestPosixServices::OnceRunner value){runner_=std::move(value);}

void NativeOnce::abandon_dead_owners() noexcept {
    for(auto &record:records_)if(record.occupied && record.guest && record.running &&
        !threads_.signal_snapshot(record.owner,record.registers)){
        record.running=false;
        record.failure="pthread_once: initializer owner was abandoned; retry is unsupported";
    }
}
void NativeOnce::retire(std::uint32_t id,Address tls,const std::shared_ptr<a64::ThreadRegisterState> &owner) noexcept {
    for(auto &record:records_)if(record.occupied && record.guest && record.owner==id && record.tls==tls && record.registers==owner){
        record.running=false;
        record.failure="pthread_once: initializer owner terminated; retry is unsupported";
    }
}
Fault NativeOnce::validate_control(const Record &record,std::uint32_t expected) const noexcept {
    const auto mapping=memory_.mapping(record.control);
    if(!mapping)return Fault::read;
    if(mapping->address!=record.mapping_base || mapping->size!=record.mapping_size || mapping->permissions!=record.permissions)
        return Fault::unsupported_service;
    std::array<std::uint8_t,4> bytes{};
    if(!memory_.read(record.control,bytes))return Fault::read;
    if(control_value(bytes)!=expected)return Fault::unsupported_service;
    if(!memory_.accessible(record.control,4,a64::Permission::write))return Fault::write;
    return Fault::none;
}
struct NativeOnce::DeferredWait final : a64::DeferredService {
    NativeOnce &p;Record target;
    std::shared_ptr<a64::ThreadRegisterState> owner;
    std::uint32_t tid;Address tls,stack,stack_top;std::uint64_t invocation;
    DeferredWait(NativeOnce &p,const Record &target,const a64::ServiceState &frame):p(p),target(target),
        owner(p.threads_.thread_register_state(frame.trusted_tls)),tid(p.threads_.tid()),tls(frame.trusted_tls),
        stack(frame.stack_pointer),stack_top(frame.stack_top),invocation(frame.invocation){}
    const Record *current() const noexcept {
        for(const auto &record:p.records_)if(record.occupied && record.control==target.control)return &record;
        return nullptr;
    }
    bool ready() const noexcept override {
        if(p.app_.process_state->exit_status() || !p.threads_.signal_snapshot(tid,owner))return true;
        const auto *record=current();
        return !record || !record->guest || record->ticket!=target.ticket || !record->running ||
            !p.threads_.signal_snapshot(record->owner,record->registers) || p.validate_control(*record,1)!=Fault::none;
    }
    std::optional<std::chrono::steady_clock::time_point> deadline() const noexcept override {return {};}
    a64::DeferredServiceResult resume(a64::ServiceState &frame) noexcept override {
        if(p.app_.process_state->exit_status())return {Fault::process_exit,true};
        if(p.threads_.exit_value(tls))return {Fault::thread_exit,true};
        if(!owner || p.threads_.tid()!=tid || p.threads_.tls()!=tls || frame.trusted_tls!=tls ||
           frame.invocation!=invocation || frame.stack_pointer!=stack || frame.stack_top!=stack_top ||
           p.threads_.thread_register_state(tls)!=owner)return {Fault::invalid_call,true};
        p.abandon_dead_owners();
        if(const auto *record=current()){
            if(!record->guest || record->ticket!=target.ticket || !record->running){
                p.rejection_=record->failure.empty()?"pthread_once: initializer record changed during contention":record->failure;
                return {Fault::unsupported_service,true};
            }
            const auto valid=p.validate_control(*record,1);
            return {valid,valid!=Fault::none};
        }
        const auto valid=p.validate_control(target,2);
        if(valid!=Fault::none)return {valid,true};
        frame.registers[0]=0;return {Fault::none,true};
    }
};
Fault NativeOnce::claim(a64::ServiceState &state,bool full_frame,bool allow_deferred) noexcept {
    // The child allowance is at most the legacy initializer's 1m cap. Other
    // callers retain the old synchronous runner and its unparkable depth guard.
    abandon_dead_owners();
    if(!threads_.factory_execution_active() || !allow_deferred)return invoke(state,full_frame);
    try {
        const auto reject=[&](std::string_view reason,Fault fault=Fault::unsupported_service){rejection_=reason;return fault;};
        if(!app_.process_state || app_.process_state->exit_status())return reject("pthread_once: process has terminated",Fault::process_exit);
        const Address control=state.registers[0],initializer=state.registers[1];
        const auto owner=threads_.thread_register_state(state.trusted_tls);
        const auto tid=threads_.tid();const auto tls=threads_.tls();
        if(!full_frame || !state.invocation || state.trusted_tls!=tls || !owner || state.resume || state.deferred ||
           !threads_.signal_snapshot(tid,owner))return reject("pthread_once: invalid trusted claim frame",Fault::invalid_call);
        if(control%4)return reject("pthread_once: control is not 4-byte aligned");
        abandon_dead_owners();
        for(const auto &record:records_)if(record.occupied && record.control==control){
            if(!record.running)return reject(record.failure.empty()?"pthread_once: initializer was abandoned; retry is unsupported":record.failure);
            if(record.owner==tid && record.tls==tls && record.registers==owner)return reject("pthread_once: recursive initialization would deadlock");
            if(!record.guest)return reject("pthread_once: legacy initializer contention is unsupported");
            const auto valid=validate_control(record,1);if(valid!=Fault::none)return valid;
            state.deferred=std::make_shared<DeferredWait>(*this,record,state);
            rejection_={};return Fault::none;
        }
        std::array<std::uint8_t,4> bytes{};
        if(!memory_.read(control,bytes))return reject("pthread_once: control is not readable",Fault::read);
        const auto value=control_value(bytes);
        if(value==2){state.registers[0]=0;rejection_={};return Fault::none;}
        if(value!=0)return reject("pthread_once: underway or invalid control has no runtime initializer owner");
        if(!memory_.accessible(control,4,a64::Permission::write))return reject("pthread_once: control is not writable",Fault::write);
        if(initializer%4 || !memory_.accessible(initializer,4,a64::Permission::execute))return reject("pthread_once: initializer is not aligned executable guest code",Fault::execute);
        if(state.stack_pointer<32 || state.stack_pointer%16 || !state.stack_top || state.stack_pointer>state.stack_top ||
           state.stack_top-state.stack_pointer<32 ||
           !memory_.accessible(state.stack_pointer,32,a64::Permission::write))return reject("pthread_once: shim stack is not aligned and writable",Fault::write);
        const auto mapping=memory_.mapping(control);if(!mapping)return reject("pthread_once: control mapping is unavailable",Fault::read);
        Record *available=nullptr;for(auto &record:records_)if(!record.occupied){available=&record;break;}
        if(!available || next_ticket_==UINT64_MAX)return reject("pthread_once: initializer or ticket capacity exhausted");
        Record prepared;
        prepared.control=control;prepared.tls=tls;prepared.mapping_base=mapping->address;prepared.mapping_size=mapping->size;
        prepared.permissions=mapping->permissions;prepared.owner=tid;prepared.occupied=prepared.running=prepared.guest=true;
        prepared.ticket=next_ticket_++;prepared.invocation=state.invocation;prepared.shim_stack=state.stack_pointer;
        prepared.stack_top=state.stack_top;prepared.registers=owner;
        *available=std::move(prepared);
        if(!memory_.write(control,underway)){*available={};return reject("pthread_once: claim control write failed",Fault::write);}
        state.registers[0]=1;state.registers[2]=available->ticket;rejection_={};return Fault::none;
    }catch(...){rejection_="pthread_once: claim preparation failed";return Fault::unsupported_service;}
}
Fault NativeOnce::complete(a64::ServiceState &state,bool full_frame) noexcept {
    if(!app_.process_state || app_.process_state->exit_status())return Fault::process_exit;
    abandon_dead_owners();
    const auto owner=threads_.thread_register_state(state.trusted_tls);
    for(auto &record:records_)if(record.occupied && record.control==state.registers[0]){
        if(!full_frame || !record.guest || !record.running || record.ticket!=state.registers[1] ||
           record.owner!=threads_.tid() || record.tls!=threads_.tls() || state.trusted_tls!=record.tls ||
           record.registers!=owner || record.invocation!=state.invocation || record.shim_stack!=state.stack_pointer ||
           record.stack_top!=state.stack_top)return Fault::invalid_call;
        const auto valid=validate_control(record,1);
        if(valid!=Fault::none){record.running=false;record.failure="pthread_once: initializer changed its control mapping or state";return valid;}
        if(!memory_.write(record.control,complete_word)){record.running=false;record.failure="pthread_once: completion control write failed";return Fault::write;}
        record={};state.registers[0]=0;rejection_={};return Fault::none;
    }
    rejection_="pthread_once: completion has no matching initializer record";return Fault::invalid_call;
}

Fault NativeOnce::invoke(a64::ServiceState &state,bool full_frame) noexcept {
    Record *claimed=nullptr;
    const auto reject=[&](std::string_view reason,Fault fault=Fault::unsupported_service){
        rejection_=reason;
        if(claimed)claimed->failure=reason;
        return fault;
    };
    try {
        const Address control=state.registers[0],initializer=state.registers[1];
        if(!app_.process_state)return reject("pthread_once: process state is unavailable");
        if(app_.process_state->exit_status())return reject("pthread_once: process has terminated",Fault::process_exit);
        if(control%4)return reject("pthread_once: control is not 4-byte aligned");
        // Runtime ownership wins over a guest-forged completed control word.
        for(const auto &record:records_)if(record.occupied && record.control==control){
            if(!record.running)return reject(record.failure.empty()?"pthread_once: initializer was abandoned; retry is unsupported":record.failure);
            if(record.owner==threads_.tid() && record.tls==threads_.tls())return reject("pthread_once: recursive initialization would deadlock");
            return reject("pthread_once: initializer belongs to a suspended logical thread; resumable contention is unsupported");
        }
        std::array<std::uint8_t,4> bytes{};
        if(!memory_.read(control,bytes))return reject("pthread_once: control is not readable",Fault::read);
        const auto value=control_value(bytes);
        if(value==2){state.registers[0]=0;rejection_={};return Fault::none;}
        if(value==1)return reject("pthread_once: underway control has no runtime initializer owner");
        if(value!=0)return reject("pthread_once: control has an invalid state");
        if(!memory_.accessible(control,bytes.size(),a64::Permission::write))return reject("pthread_once: control is not writable",Fault::write);
        if(initializer%4 || !memory_.accessible(initializer,4,a64::Permission::execute))return reject("pthread_once: initializer is not aligned executable guest code",Fault::execute);
        if(!full_frame)return reject("pthread_once: initialization requires a trusted full guest frame");
        const auto stack=state.stack_pointer;
        if(stack<16 || stack%16 || !memory_.accessible(stack-16,16,a64::Permission::write))return reject("pthread_once: active guest stack is not aligned and writable",Fault::write);
        if(!runner_)return reject("pthread_once: no owned initializer runner");
        Record *available=nullptr;
        for(auto &record:records_)if(!record.occupied){available=&record;break;}
        if(!available || depth_==records_.size())return reject("pthread_once: active and abandoned initializer limit reached");
        const auto mapping=memory_.mapping(control);
        if(!mapping)return reject("pthread_once: control mapping is unavailable",Fault::read);
        const auto owner=threads_.tid();
        const auto tls=threads_.tls();
        if(threads_.exit_value(tls))return reject("pthread_once: logical thread has terminated",Fault::thread_exit);
        // Copy before publishing state 1; nested callbacks may replace the runner.
        const auto callback=runner_;
        *available={control,tls,mapping->address,mapping->size,mapping->permissions,owner,depth_+1,true,true,{}};
        if(!memory_.write(control,underway)){
            *available={};
            return reject("pthread_once: control write failed before initialization",Fault::write);
        }
        claimed=available;
        ++depth_;
        struct CallbackScope {
            Record &record;unsigned &depth;
            ~CallbackScope(){record.running=false;--depth;}
        } scope{*claimed,depth_};
        const auto result=callback(initializer,stack,tls,1'000'000);
        if(app_.process_state->exit_status())return reject("pthread_once: initializer terminated the process",Fault::process_exit);
        if(threads_.exit_value(tls))return reject("pthread_once: initializer terminated its logical thread",Fault::thread_exit);
        if(result.fault!=Fault::none)return reject("pthread_once: initializer execution failed; completion was not published",result.fault);
        if(!result.returned)return reject("pthread_once: initializer did not return; completion was not published",Fault::invalid_call);
        if(threads_.tid()!=owner || threads_.tls()!=tls)return reject("pthread_once: initializer did not restore its logical thread binding");
        // Mapping metadata has no backing identity: an identical remap restoring
        // state 1 cannot be distinguished from the original live guest mapping.
        const auto after=memory_.mapping(control);
        if(!after)return reject("pthread_once: initializer removed the control mapping",Fault::read);
        if(after->address!=claimed->mapping_base || after->size!=claimed->mapping_size)return reject("pthread_once: initializer changed the control mapping bounds");
        if(!memory_.read(control,bytes))return reject("pthread_once: initializer made its control unreadable",Fault::read);
        if(control_value(bytes)!=1)return reject("pthread_once: initializer modified its underway control");
        if(!memory_.accessible(control,bytes.size(),a64::Permission::write))return reject("pthread_once: initializer made its control unwritable",Fault::write);
        if(after->permissions!=claimed->permissions)return reject("pthread_once: initializer changed the control mapping permissions");
        if(!memory_.write(control,complete_word))return reject("pthread_once: completion control write failed",Fault::write);
        *claimed={};
        claimed=nullptr;
        state.registers[0]=0;
        rejection_={};
        return Fault::none;
    }catch(const ThreadExit &exit){
        threads_.request_exit(exit.value);
        return reject("pthread_once: initializer exited its logical thread",Fault::thread_exit);
    }catch(const ProcessExit &exit){
        if(app_.process_state){if(exit.signal)app_.process_state->request_signal(exit.signal);else app_.process_state->request_exit(exit.status);}
        return reject("pthread_once: initializer exited the process",Fault::process_exit);
    }catch(...){
        return reject(claimed?"pthread_once: initializer runner raised an exception; completion was not published":"pthread_once: initializer preparation raised an exception",Fault::windows_service);
    }
}
}
