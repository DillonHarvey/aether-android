#include "threads.hpp"
#include "aether/common/thread_exit.hpp"
#include "aether/host/entropy.hpp"
#include "aether/host/process_info.hpp"
#include <limits>
#include <utility>
namespace aether::bionic {
namespace {
constexpr a64::Address main_tls=0x25000,tls_base=0x30000000,stack_base=0x34000000;
constexpr std::size_t stack_size=0x10000;
std::array<std::uint8_t,8> bytes(std::uint64_t value){std::array<std::uint8_t,8> out{};for(unsigned n=0;n<8;++n)out[n]=static_cast<std::uint8_t>(value>>(n*8));return out;}
}
NativeThreads::NativeThreads(a64::GuestMemory &memory,std::uint32_t tid,a64::Address error):memory_(memory),main_(tid),active_(tid),next_(tid),main_errno_(error){}
void NativeThreads::initialize_tls(a64::Address tls,std::uint32_t id) {
    if(!memory_.write(tls,bytes(tls)) || !memory_.write(tls+8,bytes(id)) || !memory_.write(tls+40,bytes(guard_)))throw a64::GuestError("AETHER_GUEST_TLS","Cannot initialize native TLS");
}
void NativeThreads::initialize() {
    const auto priority=host::current_thread_priority();if(!priority)throw a64::GuestError("AETHER_GUEST_PRIORITY","Cannot capture native owner priority");priority_baseline_=*priority;
    std::array<std::uint8_t,16> random{};if(!host::secure_random_128(random))throw a64::GuestError("AETHER_GUEST_TLS","Native TLS entropy unavailable");
    for(unsigned n=0;n<8;++n)guard_=(guard_<<8)|random[n];guard_&=~std::uint64_t{255};
    memory_.map(main_tls,4096,a64::read_write);main_tls_owned_=true;initialize_tls(main_tls,main_);
}
NativeThreads::~NativeThreads(){if(priority_dirty_ && !managed_priority_ && !host::restore_thread_priority(priority_baseline_))std::terminate();for(auto &thread:threads_)if(thread)release(*thread);if(main_tls_owned_)try{memory_.unmap(main_tls);}catch(...) {}}
void NativeThreads::release(Thread &thread)noexcept {
    if(thread.stack_owned){try{memory_.unmap(thread.stack);}catch(...) {}thread.stack_owned=false;}
    if(thread.tls_owned){try{memory_.unmap(thread.tls);}catch(...) {}thread.tls_owned=false;}
}
void NativeThreads::managed_priority(int baseline,host::PriorityService service) {
    if(std::this_thread::get_id()!=owner_ || priority_dirty_ || created || !service || !host::priority_profile_target(baseline,0))throw a64::GuestError("AETHER_GUEST_PRIORITY","Priority backend requires the idle native owner");
    priority_baseline_=baseline;managed_priority_=std::move(service);
}
std::int32_t &NativeThreads::local_priority() {
    if(external_){(void)binding_signal_mask(*external_);for(auto &state:managed_masks_)if(state.id==external_->id && state.tls==external_->tls)return state.nice;}
    for(auto &thread:threads_)if(thread && thread->id==active_)return thread->nice;
    return main_nice_;
}
host::PriorityResult NativeThreads::priority(std::int32_t which,std::uint32_t who,std::optional<std::int32_t> nice) {
    if(std::this_thread::get_id()!=owner_ || priority_restore_failed_)return {5};
    if(which<0 || which>2)return {22};if(which!=0)return {95};
    if(who==host::current_process_id())who=main_;
    if(who && who!=tid()) {
        for(auto &thread:threads_)if(thread && thread->id==who){
            if(thread->state==State::completed || thread->state==State::failed)return {3};
            if(thread->state!=State::runnable)return {95};
            if(nice){if(!host::priority_profile_supported(*nice))return {95};thread->nice=*nice;}
            return {0,thread->nice};
        }
        if(who==main_)return {95};for(const auto &state:managed_masks_)if(state.id==who)return {95};return {3};
    }
    if(nice && !host::priority_profile_supported(*nice))return {95};
    if(managed_priority_ && (external_ || active_==main_)) {
        try {const auto result=managed_priority_(nice);if(!result.error && !host::priority_profile_supported(result.nice))return {95};return result;}catch(...){return {5};}
    }
    auto &value=local_priority();if(nice){if(!host::apply_thread_priority(priority_baseline_,*nice))return {5};value=*nice;priority_dirty_=true;}
    return {0,value};
}
void NativeThreads::runner(GuestPosixServices::ThreadRunner value){for(const auto &thread:threads_)if(thread)throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Cannot replace native runner with live threads");runner_=std::move(value);}
std::optional<GuestPosixServices::ThreadBinding> NativeThreads::exchange_binding(std::optional<GuestPosixServices::ThreadBinding> value) {
    if(value && (value->id<0x40000001U || value->id>0x7fffffffU || value->id==host::current_process_id() || !memory_.accessible(value->tls,48,a64::Permission::read) || !memory_.accessible(value->error,4,a64::Permission::write)))throw a64::GuestError("AETHER_GUEST_TLS","Invalid managed native thread binding");
    if(value)(void)binding_signal_mask(*value);
    if(!managed_priority_) {
        auto next=main_nice_;if(value){for(const auto &state:managed_masks_)if(state.id==value->id && state.tls==value->tls)next=state.nice;}
        if(!host::apply_thread_priority(priority_baseline_,next))throw a64::GuestError("AETHER_GUEST_PRIORITY","Cannot switch logical native priority");priority_dirty_=true;
    }
    return std::exchange(external_,value);
}
a64::Address NativeThreads::tls()const noexcept {if(external_)return external_->tls;for(const auto &thread:threads_)if(thread && thread->id==active_)return thread->tls;return main_tls;}
a64::Address NativeThreads::error_address()const noexcept{return external_?external_->error:(active_==main_?main_errno_:tls()+0x100);}
std::uint64_t &NativeThreads::binding_signal_mask(const GuestPosixServices::ThreadBinding &binding) {
    ManagedMask *empty=nullptr;
    for(auto &mask:managed_masks_){
        if(mask.tls==binding.tls && mask.id){if(mask.id!=binding.id)mask={binding.id,binding.tls,binding.initial_signal_mask};return mask.mask;}
        if(!mask.id && !empty)empty=&mask;
    }
    if(!empty)throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Managed signal mask slots exhausted");
    *empty={binding.id,binding.tls,binding.initial_signal_mask};return empty->mask;
}
std::uint64_t &NativeThreads::signal_mask() {
    if(external_)return binding_signal_mask(*external_);
    for(auto &thread:threads_)if(thread && thread->id==active_)return thread->signal_mask;
    return main_mask_;
}
std::uint64_t &NativeThreads::signal_pending() {
    if(external_){(void)binding_signal_mask(*external_);for(auto &state:managed_masks_)if(state.id==external_->id && state.tls==external_->tls)return state.pending;throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Missing managed signal state");}
    for(auto &thread:threads_)if(thread && thread->id==active_)return thread->pending_signals;
    return main_pending_;
}
void NativeThreads::discard_signal_pending(std::uint64_t bits)noexcept {
    main_pending_&=~bits;for(auto &thread:threads_)if(thread)thread->pending_signals&=~bits;for(auto &state:managed_masks_)state.pending&=~bits;
}
unsigned NativeThreads::change_signal_mask(std::array<std::uint64_t,31> &r) {
    const auto how=static_cast<std::int32_t>(r[0]);
    std::uint64_t requested=0;
    if(r[1]){
        if(how<0 || how>2)return 22;
        std::array<std::uint8_t,8> input{};if(!memory_.read(r[1],input))return 14;
        for(unsigned i=0;i<8;++i)requested|=std::uint64_t{input[i]}<<(8*i);
    }
    if(r[2] && !memory_.accessible(r[2],8,a64::Permission::write))return 14;
    auto &mask=signal_mask();const auto previous=mask;auto next=previous;
    if(r[1]){
        constexpr auto timer=std::uint64_t{1}<<31;
        constexpr auto reserved_unblocked=(std::uint64_t{1}<<41)-(std::uint64_t{1}<<32);
        if(how==1){requested=(requested&~timer)|reserved_unblocked;next&=~requested;}
        else{requested=(requested|timer)&~reserved_unblocked;next=how==0?(previous|requested):requested;}
        next&=~((std::uint64_t{1}<<8)|(std::uint64_t{1}<<18));
    }
    if(r[2] && !memory_.write(r[2],bytes(previous)))return 14;
    mask=next;return 0;
}
void NativeThreads::request_exit(std::uint64_t value) noexcept {
    if(external_){for(auto &state:managed_masks_)if(state.id==external_->id && state.tls==external_->tls){if(!state.exited)state.exited=value;return;}}
    for(auto &thread:threads_)if(thread && thread->id==active_){if(!thread->exited)thread->exited=value;return;}
    if(!main_exit_)main_exit_=value;
}
std::optional<std::uint64_t> NativeThreads::exit_value(a64::Address tls) const noexcept {
    if(!tls)tls=this->tls();
    if(tls==main_tls)return main_exit_;
    for(const auto &thread:threads_)if(thread && thread->tls==tls)return thread->exited;
    for(const auto &state:managed_masks_)if(state.id && state.tls==tls)return state.exited;
    return {};
}
a64::Fault NativeThreads::create(std::array<std::uint64_t,31> &r) {
    if(!runner_){rejection_="pthread_create: no owned native runner";return a64::Fault::unsupported_service;}
    if(r[1]){rejection_="pthread_create: non-default attributes unsupported";return a64::Fault::unsupported_service;}
    if(!memory_.accessible(r[0],8,a64::Permission::write))return a64::Fault::write;
    if(r[2]%4 || !memory_.accessible(r[2],4,a64::Permission::execute))return a64::Fault::execute;
    std::size_t slot=0;while(slot<threads_.size() && threads_[slot])++slot;
    if(slot==threads_.size() || next_>=0x3fffffffU){r[0]=11;return a64::Fault::none;}
    auto id=next_+1;if(id==host::current_process_id())++id;if(id>=0x40000000U){r[0]=11;return a64::Fault::none;}
    const auto parent_priority=priority(0,0,{});if(parent_priority.error){r[0]=parent_priority.error;return a64::Fault::none;}
    Thread value{id,r[2],r[3],stack_base+slot*0x20000,tls_base+slot*0x2000};value.nice=parent_priority.nice;
    value.signal_mask=signal_mask();
    try {
        memory_.map(value.stack,stack_size,a64::read_write);value.stack_owned=true;
        memory_.map(value.tls,4096,a64::read_write);value.tls_owned=true;initialize_tls(value.tls,value.id);
        if(!memory_.write(r[0],bytes(value.id))){release(value);return a64::Fault::write;}
        threads_[slot]=std::move(value);next_=id;++created;r[0]=0;return a64::Fault::none;
    }catch(...){release(value);r[0]=11;return a64::Fault::none;}
}
a64::Fault NativeThreads::run(Thread &thread,std::uint64_t budget) {
    if(priority_restore_failed_)return a64::Fault::windows_service;
    if(thread.state==State::failed)return thread.execution.result.fault;
    if(thread.state==State::completed)return a64::Fault::none;
    if(thread.state!=State::runnable){rejection_="pthread: cyclic or blocked native execution unsupported";return a64::Fault::unsupported_service;}
    if(!budget)return a64::Fault::budget;
    const auto host_before=host::current_thread_priority();if(!host_before || !host::apply_thread_priority(priority_baseline_,thread.nice)){thread.state=State::failed;thread.execution.result.fault=a64::Fault::windows_service;return a64::Fault::windows_service;}
    a64::Fault result=a64::Fault::none;
    {
        const auto previous=active_;const auto external=std::exchange(external_,{});active_=thread.id;
        struct Restore {NativeThreads &p;std::uint32_t previous;std::optional<GuestPosixServices::ThreadBinding> external;int host;~Restore(){if(!host::restore_thread_priority(host))p.priority_restore_failed_=true;p.active_=previous;p.external_=external;}} restore{*this,previous,external,*host_before};
        thread.state=State::running;++started;
        try{thread.execution=runner_(thread.entry,thread.arg,thread.stack+stack_size,thread.tls,budget);}
        catch(const ThreadExit &exit){thread.execution.result.fault=a64::Fault::thread_exit;thread.execution.result.registers[0]=exit.value;request_exit(exit.value);}
        catch(const ProcessExit &exit){thread.execution.result.fault=a64::Fault::process_exit;thread.execution.result.detail=exit.status;}
        catch(...){thread.execution.result.fault=a64::Fault::windows_service;}
        if(thread.execution.result.fault==a64::Fault::thread_exit){thread.execution.result.registers[0]=thread.exited.value_or(thread.execution.result.registers[0]);thread.state=State::completed;}
        else if(!thread.execution.result.returned){thread.state=State::failed;rejection_="pthread: child guest execution failed";if(thread.execution.result.fault==a64::Fault::none)thread.execution.result.fault=a64::Fault::invalid_call;result=thread.execution.result.fault;}
        else thread.state=State::completed;
    }
    if(priority_restore_failed_){rejection_="pthread: host priority restoration failed";thread.state=State::failed;thread.execution.result.fault=a64::Fault::windows_service;return a64::Fault::windows_service;}
    return result;
}

a64::Fault NativeThreads::join(std::array<std::uint64_t,31> &r) {
    if(r[0]==tid()){r[0]=35;return a64::Fault::none;}
    auto found=threads_.end();for(auto it=threads_.begin();it!=threads_.end();++it)if(*it && (*it)->id==r[0]){found=it;break;}
    if(found==threads_.end()){r[0]=3;return a64::Fault::none;}
    if(r[1] && !memory_.accessible(r[1],8,a64::Permission::write))return a64::Fault::write;
    auto &thread=**found;
    if(thread.state==State::running){r[0]=35;return a64::Fault::none;}
    const auto fault=run(thread,1000000);if(fault!=a64::Fault::none)return fault;
    if(r[1] && !memory_.write(r[1],bytes(thread.execution.result.registers[0])))return a64::Fault::write;
    release(thread);found->reset();++joined;r[0]=0;return a64::Fault::none;
}
bool NativeThreads::has_runnable() const noexcept {
    for (const auto &thread : threads_) if (thread && thread->state == State::runnable) return true;
    return false;
}
a64::Fault NativeThreads::run_next(std::uint64_t budget, std::uint64_t &spent) {
    spent = 0;
    for (auto &thread : threads_) if (thread && thread->state == State::runnable) {
        const auto fault = run(*thread, budget);
        spent = thread->execution.ticks ? thread->execution.ticks : 1;
        return fault;
    }
    return a64::Fault::unsupported_service;
}
a64::Fault NativeThreads::pump(std::uint64_t budget) {
    if(budget>1000000)budget=1000000;
    for(;;) {
        Thread *pending=nullptr;for(auto &thread:threads_)if(thread && thread->state==State::runnable){pending=&*thread;break;}
        if(!pending)return a64::Fault::none;
        const auto fault=run(*pending,budget);if(fault!=a64::Fault::none)return fault;
        const auto spent=pending->execution.ticks?pending->execution.ticks:1;
        budget=spent>=budget?0:budget-spent;
    }
}
}
