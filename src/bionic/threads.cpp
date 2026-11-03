#include "threads.hpp"
#include "thread_specific.hpp"
#include "thread_attributes.hpp"
#include "aether/common/thread_exit.hpp"
#include "aether/host/entropy.hpp"
#include "aether/host/process_info.hpp"
#include <exception>
#include <limits>
#include <utility>
namespace aether::bionic {
namespace {
constexpr a64::Address main_tls=0x25000,tls_base=0x30000000,stack_base=0x60100000;
constexpr std::uint64_t stack_stride=0x900000,minimum_stack=NativeThreadOptions::minimum_stack_size,maximum_stack=0x800000,maximum_guard=0x100000;
static_assert(stack_base-maximum_guard>=0x60000000);
static_assert(stack_stride>=maximum_stack+maximum_guard);
static_assert(stack_base+15*stack_stride+maximum_stack<=0x69000000);
std::array<std::uint8_t,8> bytes(std::uint64_t value){std::array<std::uint8_t,8> out{};for(unsigned n=0;n<8;++n)out[n]=static_cast<std::uint8_t>(value>>(n*8));return out;}
}
NativeThreads::NativeThreads(a64::GuestMemory &memory,std::uint32_t tid,a64::Address error,NativeThreadSpecific *specific):specific_(specific),memory_(memory),main_(tid),active_(tid),next_(tid),main_errno_(error){}
void NativeThreads::initialize_tls(a64::Address tls,std::uint32_t id) {
    if(!memory_.write(tls,bytes(tls)) || !memory_.write(tls+8,bytes(id)) || !memory_.write(tls+40,bytes(guard_)))throw a64::GuestError("AETHER_GUEST_TLS","Cannot initialize native TLS");
}
void NativeThreads::initialize() {
    auto registers=std::make_shared<a64::ThreadRegisterState>(a64::ThreadRegisterState{main_tls,0});
    const auto priority=host::current_thread_priority();if(!priority)throw a64::GuestError("AETHER_GUEST_PRIORITY","Cannot capture native owner priority");priority_baseline_=*priority;
    std::array<std::uint8_t,16> random{};if(!host::secure_random_128(random))throw a64::GuestError("AETHER_GUEST_TLS","Native TLS entropy unavailable");
    for(unsigned n=0;n<8;++n)guard_=(guard_<<8)|random[n];guard_&=~std::uint64_t{255};
    memory_.map(main_tls,4096,a64::read_write);main_tls_owned_=true;initialize_tls(main_tls,main_);
    main_registers_=std::move(registers);
}
NativeThreads::~NativeThreads(){close_tasks();if(priority_dirty_ && !managed_priority_ && !host::restore_thread_priority(priority_baseline_))std::terminate();for(auto &thread:threads_)if(thread)release(*thread);if(main_tls_owned_)try{memory_.unmap(main_tls);}catch(...) {}}
void NativeThreads::release(Thread &thread)noexcept {
    if(thread.task){thread.task->close();thread.task.reset();}
    if(specific_)specific_->discard(thread.id,thread.tls);
    if(thread.stack_owned){try{memory_.unmap(thread.stack);}catch(...) {}thread.stack_owned=false;}
    if(thread.guard_owned){try{memory_.unmap(thread.stack-thread.guard_size);}catch(...) {}thread.guard_owned=false;}
    if(thread.tls_owned){try{memory_.unmap(thread.tls);}catch(...) {}thread.tls_owned=false;}
    thread.registers.reset();
    thread.pending_signals=0;thread.information={};
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
            if(thread->state!=State::runnable && !(thread->task && thread->state==State::waiting))return {95};
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
void NativeThreads::runner(GuestPosixServices::ThreadRunner value){for(const auto &thread:threads_)if(thread)throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Cannot replace native runner with live threads");if(value && factory_)throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Native factory and synchronous runner are exclusive");runner_=std::move(value);}
void NativeThreads::factory(GuestPosixServices::ThreadFactory value) {
    if(std::this_thread::get_id()!=owner_)throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Native factory requires the owner");
    for(const auto &thread:threads_)if(thread)throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Cannot replace native factory with live threads");
    if(value && runner_)throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Native factory and synchronous runner are exclusive");
    factory_=std::move(value);
}
void NativeThreads::deferred_yield(std::function<bool()> request) {
    if(std::this_thread::get_id()!=owner_)throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Deferred yield requires the owner");
    for(const auto &thread:threads_)if(thread)throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Cannot replace yield binding with live threads");
    deferred_yield_=std::move(request);
}
void NativeThreads::close_tasks() noexcept {
    if(std::this_thread::get_id()!=owner_)std::terminate();
    for(auto &thread:threads_)if(thread && thread->task){
        thread->task->close();
        thread->task.reset(); // Drop CPU/JNI capsule leases while their owners still exist.
        if(thread->state!=State::completed && thread->state!=State::failed)thread->state=State::cancelled;
    }
}
std::optional<GuestPosixServices::ExecutionBinding> NativeThreads::prepare_execution(std::uint32_t id,const std::shared_ptr<a64::ThreadRegisterState> &owner) const noexcept {
    if(std::this_thread::get_id()!=owner_ || !owner)return {};
    for(const auto &thread:threads_)if(thread && thread->id==id && thread->registers==owner){
        GuestPosixServices::ExecutionBinding binding;binding.active=id;binding.owner=owner;
        return binding_valid(binding)?std::optional{std::move(binding)}:std::nullopt;
    }
    return {};
}
bool NativeThreads::binding_valid(const GuestPosixServices::ExecutionBinding &binding) const noexcept {
    if(std::this_thread::get_id()!=owner_ || !binding.owner)return false;
    if(binding.external){
        for(const auto &state:managed_masks_)if(state.id==binding.external->id && state.tls==binding.external->tls)
            return state.registers==binding.owner;
        return false;
    }
    if(binding.active==main_)return binding.owner==main_registers_;
    for(const auto &thread:threads_)if(thread && thread->id==binding.active && thread->registers==binding.owner)
        return thread->state==State::prepared || thread->state==State::runnable || thread->state==State::running || thread->state==State::waiting;
    return false;
}
void NativeThreads::exchange_execution(GuestPosixServices::ExecutionBinding &binding) noexcept {
    const auto previous=thread_register_state(tls());
    if(!previous || !binding_valid(binding))std::terminate();
    std::swap(active_,binding.active);external_.swap(binding.external);binding.owner=previous;
}
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
std::shared_ptr<a64::ThreadRegisterState> NativeThreads::thread_register_state(a64::Address trusted_tls) const noexcept {
    if(std::this_thread::get_id()!=owner_)return {};
    if(external_){
        if(trusted_tls!=external_->tls)return {};
        for(const auto &state:managed_masks_)if(state.id==external_->id && state.tls==trusted_tls)return state.registers;
        return {};
    }
    if(active_==main_)return trusted_tls==main_tls?main_registers_:nullptr;
    for(const auto &thread:threads_)if(thread && thread->id==active_ && thread->tls==trusted_tls)return thread->registers;
    return {};
}
bool NativeThreads::register_owner_live(const std::shared_ptr<a64::ThreadRegisterState> &registers) const noexcept {
    if (std::this_thread::get_id() != owner_ || !registers) return false;
    const auto finalizing = [&](std::uint32_t id, a64::Address trusted_tls) {
        for (std::size_t i = 0; i < finalizing_depth_; ++i)
            if (finalizing_[i].id == id && finalizing_[i].tls == trusted_tls)
                return !finalizing_[i].exited;
        return false;
    };
    if (registers == main_registers_)
        return finalizing(main_, main_tls) || !main_exit_;
    for (const auto &thread : threads_)
        if (thread && registers == thread->registers)
            return (thread->state == State::runnable || thread->state == State::running || thread->state == State::waiting) &&
                   (finalizing(thread->id, thread->tls) || !thread->exited);
    for (const auto &state : managed_masks_)
        if (state.id && registers == state.registers)
            return finalizing(state.id, state.tls) || !state.exited;
    return false;
}
a64::Address NativeThreads::error_address()const noexcept{return external_?external_->error:(active_==main_?main_errno_:tls()+0x100);}
std::uint64_t &NativeThreads::binding_signal_mask(const GuestPosixServices::ThreadBinding &binding) {
    ManagedMask *selected=nullptr,*empty=nullptr;
    for(auto &mask:managed_masks_){
        if(mask.tls==binding.tls && mask.id){
            if(mask.id==binding.id){
                if(binding.prepared_registers && binding.prepared_registers!=mask.registers)
                    throw a64::GuestError("AETHER_GUEST_TLS","Managed TLS register incarnation changed");
                return mask.mask;
            }
            selected=&mask;break;
        }
        if(!mask.id && !empty)empty=&mask;
    }
    if(!selected)selected=empty;
    if(!selected)throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Managed signal mask slots exhausted");
    ManagedMask candidate{binding.id,binding.tls,binding.initial_signal_mask};
    candidate.name=main_name_;
    candidate.registers=binding.prepared_registers;
    if(candidate.registers){
        // A prepared host object belongs to one trusted owner incarnation.
        // Its guest-written architectural values never select that owner.
        bool shared=candidate.registers==main_registers_;
        for(const auto &thread:threads_)if(thread && candidate.registers==thread->registers)shared=true;
        for(const auto &mask:managed_masks_)if(mask.id && candidate.registers==mask.registers)shared=true;
        if(shared)throw a64::GuestError("AETHER_GUEST_TLS","TLS owners cannot share architectural register state");
    }else{
        candidate.registers=std::make_shared<a64::ThreadRegisterState>(a64::ThreadRegisterState{binding.tls,0});
    }
    if(selected->id && specific_)specific_->discard(selected->id,selected->tls);
    *selected=std::move(candidate);
    return selected->mask;
}
std::uint64_t &NativeThreads::current_locale() {
    if(external_){
        (void)binding_signal_mask(*external_);
        for(auto &state:managed_masks_)if(state.id==external_->id && state.tls==external_->tls)return state.locale;
        throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Missing managed locale state");
    }
    for(auto &thread:threads_)if(thread && thread->id==active_)return thread->locale;
    return main_locale_;
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
NativeSignalInfos *NativeThreads::signal_information() noexcept {
    const auto target=current_signal_target();
    return target?target->information:nullptr;
}
std::optional<NativeThreads::SignalTarget> NativeThreads::current_signal_target() noexcept {
    if(std::this_thread::get_id()!=owner_)return {};
    if(external_){for(auto &state:managed_masks_)if(state.id==external_->id && state.tls==external_->tls)return SignalTarget{&state.mask,&state.pending,&state.information};return {};}
    if(active_==main_)return SignalTarget{&main_mask_,&main_pending_,&main_information_};
    for(auto &thread:threads_)if(thread && thread->id==active_)return SignalTarget{&thread->signal_mask,&thread->pending_signals,&thread->information};
    return {};
}
NativeSignalStack &NativeThreads::current_signal_stack() {
    if(external_){
        (void)binding_signal_mask(*external_);
        for(auto &state:managed_masks_)if(state.id==external_->id && state.tls==external_->tls)return state.signal_stack;
        throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Missing managed alternate signal stack state");
    }
    for(auto &thread:threads_)if(thread && thread->id==active_)return thread->signal_stack;
    return main_signal_stack_;
}
void NativeThreads::discard_signal_pending(std::uint64_t bits)noexcept {
    main_pending_&=~bits;for(auto &thread:threads_)if(thread)thread->pending_signals&=~bits;for(auto &state:managed_masks_)state.pending&=~bits;
    for(unsigned signal=1;signal<32;++signal)if(bits&(std::uint64_t{1}<<(signal-1))){
        main_information_[signal].reset();
        for(auto &thread:threads_)if(thread)thread->information[signal].reset();
        for(auto &state:managed_masks_)state.information[signal].reset();
    }
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
void NativeThreads::begin_finalization() {
    if(std::this_thread::get_id()!=owner_ || finalizing_depth_==finalizing_.size())
        throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Thread finalization requires its bounded owner");
    for(std::size_t i=0;i<finalizing_depth_;++i)
        if(finalizing_[i].id==tid() && finalizing_[i].tls==tls())
            throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Recursive logical thread finalization");
    finalizing_[finalizing_depth_++]={tid(),tls()};
}
void NativeThreads::end_finalization() noexcept {
    if(!finalizing_depth_)std::terminate();
    finalizing_[--finalizing_depth_]={};
}
void NativeThreads::retire(std::uint32_t id,a64::Address tls) noexcept {
    if(specific_)specific_->discard(id,tls);
    for(auto &state:managed_masks_)if(state.id==id && state.tls==tls)state={};
}
void NativeThreads::request_exit(std::uint64_t value) noexcept {
    for(std::size_t i=0;i<finalizing_depth_;++i)if(finalizing_[i].id==tid() && finalizing_[i].tls==tls())finalizing_[i].exited=true;
    if(external_){for(auto &state:managed_masks_)if(state.id==external_->id && state.tls==external_->tls){if(!state.exited)state.exited=value;return;}}
    for(auto &thread:threads_)if(thread && thread->id==active_){if(!thread->exited)thread->exited=value;return;}
    if(!main_exit_)main_exit_=value;
}
std::optional<std::uint64_t> NativeThreads::exit_value(a64::Address tls) const noexcept {
    if(!tls)tls=this->tls();
    for(std::size_t i=0;i<finalizing_depth_;++i)if(finalizing_[i].tls==tls && finalizing_[i].id==tid() && !finalizing_[i].exited)return {};
    if(tls==main_tls)return main_exit_;
    for(const auto &thread:threads_)if(thread && thread->tls==tls)return thread->exited;
    for(const auto &state:managed_masks_)if(state.id && state.tls==tls)return state.exited;
    return {};
}
a64::Fault NativeThreads::create(std::array<std::uint64_t,31> &r,const NativeThreadOptions &options) {
    if(!runner_ && !factory_){rejection_="pthread_create: no owned native runner or factory";return a64::Fault::unsupported_service;}
    if(options.stack_size<minimum_stack){r[0]=22;return a64::Fault::none;}
    if(options.stack_size>maximum_stack || options.guard_size>maximum_guard){r[0]=95;return a64::Fault::none;}
    if(!memory_.accessible(r[0],8,a64::Permission::write))return a64::Fault::write;
    if(r[2]%4 || !memory_.accessible(r[2],4,a64::Permission::execute))return a64::Fault::execute;
    std::size_t slot=0;while(slot<threads_.size() && threads_[slot])++slot;
    if(slot==threads_.size() || next_>=0x3fffffffU){r[0]=11;return a64::Fault::none;}
    auto id=next_+1;if(id==host::current_process_id())++id;if(id>=0x40000000U){r[0]=11;return a64::Fault::none;}
    const auto parent_priority=priority(0,0,{});if(parent_priority.error){r[0]=parent_priority.error;return a64::Fault::none;}
    Thread value{id,r[2],r[3],stack_base+slot*stack_stride,tls_base+slot*0x2000};value.nice=parent_priority.nice;
    value.stack_size=options.stack_size;value.mapped_size=(options.stack_size+4095)&~std::uint64_t{4095};
    value.guard_size=(options.guard_size+4095)&~std::uint64_t{4095};value.detached=options.detached;
    value.signal_mask=signal_mask();
    if(const auto parent_name=find_name(tid()))value.name=*parent_name;
    bool installed=false;
    try {
        value.registers=std::make_shared<a64::ThreadRegisterState>(a64::ThreadRegisterState{value.tls,0});
        if(value.guard_size){memory_.map(value.stack-value.guard_size,static_cast<std::size_t>(value.guard_size),a64::Permission::none);value.guard_owned=true;}
        memory_.map(value.stack,static_cast<std::size_t>(value.mapped_size),a64::read_write);value.stack_owned=true;
        memory_.map(value.tls,4096,a64::read_write);value.tls_owned=true;initialize_tls(value.tls,value.id);
        value.state=factory_?State::prepared:State::runnable;
        threads_[slot]=std::move(value);installed=true;
        auto &admitted=*threads_[slot];
        if(factory_){
            const GuestPosixServices::ThreadSpec spec{id,admitted.entry,admitted.arg,admitted.stack+admitted.mapped_size,
                admitted.tls,admitted.registers,admitted.signal_mask,1000000,admitted.nice};
            admitted.task=factory_(spec);
            if(!admitted.task || admitted.task->state()!=GuestPosixServices::ThreadTaskState::prepared)
                throw a64::GuestError("AETHER_GUEST_THREAD_STATE","Factory did not return a dormant native task");
        }
        // Preparation can allocate/collect. Revalidate the complete handle
        // destination before the sole publication; no guest work follows it.
        if(!memory_.write(r[0],bytes(id))){release(admitted);threads_[slot].reset();return a64::Fault::write;}
        if(admitted.task && !admitted.task->publish()){
            rejection_="pthread_create: prepared task publication invariant failed after handle commit";
            release(admitted);threads_[slot].reset();return a64::Fault::invalid_call;
        }
        admitted.state=State::runnable;next_=id;++created;r[0]=0;return a64::Fault::none;
    }catch(const std::exception &){
        if(installed){release(*threads_[slot]);threads_[slot].reset();}else release(value);
        r[0]=11;return a64::Fault::none;
    }catch(...){
        if(installed){release(*threads_[slot]);threads_[slot].reset();}else release(value);
        throw; // Process/thread exit and private scheduler cancellation retain their control flow.
    }
}
a64::Fault NativeThreads::run(Thread &thread,std::uint64_t budget) {
    thread.slice_ticks=0;
    if(priority_restore_failed_)return a64::Fault::windows_service;
    if(thread.state==State::failed)return thread.execution.result.fault;
    if(thread.state==State::completed)return a64::Fault::none;
    if(thread.state==State::cancelled){rejection_="pthread: cancelled native task has no ordinary return value";return a64::Fault::unsupported_service;}
    if(thread.task){
        using TaskState=GuestPosixServices::ThreadTaskState;
        const auto current=thread.task->state();
        if(current==TaskState::waiting){thread.state=State::waiting;rejection_="pthread: native task is waiting for actual readiness";return a64::Fault::unsupported_service;}
        const bool terminal_current=current==TaskState::completed || current==TaskState::failed || current==TaskState::cancelled;
        if(current!=TaskState::runnable && !terminal_current){rejection_="pthread: native task is not runnable";return a64::Fault::unsupported_service;}
        if(!terminal_current && (external_ || active_!=main_)){
            rejection_="pthread: recursive native task pumping requires a deferred wait";return a64::Fault::unsupported_service;
        }
        if(!budget && !terminal_current)return a64::Fault::budget;
        thread.state=State::running;

        // The factory's independent fiber entry owns cancellation and finalizers.
        // Never run it through the synchronous catch-all below.
        GuestPosixServices::ThreadSlice slice;
        try{slice=thread.task->resume_slice(budget,thread.nice);}
        catch(...){
            // A root-side admission failure must not strand a runnable task as
            // running. Preserve the original unwind, including cancellation.
            if(thread.task->started() && !thread.task_started){thread.task_started=true;++started;}
            thread.state=State::runnable;throw;
        }
        if(thread.task->started() && !thread.task_started){thread.task_started=true;++started;}
        thread.slice_ticks=slice.ticks;
        if(slice.progress_fault!=a64::Fault::none){
            if(slice.state!=TaskState::runnable || slice.terminal || slice.ticks){thread.state=State::failed;return a64::Fault::invalid_call;}
            thread.state=State::runnable;rejection_="pthread: caller progress allowance or admission refused";return slice.progress_fault;
        }
        if(slice.ticks>budget){thread.state=State::failed;thread.execution.result.fault=a64::Fault::budget;return a64::Fault::budget;}
        const bool terminal=slice.state==TaskState::completed || slice.state==TaskState::cancelled || slice.state==TaskState::failed;
        if(terminal!=slice.terminal.has_value() && slice.state!=TaskState::cancelled){
            thread.state=State::failed;thread.execution.result.fault=a64::Fault::invalid_call;
            rejection_="pthread: native slice terminal metadata disagrees with its state";return a64::Fault::invalid_call;
        }
        if(slice.terminal)thread.execution=*slice.terminal;
        if(slice.state==TaskState::runnable){thread.state=State::runnable;return a64::Fault::none;}
        if(slice.state==TaskState::waiting){thread.state=State::waiting;return a64::Fault::none;}
        if(slice.state==TaskState::cancelled){thread.state=State::cancelled;rejection_="pthread: native task was cancelled";return a64::Fault::unsupported_service;}
        if(slice.state==TaskState::completed && !thread.execution.finalization_failed &&
           ((thread.execution.result.returned && thread.execution.result.fault==a64::Fault::none) || thread.execution.result.fault==a64::Fault::thread_exit)){
            if(thread.execution.result.fault==a64::Fault::thread_exit)
                thread.execution.result.registers[0]=thread.exited.value_or(thread.execution.result.registers[0]);
            thread.state=State::completed;return a64::Fault::none;
        }
        thread.state=State::failed;
        if(thread.execution.result.fault==a64::Fault::none)thread.execution.result.fault=a64::Fault::invalid_call;
        rejection_="pthread: native task failed or returned an invalid slice state";
        return thread.execution.result.fault;
    }
    if(thread.state!=State::runnable){rejection_="pthread: cyclic or blocked native execution unsupported";return a64::Fault::unsupported_service;}
    if(!budget)return a64::Fault::budget;
    const auto host_before=host::current_thread_priority();if(!host_before || !host::apply_thread_priority(priority_baseline_,thread.nice)){thread.state=State::failed;thread.execution.result.fault=a64::Fault::windows_service;return a64::Fault::windows_service;}
    a64::Fault result=a64::Fault::none;
    {
        const auto previous=active_;const auto external=std::exchange(external_,{});active_=thread.id;
        struct Restore {NativeThreads &p;std::uint32_t previous;std::optional<GuestPosixServices::ThreadBinding> external;int host;~Restore(){if(!host::restore_thread_priority(host))p.priority_restore_failed_=true;p.active_=previous;p.external_=external;}} restore{*this,previous,external,*host_before};
        thread.state=State::running;++started;
        try{thread.execution=runner_(thread.entry,thread.arg,thread.stack+thread.mapped_size,thread.tls,budget);}
        catch(const ThreadExit &exit){thread.execution.result.fault=a64::Fault::thread_exit;thread.execution.result.registers[0]=exit.value;request_exit(exit.value);}
        catch(const ProcessExit &exit){thread.execution.result.fault=a64::Fault::process_exit;thread.execution.result.detail=exit.status;}
        catch(...){thread.execution.result.fault=a64::Fault::windows_service;}
        if(thread.execution.result.fault==a64::Fault::thread_exit && !thread.execution.finalization_failed){thread.execution.result.registers[0]=thread.exited.value_or(thread.execution.result.registers[0]);thread.state=State::completed;}
        else if(thread.execution.finalization_failed || !thread.execution.result.returned){thread.state=State::failed;rejection_="pthread: child guest execution failed";if(thread.execution.result.fault==a64::Fault::none)thread.execution.result.fault=a64::Fault::invalid_call;result=thread.execution.result.fault;}
        else thread.state=State::completed;
    }
    thread.slice_ticks=thread.execution.ticks?thread.execution.ticks:1;
    if(priority_restore_failed_){rejection_="pthread: host priority restoration failed";thread.state=State::failed;thread.execution.result.fault=a64::Fault::windows_service;return a64::Fault::windows_service;}
    return result;
}

struct NativeThreads::JoinClaim {
    NativeThreads &p;std::uint32_t target;std::shared_ptr<a64::ThreadRegisterState> owner;bool claimed=false;
    JoinClaim(NativeThreads &p,const Thread &thread):p(p),target(thread.id),owner(thread.registers){}
    JoinClaim(const JoinClaim &)=delete;
    JoinClaim &operator=(const JoinClaim &)=delete;
    ~JoinClaim(){clear();}
    Thread *get() const noexcept {
        for(auto &thread:p.threads_)if(thread && thread->id==target && thread->registers==owner)return &*thread;
        return nullptr;
    }
    bool acquire() noexcept {
        auto *thread=get();
        if(!thread || !owner || thread->detached || thread->join_claim)return false;
        thread->join_claim=this;claimed=true;return true;
    }
    void clear() noexcept {
        if(!claimed)return;
        if(std::this_thread::get_id()!=p.owner_)std::terminate();
        if(auto *thread=get();thread && thread->join_claim==this)thread->join_claim=nullptr;
        claimed=false;
    }
    bool owns() const noexcept {const auto *thread=get();return claimed && thread && thread->join_claim==this;}
};
struct NativeThreads::DeferredJoin final : a64::DeferredService {
    NativeThreads &p;JoinClaim claim;std::shared_ptr<ProcessState> process;
    std::uint32_t joiner;std::shared_ptr<a64::ThreadRegisterState> owner;
    a64::Address output,tls,stack_top;std::uint64_t invocation;
    DeferredJoin(NativeThreads &p,const Thread &thread,const a64::ServiceState &frame,std::shared_ptr<ProcessState> process):
        p(p),claim(p,thread),process(std::move(process)),joiner(p.tid()),owner(p.thread_register_state(frame.trusted_tls)),
        output(frame.registers[1]),tls(frame.trusted_tls),stack_top(frame.stack_top),invocation(frame.invocation){}
    bool ready() const noexcept override {
        if(std::this_thread::get_id()!=p.owner_ || process->exit_status() || !p.signal_snapshot(joiner,owner))return true;
        const auto *thread=claim.get();
        if(!thread || thread->detached || (claim.claimed && !claim.owns()) ||
           (!claim.claimed && thread->join_claim))return true;
        return thread->state==State::completed || thread->state==State::failed || thread->state==State::cancelled ||
            thread->state==State::running || thread->state==State::prepared;
    }
    std::optional<std::chrono::steady_clock::time_point> deadline() const noexcept override {return {};}
    a64::DeferredServiceResult resume(a64::ServiceState &frame) noexcept override {
        if(std::this_thread::get_id()!=p.owner_)return {a64::Fault::invalid_call,true};
        const auto finish=[&](a64::Fault fault,unsigned code=0){claim.clear();if(fault==a64::Fault::none)frame.registers[0]=code;return a64::DeferredServiceResult{fault,true};};
        if(process->exit_status())return finish(a64::Fault::process_exit);
        if(!owner || p.tid()!=joiner || p.tls()!=tls || frame.trusted_tls!=tls || frame.invocation!=invocation ||
           frame.stack_top!=stack_top || p.thread_register_state(tls)!=owner)return finish(a64::Fault::invalid_call);
        auto *thread=claim.get();
        if(!thread)return finish(a64::Fault::none,3);
        if(thread->detached)return finish(a64::Fault::none,22);
        if(thread->id==joiner || thread->state==State::running)return finish(a64::Fault::none,35);
        if(!claim.claimed){
            if(output && !p.memory_.accessible(output,8,a64::Permission::write))return finish(a64::Fault::write);
            if(!claim.acquire())return finish(a64::Fault::none,22);
        }else if(!claim.owns())return finish(a64::Fault::invalid_call);
        if(thread->state==State::failed)
            return finish(thread->execution.result.fault==a64::Fault::none?a64::Fault::invalid_call:thread->execution.result.fault);
        if(thread->state==State::cancelled || thread->state==State::prepared)return finish(a64::Fault::unsupported_service);
        if(thread->state!=State::completed)return {a64::Fault::none,false};
        // Root progress has published genuine terminal execution/finalization.
        // No guest callback occurs between the fresh output write and reaping.
        if(output && !p.memory_.write(output,bytes(thread->execution.result.registers[0])))return finish(a64::Fault::write);
        claim.clear();
        p.release(*thread);
        for(auto &slot:p.threads_)if(slot && &*slot==thread){slot.reset();break;}
        ++p.joined;frame.registers[0]=0;return {a64::Fault::none,true};
    }
};
a64::Fault NativeThreads::invoke_join(a64::ServiceState &frame,bool allow_deferred,std::shared_ptr<ProcessState> process) {
    if(!process)return a64::Fault::invalid_call;
    if(!factory_execution_active() || !allow_deferred)return join(frame.registers);
    if(std::this_thread::get_id()!=owner_ || !frame.invocation || frame.trusted_tls!=tls() ||
       !signal_snapshot(tid(),thread_register_state(frame.trusted_tls)))return a64::Fault::invalid_call;
    auto &r=frame.registers;
    Thread *target=nullptr;for(auto &thread:threads_)if(thread && thread->id==r[0]){target=&*thread;break;}
    if(!target){r[0]=r[0]==tid()?35:3;return a64::Fault::none;}
    if(target->detached || target->join_claim){r[0]=22;return a64::Fault::none;}
    if(target->id==tid() || target->state==State::running){r[0]=35;return a64::Fault::none;}
    if(r[1] && !memory_.accessible(r[1],8,a64::Permission::write))return a64::Fault::write;
    // All allocation precedes the first reservation or result/output effect.
    frame.deferred=std::make_shared<DeferredJoin>(*this,*target,frame,std::move(process));
    return a64::Fault::none;
}
a64::Fault NativeThreads::join(std::array<std::uint64_t,31> &r) {
    auto found=threads_.end();for(auto it=threads_.begin();it!=threads_.end();++it)if(*it && (*it)->id==r[0]){found=it;break;}
    if(found==threads_.end()){r[0]=r[0]==tid()?35:3;return a64::Fault::none;}
    if((*found)->detached){r[0]=22;return a64::Fault::none;}
    if(r[0]==tid()){r[0]=35;return a64::Fault::none;}
    if(r[1] && !memory_.accessible(r[1],8,a64::Permission::write))return a64::Fault::write;
    auto &thread=**found;
    JoinClaim claim(*this,thread);
    if(!claim.acquire()){r[0]=22;return a64::Fault::none;}
    if(thread.state==State::running){r[0]=35;return a64::Fault::none;}
    std::uint64_t budget=1000000;
    for(std::size_t slices=0;;++slices){
        const auto fault=run(thread,budget);if(fault!=a64::Fault::none)return fault;
        if(thread.detached && thread.state!=State::completed){r[0]=22;return a64::Fault::none;}
        if(thread.state==State::completed)break;
        if(thread.state==State::waiting){rejection_="pthread_join: child requires actual readiness before completion";return a64::Fault::unsupported_service;}
        budget=thread.slice_ticks>=budget?0:budget-thread.slice_ticks;
        if(!budget || slices+1==1024){rejection_="pthread_join: bounded progress exhausted before child completion";return a64::Fault::budget;}
    }
    if(thread.state!=State::completed){rejection_="pthread_join: child did not reach a terminal result";return a64::Fault::unsupported_service;}
    // A child may detach itself during the join's nested runner. It must remain
    // alive until that runner has restored its parent frame and host priority.
    if(thread.detached){release(thread);found->reset();r[0]=22;return a64::Fault::none;}
    if(r[1] && !memory_.write(r[1],bytes(thread.execution.result.registers[0])))return a64::Fault::write;
    release(thread);found->reset();++joined;r[0]=0;return a64::Fault::none;
}
std::array<char,16> *NativeThreads::find_name(std::uint64_t id) noexcept {
    if(id==main_)return main_exit_?nullptr:&main_name_;
    for(auto &thread:threads_)if(thread && thread->id==id)
        return thread->state==State::completed || thread->state==State::failed || thread->state==State::cancelled || thread->exited?nullptr:&thread->name;
    for(auto &state:managed_masks_)if(state.id && state.id==id)return state.exited?nullptr:&state.name;
    return nullptr;
}
std::optional<NativeThreads::SignalTarget> NativeThreads::signal_target(std::uint32_t id) noexcept {
    if(!find_name(id))return {};
    if(id==main_)return SignalTarget{&main_mask_,&main_pending_,&main_information_};
    for(auto &thread:threads_)if(thread && thread->id==id)return SignalTarget{&thread->signal_mask,&thread->pending_signals,&thread->information};
    for(auto &state:managed_masks_)if(state.id==id)return SignalTarget{&state.mask,&state.pending,&state.information};
    return {};
}
std::optional<NativeThreads::SignalSnapshot> NativeThreads::signal_snapshot(std::uint32_t id,const std::shared_ptr<a64::ThreadRegisterState> &owner) const noexcept {
    if(std::this_thread::get_id()!=owner_ || !owner)return {};
    if(id==main_)
        return owner==main_registers_ && !main_exit_ ? std::optional{SignalSnapshot{id,main_mask_,main_pending_}} : std::nullopt;
    for(const auto &thread:threads_)if(thread && thread->id==id){
        if(thread->registers!=owner || thread->exited ||
           (thread->state!=State::runnable && thread->state!=State::running && thread->state!=State::waiting))return {};
        return SignalSnapshot{id,thread->signal_mask,thread->pending_signals};
    }
    for(const auto &state:managed_masks_)if(state.id==id)
        return state.registers==owner && !state.exited ? std::optional{SignalSnapshot{id,state.mask,state.pending}} : std::nullopt;
    return {};
}

a64::Fault NativeThreads::thread_name(std::array<std::uint64_t,31> &r,bool set,bool kernel) noexcept {
    // Names belong to logical pthreads, not their shared Windows execution thread.
    std::array<char,16> value{};
    if(set){
        for(std::size_t i=0;i<(kernel?value.size()-1:value.size());++i){
            if(r[1]>=a64::GuestMemory::address_limit || i>=a64::GuestMemory::address_limit-r[1]){if(kernel){r[0]=14;return a64::Fault::none;}return a64::Fault::read;}
            std::array<std::uint8_t,1> byte{};if(!memory_.read(r[1]+i,byte)){if(kernel){r[0]=14;return a64::Fault::none;}return a64::Fault::read;}
            value[i]=static_cast<char>(byte[0]);if(!byte[0])break;
            if(i==value.size()-1 && !kernel){r[0]=34;return a64::Fault::none;}
        }
        value.back()=0;
    }else if(!kernel && r[2]<value.size()){r[0]=34;return a64::Fault::none;}
    auto target=find_name(kernel?tid():r[0]);if(!target){r[0]=3;return a64::Fault::none;}
    if(set)*target=value;
    else if(!memory_.write(r[1],{reinterpret_cast<const std::uint8_t*>(target->data()),target->size()})){r[0]=14;return a64::Fault::none;}
    r[0]=0;return a64::Fault::none;
}

unsigned NativeThreads::query(std::uint64_t id,NativeThreadOptions &options,a64::Address &base) const noexcept {
    for(const auto &thread:threads_)if(thread && thread->id==id){
        options.stack_size=thread->mapped_size;options.guard_size=thread->guard_size;options.detached=thread->detached;base=thread->stack;return 0;
    }
    if(id==main_)return 95;
    if(external_ && id==external_->id)return 95;
    for(const auto &state:managed_masks_)if(state.id && state.id==id)return 95;
    return 3;
}
a64::Fault NativeThreads::detach(std::array<std::uint64_t,31> &r) {
    for(auto &thread:threads_)if(thread && thread->id==r[0]){
        if(thread->detached || thread->join_claim){r[0]=22;return a64::Fault::none;}
        thread->detached=true;
        if(thread->state==State::completed){release(*thread);thread.reset();}
        r[0]=0;return a64::Fault::none;
    }
    NativeThreadOptions ignored;a64::Address base=0;
    r[0]=query(r[0],ignored,base);return a64::Fault::none;
}
bool NativeThreads::has_runnable() const noexcept {
    for(const auto &thread:threads_)if(thread){
        if(thread->task && thread->state!=State::completed && thread->state!=State::failed && thread->state!=State::cancelled && thread->state!=State::prepared){
            const auto state=thread->task->state();
            if(state==GuestPosixServices::ThreadTaskState::runnable || state==GuestPosixServices::ThreadTaskState::completed ||
               state==GuestPosixServices::ThreadTaskState::failed || state==GuestPosixServices::ThreadTaskState::cancelled)return true;
        }else if(!thread->task && thread->state==State::runnable)return true;
    }
    return false;
}
a64::Fault NativeThreads::run_next(std::uint64_t budget, std::uint64_t &spent) {
    spent = 0;
    for(std::size_t offset=0;offset<threads_.size();++offset){
        const auto index=factory_?(run_cursor_+offset)%threads_.size():offset;
        auto &thread=threads_[index];
        if(!thread || !(thread->state==State::runnable ||
           (thread->task && thread->state==State::waiting && thread->task->state()!=GuestPosixServices::ThreadTaskState::waiting)))continue;
        // A yielded factory task remains runnable. Advance before its slice so
        // repeated poll/descriptor progress cannot starve a later producer.
        if(factory_)run_cursor_=(index+1)%threads_.size();
        const auto fault = run(*thread, budget);
        spent = thread->slice_ticks;
        if(fault==a64::Fault::none && thread->detached && thread->state==State::completed){release(*thread);thread.reset();}
        return fault;
    }
    return a64::Fault::unsupported_service;
}
a64::Fault NativeThreads::yield(bool full_frame) {
    rejection_={};
    if(std::this_thread::get_id()!=owner_){
        rejection_="sched_yield: native scheduling requires the owner thread";
        return a64::Fault::unsupported_service;
    }
    if(priority_restore_failed_){
        rejection_="sched_yield: native owner priority restoration failed";
        return a64::Fault::windows_service;
    }
    if(full_frame && deferred_yield_ && deferred_yield_())return a64::Fault::none;
    const bool pending=has_runnable();
    if(pending && !full_frame){
        rejection_="sched_yield: queued native progress requires a trusted full guest frame";
        return a64::Fault::unsupported_service;
    }
    std::this_thread::yield();
    if(!pending)return a64::Fault::none;
    // Reuse the same bounded runner, TLS/priority restoration, detached cleanup
    // and retained joinable result/failure as blocking native operations. Never
    // drain the queue, restart a failed peer or switch to a managed fiber here.
    std::uint64_t spent=0;
    const auto fault=run_next(1'000'000,spent);
    if(fault!=a64::Fault::none && rejection_.empty())rejection_="sched_yield: queued native execution failed";
    return fault;
}

a64::Fault NativeThreads::pump(std::uint64_t budget) {
    if(budget>1000000)budget=1000000;
    if(factory_){
        // One ordered pass, not a drain that mistakes a repeatedly yielding
        // long-lived task for an incomplete synchronous child call.
        for(auto &thread:threads_)if(thread && (thread->state==State::runnable ||
            (thread->state==State::waiting && thread->task && thread->task->state()!=GuestPosixServices::ThreadTaskState::waiting))){
            if(!budget)return a64::Fault::budget;
            const auto fault=run(*thread,budget);if(fault!=a64::Fault::none)return fault;
            budget=thread->slice_ticks>=budget?0:budget-thread->slice_ticks;
            if(thread->detached && thread->state==State::completed){release(*thread);thread.reset();}
        }
        return a64::Fault::none;
    }
    for(;;) {
        std::optional<Thread> *pending=nullptr;for(auto &thread:threads_)if(thread && thread->state==State::runnable){pending=&thread;break;}
        if(!pending)return a64::Fault::none;
        const auto fault=run(**pending,budget);if(fault!=a64::Fault::none)return fault;
        const auto spent=(*pending)->execution.ticks?(*pending)->execution.ticks:1;
        if((*pending)->detached && (*pending)->state==State::completed){release(**pending);pending->reset();}
        budget=spent>=budget?0:budget-spent;
    }
}
}
