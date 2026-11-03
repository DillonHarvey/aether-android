#include "signals.hpp"
#include "threads.hpp"
#include "aether/host/process_info.hpp"
#include "aether/common/thread_exit.hpp"
#include <algorithm>
#include <limits>
#include <utility>
#include <thread>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
constexpr std::uint32_t siginfo = 4, restart = 0x10000000, nodefer = 0x40000000, reset = 0x80000000, onstack = 0x08000000, autodisarm=0x80000000;
constexpr std::size_t signal_frame_size=4688,signal_area_size=signal_frame_size+16,context_offset=128,mcontext_offset=304,reserved_offset=592;
constexpr std::uint32_t fpsimd_magic=0x46508001,esr_magic=0x45535201;
constexpr std::uint64_t unblockable = (std::uint64_t{1} << 8) | (std::uint64_t{1} << 18);
constexpr auto error_result = std::numeric_limits<std::uint64_t>::max();
std::uint64_t bit(unsigned signal) { return std::uint64_t{1} << (signal - 1); }
bool on_alternate(const NativeSignalStack &stack,Address sp) {
    return !(stack.flags&autodisarm) && stack.size && sp>stack.base && sp-stack.base<=stack.size;
}
bool ignored_by_default(unsigned signal) { return signal == 17 || signal == 18 || signal == 23 || signal == 28; }
bool stops_by_default(unsigned signal) { return signal == 19 || signal == 20 || signal == 21 || signal == 22; }
template<std::size_t N> std::array<std::uint8_t, N> bytes(std::uint64_t value) {
    std::array<std::uint8_t, N> result{};
    for (std::size_t i = 0; i < N; ++i) result[i] = static_cast<std::uint8_t>(value >> (i * 8));
    return result;
}
std::uint64_t word(std::span<const std::uint8_t> input, std::size_t offset, unsigned length = 8) {
    std::uint64_t result = 0;
    for (unsigned i = 0; i < length; ++i) result |= std::uint64_t{input[offset + i]} << (i * 8);
    return result;
}
void put_word(std::span<std::uint8_t> output,std::size_t offset,std::uint64_t value,unsigned length=8) {
    for(unsigned i=0;i<length;++i)output[offset+i]=static_cast<std::uint8_t>(value>>(i*8));
}
void enqueue_signal(std::uint64_t &pending,NativeSignalInfos &information,unsigned signal,const NativeSignalInfo &info) {
    const auto value=bit(signal);
    if(!(pending&value))information[signal]=info;
    pending|=value;
}
a64::ArchitecturalState service_context(const a64::ServiceState &state) {
    if(state.resume)return *state.resume;
    return {state.registers,state.vectors,state.pc,state.stack_pointer,state.pstate,state.fpsr,state.fpcr};
}
} // namespace

void NativeSignals::runner(GuestPosixServices::SignalRunner value) { runner_ = std::move(value); }
void NativeSignals::fault_runner(GuestPosixServices::FaultSignalRunner value) { fault_runner_ = std::move(value); }
std::uint32_t NativeSignals::alarm(std::uint32_t seconds) {
    const auto now = AlarmClock::now();
    // Observe an expired timer before replacing/cancelling it. Cancellation
    // does not retract a signal that has already become process-pending.
    if (alarm_deadline_ && *alarm_deadline_ <= now) poll_alarm();
    std::uint32_t previous = 0;
    if (alarm_deadline_ && *alarm_deadline_ > now) {
        const auto remaining = *alarm_deadline_ - now;
        previous = static_cast<std::uint32_t>(std::chrono::ceil<std::chrono::seconds>(remaining).count());
    }
    alarm_deadline_.reset();
    if (seconds) alarm_deadline_ = now + std::chrono::seconds(seconds);
    return previous;
}
void NativeSignals::poll_alarm() noexcept {
    if (!alarm_deadline_ || AlarmClock::now() < *alarm_deadline_) return;
    alarm_deadline_.reset();
    // Alarm delivery is process-directed. A blocked caller must not retain the
    // signal privately when another logical thread can accept it.
    if (actions_[14].handler != 1)enqueue_signal(process_pending_,process_information_,14,NativeSignalInfo{128,0,0});
}
bool NativeSignals::ready() {
    poll_alarm();
    return ((threads_.signal_pending() | process_pending_) & ~(threads_.signal_mask() & ~unblockable)) != 0;
}
bool NativeSignals::wait_ready(std::uint32_t id,const std::shared_ptr<a64::ThreadRegisterState> &owner) const noexcept {
    const auto target=threads_.signal_snapshot(id,owner);
    if(!target)return false;
    auto pending=target->pending|process_pending_;
    if(alarm_deadline_ && AlarmClock::now()>=*alarm_deadline_ && actions_[14].handler!=1)pending|=bit(14);
    pending&=~(target->mask&~unblockable);
    for(unsigned signal=1;signal<32;++signal)if(pending&bit(signal)){
        const auto &action=actions_[signal];
        if(action.handler!=1 && (action.handler || !ignored_by_default(signal)))return true;
    }
    return false;
}
std::optional<NativeSignals::AlarmClock::time_point> NativeSignals::wait_deadline(std::uint32_t id,const std::shared_ptr<a64::ThreadRegisterState> &owner) const noexcept {
    const auto target=threads_.signal_snapshot(id,owner);
    if(!target || !alarm_deadline_ || (target->mask&bit(14)) || actions_[14].handler==1)return {};
    return alarm_deadline_;
}
std::optional<NativeSignals::IoInterruption> NativeSignals::io_interruption() {
    poll_alarm();
    const auto pending=(threads_.signal_pending()|process_pending_)&~(threads_.signal_mask()&~unblockable);
    for(unsigned signal=1;signal<32;++signal)if(pending&bit(signal)){
        const auto &action=actions_[signal];
        if(action.handler==1 || (!action.handler && ignored_by_default(signal)))continue;
        return IoInterruption{signal,action.handler>1 && (action.flags&restart)!=0};
    }
    return {};
}
bool NativeSignals::io_frame_ready(const IoInterruption &selected,const a64::ServiceState &state) const noexcept {
    if(selected.signal<1 || selected.signal>=32 || terminated_ || app_.process_state->exit_status() ||
       state.resume || !context_ready(state))return false;
    const auto target=threads_.current_signal_target();
    if(!target)return false;
    const auto pending=(*target->pending|process_pending_)&~(*target->mask&~unblockable);
    return (pending&bit(selected.signal)) && actions_[selected.signal].handler>1 &&
        pending_information(selected.signal).has_value();
}
Fault NativeSignals::broken_pipe(a64::ServiceState &state,bool full_frame) {
    constexpr unsigned signal=13;
    const auto pending_bit=bit(signal);
    const auto &action=actions_[signal];
    const bool blocked=(threads_.signal_mask()&pending_bit)!=0;
    // Blocked ignored signals still become pending: disposition can change
    // before unblocking. Preserve first-coalesced origin information.
    if(!blocked && action.handler==1)return Fault::none;
    if(!blocked && action.handler>1 && (!full_frame || depth_>=stack_frames_.size() ||
       (!context_ready(state) && (!runner_ || (action.flags&siginfo)))))return Fault::unsupported_service;
    auto *information=threads_.signal_information();
    if(!information)return Fault::unsupported_service;
    enqueue_signal(threads_.signal_pending(),*information,signal,
        NativeSignalInfo{0,host::current_process_id(),10000U+static_cast<std::uint32_t>(app_.instance_id%10000)});
    return blocked?Fault::none:deliver_pending(state,full_frame);
}
void NativeSignals::consume_pending(std::uint64_t value) {
    auto &local = threads_.signal_pending();
    if(local&value){
        local&=~value;
        if(auto *information=threads_.signal_information())for(unsigned signal=1;signal<32;++signal)if(value&bit(signal))(*information)[signal].reset();
    }else discard_process_pending(value);
}
void NativeSignals::discard_process_pending(std::uint64_t value) noexcept {
    process_pending_&=~value;
    for(unsigned signal=1;signal<32;++signal)if(value&bit(signal))process_information_[signal].reset();
}
void NativeSignals::discard_pending(std::uint64_t value) noexcept {
    threads_.discard_signal_pending(value);discard_process_pending(value);
}
std::optional<NativeSignalInfo> NativeSignals::pending_information(unsigned signal) const noexcept {
    if(signal>=32)return {};
    const auto target=threads_.current_signal_target();
    if(target && (*target->pending&bit(signal)))return (*target->information)[signal];
    if(process_pending_&bit(signal))return process_information_[signal];
    return {};
}
bool NativeSignals::context_ready(const a64::ServiceState &state) const noexcept {
    if(!fault_runner_ || !state.invocation || !state.operation_allowance(1'000'000) || depth_>=stack_frames_.size() ||
       state.trusted_tls!=threads_.tls() || !threads_.thread_register_state(state.trusted_tls))return false;
    const auto context=service_context(state);
    return context.pc<a64::GuestMemory::address_limit && context.sp<=a64::GuestMemory::address_limit &&
        !(context.pstate&~std::uint32_t{0xf0000000});
}
bool NativeSignals::frame_ready(const a64::ServiceState &state) const noexcept {
    if(terminated_ || app_.process_state->exit_status() || state.resume || !context_ready(state))return false;
    const auto target=threads_.current_signal_target();
    if(!target)return false;
    const auto pending=(*target->pending|process_pending_)&~(*target->mask&~unblockable);
    for(unsigned signal=1;signal<32;++signal)if(pending&bit(signal)){
        const auto &action=actions_[signal];
        if(action.handler==1 || (!action.handler && ignored_by_default(signal)))continue;
        return action.handler>1 && pending_information(signal).has_value();
    }
    return false;
}
bool NativeSignals::pending_signal_entry(const a64::SignalEntry &entry,Address tls,std::uint64_t invocation) const noexcept {
    if(!depth_)return false;
    const auto &active=stack_frames_[depth_-1];
    return active.frame && active.frame==entry.frame && entry.state.sp==active.frame && entry.state.pc==active.handler &&
        active.invocation==invocation && active.tls==tls && threads_.tls()==tls && active.owner==threads_.tid() &&
        active.registers && active.registers==threads_.thread_register_state(tls);
}
Fault NativeSignals::fail(a64::ServiceState &state, unsigned value, std::uint64_t result) {
    if (!memory_.write(threads_.error_address(), bytes<4>(value))) return Fault::write;
    state.registers[0] = result;
    return Fault::none;
}
Fault NativeSignals::validate(const Action &action) const {
    if (action.flags & ~(siginfo | restart | nodefer | reset | onstack)) return Fault::unsupported_service;
    if (action.handler>1 && (action.flags&siginfo) && !fault_runner_)return Fault::unsupported_service;
    if (action.handler > 1 && (action.handler % 4 || !memory_.accessible(action.handler, 4, a64::Permission::execute)))
        return Fault::execute;
    return Fault::none;
}
Fault NativeSignals::alternate_stack(a64::ServiceState &state,bool full_frame) {
    if(!full_frame)return Fault::unsupported_service;
    auto &r=state.registers;std::array<std::uint8_t,24> input{};
    if(r[0] && !memory_.read(r[0],input))return fail(state,14,error_result);
    auto &current=threads_.current_signal_stack();const auto previous=current;
    const auto old_flags=(previous.size?(on_alternate(previous,state.stack_pointer)?1U:0U):2U)|(previous.flags&autodisarm);
    if(r[0]){
        if(on_alternate(previous,state.stack_pointer))return fail(state,1,error_result);
        const auto flags=static_cast<std::uint32_t>(word(input,8,4)),mode=flags&~autodisarm;
        if(mode>2)return fail(state,22,error_result);
        NativeSignalStack next{word(input,0),word(input,16),flags};
        if(mode==2){next.base=0;next.size=0;}
        else if(next.size<5120)return fail(state,12,error_result);
        current=next; // The kernel commits before attempting to copy old state out.
    }
    if(r[1]){
        std::array<std::uint8_t,24> output{};
        const auto base=bytes<8>(previous.base),size=bytes<8>(previous.size);const auto flags=bytes<4>(old_flags);
        std::copy(base.begin(),base.end(),output.begin());std::copy(flags.begin(),flags.end(),output.begin()+8);
        std::copy(size.begin(),size.end(),output.begin()+16);
        if(!memory_.write(r[1],output))return fail(state,14,error_result);
    }
    r[0]=0;return Fault::none;
}

struct NativeSignals::DeferredSigwait final : a64::DeferredService {
    NativeSignals &p;
    std::uint64_t requested,invocation;
    Address output,tls,stack_top;std::uint32_t tid;
    std::shared_ptr<a64::ThreadRegisterState> owner;
    DeferredSigwait(NativeSignals &p,std::uint64_t requested,const a64::ServiceState &frame):
        p(p),requested(requested),invocation(frame.invocation),output(frame.registers[1]),tls(frame.trusted_tls),
        stack_top(frame.stack_top),tid(p.threads_.tid()),owner(p.threads_.thread_register_state(tls)) {}
    bool ready() const noexcept override {
        if(!p.app_.process_state || p.app_.process_state->exit_status() || p.terminated_)return true;
        const auto target=p.threads_.signal_snapshot(tid,owner);
        if(!target)return true;
        // sigwait accepts matching pending signals even when blocked. The
        // snapshot proves the owner; its current mask must not filter this set.
        auto pending=target->pending|p.process_pending_;
        if((requested&bit(14)) && p.alarm_deadline_ && AlarmClock::now()>=*p.alarm_deadline_ && p.actions_[14].handler!=1)
            pending|=bit(14);
        return (pending&requested)!=0;
    }
    std::optional<AlarmClock::time_point> deadline() const noexcept override {
        if(!p.threads_.signal_snapshot(tid,owner) || !(requested&bit(14)) || p.actions_[14].handler==1)return {};
        return p.alarm_deadline_;
    }
    a64::DeferredServiceResult resume(a64::ServiceState &frame) noexcept override {
        try {
            if(!p.app_.process_state)return {Fault::invalid_call,true};
            if(p.app_.process_state->exit_status() || p.terminated_)return {Fault::process_exit,true};
            if(!owner || !p.threads_.signal_snapshot(tid,owner) || p.threads_.tid()!=tid || p.threads_.tls()!=tls ||
               frame.trusted_tls!=tls || frame.invocation!=invocation || frame.stack_top!=stack_top ||
               p.threads_.thread_register_state(tls)!=owner)return {Fault::invalid_call,true};
            // A readiness hint never queues or consumes a signal. Only this
            // restored owner commits a due alarm and selects actual pending data.
            p.poll_alarm();
            const auto pending=(p.threads_.signal_pending()|p.process_pending_)&requested;
            if(!pending)return {Fault::none,false};
            unsigned signal=1;while(!(pending&bit(signal)))++signal;
            if(signal>=32)return {Fault::unsupported_service,true};
            // Preserve local/process provenance and pending information until
            // the whole int write succeeds. No guest callback crosses this pair.
            if(!p.memory_.write(output,bytes<4>(signal)))return {Fault::write,true};
            p.consume_pending(bit(signal));
            frame.registers[0]=0;return {Fault::none,true};
        }catch(...){return {Fault::unsupported_service,true};}
    }
};
Fault NativeSignals::invoke(unsigned operation, a64::ServiceState &state, bool full_frame,bool allow_deferred) {
    if (terminated_) return Fault::process_exit;
    poll_alarm();
    auto &registers = state.registers;
    if (operation == 4) {
        std::array<std::uint8_t, 8> input{};
        // Bionic reads the caller's sigset in userspace before entering the wait.
        if (!memory_.read(registers[0], input)) return Fault::read;
        auto requested = word(input, 0);
        // Match sigtimedwait64's SIG_SETMASK reserved-signal filtering. The
        // kernel also removes SIGKILL/SIGSTOP from the accepted wait set.
        constexpr auto timer = std::uint64_t{1} << 31;
        constexpr auto reserved = (std::uint64_t{1} << 41) - (std::uint64_t{1} << 32);
        requested = ((requested | timer) & ~reserved) & ~unblockable;
        auto ready = (threads_.signal_pending() | process_pending_) & requested;
        // The live process alarm is an actual bounded signal producer. It can
        // satisfy a synchronous wait without inventing a parked continuation.
        if (!ready && threads_.factory_execution_active()){
            // Realtime delivery requires a queue. Do not pretend an RT-only
            // requested set has a supported future producer in this profile.
            constexpr auto standard=(std::uint64_t{1}<<31)-1;
            if(!(requested&standard))return Fault::unsupported_service;
            if(!full_frame || !allow_deferred || !switch_safe())return Fault::unsupported_service;
            if(!state.invocation || state.trusted_tls!=threads_.tls() || state.resume || state.deferred ||
               !threads_.signal_snapshot(threads_.tid(),threads_.thread_register_state(state.trusted_tls)))return Fault::invalid_call;
            // Copy the filtered set/output and allocate the entire operation
            // before any acceptance. Unmatched handlers belong to the host's
            // outer pthread wait protocol; they do not consume this wait set.
            state.deferred=std::make_shared<DeferredSigwait>(*this,requested,state);
            return Fault::none;
        }
        if (!ready && (requested & bit(14)) && alarm_deadline_) {
            std::this_thread::sleep_until(*alarm_deadline_);
            poll_alarm();
            ready = (threads_.signal_pending() | process_pending_) & requested;
        }
        // Unmatched waits without a live supported producer stay explicit.
        if (!ready) return Fault::unsupported_service;
        unsigned signal = 1;
        while (!(ready & bit(signal))) ++signal;
        if (signal >= 32) return Fault::unsupported_service;
        // Successful sigwait writes an int, bypassing the installed handler.
        // Preflight output so a fault never loses a pending guest signal.
        if (!memory_.write(registers[1], bytes<4>(signal))) return Fault::write;
        consume_pending(bit(signal));
        registers[0] = 0;
        return Fault::none;
    }
    if (operation == 3) {
        const auto pending = (threads_.signal_pending() | process_pending_) & threads_.signal_mask() & ~unblockable;
        if (!memory_.write(registers[0], bytes<8>(pending))) return fail(state, 14, error_result);
        registers[0] = 0;
        return Fault::none;
    }
    if (operation > 3) return Fault::unsupported_service;
    const auto signal = static_cast<std::int32_t>(registers[0]);
    if (signal < (operation == 2 ? 0 : 1) || signal > 64) return fail(state, 22, error_result);
    if (operation == 2) {
        if (!signal) { registers[0] = 0; return Fault::none; }
        // A bitset faithfully coalesces standard signals. Realtime signals require a queue.
        if (signal >= 32) return Fault::unsupported_service;
        const auto number = static_cast<unsigned>(signal);
        const auto mask = bit(number);
        const auto action = actions_[number];
        const bool blocked = (threads_.signal_mask() & mask & ~unblockable) != 0;
        if (!blocked) {
            if (action.handler == 1 || (!action.handler && ignored_by_default(number))) {
                if (number == 18) discard_pending(bit(19) | bit(20) | bit(21) | bit(22));
                else if (stops_by_default(number)) discard_pending(bit(18));
                registers[0] = 0; return Fault::none;
            }
            if (!action.handler && stops_by_default(number)) return Fault::unsupported_service;
            if(action.handler>1 && (!full_frame || depth_>=stack_frames_.size() ||
                (!context_ready(state) && (!runner_ || (action.flags&siginfo)))))return Fault::unsupported_service;
        }
        if (number == 18) discard_pending(bit(19) | bit(20) | bit(21) | bit(22));
        else if (stops_by_default(number)) discard_pending(bit(18));
        auto *information=threads_.signal_information();
        if(!information)return Fault::unsupported_service;
        enqueue_signal(threads_.signal_pending(),*information,number,
            NativeSignalInfo{-6,host::current_process_id(),10000U+static_cast<std::uint32_t>(app_.instance_id%10000)});
        registers[0] = 0;
        if (!blocked) {
            const auto fault = deliver_pending(state, full_frame);
            if (fault != Fault::none) return fault;
        }
        return Fault::none;
    }
    const auto number = static_cast<unsigned>(signal);
    const bool updating = operation == 0 || registers[1] != 0;
    if (updating && (number == 9 || number == 19)) return fail(state, 22, error_result);
    Action next;
    if (operation == 0) {
        next.flags = restart; next.handler = registers[1];
    } else if (updating) {
        std::array<std::uint8_t, 32> input{};
        if (!memory_.read(registers[1], input)) return Fault::read;
        next.flags = static_cast<std::uint32_t>(word(input, 0, 4));
        next.handler = word(input, 8);
        next.mask = word(input, 16) & ~unblockable;
        // Bionic arm64 does not copy the supplied sa_restorer into the kernel action.
    }
    if (updating) {
        const auto fault = validate(next);
        if (fault != Fault::none) return fault;
    }
    const auto previous = actions_[number];
    if (operation == 1 && registers[2]) {
        std::array<std::uint8_t, 32> output{};
        const auto flags = bytes<4>(previous.flags);
        const auto handler = bytes<8>(previous.handler), old_mask = bytes<8>(previous.mask);
        std::copy(flags.begin(), flags.end(), output.begin());
        std::copy(handler.begin(), handler.end(), output.begin() + 8);
        std::copy(old_mask.begin(), old_mask.end(), output.begin() + 16);
        if (!memory_.write(registers[2], output)) return Fault::write;
    }
    if (updating) {
        actions_[number] = next;
        if (next.handler == 1 || (!next.handler && ignored_by_default(number))) {
            discard_pending(bit(number));
        }
    }
    registers[0] = operation == 0 ? previous.handler : 0;
    return Fault::none;
}

Fault NativeSignals::tgkill(std::uint64_t group_bits,std::uint64_t target_bits,std::uint64_t signal_bits,a64::ServiceState &state,bool full_frame) {
    const auto group=static_cast<std::int32_t>(group_bits),target=static_cast<std::int32_t>(target_bits),signal=static_cast<std::int32_t>(signal_bits);
    if(group<=0 || target<=0)return fail(state,22,error_result);
    if(static_cast<std::uint32_t>(group)!=host::current_process_id())return fail(state,3,error_result);
    const auto destination=threads_.signal_target(static_cast<std::uint32_t>(target));
    if(!destination)return fail(state,3,error_result);
    if(signal<0 || signal>64)return fail(state,22,error_result);
    if(!signal){state.registers[0]=0;return Fault::none;}
    if(signal>=32)return Fault::unsupported_service; // Realtime delivery needs a queue, not a bitset.
    // SIGKILL takes precedence over older ready handlers, including self sends.
    if(signal==9){app_.process_state->request_signal(9);terminated_=true;return Fault::process_exit;}
    if(static_cast<std::uint32_t>(target)==threads_.tid()){
        auto delivery=state;delivery.registers[0]=static_cast<unsigned>(signal);
        const auto fault=invoke(2,delivery,full_frame);
        if(fault==Fault::none)state=std::move(delivery);
        return fault;
    }
    const auto number=static_cast<unsigned>(signal);const auto value=bit(number);
    const auto action=actions_[number];
    const bool blocked=(*destination->mask & value & ~unblockable)!=0;
    if(!blocked && !action.handler && stops_by_default(number))return Fault::unsupported_service;
    if(number==18)discard_pending(bit(19)|bit(20)|bit(21)|bit(22));
    else if(stops_by_default(number))discard_pending(bit(18));
    if(!blocked && (action.handler==1 || (!action.handler && ignored_by_default(number)))){state.registers[0]=0;return Fault::none;}
    enqueue_signal(*destination->pending,*destination->information,number,
        NativeSignalInfo{-6,host::current_process_id(),10000U+static_cast<std::uint32_t>(app_.instance_id%10000)});
    state.registers[0]=0;return Fault::none;
}

Fault NativeSignals::abort(a64::ServiceState &state,bool full_frame,ProcessState &process) {
    if(process.exit_status())return Fault::process_exit;
    if(aborting_){process.request_signal(6);return Fault::process_exit;}
    aborting_=true;
    // Fatal state is committed after the first handler, including exceptional unwind.
    struct Finish {bool &active;ProcessState &process;~Finish(){process.request_signal(6);active=false;}} finish{aborting_,process};
    constexpr auto mask=std::uint64_t{1}<<5;
    threads_.signal_mask() &= ~mask;
    auto deliver=[&]{
        const auto fault=deliver_pending(state,full_frame,mask);
        if(fault!=Fault::none && fault!=Fault::process_exit)abort_failure_=fault;
        return fault;
    };
    // Unblocking an existing pending SIGABRT and the explicit raise are separate.
    if((threads_.signal_pending() | process_pending_) & mask){
        const auto interrupted=service_context(state);
        if(deliver()!=Fault::none || process.exit_status())return Fault::process_exit;
        if(state.resume){
            // Continue this distinct abort step only after an actual ordinary
            // return. A redirected context must not invent a second raise.
            const auto resumed=*state.resume;
            if(resumed.pc!=interrupted.pc || resumed.sp!=interrupted.sp)return Fault::process_exit;
            state.registers=resumed.registers;state.vectors=resumed.vectors;
            state.stack_pointer=resumed.sp;state.pc=resumed.pc;state.pstate=resumed.pstate;
            state.fpsr=resumed.fpsr;state.fpcr=resumed.fpcr;state.resume.reset();
        }
    }
    if(actions_[6].handler>1){
        auto *information=threads_.signal_information();
        if(!information)return Fault::unsupported_service;
        enqueue_signal(threads_.signal_pending(),*information,6,
            NativeSignalInfo{-6,host::current_process_id(),10000U+static_cast<std::uint32_t>(app_.instance_id%10000)});
        if(deliver()!=Fault::none || process.exit_status())return Fault::process_exit;
    }
    actions_[6]={};
    threads_.signal_pending()&=~mask;
    if(auto *information=threads_.signal_information())(*information)[6].reset();
    discard_process_pending(mask);
    return Fault::process_exit;
}

a64::CpuFaultAction NativeSignals::synchronous_fault(const a64::CpuException &exception,a64::ArchitecturalState &candidate,
                                                    const a64::CpuFaultBoundary &boundary) {
    using a64::CpuFaultAction;
    using a64::CpuExceptionKind;
    if(terminated_ || app_.process_state->exit_status())return CpuFaultAction::unhandled;
    const auto registers=threads_.thread_register_state(boundary.tls);
    if(!boundary.invocation || !registers || boundary.tls!=threads_.tls())return CpuFaultAction::unhandled;
    unsigned signal=0,code=0;
    auto fault_address=exception.address;
    switch(exception.kind){
    case CpuExceptionKind::undefined_encoding:signal=4;code=1;break;
    case CpuExceptionKind::breakpoint:signal=5;code=1;break;
    case CpuExceptionKind::data_alignment:
    case CpuExceptionKind::stack_alignment:signal=7;code=1;break;
    case CpuExceptionKind::instruction_abort:
        if(exception.address%4){signal=7;code=1;break;}
        [[fallthrough]];
    case CpuExceptionKind::read_abort:
    case CpuExceptionKind::write_abort:
    case CpuExceptionKind::data_cache_abort:
    case CpuExceptionKind::instruction_cache_abort: {
        // This proof was captured at the failed predicate, before any handler
        // can change mappings. The operation's start and intent do not identify
        // the first failing byte or the permission actually checked.
        if(!exception.memory_failure)return CpuFaultAction::unhandled;
        const auto &failure=*exception.memory_failure;
        switch(failure.kind){
        case a64::MemoryFailureKind::invalid:return CpuFaultAction::unhandled;
        case a64::MemoryFailureKind::unmapped:signal=11;code=1;break;
        case a64::MemoryFailureKind::protection:signal=11;code=2;break;
        }
        fault_address=failure.address;
        break;
    }
    }
    if(!signal)return CpuFaultAction::unhandled;
    const auto terminal=[&](unsigned value){
        GuestSignalFault fault;
        fault.kind=static_cast<std::uint32_t>(exception.kind);
        fault.subtype=exception.subtype;fault.access_bytes=exception.access_bytes;fault.signal_code=code;
        fault.pc=exception.state.pc;fault.sp=exception.state.sp;fault.address=exception.address;
        fault.registers=exception.state.registers;
        if(exception.memory_failure){
            fault.has_memory_failure=true;
            fault.memory_kind=static_cast<std::uint32_t>(exception.memory_failure->kind);
            fault.permission=static_cast<std::uint32_t>(exception.memory_failure->permission);
            fault.memory_address=exception.memory_failure->address;
        }
        // Only this classified, unhandled synchronous exception supplies an
        // architectural record. Raised signals and handler-validation errors
        // retain their distinct signal-only cause. An earlier cause wins.
        app_.process_state->request_signal(static_cast<std::uint8_t>(value),fault);
        terminated_=true;
        return CpuFaultAction::unhandled;
    };
    auto action=actions_[signal];
    const auto signal_bit=bit(signal);
    const auto old_mask=threads_.signal_mask();
    // Forced synchronous faults cannot be deferred or swallowed by SIG_IGN.
    if(action.handler==1 || (old_mask&signal_bit)){
        actions_[signal].handler=0;
        threads_.signal_mask()=old_mask&~signal_bit;
        action.handler=0;
    }
    if(!action.handler)return terminal(signal);
    a64::ArchitecturalState restored;
    const NativeSignalInfo info{static_cast<std::int32_t>(code),0,0};
    if(deliver_frame(signal,info,fault_address,exception.state,restored,boundary,false)!=Fault::none)
        return CpuFaultAction::unhandled;
    candidate=restored;
    return CpuFaultAction::resume;
}

Fault NativeSignals::deliver_frame(unsigned signal,const NativeSignalInfo &info,std::optional<Address> fault_address,
                                   const a64::ArchitecturalState &state,a64::ArchitecturalState &candidate,
                                   const a64::CpuFaultBoundary &boundary,bool pending) {
    const auto owner=threads_.tid();
    const auto registers=threads_.thread_register_state(boundary.tls);
    if(!boundary.invocation || !registers || boundary.tls!=threads_.tls())return Fault::unsupported_service;
    const auto action=actions_[signal];
    const auto signal_bit=bit(signal);
    const auto terminal=[&](unsigned value){
        app_.process_state->request_signal(static_cast<std::uint8_t>(value));
        terminated_=true;
        return Fault::process_exit;
    };
    if(!fault_runner_ || depth_>=stack_frames_.size() || !boundary.operation_allowance(1'000'000))return Fault::unsupported_service;
    const auto execute=fault_runner_; // Pin before callback replacement/reentry.
    if(validate(action)!=Fault::none)return terminal(11);
    const auto same_owner=[&]()noexcept{
        return threads_.tid()==owner && threads_.tls()==boundary.tls &&
            threads_.thread_register_state(boundary.tls)==registers;
    };
    const auto saved_mask=threads_.signal_mask();
    const auto saved_alternate=threads_.current_signal_stack();
    auto top=state.sp;
    StackFrame bounds{};
    for(unsigned i=depth_;i>0;--i){
        const auto &active=stack_frames_[i-1];
        if(active.owner==owner && top>active.base && top<=active.end){bounds=active;break;}
    }
    if(saved_alternate.size && !(saved_alternate.flags&2U)){
        if(saved_alternate.base>=a64::GuestMemory::address_limit || saved_alternate.size>a64::GuestMemory::address_limit-saved_alternate.base){
            if(action.flags&onstack)return terminal(11);
        }else{
            const auto end=saved_alternate.base+saved_alternate.size;
            if((action.flags&onstack) && !on_alternate(saved_alternate,top)){
                top=end;bounds={owner,saved_alternate.base,end};
            }else if(top>saved_alternate.base && top<=end)bounds={owner,saved_alternate.base,end};
        }
    }
    if(top<signal_area_size || top>a64::GuestMemory::address_limit)return terminal(11);
    const auto record=(top-16)&~Address{15};
    if(record<signal_frame_size)return terminal(11);
    const auto frame=record-signal_frame_size;
    if(bounds.end && (frame<bounds.base || record+16>bounds.end))return terminal(11);
    if(!memory_.accessible(frame,signal_area_size,a64::Permission::write))return terminal(11);
    std::array<std::uint8_t,signal_area_size> data{};
    put_word(data,0,signal,4);put_word(data,8,static_cast<std::uint32_t>(info.code),4);
    if(fault_address)put_word(data,16,*fault_address);
    else if(info.code==-6){put_word(data,16,info.pid,4);put_word(data,20,info.uid,4);}
    const auto alternate_flags=(saved_alternate.size?(on_alternate(saved_alternate,state.sp)?1U:0U):2U)|(saved_alternate.flags&autodisarm);
    put_word(data,context_offset+16,saved_alternate.base);
    put_word(data,context_offset+24,alternate_flags,4);
    put_word(data,context_offset+32,saved_alternate.size);
    put_word(data,context_offset+40,saved_mask);
    put_word(data,mcontext_offset,fault_address.value_or(0));
    for(std::size_t i=0;i<state.registers.size();++i)put_word(data,mcontext_offset+8+i*8,state.registers[i]);
    put_word(data,mcontext_offset+256,state.sp);
    put_word(data,mcontext_offset+264,state.pc);
    put_word(data,mcontext_offset+272,state.pstate);
    put_word(data,reserved_offset,fpsimd_magic,4);put_word(data,reserved_offset+4,528,4);
    put_word(data,reserved_offset+8,state.fpsr,4);put_word(data,reserved_offset+12,state.fpcr,4);
    for(std::size_t i=0;i<state.vectors.size();++i){
        put_word(data,reserved_offset+16+i*16,state.vectors[i][0]);
        put_word(data,reserved_offset+24+i*16,state.vectors[i][1]);
    }
    put_word(data,signal_frame_size,state.registers[29]);
    put_word(data,signal_frame_size+8,state.registers[30]);
    if(!memory_.write(frame,data))return terminal(11);
    a64::SignalEntry entry{state,frame};
    entry.state.pc=action.handler;entry.state.sp=frame;
    entry.state.registers[0]=signal;
    entry.state.registers[29]=record;entry.state.registers[30]=a64::GuestCpu::signal_restorer;
    if(action.flags&siginfo){entry.state.registers[1]=frame;entry.state.registers[2]=frame+context_offset;}
    if(pending)consume_pending(signal_bit);
    if(action.flags&reset)actions_[signal].handler=0;
    threads_.signal_mask()=(saved_mask|action.mask|((action.flags&nodefer)?0:signal_bit))&~unblockable;
    if(saved_alternate.flags&autodisarm)threads_.current_signal_stack()={};
    const auto slot=depth_++;
    bounds.owner=owner;bounds.frame=frame;bounds.handler=action.handler;bounds.tls=boundary.tls;
    bounds.invocation=boundary.invocation;bounds.registers=registers;
    stack_frames_[slot]=std::move(bounds);
    ++delivery_serial_;
    struct Restore {
        NativeSignals &self;
        decltype(same_owner) &same;
        std::uint64_t mask;
        NativeSignalStack alternate;
        unsigned slot;
        bool committed=false;
        ~Restore(){
            self.stack_frames_[slot]={};--self.depth_;
            if(!committed && same()){
                self.threads_.signal_mask()=mask;
                self.threads_.current_signal_stack()=alternate;
            }
        }
    } restore{*this,same_owner,saved_mask,saved_alternate,slot};
    a64::ExecutionResult result;
    try{result=execute(entry,boundary.tls,boundary.operation_allowance(1'000'000));}
    catch(const ProcessExit &exit){
        if(exit.signal)app_.process_state->request_signal(exit.signal);else app_.process_state->request_exit(exit.status);
        return Fault::process_exit;
    }catch(const ThreadExit &exit){threads_.request_exit(exit.value);return Fault::thread_exit;}
    if(app_.process_state->exit_status() || terminated_)return Fault::process_exit;
    if(threads_.exit_value(boundary.tls))return Fault::thread_exit;
    if(!same_owner())return Fault::unsupported_service;
    if(result.fault!=Fault::none)return result.fault;
    if(!result.returned || !result.signal_return)return Fault::unsupported_service;
    if(!memory_.read(frame,data))return terminal(11);
    const auto pstate=word(data,mcontext_offset+272);
    if(pstate&~std::uint64_t{0xf0000000})return terminal(11);
    a64::ArchitecturalState restored;
    restored.pc=word(data,mcontext_offset+264);restored.sp=word(data,mcontext_offset+256);
    if(restored.pc>=a64::GuestMemory::address_limit || restored.sp>a64::GuestMemory::address_limit)return terminal(11);
    restored.pstate=static_cast<std::uint32_t>(pstate);
    for(std::size_t i=0;i<restored.registers.size();++i)restored.registers[i]=word(data,mcontext_offset+8+i*8);
    std::size_t fp_offset=0;
    bool ended=false;
    for(std::size_t offset=reserved_offset;offset<signal_frame_size;){
        if(signal_frame_size-offset<8 || offset%16)return terminal(11);
        const auto magic=static_cast<std::uint32_t>(word(data,offset,4));
        const auto size=static_cast<std::uint32_t>(word(data,offset+4,4));
        if(!magic){if(size)return terminal(11);ended=true;break;}
        if(size<8 || size>signal_frame_size-offset || size%16)return terminal(11);
        if(magic==fpsimd_magic){if(fp_offset || size!=528)return terminal(11);fp_offset=offset;}
        else if(magic!=esr_magic || size!=16)return terminal(11);
        offset+=size;
    }
    if(!ended || !fp_offset)return terminal(11);
    restored.fpsr=static_cast<std::uint32_t>(word(data,fp_offset+8,4));
    restored.fpcr=static_cast<std::uint32_t>(word(data,fp_offset+12,4));
    for(std::size_t i=0;i<restored.vectors.size();++i){
        restored.vectors[i][0]=word(data,fp_offset+16+i*16);
        restored.vectors[i][1]=word(data,fp_offset+24+i*16);
    }
    NativeSignalStack restored_alternate{word(data,context_offset+16),word(data,context_offset+32),
        static_cast<std::uint32_t>(word(data,context_offset+24,4))};
    const auto mode=restored_alternate.flags&~autodisarm;
    if(mode>2)return terminal(11);
    if(mode==2){restored_alternate.base=0;restored_alternate.size=0;}
    else{
        if(restored_alternate.size<5120 || restored_alternate.base>=a64::GuestMemory::address_limit ||
           restored_alternate.size>a64::GuestMemory::address_limit-restored_alternate.base)return terminal(11);
        restored_alternate.flags&=~1U; // SS_ONSTACK is observed status, not registration.
    }
    threads_.signal_mask()=word(data,context_offset+40)&~unblockable;
    threads_.current_signal_stack()=restored_alternate;
    candidate=restored;
    restore.committed=true;
    return Fault::none;
}

Fault NativeSignals::deliver_pending(a64::ServiceState &state, bool full_frame, std::uint64_t allowed) {
    if (terminated_) return Fault::process_exit;
    if(state.resume)return Fault::none;
    poll_alarm();
    for (unsigned work = 0; work < 64; ++work) {
        const auto ready = (threads_.signal_pending() | process_pending_) & ~(threads_.signal_mask() & ~unblockable) & allowed;
        if (!ready) return Fault::none;
        unsigned signal = 1;
        while (!(ready & bit(signal))) ++signal;
        if (signal >= 32) return Fault::unsupported_service;
        const auto pending_bit = bit(signal);
        const auto action = actions_[signal]; // Handler can replace the process-wide disposition.
        if (action.handler == 1 || (!action.handler && ignored_by_default(signal))) {
            consume_pending(pending_bit);
            continue;
        }
        if (!action.handler) {
            if (stops_by_default(signal)) return Fault::unsupported_service;
            consume_pending(pending_bit);
            app_.process_state->request_signal(static_cast<std::uint8_t>(signal));
            terminated_ = true;
            return Fault::process_exit;
        }
        if(full_frame && context_ready(state)){
            const auto information=pending_information(signal);
            if(information){
                const auto context=service_context(state);
                const a64::CpuFaultBoundary boundary{state.trusted_tls,state.invocation,state.stack_top,state.remaining_budget,
                    state.resource_metered,state.instruction_limit};
                a64::ArchitecturalState restored;
                const auto fault=deliver_frame(signal,*information,{},context,restored,boundary,true);
                if(fault==Fault::none)state.resume=restored;
                return fault; // The CPU commits this context before another handler.
            }
        }
        // Frameless legacy callers cannot fabricate a three-argument context.
        if(action.flags&siginfo)return Fault::unsupported_service;
        if (!full_frame || !runner_ || depth_ >= 8) return Fault::unsupported_service;
        const auto executable = validate(action);
        if (executable != Fault::none) return executable;
        auto &alternate=threads_.current_signal_stack();const auto saved_alternate=alternate;
        auto pointer=state.stack_pointer;StackFrame bounds{};
        // Retain the real active range even while autodisarm hides its registration.
        for(unsigned i=depth_;i>0;--i){const auto &active=stack_frames_[i-1];if(active.owner==threads_.tid() && pointer>active.base && pointer<=active.end){bounds=active;break;}}
        if(alternate.size && !(alternate.flags&2U)){
            if(alternate.base>=a64::GuestMemory::address_limit || alternate.size>a64::GuestMemory::address_limit-alternate.base){
                if(action.flags&onstack)return Fault::write;
            }else{
                const auto end=alternate.base+alternate.size;
                if((action.flags&onstack) && !on_alternate(alternate,pointer)){
                    pointer=end&~Address{15};bounds={threads_.tid(),alternate.base,end};
                }else if(pointer>alternate.base && pointer<=end)bounds={threads_.tid(),alternate.base,end};
            }
        }
        if(pointer<272 || pointer%16)return Fault::write;
        const auto stack=pointer-256;
        if(bounds.end && (stack<bounds.base || stack-bounds.base<16))return Fault::write;
        if(!memory_.accessible(stack-16,16,a64::Permission::write))return Fault::write;
        consume_pending(pending_bit);
        if (action.flags & reset) actions_[signal].handler = 0;
        auto &mask = threads_.signal_mask();
        const auto saved = mask;
        mask = (saved | action.mask | ((action.flags & nodefer) ? 0 : pending_bit)) & ~unblockable;
        const bool disarmed=(alternate.flags&autodisarm)!=0;
        if(disarmed)alternate={};
        bounds.frame=0;bounds.handler=0;bounds.tls=0;bounds.invocation=0;bounds.registers.reset();
        stack_frames_[depth_]=std::move(bounds);
        ++depth_;
        ++delivery_serial_;
        struct Restore {
            std::uint64_t &mask;std::uint64_t saved;unsigned &depth;
            NativeSignalStack &alternate;NativeSignalStack previous;bool disarmed;
            std::array<StackFrame,8> &frames;
            ~Restore(){mask=saved;if(disarmed)alternate=previous;frames[--depth]={};}
        } restore{mask,saved,depth_,alternate,saved_alternate,disarmed,stack_frames_};
        const auto result = runner_(action.handler, signal, stack, threads_.tls());
        if (terminated_) return Fault::process_exit;
        if (!result.returned) return result.fault == Fault::none ? Fault::invalid_call : result.fault;
    }
    return ((threads_.signal_pending() | process_pending_) & ~(threads_.signal_mask() & ~unblockable) & allowed) ? Fault::unsupported_service : Fault::none;
}
} // namespace aether::bionic
