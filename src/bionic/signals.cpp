#include "signals.hpp"
#include "threads.hpp"
#include "aether/host/process_info.hpp"
#include <algorithm>
#include <limits>
#include <utility>
#include <thread>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
constexpr std::uint32_t restart = 0x10000000, nodefer = 0x40000000, reset = 0x80000000, onstack = 0x08000000, autodisarm=0x80000000;
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
} // namespace

void NativeSignals::runner(GuestPosixServices::SignalRunner value) { runner_ = std::move(value); }
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
    if (actions_[14].handler != 1) process_pending_ |= bit(14);
}
bool NativeSignals::ready() {
    poll_alarm();
    return ((threads_.signal_pending() | process_pending_) & ~(threads_.signal_mask() & ~unblockable)) != 0;
}
void NativeSignals::consume_pending(std::uint64_t value) {
    auto &local = threads_.signal_pending();
    if (local & value) local &= ~value;
    else process_pending_ &= ~value;
}
Fault NativeSignals::fail(a64::ServiceState &state, unsigned value, std::uint64_t result) {
    if (!memory_.write(threads_.error_address(), bytes<4>(value))) return Fault::write;
    state.registers[0] = result;
    return Fault::none;
}
Fault NativeSignals::validate(const Action &action) const {
    if (action.flags & ~(restart | nodefer | reset | onstack)) return Fault::unsupported_service;
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

Fault NativeSignals::invoke(unsigned operation, a64::ServiceState &state, bool full_frame) {
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
                if (number == 18) threads_.discard_signal_pending(bit(19) | bit(20) | bit(21) | bit(22));
                else if (stops_by_default(number)) threads_.discard_signal_pending(bit(18));
                registers[0] = 0; return Fault::none;
            }
            if (!action.handler && stops_by_default(number)) return Fault::unsupported_service;
            if (action.handler > 1 && (!full_frame || !runner_ || depth_ >= 8)) return Fault::unsupported_service;
        }
        if (number == 18) threads_.discard_signal_pending(bit(19) | bit(20) | bit(21) | bit(22));
        else if (stops_by_default(number)) threads_.discard_signal_pending(bit(18));
        threads_.signal_pending() |= mask;
        if (!blocked) {
            const auto fault = deliver_pending(state, full_frame);
            if (fault != Fault::none) return fault;
        }
        registers[0] = 0;
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
            threads_.discard_signal_pending(bit(number));
            process_pending_ &= ~bit(number);
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
        if(fault==Fault::none)state.registers[0]=delivery.registers[0];
        return fault;
    }
    const auto number=static_cast<unsigned>(signal);const auto value=bit(number);
    const auto action=actions_[number];
    const bool blocked=(*destination->mask & value & ~unblockable)!=0;
    if(!blocked && !action.handler && stops_by_default(number))return Fault::unsupported_service;
    if(number==18)threads_.discard_signal_pending(bit(19)|bit(20)|bit(21)|bit(22));
    else if(stops_by_default(number))threads_.discard_signal_pending(bit(18));
    if(!blocked && (action.handler==1 || (!action.handler && ignored_by_default(number)))){state.registers[0]=0;return Fault::none;}
    *destination->pending |= value;
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
        if(deliver()!=Fault::none || process.exit_status())return Fault::process_exit;
    }
    if(actions_[6].handler>1){
        threads_.signal_pending() |= mask;
        if(deliver()!=Fault::none || process.exit_status())return Fault::process_exit;
    }
    actions_[6]={};
    threads_.signal_pending() &= ~mask;process_pending_ &= ~mask;
    return Fault::process_exit;
}

Fault NativeSignals::deliver_pending(a64::ServiceState &state, bool full_frame, std::uint64_t allowed) {
    if (terminated_) return Fault::process_exit;
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
        stack_frames_[depth_]=bounds;
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
