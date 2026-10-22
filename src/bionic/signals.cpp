#include "signals.hpp"
#include "threads.hpp"
#include <algorithm>
#include <limits>
#include <utility>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
constexpr std::uint32_t restart = 0x10000000, nodefer = 0x40000000, reset = 0x80000000;
constexpr std::uint64_t unblockable = (std::uint64_t{1} << 8) | (std::uint64_t{1} << 18);
constexpr auto error_result = std::numeric_limits<std::uint64_t>::max();
std::uint64_t bit(unsigned signal) { return std::uint64_t{1} << (signal - 1); }
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
Fault NativeSignals::fail(a64::ServiceState &state, unsigned value, std::uint64_t result) {
    if (!memory_.write(threads_.error_address(), bytes<4>(value))) return Fault::write;
    state.registers[0] = result;
    return Fault::none;
}
Fault NativeSignals::validate(const Action &action) const {
    if (action.flags & ~(restart | nodefer | reset)) return Fault::unsupported_service;
    if (action.handler > 1 && (action.handler % 4 || !memory_.accessible(action.handler, 4, a64::Permission::execute)))
        return Fault::execute;
    return Fault::none;
}
Fault NativeSignals::invoke(unsigned operation, a64::ServiceState &state, bool full_frame) {
    if (terminated_) return Fault::invalid_call;
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
        const auto ready = threads_.signal_pending() & requested;
        // There is currently no asynchronous signal sender or resumable native
        // wait. Never turn an indefinite wait into fabricated success/EAGAIN.
        if (!ready) return Fault::unsupported_service;
        unsigned signal = 1;
        while (!(ready & bit(signal))) ++signal;
        if (signal >= 32) return Fault::unsupported_service;
        // Successful sigwait writes an int, bypassing the installed handler.
        // Preflight output so a fault never loses a pending guest signal.
        if (!memory_.write(registers[1], bytes<4>(signal))) return Fault::write;
        threads_.signal_pending() &= ~bit(signal);
        registers[0] = 0;
        return Fault::none;
    }
    if (operation == 3) {
        const auto pending = threads_.signal_pending() & threads_.signal_mask() & ~unblockable;
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
        if (next.handler == 1 || (!next.handler && ignored_by_default(number)))
            threads_.discard_signal_pending(bit(number));
    }
    registers[0] = operation == 0 ? previous.handler : 0;
    return Fault::none;
}

Fault NativeSignals::deliver_pending(a64::ServiceState &state, bool full_frame) {
    if (terminated_) return Fault::invalid_call;
    for (unsigned work = 0; work < 64; ++work) {
        const auto ready = threads_.signal_pending() & ~(threads_.signal_mask() & ~unblockable);
        if (!ready) return Fault::none;
        unsigned signal = 1;
        while (!(ready & bit(signal))) ++signal;
        if (signal >= 32) return Fault::unsupported_service;
        const auto pending_bit = bit(signal);
        const auto action = actions_[signal]; // Handler can replace the process-wide disposition.
        if (action.handler == 1 || (!action.handler && ignored_by_default(signal))) {
            threads_.signal_pending() &= ~pending_bit;
            continue;
        }
        if (!action.handler) {
            if (stops_by_default(signal)) return Fault::unsupported_service;
            threads_.signal_pending() &= ~pending_bit;
            terminated_ = true;
            return Fault::invalid_call;
        }
        if (!full_frame || !runner_ || depth_ >= 8) return Fault::unsupported_service;
        const auto executable = validate(action);
        if (executable != Fault::none) return executable;
        if (state.stack_pointer < 272 || state.stack_pointer % 16) return Fault::write;
        const auto stack = state.stack_pointer - 256;
        if (!memory_.accessible(stack - 16, 16, a64::Permission::write)) return Fault::write;
        threads_.signal_pending() &= ~pending_bit;
        if (action.flags & reset) actions_[signal].handler = 0;
        auto &mask = threads_.signal_mask();
        const auto saved = mask;
        mask = (saved | action.mask | ((action.flags & nodefer) ? 0 : pending_bit)) & ~unblockable;
        ++depth_;
        struct Restore {
            std::uint64_t &mask;
            std::uint64_t saved;
            unsigned &depth;
            ~Restore() { mask = saved; --depth; }
        } restore{mask, saved, depth_};
        const auto result = runner_(action.handler, signal, stack, threads_.tls());
        if (terminated_) return Fault::invalid_call;
        if (!result.returned) return result.fault == Fault::none ? Fault::invalid_call : result.fault;
    }
    return (threads_.signal_pending() & ~(threads_.signal_mask() & ~unblockable)) ? Fault::unsupported_service : Fault::none;
}
} // namespace aether::bionic
