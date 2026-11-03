#include "standard_library.hpp"
#include "threads.hpp"
#include "aether/common/thread_exit.hpp"
#include <algorithm>
#include <bit>
#include <limits>
#include <new>
#include <utility>
#include <vector>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
// Standard Android signal identifiers, indexed by actual AArch64 signal number.
constexpr std::array<std::string_view, 32> names{
    "", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2",
    "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU",
    "XFSZ", "VTALRM", "PROF", "WINCH", "IO", "PWR", "SYS"};
constexpr std::array<std::string_view, 32> descriptions{
    "", "Hangup", "Interrupt", "Quit", "Illegal instruction", "Trace trap", "Aborted", "Bus error",
    "Arithmetic exception", "Killed", "User signal 1", "Invalid memory reference", "User signal 2", "Broken pipe",
    "Alarm", "Terminated", "Stack fault", "Child process changed", "Continued", "Stopped", "Terminal stop",
    "Terminal input stopped", "Terminal output stopped", "Urgent socket condition", "CPU time limit reached",
    "File size limit reached", "Virtual timer expired", "Profiling timer expired", "Window size changed",
    "I/O notification", "Power failure", "Invalid system call"};
constexpr std::array<std::string_view, 16> address_errors{
    "Success", "Address family does not match host", "Name lookup temporarily unavailable", "Invalid lookup flags",
    "Name lookup failed", "Unsupported address family", "Memory allocation failed", "No address records",
    "Unknown host or service", "Service does not match socket type", "Unsupported socket type", "System error",
    "Invalid address hints", "Unknown protocol", "Lookup buffer is too small", "Unknown address lookup error"};
void word(std::span<std::uint8_t> bytes, std::size_t offset, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) bytes[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
}
struct Failure { Fault fault; std::string_view text; };
[[noreturn]] void fail(Fault fault, std::string_view text) { throw Failure{fault, text}; }
}
NativeStandardLibrary::NativeStandardLibrary(a64::GuestMemory &memory, NativeThreads &threads, const a64::AppContext &app)
    : memory_(memory), threads_(threads), app_(app), app_id_(app.instance_id) {}
NativeStandardLibrary::~NativeStandardLibrary() {
    if (owner_ != std::this_thread::get_id()) std::terminate();
    const auto release = [&](Address address, std::size_t size, const auto &identity) {
        try {
            const auto mapping = memory_.mapping(address);
            const auto current = memory_.word_identity(address);
            if (identity && current && *identity == *current && mapping && mapping->address == address && mapping->size == size)
                memory_.unmap(address);
        } catch (...) {}
    };
    for (std::size_t i = 0; i < unknown_.size(); ++i)
        if (unknown_[i].owned) release(unknown_base + i * a64::GuestMemory::page_size, a64::GuestMemory::page_size, unknown_[i].identity);
    if (constants_owned_) release(constants_base, constants_bytes, constants_identity_);
}
void NativeStandardLibrary::runner(GuestPosixServices::PhdrRunner value) { runner_ = std::move(value); }
void NativeStandardLibrary::constants() {
    if (constants_owned_) {
        const auto current = memory_.word_identity(constants_base);
        const auto mapping = memory_.mapping(constants_base);
        if (!current || !constants_identity_ || *current != *constants_identity_ || !mapping ||
            mapping->address != constants_base || mapping->size != constants_bytes || mapping->permissions != a64::Permission::read)
            fail(Fault::invalid_call, "stdlib: readonly constant mapping changed");
        return;
    }
    std::array<std::uint8_t, constants_bytes> bytes{};
    std::size_t used = 65 * 8; // Real sys_signame[65]: signal zero and all RT entries remain null.
    const auto append = [&](std::string_view text) {
        if (text.size() + 1 > bytes.size() - used) fail(Fault::invalid_call, "stdlib: constant storage bound exceeded");
        const auto address = constants_base + used;
        std::copy(text.begin(), text.end(), bytes.begin() + used); used += text.size() + 1;
        return address;
    };
    std::array<Address, 16> errors{};
    std::array<Address, 65> signals{};
    for (std::size_t i = 1; i < names.size(); ++i) word(bytes, i * 8, append(names[i]));
    for (std::size_t i = 0; i < errors.size(); ++i) errors[i] = append(address_errors[i]);
    for (std::size_t i = 1; i < descriptions.size(); ++i) signals[i] = append(descriptions[i]);
    for (std::size_t i = 35; i < signals.size(); ++i) signals[i] = append("Real-time signal " + std::to_string(i - 35));
    memory_.map(constants_base, constants_bytes, a64::read_write);
    bool mapped = true;
    try {
        if (!memory_.write(constants_base, bytes)) fail(Fault::write, "stdlib: constant publication failed");
        memory_.protect(constants_base, a64::Permission::read);
        constants_identity_ = memory_.word_identity(constants_base);
        if (!constants_identity_) fail(Fault::invalid_call, "stdlib: constant backing identity unavailable");
        address_errors_ = errors; signals_ = signals; constants_owned_ = true; mapped = false;
    } catch (...) { if (mapped) memory_.unmap(constants_base); throw; }
}
Address NativeStandardLibrary::sys_signame_address() {
    if (owner_ != std::this_thread::get_id() || !app_id_ || app_.instance_id != app_id_)
        throw a64::GuestError("AETHER_STDLIB_OWNER", "Constant lookup belongs to another owner");
    try { constants(); return constants_base; }
    catch (const Failure &failure) { throw a64::GuestError("AETHER_STDLIB_MAPPING", std::string(failure.text)); }
}
Address NativeStandardLibrary::signal_text(std::int32_t signal) {
    constants();
    if (signal > 0 && signal < static_cast<std::int32_t>(signals_.size()) && signals_[signal]) return signals_[signal];
    for (std::size_t i = 0; i < unknown_.size(); ++i) if (unknown_[i].owned && unknown_[i].signal == signal) {
        const auto address = unknown_base + i * a64::GuestMemory::page_size;
        const auto current = memory_.word_identity(address);
        const auto mapping = memory_.mapping(address);
        if (!current || !unknown_[i].identity || *current != *unknown_[i].identity || !mapping ||
            mapping->address != address || mapping->size != a64::GuestMemory::page_size || mapping->permissions != a64::Permission::read)
            fail(Fault::invalid_call, "strsignal: readonly text mapping changed");
        return unknown_base + i * a64::GuestMemory::page_size;
    }
    const auto slot = std::find_if(unknown_.begin(), unknown_.end(), [](const auto &entry) { return !entry.owned; });
    if (slot == unknown_.end()) fail(Fault::unsupported_service, "strsignal: distinct unknown-number capacity exhausted");
    const auto address = unknown_base + static_cast<std::size_t>(slot - unknown_.begin()) * a64::GuestMemory::page_size;
    const auto text = "Unknown signal " + std::to_string(signal);
    std::array<std::uint8_t, a64::GuestMemory::page_size> bytes{};
    std::copy(text.begin(), text.end(), bytes.begin());
    memory_.map(address, bytes.size(), a64::read_write);
    try {
        if (!memory_.write(address, bytes)) fail(Fault::write, "strsignal: text publication failed");
        memory_.protect(address, a64::Permission::read);
        const auto identity = memory_.word_identity(address);
        if (!identity) fail(Fault::invalid_call, "strsignal: text backing identity unavailable");
        *slot = {signal, true, identity};
    } catch (...) { memory_.unmap(address); throw; }
    return address;
}
Fault NativeStandardLibrary::sort(a64::ServiceState &state, bool full_frame) {
    const auto base = state.registers[0], count = state.registers[1], width = state.registers[2], callback = state.registers[3];
    if (count < 2 || !width) { state.registers[0] = 0; return Fault::none; }
    if (!full_frame) fail(Fault::unsupported_service, "qsort: comparator requires a trusted full service frame");
    if (count > 4096 || width > 1024 * 1024 || count > (1024 * 1024) / width)
        fail(Fault::unsupported_service, "qsort: array exceeds 4096 elements or one MiB");
    const auto size = static_cast<std::size_t>(count * width);
    if (!base || base >= a64::GuestMemory::address_limit || size > a64::GuestMemory::address_limit - base)
        fail(Fault::invalid_call, "qsort: array extent wraps or is null");
    if (!memory_.accessible(base, size, a64::Permission::read)) fail(Fault::read, "qsort: array is not readable");
    if (!memory_.accessible(base, size, a64::Permission::write)) fail(Fault::write, "qsort: array is not writable");
    const auto tid = threads_.tid(); const auto tls = threads_.tls();
    const auto invocation = state.invocation, stack_top = state.stack_top;
    const auto owner = threads_.thread_register_state(tls);
    if (!tid || !tls || !owner || state.trusted_tls != tls || !state.invocation)
        fail(Fault::invalid_call, "qsort: exact logical thread/TLS invocation is unavailable");
    if (!runner_) fail(Fault::unsupported_service, "qsort: genuine guest comparator runner is unavailable");
    if (callback % 4 || !memory_.accessible(callback, 4, a64::Permission::execute))
        fail(Fault::execute, "qsort: comparator is not aligned executable guest code");
    const auto stack = state.stack_pointer;
    if (stack < 16 || stack % 16 || !state.stack_top || stack > state.stack_top ||
        !memory_.accessible(stack - 16, 16, a64::Permission::write))
        fail(Fault::write, "qsort: comparator stack is not aligned writable guest storage");
    if (depth_ >= 16) fail(Fault::nesting_limit, "qsort: comparator nesting exceeds sixteen sorts");
    struct Page { Address address; a64::GuestMemory::WordIdentity identity; };
    std::vector<Page> pages;
    const auto first_page = base & ~Address(a64::GuestMemory::page_size - 1);
    const auto last_page = (base + size - 1) & ~Address(a64::GuestMemory::page_size - 1);
    pages.reserve(static_cast<std::size_t>((last_page - first_page) / a64::GuestMemory::page_size + 1));
    for (auto page = first_page;; page += a64::GuestMemory::page_size) {
        const auto identity = memory_.word_identity(page, a64::read_write);
        if (!identity) fail(Fault::invalid_call, "qsort: array backing proof is unavailable");
        pages.push_back({page, *identity});
        if (page == last_page) break;
    }
    std::vector<std::uint8_t> swap_bytes(static_cast<std::size_t>(width * 2));
    const auto run = runner_; // Nested callbacks may replace the configured function.
    if (!depth_) { remaining_ = state.operation_allowance(1'000'000); comparisons_ = charged_ = 0; }
    ++depth_;
    struct End { unsigned &depth; ~End() { --depth; } } end{depth_};
    const auto context = [&] {
        if (app_.process_state->exit_status()) fail(Fault::process_exit, "qsort: process terminated during comparator execution");
        if (threads_.exit_value(tls)) fail(Fault::thread_exit, "qsort: comparator terminated its logical thread");
        if (threads_.tid() != tid || threads_.tls() != tls || threads_.thread_register_state(tls) != owner ||
            state.trusted_tls != tls || state.invocation != invocation || state.stack_top != stack_top || state.stack_pointer != stack)
            fail(Fault::invalid_call, "qsort: comparator did not restore its exact logical owner");
    };
    const auto check = [&](Address address, std::size_t bytes) {
        if (!memory_.accessible(address, bytes, a64::read_write))
            fail(Fault::write, "qsort: comparator changed array accessibility");
        const auto first = (address & ~Address(a64::GuestMemory::page_size - 1));
        const auto last = (address + bytes - 1) & ~Address(a64::GuestMemory::page_size - 1);
        for (auto page = first;; page += a64::GuestMemory::page_size) {
            const auto index = static_cast<std::size_t>((page - first_page) / a64::GuestMemory::page_size);
            const auto current = memory_.word_identity(page, a64::read_write);
            if (index >= pages.size() || !current || *current != pages[index].identity)
                fail(Fault::invalid_call, "qsort: comparator replaced the original array backing");
            if (page == last) break;
        }
    };
    const auto element = [&](std::uint64_t index) { return base + index * width; };
    const auto compare = [&](std::uint64_t left, std::uint64_t right) {
        context(); check(element(left), static_cast<std::size_t>(width)); check(element(right), static_cast<std::size_t>(width));
        const auto allowance = state.operation_allowance(remaining_);
        if (comparisons_ == 65536 || !allowance) fail(Fault::budget, "qsort: comparator campaign allowance exhausted");
        if (!memory_.accessible(callback, 4, a64::Permission::execute)) fail(Fault::execute, "qsort: comparator is no longer executable");
        if (!memory_.accessible(stack - 16, 16, a64::Permission::write)) fail(Fault::write, "qsort: callback stack changed");
        ++comparisons_;
        const auto witness = charged_;
        const auto execution = run(callback, {element(left), element(right), 0}, stack, tls, allowance);
        context();
        if (execution.result.fault != Fault::none) fail(execution.result.fault, "qsort: guest comparator failed");
        if (!execution.result.returned) fail(Fault::invalid_call, "qsort: guest comparator did not return");
        if (charged_ < witness || execution.ticks < charged_ - witness)
            fail(Fault::invalid_call, "qsort: comparator accounting witness changed");
        const auto own = execution.ticks - (charged_ - witness);
        if (own > remaining_) fail(Fault::budget, "qsort: guest comparator exceeded campaign allowance");
        remaining_ -= own; charged_ += own;
        check(element(left), static_cast<std::size_t>(width)); check(element(right), static_cast<std::size_t>(width));
        return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(execution.result.registers[0]));
    };
    const auto swap = [&](std::uint64_t left, std::uint64_t right) {
        if (left == right) return;
        context(); check(element(left), static_cast<std::size_t>(width)); check(element(right), static_cast<std::size_t>(width));
        auto a = std::span(swap_bytes).first(static_cast<std::size_t>(width));
        auto b = std::span(swap_bytes).subspan(static_cast<std::size_t>(width));
        if (!memory_.read(element(left), a) || !memory_.read(element(right), b)) fail(Fault::read, "qsort: swap read failed");
        // No callbacks occur between these reads and the two proved writes.
        if (!memory_.write(element(left), b) || !memory_.write(element(right), a)) fail(Fault::write, "qsort: swap write failed");
    };
    const auto sift = [&](std::uint64_t root, std::uint64_t length) {
        while (root < length / 2) {
            auto child = root * 2 + 1;
            if (child + 1 < length && compare(child, child + 1) < 0) ++child;
            if (compare(root, child) >= 0) break;
            swap(root, child); root = child;
        }
    };
    for (auto start = count / 2; start; --start) sift(start - 1, count);
    for (auto end_index = count; end_index > 1; --end_index) { swap(0, end_index - 1); sift(0, end_index - 1); }
    context(); check(base, size);
    state.registers[0] = 0;
    return Fault::none;
}
Fault NativeStandardLibrary::invoke(StandardLibraryOperation operation, a64::ServiceState &state, bool full_frame) noexcept {
    rejection_ = {};
    if (owner_ != std::this_thread::get_id() || !app_id_ || app_.instance_id != app_id_)
        return Fault::invalid_call;
    const auto reject = [&](Fault fault, std::string_view text) { rejection_ = text; return fault; };
    try {
        if (!app_.process_state) fail(Fault::invalid_call, "stdlib: process identity is unavailable");
        if (app_.process_state->exit_status()) return Fault::process_exit;
        auto &r = state.registers;
        switch (operation) {
        case StandardLibraryOperation::random:
            random_state_ = static_cast<std::uint32_t>((std::uint64_t{random_state_} * 1103515245 + 12345) & 0x7fffffff);
            r[0] = random_state_; return Fault::none;
        case StandardLibraryOperation::seed_random:
            random_state_ = static_cast<std::uint32_t>(r[0]); return Fault::none;
        case StandardLibraryOperation::divide: {
            const auto numerator = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[0]));
            const auto denominator = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[1]));
            if (!denominator || (numerator == INT32_MIN && denominator == -1))
                fail(Fault::invalid_call, "div: division by zero or unrepresentable quotient");
            const auto quotient = static_cast<std::uint32_t>(numerator / denominator);
            const auto remainder = static_cast<std::uint32_t>(numerator % denominator);
            r[0] = quotient | (std::uint64_t{remainder} << 32); return Fault::none;
        }
        case StandardLibraryOperation::divide_long_long: {
            const auto numerator = std::bit_cast<std::int64_t>(r[0]), denominator = std::bit_cast<std::int64_t>(r[1]);
            if (!denominator || (numerator == INT64_MIN && denominator == -1))
                fail(Fault::invalid_call, "lldiv: division by zero or unrepresentable quotient");
            r[0] = std::bit_cast<std::uint64_t>(numerator / denominator);
            r[1] = std::bit_cast<std::uint64_t>(numerator % denominator); return Fault::none;
        }
        case StandardLibraryOperation::environment:
            for (std::size_t n = 0; n < 1024; ++n) {
                std::array<std::uint8_t, 1> byte{};
                if (!r[0] || r[0] >= a64::GuestMemory::address_limit || n >= a64::GuestMemory::address_limit - r[0] ||
                    !memory_.read(r[0] + n, byte)) fail(Fault::read, "getenv: name is not a readable bounded guest string");
                if (!byte[0]) { r[0] = 0; return Fault::none; } // The controlled guest environment is genuinely empty.
            }
            fail(Fault::unsupported_service, "getenv: name exceeds 1023 bytes");
        case StandardLibraryOperation::address_error: {
            constants();
            const auto code = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[0]));
            r[0] = address_errors_[code >= 0 && code < 15 ? static_cast<std::size_t>(code) : 15]; return Fault::none;
        }
        case StandardLibraryOperation::signal_description:
            r[0] = signal_text(std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[0]))); return Fault::none;
        case StandardLibraryOperation::sort:
            return sort(state, full_frame);
        }
        fail(Fault::unsupported_service, "stdlib: operation is outside the implemented profile");
    } catch (const Failure &failure) { return reject(failure.fault, failure.text); }
    catch (const ThreadExit &exit) { threads_.request_exit(exit.value); return reject(Fault::thread_exit, "qsort: comparator exited its thread"); }
    catch (const ProcessExit &exit) {
        if (app_.process_state) { if (exit.signal) app_.process_state->request_signal(exit.signal); else app_.process_state->request_exit(exit.status); }
        return reject(Fault::process_exit, "qsort: comparator exited the process");
    }
    catch (const std::bad_alloc &) { return reject(Fault::windows_service, "stdlib: bounded host allocation failed"); }
    catch (const a64::GuestError &) { return reject(Fault::windows_service, "stdlib: owned guest storage failed"); }
    catch (...) { return reject(Fault::windows_service, "stdlib: host or comparator operation failed"); }
}
} // namespace aether::bionic
