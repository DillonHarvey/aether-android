// Compiled original ARM64 only. No external APK, method or guest-code input.
#include "probes.hpp"
#include "aether/bionic/guest_posix.hpp"
#include "aether/common/process_exit.hpp"

namespace aether::security {
std::uint8_t run_process_exit_probe(HANDLE writer, std::uint64_t session, std::uint8_t status) {
    if (status != 0 && status != 255 && status != 134)
        throw ProtocolError("Invalid fixed process exit status");
    const bool aborting = status == 134;
    a64::GuestMemory memory;
    const a64::AppContext app{76, false};
    host::HostTimeService time;
    bionic::GuestPosixServices services(memory, app, time);
    a64::GuestCpu cpu(memory, app, &services);
    cpu.set_thread_pointer(services.thread_pointer());
    const auto target = services.resolve("libc.so", aborting ? "abort" : "_exit", "LIBC");
    if (!target)
        throw ProtocolError("Process exit fixture could not resolve its fixed libc export");
    constexpr a64::Address marker = 0x80000, entry = 0x90000;
    memory.map(marker, 4096, a64::read_write);
    memory.map(entry, 4096, a64::read_write);
    const auto low = [](auto address, unsigned reg) {
        return 0xd2800000U | reg | static_cast<std::uint32_t>((address & 65535) << 5);
    };
    const auto high = [](auto address, unsigned reg) {
        return 0xf2a00000U | reg | static_cast<std::uint32_t>(((address >> 16) & 65535) << 5);
    };
    // Preserve LR, call real _exit/abort, then mark only an incorrect return.
    const std::array<std::uint32_t, 10> code{
        0xa9bf7bfd, low(target->address, 16), high(target->address, 16), 0xd63f0200,
        low(marker, 1), high(marker, 1), 0x52800002U | (0x1234U << 5), 0xb9000022,
        0xa8c17bfd, 0xd65f03c0};
    if (!memory.write(entry, {reinterpret_cast<const std::uint8_t *>(code.data()), sizeof(code)}))
        throw ProtocolError("Cannot write process exit fixture");
    memory.protect(entry, a64::read_execute);
    try {
        const auto result = cpu.call(entry, std::array<std::uint64_t, 1>{status}, marker + 4096);
        if (result.returned || result.fault != a64::Fault::process_exit || result.detail != status)
            throw ProtocolError("Actual ARM64 process exit did not yield its terminal fault");
        app.process_state->checkpoint(); // Trusted boundary, after generated frames have returned.
    } catch (const ProcessExit &exit) {
        std::array<std::uint8_t, 4> observed{};
        if (exit.status != status || exit.signal != (aborting ? 6 : 0) ||
            app.process_state->exit_status() != status ||
            app.process_state->termination_signal() !=
                (aborting ? std::optional<std::uint8_t>{6} : std::nullopt) ||
            !memory.read(marker, observed) || observed != std::array<std::uint8_t, 4>{} ||
            !cpu.metrics().compiled_blocks || !cpu.metrics().guest_ticks)
            throw ProtocolError("Process exit fixture continued or lost the terminal status");
        if (aborting)
            throw ProtocolError("AETHER_GUEST_SIGNAL: guest terminated abnormally by signal 6");
        write_pipe_frame(writer, guest_exit_frame(session, exit.status));
        return exit.status;
    }
    throw ProtocolError("Actual ARM64 process exit unexpectedly returned");
}
} // namespace aether::security
