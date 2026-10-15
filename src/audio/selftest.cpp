#include "aether/audio/selftest.hpp"
#include "aether/apk/inspect.hpp"
#include "aether/audio/fixture_hash.hpp"
#include "aether/bionic/guest_posix.hpp"
#include "aether/common/text.hpp"
#include <Windows.h>
#include <algorithm>
#include <bit>
#include <sstream>

namespace aether::audio {
namespace {
[[noreturn]] void fail(std::string message) {
    throw a64::GuestError("AETHER_AUDIO_SELFTEST", std::move(message));
}
class Services final : public a64::GuestServices, public elf::ImportResolver {
    bionic::GuestPosixServices &posix_;
    GuestAudioServices &audio_;

  public:
    Services(bionic::GuestPosixServices &posix, GuestAudioServices &audio) : posix_(posix), audio_(audio) {}
    bool has_library(std::string_view name) const noexcept override {
        return audio_.has_library(name) || posix_.has_library(name);
    }
    std::optional<elf::GuestSymbol> resolve(std::string_view library, std::string_view name,
                                            std::string_view version) const override {
        return audio_.has_library(library) ? audio_.resolve(library, name, version)
                                           : posix_.resolve(library, name, version);
    }
    a64::Fault invoke(std::uint32_t service, a64::Address instruction,
                      std::array<std::uint64_t, 31> &registers) noexcept override {
        return GuestAudioServices::handles_service(service) ? audio_.invoke(service, instruction, registers)
                                                            : posix_.invoke(service, instruction, registers);
    }
};
} // namespace
bool SelftestReport::passed() const {
    return !checks.empty() &&
           std::all_of(checks.begin(), checks.end(), [](const auto &check) { return check.second; });
}
SelftestReport execute_audio_fixture(std::span<const std::uint8_t> bytes, std::uint64_t app_id,
                                     host::TimeService &time, host::AudioService &provider) {
    const auto hash = apk::sha256(bytes);
    if (hash != fixture::sha256)
        throw a64::GuestError("AETHER_AUDIO_FIXTURE_NOT_TRUSTED",
                              "Only the exact built-in first-party AAudio ELF may execute before Phase 7");
    SelftestReport report;
    report.fixture_hash = hash;
    const auto check = [&](std::string name, bool value) {
        report.checks.emplace_back(std::move(name), value);
    };
    a64::GuestMemory memory;
    a64::AppContext app{app_id, true, false, true};
    bionic::GuestPosixServices posix(memory, app, time);
    GuestAudioServices audio(memory, app, true, &provider);
    Services services(posix, audio);
    elf::GuestLoader loader(memory, services);
    const std::array modules{elf::ModuleInput{"libaether_audio.so", bytes}};
    loader.load(modules, "libaether_audio.so");
    constexpr a64::Address output = 0x30000000, pcm_address = output + 32, stack = 0x31000000;
    constexpr std::size_t frames = 32768, pcm_size = frames * 4;
    memory.map(output, 135168, a64::read_write);
    memory.map(stack, 65536, a64::read_write);
    a64::GuestCpu cpu(memory, app, &services);
    loader.initialize(cpu, stack + 65536);
    const auto value = [&](std::string_view name, std::initializer_list<std::uint64_t> arguments = {}) {
        const auto symbol = loader.symbol("libaether_audio.so", name);
        const auto returned = cpu.call(symbol.address, {arguments.begin(), arguments.size()}, stack + 65536);
        if (!returned.returned)
            fail(std::string(name) + ": " + std::string(a64::fault_name(returned.fault)) + "; " +
                 std::string(audio.last_error()) + "; " + std::string(posix.last_rejection()));
        return returned.registers[0];
    };
    const auto call = [&](std::string_view name, std::initializer_list<std::uint64_t> arguments = {}) {
        const auto returned = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value(name, arguments)));
        if (returned != 0)
            fail(std::string(name) + " returned " + std::to_string(returned) + "; " +
                 std::string(audio.last_error()));
    };
    check("unsupported-aaudio-modes-return-real-errors", value("aether_audio_rejections") == 127 &&
                                                             audio.metrics().streams_opened == 0 &&
                                                             audio.metrics().builders == 0);
    call("aether_audio_open");
    report.host = audio.host_info();
    check("real-wasapi-output-with-private-session-mute",
          !report.host.endpoint.empty() && report.host.muted && report.host.mix_rate > 0 &&
              report.host.clock_frequency > 0 && audio.metrics().streams == 1);
    const std::array<std::uint64_t, 8> expected{2, 48000, 2, 2, 1, 1, 0, 10};
    bool queries = true;
    for (std::size_t i = 0; i < expected.size(); ++i)
        queries = queries && value("aether_audio_query", {i}) == expected[i];
    report.prefilled_frames = value("aether_audio_query", {8});
    const auto capacity = report.prefilled_frames;
    if (!capacity || capacity > frames)
        fail("WASAPI buffer is outside the fixture's bounded write size");
    check("guest-queries-report-actual-stream-properties",
          queries && capacity == report.host.buffer_frames && value("aether_audio_query", {9}) == capacity &&
              value("aether_audio_query", {10}) == report.host.burst_frames);
    std::vector<std::uint8_t> guarded(pcm_size + 64, 0xa5);
    if (!memory.write(output, guarded))
        fail("Cannot initialize audio fixture canaries");
    call("aether_audio_fill", {pcm_address, frames, 0});
    if (!memory.read(output, guarded))
        fail("Cannot read generated guest PCM");
    const auto canaries = [&] {
        return std::all_of(guarded.begin(), guarded.begin() + 32, [](auto v) { return v == 0xa5; }) &&
               std::all_of(guarded.end() - 32, guarded.end(), [](auto v) { return v == 0xa5; });
    };
    const auto pcm = std::span{guarded}.subspan(32, pcm_size);
    const std::vector<std::uint8_t> original_pcm(pcm.begin(), pcm.end());
    check("arm64-generates-bounded-nonzero-stereo-pcm",
          canaries() && std::any_of(pcm.begin(), pcm.end(), [](auto v) { return v != 0; }));
    report.fixture_frames = frames;
    check("nonblocking-prefill-and-full-buffer-short-write",
          value("aether_audio_write", {pcm_address, frames, 0}) == capacity &&
              value("aether_audio_write", {pcm_address, 8, 0}) == 0 &&
              value("aether_audio_query", {11}) == capacity);
    call("aether_audio_flush");
    check("flush-discards-buffer-and-preserves-cumulative-counters",
          value("aether_audio_query", {0}) == 8 && value("aether_audio_query", {11}) == capacity &&
              value("aether_audio_query", {12}) == capacity &&
              audio.host_metrics().frames_discarded == capacity);
    if (value("aether_audio_write", {pcm_address, frames, 0}) != capacity)
        fail("Audio prefill changed capacity");
    call("aether_audio_start");
    check("started-stream-writes-through-actual-buffer-events",
          value("aether_audio_query", {0}) == 4 &&
              value("aether_audio_write", {pcm_address + capacity * 4, frames - capacity, 1'000'000'000}) ==
                  frames - capacity &&
              value("aether_audio_query", {12}) > capacity && audio.host_metrics().event_wakes > 0);
    call("aether_audio_pause");
    report.paused_clock = audio.host_metrics().clock_position;
    const auto paused_frames = value("aether_audio_query", {12});
    Sleep(20);
    const auto later_paused_frames = value("aether_audio_query", {12});
    report.paused_clock_after = audio.host_metrics().clock_position;
    check("pause-freezes-device-clock-and-retains-queued-frames",
          value("aether_audio_query", {0}) == 6 && report.paused_clock > 0 &&
              report.paused_clock_after == report.paused_clock && paused_frames == later_paused_frames);
    call("aether_audio_start");
    check("resume-submits-the-next-guest-buffer",
          value("aether_audio_write", {pcm_address, frames, 1'000'000'000}) == frames);
    call("aether_audio_stop");
    check("stop-drains-before-reporting-stopped",
          value("aether_audio_wait", {9, 2'000'000'000}) == 10 && value("aether_audio_query", {0}) == 10 &&
              value("aether_audio_query", {11}) == capacity + frames * 2 &&
              value("aether_audio_query", {12}) == capacity + frames * 2 &&
              audio.host_metrics().padding == 0);
    check("same-state-zero-timeout-is-not-a-false-transition",
          static_cast<std::uint32_t>(value("aether_audio_wait", {10, 0})) ==
              static_cast<std::uint32_t>(-885));
    if (!memory.read(output, guarded))
        fail("Cannot verify final audio memory canaries");
    check("audio-writes-preserve-the-guest-input-and-canaries",
          canaries() && std::equal(original_pcm.begin(), original_pcm.end(), guarded.begin() + 32));
    call("aether_audio_close");
    loader.finalize(cpu, stack + 65536);
    report.relocations = loader.relocation_count();
    report.cpu = cpu.metrics();
    audio.shutdown();
    report.audio = audio.metrics();
    report.playback = audio.host_metrics();
    check("guest-and-host-audio-resources-closed",
          report.audio.builders == 0 && report.audio.streams == 0 && report.audio.streams_opened == 1 &&
              report.audio.streams_closed == 1 && report.playback.cleanup_failures == 0 &&
              !memory.accessible(GuestAudioServices::trampoline_base, 8, a64::Permission::execute));
    check("actual-jit-pcm-and-wasapi-device-progress",
          report.cpu.compiled_blocks > 0 && report.cpu.emitted_bytes > 0 &&
              report.cpu.host_calls >= report.audio.calls && report.cpu.interpreter_fallbacks == 0 &&
              report.cpu.rx_failures == 0 && report.playback.clock_position > report.paused_clock &&
              report.playback.clock_qpc_100ns > 0);
    check("guest-pages-remain-non-executable", memory.host_pages_are_non_executable());
    return report;
}
std::string SelftestReport::json() const {
    std::ostringstream out;
    out << "{\"schemaVersion\":1,\"command\":\"audio-selftest\",\"passed\":" << (passed() ? "true" : "false")
        << ",\"mode\":\"self-authored-fixtures-only\",\"androidOsStarted\":false,\"guestCallsExecuted\":true,"
           "\"backend\":\"WASAPI-shared-event\",\"audibleOutputVerified\":false,\"capturePerformed\":false,"
           "\"fixtureSha256\":"
        << json_quote(fixture_hash) << ",\"capturePath\":" << json_quote(capture_path)
        << ",\"relocations\":" << relocations << ",\"registryEntries\":" << api_registry().size()
        << ",\"fixtureFrames\":" << fixture_frames << ",\"prefilledFrames\":" << prefilled_frames
        << ",\"pausedClock\":" << paused_clock << ",\"pausedClockAfter\":" << paused_clock_after
        << ",\"host\":{\"endpoint\":" << json_quote(host.endpoint) << ",\"sampleRate\":" << host.sample_rate
        << ",\"channels\":" << host.channels
        << ",\"format\":\"PCM_I16\",\"bufferFrames\":" << host.buffer_frames
        << ",\"burstFrames\":" << host.burst_frames << ",\"mixRate\":" << host.mix_rate
        << ",\"mixChannels\":" << host.mix_channels << ",\"mixBits\":" << host.mix_bits
        << ",\"mixTag\":" << host.mix_tag << ",\"period100ns\":" << host.period_100ns
        << ",\"latency100ns\":" << host.latency_100ns << ",\"clockFrequency\":" << host.clock_frequency
        << ",\"muted\":" << (host.muted ? "true" : "false")
        << "},"
           "\"playback\":{\"framesWritten\":"
        << playback.frames_written << ",\"framesRead\":" << playback.frames_read
        << ",\"framesDiscarded\":" << playback.frames_discarded << ",\"packets\":" << playback.packets
        << ",\"writeCalls\":" << playback.write_calls << ",\"shortWrites\":" << playback.short_writes
        << ",\"eventWaits\":" << playback.event_waits << ",\"eventWakes\":" << playback.event_wakes
        << ",\"starts\":" << playback.starts << ",\"pauses\":" << playback.pauses
        << ",\"stops\":" << playback.stops << ",\"flushes\":" << playback.flushes
        << ",\"clockReads\":" << playback.clock_reads << ",\"clockPosition\":" << playback.clock_position
        << ",\"clockQpc100ns\":" << playback.clock_qpc_100ns
        << ",\"impreciseClockReads\":" << playback.imprecise_clock_reads
        << ",\"pcmChecksum\":" << playback.pcm_checksum << ",\"padding\":" << playback.padding
        << ",\"cleanupFailures\":" << playback.cleanup_failures
        << "},"
           "\"audio\":{\"calls\":"
        << audio.calls << ",\"rejected\":" << audio.rejected << ",\"apiErrors\":" << audio.api_errors
        << ",\"streamsOpened\":" << audio.streams_opened << ",\"streamsClosed\":" << audio.streams_closed
        << ",\"builders\":" << audio.builders << ",\"streams\":" << audio.streams
        << "},"
           "\"cpu\":{\"compiledBlocks\":"
        << cpu.compiled_blocks << ",\"emittedBytes\":" << cpu.emitted_bytes
        << ",\"hostCalls\":" << cpu.host_calls << ",\"guestTicks\":" << cpu.guest_ticks
        << ",\"rxFailures\":" << cpu.rx_failures << ",\"interpreterFallbacks\":" << cpu.interpreter_fallbacks
        << "},\"checks\":[";
    bool comma = false;
    for (const auto &[name, passed_check] : checks) {
        if (comma)
            out << ',';
        comma = true;
        out << "{\"name\":" << json_quote(name) << ",\"passed\":" << (passed_check ? "true" : "false") << '}';
    }
    out << "],\"isolation\":" << (isolation_json.empty() ? "null" : isolation_json) << '}';
    return out.str();
}
std::string SelftestReport::text(bool verbose) const {
    std::ostringstream out;
    out << "Aether ARM64 AAudio/WASAPI self-test: " << (passed() ? "PASS" : "FAIL") << '\n'
        << "Endpoint: " << host.endpoint << "; shared PCM16 " << host.sample_rate << " Hz / " << host.channels
        << " channels; private test session muted\n"
        << "Guest PCM frames submitted: " << playback.frames_written
        << "; discarded by tested flush: " << playback.frames_discarded
        << "; device clock: " << playback.clock_position << '/' << host.clock_frequency << '\n'
        << "LPAC guest execution with broker-owned WASAPI. Acoustic output and the full security gate remain "
           "unverified.\n";
    if (verbose)
        for (const auto &[name, passed_check] : checks)
            out << (passed_check ? "PASS " : "FAIL ") << name << '\n';
    return out.str();
}
} // namespace aether::audio
