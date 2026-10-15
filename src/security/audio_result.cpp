#include "aether/security/audio_protocol.hpp"
#include "aether/security/audio_session.hpp"

namespace aether::security {
namespace {
constexpr std::array<std::string_view, 15> checks{"unsupported-aaudio-modes-return-real-errors",
                                                  "real-wasapi-output-with-private-session-mute",
                                                  "guest-queries-report-actual-stream-properties",
                                                  "arm64-generates-bounded-nonzero-stereo-pcm",
                                                  "nonblocking-prefill-and-full-buffer-short-write",
                                                  "flush-discards-buffer-and-preserves-cumulative-counters",
                                                  "started-stream-writes-through-actual-buffer-events",
                                                  "pause-freezes-device-clock-and-retains-queued-frames",
                                                  "resume-submits-the-next-guest-buffer",
                                                  "stop-drains-before-reporting-stopped",
                                                  "same-state-zero-timeout-is-not-a-false-transition",
                                                  "audio-writes-preserve-the-guest-input-and-canaries",
                                                  "guest-and-host-audio-resources-closed",
                                                  "actual-jit-pcm-and-wasapi-device-progress",
                                                  "guest-pages-remain-non-executable"};
}
std::vector<std::uint8_t> encode_audio_result(const audio::SelftestReport &r) {
    if (r.checks.size() != checks.size() || r.fixture_hash.size() != 64)
        throw ProtocolError("AETHER_AUDIO_RESULT: invalid fixture report");
    // The report carries observations, never the broker's resource token.
    AudioSnapshot snapshot{0xb6a0000000000001ULL, 0, host::AudioState::closed, r.host, r.playback};
    const auto encoded = snapshot.encode();
    std::vector<std::uint8_t> bytes;
    append_u64(bytes, encoded.size());
    bytes.insert(bytes.end(), encoded.begin(), encoded.end());
    append_text(bytes, r.fixture_hash);
    for (const auto n :
         {static_cast<std::uint64_t>(r.relocations), r.fixture_frames, r.prefilled_frames, r.paused_clock,
          r.paused_clock_after, r.audio.calls, r.audio.rejected, r.audio.api_errors, r.audio.streams_opened,
          r.audio.streams_closed, static_cast<std::uint64_t>(r.audio.builders),
          static_cast<std::uint64_t>(r.audio.streams), r.cpu.compiled_blocks, r.cpu.emitted_bytes,
          r.cpu.host_calls, r.cpu.guest_ticks, r.cpu.rx_failures, r.cpu.interpreter_fallbacks})
        append_u64(bytes, n);
    std::uint64_t mask = 0;
    for (std::size_t i = 0; i < checks.size(); ++i) {
        if (r.checks[i].first != checks[i])
            throw ProtocolError("AETHER_AUDIO_RESULT: unexpected fixture check");
        if (r.checks[i].second)
            mask |= 1ULL << i;
    }
    append_u64(bytes, mask);
    return bytes;
}
audio::SelftestReport decode_audio_result(std::span<const std::uint8_t> bytes) {
    const auto length = read_u64(bytes, 0);
    if (bytes.size() > maximum_payload || length > bytes.size() - 8)
        throw ProtocolError("AETHER_AUDIO_RESULT: invalid snapshot size");
    const auto snapshot = AudioSnapshot::decode(bytes.subspan(8, static_cast<std::size_t>(length)));
    if (snapshot.token != 0xb6a0000000000001ULL || snapshot.value ||
        snapshot.state != host::AudioState::closed)
        throw ProtocolError("AETHER_AUDIO_RESULT: invalid report snapshot");
    audio::SelftestReport r;
    r.host = snapshot.info;
    r.playback = snapshot.metrics;
    std::size_t offset = 8 + static_cast<std::size_t>(length);
    r.fixture_hash = read_text(bytes, offset, 64);
    const auto next = [&] {
        const auto n = read_u64(bytes, offset);
        offset += 8;
        return n;
    };
    r.relocations = static_cast<std::size_t>(next());
    r.fixture_frames = next();
    r.prefilled_frames = next();
    r.paused_clock = next();
    r.paused_clock_after = next();
    r.audio.calls = next();
    r.audio.rejected = next();
    r.audio.api_errors = next();
    r.audio.streams_opened = next();
    r.audio.streams_closed = next();
    r.audio.builders = static_cast<std::size_t>(next());
    r.audio.streams = static_cast<std::size_t>(next());
    r.cpu.compiled_blocks = next();
    r.cpu.emitted_bytes = next();
    r.cpu.host_calls = next();
    r.cpu.guest_ticks = next();
    r.cpu.rx_failures = next();
    r.cpu.interpreter_fallbacks = next();
    const auto mask = next();
    if (offset != bytes.size() || mask >= (1ULL << checks.size()) || r.fixture_hash.size() != 64)
        throw ProtocolError("AETHER_AUDIO_RESULT: invalid checks or trailing data");
    for (std::size_t i = 0; i < checks.size(); ++i)
        r.checks.emplace_back(checks[i], (mask & (1ULL << i)) != 0);
    return r;
}
void run_audio_worker(HANDLE reader, HANDLE writer, std::uint64_t session, std::uint64_t app_id) {
    BrokerClient client(reader, writer, session);
    BrokerAudioService provider(client);
    const auto bytes = client.read_package();
    std::vector<std::uint8_t> result;
    try {
        result = encode_audio_result(audio::execute_audio_fixture(bytes, app_id, client, provider));
    } catch (const a64::GuestError &error) {
        throw ProtocolError(error.code + ": " + error.what());
    }
    const auto size = static_cast<std::uint32_t>(result.size());
    write_pipe_frame(writer, {{Operation::finished, client.next_sequence(), session, size, Status::ok},
                              std::move(result)});
}
} // namespace aether::security
