#include "aether/security/audio_protocol.hpp"
#include <bit>
#include <limits>

namespace aether::security {
namespace {
void validate(const AudioSnapshot &s) {
    if ((s.token >> 32) != 0xb6a00000 || !(s.token & UINT32_MAX) ||
        s.value > host::AudioStream::maximum_write_bytes / 2 || s.state > host::AudioState::disconnected ||
        s.info.endpoint.empty() || s.info.endpoint.size() > 1024 ||
        s.info.endpoint.find('\0') != std::string::npos || s.info.sample_rate < 8000 ||
        s.info.sample_rate > 192000 || (s.info.channels != 1 && s.info.channels != 2) ||
        !s.info.buffer_frames || !s.info.burst_frames || !s.info.clock_frequency ||
        s.metrics.padding > s.info.buffer_frames || s.metrics.frames_read > s.metrics.frames_written ||
        s.metrics.frames_discarded > s.metrics.frames_read)
        throw ProtocolError("AETHER_AUDIO_WIRE: invalid stream snapshot");
}
} // namespace
std::vector<std::uint8_t> AudioSnapshot::encode() const {
    validate(*this);
    std::vector<std::uint8_t> bytes;
    for (const auto n : {token, value, static_cast<std::uint64_t>(state)})
        append_u64(bytes, n);
    append_text(bytes, info.endpoint);
    for (const auto n : {info.sample_rate, info.channels, info.buffer_frames, info.burst_frames,
                         info.mix_rate, info.mix_channels, info.mix_bits, info.mix_tag})
        append_u64(bytes, n);
    for (const auto n : {info.period_100ns,
                         info.latency_100ns,
                         info.clock_frequency,
                         static_cast<std::uint64_t>(info.muted),
                         metrics.frames_written,
                         metrics.frames_read,
                         metrics.frames_discarded,
                         metrics.packets,
                         metrics.write_calls,
                         metrics.short_writes,
                         metrics.event_waits,
                         metrics.event_wakes,
                         metrics.starts,
                         metrics.pauses,
                         metrics.stops,
                         metrics.flushes,
                         metrics.clock_reads,
                         metrics.clock_position,
                         metrics.clock_qpc_100ns,
                         metrics.imprecise_clock_reads,
                         metrics.pcm_checksum,
                         metrics.cleanup_failures,
                         static_cast<std::uint64_t>(metrics.padding)})
        append_u64(bytes, n);
    return bytes;
}
AudioSnapshot AudioSnapshot::decode(std::span<const std::uint8_t> bytes) {
    if (bytes.size() > maximum_payload)
        throw ProtocolError("AETHER_AUDIO_WIRE: oversized snapshot");
    AudioSnapshot s;
    std::size_t offset = 0;
    const auto next = [&] {
        const auto v = read_u64(bytes, offset);
        offset += 8;
        return v;
    };
    s.token = next();
    s.value = next();
    const auto state = next();
    if (state > static_cast<std::uint64_t>(host::AudioState::disconnected))
        throw ProtocolError("AETHER_AUDIO_WIRE: invalid state");
    s.state = static_cast<host::AudioState>(state);
    s.info.endpoint = read_text(bytes, offset, 1024);
    for (auto *n : {&s.info.sample_rate, &s.info.channels, &s.info.buffer_frames, &s.info.burst_frames,
                    &s.info.mix_rate, &s.info.mix_channels, &s.info.mix_bits, &s.info.mix_tag}) {
        const auto v = next();
        if (v > UINT32_MAX)
            throw ProtocolError("AETHER_AUDIO_WIRE: overflowing stream property");
        *n = static_cast<std::uint32_t>(v);
    }
    s.info.period_100ns = next();
    s.info.latency_100ns = next();
    s.info.clock_frequency = next();
    const auto muted = next();
    if (muted > 1)
        throw ProtocolError("AETHER_AUDIO_WIRE: noncanonical boolean");
    s.info.muted = muted != 0;
    for (auto *n :
         {&s.metrics.frames_written, &s.metrics.frames_read, &s.metrics.frames_discarded, &s.metrics.packets,
          &s.metrics.write_calls, &s.metrics.short_writes, &s.metrics.event_waits, &s.metrics.event_wakes,
          &s.metrics.starts, &s.metrics.pauses, &s.metrics.stops, &s.metrics.flushes, &s.metrics.clock_reads,
          &s.metrics.clock_position, &s.metrics.clock_qpc_100ns, &s.metrics.imprecise_clock_reads,
          &s.metrics.pcm_checksum, &s.metrics.cleanup_failures})
        *n = next();
    const auto padding = next();
    if (padding > UINT32_MAX || offset != bytes.size())
        throw ProtocolError("AETHER_AUDIO_WIRE: invalid padding or trailing data");
    s.metrics.padding = static_cast<std::uint32_t>(padding);
    validate(s);
    return s;
}
Status audio_status(host::AudioFailure reason) noexcept {
    if (reason == host::AudioFailure::denied)
        return Status::denied;
    if (reason == host::AudioFailure::quota)
        return Status::quota;
    return Status::invalid;
}
Frame audio_failure(const Frame &request, host::AudioFailure reason, std::int32_t native) {
    Frame result{
        {request.header.operation, request.header.sequence, request.header.session, 16, audio_status(reason)},
        {}};
    append_u64(result.payload, static_cast<std::uint64_t>(reason));
    append_u64(result.payload, std::bit_cast<std::uint32_t>(native));
    return result;
}
AudioSnapshot audio_response(const Frame &response) {
    if (response.header.payload_size != response.payload.size())
        throw ProtocolError("AETHER_AUDIO_WIRE: inconsistent reply size");
    if (response.header.status == Status::ok)
        return AudioSnapshot::decode(response.payload);
    if (response.payload.size() != 16)
        throw ProtocolError("AETHER_AUDIO_WIRE: invalid failure reply");
    const auto reason = read_u64(response.payload, 0), native = read_u64(response.payload, 8);
    if (reason > static_cast<std::uint64_t>(host::AudioFailure::quota) || native > UINT32_MAX ||
        audio_status(static_cast<host::AudioFailure>(reason)) != response.header.status)
        throw ProtocolError("AETHER_AUDIO_WIRE: invalid failure reason or status");
    throw host::AudioError(static_cast<host::AudioFailure>(reason), "Broker audio request failed",
                           std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(native)));
}
} // namespace aether::security
