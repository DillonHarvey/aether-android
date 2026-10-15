#pragma once
#include "aether/host/audio_stream.hpp"
#include "aether/security/protocol.hpp"

namespace aether::security {
enum class AudioControl : std::uint64_t { start, pause, flush, stop };
inline constexpr std::size_t audio_chunk_bytes = maximum_payload - 16;
struct AudioSnapshot {
    std::uint64_t token = 0, value = 0;
    host::AudioState state = host::AudioState::closed;
    host::AudioInfo info;
    host::AudioMetrics metrics;
    std::vector<std::uint8_t> encode() const;
    static AudioSnapshot decode(std::span<const std::uint8_t> bytes);
};
Status audio_status(host::AudioFailure reason) noexcept;
Frame audio_failure(const Frame &request, host::AudioFailure reason, std::int32_t native = 0);
// Throws a typed audio error for a canonical error reply, ProtocolError otherwise.
AudioSnapshot audio_response(const Frame &response);
} // namespace aether::security
