#pragma once
#include "aether/audio/selftest.hpp"
#include "aether/security/audio_client.hpp"

namespace aether::security {
std::vector<std::uint8_t> encode_audio_result(const audio::SelftestReport &report);
audio::SelftestReport decode_audio_result(std::span<const std::uint8_t> bytes);
void run_audio_worker(HANDLE reader, HANDLE writer, std::uint64_t session, std::uint64_t app_id);
} // namespace aether::security
