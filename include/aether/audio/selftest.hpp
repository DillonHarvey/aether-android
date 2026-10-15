#pragma once
#include "aether/audio/guest.hpp"
#include "aether/host/time_service.hpp"
#include <filesystem>
#include <utility>
#include <vector>

namespace aether::audio {
struct SelftestReport {
    std::string fixture_hash, capture_path, isolation_json;
    std::size_t relocations = 0;
    std::uint64_t fixture_frames = 0, prefilled_frames = 0, paused_clock = 0, paused_clock_after = 0;
    host::AudioInfo host;
    host::AudioMetrics playback;
    Metrics audio;
    a64::Metrics cpu;
    std::vector<std::pair<std::string, bool>> checks;
    bool passed() const;
    std::string json() const;
    std::string text(bool verbose) const;
};
SelftestReport execute_audio_fixture(std::span<const std::uint8_t> bytes, std::uint64_t app_id,
                                     host::TimeService &time, host::AudioService &provider);
SelftestReport audio_selftest(const std::filesystem::path &fixture);
} // namespace aether::audio
