#pragma once
#include "aether/security/audio_protocol.hpp"
#include <chrono>
#include <optional>

namespace aether::security {
// Owned by one broker channel. Staged PCM never reaches WASAPI before a complete commit.
class AudioBroker final {
  public:
    AudioBroker(bool allowed, std::unique_ptr<host::AudioService> provider, bool retain_fixture_pcm = false);
    ~AudioBroker();
    Frame dispatch(const Frame &request);
    void revoke() noexcept;
    bool has_stream() const noexcept { return stream_ != nullptr; }
    std::size_t staged_bytes() const noexcept { return pcm_.size(); }
    const AudioSnapshot &snapshot() const noexcept { return last_; }
    const std::vector<std::uint8_t> &fixture_pcm() const noexcept { return capture_; }

  private:
    bool allowed_, retain_fixture_pcm_;
    std::unique_ptr<host::AudioService> provider_;
    std::unique_ptr<host::AudioStream> stream_;
    AudioSnapshot last_;
    std::optional<std::size_t> expected_;
    std::vector<std::uint8_t> pcm_, capture_;
    std::chrono::steady_clock::time_point deadline_;
    void update();
    void cancel() noexcept;
    void close();
    void execute(const Frame &request);
};
} // namespace aether::security
