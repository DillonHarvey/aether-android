#pragma once
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

namespace aether::host {
enum class AudioFailure { argument, state, thread, unavailable, disconnected, windows, denied, quota };
class AudioError final : public std::runtime_error {
  public:
    AudioError(AudioFailure why, std::string message, std::int32_t code = 0)
        : std::runtime_error(std::move(message)), reason(why), native(code) {}
    const AudioFailure reason;
    const std::int32_t native;
};
enum class AudioState { open, started, paused, flushed, stopping, stopped, closed, disconnected };
struct AudioConfig {
    std::uint32_t sample_rate = 48000, channels = 2;
    bool muted = false; // Trusted-host choice; never the endpoint/master mute.
};
// Trusted host context only; never accepted in a worker audio request. The
// installation owner validates and retains the selected icon's path identity.
struct AudioSessionIdentity {
    std::string installed_id, display_name;
    std::filesystem::path icon_path;
};
struct AudioInfo {
    std::string endpoint;
    std::uint32_t sample_rate = 0, channels = 0, buffer_frames = 0, burst_frames = 0;
    std::uint32_t mix_rate = 0, mix_channels = 0, mix_bits = 0, mix_tag = 0;
    std::uint64_t period_100ns = 0, latency_100ns = 0, clock_frequency = 0;
    bool muted = false;
};
struct AudioMetrics {
    std::uint64_t frames_written = 0, frames_read = 0, frames_discarded = 0, packets = 0;
    std::uint64_t write_calls = 0, short_writes = 0, event_waits = 0, event_wakes = 0;
    std::uint64_t starts = 0, pauses = 0, stops = 0, flushes = 0, clock_reads = 0;
    std::uint64_t clock_position = 0, clock_qpc_100ns = 0, imprecise_clock_reads = 0;
    std::uint64_t pcm_checksum = 14695981039346656037ULL, cleanup_failures = 0;
    std::uint32_t padding = 0;
};
// Single owner thread. Values and PCM only; no COM, Windows handle or native pointer escapes.
// Construction uses the current default multimedia playback endpoint, never capture/loopback.
class AudioStream {
  public:
    static constexpr std::size_t maximum_write_bytes = 131072;
    static constexpr std::int64_t maximum_timeout_ns = 2'000'000'000;
    virtual ~AudioStream() = default;
    virtual const AudioInfo &info() const noexcept = 0;
    virtual const AudioMetrics &metrics() const noexcept = 0;
    virtual AudioState state() const noexcept = 0;
    virtual std::uint32_t write(std::span<const std::uint8_t> pcm, std::int64_t timeout_ns) = 0;
    virtual void start() = 0;
    virtual void pause() = 0;
    virtual void request_stop() = 0;
    virtual void flush() = 0;
    virtual void observe() = 0;
    virtual bool wait_for_change(AudioState previous, std::int64_t timeout_ns) = 0;
    virtual void close() = 0;
};
class AudioService {
  public:
    virtual ~AudioService() = default;
    virtual std::unique_ptr<AudioStream> open(AudioConfig config) = 0;
};
class HostAudioStream final : public AudioStream {
  public:
    explicit HostAudioStream(AudioConfig config, std::optional<AudioSessionIdentity> identity = {});
    ~HostAudioStream() override;
    HostAudioStream(const HostAudioStream &) = delete;
    HostAudioStream &operator=(const HostAudioStream &) = delete;
    const AudioInfo &info() const noexcept override;
    const AudioMetrics &metrics() const noexcept override;
    AudioState state() const noexcept override;
    std::uint32_t write(std::span<const std::uint8_t> pcm, std::int64_t timeout_ns) override;
    void start() override;
    void pause() override;
    void request_stop() override;
    void flush() override;
    // Refreshes padding/state and the actual device clock. No failed writes are retried.
    void observe() override;
    bool wait_for_change(AudioState previous, std::int64_t timeout_ns) override;
    void close() override;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
// Without identity, muting is a trusted fixture choice. Installed sessions use
// Windows-owned persistent volume/mute controls and never reset their values.
class HostAudioService final : public AudioService {
  public:
    explicit HostAudioService(bool muted = false) : muted_(muted) {}
    explicit HostAudioService(AudioSessionIdentity identity) : muted_(false), identity_(std::move(identity)) {}
    std::unique_ptr<AudioStream> open(AudioConfig config) override {
        config.muted = muted_;
        return std::make_unique<HostAudioStream>(config, identity_);
    }

  private:
    bool muted_;
    std::optional<AudioSessionIdentity> identity_;
};
} // namespace aether::host
