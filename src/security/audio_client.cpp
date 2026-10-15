#include "aether/security/audio_client.hpp"
#include "aether/security/audio_protocol.hpp"
#include <algorithm>
#include <thread>

namespace aether::security {
namespace {
class RemoteAudio final : public host::AudioStream {
    BrokerClient &client_;
    const std::thread::id owner_ = std::this_thread::get_id();
    AudioSnapshot cached_;
    bool retired_ = false, broken_ = false;
    void live() const {
        if (owner_ != std::this_thread::get_id())
            throw host::AudioError(host::AudioFailure::thread, "Audio client belongs to another thread");
        if (retired_ || broken_)
            throw host::AudioError(host::AudioFailure::state, "Audio client stream is retired");
    }
    std::vector<std::uint8_t> payload() const {
        std::vector<std::uint8_t> bytes;
        append_u64(bytes, cached_.token);
        return bytes;
    }
    void request(Operation op, std::vector<std::uint8_t> bytes) {
        try {
            auto next = audio_response(client_.request(op, std::move(bytes)));
            if (next.token != cached_.token || next.info.sample_rate != cached_.info.sample_rate ||
                next.info.channels != cached_.info.channels || next.info.muted != cached_.info.muted ||
                next.info.buffer_frames != cached_.info.buffer_frames)
                throw ProtocolError("AETHER_AUDIO_WIRE: stream identity or format changed");
            cached_ = std::move(next);
        } catch (const host::AudioError &error) {
            if (error.reason == host::AudioFailure::denied ||
                error.reason == host::AudioFailure::disconnected ||
                error.reason == host::AudioFailure::windows)
                broken_ = true;
            throw;
        } catch (...) {
            broken_ = true;
            throw;
        }
    }
    void control(AudioControl action) {
        live();
        auto bytes = payload();
        append_u64(bytes, static_cast<std::uint64_t>(action));
        request(Operation::audio_control, std::move(bytes));
    }

  public:
    RemoteAudio(BrokerClient &client, AudioSnapshot initial) : client_(client), cached_(std::move(initial)) {}
    ~RemoteAudio() override {
        if (!retired_ && !broken_ && owner_ == std::this_thread::get_id())
            try {
                close();
            } catch (...) {
            }
    }
    const host::AudioInfo &info() const noexcept override { return cached_.info; }
    const host::AudioMetrics &metrics() const noexcept override { return cached_.metrics; }
    host::AudioState state() const noexcept override { return cached_.state; }
    void start() override { control(AudioControl::start); }
    void pause() override { control(AudioControl::pause); }
    void flush() override { control(AudioControl::flush); }
    void request_stop() override { control(AudioControl::stop); }
    void observe() override {
        live();
        request(Operation::audio_observe, payload());
    }
    bool wait_for_change(host::AudioState previous, std::int64_t duration) override {
        live();
        if (duration < 0 || duration > maximum_timeout_ns || previous > host::AudioState::disconnected)
            throw host::AudioError(host::AudioFailure::argument, "Invalid remote audio wait");
        auto bytes = payload();
        append_u64(bytes, static_cast<std::uint64_t>(previous));
        append_u64(bytes, static_cast<std::uint64_t>(duration));
        request(Operation::audio_wait, std::move(bytes));
        if (cached_.value > 1) {
            broken_ = true;
            throw ProtocolError("AETHER_AUDIO_WIRE: invalid wait result");
        }
        return cached_.value != 0;
    }
    std::uint32_t write(std::span<const std::uint8_t> pcm, std::int64_t duration) override {
        live();
        if (pcm.size() > maximum_write_bytes || pcm.size() % (cached_.info.channels * 2) || duration < 0 ||
            duration > maximum_timeout_ns)
            throw host::AudioError(host::AudioFailure::argument, "Invalid remote audio write");
        auto begin = payload();
        append_u64(begin, pcm.size());
        append_u64(begin, static_cast<std::uint64_t>(duration));
        request(Operation::audio_write_begin, std::move(begin));
        for (std::size_t offset = 0; offset < pcm.size();) {
            const auto count = std::min(audio_chunk_bytes, pcm.size() - offset);
            auto chunk = payload();
            append_u64(chunk, offset);
            chunk.insert(chunk.end(), pcm.begin() + offset, pcm.begin() + offset + count);
            request(Operation::audio_write_chunk, std::move(chunk));
            offset += count;
        }
        request(Operation::audio_write_commit, payload());
        if (cached_.value > pcm.size() / (cached_.info.channels * 2)) {
            broken_ = true;
            throw ProtocolError("AETHER_AUDIO_WIRE: invalid short-write result");
        }
        return static_cast<std::uint32_t>(cached_.value);
    }
    void close() override {
        if (retired_)
            return;
        live();
        retired_ = true;
        request(Operation::audio_close, payload());
        if (cached_.state != host::AudioState::closed) {
            broken_ = true;
            throw ProtocolError("AETHER_AUDIO_WIRE: stream did not close");
        }
    }
};
} // namespace
std::unique_ptr<host::AudioStream> BrokerAudioService::open(host::AudioConfig config) {
    std::vector<std::uint8_t> bytes;
    append_u64(bytes, config.sample_rate);
    append_u64(bytes, config.channels);
    auto initial = audio_response(client_.request(Operation::audio_open, std::move(bytes)));
    if (initial.state != host::AudioState::open || initial.value ||
        initial.info.sample_rate != config.sample_rate || initial.info.channels != config.channels)
        throw ProtocolError("AETHER_AUDIO_WIRE: invalid opened stream");
    return std::make_unique<RemoteAudio>(client_, std::move(initial));
}
} // namespace aether::security
