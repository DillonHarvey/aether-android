#include "aether/security/audio_broker.hpp"
#include <algorithm>
#include <atomic>

namespace aether::security {
namespace {
void require(bool condition, host::AudioFailure reason = host::AudioFailure::argument) {
    if (!condition)
        throw host::AudioError(reason, "Invalid bounded audio request");
}
std::uint64_t stream_token() {
    static std::atomic<std::uint64_t> next{1};
    auto value = next.load();
    do {
        require(value <= UINT32_MAX, host::AudioFailure::quota);
    } while (!next.compare_exchange_weak(value, value + 1));
    return 0xb6a0000000000000ULL | value;
}
} // namespace
AudioBroker::AudioBroker(bool allowed, std::unique_ptr<host::AudioService> provider, bool retain_fixture_pcm)
    : allowed_(allowed), retain_fixture_pcm_(retain_fixture_pcm), provider_(std::move(provider)) {
    if (allowed_ && !provider_)
        throw ProtocolError("AETHER_BROKER_POLICY: missing audio provider");
}
AudioBroker::~AudioBroker() { revoke(); }
void AudioBroker::update() {
    if (stream_) {
        last_.info = stream_->info();
        last_.metrics = stream_->metrics();
        last_.state = stream_->state();
    }
}
void AudioBroker::cancel() noexcept {
    expected_.reset();
    pcm_.clear();
}
void AudioBroker::close() {
    cancel();
    if (!stream_)
        return;
    // Retire even if close fails: no replay of a failed resource operation.
    auto retiring = std::move(stream_);
    try {
        retiring->close();
    } catch (...) {
        last_.metrics = retiring->metrics();
        last_.state = host::AudioState::closed;
        throw;
    }
    last_.metrics = retiring->metrics();
    last_.state = host::AudioState::closed;
}
void AudioBroker::revoke() noexcept {
    allowed_ = false;
    try {
        close();
    } catch (...) {
        ++last_.metrics.cleanup_failures;
    }
}
void AudioBroker::execute(const Frame &request) {
    using host::AudioFailure;
    require(allowed_, AudioFailure::denied);
    require(request.payload.size() <= maximum_payload);
    const auto op = request.header.operation;
    const auto &p = request.payload;
    if (op == Operation::audio_open) {
        require(p.size() == 16);
        const auto rate = read_u64(p, 0), channels = read_u64(p, 8);
        require(rate >= 8000 && rate <= 192000 && (channels == 1 || channels == 2));
        require(!stream_, AudioFailure::quota);
        const auto token = stream_token();
        stream_ =
            provider_->open({static_cast<std::uint32_t>(rate), static_cast<std::uint32_t>(channels), false});
        require(stream_ != nullptr, AudioFailure::windows);
        last_.token = token;
        last_.value = 0;
        update();
        return;
    }
    require(p.size() >= 8);
    require(stream_ && read_u64(p, 0) == last_.token, AudioFailure::state);
    last_.value = 0;
    if (op == Operation::audio_close) {
        require(p.size() == 8);
        close();
        return;
    }
    // An unfinished upload cannot be interleaved with a stream mutation or observation.
    require(!expected_ || op == Operation::audio_write_chunk || op == Operation::audio_write_commit,
            AudioFailure::state);
    if (op == Operation::audio_control) {
        require(p.size() == 16);
        const auto action = read_u64(p, 8);
        require(action <= static_cast<std::uint64_t>(AudioControl::stop));
        switch (static_cast<AudioControl>(action)) {
        case AudioControl::start:
            stream_->start();
            break;
        case AudioControl::pause:
            stream_->pause();
            break;
        case AudioControl::flush:
            stream_->flush();
            break;
        case AudioControl::stop:
            stream_->request_stop();
            break;
        }
    } else if (op == Operation::audio_observe) {
        require(p.size() == 8);
        stream_->observe();
    } else if (op == Operation::audio_wait) {
        require(p.size() == 24);
        const auto state = read_u64(p, 8), duration = read_u64(p, 16);
        require(state <= static_cast<std::uint64_t>(host::AudioState::disconnected) &&
                duration <= host::AudioStream::maximum_timeout_ns);
        last_.value = stream_->wait_for_change(static_cast<host::AudioState>(state),
                                               static_cast<std::int64_t>(duration));
    } else if (op == Operation::audio_write_begin) {
        require(p.size() == 24);
        const auto count = read_u64(p, 8), duration = read_u64(p, 16);
        require(count <= host::AudioStream::maximum_write_bytes && count % (last_.info.channels * 2) == 0 &&
                duration <= host::AudioStream::maximum_timeout_ns);
        pcm_.clear();
        pcm_.reserve(static_cast<std::size_t>(count));
        expected_ = static_cast<std::size_t>(count);
        deadline_ = std::chrono::steady_clock::now() + std::chrono::nanoseconds(duration);
    } else if (op == Operation::audio_write_chunk) {
        require(expected_.has_value() && p.size() > 16 && p.size() <= 16 + audio_chunk_bytes);
        require(read_u64(p, 8) == pcm_.size() && p.size() - 16 <= *expected_ - pcm_.size());
        pcm_.insert(pcm_.end(), p.begin() + 16, p.end());
    } else if (op == Operation::audio_write_commit) {
        require(p.size() == 8 && expected_ && pcm_.size() == *expected_);
        const auto remaining = std::max<std::int64_t>(0, std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                             deadline_ - std::chrono::steady_clock::now())
                                                             .count());
        // Remove the pending transaction before calling the device, even if it throws.
        expected_.reset();
        if (retain_fixture_pcm_ && capture_.empty() && pcm_.size() == host::AudioStream::maximum_write_bytes)
            capture_ = pcm_;
        last_.value = stream_->write(pcm_, remaining);
        require(last_.value <= pcm_.size() / (last_.info.channels * 2), AudioFailure::windows);
        pcm_.clear();
    } else
        require(false);
    update();
}
Frame AudioBroker::dispatch(const Frame &request) {
    try {
        execute(request);
        auto payload = last_.encode();
        return {{request.header.operation, request.header.sequence, request.header.session,
                 static_cast<std::uint32_t>(payload.size()), Status::ok},
                std::move(payload)};
    } catch (const host::AudioError &error) {
        cancel();
        update();
        if (error.reason == host::AudioFailure::disconnected || error.reason == host::AudioFailure::windows) {
            try {
                close();
            } catch (...) {
                ++last_.metrics.cleanup_failures;
            }
        }
        return audio_failure(request, error.reason, error.native);
    } catch (const ProtocolError &) {
        cancel();
        // This also catches a noncanonical provider snapshot. Retire it before another request.
        try {
            close();
        } catch (...) {
            ++last_.metrics.cleanup_failures;
        }
        return audio_failure(request, host::AudioFailure::argument);
    } catch (...) {
        revoke();
        throw;
    }
}
} // namespace aether::security
