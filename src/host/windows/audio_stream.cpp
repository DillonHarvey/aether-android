#include "aether/host/audio_stream.hpp"
#include "aether/common/text.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include <Windows.h>
#include <algorithm>
#include <audioclient.h>
#include <audiopolicy.h>
#include <chrono>
#include <cstring>
#include <limits>
#include <mmdeviceapi.h>
#include <optional>
#include <propsys.h>
#include <sstream>
#include <thread>
#include <wrl/client.h>

#include <functiondiscoverykeys_devpkey.h>

namespace aether::host {
namespace {
using Microsoft::WRL::ComPtr;
using Steady = std::chrono::steady_clock;
[[noreturn]] void failed(AudioFailure kind, const char *operation, HRESULT result = S_OK) {
    std::ostringstream text;
    text << operation;
    if (FAILED(result))
        text << " (HRESULT 0x" << std::hex << static_cast<std::uint32_t>(result) << ')';
    throw AudioError(kind, text.str(), result);
}
void check(HRESULT result, const char *operation) {
    if (FAILED(result)) {
        const auto kind = result == AUDCLNT_E_DEVICE_INVALIDATED || result == AUDCLNT_E_RESOURCES_INVALIDATED
                              ? AudioFailure::disconnected
                          : result == AUDCLNT_E_SERVICE_NOT_RUNNING || result == E_NOTFOUND
                              ? AudioFailure::unavailable
                              : AudioFailure::windows;
        failed(kind, operation, result);
    }
}
void timeout_valid(std::int64_t value) {
    if (value < 0 || value > HostAudioStream::maximum_timeout_ns)
        failed(AudioFailure::argument, "Audio timeout must be between zero and two seconds");
}
struct Apartment {
    bool owned = false;
    Apartment() {
        const auto result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (result != RPC_E_CHANGED_MODE)
            check(result, "Initialize audio COM apartment");
        owned = SUCCEEDED(result);
    }
    ~Apartment() {
        if (owned)
            CoUninitialize();
    }
};
struct MixFormat {
    WAVEFORMATEX *value = nullptr;
    ~MixFormat() { CoTaskMemFree(value); }
};
struct Property {
    PROPVARIANT value{};
    ~Property() { PropVariantClear(&value); }
};
} // namespace
struct HostAudioStream::Impl {
    const std::thread::id owner = std::this_thread::get_id();
    Apartment apartment;
    UniqueHandle event;
    ComPtr<IMMDeviceEnumerator> enumerator;
    ComPtr<IMMDevice> device;
    ComPtr<IAudioClient> client;
    ComPtr<IAudioRenderClient> render;
    ComPtr<IAudioClock> clock;
    ComPtr<ISimpleAudioVolume> volume;
    AudioInfo info;
    AudioMetrics stats;
    AudioState state = AudioState::open;
    bool running = false;
    std::optional<Steady::time_point> drained_at;
    explicit Impl(AudioConfig config) {
        if (config.sample_rate < 8000 || config.sample_rate > 192000 || config.channels < 1 ||
            config.channels > 2)
            failed(AudioFailure::argument, "Audio requires 8-192 kHz mono/stereo PCM16");
        check(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_INPROC_SERVER,
                               IID_PPV_ARGS(&enumerator)),
              "Create audio endpoint enumerator");
        check(enumerator->GetDefaultAudioEndpoint(eRender, eMultimedia, &device),
              "No default multimedia playback endpoint");
        ComPtr<IPropertyStore> properties;
        check(device->OpenPropertyStore(STGM_READ, &properties), "Read audio endpoint properties");
        Property name;
        check(properties->GetValue(PKEY_Device_FriendlyName, &name.value), "Read audio endpoint name");
        if (name.value.vt != VT_LPWSTR || !name.value.pwszVal)
            failed(AudioFailure::windows, "Audio endpoint name has an unexpected type");
        info.endpoint = utf8(name.value.pwszVal);
        check(device->Activate(__uuidof(IAudioClient), CLSCTX_INPROC_SERVER, nullptr,
                               reinterpret_cast<void **>(client.GetAddressOf())),
              "Activate WASAPI audio client");
        MixFormat mix;
        check(client->GetMixFormat(&mix.value), "Query audio engine mix format");
        if (!mix.value)
            failed(AudioFailure::windows, "Audio engine returned no mix format");
        info.mix_rate = mix.value->nSamplesPerSec;
        info.mix_channels = mix.value->nChannels;
        info.mix_bits = mix.value->wBitsPerSample;
        info.mix_tag = mix.value->wFormatTag;
        REFERENCE_TIME period = 0, minimum = 0;
        check(client->GetDevicePeriod(&period, &minimum), "Query audio engine period");
        if (period <= 0 || period > 10'000'000)
            failed(AudioFailure::windows, "Audio engine period is outside the supported bound");
        info.period_100ns = static_cast<std::uint64_t>(period);
        info.sample_rate = config.sample_rate;
        info.channels = config.channels;
        info.burst_frames =
            static_cast<std::uint32_t>((info.period_100ns * config.sample_rate + 9'999'999) / 10'000'000);
        WAVEFORMATEX format{};
        format.wFormatTag = WAVE_FORMAT_PCM;
        format.nChannels = static_cast<WORD>(config.channels);
        format.nSamplesPerSec = config.sample_rate;
        format.wBitsPerSample = 16;
        format.nBlockAlign = static_cast<WORD>(config.channels * 2);
        format.nAvgBytesPerSec = config.sample_rate * format.nBlockAlign;
        GUID session{};
        check(CoCreateGuid(&session), "Create private audio session identity");
        event.reset(CreateEventW(nullptr, FALSE, FALSE, nullptr));
        if (!event)
            failed(AudioFailure::windows, "Create audio buffer event", HRESULT_FROM_WIN32(GetLastError()));
        constexpr DWORD flags = AUDCLNT_STREAMFLAGS_EVENTCALLBACK | AUDCLNT_STREAMFLAGS_NOPERSIST |
                                AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY;
        check(client->Initialize(AUDCLNT_SHAREMODE_SHARED, flags, 0, 0, &format, &session),
              "Initialize shared PCM16 WASAPI stream");
        check(client->SetEventHandle(event.get()), "Bind audio buffer event");
        check(client->GetBufferSize(&info.buffer_frames), "Query WASAPI buffer capacity");
        if (!info.buffer_frames || info.buffer_frames > 65536)
            failed(AudioFailure::windows, "WASAPI buffer exceeds the 65,536-frame bound");
        REFERENCE_TIME latency = 0;
        check(client->GetStreamLatency(&latency), "Query WASAPI stream latency");
        if (latency < 0 || latency > 10'000'000)
            failed(AudioFailure::windows, "WASAPI stream latency exceeds the one-second bound");
        info.latency_100ns = static_cast<std::uint64_t>(latency);
        check(client->GetService(IID_PPV_ARGS(&render)), "Acquire WASAPI render service");
        check(client->GetService(IID_PPV_ARGS(&clock)), "Acquire WASAPI device clock");
        check(client->GetService(IID_PPV_ARGS(&volume)), "Acquire private session volume");
        check(clock->GetFrequency(&info.clock_frequency), "Query audio clock frequency");
        if (!info.clock_frequency)
            failed(AudioFailure::windows, "Audio clock frequency is zero");
        check(volume->SetMute(config.muted ? TRUE : FALSE, nullptr), "Set private session mute");
        BOOL muted = FALSE;
        check(volume->GetMute(&muted), "Verify private session mute");
        info.muted = muted != FALSE;
        if (info.muted != config.muted)
            failed(AudioFailure::windows, "Audio session mute does not match the requested state");
    }
    ~Impl() { cleanup(); }
    void thread() const {
        if (owner != std::this_thread::get_id())
            failed(AudioFailure::thread, "Audio stream belongs to another thread");
    }
    void live() const {
        thread();
        if (state == AudioState::closed || state == AudioState::disconnected)
            failed(state == AudioState::disconnected ? AudioFailure::disconnected : AudioFailure::state,
                   "Audio stream is closed or disconnected");
    }
    void operation(HRESULT result, const char *name) {
        if (FAILED(result))
            state = AudioState::disconnected;
        check(result, name);
    }
    void padding() {
        operation(client->GetCurrentPadding(&stats.padding), "Query WASAPI queued frames");
        if (stats.padding > info.buffer_frames || stats.padding > stats.frames_written)
            failed(AudioFailure::windows, "Invalid WASAPI padding count");
        stats.frames_read = std::max(stats.frames_read, stats.frames_written - stats.padding);
        if (state == AudioState::stopping && stats.padding == 0) {
            // Empty shared padding proves engine consumption. Allow the reported endpoint
            // latency and one engine period before freezing the remaining device timeline.
            if (!drained_at)
                drained_at =
                    Steady::now() + std::chrono::nanoseconds((info.latency_100ns + info.period_100ns) * 100);
            if (Steady::now() < *drained_at)
                return;
            operation(client->Stop(), "Stop drained WASAPI stream");
            running = false;
            state = AudioState::stopped;
            ++stats.stops;
        }
    }
    bool wait(Steady::time_point deadline) {
        const auto now = Steady::now();
        if (now >= deadline)
            return false;
        const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - now).count();
        const auto milliseconds = static_cast<DWORD>(std::min<std::int64_t>((ns + 999999) / 1000000, 2000));
        ++stats.event_waits;
        const auto result = WaitForSingleObject(event.get(), milliseconds);
        if (result == WAIT_OBJECT_0) {
            ++stats.event_wakes;
            return true;
        }
        if (result == WAIT_TIMEOUT)
            return false;
        failed(AudioFailure::windows, "Wait for WASAPI buffer event", HRESULT_FROM_WIN32(GetLastError()));
    }
    void cleanup() noexcept {
        if (state == AudioState::closed)
            return;
        if (client && running && FAILED(client->Stop()))
            ++stats.cleanup_failures;
        running = false;
        volume.Reset();
        clock.Reset();
        render.Reset();
        client.Reset();
        device.Reset();
        enumerator.Reset();
        event.reset();
        stats.padding = 0;
        state = AudioState::closed;
    }
};
HostAudioStream::HostAudioStream(AudioConfig config) : impl_(std::make_unique<Impl>(config)) {}
HostAudioStream::~HostAudioStream() = default;
const AudioInfo &HostAudioStream::info() const noexcept { return impl_->info; }
const AudioMetrics &HostAudioStream::metrics() const noexcept { return impl_->stats; }
AudioState HostAudioStream::state() const noexcept { return impl_->state; }
std::uint32_t HostAudioStream::write(std::span<const std::uint8_t> pcm, std::int64_t timeout_ns) {
    auto &p = *impl_;
    p.live();
    timeout_valid(timeout_ns);
    const auto stride = p.info.channels * 2;
    if (pcm.size() > maximum_write_bytes || pcm.size() % stride)
        failed(AudioFailure::argument, "Audio write is oversized or contains a partial PCM frame");
    if (p.state == AudioState::stopping)
        failed(AudioFailure::state, "Cannot write while an audio stream is draining");
    ++p.stats.write_calls;
    const auto frames = static_cast<std::uint32_t>(pcm.size() / stride);
    const auto deadline = Steady::now() + std::chrono::nanoseconds(timeout_ns);
    std::uint32_t written = 0;
    while (written < frames) {
        p.padding();
        const auto count = std::min(frames - written, p.info.buffer_frames - p.stats.padding);
        if (count) {
            BYTE *buffer = nullptr;
            p.operation(p.render->GetBuffer(count, &buffer), "Acquire WASAPI output packet");
            if (!buffer) {
                p.render->ReleaseBuffer(count, AUDCLNT_BUFFERFLAGS_SILENT);
                failed(AudioFailure::windows, "WASAPI returned a null output packet");
            }
            const auto bytes = pcm.subspan(static_cast<std::size_t>(written) * stride,
                                           static_cast<std::size_t>(count) * stride);
            std::memcpy(buffer, bytes.data(), bytes.size());
            auto checksum = p.stats.pcm_checksum;
            for (const auto value : std::span{buffer, bytes.size()}) {
                checksum ^= value;
                checksum *= 1099511628211ULL;
            }
            p.operation(p.render->ReleaseBuffer(count, 0), "Submit WASAPI PCM packet");
            p.stats.pcm_checksum = checksum;
            p.stats.frames_written += count;
            ++p.stats.packets;
            written += count;
        } else if (!p.wait(deadline))
            break;
        if (written < frames && Steady::now() >= deadline)
            break;
    }
    if (written < frames)
        ++p.stats.short_writes;
    p.padding();
    return written;
}
void HostAudioStream::start() {
    auto &p = *impl_;
    p.live();
    if (p.state == AudioState::started || p.state == AudioState::stopping)
        failed(AudioFailure::state, "Audio stream is already started or draining");
    p.operation(p.client->Start(), "Start WASAPI stream");
    p.running = true;
    p.state = AudioState::started;
    ++p.stats.starts;
}
void HostAudioStream::pause() {
    auto &p = *impl_;
    p.live();
    if (p.state != AudioState::started)
        failed(AudioFailure::state, "Only a started audio stream can pause");
    p.operation(p.client->Stop(), "Pause WASAPI stream");
    p.running = false;
    p.state = AudioState::paused;
    ++p.stats.pauses;
    observe();
}
void HostAudioStream::request_stop() {
    auto &p = *impl_;
    p.live();
    if (p.state != AudioState::started)
        failed(AudioFailure::state, "Only a started audio stream can drain and stop");
    p.state = AudioState::stopping;
    p.drained_at.reset();
    p.padding();
}
void HostAudioStream::flush() {
    auto &p = *impl_;
    p.live();
    if (p.running)
        failed(AudioFailure::state, "Pause or stop audio before flushing");
    p.padding();
    const auto discarded = p.stats.padding;
    p.operation(p.client->Reset(), "Flush WASAPI queued frames");
    p.stats.frames_discarded += discarded;
    p.stats.frames_read = p.stats.frames_written;
    p.stats.padding = 0;
    p.stats.clock_position = 0;
    p.state = AudioState::flushed;
    ++p.stats.flushes;
}
void HostAudioStream::observe() {
    auto &p = *impl_;
    p.live();
    p.padding();
    const auto result = p.clock->GetPosition(&p.stats.clock_position, &p.stats.clock_qpc_100ns);
    p.operation(result, "Read WASAPI device position");
    ++p.stats.clock_reads;
    if (result == S_FALSE)
        ++p.stats.imprecise_clock_reads;
}
bool HostAudioStream::wait_for_change(AudioState previous, std::int64_t timeout_ns) {
    auto &p = *impl_;
    p.live();
    timeout_valid(timeout_ns);
    const auto deadline = Steady::now() + std::chrono::nanoseconds(timeout_ns);
    do {
        observe();
        if (p.state != previous)
            return true;
        if (!p.wait(deadline))
            break;
    } while (Steady::now() < deadline);
    observe();
    return p.state != previous;
}
void HostAudioStream::close() {
    impl_->thread();
    impl_->cleanup();
}
} // namespace aether::host
