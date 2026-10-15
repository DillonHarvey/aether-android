#include "aether/audio/guest.hpp"
#include <algorithm>
#include <atomic>
#include <bit>
#include <map>
#include <thread>
#include <vector>

namespace aether::audio {
namespace {
// Android API 26 scalar constants, verified against the reviewed NDK r30 AAudio.h.
constexpr std::int32_t ok = 0, disconnected = -899, illegal = -898, internal = -896, invalid_state = -895,
                       invalid_handle = -892, unimplemented = -890, no_handles = -888, no_memory = -887,
                       timeout = -885, invalid_format = -883, out_of_range = -882, no_service = -881,
                       invalid_rate = -880;
enum class Operation {
    create_builder,
    delete_builder,
    set_rate,
    set_channels,
    set_samples,
    set_format,
    set_sharing,
    set_direction,
    set_performance,
    set_capacity,
    open,
    close,
    start,
    pause,
    flush,
    stop,
    state,
    wait_state,
    write,
    get_rate,
    get_channels,
    get_samples,
    get_format,
    get_sharing,
    get_direction,
    get_performance,
    get_capacity,
    get_size,
    get_burst,
    frames_written,
    frames_read,
    count
};
constexpr std::array<std::string_view, static_cast<std::size_t>(Operation::count)> entries{
    "AAudio_createStreamBuilder",
    "AAudioStreamBuilder_delete",
    "AAudioStreamBuilder_setSampleRate",
    "AAudioStreamBuilder_setChannelCount",
    "AAudioStreamBuilder_setSamplesPerFrame",
    "AAudioStreamBuilder_setFormat",
    "AAudioStreamBuilder_setSharingMode",
    "AAudioStreamBuilder_setDirection",
    "AAudioStreamBuilder_setPerformanceMode",
    "AAudioStreamBuilder_setBufferCapacityInFrames",
    "AAudioStreamBuilder_openStream",
    "AAudioStream_close",
    "AAudioStream_requestStart",
    "AAudioStream_requestPause",
    "AAudioStream_requestFlush",
    "AAudioStream_requestStop",
    "AAudioStream_getState",
    "AAudioStream_waitForStateChange",
    "AAudioStream_write",
    "AAudioStream_getSampleRate",
    "AAudioStream_getChannelCount",
    "AAudioStream_getSamplesPerFrame",
    "AAudioStream_getFormat",
    "AAudioStream_getSharingMode",
    "AAudioStream_getDirection",
    "AAudioStream_getPerformanceMode",
    "AAudioStream_getBufferCapacityInFrames",
    "AAudioStream_getBufferSizeInFrames",
    "AAudioStream_getFramesPerBurst",
    "AAudioStream_getFramesWritten",
    "AAudioStream_getFramesRead"};
std::int32_t integer(std::uint64_t value) {
    return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value));
}
struct ApiFailure {
    std::int32_t result;
    const char *message;
};
struct Rejection {
    a64::Fault fault;
    const char *message;
};
std::uint64_t token() {
    static std::atomic<std::uint64_t> next{1};
    auto id = next.load();
    do {
        if (id >= 0x100000000ULL)
            throw ApiFailure{no_handles, "Audio identity quota exhausted"};
    } while (!next.compare_exchange_weak(id, id + 1));
    return 0xa6a0000000000000ULL | id;
}
std::uint64_t result(std::int32_t value) { return static_cast<std::uint32_t>(value); }
std::int32_t android_state(host::AudioState state) {
    switch (state) {
    case host::AudioState::open:
        return 2;
    case host::AudioState::started:
        return 4;
    case host::AudioState::paused:
        return 6;
    case host::AudioState::flushed:
        return 8;
    case host::AudioState::stopping:
        return 9;
    case host::AudioState::stopped:
        return 10;
    case host::AudioState::closed:
        return 12;
    case host::AudioState::disconnected:
        return 13;
    }
    return 1;
}
} // namespace
std::span<const std::string_view> api_registry() noexcept { return entries; }
struct GuestAudioServices::Impl {
    struct Builder {
        std::int32_t rate = 0, channels = 0, format = 0, sharing = 1, direction = 0, performance = 10,
                     capacity = 0;
    };
    a64::GuestMemory &memory;
    const a64::AppContext &app;
    const std::thread::id owner = std::this_thread::get_id();
    host::HostAudioService direct;
    host::AudioService &provider;
    bool owned = false, closed = false;
    std::map<std::uint64_t, Builder> builders;
    std::uint64_t stream_token = 0;
    std::unique_ptr<host::AudioStream> stream;
    Metrics stats;
    host::AudioInfo info;
    host::AudioMetrics last_host;
    std::string error;
    Impl(a64::GuestMemory &m, const a64::AppContext &a, bool mute, host::AudioService *service)
        : memory(m), app(a), direct(mute), provider(service ? *service : direct) {}
    ~Impl() { cleanup(); }
    void writable(a64::Address address, std::size_t size) const {
        if (!memory.accessible(address, size, a64::Permission::write))
            throw Rejection{a64::Fault::write, "AAudio output is outside writable guest memory"};
    }
    void put(a64::Address address, std::uint64_t value, std::size_t size) {
        std::array<std::uint8_t, 8> data{};
        for (std::size_t i = 0; i < size; ++i)
            data[i] = static_cast<std::uint8_t>(value >> (8 * i));
        if (!memory.write(address, std::span{data}.first(size)))
            throw Rejection{a64::Fault::write, "Cannot copy an AAudio result to guest memory"};
    }
    Builder &builder(std::uint64_t id) {
        const auto found = builders.find(id);
        if (found == builders.end())
            throw ApiFailure{invalid_handle, "AAudio builder is stale or belongs to another app"};
        return found->second;
    }
    host::AudioStream &audio(std::uint64_t id) {
        if (!stream || id != stream_token)
            throw ApiFailure{invalid_handle, "AAudio stream is stale or belongs to another app"};
        return *stream;
    }
    void retire() {
        if (stream) {
            stream->close();
            last_host = stream->metrics();
            stream.reset();
            stream_token = 0;
            stats.streams = 0;
            ++stats.streams_closed;
        }
    }
    void cleanup() noexcept {
        if (closed)
            return;
        try {
            retire();
        } catch (...) {
            ++last_host.cleanup_failures;
        }
        builders.clear();
        stats.builders = 0;
        if (owned) {
            try {
                memory.unmap(trampoline_base);
            } catch (...) {
                ++last_host.cleanup_failures;
            }
            owned = false;
        }
        closed = true;
    }
    std::uint64_t dispatch(Operation op, std::array<std::uint64_t, 31> &r) {
        if (op == Operation::create_builder) {
            writable(r[0], 8);
            if (builders.size() >= 4)
                throw ApiFailure{no_handles, "AAudio builder quota is four per app"};
            const auto id = token();
            builders.emplace(id, Builder{});
            put(r[0], id, 8);
            stats.builders = builders.size();
            return ok;
        }
        if (op <= Operation::open) {
            auto &b = builder(r[0]);
            const auto value = integer(r[1]);
            switch (op) {
            case Operation::delete_builder:
                builders.erase(r[0]);
                stats.builders = builders.size();
                return ok;
            case Operation::set_rate:
                b.rate = value;
                return ok;
            case Operation::set_channels:
            case Operation::set_samples:
                b.channels = value;
                return ok;
            case Operation::set_format:
                b.format = value;
                return ok;
            case Operation::set_sharing:
                b.sharing = value;
                return ok;
            case Operation::set_direction:
                b.direction = value;
                return ok;
            case Operation::set_performance:
                b.performance = value;
                return ok;
            case Operation::set_capacity:
                b.capacity = value;
                return ok;
            case Operation::open: {
                writable(r[1], 8);
                if (b.rate && (b.rate < 8000 || b.rate > 192000))
                    throw ApiFailure{invalid_rate, "AAudio rate must be unspecified or 8-192 kHz"};
                if (b.channels < 0 || b.channels > 2)
                    throw ApiFailure{out_of_range, "AAudio supports unspecified, mono or stereo channels"};
                if (b.format != 0 && b.format != 1)
                    throw ApiFailure{invalid_format, "Only AAudio PCM_I16 is implemented"};
                if (b.direction != 0 || b.sharing != 1 || b.performance != 10 || b.capacity != 0)
                    throw ApiFailure{unimplemented,
                                     "AAudio requires output/shared/normal/default-capacity mode"};
                if (stream)
                    throw ApiFailure{no_handles, "AAudio stream quota is one per app"};
                const auto id = token();
                auto created = provider.open(
                    host::AudioConfig{b.rate ? static_cast<std::uint32_t>(b.rate) : 48000,
                                      b.channels ? static_cast<std::uint32_t>(b.channels) : 2, false});
                info = created->info();
                put(r[1], id, 8);
                stream = std::move(created);
                stream_token = id;
                ++stats.streams_opened;
                stats.streams = 1;
                return ok;
            }
            default:
                break;
            }
        }
        auto &s = audio(r[0]);
        switch (op) {
        case Operation::close:
            retire();
            return ok;
        case Operation::start:
            s.start();
            return ok;
        case Operation::pause:
            s.pause();
            return ok;
        case Operation::flush:
            s.flush();
            return ok;
        case Operation::stop:
            s.request_stop();
            return ok;
        case Operation::state:
            return result(android_state(s.state()));
        case Operation::wait_state: {
            const auto previous = integer(r[1]);
            const auto duration = std::bit_cast<std::int64_t>(r[3]);
            if (previous < 0 || previous > 13 || duration < 0 ||
                duration > host::HostAudioStream::maximum_timeout_ns)
                throw ApiFailure{out_of_range, "AAudio state wait exceeds the supported state/time bounds"};
            if (r[2])
                writable(r[2], 4);
            bool changed = true;
            if (previous == android_state(s.state()))
                changed = s.wait_for_change(s.state(), duration);
            else
                s.observe();
            if (r[2])
                put(r[2], static_cast<std::uint32_t>(android_state(s.state())), 4);
            if (!changed)
                throw ApiFailure{timeout, "AAudio state did not change before the deadline"};
            return ok;
        }
        case Operation::write: {
            const auto frames = integer(r[2]);
            const auto duration = std::bit_cast<std::int64_t>(r[3]);
            if (frames < 0 || frames > 32768 || duration < 0 ||
                duration > host::HostAudioStream::maximum_timeout_ns)
                throw ApiFailure{out_of_range, "AAudio write exceeds 32,768 frames or the two-second bound"};
            const auto count = static_cast<std::size_t>(frames) * s.info().channels * 2;
            if (count && !memory.accessible(r[1], count, a64::Permission::read))
                throw Rejection{a64::Fault::read, "AAudio PCM input is outside readable guest memory"};
            std::vector<std::uint8_t> pcm(count);
            if (count && !memory.read(r[1], pcm))
                throw Rejection{a64::Fault::read, "Cannot copy AAudio PCM from guest memory"};
            return s.write(pcm, duration);
        }
        case Operation::get_rate:
            return s.info().sample_rate;
        case Operation::get_channels:
        case Operation::get_samples:
            return s.info().channels;
        case Operation::get_format:
            return 1;
        case Operation::get_sharing:
            return 1;
        case Operation::get_direction:
            return 0;
        case Operation::get_performance:
            return 10;
        case Operation::get_capacity:
        case Operation::get_size:
            return s.info().buffer_frames;
        case Operation::get_burst:
            return s.info().burst_frames;
        case Operation::frames_written:
            return s.metrics().frames_written;
        case Operation::frames_read:
            s.observe();
            return s.metrics().frames_read;
        default:
            throw Rejection{a64::Fault::unsupported_service, "Unregistered AAudio operation"};
        }
    }
};
GuestAudioServices::GuestAudioServices(a64::GuestMemory &memory, const a64::AppContext &app, bool muted,
                                       host::AudioService *provider)
    : impl_(std::make_unique<Impl>(memory, app, muted, provider)) {
    memory.map(trampoline_base, 4096, a64::read_write);
    impl_->owned = true;
    for (std::size_t i = 0; i < entries.size(); ++i) {
        impl_->put(trampoline_base + i * 8, 0xd4000001u | ((first_service + i) << 5), 4);
        impl_->put(trampoline_base + i * 8 + 4, 0xd65f03c0u, 4);
    }
    memory.protect(trampoline_base, a64::read_execute);
}
GuestAudioServices::~GuestAudioServices() = default;
bool GuestAudioServices::handles_service(std::uint32_t service) noexcept {
    return service >= first_service && service - first_service < entries.size();
}
bool GuestAudioServices::has_library(std::string_view library) const noexcept {
    return library == "libaaudio.so";
}
std::optional<elf::GuestSymbol> GuestAudioServices::resolve(std::string_view library, std::string_view name,
                                                            std::string_view version) const {
    if (!has_library(library) || (!version.empty() && version != "LIBAAUDIO"))
        return std::nullopt;
    const auto found = std::find(entries.begin(), entries.end(), name);
    if (found == entries.end())
        return std::nullopt;
    return elf::GuestSymbol{std::string(name),
                            std::string(library),
                            std::string(version),
                            trampoline_base + static_cast<std::uint64_t>(found - entries.begin()) * 8,
                            8,
                            2};
}
a64::Fault GuestAudioServices::invoke(std::uint32_t service, a64::Address instruction,
                                      std::array<std::uint64_t, 31> &registers) noexcept {
    auto &p = *impl_;
    p.error.clear();
    try {
        if (p.owner != std::this_thread::get_id())
            throw Rejection{a64::Fault::invalid_call, "AAudio belongs to another owner thread"};
        if (p.closed || !handles_service(service) ||
            instruction != trampoline_base + (service - first_service) * 8)
            throw Rejection{a64::Fault::unsupported_service,
                            "AAudio trap is not at its live registered call site"};
        if (!p.app.instance_id || !p.app.audio_playback_allowed)
            throw Rejection{a64::Fault::capability_denied, "This app has no audio playback capability"};
        ++p.stats.calls;
        registers[0] = p.dispatch(static_cast<Operation>(service - first_service), registers);
        return a64::Fault::none;
    } catch (const ApiFailure &failure) {
        ++p.stats.api_errors;
        p.error = failure.message;
        registers[0] = result(failure.result);
    } catch (const host::AudioError &failure) {
        if (failure.reason == host::AudioFailure::denied) {
            ++p.stats.rejected;
            p.error = failure.what();
            return a64::Fault::capability_denied;
        }
        ++p.stats.api_errors;
        p.error = failure.what();
        std::int32_t code = internal;
        switch (failure.reason) {
        case host::AudioFailure::argument:
            code = illegal;
            break;
        case host::AudioFailure::quota:
            code = no_handles;
            break;
        case host::AudioFailure::state:
            code = invalid_state;
            break;
        case host::AudioFailure::unavailable:
            code = no_service;
            break;
        case host::AudioFailure::disconnected:
            code = disconnected;
            break;
        default:
            break;
        }
        registers[0] = result(code);
    } catch (const Rejection &failure) {
        ++p.stats.rejected;
        p.error = failure.message;
        return failure.fault;
    } catch (const std::bad_alloc &) {
        ++p.stats.api_errors;
        p.error = "AAudio host allocation failed";
        registers[0] = result(no_memory);
    } catch (...) {
        ++p.stats.rejected;
        p.error = "Host failure while marshalling AAudio";
        return a64::Fault::windows_service;
    }
    return a64::Fault::none;
}
const Metrics &GuestAudioServices::metrics() const noexcept { return impl_->stats; }
const host::AudioInfo &GuestAudioServices::host_info() const noexcept { return impl_->info; }
const host::AudioMetrics &GuestAudioServices::host_metrics() const noexcept {
    return impl_->stream ? impl_->stream->metrics() : impl_->last_host;
}
std::string_view GuestAudioServices::last_error() const noexcept { return impl_->error; }
void GuestAudioServices::shutdown() {
    if (impl_->owner != std::this_thread::get_id())
        throw a64::GuestError("AETHER_AUDIO_THREAD", "Audio shutdown requires the owner thread");
    impl_->cleanup();
}
} // namespace aether::audio
