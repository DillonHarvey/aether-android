#include "input_queue.hpp"
#include "descriptors.hpp"
#include "looper.hpp"
#include "aether/android/native_activity.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <limits>
#include <thread>

namespace aether::bionic {
namespace {
using a64::Fault;
using android::PointerAction;
constexpr std::size_t event_limit = 256;
constexpr std::uint64_t maximum_ms = std::uint64_t{INT64_MAX} / 1'000'000;
struct Failure { Fault fault; std::string_view reason; };
[[noreturn]] void fail(Fault fault, std::string_view reason) { throw Failure{fault, reason}; }
std::uint64_t negative(std::int32_t value) { return static_cast<std::uint64_t>(static_cast<std::int64_t>(value)); }
std::array<std::uint8_t, 8> pointer_bytes(std::uint64_t value) {
    std::array<std::uint8_t, 8> bytes{};
    for (unsigned i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<std::uint8_t>(value >> (i * 8));
    return bytes;
}
bool same_key_capture(const android::NativeActivityKeyInput &left, const android::NativeActivityKeyInput &right) noexcept {
    const auto &a = left.sample;
    const auto &b = right.sample;
    return left.activity == right.activity && left.request == right.request &&
        a.up == b.up && a.code == b.code && a.meta == b.meta && a.repeat == b.repeat &&
        a.character_status == b.character_status && a.unicode == b.unicode &&
        a.root == b.root && a.window_generation == b.window_generation &&
        a.input_generation == b.input_generation && a.capture_generation == b.capture_generation &&
        a.event_time_known == b.event_time_known && a.down_time_known == b.down_time_known &&
        a.down_time_ms == b.down_time_ms && a.event_time_ms == b.event_time_ms &&
        a.source_known == b.source_known && a.source == b.source;
}
} // namespace
struct NativeInputQueues::Impl {
    enum class Phase : std::uint8_t { free, pending, in_flight, finished, reserved_post };
    struct Event {
        std::uint64_t id = 0;
        Phase phase = Phase::free;
        bool handled = false;
        bool no_post = false;
        android::NativeActivityPointerInput input;
        std::optional<android::NativeActivityKeyInput> key;
        std::uint32_t action = 0, source = 0, pointer = 0;
        float x = 0, y = 0;
        std::optional<std::uint64_t> down_ns, event_ns;
    };
    struct State final : NativeDescriptors::PollSource {
        const std::thread::id owner = std::this_thread::get_id();
        std::uint64_t id = 0;
        bool active = true;
        std::array<Event, event_limit> events{};
        std::array<std::size_t, event_limit> pending{};
        std::array<std::size_t, event_limit> ingress{};
        std::size_t head = 0, count = 0, live = 0, occupied = 0;
        std::size_t ingress_head = 0;
        std::uint16_t readiness() const noexcept override {
            if (owner != std::this_thread::get_id()) return 0x20;
            return !active ? 0x10 : count ? 0x41 : 0;
        }
    };
    struct Queue {
        struct Attachment { std::uint64_t looper = 0; NativeLooper::Attachment token; };
        std::shared_ptr<State> state;
        std::shared_ptr<android::NativeActivityInputScope> completion_scope;
        int fd = -1;
        std::weak_ptr<const void> description;
        std::array<Attachment, 64> attachments{};
        std::optional<android::NativeActivityPointerInput> gesture;
        std::uint64_t activity = 0, root = 0, generation = 0;
        std::uint64_t last_key_request = 0;
    };
    a64::GuestMemory &memory;
    NativeDescriptors &descriptors;
    NativeLooper &looper;
    const a64::AppContext &app;
    const std::uint64_t app_id;
    const std::thread::id owner = std::this_thread::get_id();
    std::unique_ptr<Queue> queue;
    std::uint64_t next_event = 0xa1e0000000000001ULL;
    std::uint32_t incarnations = 0;
    std::string_view error;
    Impl(a64::GuestMemory &m, NativeDescriptors &d, NativeLooper &l, const a64::AppContext &a)
        : memory(m), descriptors(d), looper(l), app(a), app_id(a.instance_id) {}
    void owner_check() const {
        if (owner != std::this_thread::get_id() || !app_id || app.instance_id != app_id)
            fail(Fault::invalid_call, "native input queue belongs to another app or host owner");
    }
    void live() const {
        owner_check();
        if (!app.process_state) fail(Fault::invalid_call, "native input queue has no process owner");
        if (app.process_state->exit_status()) fail(Fault::process_exit, "native input queue process has terminated");
    }
    Queue &get(std::uint64_t id) {
        if (!queue || !id || queue->state->id != id || !queue->state->active)
            fail(Fault::invalid_call, "native input queue is stale or foreign");
        return *queue;
    }
    Event &event(std::uint64_t id) {
        if (queue && queue->state->active && id)
            for (auto &event : queue->state->events) if (event.id == id && event.phase == Phase::in_flight) return event;
        fail(Fault::invalid_call, "native input event has no live dequeued lease");
    }
    void retire() noexcept {
        if (!queue) return;
        if (owner != std::this_thread::get_id()) std::terminate();
        queue->completion_scope->active = false;
        queue->state->active = false;
        queue->state->events = {};
        queue->state->head = queue->state->count = queue->state->live = queue->state->occupied = 0;
        queue->state->ingress_head = 0;
        for (auto &attachment : queue->attachments) {
            looper.detach_source(attachment.token);
            attachment.looper = 0;
        }
        const auto original = queue->description.lock();
        if (original && descriptors.descriptor_identity(queue->fd) == original) (void)descriptors.close(queue->fd);
        queue.reset();
    }
};
NativeInputQueues::NativeInputQueues(a64::GuestMemory &memory, NativeDescriptors &descriptors,
                                   NativeLooper &looper, const a64::AppContext &app)
    : impl_(std::make_unique<Impl>(memory, descriptors, looper, app)) {}
NativeInputQueues::~NativeInputQueues() { impl_->retire(); }
std::uint64_t NativeInputQueues::create() {
    auto &p = *impl_;
    try {
        p.live();
        if (p.queue || p.incarnations >= 32) fail(Fault::unsupported_service, "native input queue lifetime capacity exhausted");
        const auto id = 0xa1c0000000000001ULL + p.incarnations++;
        auto queue = std::make_unique<Impl::Queue>();
        queue->state = std::make_shared<Impl::State>();
        queue->completion_scope = std::make_shared<android::NativeActivityInputScope>();
        queue->state->id = id;
        const auto descriptor = p.descriptors.poll_source(queue->state);
        if (descriptor.error != host::FileError::none || descriptor.value < 0 || descriptor.value > 255)
            fail(Fault::unsupported_service, "native input queue readiness descriptor capacity is unavailable");
        queue->fd = static_cast<int>(descriptor.value);
        queue->description = p.descriptors.poll_identity(queue->fd);
        p.queue = std::move(queue);
        return id;
    } catch (const Failure &failure) { throw a64::GuestError("AETHER_NATIVE_INPUT_QUEUE", std::string(failure.reason)); }
}
std::uint64_t NativeInputQueues::current() const noexcept {
    const auto &p = *impl_;
    return p.owner == std::this_thread::get_id() && p.app_id && p.app.instance_id == p.app_id &&
           p.queue && p.queue->state->active ? p.queue->state->id : 0;
}
void NativeInputQueues::shutdown() noexcept { impl_->retire(); }
void NativeInputQueues::retire(std::uint64_t id) {
    auto &p = *impl_;
    try { p.owner_check(); (void)p.get(id); p.retire(); }
    catch (const Failure &failure) { throw a64::GuestError("AETHER_NATIVE_INPUT_QUEUE", std::string(failure.reason)); }
}
bool NativeInputQueues::enqueue(std::uint64_t id, const android::NativeActivityPointerInput &input) {
    auto &p = *impl_;
    try {
        p.live();
        auto &queue = p.get(id);
        const auto endpoint=queue.description.lock();
        if(!endpoint || p.descriptors.poll_identity(queue.fd)!=endpoint)
            fail(Fault::invalid_call,"native input readiness descriptor was closed or replaced; new input was not admitted");
        const auto &sample = input.sample;
        if (!input.activity || !input.root || !input.window_generation || !input.input_generation || input.root != sample.root ||
            !sample.native_producer || !sample.native_width || sample.native_width > 1024 ||
            !sample.native_height || sample.native_height > 1024 || sample.pointer > 31 ||
            sample.capture_dpi < 48 || sample.capture_dpi > 960 ||
            (sample.source != 0x1002 && sample.source != 0x2002) || static_cast<unsigned>(sample.action) > 3 ||
            !std::isfinite(sample.x) || !std::isfinite(sample.y) || std::abs(sample.x) > 65536 || std::abs(sample.y) > 65536)
            fail(Fault::invalid_call, "native pointer sample lacks actual bounded capture identity");
        if (queue.activity && (queue.activity != input.activity || queue.root != input.root || queue.generation != input.window_generation)) return false;
        if (input.synthetic_cancel) {
            if (sample.action != PointerAction::cancel || (!sample.time_known && (sample.down_time_ms || sample.event_time_ms)))
                fail(Fault::invalid_call, "native synthetic cancellation has invalid time provenance");
        } else if (!android::valid_pointer_context(sample) || !sample.time_known)
            fail(Fault::unsupported_service, "native pointer input requires captured ingress times");
        const bool down = sample.action == PointerAction::down;
        const bool terminal = sample.action == PointerAction::up || sample.action == PointerAction::cancel;
        if (down && (queue.gesture || input.synthetic_cancel)) fail(Fault::invalid_call, "native pointer DOWN overlaps a live gesture");
        if (!down && !queue.gesture) return false;
        if (queue.gesture) {
            const auto &origin = queue.gesture->sample;
            if (input.input_generation != queue.gesture->input_generation ||
                sample.pointer != origin.pointer || sample.source != origin.source || sample.root != origin.root ||
                sample.native_producer != origin.native_producer || sample.native_width != origin.native_width ||
                sample.native_height != origin.native_height || sample.capture_dpi != origin.capture_dpi) return false;
            if (!input.down_time_known || input.down_time_ms != origin.down_time_ms ||
                (sample.time_known && (sample.down_time_ms != origin.down_time_ms || sample.event_time_ms < origin.event_time_ms)))
                fail(Fault::invalid_call, "native pointer capture clock or original down time changed");
        } else if (!input.down_time_known || input.down_time_ms != sample.down_time_ms)
            fail(Fault::invalid_call, "native pointer DOWN has no original down-time proof");
        const auto down_ms = down ? sample.down_time_ms : queue.gesture->sample.down_time_ms;
        if (down_ms > maximum_ms || (sample.time_known && (sample.down_time_ms > sample.event_time_ms || sample.event_time_ms > maximum_ms)))
            fail(Fault::unsupported_service, "native pointer nanosecond time is outside int64 range");
        auto &state = *queue.state;
        if (state.occupied >= (terminal ? event_limit : event_limit - 1) || p.next_event == UINT64_MAX)
            fail(Fault::unsupported_service, "native input event capacity exhausted; terminal input is not silently dropped");
        auto available = std::find_if(state.events.begin(), state.events.end(), [](const auto &event) { return event.phase == Impl::Phase::free; });
        if (available == state.events.end() || state.count >= event_limit) std::terminate();
        Impl::Event event;
        event.id = p.next_event++;
        event.phase = Impl::Phase::pending;
        event.input = input; // Keep the original DP/DPI/time and capture envelope.
        event.action = static_cast<std::uint32_t>(sample.action); event.source = sample.source; event.pointer = sample.pointer;
        event.x = sample.x * (static_cast<float>(sample.capture_dpi) / 96.0f);
        event.y = sample.y * (static_cast<float>(sample.capture_dpi) / 96.0f);
        event.down_ns = down_ms * 1'000'000;
        if (sample.time_known) event.event_ns = sample.event_time_ms * 1'000'000;
        *available = event;
        const auto slot = static_cast<std::size_t>(available - state.events.begin());
        state.pending[(state.head + state.count) % event_limit] = slot;
        state.ingress[(state.ingress_head + state.live) % event_limit] = slot;
        ++state.count; ++state.live; ++state.occupied;
        queue.activity = input.activity; queue.root = input.root; queue.generation = input.window_generation;
        if (terminal) queue.gesture.reset();
        else queue.gesture = input;
        return true;
    } catch (const Failure &failure) { throw a64::GuestError("AETHER_NATIVE_INPUT_QUEUE", std::string(failure.reason)); }
}
bool NativeInputQueues::enqueue_key(std::uint64_t id, const android::NativeActivityKeyInput &input) {
    auto &p = *impl_;
    try {
        if (input.stage == android::NativeKeyStage::cancel) {
            // Trusted retirement is valid after endpoint loss/process exit.
            // Authenticate existing custody without consulting any provider.
            p.owner_check();
            if (!p.queue || !id || p.queue->state->id != id || !p.queue->state->active) return false;
            auto &state = *p.queue->state;
            const auto slot = std::find_if(state.events.begin(), state.events.end(), [&](const auto &event) {
                return event.key && event.key->request == input.request;
            });
            if (slot == state.events.end()) return false;
            if (!same_key_capture(*slot->key, input))
                fail(Fault::invalid_call, "native key cancellation changed its original capture");
            // Never invalidate an actual pending/dequeued app lease early.
            if (slot->phase == Impl::Phase::reserved_post) {
                *slot = {};
                --state.occupied;
            } else slot->no_post = true;
            return true;
        }
        p.live();
        auto &queue = p.get(id);
        const auto endpoint = queue.description.lock();
        if (!endpoint || p.descriptors.poll_identity(queue.fd) != endpoint)
            fail(Fault::invalid_call, "native input readiness descriptor was closed or replaced; key input was not admitted");
        const auto &sample = input.sample;
        if (!input.activity || !input.request || !sample.root || !android::valid_key_input(sample) ||
            static_cast<unsigned>(input.stage) > static_cast<unsigned>(android::NativeKeyStage::cancel))
            fail(Fault::invalid_call, "native key sample lacks its original bounded capture and request identity");
        if (queue.activity && (queue.activity != input.activity || queue.root != sample.root ||
                              queue.generation != sample.window_generation)) return false;
        if ((sample.down_time_known && sample.down_time_ms > maximum_ms) ||
            (sample.event_time_known && sample.event_time_ms > maximum_ms))
            fail(Fault::unsupported_service, "native key nanosecond time is outside int64 range");
        auto &state = *queue.state;
        auto slot = std::find_if(state.events.begin(), state.events.end(), [&](const auto &event) {
            return event.key && event.key->request == input.request;
        });
        const bool pre = input.stage == android::NativeKeyStage::pre_ime;
        if (!pre) {
            if (slot == state.events.end()) return false;
            if (!same_key_capture(*slot->key, input))
                fail(Fault::invalid_call, "native key continuation changed its original capture");
            if (slot->phase != Impl::Phase::reserved_post || slot->no_post) return false;
        } else {
            if (input.request <= queue.last_key_request || slot != state.events.end())
                fail(Fault::invalid_call, "native key pre-IME request was duplicated or regressed");
            if (state.occupied >= event_limit - 1)
                fail(Fault::unsupported_service, "native key capacity exhausted; pointer terminal capacity is reserved");
            slot = std::find_if(state.events.begin(), state.events.end(), [](const auto &event) {
                return event.phase == Impl::Phase::free;
            });
        }
        if (p.next_event == UINT64_MAX)
            fail(Fault::unsupported_service, "native input event identity exhausted");
        if (slot == state.events.end() || state.count >= event_limit || state.live >= event_limit) std::terminate();
        Impl::Event event;
        event.id = p.next_event++;
        event.phase = Impl::Phase::pending;
        event.key = input;
        event.action = sample.up ? 1u : 0u;
        event.source = sample.source;
        if (sample.down_time_known) event.down_ns = sample.down_time_ms * 1'000'000;
        if (sample.event_time_known) event.event_ns = sample.event_time_ms * 1'000'000;
        *slot = event;
        const auto index = static_cast<std::size_t>(slot - state.events.begin());
        state.pending[(state.head + state.count) % event_limit] = index;
        state.ingress[(state.ingress_head + state.live) % event_limit] = index;
        ++state.count; ++state.live;
        if (pre) { ++state.occupied; queue.last_key_request = input.request; }
        queue.activity = input.activity; queue.root = sample.root; queue.generation = sample.window_generation;
        return true;
    } catch (const Failure &failure) { throw a64::GuestError("AETHER_NATIVE_INPUT_QUEUE", std::string(failure.reason)); }
}
std::optional<android::NativeActivityInputCompletion> NativeInputQueues::peek_input_completion() const {
    const auto &p = *impl_;
    try {
        p.live();
        if (!p.queue || !p.queue->state->active || !p.queue->state->live) return {};
        const auto &state = *p.queue->state;
        const auto &event = state.events[state.ingress[state.ingress_head]];
        if (event.phase != Impl::Phase::finished) return {};
        android::NativeActivityInputCompletion completion;
        completion.queue = state.id;
        completion.event = event.id;
        completion.input = event.input;
        completion.key = event.key;
        completion.handled = event.handled;
        completion.scope = p.queue->completion_scope;
        return completion;
    } catch (const Failure &failure) { throw a64::GuestError("AETHER_NATIVE_INPUT_QUEUE", std::string(failure.reason)); }
}
bool NativeInputQueues::commit_input_completion(std::uint64_t queue, std::uint64_t event) noexcept {
    auto &p = *impl_;
    if (p.owner != std::this_thread::get_id() || !p.app_id || p.app.instance_id != p.app_id ||
        !p.queue || !p.queue->state->active || !p.queue->completion_scope->active ||
        !queue || p.queue->state->id != queue || !event || !p.queue->state->live) return false;
    auto &state = *p.queue->state;
    auto &head = state.events[state.ingress[state.ingress_head]];
    if (head.id != event || head.phase != Impl::Phase::finished) return false;
    // There is no guest/provider work between ordered handoff and this exact
    // owner commit. Do not introduce a new process/clock/allocation failure.
    if (head.key && head.key->stage == android::NativeKeyStage::pre_ime && !head.handled && !head.no_post) {
        head.phase = Impl::Phase::reserved_post;
    } else {
        head = {};
        --state.occupied;
    }
    state.ingress_head = (state.ingress_head + 1) % event_limit;
    --state.live;
    return true;
}
Fault NativeInputQueues::invoke(std::string_view name, a64::ServiceState &frame, bool full_frame) noexcept {
    auto &p = *impl_;
    if (p.owner != std::this_thread::get_id()) return Fault::invalid_call;
    p.error = {};
    try {
        p.live();
        auto &r = frame.registers;
        if (name.starts_with("AInputQueue_")) {
            auto &queue = p.get(r[0]);
            auto &state = *queue.state;
            if (name == "AInputQueue_attachLooper") {
                for (const auto &attachment : queue.attachments)
                    if (attachment.looper && attachment.looper == r[1]) return Fault::none;
                const auto slot = std::find_if(queue.attachments.begin(), queue.attachments.end(),
                                               [](const auto &attachment) { return !attachment.looper; });
                if (slot == queue.attachments.end()) fail(Fault::unsupported_service, "native input queue Looper attachment capacity exhausted");
                const auto original = queue.description.lock();
                if (!original || p.descriptors.poll_identity(queue.fd) != original)
                    fail(Fault::invalid_call, "native input queue readiness descriptor was closed or replaced");
                auto replacement = p.looper.attach_source(r[1], queue.fd,
                    std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[2])), r[3], r[4]);
                slot->token = std::move(replacement);
                slot->looper = r[1];
            } else if (name == "AInputQueue_detachLooper") {
                for (auto &attachment : queue.attachments) {
                    p.looper.detach_source(attachment.token);
                    attachment.looper = 0;
                }
            }
            else if (name == "AInputQueue_hasEvents") r[0] = state.count ? 1 : 0;
            else if (name == "AInputQueue_getEvent") {
                if (!p.memory.accessible(r[1], 8, a64::Permission::write))
                    fail(Fault::write, "native input event output is not writable; the pending event was retained");
                if (!state.count) {
                    if (!p.memory.write(r[1], pointer_bytes(0))) fail(Fault::write, "native input event null output publication failed");
                    r[0] = negative(-11); return Fault::none;
                }
                auto &event = state.events[state.pending[state.head]];
                if (!p.memory.write(r[1], pointer_bytes(event.id)))
                    fail(Fault::write, "native input event output is not writable; the pending event was retained");
                event.phase = Impl::Phase::in_flight;
                state.head = (state.head + 1) % event_limit; --state.count;
                r[0] = 0;
            } else if (name == "AInputQueue_preDispatchEvent") {
                auto &event = p.event(r[1]);
                if (event.key && event.key->stage == android::NativeKeyStage::pre_ime) {
                    event.handled = false;
                    event.phase = Impl::Phase::finished;
                    r[0] = 1; // Actual lease transfer; later idle-main work decides IME/post-IME.
                } else r[0] = 0;
            }
            else if (name == "AInputQueue_finishEvent") {
                auto &event=p.event(r[1]);
                event.handled = static_cast<std::uint32_t>(r[2]) != 0;
                event.phase = Impl::Phase::finished;
                // No allocation, posting, peer progress, provider or guest call
                // occurs here. Both outcomes remain in ingress order until the
                // trusted idle-main consumer accepts this exact completion.
            }
            else fail(Fault::unsupported_service, "native input queue operation is unsupported");
            return Fault::none;
        }
        const auto &event = p.event(r[0]);
        if (name == "AInputEvent_getType") r[0] = event.key ? 1 : 2;
        else if (name == "AInputEvent_getSource") r[0] = event.source;
        else if (name.starts_with("AKeyEvent_")) {
            if (!event.key) fail(Fault::invalid_call, "native key getter requires an actual key lease");
            const auto &sample = event.key->sample;
            if (name == "AKeyEvent_getAction") r[0] = event.action;
            else if (name == "AKeyEvent_getKeyCode") r[0] = sample.code;
            else if (name == "AKeyEvent_getMetaState") r[0] = sample.meta;
            else if (name == "AKeyEvent_getRepeatCount") r[0] = sample.repeat;
            else if (name == "AKeyEvent_getDownTime" || name == "AKeyEvent_getEventTime") {
                const auto time = name == "AKeyEvent_getDownTime" ? event.down_ns : event.event_ns;
                if (!time) fail(Fault::unsupported_service, "native key timestamp is explicitly unknown");
                r[0] = *time;
            } else fail(Fault::unsupported_service, "native key device, scan code, flags or requested property was not captured");
        }
        else if (event.key) {
            if (name.starts_with("AMotionEvent_"))
                fail(Fault::invalid_call, "native motion getter requires an actual motion lease");
            fail(Fault::unsupported_service, "native input device or requested property was not captured");
        }
        else if (name == "AMotionEvent_getAction") r[0] = event.action;
        else if (name == "AMotionEvent_getPointerCount") r[0] = 1;
        else if (name == "AMotionEvent_getHistorySize") r[0] = 0;
        else if (name == "AMotionEvent_getDownTime" || name == "AMotionEvent_getEventTime") {
            const auto time = name == "AMotionEvent_getDownTime" ? event.down_ns : event.event_ns;
            if (!time) fail(Fault::unsupported_service, "native input timestamp is explicitly unknown");
            r[0] = *time;
        } else if (name == "AMotionEvent_getPointerId") {
            if (r[1]) fail(Fault::invalid_call, "native input pointer index is outside its single captured pointer");
            r[0] = event.pointer;
        } else if (name == "AMotionEvent_getX" || name == "AMotionEvent_getY" || name == "AMotionEvent_getAxisValue") {
            if (!full_frame) fail(Fault::unsupported_service, "native motion float output requires a full service frame");
            const bool axis = name == "AMotionEvent_getAxisValue";
            if (r[axis ? 2 : 1]) fail(Fault::invalid_call, "native input pointer index is outside its single captured pointer");
            bool y = name == "AMotionEvent_getY";
            if (axis) {
                const auto selected = static_cast<std::uint32_t>(r[1]);
                if (selected > 1) fail(Fault::unsupported_service, "native motion axis was not captured by the host");
                y = selected == 1;
            }
            frame.vectors[0] = {std::bit_cast<std::uint32_t>(y ? event.y : event.x), 0};
        } else fail(Fault::unsupported_service, "native input property was not captured or is outside the supported profile");
        return Fault::none;
    } catch (const Failure &failure) { p.error = failure.reason; return failure.fault; }
    catch (...) { p.error = "native input queue host operation failed"; return Fault::unsupported_service; }
}
std::string_view NativeInputQueues::rejection() const noexcept { return impl_->error; }
} // namespace aether::bionic
