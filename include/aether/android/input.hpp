#pragma once
#include "aether/dex/runtime.hpp"

namespace aether::android {
struct ViewBounds {
    float x = 0, y = 0, width = 0, height = 0;
    bool contains(float px, float py) const noexcept {
        return px >= x && py >= y && px < x + width && py < y + height;
    }
    bool operator==(const ViewBounds &) const = default;
};
struct ViewPlacement {
    dex::ObjectId view;
    ViewBounds bounds;
};
enum class PointerAction : std::uint32_t { down = 0, up = 1, move = 2, cancel = 3 };
struct PointerInput {
    PointerAction action = PointerAction::move;
    std::uint32_t pointer = 0, source = 0x2002; // Android SOURCE_MOUSE; touchscreen is 0x1002.
    float x = 0, y = 0;                         // Activity-local density-independent coordinates.
    // Trusted UI capture identity. Zero is the legacy direct/developer path;
    // installed transport requires the actual published root. A native stream
    // also carries its admitted producer and physical extent, never host handles.
    std::uint64_t root = 0, native_producer = 0;
    std::uint32_t native_width = 0, native_height = 0;
    // Actual input-ingress times in the SystemClock.uptimeMillis time base.
    // Explicit presence preserves a genuine boot-zero timestamp. The captured
    // Windows DPI converts internal DP to public MotionEvent pixels once.
    bool time_known = false;
    std::uint64_t down_time_ms = 0, event_time_ms = 0;
    std::uint32_t capture_dpi = 0; // Zero only for legacy direct input.
};
inline constexpr bool valid_pointer_context(const PointerInput &event) noexcept {
    if (event.capture_dpi && (event.capture_dpi < 48 || event.capture_dpi > 960)) return false;
    if (event.time_known) {
        if (event.down_time_ms > event.event_time_ms || event.event_time_ms > std::uint64_t{INT64_MAX} ||
            (event.action == PointerAction::down && event.down_time_ms != event.event_time_ms)) return false;
    } else if (event.down_time_ms || event.event_time_ms) return false;
    if (!event.root)
        return !event.native_producer && !event.native_width && !event.native_height;
    if (!event.time_known || !event.capture_dpi) return false;
    if (event.pointer > 31) return false; // Android pointer identity namespace, distinct from Win32 IDs.
    if (!event.native_producer)
        return !event.native_width && !event.native_height;
    return event.native_width && event.native_width <= 1024 && event.native_height && event.native_height <= 1024;
}
// Deferred means real owned native work, never an application-handled result.
enum class KeyDispatchOutcome : std::uint64_t { none, handled, unhandled, cancelled, deferred };
enum class KeyCharacterStatus : std::uint32_t { none = 0, bmp = 1, unsupported = 2 };
inline constexpr std::uint32_t key_lock_meta_mask = 0x700000u;
inline constexpr std::uint32_t key_meta_mask = 0x711003u;
struct KeyInput {
    bool up = false;
    std::uint32_t code = 0, meta = 0, repeat = 0; // Android keycode and AMETA bits.
    KeyCharacterStatus character_status = KeyCharacterStatus::none;
    std::uint32_t unicode = 0; // One admitted UTF-16 unit; never a truncated sequence.
    // Trusted capture identity is separate from public immutable KeyEvent values.
    std::uint64_t root = 0, window_generation = 0, input_generation = 0, capture_generation = 0;
    bool event_time_known = false, down_time_known = false;
    std::uint64_t down_time_ms = 0, event_time_ms = 0;
    bool source_known = false;
    std::uint32_t source = 0;
};
inline constexpr bool valid_key_input(const KeyInput &event) noexcept {
    if (event.code > 512 || event.repeat > 65535 || (event.meta & ~key_meta_mask)) return false;
    if (event.root ? (!event.window_generation || !event.input_generation || !event.capture_generation ||
            !event.event_time_known || !event.source_known) :
            (event.window_generation || event.input_generation || event.capture_generation)) return false;
    if (event.event_time_known ? event.event_time_ms > std::uint64_t{INT64_MAX} : event.event_time_ms != 0) return false;
    if (event.down_time_known) {
        if (!event.event_time_known || event.down_time_ms > event.event_time_ms ||
            (!event.up && !event.repeat && event.down_time_ms != event.event_time_ms)) return false;
    } else if (event.down_time_ms) return false;
    if (event.source_known ? event.source != 0x101u : event.source != 0) return false;
    switch (event.character_status) {
    case KeyCharacterStatus::none:
    case KeyCharacterStatus::unsupported:
        return event.unicode == 0;
    case KeyCharacterStatus::bmp:
        if (event.meta & ~(key_lock_meta_mask | 1u)) return false;
        if (event.unicode == 9) return event.code == 61;
        if (event.unicode == 10) return event.code == 66 || event.code == 160;
        return event.code != 67 && event.code != 112 && event.unicode >= 0x20 && event.unicode <= 0xffff &&
               !(event.unicode >= 0x7f && event.unicode <= 0x9f) &&
               !(event.unicode >= 0xd800 && event.unicode <= 0xdfff);
    }
    return false;
}
} // namespace aether::android
