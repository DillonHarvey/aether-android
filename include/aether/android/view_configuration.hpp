#pragma once
#include <cstdint>
#include <optional>
#include <string_view>

namespace aether::android {
struct ViewConfigurationMenuKey {
    bool value = false, known = false;
};
struct ViewConfigurationBounds { std::int32_t width = 0, height = 0; };
struct ViewConfigurationParameters {
    std::int32_t edge_slop = 0, fading_edge_length = 0, scrollbar_size = 0;
    std::int32_t double_tap_slop = 0, window_touch_slop = 0;
    float ambiguous_gesture_multiplier = 0;
    std::int32_t maximum_drawing_cache_bytes = 0, overscroll_distance = 0, overfling_distance = 0;
    bool fading_marquee_enabled = false;
    std::int32_t touch_slop = 0, handwriting_slop = 0, hover_slop = 0, minimum_scrollbar_touch_target = 0;
    std::int32_t paging_touch_slop = 0, double_tap_touch_slop = 0, handwriting_gesture_line_margin = 0;
    std::int32_t minimum_fling_velocity = 0, maximum_fling_velocity = 0;
    std::int32_t minimum_rotary_fling_velocity = 0, maximum_rotary_fling_velocity = 0;
    std::int32_t rotary_haptic_tick_interval_pixels = 0;
    bool rotary_haptic_feedback_enabled = false;
    std::int64_t global_actions_key_timeout = 0;
    float horizontal_scroll_factor = 0, vertical_scroll_factor = 0;
    bool show_menu_shortcuts_when_keyboard_present = false;
    std::int32_t minimum_scaling_span = 0;
    std::int64_t screenshot_chord_key_timeout = 0;
    std::int32_t smart_selection_initialized_timeout = 0, smart_selection_initializing_timeout = 0;
    bool prefer_keep_clear_for_focus = false, view_based_rotary_scroll_haptics = false;
};
// Descriptors are copied before callbacks. The caller retains actual resource
// owners and preserves the preceding original Context/metrics/configuration calls.
// Resource names below are SDK identities, not app resource IDs or fallback data.
struct ViewConfigurationSource {
    void *context = nullptr;
    std::int32_t (*dimension)(void *, std::string_view) = nullptr;
    std::int32_t (*int_value)(void *, std::string_view) = nullptr;
    bool (*boolean)(void *, std::string_view) = nullptr;
    // Actual getValue -> TypedValue.getFloat semantics, not guessed coercion.
    float (*float_value)(void *, std::string_view) = nullptr;
    ViewConfigurationBounds (*maximum_bounds)(void *) = nullptr;
    // nullopt means an actual caught RemoteException only. An unavailable
    // backend must throw a precise unsupported error instead of inventing one.
    std::optional<bool> (*has_navigation_bar)(void *) = nullptr;
    void (*charge)(void *, std::uint64_t) = nullptr;
};
// A cold constructor only. density/xlarge are authentic previously read values;
// original managed object/cache/hot-path semantics belong to the caller.
// Menu state commits partway through, exactly when its source query completes.
// No parameter result is returned after failure; callback errors propagate.
ViewConfigurationParameters load_view_configuration(float density, bool xlarge,
    ViewConfigurationMenuKey &menu_key, ViewConfigurationSource source);
} // namespace aether::android
