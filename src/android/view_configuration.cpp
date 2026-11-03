#include "aether/android/view_configuration.hpp"
#include "aether/apk/inspect.hpp"
#include <bit>
#include <cmath>
#include <limits>

namespace aether::android {
namespace {
std::int32_t java_integer(float value) noexcept {
    if (std::isnan(value)) return 0;
    if (value >= static_cast<float>(std::numeric_limits<std::int32_t>::max()))
        return std::numeric_limits<std::int32_t>::max();
    if (value <= static_cast<float>(std::numeric_limits<std::int32_t>::min()))
        return std::numeric_limits<std::int32_t>::min();
    return static_cast<std::int32_t>(value);
}
} // namespace
ViewConfigurationParameters load_view_configuration(float density, bool xlarge,
    ViewConfigurationMenuKey &menu_key, ViewConfigurationSource source) {
    if (!source.dimension || !source.int_value || !source.boolean || !source.float_value ||
        !source.maximum_bounds || !source.charge)
        throw apk::InspectError("AETHER_VIEW_CONFIGURATION_SOURCE", "view-configuration",
                                "Cold configuration requires actual resource, bounds and work sources");
    const auto charge = [&](std::uint64_t amount = 1) { source.charge(source.context, amount); };
    const auto dimension = [&](std::string_view name) {
        charge(); return source.dimension(source.context, name);
    };
    const auto integer = [&](std::string_view name) {
        charge(); return source.int_value(source.context, name);
    };
    const auto boolean = [&](std::string_view name) {
        charge(); return source.boolean(source.context, name);
    };
    charge();
    const float scaled_density = xlarge ? density * 1.5f : density;
    const auto rounded = [&](float sdk_value) {
        charge();
        const float product = scaled_density * sdk_value;
        return java_integer(product + 0.5f);
    };
    ViewConfigurationParameters result;
    result.edge_slop = rounded(12.0f);
    result.fading_edge_length = rounded(12.0f);
    result.scrollbar_size = dimension("config_scrollbarSize");
    result.double_tap_slop = rounded(100.0f);
    result.window_touch_slop = rounded(16.0f);
    charge();
    const float multiplier = source.float_value(source.context, "config_ambiguousGestureMultiplier");
    charge();
    // Java Math.max propagates NaN; std::fmax would instead choose 1.
    result.ambiguous_gesture_multiplier = std::isnan(multiplier) || multiplier >= 1.0f ? multiplier : 1.0f;
    charge();
    const auto bounds = source.maximum_bounds(source.context);
    charge(2);
    const auto cache_bytes = std::uint32_t{4} * static_cast<std::uint32_t>(bounds.width) *
        static_cast<std::uint32_t>(bounds.height);
    result.maximum_drawing_cache_bytes = std::bit_cast<std::int32_t>(cache_bytes);
    result.overscroll_distance = rounded(0.0f);
    result.overfling_distance = rounded(6.0f);
    if (!menu_key.known) {
        const auto override_value = integer("config_overrideHasPermanentMenuKey");
        if (override_value == 1 || override_value == 2) {
            menu_key.value = override_value == 1;
            menu_key.known = true;
        } else {
            if (!source.has_navigation_bar)
                throw apk::InspectError("AETHER_VIEW_CONFIGURATION_NAVIGATION", "view-configuration",
                                        "Menu-key autodetection requires an actual navigation-bar source");
            charge();
            const auto navigation = source.has_navigation_bar(source.context);
            if (navigation) {
                menu_key.value = !*navigation;
                menu_key.known = true;
            } else {
                menu_key.value = false; // SDK catches only the observed RemoteException.
            }
        }
    }
    result.fading_marquee_enabled = boolean("config_ui_enableFadingMarquee");
    result.touch_slop = dimension("config_viewConfigurationTouchSlop");
    result.handwriting_slop = dimension("config_viewConfigurationHandwritingSlop");
    result.hover_slop = dimension("config_viewConfigurationHoverSlop");
    result.minimum_scrollbar_touch_target = dimension("config_minScrollbarTouchTarget");
    charge();
    result.paging_touch_slop = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(result.touch_slop) * 2u);
    result.double_tap_touch_slop = result.touch_slop;
    result.handwriting_gesture_line_margin = dimension("config_viewConfigurationHandwritingGestureLineMargin");
    result.minimum_fling_velocity = dimension("config_viewMinFlingVelocity");
    result.maximum_fling_velocity = dimension("config_viewMaxFlingVelocity");
    const auto minimum_rotary = dimension("config_viewMinRotaryEncoderFlingVelocity");
    const auto maximum_rotary = dimension("config_viewMaxRotaryEncoderFlingVelocity");
    charge();
    result.minimum_rotary_fling_velocity = minimum_rotary < 0 || maximum_rotary < 0
        ? std::numeric_limits<std::int32_t>::max() : minimum_rotary;
    result.maximum_rotary_fling_velocity = minimum_rotary < 0 || maximum_rotary < 0
        ? std::numeric_limits<std::int32_t>::min() : maximum_rotary;
    const auto tick_interval = dimension("config_rotaryEncoderAxisScrollTickInterval");
    charge();
    result.rotary_haptic_tick_interval_pixels = tick_interval > 0
        ? tick_interval : std::numeric_limits<std::int32_t>::max();
    result.rotary_haptic_feedback_enabled = boolean("config_viewRotaryEncoderHapticScrollFedbackEnabled");
    result.global_actions_key_timeout = integer("config_globalActionsKeyTimeout");
    const auto horizontal_factor = dimension("config_horizontalScrollFactor");
    charge();
    result.horizontal_scroll_factor = static_cast<float>(horizontal_factor);
    const auto vertical_factor = dimension("config_verticalScrollFactor");
    charge();
    result.vertical_scroll_factor = static_cast<float>(vertical_factor);
    result.show_menu_shortcuts_when_keyboard_present = boolean("config_showMenuShortcutsWhenKeyboardPresent");
    result.minimum_scaling_span = dimension("config_minScalingSpan");
    result.screenshot_chord_key_timeout = integer("config_screenshotChordKeyTimeout");
    result.smart_selection_initialized_timeout = integer("config_smartSelectionInitializedTimeoutMillis");
    result.smart_selection_initializing_timeout = integer("config_smartSelectionInitializingTimeoutMillis");
    result.prefer_keep_clear_for_focus = boolean("config_preferKeepClearForFocus");
    result.view_based_rotary_scroll_haptics = boolean("config_viewBasedRotaryEncoderHapticsEnabled");
    return result;
}
} // namespace aether::android
