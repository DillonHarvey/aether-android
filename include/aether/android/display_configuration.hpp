#pragma once
#include <cstdint>

namespace aether::android {
// Declared Aether virtual-platform policy for an admitted host viewport:
// SDK35 UI_MODE_TYPE_NORMAL | UI_MODE_NIGHT_NO. This does not describe Windows
// theme settings, unknown device facts or a new Configuration()'s zero defaults.
inline constexpr std::uint32_t admitted_virtual_ui_mode = 0x01u | 0x10u;

// Actual virtual-display facts, distinct from the Activity's requested policy.
struct DisplayConfiguration {
    std::uint32_t screen_width_dp = 560, screen_height_dp = 380;
    std::uint32_t smallest_screen_width_dp = 380, density_dpi = 160;
    constexpr std::uint32_t orientation() const noexcept {
        return screen_width_dp > screen_height_dp ? 2u : 1u;
    }
    constexpr bool valid() const noexcept {
        return screen_width_dp && screen_width_dp <= 32768 && screen_height_dp && screen_height_dp <= 32768 &&
               smallest_screen_width_dp == (screen_width_dp < screen_height_dp ? screen_width_dp : screen_height_dp) &&
               density_dpi >= 80 && density_dpi <= 1600;
    }
    // SDK35 Configuration.reduceScreenLayout's size classification for the
    // actual admitted single virtual display. This is not a guessed full
    // screenLayout bitmask. Zero denotes invalid/unknown configuration facts.
    constexpr std::uint32_t layout_size() const noexcept {
        if (!valid()) return 0;
        const auto longer = screen_width_dp > screen_height_dp ? screen_width_dp : screen_height_dp;
        const auto shorter = screen_width_dp < screen_height_dp ? screen_width_dp : screen_height_dp;
        if (longer < 470) return 1;
        if (longer >= 960 && shorter >= 720) return 4;
        if (longer >= 640 && shorter >= 480) return 3;
        return 2;
    }
    bool operator==(const DisplayConfiguration &) const = default;
};
} // namespace aether::android
