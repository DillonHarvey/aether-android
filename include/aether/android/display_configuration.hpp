#pragma once
#include <cstdint>

namespace aether::android {
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
    bool operator==(const DisplayConfiguration &) const = default;
};
} // namespace aether::android
