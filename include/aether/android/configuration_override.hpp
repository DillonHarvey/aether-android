#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>

namespace aether::android {
enum class ConfigurationField : std::size_t {
    font_scale, mcc, mnc, touchscreen, keyboard, keyboard_hidden, hard_keyboard_hidden,
    navigation, navigation_hidden, orientation, screen_layout, color_mode, ui_mode,
    width_dp, height_dp, smallest_dp, density_dpi, count
};
inline constexpr auto configuration_field_count = static_cast<std::size_t>(ConfigurationField::count);
struct ConfigurationValueFacts {
    std::array<std::uint32_t, configuration_field_count> numbers{}, known{};
    std::uint64_t remainder_origin = 0, window_origin = 0;
    std::array<std::int32_t, 4> max_bounds{};
};
using ConfigurationOverrideWork = std::function<void(std::uint64_t)>;
enum class ConfigurationKeyMatch { equal, different, unknown };

// base is the private immutable manager baseline, never a guest-mutable value.
// Origins belong to the same authenticated source namespace. Zero identifies
// SDK undefined defaults, not an unknown host configuration. Work exceptions
// propagate; unprovable merges throw a precise InspectError. No heap is retained.
ConfigurationValueFacts merge_configuration_override(const ConfigurationValueFacts &base,
    const ConfigurationValueFacts &raw, const ConfigurationOverrideWork &work);

// Compare immutable RAW override snapshots for a ResourcesImpl key. Effective
// merged equality is insufficient. Account for Configuration's float hash as
// well as equality: signed zero and NaN must not become false cache reuse.
// unknown is not evidence of a cache miss or permission to substitute identity.
ConfigurationKeyMatch compare_configuration_override_keys(const ConfigurationValueFacts &a,
    const ConfigurationValueFacts &b, const ConfigurationOverrideWork &work);
} // namespace aether::android
