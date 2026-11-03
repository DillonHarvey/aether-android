#include "aether/android/dimension_value.hpp"
#include "aether/apk/inspect.hpp"
#include <array>
#include <bit>
#include <cmath>
#include <limits>

namespace aether::android {
namespace {
float complex_value(std::uint32_t encoded) noexcept {
    constexpr std::array radix{1.0f / 256.0f, 1.0f / 32768.0f,
                               1.0f / 8388608.0f, 1.0f / 2147483648.0f};
    const auto mantissa = std::bit_cast<std::int32_t>(encoded & 0xffffff00u);
    return static_cast<float>(mantissa) * radix[(encoded >> 4) & 3u];
}
float pixels(std::uint32_t encoded, float value, std::uint32_t density_dpi) {
    const auto unit = encoded & 15u;
    if (unit == 0) return value;
    if (unit == 1) {
        if (!density_dpi)
            throw apk::InspectError("AETHER_DIMENSION_METRICS", "dimension-value",
                                    "DP conversion requires the actual nonzero display density");
        const float density = static_cast<float>(density_dpi) * (1.0f / 160.0f);
        return value * density;
    }
    throw apk::InspectError("AETHER_DIMENSION_UNSUPPORTED", "dimension-value",
                            "Dimension unit requires unavailable scaling or physical display metrics");
}
std::int32_t java_integer(float value) noexcept {
    if (std::isnan(value)) return 0;
    if (value >= static_cast<float>(std::numeric_limits<std::int32_t>::max()))
        return std::numeric_limits<std::int32_t>::max();
    if (value <= static_cast<float>(std::numeric_limits<std::int32_t>::min()))
        return std::numeric_limits<std::int32_t>::min();
    return static_cast<std::int32_t>(value);
}
} // namespace
float dimension_value(std::uint32_t complex, std::uint32_t density_dpi) {
    return pixels(complex, complex_value(complex), density_dpi);
}
std::int32_t dimension_pixel_offset(std::uint32_t complex, std::uint32_t density_dpi) {
    return java_integer(dimension_value(complex, density_dpi));
}
std::int32_t dimension_pixel_size(std::uint32_t complex, std::uint32_t density_dpi) {
    const float value = complex_value(complex);
    const float scaled = pixels(complex, value, density_dpi);
    const auto rounded = java_integer(scaled >= 0.0f ? scaled + 0.5f : scaled - 0.5f);
    if (rounded) return rounded;
    if (value == 0.0f) return 0;
    return value > 0.0f ? 1 : -1;
}
} // namespace aether::android
