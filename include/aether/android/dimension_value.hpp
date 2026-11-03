#pragma once
#include <cstdint>

namespace aether::android {
// Conversion of an actual TYPE_DIMENSION complex value, not an integer layout
// sentinel or TYPE_FLOAT. Constant work, no retained storage; the framework
// caller charges its existing provider ledger and authenticates the value type.
// PX is independent of metrics; DP requires the real nonzero density DPI.
// SP and physical units need metrics not represented by this interface and
// remain explicitly unsupported. No font-scale or physical-DPI guess is made.
float dimension_value(std::uint32_t complex, std::uint32_t density_dpi);
// Java float-to-int truncation/saturation, rather than a C++ overflowing cast.
std::int32_t dimension_pixel_offset(std::uint32_t complex, std::uint32_t density_dpi);
// SDK35 sign-sensitive rounding and minimum one pixel for a nonzero magnitude.
std::int32_t dimension_pixel_size(std::uint32_t complex, std::uint32_t density_dpi);
} // namespace aether::android
