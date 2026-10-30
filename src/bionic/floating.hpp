#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace aether::bionic {
struct FloatingResult {
    std::array<std::uint64_t,2> bits{};
    std::size_t consumed{};
    bool range_error{};
};
// Original integer-only, nearest-even IEEE binary32/64/128 conversion.
// Throws for unsupported widths, >1 MiB input, or >16384 significant digits
// needing exact conversion after redundant zero removal and coarse range checks.
FloatingResult native_floating_parse(std::string_view,unsigned width);
}
