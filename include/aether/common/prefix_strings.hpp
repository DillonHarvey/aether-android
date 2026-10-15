#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace aether {
inline constexpr std::size_t prefix_string_count = 1024;
inline constexpr std::size_t prefix_string_bytes = 512;
inline constexpr std::size_t prefix_decoded_bytes = 64 * 1024;
struct DecodedPrefixStrings {
    std::vector<std::string> values;
    std::size_t consumed = 0;
};
// Original bounded byte-string encoding. Each row stores a little-endian
// uint16 prior-row index, shared-prefix length and literal-suffix length.
// 0xffff means no prior row. Order and duplicate values are preserved.
// Invalid counts, extents/references or decoded quotas throw invalid_argument.
std::vector<std::uint8_t> encode_prefix_strings(std::span<const std::string> values);
DecodedPrefixStrings decode_prefix_strings(std::span<const std::uint8_t> bytes, std::size_t count);
} // namespace aether
