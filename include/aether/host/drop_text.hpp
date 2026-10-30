#pragma once
#include "aether/apk/package.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace aether::host {
enum class DropPayloadKind : std::uint32_t { file = 0, plain_text = 1 };
inline constexpr std::size_t drop_text_limit = 4096;
inline constexpr std::size_t drop_text_chunk_limit = 1024;
struct DropTextInfo {
    std::uint64_t units = 0;
    std::string utf16le_sha256;
    bool operator==(const DropTextInfo &) const = default;
};
inline bool valid_drop_text_info(const DropTextInfo &info) noexcept {
    return info.units <= drop_text_limit && info.utf16le_sha256.size() == 64 &&
        std::all_of(info.utf16le_sha256.begin(), info.utf16le_sha256.end(), [](char unit) {
            return (unit >= '0' && unit <= '9') || (unit >= 'a' && unit <= 'f');
        });
}
inline bool valid_drop_text(std::u16string_view text) noexcept {
    if (text.size() > drop_text_limit) return false;
    for (std::size_t index = 0; index < text.size(); ++index) {
        const auto unit = text[index];
        if (!unit || (unit >= 0xdc00 && unit <= 0xdfff)) return false;
        if (unit >= 0xd800 && unit <= 0xdbff) {
            if (++index == text.size() || text[index] < 0xdc00 || text[index] > 0xdfff) return false;
        }
    }
    return true;
}
// Exact selected UTF-16 code units in explicit little-endian order. No BOM,
// terminator, whitespace changes or Unicode normalization enters this digest.
inline DropTextInfo describe_drop_text(std::u16string_view text) {
    if (!valid_drop_text(text)) throw std::invalid_argument("AETHER_DROP_TEXT_INVALID");
    std::array<std::uint8_t, drop_text_limit * 2> bytes{};
    std::size_t offset = 0;
    for (const auto unit : text) {
        bytes[offset++] = static_cast<std::uint8_t>(unit);
        bytes[offset++] = static_cast<std::uint8_t>(unit >> 8);
    }
    return {static_cast<std::uint64_t>(text.size()), apk::sha256(apk::Bytes(bytes.data(), offset))};
}
inline bool matches_drop_text(const DropTextInfo &info, std::u16string_view text) {
    return valid_drop_text_info(info) && info.units == text.size() && valid_drop_text(text) &&
        describe_drop_text(text) == info;
}
} // namespace aether::host
