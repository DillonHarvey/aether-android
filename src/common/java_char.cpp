#include "aether/common/java_char.hpp"
#include "../../third_party/unicode/ucd16.hpp"
#include <limits>

namespace aether::java_char {
namespace {
// Original Aether algorithms; no Java or ICU implementation source imported.
// Android15 String.java charAt-based comparator:
// SHA256930cbe2993b3ceb6409b349afdc3b68c1e0ac2050fcad9bd1a2796014a06b6c1.
// Character.java simple char mapping forwards to the ICU75.1 profile:
// SHA256ff0c3ab5136c069e2be9f5c155dbfb21dbbb8d91fdb86c4c7b88d79ef4d19254.
// Reuse existing Unicode16 licensed data, ucd16.hpp SHA256
// 91e094a1cf88a51d7ede2291fa71ce1b453713803fd27a2be8fc329e8c37776f;
// notice: third_party/licenses/unicode-16-Unicode-3.0.txt.
// An in-memory whole-BMP source-data comparison against Unicode15.1
// UnicodeData.txt SHA2562fc713e6a31a87c4850a37fe2caffa4218180fadb5de86b43a143ddb4581fb86
// found exactly the five upper and five lower changes guarded below. Those
// Unicode16-only mappings must remain identity in the Android15 target profile.
constexpr std::uint16_t decimal_flag = 1u << 3;
static_assert([] {
    std::size_t count = 0;
    for (const auto &range : bionic::unicode16::properties)
        if (range.first <= 0xffff && (range.flags & decimal_flag)) {
            if (range.last > 0xffff || range.last - range.first != 9) return false;
            ++count;
        }
    return count == 36; // ASCII is handled separately.
}());
template<std::size_t N>
char16_t mapped(const std::array<bionic::unicode16::Mapping, N> &table, char16_t unit) noexcept {
    std::size_t first = 0, last = N;
    while (first < last) {
        const auto middle = first + (last - first) / 2;
        const auto &entry = table[middle];
        if (unit < entry.point) last = middle;
        else if (unit > entry.point) first = middle + 1;
        else return static_cast<char16_t>(entry.result);
    }
    return unit;
}
std::uint32_t decimal(char16_t unit) noexcept {
    if (unit >= u'0' && unit <= u'9') return static_cast<std::uint32_t>(unit - u'0');
    std::size_t first = 0, last = bionic::unicode16::properties.size();
    while (first < last) {
        const auto middle = first + (last - first) / 2;
        const auto &range = bionic::unicode16::properties[middle];
        if (unit < range.first) last = middle;
        else if (unit > range.last) first = middle + 1;
        else return (range.flags & decimal_flag) ? static_cast<std::uint32_t>(unit - range.first) : 10u;
    }
    return 10;
}
} // namespace

char16_t upper(char16_t unit) noexcept {
    if (unit >= u'a' && unit <= u'z') return static_cast<char16_t>(unit - u'a' + u'A');
    switch (unit) {
    case 0x019b: case 0x0264: case 0x1c8a: case 0xa7cd: case 0xa7db: return unit;
    default: return mapped(bionic::unicode16::uppercase, unit);
    }
}
char16_t lower(char16_t unit) noexcept {
    if (unit >= u'A' && unit <= u'Z') return static_cast<char16_t>(unit - u'A' + u'a');
    switch (unit) {
    case 0x1c89: case 0xa7cb: case 0xa7cc: case 0xa7da: case 0xa7dc: return unit;
    default: return mapped(bionic::unicode16::lowercase, unit);
    }
}
std::int32_t compare_ignore_case(std::u16string_view left, std::u16string_view right) noexcept {
    const auto count = left.size() < right.size() ? left.size() : right.size();
    for (std::size_t at = 0; at < count; ++at) {
        if (left[at] == right[at]) continue;
        auto left_unit = upper(left[at]), right_unit = upper(right[at]);
        if (left_unit == right_unit) continue;
        left_unit = lower(left_unit);
        right_unit = lower(right_unit);
        if (left_unit != right_unit)
            return static_cast<std::int32_t>(left_unit) - static_cast<std::int32_t>(right_unit);
    }
    const bool negative = left.size() < right.size();
    const auto difference = negative ? right.size() - left.size() : left.size() - right.size();
    constexpr auto maximum = static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max());
    const auto result = static_cast<std::int32_t>(difference > maximum ? maximum : difference);
    return negative ? -result : result;
}
bool equals_ignore_case(std::u16string_view left, std::u16string_view right) noexcept {
    return compare_ignore_case(left, right) == 0;
}
std::optional<std::int32_t> parse_int32(std::u16string_view text) noexcept {
    if (text.empty()) return {};
    const bool negative = text.front() == u'-';
    const auto first = negative || text.front() == u'+' ? std::size_t{1} : std::size_t{0};
    if (first == text.size()) return {};
    const auto maximum = negative ? std::uint64_t{0x80000000u} : std::uint64_t{0x7fffffffu};
    std::uint64_t magnitude = 0;
    for (auto at = first; at < text.size(); ++at) {
        const auto digit = decimal(text[at]);
        if (digit > 9 || magnitude > (maximum - digit) / 10u) return {};
        magnitude = magnitude * 10u + digit;
    }
    if (negative && magnitude == 0x80000000u) return std::numeric_limits<std::int32_t>::min();
    const auto result = static_cast<std::int32_t>(magnitude);
    return negative ? -result : result;
}
} // namespace aether::java_char
