#pragma once
#include <cstdint>
#include <optional>
#include <string_view>

namespace aether::java_char {
// Android15 Character simple case mapping for individual UTF-16 units, using
// its Unicode15.1 profile. Surrogate units remain unchanged; this is neither
// supplementary code-point folding nor locale/full-string case conversion.
char16_t upper(char16_t unit) noexcept;
char16_t lower(char16_t unit) noexcept;

// Android15 String.compareToIgnoreCase order: compare original units, then
// upper units, then lower(upper) units, then the UTF-16 length difference.
// Callers use the current <=4096-unit value profile. Beyond signed-int length
// differences the return saturates, preserving sign without integer overflow.
std::int32_t compare_ignore_case(std::u16string_view left, std::u16string_view right) noexcept;
bool equals_ignore_case(std::u16string_view left, std::u16string_view right) noexcept;

// Decimal Integer.parseInt value semantics: ASCII optional sign, BMP decimal
// digits and exact signed32 bounds. Empty, sign-only, invalid and overflowing
// text returns nullopt. A null Java String is handled by the guest caller.
std::optional<std::int32_t> parse_int32(std::u16string_view text) noexcept;
} // namespace aether::java_char
