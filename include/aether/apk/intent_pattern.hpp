#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aether::apk {
enum class IntentPatternType : std::int32_t {
    literal = 0, prefix = 1, simple_glob = 2, advanced_glob = 3, suffix = 4
};

// Original UTF-16 Android pattern value, without regex substitution or I/O.
// Advanced patterns retain the pinned 2048-word parser bound and consume
// greedily without backtracking. Candidate admission matches the current
// 4096-unit Intent/Uri profile; no pattern or candidate is truncated.
class IntentPattern final {
  public:
    IntentPattern(std::u16string_view pattern, IntentPatternType type);
    bool matches(std::optional<std::u16string_view> candidate) const;
    // The resolver must charge this storage together with the retained manifest
    // against its unchanged 4 MiB metadata budget, before publishing a plan.
    std::size_t accounted_bytes() const noexcept;

  private:
    enum class TokenKind : std::uint32_t { literal, any, set, inverse_set };
    struct Range { char16_t first, last; };
    struct Token {
        TokenKind kind = TokenKind::literal;
        char16_t literal = 0;
        std::uint16_t reserved = 0;
        std::size_t first_range = 0, range_count = 0;
        std::int32_t minimum = 1, maximum = 1;
    };
    static_assert(sizeof(Token) <= 32);
    static_assert(sizeof(Range) == 4);
    std::u16string pattern_;
    IntentPatternType type_;
    std::vector<Token> tokens_;
    std::vector<Range> ranges_;
    void compile_advanced();
    bool match_advanced(std::u16string_view candidate) const noexcept;
};
static_assert(sizeof(IntentPattern) <= 128);
} // namespace aether::apk
