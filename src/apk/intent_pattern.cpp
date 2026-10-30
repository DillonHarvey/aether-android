#include "aether/apk/intent_pattern.hpp"
#include "aether/apk/inspect.hpp"
#include "../../third_party/unicode/ucd16.hpp"
#include <limits>

namespace aether::apk {
namespace {
// Original implementation of observable Android15 PatternMatcher semantics.
// Reference only: frameworks/base4e43ad12e1b211f15152e9c5b16b0fe88e6b93f3,
// PatternMatcher.java SHA2568f122811a42d9c7078f45fed1898341ce0473d64a4ba1aded58bdae970c31d54.
// Existing Unicode-3.0 licensed data is reused for Java decimal range counts;
// provenance/notices remain third_party/dependencies.json and ADR0295/ADR0347.
constexpr std::size_t pattern_record_bytes = 128;
constexpr std::size_t token_record_bytes = 32;
constexpr std::size_t advanced_words = 2048;
constexpr std::size_t candidate_units = 4096;
constexpr std::uint16_t decimal_flag = 1u << 3;
static_assert([] {
    std::size_t count = 0;
    for (const auto &range : bionic::unicode16::properties)
        if (range.first <= 0xffff && (range.flags & decimal_flag)) {
            if (range.last > 0xffff || range.last - range.first != 9) return false;
            ++count;
        }
    return count == 36;
}());
[[noreturn]] void invalid(std::string_view message) {
    throw InspectError("AETHER_INTENT_PATTERN_INVALID", "intent-pattern", std::string(message));
}
[[noreturn]] void limit(std::string_view message) {
    throw InspectError("AETHER_INTENT_PATTERN_LIMIT", "intent-pattern", std::string(message));
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
std::int32_t repetition(std::u16string_view text) {
    if (text.empty()) invalid("Advanced repetition count is empty");
    const bool negative = text.front() == u'-';
    const auto first = negative || text.front() == u'+' ? std::size_t{1} : std::size_t{0};
    if (first == text.size()) invalid("Advanced repetition sign has no digits");
    const auto maximum = negative ? std::uint64_t{0x80000000u} : std::uint64_t{0x7fffffffu};
    std::uint64_t magnitude = 0;
    for (auto at = first; at < text.size(); ++at) {
        const auto digit = decimal(text[at]);
        if (digit > 9 || magnitude > (maximum - digit) / 10u)
            invalid("Advanced repetition is not a signed Java int");
        magnitude = magnitude * 10u + digit;
    }
    if (negative && magnitude == 0x80000000u) return std::numeric_limits<std::int32_t>::min();
    const auto value = static_cast<std::int32_t>(magnitude);
    return negative ? -value : value;
}
bool simple(std::u16string_view pattern, std::u16string_view candidate) noexcept {
    std::size_t pattern_at = 0, input_at = 0;
    const auto peek = [&] { return pattern_at < pattern.size() ? pattern[pattern_at] : char16_t{}; };
    while (pattern_at < pattern.size() && input_at < candidate.size()) {
        auto unit = pattern[pattern_at++];
        const bool escaped = unit == u'\\';
        if (escaped) { unit = peek(); ++pattern_at; }
        if (peek() != u'*') {
            // Pinned simple glob treats even an escaped dot as a one-unit
            // wildcard here. Escaping only changes the dot-star branch below.
            if (unit != u'.' && candidate[input_at] != unit) return false;
            ++input_at;
        } else if (unit == u'.' && !escaped) {
            if (pattern_at >= pattern.size() - 1) return true;
            ++pattern_at;
            auto following = peek();
            if (following == u'\\') { ++pattern_at; following = peek(); }
            while (input_at < candidate.size() && candidate[input_at] != following) ++input_at;
            if (input_at == candidate.size()) return false;
            ++input_at;
            ++pattern_at;
        } else {
            while (input_at < candidate.size() && candidate[input_at] == unit) ++input_at;
            ++pattern_at;
        }
    }
    if (pattern_at >= pattern.size() && input_at >= candidate.size()) return true;
    // Unlike a general regexp, an unvisited a* does not match empty input.
    return pattern.size() >= 2 && pattern_at == pattern.size() - 2 &&
           pattern[pattern_at] == u'.' && pattern[pattern_at + 1] == u'*';
}
} // namespace

IntentPattern::IntentPattern(std::u16string_view pattern, IntentPatternType type) : type_(type) {
    if (type < IntentPatternType::literal || type > IntentPatternType::suffix)
        throw InspectError("AETHER_INTENT_PATTERN_UNSUPPORTED", "intent-pattern", "Unknown Android pattern type");
    if (pattern.size() > (manifest_activity_bytes - pattern_record_bytes) / sizeof(char16_t) - 1)
        limit("Pattern text exceeds the existing metadata storage budget");
    pattern_.assign(pattern);
    if (type_ == IntentPatternType::advanced_glob) compile_advanced();
    if (accounted_bytes() > manifest_activity_bytes)
        limit("Compiled pattern exceeds the existing metadata storage budget");
}
std::size_t IntentPattern::accounted_bytes() const noexcept {
    return pattern_record_bytes + (pattern_.capacity() + 1) * sizeof(char16_t) +
           tokens_.capacity() * token_record_bytes + ranges_.capacity() * sizeof(Range);
}
void IntentPattern::compile_advanced() {
    std::size_t at = 0, words = 0;
    bool modified = false;
    const auto room = [&] {
        // Android checks for three available words before each parser step,
        // including the closing step after numeric repetition parsing.
        if (words > advanced_words - 3) limit("Advanced pattern exceeds Android's 2048-word parser bound");
    };
    while (at < pattern_.size()) {
        room();
        auto unit = pattern_[at];
        if (unit == u'}') { ++at; continue; } // An outside unmatched close is ignored.
        if (unit == u'*' || unit == u'+' || unit == u'{') {
            if (tokens_.empty() || modified) invalid("Advanced modifier must follow an unmodified token");
            auto &token = tokens_.back();
            modified = true;
            if (unit != u'{') {
                token.minimum = unit == u'*' ? 0 : 1;
                token.maximum = std::numeric_limits<std::int32_t>::max();
                ++words;
                ++at;
                continue;
            }
            const auto close = pattern_.find(u'}', at + 1);
            if (close == pattern_.npos) invalid("Advanced repetition has no closing brace");
            const auto text = std::u16string_view(pattern_).substr(at + 1, close - at - 1);
            const auto comma = text.find(u',');
            token.minimum = repetition(text.substr(0, comma));
            token.maximum = comma == text.npos ? token.minimum : comma + 1 == text.size() ?
                std::numeric_limits<std::int32_t>::max() : repetition(text.substr(comma + 1));
            if (token.minimum > token.maximum) invalid("Advanced repetition minimum exceeds maximum");
            words += 3;
            room();
            ++words;
            at = close + 1;
            continue;
        }
        Token token;
        modified = false;
        if (unit == u'[') {
            if (at + 1 == pattern_.size()) invalid("Advanced character set is unterminated");
            ++words;
            ++at;
            token.kind = pattern_[at] == u'^' ? TokenKind::inverse_set : TokenKind::set;
            if (token.kind == TokenKind::inverse_set) ++at;
            token.first_range = ranges_.size();
            std::optional<char16_t> lower;
            bool closed = false;
            while (at < pattern_.size()) {
                room();
                unit = pattern_[at];
                if (unit == u']') {
                    if (ranges_.size() == token.first_range && !lower)
                        invalid("Advanced character set is empty");
                    ++words;
                    ++at;
                    closed = true;
                    break;
                }
                if (unit == u'\\') {
                    if (at + 1 == pattern_.size()) invalid("Advanced escape has no following unit");
                    unit = pattern_[++at];
                }
                if (lower) {
                    ranges_.push_back({*lower, unit});
                    lower.reset();
                    ++words;
                } else if (at + 2 < pattern_.size() && pattern_[at + 1] == u'-' && pattern_[at + 2] != u']') {
                    lower = unit;
                    ++words;
                    ++at;
                } else {
                    ranges_.push_back({unit, unit});
                    words += 2;
                }
                ++at;
            }
            if (!closed) invalid("Advanced character set is unterminated");
            token.range_count = ranges_.size() - token.first_range;
        } else {
            if (unit == u'\\') {
                if (at + 1 == pattern_.size()) invalid("Advanced escape has no following unit");
                token.literal = pattern_[++at];
            } else if (unit == u'.') token.kind = TokenKind::any;
            else token.literal = unit;
            ++words;
            ++at;
        }
        tokens_.push_back(token);
    }
}
bool IntentPattern::match_advanced(std::u16string_view candidate) const noexcept {
    std::size_t at = 0;
    for (const auto &token : tokens_) {
        std::int32_t consumed = 0;
        while (consumed < token.maximum && at < candidate.size()) {
            bool accepted = token.kind == TokenKind::any;
            if (token.kind == TokenKind::literal) accepted = candidate[at] == token.literal;
            else if (token.kind == TokenKind::set || token.kind == TokenKind::inverse_set) {
                bool contained = false;
                for (std::size_t n = 0; n < token.range_count; ++n) {
                    const auto &range = ranges_[token.first_range + n];
                    if (candidate[at] >= range.first && candidate[at] <= range.last) { contained = true; break; }
                }
                accepted = token.kind == TokenKind::set ? contained : !contained;
            }
            if (!accepted) break;
            ++consumed;
            ++at;
        }
        if (consumed < token.minimum) return false;
    }
    return at == candidate.size();
}
bool IntentPattern::matches(std::optional<std::u16string_view> candidate) const {
    if (!candidate) return false;
    if (candidate->size() > candidate_units) limit("Pattern candidate exceeds the current 4096-unit Intent/Uri profile");
    switch (type_) {
    case IntentPatternType::literal: return *candidate == pattern_;
    case IntentPatternType::prefix: return candidate->starts_with(pattern_);
    case IntentPatternType::simple_glob: return simple(pattern_, *candidate);
    case IntentPatternType::advanced_glob: return match_advanced(*candidate);
    case IntentPatternType::suffix: return candidate->ends_with(pattern_);
    }
    return false;
}
} // namespace aether::apk
