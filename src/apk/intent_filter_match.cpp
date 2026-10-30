#include "aether/apk/intent_filter.hpp"
#include "aether/common/java_char.hpp"
#include "aether/common/uri.hpp"
#include <algorithm>
#include <array>

namespace aether::apk {
namespace {
// Original Aether matcher, reviewed against Android15 IntentFilter,
// UriRelativeFilterGroup and UriRelativeFilter at frameworks/base revision
// 4e43ad12e1b211f15152e9c5b16b0fe88e6b93f3. No framework code is imported.
constexpr std::int32_t normal = 0x8000;
constexpr std::int32_t empty_match = 0x0100000, scheme_match = 0x0200000;
constexpr std::int32_t host_match = 0x0300000, port_match = 0x0400000;
constexpr std::int32_t path_match = 0x0500000, ssp_match = 0x0580000, type_match = 0x0600000;
constexpr std::int32_t no_type = -1, no_data = -2, no_action = -3, no_category = -4;
constexpr std::size_t category_count = 65536;

void bounded(std::optional<std::u16string_view> text) {
    if (text && text->size() > uri::text_units)
        throw InspectError("AETHER_INTENT_MATCH_LIMIT", "intent-match", "Intent match text exceeds 4096 UTF-16 units");
}
bool contains(const std::vector<std::u16string> &values, std::u16string_view value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}
bool patterns(const std::vector<IntentPattern> &values, std::optional<std::u16string_view> value) {
    for (const auto &pattern : values) if (pattern.matches(value)) return true;
    return false;
}
class Data final {
    struct Text {
        bool ready = false;
        std::optional<std::u16string> value;
    };
    std::optional<uri::Parsed> parsed_;
    std::array<Text, 7> parts_{};
    Text host_;
    std::int32_t port_ = -2;
  public:
    explicit Data(std::optional<std::u16string_view> data) {
        if (data) parsed_.emplace(*data);
    }
    bool present() const noexcept { return parsed_.has_value(); }
    std::optional<std::u16string_view> scheme() const {
        if (parsed_) if (const auto part = parsed_->part(uri::Part::scheme))
            return parsed_->text.substr(part->first, part->last - part->first);
        return {};
    }
    std::optional<std::u16string_view> part(uri::Part wanted) {
        auto &cached = parts_[static_cast<std::size_t>(wanted)];
        if (!cached.ready) {
            if (parsed_) if (const auto part = parsed_->part(wanted)) {
                const auto encoded = parsed_->text.substr(part->first, part->last - part->first);
                cached.value = wanted == uri::Part::scheme ? std::u16string(encoded) : uri::decode(encoded);
            }
            cached.ready = true;
        }
        return cached.value ? std::optional<std::u16string_view>{*cached.value} : std::nullopt;
    }
    std::optional<std::u16string_view> host() {
        if (!host_.ready) {
            if (parsed_) if (const auto authority = parsed_->authority())
                host_.value = uri::host(parsed_->text.substr(authority->first, authority->last - authority->first));
            host_.ready = true;
        }
        return host_.value ? std::optional<std::u16string_view>{*host_.value} : std::nullopt;
    }
    std::int32_t port() {
        if (port_ == -2) {
            port_ = -1;
            if (parsed_) if (const auto authority = parsed_->authority())
                port_ = uri::port(parsed_->text.substr(authority->first, authority->last - authority->first));
        }
        return port_;
    }
};
bool mime(const CompiledIntentFilter &filter, std::optional<std::u16string_view> type) {
    if (!type) return false;
    if (contains(filter.types, *type)) return true;
    if (*type == u"*/*") return !filter.types.empty();
    if (filter.partial_types && contains(filter.types, u"*")) return true;
    const auto slash = type->find(u'/');
    if (slash != type->npos && slash > 0) {
        if (filter.partial_types && contains(filter.types, type->substr(0, slash))) return true;
        if (type->size() == slash + 2 && (*type)[slash + 1] == u'*') {
            const auto prefix = type->substr(0, slash + 1);
            for (const auto &declared : filter.types) if (declared.starts_with(prefix)) return true;
        }
    }
    return false;
}
std::int32_t authority(const CompiledIntentFilter &filter, Data &data) {
    const auto host = data.host();
    if (!host) return no_data;
    // Preserve declaration order: the first match wins, not the highest score.
    for (const auto &declared : filter.authorities) {
        auto candidate = *host;
        if (declared.wildcard) {
            if (candidate.size() < declared.host.size()) continue;
            candidate = candidate.substr(candidate.size() - declared.host.size());
        }
        if (!java_char::equals_ignore_case(candidate, declared.host)) continue;
        if (declared.port >= 0) {
            if (declared.port != data.port()) continue;
            return port_match;
        }
        return host_match;
    }
    return no_data;
}
std::vector<std::u16string_view> split(std::u16string_view query, char16_t delimiter) {
    const auto first_separator = query.find(delimiter);
    if (first_separator == query.npos) return {query}; // Includes Java split("")'s one empty element.
    std::vector<std::u16string_view> result;
    std::size_t first = 0, end = first_separator;
    for (;;) {
        result.push_back(query.substr(first, end - first));
        first = end + 1;
        end = query.find(delimiter, first);
        if (end == query.npos) {
            result.push_back(query.substr(first));
            break;
        }
    }
    // String.split(regex) uses limit zero, dropping every trailing empty part.
    while (!result.empty() && result.back().empty()) result.pop_back();
    return result;
}
bool query_pattern(const IntentPattern &pattern, std::optional<std::u16string_view> query) {
    if (!query) return false;
    auto parameters = split(*query, u'&');
    if (parameters.size() == 1) parameters = split(*query, u';');
    for (const auto parameter : parameters) if (pattern.matches(parameter)) return true;
    return false;
}
bool relative_groups(const CompiledIntentFilter &filter, Data &data) {
    for (const auto &group : filter.relative_groups) {
        if (group.conditions.empty()) continue;
        bool matched = true;
        for (const auto &condition : group.conditions) {
            bool condition_match = false;
            switch (condition.part) {
            case IntentRelativePart::path:
                condition_match = condition.pattern.matches(data.part(uri::Part::path)); break;
            case IntentRelativePart::query:
                condition_match = query_pattern(condition.pattern, data.part(uri::Part::query)); break;
            case IntentRelativePart::fragment:
                condition_match = condition.pattern.matches(data.part(uri::Part::fragment)); break;
            }
            if (!condition_match) { matched = false; break; }
        }
        if (matched) return group.allow; // Ordered allow/block; later groups cannot reverse this decision.
    }
    return false;
}
std::int32_t match_data(const CompiledIntentFilter &filter, const IntentMatchRequest &request, Data &data) {
    if (filter.types.empty() && filter.schemes.empty())
        return !request.type && !request.data ? empty_match + normal : no_data;
    auto result = empty_match;
    const auto scheme = data.scheme();
    if (!filter.schemes.empty()) {
        if (!contains(filter.schemes, scheme.value_or(u""))) return no_data;
        result = scheme_match;
        if (!filter.scheme_specific_parts.empty() && data.present())
            result = patterns(filter.scheme_specific_parts, data.part(uri::Part::scheme_specific_part)) ? ssp_match : no_data;
        if (result != ssp_match && !filter.authorities.empty()) {
            const auto auth = authority(filter, data);
            if (auth < 0) return no_data;
            if (filter.relative_reference_groups) {
                if (filter.paths.empty() && filter.relative_groups.empty()) result = auth;
                else if (patterns(filter.paths, data.part(uri::Part::path)) || relative_groups(filter, data)) result = path_match;
                else return no_data;
            } else {
                if (filter.paths.empty()) result = auth;
                else if (patterns(filter.paths, data.part(uri::Part::path))) result = path_match;
                else return no_data;
            }
        }
        if (result == no_data) return no_data;
    } else if (scheme && !scheme->empty() && *scheme != u"content" && *scheme != u"file") return no_data;
    if (!filter.types.empty()) {
        if (!mime(filter, request.type)) return no_type;
        result = type_match;
    } else if (request.type) return no_type;
    return result + normal;
}
IntentFilterMatch mismatch(std::int32_t reason) { return {IntentMatchStatus::no_match, reason}; }
} // namespace

IntentFilterMatch match_intent_filter(const CompiledIntentFilter &filter, const IntentMatchRequest &request) {
    bounded(request.action);
    bounded(request.type);
    bounded(request.data);
    if (request.categories.size() > category_count)
        throw InspectError("AETHER_INTENT_MATCH_LIMIT", "intent-match", "Intent match exceeds 65536 categories");
    for (const auto category : request.categories) bounded(category);
    if (filter.issue != IntentFilterIssue::none) return {IntentMatchStatus::unsupported, no_data};
    if (request.action && !contains(filter.actions, *request.action)) return mismatch(no_action);
    if (request.mime_state != IntentMimeState::resolved) return {IntentMatchStatus::unsupported, no_type};
    for (const auto &group : filter.relative_groups) for (const auto &condition : group.conditions)
        if (condition.part != IntentRelativePart::path && condition.part != IntentRelativePart::query &&
            condition.part != IntentRelativePart::fragment) return {IntentMatchStatus::unsupported, no_data};
    Data data(request.data);
    const auto score = match_data(filter, request, data);
    if (score < 0) return mismatch(score);
    for (const auto category : request.categories) {
        // matchCategories returns the first mismatching String. A mismatching
        // null is its success sentinel, so later entries are not examined.
        if (!category) break;
        if (!contains(filter.categories, *category)) return mismatch(no_category);
    }
    // MATCH_DEFAULT_ONLY is candidate-selection policy, after ordinary Android
    // match semantics; never synthesize DEFAULT into the request's categories.
    if (request.default_only && !contains(filter.categories, u"android.intent.category.DEFAULT"))
        return mismatch(no_category);
    return {IntentMatchStatus::matched, score};
}
} // namespace aether::apk
