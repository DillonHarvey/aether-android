#pragma once
#include "aether/apk/inspect.hpp"
#include "aether/apk/intent_pattern.hpp"
#include <optional>
#include <span>
#include <string_view>

namespace aether::apk {
enum class IntentFilterIssue { none, resource, typed_value, feature_policy, extension, mime_group };
struct IntentFilterPolicy {
    // No implicit device/aconfig decision. Only filters that use this feature
    // require its value. Unknown extensions remain explicitly unsupported.
    std::optional<bool> relative_reference_groups;
    std::uint32_t target_sdk = 35; // Direct compilation profile; resolver derives manifest SDK.
};
struct IntentAuthority {
    std::u16string host; // Leading '*' removed; compare with Java ignore-case.
    bool wildcard = false;
    std::int32_t port = -1; // Negative Android parseInt values mean unconstrained.
};
enum class IntentRelativePart { path, query, fragment };
struct IntentRelativeCondition {
    IntentRelativePart part;
    IntentPattern pattern;
};
struct IntentRelativeGroup {
    bool allow = true;
    std::vector<IntentRelativeCondition> conditions;
};
// Pure semantic value; it confers no launch permission. Use the decoder and
// account the returned value together with retained manifest storage before
// publishing it as a routing plan. Unknown constraints never become wildcards.
struct CompiledIntentFilter {
    IntentFilterIssue issue = IntentFilterIssue::none;
    std::int32_t priority = 0, order = 0;
    bool auto_verify = false;
    std::vector<std::u16string> actions, categories, types, schemes;
    // types stores Android's internal partial form: "image/*" becomes "image".
    bool partial_types = false;
    bool relative_reference_groups = false; // Explicit resolved feature policy.
    std::vector<IntentAuthority> authorities;
    std::vector<IntentPattern> scheme_specific_parts, paths;
    std::vector<IntentRelativeGroup> relative_groups;
    std::size_t accounted_bytes() const noexcept;
};
// Invalid structural/manifest values throw InspectError. Unsupported resource,
// typed or feature forms are retained as an issue, never silently omitted.
CompiledIntentFilter compile_intent_filter(const ManifestIntentFilter &filter,
                                          const IntentFilterPolicy &policy = {});
std::string_view intent_filter_issue_name(IntentFilterIssue issue) noexcept;

enum class IntentMimeState { resolved, unresolved };
struct IntentMatchRequest {
    std::optional<std::u16string_view> action, type, data;
    // Caller preserves actual iteration order. A null category is distinct
    // from an empty String, including Android matchCategories' null sentinel.
    std::span<const std::optional<std::u16string_view>> categories;
    IntentMimeState mime_state = IntentMimeState::resolved;
    bool default_only = false;
};
enum class IntentMatchStatus { matched, no_match, unsupported };
struct IntentFilterMatch {
    IntentMatchStatus status = IntentMatchStatus::no_match;
    // Android match category + adjustment or its negative mismatch reason.
    std::int32_t score = -2;
};
// Matches an admitted semantic value, never invokes a content provider, opens a
// URI, normalizes strings or grants access. Unresolved MIME/constraints remain
// unsupported. Uses shared lenient URI parsing and Android pattern semantics.
IntentFilterMatch match_intent_filter(const CompiledIntentFilter &filter,
                                     const IntentMatchRequest &request);
} // namespace aether::apk
