#include "aether/apk/intent_resolver.hpp"
#include "aether/common/text.hpp"
#include "aether/common/uri.hpp"
#include <algorithm>
#include <utility>

namespace aether::apk {
namespace {
[[noreturn]] void limit() {
    throw InspectError("AETHER_INTENT_RESOLUTION_LIMIT", "intent-resolution",
                       "Intent resolution exceeds the existing metadata or text profile");
}
void bounded(std::u16string_view value) {
    if (value.size() > uri::text_units) limit();
}
void bounded(const std::optional<std::u16string_view> &value) {
    if (value) bounded(*value);
}
bool same(std::string_view encoded, std::u16string_view units) {
    // Manifest strings already passed strict UTF-8 parsing. No case folding,
    // relative component expansion or normalization applies to identities.
    const auto text = utf16(encoded);
    return text.size() == units.size() && std::equal(text.begin(), text.end(), units.begin());
}
class Budget {
    std::size_t retained_;
  public:
    explicit Budget(std::size_t manifest_bytes) : retained_(manifest_bytes) {
        if (retained_ > manifest_activity_bytes) limit();
    }
    void add(std::size_t bytes) {
        if (bytes > manifest_activity_bytes - retained_) limit();
        retained_ += bytes;
    }
    void array(std::size_t count, std::size_t size) {
        if (count > (manifest_activity_bytes - retained_) / size) limit();
        add(count * size);
    }
    void check(std::size_t filter_bytes, std::size_t result_capacity) const {
        auto trial = *this;
        trial.add(filter_bytes);
        trial.array(result_capacity, sizeof(ActivityIntentMatch));
    }
    void append(std::vector<ActivityIntentMatch> &matches, ActivityIntentMatch match,
                std::size_t filter_bytes) const {
        if (matches.size() == matches.capacity()) {
            auto trial = *this;
            trial.add(filter_bytes);
            const auto available = (manifest_activity_bytes - trial.retained_) / sizeof(ActivityIntentMatch);
            if (matches.size() >= available) limit();
            const auto growth = matches.capacity() ? matches.capacity() * 2 : std::size_t{1};
            matches.reserve(std::min(available, growth));
        }
        check(filter_bytes, matches.capacity());
        matches.push_back(std::move(match));
    }
};
} // namespace

ActivityIntentResolution resolve_activity_intent(const ManifestInfo &manifest,
                                                 const ActivityIntentRequest &request,
                                                 const ActivityIntentPolicy &policy) {
    ActivityIntentResolution result;
    const auto refuse = [&](LauncherStatus status, std::string_view reason) {
        result.status = status;
        result.declaration.reset();
        result.target.reset();
        result.reason = reason;
        return std::move(result);
    };
    bounded(request.intent.action);
    bounded(request.intent.type);
    bounded(request.intent.data);
    bounded(request.package);
    if (request.component) {
        bounded(request.component->package);
        bounded(request.component->class_name);
    }
    if (request.intent.categories.size() > 65536) limit();
    for (const auto &category : request.intent.categories) bounded(category);
    if (manifest.activities.size() > manifest_activity_count) limit();
    Budget budget(activity_metadata_size(manifest));
    budget.add(sizeof(ActivityIntentResolution));
    // The map used for validation is released by the shared inventory helper.
    // Only its returned records and owned global diagnostic remain retained.
    const auto inventory = inspect_activity_eligibility(manifest);
    budget.add(sizeof(ActivityEligibilityInventory));
    budget.array(inventory.entries.capacity(), sizeof(ActivityEligibility));
    budget.add(inventory.reason.capacity() + 1);
    if (inventory.status != ActivityInventoryStatus::ready)
        return refuse(inventory.status == ActivityInventoryStatus::invalid ? LauncherStatus::invalid :
                                                                           LauncherStatus::unsupported,
                      "Activity declarations do not admit static external resolution.");
    if (inventory.application_disabled)
        return refuse(LauncherStatus::none, "The application is disabled in its manifest.");
    auto effective_policy = policy.filters;
    effective_policy.target_sdk = manifest.target_sdk.value_or(manifest.min_sdk.value_or(1));
    if (request.component) {
        // Android's explicit-component identity lookup ignores Intent.package.
        // Its subsequent caller/compat-dependent filter safety gate remains
        // separate from that lookup and must never be implicitly disabled.
        if (!same(manifest.package_id, request.component->package))
            return refuse(LauncherStatus::none, "The explicit component belongs to another package.");
        for (const auto &entry : inventory.entries) {
            if (!same(manifest.activities[entry.declaration].name, request.component->class_name)) continue;
            if (entry.status == ActivityEligibilityStatus::unsupported)
                return refuse(LauncherStatus::unsupported, "Explicit component eligibility is unsupported.");
            if (entry.status != ActivityEligibilityStatus::eligible)
                return refuse(LauncherStatus::none, "The explicit component is not externally eligible.");
            const auto &activity = manifest.activities[entry.declaration];
            const auto *filters = manifest.activity_intent_filters.empty() ? nullptr :
                &manifest.activity_intent_filters[entry.declaration];
            if ((!filters || filters->empty()) && (activity.intent_filter || activity.launcher))
                return refuse(LauncherStatus::unsupported, "Explicit component filter inventory is unavailable.");
            const bool has_filters = filters && !filters->empty();
            if (has_filters && !policy.enforce_explicit_filters)
                return refuse(LauncherStatus::unsupported, "Explicit Intent filter safety policy is unresolved.");
            if (has_filters && *policy.enforce_explicit_filters) {
                if (!request.intent.action) {
                    if (!policy.block_null_action)
                        return refuse(LauncherStatus::unsupported, "Null-action caller safety policy is unresolved.");
                    if (*policy.block_null_action)
                        return refuse(LauncherStatus::none, "Caller safety policy blocks a null-action Intent.");
                }
                auto explicit_request = request.intent;
                explicit_request.default_only = false;
                bool unresolved = false;
                for (std::size_t index = 0; index < filters->size(); ++index) {
                    const auto filter = compile_intent_filter((*filters)[index], effective_policy);
                    const auto storage = filter.accounted_bytes();
                    budget.check(storage, result.matches.capacity());
                    const auto match = match_intent_filter(filter, explicit_request);
                    if (match.status == IntentMatchStatus::unsupported) { unresolved = true; continue; }
                    if (match.status != IntentMatchStatus::matched) continue;
                    const bool is_default = std::find(filter.categories.begin(), filter.categories.end(),
                        u"android.intent.category.DEFAULT") != filter.categories.end();
                    budget.append(result.matches,
                        {entry.declaration, entry.target, index, match.score, filter.priority, filter.order,
                         is_default, filter.auto_verify}, storage);
                }
                // A known match is sufficient for the safety gate's any-filter
                // rule; unknown alternative filters cannot change its identity.
                if (result.matches.empty())
                    return refuse(unresolved ? LauncherStatus::unsupported : LauncherStatus::none,
                                  "Explicit component does not have a proven matching safety filter.");
            } else {
                budget.append(result.matches, {entry.declaration, entry.target, {}, 0, 0, 0, false, false}, 0);
            }
            result.status = LauncherStatus::selected;
            result.declaration = entry.declaration;
            result.target = entry.target;
            result.reason = "One eligible explicit component satisfies the resolved caller safety policy.";
            return result;
        }
        return refuse(LauncherStatus::none, "The explicit component is not declared by this package.");
    }
    if (request.package && !same(manifest.package_id, *request.package))
        return refuse(LauncherStatus::none, "The Intent package constraint excludes this package.");
    bool unsupported = false;
    const auto unresolved = [&](std::size_t declaration, std::optional<std::size_t> filter,
                                 IntentFilterIssue issue, std::string_view reason) {
        unsupported = true;
        if (!result.unsupported_declaration) {
            result.unsupported_declaration = declaration;
            result.unsupported_filter = filter;
            result.filter_issue = issue;
            result.reason = reason;
        }
    };
    std::optional<std::size_t> selected, target;
    bool ambiguous = false;
    for (const auto &entry : inventory.entries) {
        if (entry.status == ActivityEligibilityStatus::disabled) continue;
        const auto &activity = manifest.activities[entry.declaration];
        if (manifest.activity_intent_filters.empty()) {
            if (activity.intent_filter || activity.launcher)
                unresolved(entry.declaration, {}, IntentFilterIssue::none, "Declared filter inventory is unavailable.");
            continue;
        }
        const auto &filters = manifest.activity_intent_filters[entry.declaration];
        if (filters.empty()) {
            if (activity.intent_filter || activity.launcher)
                unresolved(entry.declaration, {}, IntentFilterIssue::none, "Declared filter inventory is unavailable.");
            continue;
        }
        if (!request.intent.action) {
            if (!policy.block_null_action) {
                unresolved(entry.declaration, {}, IntentFilterIssue::feature_policy, "Null-action caller safety policy is unresolved.");
                continue;
            }
            if (*policy.block_null_action) continue;
        }
        if (entry.status == ActivityEligibilityStatus::unsupported) {
            unresolved(entry.declaration, {}, IntentFilterIssue::none, entry.reason);
            continue;
        }
        for (std::size_t index = 0; index < filters.size(); ++index) {
            // Stream semantic values instead of retaining a second full copy
            // of all manifest text/patterns. This value lives through matching
            // and result admission, then releases before the next filter.
            const auto filter = compile_intent_filter(filters[index], effective_policy);
            const auto storage = filter.accounted_bytes();
            budget.check(storage, result.matches.capacity());
            const auto match = match_intent_filter(filter, request.intent);
            if (match.status == IntentMatchStatus::unsupported) {
                unresolved(entry.declaration, index, filter.issue,
                           filter.issue == IntentFilterIssue::none ? "Intent MIME resolution is unavailable." :
                                                                    intent_filter_issue_name(filter.issue));
                continue;
            }
            if (match.status != IntentMatchStatus::matched) continue;
            const bool is_default = std::find(filter.categories.begin(), filter.categories.end(),
                u"android.intent.category.DEFAULT") != filter.categories.end();
            budget.append(result.matches,
                {entry.declaration, entry.target, index, match.score, filter.priority, filter.order,
                 is_default, filter.auto_verify}, storage);
            if (selected && *selected != entry.declaration) ambiguous = true;
            if (!selected) { selected = entry.declaration; target = entry.target; }
        }
    }
    if (unsupported)
        return refuse(LauncherStatus::unsupported, result.reason);
    if (!selected)
        return refuse(LauncherStatus::none, "No statically eligible Activity filter matches the Intent.");
    if (ambiguous)
        return refuse(LauncherStatus::ambiguous,
                      "Multiple Activities match; Android preference and domain selection are not implemented.");
    result.status = LauncherStatus::selected;
    result.declaration = selected;
    result.target = target;
    result.reason = "All matching filters identify one statically eligible Activity declaration.";
    return result;
}
} // namespace aether::apk
