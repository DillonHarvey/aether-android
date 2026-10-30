#pragma once
#include "aether/apk/intent_filter.hpp"
#include "aether/apk/launcher.hpp"

namespace aether::apk {
struct IntentComponentRequest {
    std::u16string_view package, class_name; // Actual ComponentName strings.
};
struct ActivityIntentRequest {
    IntentMatchRequest intent;
    std::optional<std::u16string_view> package;
    std::optional<IntentComponentRequest> component;
};
struct ActivityIntentPolicy {
    IntentFilterPolicy filters;
    // Resolved trusted caller/compat/feature decisions, not Intent-controlled
    // flags. Unknown relevant Android15 safety policy refuses resolution.
    std::optional<bool> enforce_explicit_filters, block_null_action;
};
struct ActivityIntentMatch {
    std::size_t declaration = 0, target = 0;
    // Absent only when the resolved explicit-component policy needs no filter.
    std::optional<std::size_t> filter;
    std::int32_t score = 0, priority = 0, order = 0;
    bool is_default = false, auto_verify = false;
};
struct ActivityIntentResolution {
    LauncherStatus status = LauncherStatus::none;
    std::optional<std::size_t> declaration, target;
    std::vector<ActivityIntentMatch> matches;
    std::optional<std::size_t> unsupported_declaration, unsupported_filter;
    IntentFilterIssue filter_issue = IntentFilterIssue::none;
    std::string_view reason; // Fixed source-owned diagnostics, no URI content.
};
// Pure single-package static external resolution. This performs no execution,
// content-provider lookup, domain/default preference selection or permission
// grant. Multiple matching declarations stay ambiguous; priorities/scores are
// retained as evidence, not used to invent Android ranking or user defaults.
// Manifest, eligibility, result and one streamed semantic filter share the
// existing 4 MiB retained metadata allowance. Invalid/limit input may throw
// InspectError; unsupported constraints never silently disappear.
ActivityIntentResolution resolve_activity_intent(const ManifestInfo &manifest,
                                                 const ActivityIntentRequest &request,
                                                 const ActivityIntentPolicy &policy = {});
} // namespace aether::apk
