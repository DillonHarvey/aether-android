#pragma once
#include "aether/apk/inspect.hpp"
#include <string_view>

namespace aether::apk {
enum class LauncherStatus { selected, none, ambiguous, unsupported, invalid };
struct LauncherSelection {
    LauncherStatus status = LauncherStatus::none;
    std::optional<std::size_t> activity;
    std::size_t declared = 0, eligible = 0;
    std::string reason;
};
enum class ActivityInventoryStatus { ready, invalid, unsupported };
enum class ActivityEligibilityStatus { eligible, disabled, unsupported };
enum class ActivityEligibilityReason {
    none, application_disabled, component_disabled, not_exported,
    unresolved_state, unsupported_permission, duplicate_identity
};
struct ActivityEligibility {
    ActivityEligibilityStatus status = ActivityEligibilityStatus::disabled;
    // Filters and visible component identity belong to the declaration. An
    // alias executes its distinct unique earlier real Activity target.
    std::size_t declaration = 0, target = 0;
    ActivityEligibilityReason reason_code = ActivityEligibilityReason::none;
    std::string_view reason; // Fixed source-owned text; no copied manifest names.
};
struct ActivityEligibilityInventory {
    ActivityInventoryStatus status = ActivityInventoryStatus::ready;
    bool application_disabled = false;
    std::vector<ActivityEligibility> entries;
    std::string reason;
};
// One shared O(n log n) static external-launch assessment. Resource-backed
// flags/permissions remain unsupported under the existing profile; no grant or
// mutable component-state lookup occurs. Global errors retain select_launcher's
// validation order. Unrelated duplicate nonlauncher identities affect general
// candidate entries, while the legacy launcher still ignores those entries.
ActivityEligibilityInventory inspect_activity_eligibility(const ManifestInfo &manifest);
// Static external-launch eligibility shared by presentation, admission and the
// isolated worker. Selection never mutates component state or grants permission.
LauncherSelection select_launcher(const ManifestInfo &manifest);
// Resolve a selected Activity or its unique earlier alias target. This is an
// execution-profile query, not admission or permission: only unspecified,
// landscape and portrait are supported; unresolved/other values throw InspectError.
std::int32_t requested_orientation(const ManifestInfo &manifest, std::size_t selected_activity);
// Raw declared Android configChanges mask, inherited from an alias target.
// Target-SDK compatibility rules are applied separately by the runtime.
std::uint32_t handled_configuration_changes(const ManifestInfo &manifest, std::size_t selected_activity);
std::string_view launcher_status_name(LauncherStatus status);
} // namespace aether::apk
