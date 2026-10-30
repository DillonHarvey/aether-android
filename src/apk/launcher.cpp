#include "aether/apk/launcher.hpp"
#include <algorithm>
#include <bit>
#include <map>

namespace aether::apk {
namespace {
std::optional<bool> boolean(const ManifestBoolean &value, bool fallback) {
    if (value.type == manifest_absent_type)
        return fallback;
    if (value.type == 0x12)
        return value.data != 0;
    return {};
}
bool no_permission(const DisplayValue &value) {
    return value.type == manifest_absent_type || (value.type == 0 && value.reference <= 1) ||
           (value.type == 3 && value.literal.empty());
}
std::size_t activity_target(const ManifestInfo &manifest, std::size_t selected_activity,
                            const char *code, const char *phase) {
    const auto invalid = [&](const char *message) { throw InspectError(code, phase, message); };
    if (selected_activity >= manifest.activities.size())
        invalid("Activity metadata requires an existing selected declaration");
    const auto &selected = manifest.activities[selected_activity];
    if (selected.name.empty() ||
        std::count_if(manifest.activities.begin(), manifest.activities.end(),
                      [&](const auto &activity) { return activity.name == selected.name; }) != 1)
        invalid("Activity metadata requires a unique nonempty selected identity");
    if (selected.target.empty())
        return selected_activity;
    std::optional<std::size_t> target;
    for (std::size_t index = 0; index < manifest.activities.size(); ++index) {
        const auto &activity = manifest.activities[index];
        if (activity.name != selected.target)
            continue;
        if (target || index >= selected_activity || !activity.target.empty())
            invalid("Alias metadata target must be one unique earlier real Activity declaration");
        target = index;
    }
    if (!target)
        invalid("Alias metadata target Activity is missing");
    return *target;
}
} // namespace

ActivityEligibilityInventory inspect_activity_eligibility(const ManifestInfo &manifest) {
    ActivityEligibilityInventory result;
    const auto refuse = [&](ActivityInventoryStatus status, std::string reason) {
        result.status = status;
        result.reason = std::move(reason);
        return result;
    };
    // Retain unrelated duplicate declarations without guessing a general
    // component-resolution order. A launch identity or alias target must be unique.
    // A map avoids quadratic scans over the bounded 8,192-component inventory.
    std::map<std::string_view, std::pair<std::size_t, std::size_t>> components;
    for (std::size_t i = 0; i < manifest.activities.size(); ++i) {
        const auto &activity = manifest.activities[i];
        if (activity.name.empty())
            return refuse(ActivityInventoryStatus::invalid, "Activity/alias names must be nonempty.");
        const auto [entry, inserted] = components.try_emplace(activity.name, i, 0);
        (void)inserted;
        ++entry->second.second;
    }
    const auto target_sdk = manifest.target_sdk.value_or(manifest.min_sdk.value_or(1));
    for (std::size_t i = 0; i < manifest.activities.size(); ++i) {
        const auto &activity = manifest.activities[i];
        if (activity.launcher && components.at(activity.name).second != 1)
            return refuse(ActivityInventoryStatus::unsupported,
                          "Duplicate launcher component declarations are unsupported: " + activity.name);
        if (!activity.target.empty()) {
            const auto target = components.find(activity.target);
            if (target == components.end() || target->second.first >= i ||
                !manifest.activities[target->second.first].target.empty())
                return refuse(ActivityInventoryStatus::invalid,
                              "An Activity alias must target an earlier Activity declaration: " +
                                  activity.name);
            if (target->second.second != 1)
                return refuse(ActivityInventoryStatus::unsupported,
                              "Duplicate alias target declarations are unsupported: " + activity.target);
        }
        if (target_sdk >= 31 && (activity.intent_filter || activity.launcher) &&
            activity.exported.type == manifest_absent_type)
            return refuse(ActivityInventoryStatus::invalid,
                          "Target SDK 31 or later requires explicit android:exported on every "
                          "Activity/alias with an intent filter: " +
                              activity.name);
    }
    const auto application_enabled = boolean(manifest.enabled, true);
    result.application_disabled = application_enabled == false;
    result.entries.resize(manifest.activities.size());
    for (std::size_t i = 0; i < manifest.activities.size(); ++i) {
        const auto &activity = manifest.activities[i];
        auto &entry = result.entries[i];
        entry.declaration = i;
        entry.target = activity.target.empty() ? i : components.at(activity.target).first;
        const auto set_status = [&](ActivityEligibilityStatus status, ActivityEligibilityReason reason,
                                    std::string_view text) {
            entry.status = status;
            entry.reason_code = reason;
            entry.reason = text;
        };
        if (result.application_disabled) {
            set_status(ActivityEligibilityStatus::disabled, ActivityEligibilityReason::application_disabled,
                       "The application is disabled in its manifest.");
            continue;
        }
        const auto enabled = boolean(activity.enabled, true);
        const auto exported = boolean(activity.exported, activity.intent_filter || activity.launcher);
        if (enabled == false || exported == false) {
            set_status(ActivityEligibilityStatus::disabled,
                       enabled == false ? ActivityEligibilityReason::component_disabled : ActivityEligibilityReason::not_exported,
                       enabled == false ? "The Activity/alias is disabled in its manifest." : "The Activity/alias is not exported.");
            continue;
        }
        // The existing launcher permits unrelated duplicates. A general
        // resolver cannot choose between two otherwise eligible declarations
        // with the same external component identity; retain that distinction.
        if (components.at(activity.name).second != 1) {
            set_status(ActivityEligibilityStatus::unsupported, ActivityEligibilityReason::duplicate_identity,
                       "Duplicate component declarations are unsupported.");
            continue;
        }
        if (!application_enabled || !enabled || !exported) {
            set_status(ActivityEligibilityStatus::unsupported, ActivityEligibilityReason::unresolved_state,
                       "Activity enabled/exported state requires unsupported resource or typed value resolution.");
            continue;
        }
        // An alias has its own enabled/exported/permission settings; it can
        // launch a disabled or private target and never inherits its permission.
        const auto &permission = activity.permission.type == manifest_absent_type && activity.target.empty()
                                     ? manifest.permission
                                     : activity.permission;
        if (!no_permission(permission)) {
            set_status(ActivityEligibilityStatus::unsupported, ActivityEligibilityReason::unsupported_permission,
                       "Activity component permissions are not supported.");
            continue;
        }
        entry.status = ActivityEligibilityStatus::eligible;
    }
    return result;
}

LauncherSelection select_launcher(const ManifestInfo &manifest) {
    LauncherSelection result;
    result.declared =
        static_cast<std::size_t>(std::count_if(manifest.activities.begin(), manifest.activities.end(),
                                               [](const auto &activity) { return activity.launcher; }));
    const auto refuse = [&](LauncherStatus status, std::string reason) {
        result.status = status;
        result.activity.reset();
        result.reason = std::move(reason);
        return result;
    };
    const auto inventory = inspect_activity_eligibility(manifest);
    if (inventory.status != ActivityInventoryStatus::ready)
        return refuse(inventory.status == ActivityInventoryStatus::invalid ? LauncherStatus::invalid : LauncherStatus::unsupported,
                      inventory.reason);
    if (inventory.application_disabled)
        return refuse(LauncherStatus::none, "The application is disabled in its manifest.");
    std::string unresolved;
    for (const auto &entry : inventory.entries) {
        const auto &activity = manifest.activities[entry.declaration];
        if (!activity.launcher) continue;
        if (entry.status == ActivityEligibilityStatus::unsupported) {
            if (unresolved.empty()) {
                if (entry.reason_code == ActivityEligibilityReason::unresolved_state)
                    unresolved = "Launcher enabled/exported state requires unsupported resource or typed value resolution: " + activity.name;
                else if (entry.reason_code == ActivityEligibilityReason::unsupported_permission)
                    unresolved = "Launcher component permissions are not supported: " + activity.name;
                else unresolved = entry.reason;
            }
            continue;
        }
        if (entry.status == ActivityEligibilityStatus::eligible) {
            ++result.eligible;
            result.activity = entry.declaration;
        }
    }
    if (!unresolved.empty())
        return refuse(LauncherStatus::unsupported, std::move(unresolved));
    if (result.eligible == 0)
        return refuse(LauncherStatus::none, "No enabled, exported MAIN/LAUNCHER Activity or alias.");
    if (result.eligible != 1)
        return refuse(LauncherStatus::ambiguous,
                      "Execution requires exactly one eligible launcher Activity or alias.");
    result.status = LauncherStatus::selected;
    result.reason = "One enabled, exported launcher is selected from the manifest declarations.";
    return result;
}

std::int32_t requested_orientation(const ManifestInfo &manifest, std::size_t selected_activity) {
    const auto target = activity_target(manifest, selected_activity,
                                        "AETHER_ACTIVITY_ORIENTATION_INVALID", "activity-orientation");
    // screenOrientation is not an alias attribute: the target's value applies.
    const auto &value = manifest.activities[target].screen_orientation;
    if (value.type == manifest_absent_type)
        return -1;
    if (value.type != 0x10 && value.type != 0x11)
        throw InspectError("AETHER_ACTIVITY_ORIENTATION_UNSUPPORTED", "activity-orientation",
                           "Activity screenOrientation requires unresolved resource or typed-value support (type " +
                               std::to_string(value.type) + ")");
    const auto orientation = std::bit_cast<std::int32_t>(value.data);
    if (orientation < -1 || orientation > 1)
        throw InspectError("AETHER_ACTIVITY_ORIENTATION_UNSUPPORTED", "activity-orientation",
                           "Requested Activity screenOrientation " + std::to_string(orientation) +
                               " is unsupported; this profile supports unspecified (-1), landscape (0) and portrait (1)");
    return orientation;
}

std::uint32_t handled_configuration_changes(const ManifestInfo &manifest, std::size_t selected_activity) {
    if (!manifest.activity_config_changes.empty() &&
        manifest.activity_config_changes.size() != manifest.activities.size())
        throw InspectError("AETHER_ACTIVITY_CONFIG_CHANGES_INVALID", "activity-configuration",
                           "Activity configChanges metadata is not aligned with the Activity inventory");
    const auto target = activity_target(manifest, selected_activity,
                                        "AETHER_ACTIVITY_CONFIG_CHANGES_INVALID", "activity-configuration");
    if (manifest.activity_config_changes.empty())
        return 0;
    const auto &value = manifest.activity_config_changes[target];
    if (value.type == manifest_absent_type)
        return 0;
    if (value.type != 0x10 && value.type != 0x11)
        throw InspectError("AETHER_ACTIVITY_CONFIG_CHANGES_UNSUPPORTED", "activity-configuration",
                           "Activity configChanges requires unresolved resource or typed-value support (type " +
                               std::to_string(value.type) + ")");
    if (value.data & ~manifest_config_changes_mask)
        throw InspectError("AETHER_ACTIVITY_CONFIG_CHANGES_UNSUPPORTED", "activity-configuration",
                           "Activity configChanges contains unsupported Android flag bits");
    return value.data;
}

std::string_view launcher_status_name(LauncherStatus status) {
    switch (status) {
    case LauncherStatus::selected:
        return "selected";
    case LauncherStatus::none:
        return "none";
    case LauncherStatus::ambiguous:
        return "ambiguous";
    case LauncherStatus::unsupported:
        return "unsupported";
    case LauncherStatus::invalid:
        return "invalid";
    }
    return "invalid";
}
} // namespace aether::apk
