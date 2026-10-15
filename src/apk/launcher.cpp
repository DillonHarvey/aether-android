#include "aether/apk/launcher.hpp"
#include <algorithm>
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
} // namespace

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
    // Retain unrelated duplicate declarations without guessing a general
    // component-resolution order. A launch identity or alias target must be unique.
    // A map avoids quadratic scans over the bounded 8,192-component inventory.
    std::map<std::string_view, std::pair<std::size_t, std::size_t>> components;
    for (std::size_t i = 0; i < manifest.activities.size(); ++i) {
        const auto &activity = manifest.activities[i];
        if (activity.name.empty())
            return refuse(LauncherStatus::invalid, "Activity/alias names must be nonempty.");
        const auto [entry, inserted] = components.try_emplace(activity.name, i, 0);
        (void)inserted;
        ++entry->second.second;
    }
    const auto target_sdk = manifest.target_sdk.value_or(manifest.min_sdk.value_or(1));
    for (std::size_t i = 0; i < manifest.activities.size(); ++i) {
        const auto &activity = manifest.activities[i];
        if (activity.launcher && components.at(activity.name).second != 1)
            return refuse(LauncherStatus::unsupported,
                          "Duplicate launcher component declarations are unsupported: " + activity.name);
        if (!activity.target.empty()) {
            const auto target = components.find(activity.target);
            if (target == components.end() || target->second.first >= i ||
                !manifest.activities[target->second.first].target.empty())
                return refuse(LauncherStatus::invalid,
                              "An Activity alias must target an earlier Activity declaration: " +
                                  activity.name);
            if (target->second.second != 1)
                return refuse(LauncherStatus::unsupported,
                              "Duplicate alias target declarations are unsupported: " + activity.target);
        }
        if (target_sdk >= 31 && (activity.intent_filter || activity.launcher) &&
            activity.exported.type == manifest_absent_type)
            return refuse(LauncherStatus::invalid,
                          "Target SDK 31 or later requires explicit android:exported on every "
                          "Activity/alias with an intent filter: " +
                              activity.name);
    }
    const auto application_enabled = boolean(manifest.enabled, true);
    if (application_enabled == false)
        return refuse(LauncherStatus::none, "The application is disabled in its manifest.");
    std::string unresolved;
    for (std::size_t i = 0; i < manifest.activities.size(); ++i) {
        const auto &activity = manifest.activities[i];
        if (!activity.launcher)
            continue;
        const auto enabled = boolean(activity.enabled, true);
        const auto exported = boolean(activity.exported, activity.intent_filter || activity.launcher);
        if (enabled == false || exported == false)
            continue;
        if (!application_enabled || !enabled || !exported) {
            if (unresolved.empty())
                unresolved = "Launcher enabled/exported state requires unsupported resource or typed "
                             "value resolution: " +
                             activity.name;
            continue;
        }
        // An alias has its own enabled/exported/permission settings; it can
        // launch a disabled or private target and never inherits its permission.
        const auto &permission = activity.permission.type == manifest_absent_type && activity.target.empty()
                                     ? manifest.permission
                                     : activity.permission;
        if (!no_permission(permission)) {
            if (unresolved.empty())
                unresolved = "Launcher component permissions are not supported: " + activity.name;
            continue;
        }
        ++result.eligible;
        result.activity = i;
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
