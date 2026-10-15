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
// Static external-launch eligibility shared by presentation, admission and the
// isolated worker. Selection never mutates component state or grants permission.
LauncherSelection select_launcher(const ManifestInfo &manifest);
std::string_view launcher_status_name(LauncherStatus status);
} // namespace aether::apk
