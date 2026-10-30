#pragma once
#include "aether/install/diagnostics.hpp"
#include "aether/security/installed_activity.hpp"
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace aether::install {
struct AppLaunchFailure {
    std::filesystem::path store; // Trusted host-only locator; never exported.
    std::string app_id;
    AppSessionFailure failure = AppSessionFailure::failed;
};
using AppLaunchObserver = std::function<void(const AppLaunchFailure &)>;
struct OpenLinkOptions;
struct OpenFileOptions;
using OpenLinkHandler = std::function<std::optional<security::InstalledActivity>(const OpenLinkOptions &)>;
using FileOpenHandler = std::function<std::optional<security::InstalledActivity>(const OpenFileOptions &)>;
// Typed entry for the raw native activation transport; preserves UTF-16 URI data.
int dispatch_open_link(const OpenLinkOptions &options, bool json,
                       const AppLaunchObserver &observer = {}, const OpenLinkHandler &handler = {});
int dispatch_open_file(const OpenFileOptions &options, bool json,
                       const AppLaunchObserver &observer = {}, const FileOpenHandler &handler = {});
// Returns no value for commands handled by the existing runtime CLI.
// Failure observers run after the attempted session releases its app leases.
// Observer errors cannot replace the original session exception or exit status.
std::optional<int> dispatch_cli(const std::vector<std::string> &arguments, bool json,
                              const AppLaunchObserver &launch_observer = {},
                              const OpenLinkHandler &open_link_handler = {},
                              const FileOpenHandler &open_file_handler = {});
} // namespace aether::install
