#pragma once
#include "aether/install/diagnostics.hpp"
#include <filesystem>
#include <string>

namespace aether::install {
int show_app_dialog(const std::filesystem::path &root, const std::string &id, bool settings, bool json,
                    std::optional<AppSessionFailure> session_failure = {});
}
