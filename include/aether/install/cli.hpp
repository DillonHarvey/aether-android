#pragma once
#include <optional>
#include <string>
#include <vector>

namespace aether::install {
// Returns no value for commands handled by the existing runtime CLI.
std::optional<int> dispatch_cli(const std::vector<std::string> &arguments, bool json);
} // namespace aether::install
