#pragma once
#include <Windows.h>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aether::shell {
void run_icon_broker(const std::filesystem::path &worker, const std::filesystem::path &cache,
                     const std::wstring &endpoint, HANDLE stop_event,
                     const std::function<void(std::string_view)> &diagnostic = {});
std::optional<int> dispatch_icon_cli(const std::vector<std::string> &arguments, bool json);
} // namespace aether::shell
