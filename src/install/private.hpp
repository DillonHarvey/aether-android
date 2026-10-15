#pragma once
#include "aether/apk/inspect.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include <filesystem>

namespace aether::install::detail {
host::UniqueHandle hold_directory(const std::filesystem::path &path, bool create, bool private_policy);
host::UniqueHandle private_file(const std::filesystem::path &path, DWORD access, DWORD creation,
                                std::uint64_t limit, DWORD sharing = 0, bool inherited = false);
std::vector<std::uint8_t> read_contents(HANDLE file);
void replace_contents(HANDLE file, apk::Bytes bytes);
void export_report_json(std::string_view json, const std::filesystem::path &destination);
} // namespace aether::install::detail
