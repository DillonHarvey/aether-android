#pragma once
#include <filesystem>
#include <string>

namespace aether::install::detail {
// Callers hold the shared Shell mutex and the target runtime lease.
bool runtime_registration_absent();
void register_runtime(const std::filesystem::path &root, const std::string &identity, bool repair = false);
void verify_runtime_registration(const std::filesystem::path &root, const std::string &identity,
                                 bool allow_missing);
void unregister_runtime(const std::filesystem::path &root, const std::string &identity);
std::wstring uninstall_command(const std::filesystem::path &root, const std::string &identity, bool quiet);
std::string runtime_registration_json(const std::filesystem::path &root, const std::string &identity);
} // namespace aether::install::detail
