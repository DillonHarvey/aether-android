#pragma once
#include <Windows.h>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace aether::install {
inline constexpr std::uint64_t current_runtime_compatibility = 58;
struct RuntimePayload {
    std::string path;
    std::vector<std::uint8_t> bytes;
};
struct RuntimeBundle {
    std::vector<RuntimePayload> files;
    std::uint64_t compatibility = 0;
};
// Original bounded distribution format; hashes detect damage, not a publisher.
RuntimeBundle read_runtime_bundle(const std::filesystem::path &image);
struct RuntimeSetupStatus {
    std::string state, detail;
    bool available = false;
};
RuntimeSetupStatus inspect_runtime_setup(const std::filesystem::path &root, bool installing);
RuntimeSetupStatus inspect_runtime_upgrade(const std::filesystem::path &root);
RuntimeSetupStatus inspect_runtime_repair(const std::filesystem::path &root);
// Resolve and verify the current immutable Shell module under a shared lease.
std::filesystem::path runtime_icon_library(const std::filesystem::path &root);
void install_runtime(const std::filesystem::path &root, const std::vector<RuntimePayload> &payload,
                     bool offer_explorer);
// Run from an external distribution. Existing final file identities and paths
// remain in place; interrupted writes require the exact recorded distribution.
std::string upgrade_runtime(const std::filesystem::path &root, const RuntimeBundle &bundle);
// Explicitly restores missing/recorded-prefix payloads from the exact installed
// distribution. Unrecognized modified files and foreign registration are preserved.
std::string repair_runtime(const std::filesystem::path &root, const RuntimeBundle &bundle);
// The native child transfers held identities to the verified Windows controller.
// The controller waits for this process to exit before deleting its last image.
std::string remove_runtime(const std::filesystem::path &root, DWORD controller_pid);
std::wstring runtime_uninstall_command(const std::filesystem::path &root, bool quiet);
std::filesystem::path windows_powershell();
} // namespace aether::install
