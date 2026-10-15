#pragma once
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace aether::security {
inline bool valid_installed_id(std::string_view id) noexcept {
    return id.size() == 32 && std::all_of(id.begin(), id.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}
// Installed broker identities occupy a separate namespace from development probes.
// The registry rejects collisions, including identities of removed installations.
inline std::uint64_t installed_broker_id(std::string_view id) {
    if (!valid_installed_id(id))
        throw std::invalid_argument("Invalid installed application identity");
    std::uint64_t value = 0;
    for (const auto c : id.substr(0, 16))
        value = (value << 4) | static_cast<unsigned>(c <= '9' ? c - '0' : c - 'a' + 10);
    return value | (std::uint64_t{1} << 63);
}
inline constexpr std::uint32_t installed_clock = 1, installed_files = 2;
// Trusted window metadata only. The command resolves an installed ID again;
// it never carries package paths, worker options or capability grants.
struct InstalledRelaunch {
    std::string command, display_name, icon_resource;
    std::string unavailable_reason;
};
// Host-only configuration resolved from a validated registry. Neither package
// metadata nor guest code supplies these paths, permissions or retained handles.
struct InstalledActivity {
    std::string id;
    std::uint32_t permissions = 0;
    std::filesystem::path data_root, audit_root;
    std::shared_ptr<const std::vector<std::uint8_t>> package;
    std::shared_ptr<const void> lease;
    void *package_file = nullptr; // Read-only file retained by lease, with writes/deletion denied.
    InstalledRelaunch relaunch;
    std::uint32_t icon_renderer = 1;
};
} // namespace aether::security
