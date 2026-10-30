#pragma once
#include "aether/host/windows/document_service.hpp"
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace aether::security {
struct ActivityLaunch;
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
inline constexpr std::uint32_t installed_clock = 1, installed_files = 2, installed_wall_clock = 4,
                               installed_audio_playback = 8, installed_notifications = 16, installed_clipboard = 32;
inline constexpr std::uint32_t installed_permission_mask = 63;
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
    // Host-only Windows audio attribution. Never serialized into worker messages.
    std::string audio_display_name;
    std::filesystem::path audio_icon_path;
    std::shared_ptr<const ActivityLaunch> launch;
    // Host-only, current owned notification registration. Empty means unavailable;
    // the persisted grant is separate and never inferred from Windows registration.
    std::string notification_aumid;
    // Exact user-approved read-only document for this admitted launch only.
    // Neither an Intent flag nor a persisted private-files grant supplies it.
    std::optional<host::PreparedDocumentSource> read_document;
};
} // namespace aether::security
