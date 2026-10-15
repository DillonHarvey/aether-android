#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace aether::install {
class PackageStore;
enum class ExplorerOperation { status, register_handler, repair, remove, check_upgrade };
struct ExplorerRegistration {
    std::string state = "not-registered", launcher, store, command, icon_library;
    bool verified = false, notified = false;
    std::uint32_t cache_removed = 0, cache_preserved = 0;
    std::string json() const;
};
// Per-user offered handler and explicit secondary verb. Never writes the .apk
// default value or UserChoice. Mutating CLI calls require explicit confirmation.
// The trusted native installer may supply its exclusively held, verified runtime.
// Its already-held store must stay locked through registration; do not reopen it.
ExplorerRegistration explorer_registration(ExplorerOperation operation,
                                           std::optional<std::filesystem::path> store = {},
                                           std::optional<std::filesystem::path> runtime = {},
                                           std::optional<std::filesystem::path> verified_icon_library = {},
                                           bool notify_shell = true,
                                           const PackageStore *held_store = nullptr);
} // namespace aether::install
