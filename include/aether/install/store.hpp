#pragma once
#include "aether/apk/inspect.hpp"
#include "aether/apk/signature.hpp"
#include "aether/security/installed_activity.hpp"
#include <memory>

namespace aether::install {
struct AppDiagnostics;
class InstallError final : public std::runtime_error {
  public:
    std::string code;
    InstallError(std::string code, std::string message);
};

enum class State : std::uint32_t {
    preparing = 1,
    installed,
    removing,
    removed,
    data_retained,
    installing_windows,
    updating,
    update_committed,
    update_rolled_back
};
enum class ShellState : std::uint32_t { none, pending, ready };
enum class SigningState : std::uint32_t {
    not_recorded,
    unverified,
    unsupported,
    verified_v2,
    verified_v3,
    verified_v31,
    verified_set
};
constexpr bool verified_signing(SigningState state) noexcept {
    return state == SigningState::verified_v2 || state == SigningState::verified_v3 ||
           state == SigningState::verified_v31 || state == SigningState::verified_set;
}
constexpr const char *signing_status(SigningState state) noexcept {
    return state == SigningState::verified_v2    ? "verified-apk-v2"
           : state == SigningState::verified_v3  ? "verified-apk-v3"
           : state == SigningState::verified_v31 ? "verified-apk-v3.1"
           : state == SigningState::verified_set ? "verified-xapk-set"
           : state == SigningState::unsupported  ? "unsupported"
                                                 : "unverified";
}
struct InstalledApp {
    apk::PackageFormat format = apk::PackageFormat::apk;
    std::string id, package_id, version_name, activity, sha256;
    std::uint32_t version_code = 0, min_sdk = 0, target_sdk = 0;
    std::uint64_t package_bytes = 0;
    std::uint64_t package_generation = 0;
    // Retained across APK updates; existing icon paths become stable in schema 8.
    std::uint64_t icon_generation = 0;
    // Schema 13 records the generator; older hashes continue to use renderer 1.
    std::uint32_t icon_renderer = 1;
    std::vector<std::string> declared_permissions;
    State state = State::preparing;
    bool keep_data = false;
    std::uint32_t permissions = 0;
    ShellState shell = ShellState::none;
    std::string display_name, shortcut_name, launcher, icon_sha256;
    SigningState signing = SigningState::not_recorded;
    // Sorted, distinct SHA-256 fingerprints of each verified signer's first
    // certificate. Neither certificate subjects nor publisher names are trusted.
    std::vector<std::string> signer_certificates;
    std::optional<bool> shell_verified;
    std::string json() const;
};
struct InstallPreview {
    apk::InspectResult inspection;
    bool installable = false;
    apk::SignatureReport signing;
    std::string reason;
    std::string json() const;
};
struct UpdatePreview {
    InstalledApp current;
    bool updateable = false, adopts_legacy_identity = false;
    std::string code, reason;
    std::string json(const InstallPreview &candidate) const;
};
struct PermissionReview {
    std::string sha256;
    std::uint32_t permissions = 0;
};
// Inspection never creates a store or executes package code.
InstallPreview preview(const std::filesystem::path &apk);
// Commit only the source snapshot explicitly reviewed by the caller. Native
// installation never grants effective launch authority before Windows commit.
InstalledApp install_windows(const std::filesystem::path &apk, const std::filesystem::path &root,
                             std::string_view expected_sha256, std::uint32_t permissions);
InstalledApp update_package(const std::filesystem::path &apk, const std::filesystem::path &root,
                            std::string_view id, std::string_view expected_current_sha256,
                            std::string_view expected_sha256);
bool installed_state(State state) noexcept;
std::filesystem::path package_path(const InstalledApp &app, const std::filesystem::path &root);
std::filesystem::path app_icon_path(const InstalledApp &app, const std::filesystem::path &root);
bool valid_app_id(std::string_view id) noexcept;
std::filesystem::path default_store_root();

// Authoritative append-only registry and final package/data directories. Every
// instance retains exclusive registry access and non-reparse ancestor handles.
// No temporary files, rename-based staging, backups or automatic write retries.
class PackageStore final {
  public:
    enum class Access { read, write, recover, existing_write };
    explicit PackageStore(const std::filesystem::path &root, Access access = Access::read);
    ~PackageStore();
    PackageStore(const PackageStore &) = delete;
    PackageStore &operator=(const PackageStore &) = delete;
    std::vector<InstalledApp> list() const;
    InstalledApp info(std::string_view id) const;
    AppDiagnostics diagnostics(std::string_view id) const;
    UpdatePreview review_update(const InstallPreview &candidate, std::string_view id) const;
    InstalledApp install_fixture(const std::filesystem::path &apk);
    InstalledApp install_package(const std::filesystem::path &apk, std::string_view expected_sha256,
                                 bool fixture_only = false);
    InstalledApp uninstall(std::string_view id, bool keep_data);
    InstalledApp set_permissions(std::string_view id, std::uint32_t allow, std::uint32_t deny,
                                 const std::optional<PermissionReview> &review = {});
    InstalledApp register_windows(std::string_view id);
    // The returned lease survives this short registry session and prevents removal
    // or permission changes until the isolated worker and its host have closed.
    security::InstalledActivity prepare_launch(std::string_view id);
    // Explicit recovery truncates only a short final frame after validating the
    // entire preceding chain, then rolls back incomplete install/removal intents.
    std::size_t recover();
    const std::filesystem::path &root() const noexcept;

  private:
    friend InstalledApp install_windows(const std::filesystem::path &, const std::filesystem::path &,
                                        std::string_view, std::uint32_t);
    friend InstalledApp update_package(const std::filesystem::path &, const std::filesystem::path &,
                                       std::string_view, std::string_view, std::string_view);
    InstalledApp update_bytes(apk::Bytes bytes, const InstallPreview &candidate, std::string_view id,
                              std::string_view expected_current_sha256);
    InstalledApp install_windows_bytes(apk::Bytes bytes, const apk::InspectResult &inspection,
                                       const apk::SignatureReport &signing, std::uint32_t permissions);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::install
