#pragma once
#include "aether/install/store.hpp"

namespace aether::install {
enum class LinkRegistrationOperation { status, register_handler, repair, remove, check_upgrade };
struct FileAssociation {
    std::string extension, mime_type;
    bool operator==(const FileAssociation &) const = default;
};
struct LinkRegistration {
    std::string state = "not-registered";
    bool verified = false, notified = false;
    std::vector<std::string> schemes;
    std::vector<FileAssociation> files;
    std::string json() const;
};
// Caller retains its authoritative PackageStore snapshot before this function
// takes the shared Shell mutex. No guest consent or Windows default is granted.
// Removal uses the journal's launcher binding; when that binding is empty,
// only the currently executing owning runtime may remove its recorded offer.
LinkRegistration link_registration(LinkRegistrationOperation operation, const InstalledApp &app,
                                   const std::filesystem::path &store,
                                   const std::vector<std::string> &schemes = {}, bool notify = true,
                                   const std::vector<FileAssociation> &files = {});
// Read-only bounded dependency inspection. Unknown ownership blocks removal.
bool link_registration_present(const std::filesystem::path &runtime);
} // namespace aether::install
