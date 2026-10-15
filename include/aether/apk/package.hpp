#pragma once
#include "aether/apk/archive.hpp"
#include "aether/apk/artwork.hpp"
#include "aether/apk/signature.hpp"

namespace aether::apk {
struct PackagePart {
    std::string path;
    Bytes bytes;
    std::shared_ptr<Archive> archive;
};
// Views retain archive metadata, not the backing package bytes. The caller
// keeps the original immutable input alive, including for every member source.
struct PackageView {
    PackageFormat format = PackageFormat::apk;
    std::vector<PackagePart> parts;
    const PackagePart &part(std::string_view container) const;
    struct Member {
        std::shared_ptr<Archive> archive;
        std::size_t index;
    };
    Member file(const PackageFile &identity) const;
    // A logical asset can appear only once across the installed member set.
    // No member order or filename silently selects a conflicting payload.
    Member asset(std::string_view name) const;
};
PackageView open_package(Bytes bytes, const InspectLimits &limits = {});
InspectResult inspect_package(Bytes bytes, const InspectLimits &limits = {},
                              const ArtworkOptions &artwork_options = {});
// Host-only verification of either a standalone APK or every original member
// of a consistent XAPK set. A set has no invented outer APK signature.
SignatureReport verify_package_signature(Bytes bytes, PackageFormat format);
} // namespace aether::apk
