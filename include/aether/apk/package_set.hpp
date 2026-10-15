#pragma once
#include "aether/apk/signature.hpp"

namespace aether::apk {
inline constexpr std::size_t xapk_member_count = 128;
inline constexpr std::uint64_t xapk_manifest_bytes = 16 * 1024 * 1024;
inline constexpr std::size_t xapk_metadata_bytes = 8 * 1024 * 1024;
struct XapkMember {
    std::string path, id;
    Bytes bytes;
    ManifestInfo manifest;
};
struct XapkSet {
    // Views borrow the caller's immutable container. No member is extracted,
    // re-signed, copied into a second whole-file buffer or granted execution.
    // Base is first; other members are ordered by their signed split name.
    std::vector<XapkMember> members;
};
// Structural/manifest validation, shared with future held-container consumers.
// This alone does NOT authenticate any member or authorize installation.
XapkSet open_xapk(Bytes bytes, const InspectLimits &limits = {});
struct XapkMemberInspection {
    std::string path, id;
    InspectResult inspection;
    SignatureReport signing;
};
struct XapkInspection {
    std::string sha256;
    std::uint64_t archive_bytes = 0;
    std::vector<std::string> certificates;
    std::vector<XapkMemberInspection> members;
    std::string json() const;
    std::string text(bool verbose) const;
};
// Host only: verify every APK and require the same complete signer identity.
// Full member inspection still does not select device configurations or merge
// resources, install the set, or make its Android APIs executable.
XapkInspection inspect_xapk(Bytes bytes, const InspectLimits &limits = {});
} // namespace aether::apk
