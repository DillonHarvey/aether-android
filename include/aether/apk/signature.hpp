#pragma once
#include "aether/apk/inspect.hpp"

namespace aether::apk {
struct ApkSigner {
    std::string certificate_sha256, public_key_sha256, algorithm;
    std::size_t certificate_count = 0;
    // v3/v3.1 only. These authenticate signing scope, not Android API support.
    std::uint32_t min_sdk = 0, max_sdk = 0;
    std::string scheme;
    std::optional<std::uint32_t> rotation_min_sdk;
    std::vector<std::string> rotation_certificates;
};
struct SignatureReport {
    // A signature proves possession of a key, not a publisher's claimed name,
    // Android compatibility, installation consent or guest execution authority.
    std::string status = "unverified", scheme = "none", message;
    std::vector<ApkSigner> signers;
    bool verified() const noexcept { return status == "verified"; }
    std::string json() const;
    std::string text() const;
};
// Host-side only. Malformed or cryptographically invalid v2/v3 data throws an
// InspectError; unsupported schemes/algorithms never become verified identities.
SignatureReport verify_signature(Bytes apk);
} // namespace aether::apk
