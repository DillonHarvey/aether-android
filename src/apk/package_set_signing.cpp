#include "aether/apk/package.hpp"
#include "aether/apk/package_set.hpp"
#include "aether/common/text.hpp"
#include <algorithm>

namespace aether::apk {
SignatureReport verify_package_signature(Bytes bytes, PackageFormat format) {
    if (format == PackageFormat::apk)
        return verify_signature(bytes);
    const auto set = open_xapk(bytes);
    SignatureReport result;
    std::vector<std::string> expected;
    for (const auto &member : set.members) {
        SignatureReport signing;
        try {
            signing = verify_signature(member.bytes);
        } catch (InspectError &error) {
            error.diagnostic.module = member.path;
            throw;
        }
        if (!signing.verified())
            throw InspectError("AETHER_XAPK_SIGNATURE_UNSUPPORTED", "package-signing",
                               "Every original XAPK member needs supported verified signing: " + member.path);
        std::vector<std::string> certificates;
        for (const auto &signer : signing.signers)
            certificates.push_back(signer.certificate_sha256);
        std::sort(certificates.begin(), certificates.end());
        if (expected.empty()) {
            expected = certificates;
            result = std::move(signing);
        } else if (expected != certificates) {
            throw InspectError("AETHER_XAPK_SIGNATURE_MISMATCH", "package-signing",
                               "Original APK members have different complete certificate sets: " +
                                   member.path);
        }
    }
    if (expected.empty() || std::adjacent_find(expected.begin(), expected.end()) != expected.end())
        throw InspectError("AETHER_XAPK_SIGNATURE_MISMATCH", "package-signing",
                           "XAPK members require a nonempty distinct certificate set");
    result.scheme = "apk-set";
    result.message = "Every original APK member independently verifies with this complete certificate set. "
                     "Signer details describe the base APK; there is no outer APK signature or publisher "
                     "authentication. The original container checksum binds the installation decision.";
    return result;
}
XapkInspection inspect_xapk(Bytes bytes, const InspectLimits &limits) {
    const auto set = open_xapk(bytes, limits);
    XapkInspection result;
    result.sha256 = sha256(bytes);
    result.archive_bytes = bytes.size();
    // Authenticate all complete member identities before publishing any success
    // report. A v3.1 member contributes both certificates, never just its tip.
    std::vector<SignatureReport> signatures;
    for (const auto &member : set.members) {
        auto signing = verify_signature(member.bytes);
        if (!signing.verified())
            throw InspectError("AETHER_XAPK_SIGNATURE_UNSUPPORTED", member.path,
                               "Every XAPK APK member requires a supported verified signature: " +
                                   signing.message);
        std::vector<std::string> certificates;
        for (const auto &signer : signing.signers)
            certificates.push_back(signer.certificate_sha256);
        std::sort(certificates.begin(), certificates.end());
        if (certificates.empty() ||
            std::adjacent_find(certificates.begin(), certificates.end()) != certificates.end())
            throw InspectError("AETHER_XAPK_SIGNATURE_MISMATCH", member.path,
                               "XAPK member has an empty or repeated signer identity");
        if (result.certificates.empty())
            result.certificates = certificates;
        else if (result.certificates != certificates)
            throw InspectError("AETHER_XAPK_SIGNATURE_MISMATCH", member.path,
                               "XAPK members do not share the same complete certificate set");
        signatures.push_back(std::move(signing));
    }
    std::uint64_t expanded = 0;
    std::size_t dependency_bytes = 0;
    for (std::size_t i = 0; i < set.members.size(); ++i) {
        const auto &member = set.members[i];
        auto member_limits = limits;
        member_limits.total_bytes -= expanded;
        auto inspection = inspect(member.bytes, member_limits);
        expanded += inspection.expanded_bytes;
        if (member.manifest.has_code.type == 0x12 && member.manifest.has_code.data == 0 &&
            !inspection.dex.empty())
            throw InspectError("AETHER_XAPK_INVALID", member.path,
                               "APK declares hasCode=false but contains DEX code");
        for (const auto &library : inspection.native) {
            for (const auto &dependency : library.dependencies)
                dependency_bytes += dependency.size();
        }
        if (dependency_bytes > 16 * 1024 * 1024)
            throw InspectError("AETHER_XAPK_LIMIT", "xapk",
                               "Aggregate native dependency metadata exceeds 16 MiB");
        result.members.push_back({member.path, member.id, std::move(inspection), std::move(signatures[i])});
    }
    return result;
}
std::string XapkInspection::json() const {
    std::string result = "{\"schemaVersion\":1,\"kind\":\"xapk-inspection\",\"xapkVersion\":2,"
                         "\"sha256\":" +
                         json_quote(sha256) + ",\"archiveBytes\":" + std::to_string(archive_bytes) +
                         ",\"setVerified\":true,\"publisherAuthenticated\":false,"
                         "\"installationAvailable\":false,\"executionAvailable\":false,"
                         "\"certificatesSha256\":[";
    for (const auto &certificate : certificates) {
        if (certificate != certificates.front())
            result += ',';
        result += json_quote(certificate);
    }
    result += "],\"members\":[";
    for (std::size_t i = 0; i < members.size(); ++i) {
        if (i != 0)
            result += ',';
        const auto &member = members[i];
        result += "{\"path\":" + json_quote(member.path) + ",\"id\":" + json_quote(member.id) +
                  ",\"inspection\":" + member.inspection.json(&member.signing) + '}';
    }
    return result + "],\"limitations\":["
                    "\"Read-only verification of the complete indexed APK set; no installation or execution "
                    "consent.\","
                    "\"Only XAPK v2 with stored top-level APK members is supported; APKS and OBB are "
                    "separate unsupported formats.\","
                    "\"Signed identities, versions, split names/types and dependencies agree; device "
                    "configuration selection and resource/asset/DEX composition are not implemented.\","
                    "\"Vendor labels, icons and permission lists are untrusted metadata and confer no "
                    "identity or capability.\"]}";
}
std::string XapkInspection::text(bool verbose) const {
    std::string result = "Verified XAPK v2 APK set (inspection only)\nSHA-256: " + sha256 +
                         "\nAPK members: " + std::to_string(members.size()) +
                         "\nInstallation/execution: unavailable; split composition is not implemented.\n";
    for (const auto &member : members) {
        result += "\n" + member.id + ": " + member.path + "\n";
        result += member.inspection.text(verbose, &member.signing);
    }
    return result;
}
} // namespace aether::apk
