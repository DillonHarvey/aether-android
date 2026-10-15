#include "aether/apk/signature.hpp"
#include "aether/common/text.hpp"

namespace aether::apk {
std::string SignatureReport::json() const {
    std::string out = "{\"status\":" + json_quote(status) + ",\"scheme\":" + json_quote(scheme) +
                      ",\"verified\":" + (verified() ? "true" : "false") +
                      ",\"publisherAuthenticated\":false,\"message\":" + json_quote(message) +
                      ",\"signers\":[";
    for (const auto &signer : signers) {
        if (out.back() != '[')
            out += ',';
        out += "{\"certificateSha256\":" + json_quote(signer.certificate_sha256) +
               ",\"publicKeySha256\":" + json_quote(signer.public_key_sha256) +
               ",\"algorithm\":" + json_quote(signer.algorithm) +
               ",\"certificateCount\":" + std::to_string(signer.certificate_count);
        if (scheme == "v3.1")
            out += ",\"scheme\":" + json_quote(signer.scheme);
        if (signer.rotation_min_sdk)
            out += ",\"rotationMinSdk\":" + std::to_string(*signer.rotation_min_sdk);
        if (scheme == "v3" || scheme == "v3.1") {
            out += ",\"minSdk\":" + std::to_string(signer.min_sdk) +
                   ",\"maxSdk\":" + std::to_string(signer.max_sdk) + ",\"rotationCertificatesSha256\":[";
            for (const auto &certificate : signer.rotation_certificates) {
                if (out.back() != '[')
                    out += ',';
                out += json_quote(certificate);
            }
            out += ']';
        }
        out += '}';
    }
    return out + "]}";
}
std::string SignatureReport::text() const {
    std::string out = "APK signing: " + status + " (" + scheme + "). " + message + '\n';
    for (const auto &signer : signers)
        out += "Signing certificate SHA-256: " + signer.certificate_sha256 + " [" + signer.algorithm + "]\n";
    return out;
}
} // namespace aether::apk
