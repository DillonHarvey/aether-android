#pragma once
#include "aether/host/file_service.hpp"
#include <algorithm>

namespace aether::host {
inline constexpr std::size_t document_stream_limit = 16;
inline constexpr std::size_t document_drop_limit = 16;
inline constexpr std::uint64_t document_size_limit = private_file_size_limit;
inline constexpr std::string_view document_uri_prefix = "content://aether.documents/";
struct DocumentInfo {
    std::string uri, mime_type, display_name;
    std::uint64_t size = 0;
    bool operator==(const DocumentInfo &) const = default;
};
inline bool valid_document_uri(std::string_view uri) noexcept {
    if (!uri.starts_with(document_uri_prefix)) return false;
    uri.remove_prefix(document_uri_prefix.size());
    return uri.size() == 32 && std::all_of(uri.begin(), uri.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
inline bool valid_document_mime(std::string_view mime) noexcept {
    const auto slash = mime.find('/');
    if (mime.empty() || mime.size() > 255 || slash == 0 || slash == mime.npos || slash + 1 == mime.size()) return false;
    return std::all_of(mime.begin(), mime.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '/' ||
               c == '!' || c == '#' || c == '$' || c == '&' || c == '^' || c == '_' || c == '.' || c == '+' || c == '-';
    }) && mime.find('/', slash + 1) == mime.npos;
}
inline bool valid_document_name(std::string_view name) noexcept {
    if (name.empty() || name.size() > 255 || name == "." || name == ".." ||
        name.find_first_of("/\\") != name.npos) return false;
    for (std::size_t at = 0; at < name.size();) {
        const auto first = static_cast<unsigned char>(name[at++]);
        if (first < 0x80) { if (first < 32 || first == 127) return false; continue; }
        unsigned extra = 0, code = 0, minimum = 0;
        if (first >= 0xc2 && first <= 0xdf) { extra = 1; code = first & 31; minimum = 0x80; }
        else if (first >= 0xe0 && first <= 0xef) { extra = 2; code = first & 15; minimum = 0x800; }
        else if (first >= 0xf0 && first <= 0xf4) { extra = 3; code = first & 7; minimum = 0x10000; }
        else return false;
        if (extra > name.size() - at) return false;
        while (extra--) {
            const auto next = static_cast<unsigned char>(name[at++]);
            if ((next & 0xc0) != 0x80) return false;
            code = (code << 6) | (next & 63);
        }
        if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff) ||
            (code >= 0x80 && code <= 0x9f)) return false;
    }
    return true;
}
inline bool valid_document_info(const DocumentInfo &value) noexcept {
    return valid_document_uri(value.uri) && valid_document_mime(value.mime_type) &&
           value.size <= document_size_limit && valid_document_name(value.display_name);
}
// Separate read-only authority. A URI or the private-files permission cannot
// create it. The trusted host supplies exactly one already approved selection.
// No Windows path/handle crosses this interface or the worker protocol.
class DocumentService {
  public:
    virtual ~DocumentService() = default;
    virtual FileResult describe(std::string_view uri, DocumentInfo &output) noexcept = 0;
    virtual FileResult open_document(std::string_view uri) noexcept = 0;
    virtual FileResult read_document(int descriptor, std::span<std::uint8_t> output) noexcept = 0;
    virtual FileResult close_document(int descriptor) noexcept = 0;
    // Only an already staged external drop can be claimed. These operations
    // never create a source or expand an ordinary startup document grant.
    virtual FileResult claim_drop(std::string_view, std::uint64_t) noexcept {
        return {-1, FileError::unsupported};
    }
    virtual FileResult release_drop(std::string_view, std::uint64_t) noexcept {
        return {-1, FileError::unsupported};
    }
    virtual void revoke_documents() noexcept = 0;
};
} // namespace aether::host
