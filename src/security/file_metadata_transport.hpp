#pragma once
#include "aether/security/protocol.hpp"
#include "aether/host/file_service.hpp"
#include <bit>

namespace aether::security::file_metadata_transport {
// Request: version/kind/base/directory-required/text-length, then bounded UTF-8.
// Success: ordinary FileResult16 + version8 + directory8 + metadata11*8 =120.
inline constexpr std::size_t success_bytes = 120, metadata_bytes = success_bytes - 16;
struct Request {
    std::uint64_t kind = 0, base = 0;
    bool directory_required = false;
    std::string name;
};
inline Request decode_request(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 40 || read_u64(bytes, 0) != 1 || read_u64(bytes, 8) > 1 || read_u64(bytes, 24) > 1)
        throw ProtocolError("AETHER_IPC_PATH_METADATA: invalid request version or fields");
    Request result{read_u64(bytes, 8), read_u64(bytes, 16), read_u64(bytes, 24) != 0, {}};
    std::size_t offset = 32;
    result.name = read_text(bytes, offset, host::private_path_limit);
    if (offset != bytes.size() || (result.kind == 0 ?
            (result.base > 3 || !host::valid_file_access(static_cast<host::FileAccessScope>(result.base), result.name, 0)) :
            !host::valid_file_path(result.name, true)))
        throw ProtocolError("AETHER_IPC_PATH_METADATA: unsafe or inconsistent request path");
    return result;
}
inline std::vector<std::uint8_t> encode_request(std::uint64_t kind, std::uint64_t base,
                                               bool required, std::string_view name) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(40 + name.size());
    append_u64(bytes, 1); append_u64(bytes, kind); append_u64(bytes, base); append_u64(bytes, required ? 1 : 0);
    append_text(bytes, name);
    return bytes;
}
inline void append_metadata(std::vector<std::uint8_t> &bytes, const host::FilePathMetadata &value) {
    if (!host::valid_file_path_metadata(value))
        throw ProtocolError("AETHER_IPC_PATH_METADATA: invalid provider metadata");
    const auto &file = value.file;
    append_u64(bytes, 1); append_u64(bytes, value.directory ? 1 : 0);
    append_u64(bytes, file.size); append_u64(bytes, file.identity); append_u64(bytes, file.allocated_bytes);
    append_u64(bytes, file.readonly ? 1 : 0);
    append_u64(bytes, std::bit_cast<std::uint64_t>(file.access_seconds)); append_u64(bytes, file.access_nanoseconds);
    append_u64(bytes, std::bit_cast<std::uint64_t>(file.modified_seconds)); append_u64(bytes, file.modified_nanoseconds);
    append_u64(bytes, std::bit_cast<std::uint64_t>(file.changed_seconds)); append_u64(bytes, file.changed_nanoseconds);
    append_u64(bytes, file.links);
}
inline host::FilePathMetadata decode_metadata(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != success_bytes || read_u64(bytes, 16) != 1 || read_u64(bytes, 24) > 1 ||
        read_u64(bytes, 56) > 1 || read_u64(bytes, 72) >= 1'000'000'000 ||
        read_u64(bytes, 88) >= 1'000'000'000 || read_u64(bytes, 104) >= 1'000'000'000 ||
        read_u64(bytes, 112) > UINT32_MAX)
        throw ProtocolError("AETHER_IPC_PATH_METADATA: invalid metadata reply fields");
    host::FilePathMetadata value;
    value.directory = read_u64(bytes, 24) != 0;
    auto &file = value.file;
    file.size = read_u64(bytes, 32); file.identity = read_u64(bytes, 40); file.allocated_bytes = read_u64(bytes, 48);
    file.readonly = read_u64(bytes, 56) != 0;
    file.access_seconds = std::bit_cast<std::int64_t>(read_u64(bytes, 64));
    file.access_nanoseconds = static_cast<std::uint32_t>(read_u64(bytes, 72));
    file.modified_seconds = std::bit_cast<std::int64_t>(read_u64(bytes, 80));
    file.modified_nanoseconds = static_cast<std::uint32_t>(read_u64(bytes, 88));
    file.changed_seconds = std::bit_cast<std::int64_t>(read_u64(bytes, 96));
    file.changed_nanoseconds = static_cast<std::uint32_t>(read_u64(bytes, 104));
    file.links = static_cast<std::uint32_t>(read_u64(bytes, 112));
    if (!host::valid_file_path_metadata(value))
        throw ProtocolError("AETHER_IPC_PATH_METADATA: invalid metadata bounds");
    return value;
}
} // namespace aether::security::file_metadata_transport
