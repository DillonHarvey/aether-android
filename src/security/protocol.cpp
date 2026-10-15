#include "aether/security/protocol.hpp"
#include <algorithm>

namespace aether::security {
namespace {
void put(std::span<std::uint8_t> bytes, std::size_t offset, std::uint64_t value, std::size_t count) {
    for (std::size_t i = 0; i < count; ++i)
        bytes[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
}
std::uint64_t get(std::span<const std::uint8_t> bytes, std::size_t offset, std::size_t count) {
    if (offset > bytes.size() || count > bytes.size() - offset)
        throw ProtocolError("AETHER_IPC_TRUNCATED: incomplete integer");
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < count; ++i)
        value |= static_cast<std::uint64_t>(bytes[offset + i]) << (8 * i);
    return value;
}
void validate(const Header &header) {
    if (!header.session || header.payload_size > maximum_payload || header.status > Status::quota)
        throw ProtocolError("AETHER_IPC_HEADER: invalid session, size or status");
}
} // namespace
std::array<std::uint8_t, header_bytes> encode_header(const Header &header) {
    validate(header);
    std::array<std::uint8_t, header_bytes> bytes{};
    put(bytes, 0, protocol_magic, 4);
    put(bytes, 4, protocol_version, 2);
    put(bytes, 6, static_cast<std::uint16_t>(header.operation), 2);
    put(bytes, 8, header.sequence, 8);
    put(bytes, 16, header.payload_size, 4);
    put(bytes, 20, static_cast<std::uint32_t>(header.status), 4);
    put(bytes, 24, header.session, 8);
    return bytes;
}
Header decode_header(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != header_bytes || get(bytes, 0, 4) != protocol_magic ||
        get(bytes, 4, 2) != protocol_version)
        throw ProtocolError("AETHER_IPC_VERSION: invalid header length, magic or version");
    Header header{static_cast<Operation>(get(bytes, 6, 2)), get(bytes, 8, 8), get(bytes, 24, 8),
                  static_cast<std::uint32_t>(get(bytes, 16, 4)), static_cast<Status>(get(bytes, 20, 4))};
    validate(header);
    return header;
}
std::vector<std::uint8_t> encode_frame(const Frame &frame) {
    if (frame.header.payload_size != frame.payload.size())
        throw ProtocolError("AETHER_IPC_SIZE: header and payload disagree");
    const auto header = encode_header(frame.header);
    std::vector<std::uint8_t> bytes(header.begin(), header.end());
    bytes.insert(bytes.end(), frame.payload.begin(), frame.payload.end());
    return bytes;
}
Frame decode_frame(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < header_bytes)
        throw ProtocolError("AETHER_IPC_TRUNCATED: incomplete header");
    const auto header = decode_header(bytes.first(header_bytes));
    if (bytes.size() != header_bytes + header.payload_size)
        throw ProtocolError("AETHER_IPC_SIZE: incomplete payload or trailing bytes");
    return {header, {bytes.begin() + header_bytes, bytes.end()}};
}
void append_u64(std::vector<std::uint8_t> &bytes, std::uint64_t value) {
    if (bytes.size() > maximum_payload - 8)
        throw ProtocolError("AETHER_IPC_SIZE: payload exceeds limit");
    const auto offset = bytes.size();
    bytes.resize(offset + 8);
    put(bytes, offset, value, 8);
}
std::uint64_t read_u64(std::span<const std::uint8_t> bytes, std::size_t offset) {
    return get(bytes, offset, 8);
}
void append_text(std::vector<std::uint8_t> &bytes, std::string_view text) {
    if (bytes.size() > maximum_payload - 8 || text.size() > maximum_payload - 8 - bytes.size())
        throw ProtocolError("AETHER_IPC_SIZE: text exceeds frame limit");
    append_u64(bytes, text.size());
    bytes.insert(bytes.end(), text.begin(), text.end());
}
std::string read_text(std::span<const std::uint8_t> bytes, std::size_t &offset, std::size_t limit) {
    const auto size = read_u64(bytes, offset);
    offset += 8;
    if (size > limit || size > bytes.size() - offset)
        throw ProtocolError("AETHER_IPC_TEXT: text is truncated or oversized");
    std::string result(reinterpret_cast<const char *>(bytes.data() + offset), static_cast<std::size_t>(size));
    offset += static_cast<std::size_t>(size);
    return result;
}
} // namespace aether::security
