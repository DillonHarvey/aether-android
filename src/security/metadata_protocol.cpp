#include "aether/common/text.hpp"
#include "aether/security/metadata_process.hpp"
#include <algorithm>

namespace aether::security {
namespace {
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(std::string("AETHER_ICON_IPC: ") + message);
}
std::string bounded(std::string_view value, std::size_t limit) {
    auto end = std::min(value.size(), limit);
    if (end < value.size())
        while (end && (static_cast<unsigned char>(value[end]) & 0xc0) == 0x80)
            --end;
    return std::string(value.substr(0, end));
}
} // namespace
std::vector<std::uint8_t> encode_icon_description(const apk::PackagePreview &preview) {
    std::vector<std::uint8_t> bytes;
    for (const auto value :
         {std::uint64_t(2), static_cast<std::uint64_t>(preview.format),
          static_cast<std::uint64_t>(preview.status), std::uint64_t(preview.presentation.bitmap.width),
          std::uint64_t(preview.presentation.bitmap.height), std::uint64_t(preview.package_declared),
          std::uint64_t(preview.version_code.has_value()), preview.version_code.value_or(0)})
        append_u64(bytes, value);
    const auto add = [&](std::string_view text, std::size_t limit) {
        append_text(bytes, bounded(text, limit));
    };
    add(preview.package_name, 256);
    add(preview.version_name, 128);
    add(preview.selected_container, 512);
    add(preview.code, 128);
    add(preview.reason, 512);
    add(preview.presentation.label, 256);
    add(preview.presentation.label_source, 64);
    add(preview.presentation.icon_source, 64);
    add(preview.presentation.icon_entry, 512);
    add(preview.presentation.icon_status, 32);
    add(preview.presentation.icon_error, 128);
    const auto count = std::min(std::size_t(4), preview.presentation.diagnostics.size());
    append_u64(bytes, count);
    for (std::size_t i = 0; i < count; ++i)
        add(preview.presentation.diagnostics[i], 256);
    return bytes;
}
apk::PackagePreview decode_icon_description(std::span<const std::uint8_t> bytes) {
    require(bytes.size() >= 64 && read_u64(bytes, 0) == 2 && read_u64(bytes, 8) <= 5 &&
                read_u64(bytes, 16) <= 5 && read_u64(bytes, 24) && read_u64(bytes, 24) <= 512 &&
                read_u64(bytes, 32) && read_u64(bytes, 32) <= 512 && read_u64(bytes, 40) <= 1 &&
                read_u64(bytes, 48) <= 1,
            "Invalid metadata description");
    apk::PackagePreview result;
    result.format = static_cast<apk::PreviewFormat>(read_u64(bytes, 8));
    result.status = static_cast<apk::IconStatus>(read_u64(bytes, 16));
    result.presentation.bitmap.width = static_cast<std::uint32_t>(read_u64(bytes, 24));
    result.presentation.bitmap.height = static_cast<std::uint32_t>(read_u64(bytes, 32));
    result.presentation.renderer_version = 2;
    result.package_declared = read_u64(bytes, 40) != 0;
    if (read_u64(bytes, 48))
        result.version_code = read_u64(bytes, 56);
    else
        require(read_u64(bytes, 56) == 0, "Unflagged version code");
    std::size_t offset = 64;
    const auto text = [&](std::size_t limit) {
        auto value = read_text(bytes, offset, limit);
        require(value.find('\0') == value.npos, "Embedded null in metadata");
        (void)utf16(value); // Reject invalid UTF-8 before presentation/JSON.
        return value;
    };
    result.package_name = text(256);
    result.version_name = text(128);
    result.selected_container = text(512);
    result.code = text(128);
    result.reason = text(512);
    result.presentation.label = text(256);
    result.presentation.label_source = text(64);
    result.presentation.icon_source = text(64);
    result.presentation.icon_entry = text(512);
    result.presentation.icon_status = text(32);
    result.presentation.icon_error = text(128);
    const auto count = read_u64(bytes, offset);
    offset += 8;
    require(count <= 4, "Too many metadata diagnostics");
    for (std::uint64_t i = 0; i < count; ++i)
        result.presentation.diagnostics.push_back(text(256));
    require(offset == bytes.size(), "Trailing metadata bytes");
    return result;
}
} // namespace aether::security
