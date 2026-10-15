#pragma once
#include "aether/apk/package.hpp"
#include "aether/apk/preview.hpp"

namespace aether::apk {
struct PreviewSelection {
    PreviewFormat format = PreviewFormat::unknown;
    PackageView package;
    ManifestInfo manifest;
    std::vector<std::vector<std::uint8_t>> buffers;
    std::string fallback_artwork;
    std::string density_member;
    std::string density_identity;
    std::uint64_t expanded_buffers = 0;
    std::uint64_t archive_entries = 0;
};
// Recognition and metadata hints never modify the installed-format adapters.
PreviewSelection select_preview(std::shared_ptr<Archive> archive, Bytes bytes, const IconRequest &request);
PreviewFormat preview_container_format(const Archive &archive);
void validate_preview_member_path(std::string_view path);
void add_preview_density(PreviewSelection &selection, Archive &outer);
IconBitmap bundle_fallback_icon();
} // namespace aether::apk
