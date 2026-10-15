#pragma once
#include "aether/apk/artwork.hpp"

namespace aether::apk {
// Preview formats are deliberately separate from installed PackageFormat.
// Recognizing artwork never admits a package for installation or execution.
enum class PreviewFormat { unknown, apk, xapk, apks, apkm, aab };
enum class IconStatus { extracted, no_icon, unsupported, invalid, inaccessible, timed_out };
struct IconRequest {
    std::uint32_t size_px = 256;
    std::uint32_t dpi = 96;
};
struct PackagePreview {
    PreviewFormat format = PreviewFormat::unknown;
    IconStatus status = IconStatus::unsupported;
    std::string package_name, version_name, selected_container, code, reason;
    std::optional<std::uint64_t> version_code;
    Artwork presentation;
    bool package_declared = false;
    std::string json() const;
};
// Reads only archive metadata, the selected manifest, resources and artwork.
// This is a parser entry point, never callable from the in-process Shell DLL.
PackagePreview preview_package(Bytes bytes, const IconRequest &request = {});
// Archive-structure recognition only, used to explain preview-only formats in
// existing native installation preflight. It never admits a package to install.
PreviewFormat package_preview_format(Bytes bytes, const InspectLimits &limits = {});
// Maps a stable read-only local file; does not allocate/copy the whole archive.
PackagePreview preview_package(const std::filesystem::path &path, const IconRequest &request = {});
std::string_view preview_format_name(PreviewFormat format);
std::string_view icon_status_name(IconStatus status);
IconBitmap bundle_fallback_icon();
} // namespace aether::apk
