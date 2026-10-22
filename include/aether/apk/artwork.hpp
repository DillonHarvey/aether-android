#pragma once
#include "aether/apk/inspect.hpp"

namespace aether::apk {
struct PackageView;
struct ArtworkOptions {
    bool modern = false;
    std::uint32_t size_px = 256, dpi = 96;
    std::uint16_t sdk = 35;
    // Bounded compiled metadata policy, persisted as installed renderer 3.
    // Renderer 1/2 reconstruction and runtime resource admission stay unchanged.
    bool metadata_preview = false;
};
struct IconBitmap {
    std::uint32_t width = 0, height = 0;
    std::vector<std::uint8_t> rgba;
};
struct Artwork {
    std::string label, label_source = "package-fallback";
    std::string icon_source = "aether-fallback", icon_entry;
    std::string icon_status = "no-icon", icon_error;
    std::uint32_t renderer_version = 1;
    IconBitmap bitmap;
    std::vector<std::string> diagnostics;
    std::string json() const;
};

// Pure bounded metadata/bitmap operations; they execute no APK code, extract no
// archive pathname to disk, and grant no installation or runtime authority.
Artwork artwork(Bytes package, const ManifestInfo &manifest);
Artwork artwork(const PackageView &package, const ManifestInfo &manifest,
                std::string_view launcher_container = {}, const ArtworkOptions &options = {});
// Expanded decoding is versioned so existing installed presentation hashes stay
// stable until an explicit installed-artwork migration.
IconBitmap decode_icon_png(Bytes bytes, bool expanded = false);
IconBitmap fallback_icon();
std::vector<std::uint8_t> icon_file(const IconBitmap &bitmap, std::uint32_t renderer_version = 1);
std::string clean_display_name(std::string_view value, std::string_view fallback);
std::string shortcut_stem(std::string_view display_name);
} // namespace aether::apk
