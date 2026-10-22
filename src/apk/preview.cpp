#include "aether/apk/preview.hpp"
#include "aether/apk/archive.hpp"
#include "aether/apk/package.hpp"
#include "aether/common/text.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "preview_container.hpp"
#include <Windows.h>
#include <algorithm>

namespace aether::apk {
namespace {
PackagePreview fallback() {
    PackagePreview result;
    result.presentation.label = "Android package";
    result.presentation.bitmap = fallback_icon();
    result.presentation.renderer_version = 2;
    return result;
}
void failure(PackagePreview &result, const InspectError &error) {
    result.code = error.diagnostic.code;
    result.reason = error.what();
    result.status =
        result.code.find("UNSUPPORTED") != std::string::npos || result.code == "AETHER_ICON_NO_BASE"
            ? IconStatus::unsupported
            : IconStatus::invalid;
    result.presentation.diagnostics.push_back(result.code + ": " + result.reason);
}
} // namespace
std::string_view preview_format_name(PreviewFormat format) {
    switch (format) {
    case PreviewFormat::apk:
        return "apk";
    case PreviewFormat::xapk:
        return "xapk";
    case PreviewFormat::apks:
        return "apks";
    case PreviewFormat::apkm:
        return "apkm";
    case PreviewFormat::aab:
        return "aab";
    default:
        return "unknown";
    }
}
std::string_view icon_status_name(IconStatus status) {
    switch (status) {
    case IconStatus::extracted:
        return "extracted";
    case IconStatus::no_icon:
        return "no-icon";
    case IconStatus::invalid:
        return "invalid";
    case IconStatus::inaccessible:
        return "inaccessible";
    case IconStatus::timed_out:
        return "timed-out";
    default:
        return "unsupported";
    }
}
PackagePreview preview_package(Bytes bytes, const IconRequest &request) {
    auto result = fallback();
    try {
        if (!request.size_px || request.size_px > 256 || request.dpi < 48 || request.dpi > 768)
            throw InspectError("AETHER_ICON_REQUEST_INVALID", "package-preview", "Invalid icon size or DPI");
        InspectLimits limits;
        limits.buffer_bytes = 64 * 1024 * 1024;
        auto archive = std::make_shared<Archive>(bytes, limits, ArchiveNames::case_sensitive);
        result.format = preview_container_format(*archive);
        auto selection = select_preview(archive, bytes, request);
        if (selection.format == PreviewFormat::unknown) {
            result.code = "AETHER_ICON_FORMAT_UNSUPPORTED";
            result.reason = "No recognized APK, XAPK, APKS, APKM or Android publishing-bundle structure.";
            return result;
        }
        if (selection.format == PreviewFormat::aab) {
            result.presentation.bitmap = bundle_fallback_icon();
            result.presentation.label = "Android publishing bundle";
            result.presentation.icon_source = "aether-bundle-fallback";
            result.code = "AETHER_ICON_AAB_UNSUPPORTED";
            result.reason = "AAB is a publishing input. App-specific protobuf artwork preview and direct "
                            "installation are unavailable.";
            return result;
        }
        add_preview_density(selection, *archive);
        const auto &info = selection.manifest;
        result.selected_container = selection.package.parts.front().path;
        result.package_name = info.package_id;
        result.declared_permissions = info.permissions;
        result.version_name = info.version_name;
        if (info.version_code)
            result.version_code =
                (std::uint64_t(info.version_code_major.value_or(0)) << 32) | *info.version_code;
        result.presentation = artwork(selection.package, info, result.selected_container,
                                      {true, request.size_px, request.dpi, 35, true});
        result.presentation.renderer_version = 2;
        result.package_declared = result.presentation.icon_source != "aether-fallback";
        result.status = result.package_declared ? IconStatus::extracted : IconStatus::no_icon;
        if (result.presentation.icon_status == "unsupported")
            result.status = IconStatus::unsupported;
        if (result.presentation.icon_status == "invalid")
            result.status = IconStatus::invalid;
        if (!result.package_declared) {
            result.code = result.presentation.icon_error.empty() ? "AETHER_ICON_NOT_AVAILABLE"
                                                                 : result.presentation.icon_error;
            result.reason = "No supported declared artwork; using the Aether package icon.";
            if (!selection.fallback_artwork.empty()) {
                const auto &entries = archive->entries();
                const auto icon = std::find_if(entries.begin(), entries.end(), [&](const auto &e) {
                    return e.path == selection.fallback_artwork;
                });
                if (icon == entries.end() || icon->directory || icon->bytes > 1024 * 1024)
                    throw InspectError("AETHER_ICON_CONTAINER_LIMIT", "package-preview",
                                       "Container fallback artwork is absent or exceeds 1 MiB");
                result.presentation.bitmap =
                    decode_icon_png(archive->read(static_cast<std::size_t>(icon - entries.begin())), true);
                result.presentation.icon_source = "container-png";
                result.presentation.icon_entry = selection.fallback_artwork;
                result.presentation.icon_status = "extracted";
                result.presentation.icon_error.clear();
                result.status = IconStatus::extracted;
                result.code = "AETHER_ICON_CONTAINER_FALLBACK";
                result.reason =
                    "Validated container PNG fallback; this artwork was not declared by the APK manifest.";
            }
        }
    } catch (const InspectError &error) {
        failure(result, error);
    }
    return result;
}
PreviewFormat package_preview_format(Bytes bytes, const InspectLimits &limits) {
    return preview_container_format(Archive(bytes, limits, ArchiveNames::case_sensitive));
}
PackagePreview preview_package(const std::filesystem::path &path, const IconRequest &request) {
    auto result = fallback();
    result.status = IconStatus::inaccessible;
    result.code = "AETHER_ICON_READ_FAILED";
    result.reason = "Cannot open a stable local regular package file for icon preview.";
    const auto absolute = std::filesystem::absolute(path).lexically_normal();
    const auto name = absolute.native();
    // Remote/device files are not probed by the metadata preview path.
    if (name.size() < 3 || name[1] != L':' || name[2] != L'\\' || name.find(L':', 2) != std::wstring::npos ||
        GetDriveTypeW(absolute.root_path().c_str()) != DRIVE_FIXED)
        return result;
    // Pin every directory without following junctions and without delete sharing.
    // This closes ancestor replacement races until the input mapping is released.
    std::vector<host::UniqueHandle> directories;
    std::vector<std::filesystem::path> parents;
    for (auto parent = absolute.parent_path(); !parent.empty(); parent = parent.parent_path()) {
        parents.push_back(parent);
        if (parent == parent.root_path())
            break;
    }
    for (auto it = parents.rbegin(); it != parents.rend(); ++it) {
        const auto &parent = *it;
        host::UniqueHandle directory(
            CreateFileW(parent.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        BY_HANDLE_FILE_INFORMATION attributes{};
        if (!directory || !GetFileInformationByHandle(directory.get(), &attributes) ||
            !(attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (attributes.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            return result;
        directories.push_back(std::move(directory));
    }
    host::UniqueHandle file(CreateFileW(absolute.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    BY_HANDLE_FILE_INFORMATION info{};
    if (!file || GetFileType(file.get()) != FILE_TYPE_DISK ||
        !GetFileInformationByHandle(file.get(), &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
        return result;
    const auto length = (std::uint64_t(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    if (!length)
        return preview_package(Bytes{}, request);
    host::UniqueHandle mapping(CreateFileMappingW(file.get(), nullptr, PAGE_READONLY, 0, 0, nullptr));
    if (!mapping)
        return result;
    const auto view = MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0);
    if (!view)
        return result;
    struct Unmap {
        const void *view;
        ~Unmap() { UnmapViewOfFile(view); }
    } unmap{view};
    return preview_package(Bytes(static_cast<const std::uint8_t *>(view), static_cast<std::size_t>(length)),
                           request);
}
std::string PackagePreview::json() const {
    return "{\"schemaVersion\":1,\"operation\":\"package-preview\",\"format\":" +
           json_quote(preview_format_name(format)) + ",\"status\":" + json_quote(icon_status_name(status)) +
           ",\"packageName\":" + json_quote(package_name) + ",\"versionName\":" + json_quote(version_name) +
           ",\"versionCode\":" + (version_code ? std::to_string(*version_code) : "null") +
           ",\"selectedContainer\":" + json_quote(selected_container) +
           ",\"iconAvailable\":" + (status == IconStatus::extracted ? "true" : "false") +
           ",\"iconIsPackageDeclared\":" + (package_declared ? "true" : "false") +
           ",\"installationAssessed\":false,\"executionAvailable\":false,\"signatureVerified\":false,"
           "\"code\":" +
           json_quote(code) + ",\"reason\":" + json_quote(reason) +
           ",\"presentation\":" + presentation.json() + "}";
}
} // namespace aether::apk
