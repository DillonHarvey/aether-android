#include "preview_container.hpp"
#include "metadata_json.hpp"
#include "preview_toc.hpp"
#include <algorithm>
#include <charconv>
#include <map>
#include <set>

namespace aether::apk {
namespace {
[[noreturn]] void bad(std::string message, std::string_view kind = "INVALID") {
    throw InspectError(kind == "NO_BASE" ? "AETHER_ICON_NO_BASE"
                                         : "AETHER_ICON_CONTAINER_" + std::string(kind),
                       "package-preview", std::move(message));
}
std::optional<std::size_t> entry(const Archive &archive, std::string_view path) {
    const auto &entries = archive.entries();
    const auto found =
        std::find_if(entries.begin(), entries.end(), [&](const auto &e) { return e.path == path; });
    if (found == entries.end() || found->directory)
        return {};
    return static_cast<std::size_t>(found - entries.begin());
}
void path_check(std::string_view path) {
    if (path.empty() || path.size() > 511 || path.find_first_of("\\:\0", 0, 3) != std::string_view::npos)
        bad("Container metadata has an invalid member path");
    for (std::size_t at = 0; at < path.size();) {
        const auto end = path.find('/', at);
        const auto part = path.substr(at, end == path.npos ? path.size() - at : end - at);
        if (part.empty() || part == "." || part == ".." || part.back() == '.' || part.back() == ' ')
            bad("Container metadata has an ambiguous or traversing member path");
        if (end == path.npos)
            return;
        at = end + 1;
    }
    bad("Container metadata names a directory");
}
std::vector<std::uint8_t> bounded(Archive &archive, std::string_view path, std::size_t maximum) {
    const auto index = entry(archive, path);
    if (!index)
        bad("Required container member is absent: " + std::string(path));
    if (archive.entries()[*index].bytes > maximum)
        bad("Container metadata byte limit exceeded", "LIMIT");
    return archive.read(*index);
}
metadata::Json json(Archive &archive, std::string_view path) {
    try {
        const auto result = metadata::JsonReader(bounded(archive, path, 1024 * 1024)).read();
        if (result.kind != metadata::Json::Kind::object)
            bad("Container metadata must be a JSON object");
        return result;
    } catch (const metadata::JsonError &error) {
        bad(error.what(), error.limited ? "LIMIT" : "INVALID");
    }
}
ManifestInfo manifest(const PackagePart &part) {
    const auto bytes = bounded(*part.archive, "AndroidManifest.xml", 8 * 1024 * 1024);
    return parse_manifest(bytes);
}
PackagePart nested(PreviewSelection &selection, Archive &outer, const std::string &path) {
    path_check(path);
    if (!path.ends_with(".apk"))
        bad("Selected base/density member is not an APK path");
    const auto index = entry(outer, path);
    if (!index)
        bad("Selected APK is absent: " + path);
    const auto &e = outer.entries()[*index];
    Bytes bytes;
    if (e.stored)
        bytes = outer.stored_preview_extent(*index);
    else {
        if (e.bytes > 64 * 1024 * 1024 - selection.expanded_buffers)
            bad("Selected compressed APKs exceed the 64 MiB in-memory preview budget; stored nested APKs are "
                "seekable without this allocation",
                "LIMIT");
        selection.expanded_buffers += e.bytes;
        selection.buffers.push_back(outer.read(*index));
        bytes = selection.buffers.back();
    }
    InspectLimits limits;
    limits.buffer_bytes = 64 * 1024 * 1024;
    auto archive = std::make_shared<Archive>(bytes, limits, ArchiveNames::case_sensitive);
    selection.archive_entries += archive->entries().size();
    if (selection.archive_entries > 65534)
        bad("Combined preview ZIP metadata exceeds 65,534 entries", "LIMIT");
    return {path, bytes, std::move(archive)};
}
unsigned density(std::string_view name) {
    const std::map<std::string_view, unsigned> known{{"ldpi", 120},   {"mdpi", 160},  {"tvdpi", 213},
                                                     {"hdpi", 240},   {"xhdpi", 320}, {"xxhdpi", 480},
                                                     {"xxxhdpi", 640}};
    if (const auto found = known.find(name); found != known.end())
        return found->second;
    if (!name.ends_with("dpi"))
        return 0;
    name.remove_suffix(3);
    unsigned value = 0;
    const auto parsed = std::from_chars(name.data(), name.data() + name.size(), value);
    return parsed.ec == std::errc{} && parsed.ptr == name.data() + name.size() && value >= 72 && value <= 1280
               ? value
               : 0;
}
void density_choice(PreviewSelection &out, const std::vector<std::pair<std::string, std::string>> &files,
                    const IconRequest &request) {
    const auto target = std::max(request.size_px * 160 / 48, request.dpi * 160 / 96);
    std::pair<unsigned, unsigned> best{3, 0};
    for (const auto &[path, identity] : files) {
        std::string_view qualifier = identity;
        if (!qualifier.starts_with("config."))
            continue;
        qualifier.remove_prefix(7);
        const auto d = density(qualifier);
        if (!d)
            continue;
        const auto rank = d >= target ? std::pair{0u, d - target} : std::pair{1u, target - d};
        if (rank < best) {
            best = rank;
            out.density_member = path;
            out.density_identity = identity;
        } else if (rank == best)
            bad("Ambiguous density APK metadata");
    }
}
std::vector<std::pair<std::string, std::string>> conventional_densities(const Archive &outer,
                                                                        const std::string &base) {
    std::vector<std::pair<std::string, std::string>> result;
    const auto slash = base.rfind('/');
    const auto directory = slash == base.npos ? std::string{} : base.substr(0, slash + 1);
    for (const auto &e : outer.entries()) {
        if (e.directory || !e.path.ends_with(".apk") || !e.path.starts_with(directory))
            continue;
        auto name = std::string_view(e.path).substr(directory.size());
        name.remove_suffix(4);
        if (name.starts_with("split_config."))
            name.remove_prefix(13);
        else if (name.starts_with("config."))
            name.remove_prefix(7);
        else if (name.starts_with("base-"))
            name.remove_prefix(5);
        else
            continue;
        if (density(name))
            result.emplace_back(e.path, "config." + std::string(name));
    }
    return result;
}
std::uint64_t version(const ManifestInfo &m) {
    return std::uint64_t(m.version_code_major.value_or(0)) << 32 | m.version_code.value_or(0);
}
} // namespace
void validate_preview_member_path(std::string_view path) { path_check(path); }
PreviewFormat preview_container_format(const Archive &archive) {
    if (entry(archive, "AndroidManifest.xml"))
        return PreviewFormat::apk;
    if (entry(archive, "BundleConfig.pb") && entry(archive, "base/manifest/AndroidManifest.xml"))
        return PreviewFormat::aab;
    if (entry(archive, "manifest.json"))
        return PreviewFormat::xapk;
    if (entry(archive, "info.json"))
        return PreviewFormat::apkm;
    if (entry(archive, "toc.pb") || entry(archive, "meta.sai_v1.json") || entry(archive, "meta.sai_v2.json"))
        return PreviewFormat::apks;
    for (const auto &e : archive.entries())
        if (!e.directory && e.path.ends_with(".apk"))
            return PreviewFormat::apks;
    return PreviewFormat::unknown;
}
PreviewSelection select_preview(std::shared_ptr<Archive> archive, Bytes bytes,
                                const IconRequest &request) try {
    PreviewSelection result;
    result.format = preview_container_format(*archive);
    result.archive_entries = archive->entries().size();
    if (result.format == PreviewFormat::apk) {
        result.package.parts.push_back({{}, bytes, std::move(archive)});
        result.manifest = manifest(result.package.parts.front());
    } else if (result.format == PreviewFormat::aab || result.format == PreviewFormat::unknown)
        return result;
    else {
        const bool xapk = entry(*archive, "manifest.json").has_value(),
                   apkm = entry(*archive, "info.json").has_value();
        const bool sai = entry(*archive, "meta.sai_v1.json") || entry(*archive, "meta.sai_v2.json");
        const bool toc = entry(*archive, "toc.pb").has_value();
        if (unsigned(xapk) + unsigned(apkm) + unsigned(sai) + unsigned(toc) > 1)
            bad("Conflicting package-container format markers");
        std::string base, expected_package;
        std::optional<std::uint64_t> expected_version;
        std::vector<std::pair<std::string, std::string>> files;
        if (xapk) {
            const auto index = json(*archive, "manifest.json");
            const auto format = index.get("xapk_version").integer(true);
            if (format != 1 && format != 2)
                bad("Only XAPK metadata versions 1 and 2 are recognized", "UNSUPPORTED");
            expected_package = index.get("package_name").string();
            if (const auto v = index.find("version_code"))
                expected_version = v->wide_integer(true);
            if (const auto listed = index.find("split_apks")) {
                if (listed->kind != metadata::Json::Kind::array || listed->array.empty() ||
                    listed->array.size() > 128)
                    bad("XAPK index must list 1 through 128 APKs", "LIMIT");
                std::set<std::string> paths, ids;
                for (const auto &item : listed->array) {
                    auto path = item.get("file").string(), id = item.get("id").string();
                    path_check(path);
                    if (!path.ends_with(".apk") || !entry(*archive, path) || !paths.insert(path).second ||
                        !ids.insert(id).second)
                        bad("XAPK index contains absent, repeated or invalid APK metadata");
                    if (id == "base")
                        base = path;
                    files.emplace_back(std::move(path), std::move(id));
                }
                if (base.empty())
                    bad("XAPK index has no base APK", "NO_BASE");
                for (const auto &e : archive->entries())
                    if (!e.directory && e.path.ends_with(".apk") && !paths.contains(e.path))
                        bad("XAPK contains an unindexed ambiguous APK");
            }
            if (const auto icon = index.find("icon")) {
                result.fallback_artwork = icon->string();
                path_check(result.fallback_artwork);
                // Optional container artwork must not prevent reading the
                // manifest-declared icon. Never guess another archive image.
                if (!result.fallback_artwork.ends_with(".png") || !entry(*archive, result.fallback_artwork))
                    result.fallback_artwork.clear();
            }
            if (const auto expansions = index.find("expansions")) {
                if (expansions->kind != metadata::Json::Kind::array)
                    bad("XAPK expansions must be an array");
                for (const auto &expansion : expansions->array) {
                    path_check(expansion.get("file").string());
                    if (const auto path = expansion.find("install_path"))
                        path_check(path->string());
                }
            }
        } else if (apkm) {
            const auto index = json(*archive, "info.json");
            if (index.get("apkm_version").integer() != 5)
                bad("Only the unencrypted ZIP APKM v5 layout is recognized; use a current APKMirror export",
                    "UNSUPPORTED");
            expected_package = index.get("pname").string();
            expected_version = index.get("versioncode").wide_integer(true);
            base = "base.apk";
        } else if (sai) {
            for (const auto *path : {"meta.sai_v1.json", "meta.sai_v2.json"}) {
                if (!entry(*archive, path))
                    continue;
                const auto index = json(*archive, path);
                const auto package = index.get("package").string();
                const auto code = index.get("version_code").wide_integer();
                if ((!expected_package.empty() && expected_package != package) ||
                    (expected_version && *expected_version != code))
                    bad("SAI v1/v2 package metadata disagrees");
                if (std::string_view(path) == "meta.sai_v2.json" && index.get("meta_version").integer() != 2)
                    bad("Unrecognized SAI metadata version", "UNSUPPORTED");
                expected_package = package;
                expected_version = code;
            }
        } else if (toc) {
            const auto index = preview_toc(bounded(*archive, "toc.pb", 1024 * 1024));
            expected_package = index.package;
            base = index.base;
        }
        if ((xapk || apkm || sai) && expected_package.empty())
            bad("Container package identity is empty");
        if (base.empty()) {
            if (!xapk && entry(*archive, "base.apk"))
                base = "base.apk";
            else {
                for (const auto &e : archive->entries())
                    if (!e.directory && e.path.ends_with(".apk")) {
                        if (!base.empty())
                            bad("No indexed or conventional unique base APK", "NO_BASE");
                        base = e.path;
                    }
            }
        }
        if (base.empty())
            bad("Container has no application APK", "NO_BASE");
        result.package.parts.push_back(nested(result, *archive, base));
        result.manifest = manifest(result.package.parts.front());
        if ((!expected_package.empty() && expected_package != result.manifest.package_id) ||
            (expected_version &&
             (!result.manifest.version_code || *expected_version != version(result.manifest))))
            bad("Container package/version differs from the selected APK manifest");
        if (files.empty())
            files = conventional_densities(*archive, base);
        density_choice(result, files, request);
        if (result.fallback_artwork.empty() && entry(*archive, "icon.png"))
            result.fallback_artwork = "icon.png";
    }
    if (!result.manifest.split.empty() || !result.manifest.config_for_split.empty() ||
        (result.manifest.feature_split.type == 0x12 && result.manifest.feature_split.data))
        bad("Selected APK is a split, not an application base", "NO_BASE");
    return result;
} catch (const metadata::JsonError &error) {
    bad(error.what(), error.limited ? "LIMIT" : "INVALID");
}
void add_preview_density(PreviewSelection &selection, Archive &outer) {
    if (selection.density_member.empty() || selection.package.parts.size() != 1)
        return;
    auto part = nested(selection, outer, selection.density_member);
    const auto info = manifest(part);
    if (info.package_id != selection.manifest.package_id ||
        info.version_code != selection.manifest.version_code ||
        info.version_code_major != selection.manifest.version_code_major ||
        info.split != selection.density_identity ||
        (!info.config_for_split.empty() && info.config_for_split != "base") ||
        (info.feature_split.type != manifest_absent_type &&
         (info.feature_split.type != 0x12 || info.feature_split.data)))
        bad("Selected density APK does not match the base package/version/configuration identity");
    selection.package.parts.push_back(std::move(part));
}
IconBitmap bundle_fallback_icon() {
    auto icon = fallback_icon();
    for (std::size_t i = 0; i < icon.rgba.size(); i += 4)
        std::swap(icon.rgba[i], icon.rgba[i + 2]);
    // Original stacked-package badge makes publishing bundles distinct even
    // when displayed without color. It is not an application-specific icon.
    for (unsigned y = 174; y < 214; ++y)
        for (unsigned x = 148; x < 216; ++x) {
            const auto at = (std::size_t(y) * 256 + x) * 4;
            const bool border = x < 154 || x >= 210 || (y - 174) % 16 < 5;
            icon.rgba[at] = border ? 240 : 74;
            icon.rgba[at + 1] = border ? 242 : 45;
            icon.rgba[at + 2] = border ? 250 : 128;
            icon.rgba[at + 3] = 255;
        }
    return icon;
}
} // namespace aether::apk
