#include "aether/apk/package.hpp"
#include "aether/apk/artwork.hpp"
#include "aether/apk/launcher.hpp"
#include "aether/apk/package_set.hpp"
#include <algorithm>
#include <map>
#include <set>

namespace aether::apk {
namespace {
void presentation_limits(InspectResult &result, const ArtworkOptions &options) {
    if (!options.modern)
        return;
    for (auto &limitation : result.limitations)
        if (limitation.starts_with("Presentation supports "))
            limitation =
                "Presentation uses bounded PNG, static WebP, static vector and adaptive icon rendering; "
                "unsupported resources use an explicit fallback. SDK values are declared values "
                "(null means absent).";
}
[[noreturn]] void bad(std::string message) {
    throw InspectError("AETHER_PACKAGE_COMPOSITION_UNSUPPORTED", "package-composition", std::move(message));
}
void append_manifest(ManifestInfo &base, const ManifestInfo &split) {
    if (split.isolated_splits.type != manifest_absent_type && split.isolated_splits.data)
        bad("Isolated split class loaders are not implemented");
    const bool feature = split.feature_split.type == 0x12 && split.feature_split.data;
    if (!feature && (!split.activities.empty() || !split.permissions.empty()))
        bad("Configuration splits cannot add Activity or permission declarations");
    if (split.enabled.type != manifest_absent_type || split.permission.type != manifest_absent_type ||
        split.label.type || split.icon.type)
        bad("Split application-wide flag, permission or presentation overrides are not implemented");
    base.activities.insert(base.activities.end(), split.activities.begin(), split.activities.end());
    for (const auto &permission : split.permissions)
        if (std::find(base.permissions.begin(), base.permissions.end(), permission) == base.permissions.end())
            base.permissions.push_back(permission);
    std::size_t metadata = 0;
    for (const auto &a : base.activities)
        metadata += manifest_activity_record_bytes + a.name.size() + a.target.size() +
                    a.label.literal.size() + a.icon.literal.size() + a.permission.literal.size();
    if (base.activities.size() > manifest_activity_count || metadata > manifest_activity_bytes ||
        base.permissions.size() > 1024)
        bad("Combined split declarations exceed the existing package-wide manifest bounds");
}
} // namespace
const PackagePart &PackageView::part(std::string_view container) const {
    const auto found =
        std::find_if(parts.begin(), parts.end(), [&](const auto &p) { return p.path == container; });
    if (found == parts.end())
        bad("An inspected member's original APK container is absent");
    return *found;
}
PackageView::Member PackageView::file(const PackageFile &identity) const {
    const auto archive = part(identity.container).archive;
    const auto &entries = archive->entries();
    const auto found = std::find_if(entries.begin(), entries.end(),
                                    [&](const auto &entry) { return entry.path == identity.path; });
    if (found == entries.end() || found->directory || found->bytes != identity.bytes ||
        found->compressed_bytes != identity.compressed_bytes)
        bad("An inspected member is absent or differs from its original APK entry");
    return {archive, static_cast<std::size_t>(found - entries.begin())};
}
PackageView::Member PackageView::asset(std::string_view name) const {
    if (name.empty() || name.size() > 504 || name.front() == '/' || name.back() == '/' ||
        name.find('\\') != std::string_view::npos || name.find(':') != std::string_view::npos)
        bad("Asset name must be a bounded relative archive path");
    for (std::size_t at = 0; at < name.size();) {
        const auto end = name.find('/', at);
        const auto component = name.substr(at, end == std::string_view::npos ? name.size() - at : end - at);
        if (component.empty() || component == "." || component == "..")
            bad("Asset name contains an ambiguous path component");
        at = end == std::string_view::npos ? name.size() : end + 1;
    }
    const auto path = "assets/" + std::string(name);
    std::optional<Member> selected;
    for (const auto &part : parts) {
        const auto &entries = part.archive->entries();
        for (std::size_t i = 0; i < entries.size(); ++i) {
            if (entries[i].path != path || entries[i].directory)
                continue;
            if (selected)
                bad("Asset path is ambiguous across APK members: " + path);
            selected = {part.archive, i};
        }
    }
    if (!selected)
        throw InspectError("AETHER_PACKAGE_ASSET_NOT_FOUND", "package-asset", "Asset is absent: " + path);
    return *selected;
}
PackageView open_package(Bytes bytes, const InspectLimits &limits) {
    auto archive = std::make_shared<Archive>(bytes, limits, ArchiveNames::case_sensitive);
    const auto contains = [&](std::string_view name) {
        return std::any_of(archive->entries().begin(), archive->entries().end(),
                           [&](const auto &entry) { return entry.path == name; });
    };
    const bool xapk = !contains("AndroidManifest.xml") && contains("manifest.json");
    if (!xapk)
        return {PackageFormat::apk, {{"", bytes, std::move(archive)}}};
    const auto set = open_xapk(bytes, limits);
    PackageView result;
    result.format = PackageFormat::xapk;
    for (const auto &member : set.members)
        result.parts.push_back(
            {member.path, member.bytes,
             std::make_shared<Archive>(member.bytes, limits, ArchiveNames::case_sensitive)});
    return result;
}
InspectResult inspect_package(Bytes bytes, const InspectLimits &limits, const ArtworkOptions &options) {
    const auto package = open_package(bytes, limits);
    if (package.format == PackageFormat::apk) {
        auto result = inspect(bytes, limits);
        if (options.modern)
            result.presentation = std::make_shared<Artwork>(artwork(package, result.manifest, {}, options));
        presentation_limits(result, options);
        return result;
    }
    InspectResult result;
    result.format = PackageFormat::xapk;
    result.sha256 = sha256(bytes);
    result.archive_bytes = bytes.size();
    std::set<std::string> assets;
    std::map<std::string, std::string> activity_containers;
    std::size_t dependency_bytes = 0;
    for (const auto &part : package.parts) {
        auto bounded = limits;
        bounded.total_bytes -= result.expanded_bytes;
        auto report = inspect(part.bytes, bounded);
        for (const auto &activity : report.manifest.activities)
            if (!activity_containers.emplace(activity.name, part.path).second)
                bad("Activity identity is repeated across APK members: " + activity.name);
        if (report.manifest.has_code.type == 0x12 && !report.manifest.has_code.data && !report.dex.empty())
            bad("A split declares hasCode=false but contains DEX");
        if (!report.manifest.split.empty() &&
            !(report.manifest.feature_split.type == 0x12 && report.manifest.feature_split.data) &&
            !report.dex.empty())
            bad("DEX code requires a base or feature APK, not a configuration split");
        if (report.manifest.split.empty()) {
            if (report.manifest.isolated_splits.type != manifest_absent_type &&
                report.manifest.isolated_splits.data)
                bad("Isolated split class loaders are not implemented");
            result.manifest = report.manifest;
            result.manifest_file = report.manifest_file;
            result.manifest_file.container = part.path;
            result.presentation = report.presentation;
            result.limitations = report.limitations;
        } else {
            append_manifest(result.manifest, report.manifest);
        }
        result.members.push_back({part.path, report.manifest.split, report.sha256, report.archive_bytes});
        result.entry_count += report.entry_count;
        result.expanded_bytes += report.expanded_bytes;
        for (auto &dex : report.dex) {
            dex.file.container = part.path;
            result.dex.push_back(std::move(dex));
        }
        for (auto &native : report.native) {
            for (const auto &dependency : native.dependencies)
                dependency_bytes += dependency.size();
            if (dependency_bytes > 16 * 1024 * 1024)
                bad("Combined native dependency metadata exceeds 16 MiB");
            native.file.container = part.path;
            result.native.push_back(std::move(native));
        }
        for (const auto &resource : report.resources)
            result.resources.push_back(part.path + "!/" + resource);
        for (const auto &asset : report.assets) {
            if (!assets.insert(asset).second)
                bad("Asset path is ambiguous across APK members: " + asset);
            result.assets.push_back(part.path + "!/" + asset);
        }
    }
    result.limitations.erase(
        std::remove(result.limitations.begin(), result.limitations.end(),
                    "Split metadata detected; split installation/merging is unsupported."),
        result.limitations.end());
    result.limitations.push_back(
        "Original indexed APK members share one immutable container. DEX/native/asset sources retain their "
        "original member identities; resource and Android API support remain bounded, not universal.");
    const auto launcher = select_launcher(result.manifest);
    const auto origin = launcher.activity
                            ? activity_containers.at(result.manifest.activities[*launcher.activity].name)
                            : package.parts.front().path;
    result.presentation = std::make_shared<Artwork>(artwork(package, result.manifest, origin, options));
    presentation_limits(result, options);
    return result;
}
} // namespace aether::apk
