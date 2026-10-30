#include "aether/apk/inspect.hpp"
#include "aether/apk/archive.hpp"
#include "aether/apk/artwork.hpp"
#include "aether/apk/launcher.hpp"
#include "aether/apk/signature.hpp"
#include "aether/build_info.hpp"
#include "aether/common/text.hpp"
#include <algorithm>
#include <sstream>

namespace aether::apk {
namespace {
template <class T, class F> std::string array_json(const std::vector<T> &values, F convert) {
    std::string result = "[";
    bool first = true;
    for (const auto &value : values) {
        if (!first)
            result += ',';
        first = false;
        result += convert(value);
    }
    return result + ']';
}
std::string strings_json(const std::vector<std::string> &values) {
    return array_json(values, [](const auto &value) { return json_quote(value); });
}
std::string number(const std::optional<std::uint32_t> &value) {
    return value ? std::to_string(*value) : "null";
}
std::string flag_json(const ManifestBoolean &value) {
    return "{\"type\":" + std::to_string(value.type) + ",\"data\":" + std::to_string(value.data) + '}';
}
std::string filters_json(const std::vector<std::vector<ManifestIntentFilter>> &activities) {
    return array_json(activities, [](const auto &filters) {
        return array_json(filters, [](const ManifestIntentFilter &filter) {
            return "{\"nodes\":" + array_json(filter.nodes, [](const ManifestFilterNode &node) {
                return "{\"namespace\":" + json_quote(node.ns) + ",\"name\":" + json_quote(node.name) +
                       ",\"parent\":" + (node.parent ? std::to_string(*node.parent) : "null") +
                       ",\"attributes\":" + array_json(node.attributes, [](const ManifestFilterAttribute &attribute) {
                           return "{\"namespace\":" + json_quote(attribute.ns) +
                                  ",\"name\":" + json_quote(attribute.name) +
                                  ",\"value\":{\"type\":" + std::to_string(attribute.value.type) +
                                  ",\"data\":" + std::to_string(attribute.value.reference) +
                                  ",\"literal\":" + json_quote(attribute.value.literal) + "}}";
                       }) + '}';
            }) + '}';
        });
    });
}
std::string file_json(const PackageFile &file) {
    return "{\"path\":" + json_quote(file.path) +
           ",\"compressedBytes\":" + std::to_string(file.compressed_bytes) +
           ",\"bytes\":" + std::to_string(file.bytes) + ",\"sha256\":" + json_quote(file.sha256) +
           (file.container.empty() ? "" : ",\"container\":" + json_quote(file.container)) + '}';
}
bool dex_name(const std::string &name) {
    if (name == "classes.dex")
        return true;
    if (!name.starts_with("classes") || !name.ends_with(".dex"))
        return false;
    const auto suffix = name.substr(7, name.size() - 11);
    return !suffix.empty() && suffix.front() >= '1' && suffix.front() <= '9' && suffix != "1" &&
           std::all_of(suffix.begin(), suffix.end(), [](char c) { return c >= '0' && c <= '9'; });
}
} // namespace

InspectResult inspect(Bytes bytes, const InspectLimits &limits, ScanScope scope) {
    Archive archive(bytes, limits, ArchiveNames::case_sensitive);
    InspectResult result;
    result.scope = scope;
    result.archive_bytes = bytes.size();
    result.entry_count = archive.entries().size();
    result.sha256 = sha256(bytes);
    bool have_manifest = false;
    std::size_t dependency_text_bytes = 0;
    for (std::size_t i = 0; i < archive.entries().size(); ++i) {
        const auto &entry = archive.entries()[i];
        result.expanded_bytes += entry.bytes;
        // Every member is fully size/CRC checked. Only consumers that require
        // contiguous bytes materialize a member, within the separate buffer cap.
        if (entry.directory) {
            if (scope == ScanScope::full)
                archive.stream(i, [](auto, Bytes) {});
            continue;
        }
        const auto &name = entry.path;
        auto file = [&](Bytes contents) {
            return PackageFile{name, entry.compressed_bytes, entry.bytes, sha256(contents)};
        };
        if (name == "AndroidManifest.xml") {
            const auto contents = archive.read(i);
            result.manifest = parse_manifest(contents);
            result.manifest_file = file(contents);
            have_manifest = true;
        } else if (dex_name(name)) {
            if (scope != ScanScope::full) {
                DexInfo metadata;
                metadata.file = {name, entry.compressed_bytes, entry.bytes, {}};
                result.dex.push_back(std::move(metadata));
                continue;
            }
            const auto contents = archive.read(i);
            auto metadata = inspect_dex(contents);
            metadata.file = file(contents);
            result.dex.push_back(std::move(metadata));
        } else if (name.starts_with("lib/") && name.ends_with(".so")) {
            const auto slash = name.find('/', 4);
            if (slash == std::string::npos || name.find('/', slash + 1) != std::string::npos)
                throw InspectError("AETHER_APK_UNSUPPORTED", "apk-inspect",
                                   "Unsupported native library directory layout");
            const auto abi = name.substr(4, slash - 4);
            NativeInfo metadata;
            if (scope != ScanScope::full) {
                metadata.file = {name, entry.compressed_bytes, entry.bytes, {}};
                metadata.abi = abi;
                metadata.metadata_status = scope == ScanScope::installation ? "deferred-until-launch"
                                                                          : "deferred-until-requested";
                metadata.is_elf = false;
                result.native.push_back(std::move(metadata));
                continue;
            }
            try {
                metadata = inspect_native_member(archive, i, abi);
            } catch (InspectError &error) {
                error.diagnostic.module = name;
                throw;
            }
            for (const auto &dependency : metadata.dependencies)
                dependency_text_bytes += dependency.size();
            if (dependency_text_bytes > 16 * 1024 * 1024)
                throw InspectError("AETHER_APK_LIMIT", "elf-inspect",
                                   "Total dependency metadata size limit exceeded");
            result.native.push_back(std::move(metadata));
        } else {
            if (scope == ScanScope::full)
                archive.stream(i, [](auto, Bytes) {});
            if (name.starts_with("res/") || name == "resources.arsc")
                result.resources.push_back(name);
            else if (name.starts_with("assets/"))
                result.assets.push_back(name);
        }
    }
    if (!have_manifest)
        throw InspectError("AETHER_APK_MANIFEST_MISSING", "apk-inspect",
                           "Root AndroidManifest.xml is missing; use inspect-xapk for supported XAPK v2 "
                           "sets; APKS is unsupported");
    result.presentation = std::make_shared<Artwork>(artwork(bytes, result.manifest));
    result.limitations = {
        "Inspection only: no Android application code was executed.",
        "An APK SHA-256 is a content fingerprint. Signing-certificate verification is reported separately; "
        "neither authenticates a publisher name.",
        "DEX validation covers headers, hashes, identifier table extents and map metadata; bytecode and "
        "references are not verified.",
        "Inspection reports ELF program headers and DT_NEEDED; isolated launch performs the separate "
        "loader, relocation and symbol validation.",
        "Presentation supports bounded default string/reference labels and RGB/RGBA PNG icons; other "
        "resource configurations and icon formats use an explicit fallback. SDK values are declared "
        "values (null means absent).",
        "Installed execution is experimental: bounded demand-loaded DEX 035/037/038 subset, optional ARM64 "
        "native "
        "libraries and a bounded Android API subset. Inspection does not grant execution authority."};
    if (!result.manifest.split.empty() || !result.manifest.required_splits.empty() ||
        !result.manifest.required_split_types.empty() ||
        result.manifest.split_required.type != manifest_absent_type)
        result.limitations.push_back("Split metadata detected; split installation/merging is unsupported.");
    if (std::any_of(result.native.begin(), result.native.end(),
                    [](const auto &info) { return !info.is_elf; }))
        result.limitations.push_back(
            "Native-directory non-ELF members are opaque data, not executable libraries. Embedded "
            "containers/DEX are not loaded; requesting one as a native library fails ELF validation.");
    if (scope != ScanScope::full)
        result.limitations = {
            scope == ScanScope::installation
                ? "Installation reads manifests and archive directories. DEX/native validation is deferred "
                  "to isolated launch; unused payloads are not decompressed."
                : "Runtime directory inspection defers DEX content validation to the complete class-index "
                  "pass and native content to requested loading; consumed resources retain validation."};
    return result;
}

std::string InspectResult::json(const SignatureReport *signing) const {
    const auto selection = select_launcher(manifest);
    const auto *selected = selection.activity ? &manifest.activities[*selection.activity] : nullptr;
    const auto native_flag =
        manifest.extract_native_libs ? (*manifest.extract_native_libs ? "true" : "false") : "null";
    return "{\"schemaVersion\":1,\"kind\":" +
           json_quote(format == PackageFormat::apk ? "apk-inspection" : "xapk-package-inspection") +
           ",\"scanScope\":" +
           json_quote(scope == ScanScope::full      ? "full"
                      : scope == ScanScope::runtime ? "runtime"
                                                    : "installation") +
           (format == PackageFormat::apk
                ? ""
                : ",\"packageFormat\":\"xapk\",\"members\":" +
                      array_json(members,
                                 [](const PackageMember &member) {
                                     return "{\"path\":" + json_quote(member.path) +
                                            ",\"split\":" + json_quote(member.split) +
                                            ",\"sha256\":" + json_quote(member.sha256) +
                                            ",\"bytes\":" + std::to_string(member.bytes) + '}';
                                 })) +
           ",\"aetherVersion\":" + json_quote(build::version) + ",\"sha256\":" + json_quote(sha256) +
           ",\"archiveBytes\":" + std::to_string(archive_bytes) +
           ",\"expandedBytes\":" + std::to_string(expanded_bytes) +
           ",\"entryCount\":" + std::to_string(entry_count) +
           ",\"executionAvailable\":false,\"signatureVerified\":" +
           (signing && signing->verified() ? "true" : "false") +
           ",\"signing\":" + (signing ? signing->json() : "null") +
           ",\"package\":{\"id\":" + json_quote(manifest.package_id) +
           ",\"applicationName\":" +
           (manifest.application_name.empty() ? "null" : json_quote(manifest.application_name)) +
           ",\"applicationComponentFactory\":" +
           (manifest.app_component_factory_name.empty() ? "null" : json_quote(manifest.app_component_factory_name)) +
           ",\"versionName\":" + json_quote(manifest.version_name) +
           ",\"versionCode\":" + number(manifest.version_code) + ",\"minSdk\":" + number(manifest.min_sdk) +
           ",\"targetSdk\":" + number(manifest.target_sdk) + ",\"extractNativeLibs\":" + native_flag +
           ",\"split\":" + json_quote(manifest.split) +
           ",\"requiredSplits\":" + strings_json(manifest.required_splits) +
           ",\"splitMetadata\":{\"versionCodeMajor\":" + number(manifest.version_code_major) +
           ",\"configForSplit\":" + json_quote(manifest.config_for_split) +
           ",\"requiredSplitTypes\":" + json_quote(manifest.required_split_types) +
           ",\"splitTypes\":" + json_quote(manifest.split_types) +
           ",\"isFeatureSplit\":" + flag_json(manifest.feature_split) +
           ",\"isolatedSplits\":" + flag_json(manifest.isolated_splits) +
           ",\"isSplitRequired\":" + flag_json(manifest.split_required) +
           ",\"hasCode\":" + flag_json(manifest.has_code) + '}' +
           ",\"permissions\":" + strings_json(manifest.permissions) +
           ",\"launcherSelection\":{\"status\":" + json_quote(launcher_status_name(selection.status)) +
           ",\"declaredCount\":" + std::to_string(selection.declared) +
           ",\"eligibleCount\":" + std::to_string(selection.eligible) +
           ",\"component\":" + (selected ? json_quote(selected->name) : "null") + ",\"target\":" +
           (selected ? json_quote(selected->target.empty() ? selected->name : selected->target) : "null") +
           ",\"reason\":" + json_quote(selection.reason) + "},\"activities\":" +
           array_json(manifest.activities,
                      [](const Activity &activity) {
                          return "{\"name\":" + json_quote(activity.name) +
                                 ",\"target\":" + json_quote(activity.target) +
                                 ",\"screenOrientation\":{\"type\":" + std::to_string(activity.screen_orientation.type) +
                                 ",\"data\":" + std::to_string(activity.screen_orientation.data) + '}' +
                                 ",\"launcher\":" + (activity.launcher ? "true" : "false") + '}';
                      }) +
           ",\"activityConfigChanges\":" + array_json(manifest.activity_config_changes,
               [](const ManifestInteger &value) {
                   return "{\"type\":" + std::to_string(value.type) + ",\"data\":" + std::to_string(value.data) + '}';
               }) +
           ",\"activityIntentFilters\":" + filters_json(manifest.activity_intent_filters) +
           "},\"presentation\":" + (presentation ? presentation->json() : "null") +
           ",\"manifest\":" + file_json(manifest_file) + ",\"dex\":" +
           array_json(dex,
                      [](const DexInfo &info) {
                          return "{\"file\":" + file_json(info.file) +
                                 ",\"version\":" + json_quote(info.version) +
                                 ",\"strings\":" + std::to_string(info.strings) +
                                 ",\"methods\":" + std::to_string(info.methods) +
                                 ",\"classes\":" + std::to_string(info.classes) + '}';
                      }) +
           ",\"nativeLibraries\":" +
           array_json(native,
                      [](const NativeInfo &info) {
                          return "{\"file\":" + file_json(info.file) + ",\"abi\":" + json_quote(info.abi) +
                                 ",\"isElf\":" +
                                 (info.metadata_status.starts_with("deferred-") ? "null"
                                  : info.is_elf                                   ? "true"
                                                                                  : "false") +
                                 ",\"initialExecutionTarget\":" +
                                 (info.is_elf && info.abi == "arm64-v8a" ? "true" : "false") +
                                 ",\"executionStatus\":" +
                                 json_quote(info.metadata_status.starts_with("deferred-") ? "not-assessed"
                                            : !info.is_elf                                  ? "not-executable"
                                            : info.abi == "arm64-v8a" ? "experimental-installed-only"
                                                                      : "unsupported-abi") +
                                 ",\"machine\":" + std::to_string(info.machine) +
                                 ",\"metadataStatus\":" + json_quote(info.metadata_status) +
                                 ",\"dependencies\":" + strings_json(info.dependencies) + '}';
                      }) +
           ",\"resources\":" + strings_json(resources) + ",\"assets\":" + strings_json(assets) +
           ",\"limitations\":" + strings_json(limitations) + '}';
}

std::string InspectResult::text(bool verbose, const SignatureReport *signing) const {
    std::ostringstream out;
    out << "Aether APK inspection\nPackage: " << manifest.package_id << "\nVersion: " << manifest.version_name
        << " (code " << number(manifest.version_code) << ")\nDeclared SDK: min " << number(manifest.min_sdk)
        << ", target " << number(manifest.target_sdk) << "\nSHA-256: " << sha256
        << "\nEntries: " << entry_count << ", archive bytes: " << archive_bytes
        << ", expanded bytes: " << expanded_bytes << '\n';
    out << "Application class: "
        << (manifest.application_name.empty() ? "android.app.Application (default)" : manifest.application_name)
        << '\n';
    if (signing)
        out << signing->text();
    if (presentation) {
        out << "Display name: " << presentation->label << " [" << presentation->label_source << "]\n"
            << "Icon: " << presentation->icon_source << " (" << presentation->bitmap.width << 'x'
            << presentation->bitmap.height << ")\n";
        for (const auto &diagnostic : presentation->diagnostics)
            out << "  Artwork: " << diagnostic << '\n';
    }
    const auto selection = select_launcher(manifest);
    out << "Launcher selection: " << launcher_status_name(selection.status) << " (" << selection.eligible
        << " eligible / " << selection.declared << " declared)\n";
    if (selection.activity) {
        const auto &selected = manifest.activities[*selection.activity];
        out << "Selected launcher: " << selected.name
            << "\nActivity class: " << (selected.target.empty() ? selected.name : selected.target) << '\n';
    } else {
        out << "  " << selection.reason << '\n';
    }
    for (const auto &activity : manifest.activities)
        out << (activity.launcher ? "Declared launcher: " : "Activity: ") << activity.name << '\n';
    for (const auto &info : dex)
        out << "DEX: " << info.file.path << " v" << info.version << ", " << info.classes << " classes, "
            << info.methods << " methods\n";
    for (const auto &info : native) {
        out << (info.is_elf ? "Native: " : "Native-directory data: ") << info.file.path << " [" << info.abi
            << (info.is_elf ? "; execution unavailable]\n" : "; non-ELF, not executable]\n");
        for (const auto &dependency : info.dependencies)
            out << "  needs " << dependency << '\n';
    }
    out << "Resources: " << resources.size() << "; assets: " << assets.size()
        << "; declared permissions: " << manifest.permissions.size() << '\n';
    if (verbose)
        for (const auto &permission : manifest.permissions)
            out << "  permission (not granted): " << permission << '\n';
    for (const auto &limitation : limitations)
        out << "  " << limitation << '\n';
    return out.str();
}
} // namespace aether::apk
