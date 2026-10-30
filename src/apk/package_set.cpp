#include "aether/apk/package_set.hpp"
#include "aether/apk/archive.hpp"
#include "aether/common/text.hpp"
#include "metadata_json.hpp"
#include <algorithm>
#include <charconv>
#include <map>
#include <set>

namespace aether::apk {
namespace {
[[noreturn]] void bad(std::string message) {
    throw InspectError("AETHER_XAPK_INVALID", "xapk", std::move(message));
}
[[noreturn]] void unsupported(std::string message) {
    throw InspectError("AETHER_XAPK_UNSUPPORTED", "xapk", std::move(message));
}
[[noreturn]] void limit(std::string message) {
    throw InspectError("AETHER_XAPK_LIMIT", "xapk", std::move(message));
}
using metadata::Json;
using metadata::JsonReader;
bool flag(const ManifestBoolean &value, bool fallback) {
    if (value.type == manifest_absent_type)
        return fallback;
    if (value.type != 0x12)
        unsupported("Split composition flags must be literal booleans");
    return value.data != 0;
}
void name(std::string_view value) {
    bool start = true;
    if (value.empty() || value.size() > 255)
        bad("Split name/type must contain 1 through 255 bytes");
    for (const auto c : value) {
        if (c == '.') {
            if (start)
                bad("Split name/type contains an empty segment");
            start = true;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
                  (!start && c >= '0' && c <= '9')))
                bad("Split name/type is outside the supported identifier grammar");
            start = false;
        }
    }
    if (start)
        bad("Split name/type ends with a separator");
}
std::set<std::string> types(std::string_view value) {
    std::set<std::string> result;
    if (value.empty())
        return result;
    for (;;) {
        const auto comma = value.find(',');
        auto part = value.substr(0, comma);
        const auto blank = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
        while (!part.empty() && blank(part.front()))
            part.remove_prefix(1);
        while (!part.empty() && blank(part.back()))
            part.remove_suffix(1);
        name(part);
        if (!result.emplace(part).second)
            bad("Duplicate split type declaration");
        if (result.size() > 128)
            limit("Split type list exceeds 128 names");
        if (comma == std::string_view::npos)
            return result;
        value.remove_prefix(comma + 1);
    }
}
std::size_t metadata_size(const ManifestInfo &m) {
    std::size_t size = 256 + m.package_id.size() + m.version_name.size() + m.split.size() +
                       m.application_name.size() + m.app_component_factory_name.size() + m.config_for_split.size() + m.required_split_types.size() + m.split_types.size() +
                       m.label.literal.size() + m.icon.literal.size() + m.round_icon.literal.size() +
                       m.permission.literal.size();
    for (const auto &s : m.required_splits)
        size += 32 + s.size();
    for (const auto &s : m.permissions)
        size += 32 + s.size();
    const auto activity_bytes = activity_metadata_size(m);
    if (activity_bytes > manifest_activity_bytes)
        limit("XAPK member Activity/filter metadata is misaligned or exceeds 4 MiB");
    size += activity_bytes;
    return size;
}
} // namespace

XapkSet open_xapk(Bytes bytes, const InspectLimits &limits) try {
    Archive outer(bytes, limits, ArchiveNames::case_sensitive);
    std::map<std::string, std::size_t> entries;
    for (std::size_t i = 0; i < outer.entries().size(); ++i) {
        const auto &entry = outer.entries()[i];
        if (entry.path == "toc.pb")
            unsupported("APKS is a separate format; its device selection is not XAPK v2");
        if (entry.directory || entry.path.find('/') != std::string::npos)
            unsupported("XAPK v2 currently requires top-level APK/index/icon members; OBB is unsupported");
        entries.emplace(entry.path, i);
    }
    const auto index_entry = entries.find("manifest.json");
    if (index_entry == entries.end())
        bad("XAPK v2 requires a root manifest.json index");
    if (outer.entries()[index_entry->second].bytes > 1024 * 1024)
        limit("XAPK JSON index exceeds 1 MiB");
    const auto index_bytes = outer.read(index_entry->second);
    const auto index = JsonReader(index_bytes).read();
    if (index.get("xapk_version").integer() != 2)
        unsupported("Only XAPK index version 2 is supported");
    const auto package = index.get("package_name").string();
    const auto version = index.get("version_code").integer(true);
    if (const auto found = index.object.find("expansions"); found != index.object.end()) {
        if (found->second.kind != Json::Kind::array || !found->second.array.empty())
            unsupported("XAPK expansion/OBB delivery is not implemented");
    }
    const auto &listed = index.get("split_apks");
    if (listed.kind != Json::Kind::array || listed.array.empty())
        bad("XAPK split_apks must be a nonempty array");
    if (listed.array.size() > xapk_member_count)
        limit("XAPK contains more than 128 APK members");
    XapkSet result;
    std::set<std::string> paths, ids;
    std::uint64_t manifests = 0;
    std::size_t metadata = 0, total_entries = outer.entries().size();
    for (const auto &item : listed.array) {
        const auto path = item.get("file").string();
        const auto id = item.get("id").string();
        name(id);
        if (!paths.insert(path).second || !ids.insert(id).second)
            bad("XAPK index repeats an APK file or split identity");
        const auto entry = entries.find(path);
        if (!path.ends_with(".apk") || entry == entries.end())
            bad("XAPK index names an absent or non-APK member");
        if (!outer.entries()[entry->second].stored)
            unsupported("XAPK APK members must use ZIP_STORED for immutable borrowed access");
        const auto member = outer.stored_view(entry->second);
        auto member_limits = limits;
        member_limits.entry_count = static_cast<std::uint32_t>(limits.entry_count - total_entries);
        Archive apk(member, member_limits, ArchiveNames::case_sensitive);
        total_entries += apk.entries().size();
        const auto manifest = std::find_if(apk.entries().begin(), apk.entries().end(),
                                           [](const auto &e) { return e.path == "AndroidManifest.xml"; });
        if (manifest == apk.entries().end())
            bad("XAPK APK member has no root AndroidManifest.xml: " + path);
        if (manifest->bytes > xapk_manifest_bytes - manifests)
            limit("XAPK manifest inputs exceed 16 MiB in aggregate");
        manifests += manifest->bytes;
        auto parsed = parse_manifest(apk.read(static_cast<std::size_t>(manifest - apk.entries().begin())));
        const auto charge = metadata_size(parsed);
        if (charge > xapk_metadata_bytes - metadata)
            limit("XAPK retained manifest metadata exceeds 8 MiB");
        metadata += charge;
        if (parsed.package_id != package || !parsed.version_code || *parsed.version_code != version)
            bad("XAPK index/package/version differs from signed manifest: " + path);
        if (parsed.version_code_major.value_or(0) != 0)
            unsupported("XAPK index versionCodeMajor is not implemented");
        if ((id == "base" && !parsed.split.empty()) || (id != "base" && parsed.split != id))
            bad("XAPK index split identity differs from signed manifest: " + path);
        if (!parsed.split.empty())
            name(parsed.split);
        // Even currently unused flags are retained and must be unambiguous.
        (void)flag(parsed.isolated_splits, false);
        (void)flag(parsed.split_required, false);
        (void)flag(parsed.has_code, true);
        (void)flag(parsed.feature_split, false);
        result.members.push_back({path, id, member, std::move(parsed)});
    }
    if (!ids.contains("base"))
        bad("XAPK must contain exactly one signed base APK");
    for (const auto &[path, entry] : entries) {
        if (paths.contains(path) || path == "manifest.json")
            continue;
        if (path != "icon.png")
            unsupported("Unindexed XAPK payload is unsupported: " + path);
        outer.stream(entry, [](auto, Bytes) {});
    }
    if (const auto found = index.object.find("split_configs"); found != index.object.end()) {
        if (found->second.kind != Json::Kind::array)
            bad("XAPK split_configs must be an array");
        std::set<std::string> configured;
        for (const auto &config : found->second.array)
            if (!configured.insert(config.string()).second)
                bad("XAPK split_configs repeats a split identity");
        auto expected = ids;
        expected.erase("base");
        if (configured != expected)
            bad("XAPK split_configs differs from the complete indexed split set");
    }
    std::sort(result.members.begin(), result.members.end(),
              [](const auto &a, const auto &b) { return a.manifest.split < b.manifest.split; });
    std::map<std::string, std::size_t> named;
    std::map<std::string, std::set<std::string>> supplied;
    std::vector<std::vector<std::size_t>> dependencies(result.members.size());
    for (std::size_t i = 0; i < result.members.size(); ++i)
        named.emplace(result.members[i].manifest.split, i);
    for (std::size_t i = 0; i < result.members.size(); ++i) {
        const auto &m = result.members[i].manifest;
        const auto feature = flag(m.feature_split, false);
        if (m.split.empty() && (feature || !m.config_for_split.empty()))
            bad("Base APK cannot be a feature or configuration split");
        if (feature && !m.config_for_split.empty())
            bad("Feature split cannot also configure another split");
        if (!m.config_for_split.empty()) {
            name(m.config_for_split);
            const auto target = named.find(m.config_for_split);
            if (target == named.end() || !flag(result.members[target->second].manifest.feature_split, false))
                bad("Configuration split refers to an absent or non-feature split");
            dependencies[i].push_back(target->second);
        }
        std::set<std::string> requested;
        for (const auto &required : m.required_splits) {
            name(required);
            const auto target = named.find(required);
            if (!requested.insert(required).second || target == named.end() ||
                !flag(result.members[target->second].manifest.feature_split, false))
                bad("uses-split repeats or refers to an absent/non-feature dependency");
            dependencies[i].push_back(target->second);
        }
        const auto owner = feature ? m.split : m.config_for_split;
        for (const auto &type : types(m.split_types))
            supplied[owner].insert(type);
        if (flag(m.split_required, false) && result.members.size() == 1)
            bad("Manifest requires split APKs but only the base is present");
    }
    for (const auto &member : result.members) {
        const auto &m = member.manifest;
        const auto owner = flag(m.feature_split, false) ? m.split : m.config_for_split;
        for (const auto &type : types(m.required_split_types))
            if (!supplied[owner].contains(type))
                bad("Required split type is missing for " + member.id + ": " + type);
    }
    std::vector<unsigned> state(result.members.size());
    const auto visit = [&](const auto &self, std::size_t node) -> void {
        if (state[node] == 1)
            bad("Cyclic split dependency graph");
        if (state[node] == 2)
            return;
        state[node] = 1;
        for (const auto dependency : dependencies[node])
            self(self, dependency);
        state[node] = 2;
    };
    for (std::size_t i = 0; i < result.members.size(); ++i)
        visit(visit, i);
    return result;
} catch (const metadata::JsonError &error) {
    if (error.limited)
        limit(error.what());
    bad(error.what());
}

} // namespace aether::apk
