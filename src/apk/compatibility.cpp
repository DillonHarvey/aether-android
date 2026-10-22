#include "aether/apk/compatibility.hpp"
#include "aether/apk/launcher.hpp"
#include "aether/apk/native_inventory.hpp"
#include "aether/common/prefix_strings.hpp"
#include "aether/dex/limits.hpp"
#include "aether/elf/limits.hpp"
#include <algorithm>
#include <charconv>
#include <map>
#include <set>
#include <stdexcept>

namespace aether::apk {
Compatibility execution_compatibility(const InspectResult &package) {
    // Reserve space for the opaque identity, journal framing and Windows fields.
    // A package accepted for writing must also fit every later read/removal frame.
    const auto &manifest = package.manifest;
    bool segment_start = true, separator = false;
    if (manifest.package_id.empty() || manifest.package_id.size() > 223)
        return {false, "Package identity exceeds the supported installation bounds."};
    for (const auto c : manifest.package_id) {
        if (c == '.') {
            if (segment_start)
                return {false, "Package identity contains an empty segment."};
            segment_start = true;
            separator = true;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
                  (!segment_start && c >= '0' && c <= '9')))
                return {false, "Package identity is not supported by the installation registry."};
            segment_start = false;
        }
    }
    if (!separator || segment_start || manifest.version_name.size() > 512)
        return {false, "Installation metadata exceeds the supported package/version/permission bounds."};
    std::size_t metadata_bytes = manifest.package_id.size() + manifest.version_name.size();
    try {
        metadata_bytes += encode_prefix_strings(manifest.permissions).size();
    } catch (const std::invalid_argument &) {
        return {false,
                "Declared permissions exceed 1024 names, 512 bytes per name or 64 KiB decoded metadata."};
    }
    const auto selection = select_launcher(manifest);
    if (!selection.activity)
        return {false, selection.reason};
    const auto &activity = manifest.activities[*selection.activity];
    const auto &launcher_name = activity.target.empty() ? activity.name : activity.target;
    if (launcher_name.empty() || launcher_name.size() > 512)
        return {false, "The launcher Activity exceeds the supported installation bounds."};
    metadata_bytes += launcher_name.size();
    if (metadata_bytes > 2400)
        return {false, "Package metadata exceeds the bounded installation journal capacity."};
    if (package.format == PackageFormat::apk &&
        (!manifest.split.empty() || !manifest.required_splits.empty() ||
         !manifest.required_split_types.empty() || !manifest.config_for_split.empty() ||
         (manifest.split_required.type != manifest_absent_type &&
          (manifest.split_required.type != 0x12 || manifest.split_required.data != 0)) ||
         (manifest.feature_split.type != manifest_absent_type &&
          (manifest.feature_split.type != 0x12 || manifest.feature_split.data != 0))))
        return {false, "Split APK installation is not implemented; select a standalone APK."};
    if (manifest.version_code_major.value_or(0) != 0)
        return {false, "Installation versionCodeMajor is not implemented."};
    if (package.dex.empty() || package.dex.size() > 64)
        return {false, "Execution requires a bounded set of 1 through 64 DEX files."};
    std::map<std::string, std::map<unsigned, std::string>> dex_names;
    std::uint64_t dex_bytes = 0;
    for (const auto &dex : package.dex) {
        if (package.scope == ScanScope::full && dex.version != "035" && dex.version != "037" &&
            dex.version != "038")
            return {false, "The managed runtime supports an instruction subset of DEX 035, 037 and 038."};
        const auto &path = dex.file.path;
        unsigned number = 1;
        if (path != "classes.dex") {
            if (!path.starts_with("classes") || !path.ends_with(".dex") || path.size() <= 11)
                return {false, "DEX members must use canonical classes.dex, classes2.dex, ... names."};
            const auto digits = std::string_view(path).substr(7, path.size() - 11);
            const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), number);
            if (digits.front() == '0' || parsed.ec != std::errc{} ||
                parsed.ptr != digits.data() + digits.size() || number < 2 || number > 64)
                return {false, "DEX member ordinal is outside the canonical 1 through 64 range."};
        }
        if ((package.format == PackageFormat::apk && !dex.file.container.empty()) ||
            (package.format == PackageFormat::xapk &&
             std::none_of(package.members.begin(), package.members.end(),
                          [&](const auto &member) { return member.path == dex.file.container; })))
            return {false, "DEX source has no inspected original APK identity."};
        if (!dex_names[dex.file.container].emplace(number, path).second)
            return {false, "Duplicate DEX member ordinal."};
        if (dex.file.bytes > aether::dex::source_file_bytes)
            return {false, "A DEX member exceeds the current 64 MiB per-file loading bound."};
        if (dex.file.bytes > aether::dex::source_encoded_bytes - dex_bytes)
            return {false, "Aggregate DEX input exceeds the 1 GiB class-source scan budget."};
        dex_bytes += dex.file.bytes;
    }
    std::vector<std::string> ordered_dex;
    for (const auto &[container, files] : dex_names) {
        unsigned expected = 1;
        for (const auto &[number, name] : files) {
            if (number != expected++)
                return {false,
                        "Each APK's DEX files must form a contiguous sequence starting with classes.dex."};
            ordered_dex.push_back(container.empty() ? name : container + "!/" + name);
        }
    }
    try {
        if (package.scope != ScanScope::full)
            (void)NativeDirectory(package.native);
        else
            (void)NativeInventory(package.native);
    } catch (const InspectError &error) {
        return {false, error.what()};
    }
    return {true,
            "Experimental Android compatibility. The package can be installed for isolated launch; "
            "unsupported bytecode, native libraries and Android APIs report a diagnostic. "
            "Installation does not execute the app or grant host access.",
            std::move(ordered_dex)};
}
} // namespace aether::apk
