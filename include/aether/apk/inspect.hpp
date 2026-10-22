#pragma once
#include "aether/diagnostics/diagnostic.hpp"
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace aether::apk {
using Bytes = std::span<const std::uint8_t>;
class InspectError : public std::runtime_error {
  public:
    DiagnosticEvent diagnostic;
    InspectError(std::string code, std::string phase, std::string message)
        : std::runtime_error(message),
          diagnostic{
              std::move(code),
              std::move(phase),
              std::move(message),
              "Use a supported, intact APK; see docs/APK_INSPECTION.md for limits and unsupported formats.",
              {},
              {},
              {}} {}
};
struct InspectLimits {
    // No product-level APK/aggregate size ceiling. Explicit callers may impose one.
    std::uint64_t archive_bytes = UINT64_MAX;
    // Streaming supports the non-ZIP64 range without an expanded-member allocation.
    std::uint64_t entry_bytes = 0xfffffffeULL;
    std::uint64_t total_bytes = UINT64_MAX;
    std::uint32_t entry_count = 65534; // Full non-ZIP64 entry range.
    std::uint32_t central_bytes = 16 * 1024 * 1024;
    std::uint32_t ratio = 200;
    // Aggregate retained bytes per read/read_ranges call, independent of stream length.
    std::uint64_t buffer_bytes = 64ULL * 1024 * 1024;
};
// Optional presentation metadata is kept typed. Unsupported forms never become
// executable text, a filesystem path, or an invented publisher identity.
struct DisplayValue {
    std::uint16_t type = 0;
    std::uint32_t reference = 0;
    std::string literal;
};
// Absence is outside the encoded byte range, so no supplied attribute type can
// impersonate a missing value and acquire its defaults.
inline constexpr std::uint16_t manifest_absent_type = 0x100;
struct ManifestBoolean {
    std::uint16_t type = manifest_absent_type;
    std::uint32_t data = 0;
};
struct Activity {
    std::string name;
    std::string target;
    bool launcher = false;
    DisplayValue label, icon;
    ManifestBoolean enabled, exported;
    DisplayValue permission{manifest_absent_type, 0, {}};
    bool intent_filter = false;
};
// Manifest inventory is independent of the single launcher selected for execution.
// Charge a fixed record allowance plus all retained UTF-8 strings, consistently
// across Debug/Release. XML input, string-pool and node limits remain separate.
inline constexpr std::size_t manifest_activity_count = 8192;
inline constexpr std::size_t manifest_activity_bytes = 4 * 1024 * 1024;
inline constexpr std::size_t manifest_activity_record_bytes = 256;
static_assert(sizeof(Activity) <= manifest_activity_record_bytes);
struct ManifestInfo {
    std::string package_id;
    // Empty only when android:name is absent; otherwise package-qualified.
    std::string application_name;
    // Empty when no application android:appComponentFactory is declared.
    std::string app_component_factory_name;
    std::string version_name;
    std::optional<std::uint32_t> version_code;
    std::optional<std::uint32_t> version_code_major;
    std::optional<std::uint32_t> min_sdk;
    std::optional<std::uint32_t> target_sdk;
    std::optional<bool> extract_native_libs;
    std::string split;
    std::string config_for_split;
    std::string required_split_types, split_types;
    ManifestBoolean feature_split, isolated_splits, split_required, has_code;
    std::vector<std::string> required_splits;
    std::vector<std::string> permissions;
    std::vector<Activity> activities;
    DisplayValue label, icon, round_icon;
    ManifestBoolean enabled;
    DisplayValue permission{manifest_absent_type, 0, {}};
};
struct PackageFile {
    std::string path;
    std::uint64_t compressed_bytes = 0;
    std::uint64_t bytes = 0;
    std::string sha256;
    // Empty for a standalone APK; otherwise the original APK member path in
    // the held container. Never concatenated into a host filesystem pathname.
    std::string container;
};
struct DexInfo {
    PackageFile file;
    std::string version;
    std::uint32_t strings = 0;
    std::uint32_t methods = 0;
    std::uint32_t classes = 0;
};
struct NativeInfo {
    PackageFile file;
    std::string abi;
    std::uint16_t machine = 0;
    std::vector<std::string> dependencies;
    std::string metadata_status;
    // APK native-directory members may contain data. Only ELF candidates are
    // parsed as ELF; a suffix or ABI directory never confers execution authority.
    bool is_elf = true;
};
struct Artwork;
struct SignatureReport;
enum class PackageFormat : std::uint32_t { apk, xapk };
struct PackageMember {
    std::string path, split, sha256;
    std::uint64_t bytes = 0;
};
// Installation reads manifests/directory; runtime indexes DEX and validates requested native code.
// Diagnostic inspection alone checks every archive member. No scope bypasses ZIP structure checks.
enum class ScanScope { full, runtime, installation };
struct InspectResult {
    ScanScope scope = ScanScope::full;
    PackageFormat format = PackageFormat::apk;
    std::vector<PackageMember> members;
    std::string sha256;
    std::uint64_t archive_bytes = 0;
    std::uint64_t expanded_bytes = 0;
    std::size_t entry_count = 0;
    ManifestInfo manifest;
    std::shared_ptr<const Artwork> presentation;
    PackageFile manifest_file;
    std::vector<DexInfo> dex;
    std::vector<NativeInfo> native;
    std::vector<std::string> resources;
    std::vector<std::string> assets;
    std::vector<std::string> limitations;
    std::string json(const SignatureReport *signing = nullptr) const;
    std::string text(bool verbose, const SignatureReport *signing = nullptr) const;
};
ManifestInfo parse_manifest(Bytes bytes);
DexInfo inspect_dex(Bytes bytes);
NativeInfo inspect_elf(Bytes bytes, std::string abi);
InspectResult inspect(Bytes bytes, const InspectLimits &limits = {}, ScanScope scope = ScanScope::full);
std::vector<std::uint8_t> read_package(const std::filesystem::path &path, const InspectLimits &limits = {});
std::string sha256(Bytes bytes);
std::string sha1(Bytes bytes); // DEX format checksum only, never package authentication.
} // namespace aether::apk
