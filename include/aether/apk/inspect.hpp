#pragma once
#include "aether/diagnostics/diagnostic.hpp"
#include <cstddef>
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
// Compact typed integer metadata. References and unknown types stay distinct
// from absence until the consuming execution profile can interpret them.
struct ManifestInteger {
    std::uint16_t type = manifest_absent_type;
    std::uint32_t data = 0;
};
inline constexpr std::size_t manifest_activity_config_bytes = 8;
static_assert(sizeof(ManifestInteger) == manifest_activity_config_bytes);
// Only NativeActivity's two entry keys are retained. Resource attributes remain
// distinct even if their encoded value happens to be a literal string.
struct ManifestNativeValue {
    DisplayValue value{manifest_absent_type, 0, {}};
    bool resource_attribute = false;
};
// Complete ordered raw declarations, not a resolved Android Bundle. Keep both
// value/resource attributes: resource=0 can have different parser semantics
// from a nonzero resource, and duplicate names are resolved only by consumers.
struct ManifestMetaDataEntry {
    DisplayValue name{manifest_absent_type, 0, {}};
    DisplayValue value{manifest_absent_type, 0, {}};
    DisplayValue resource{manifest_absent_type, 0, {}};
};
// Actual retained capacities, capped by the existing manifest metadata bound.
// Returns manifest_activity_bytes + 1 on overflow/excess; no copying occurs.
std::size_t activity_meta_data_storage_size(
    const std::vector<std::vector<ManifestMetaDataEntry>> &) noexcept;
struct ManifestNativeEntry {
    ManifestNativeValue lib_name, func_name;
    // A direct meta-data key without a literal name could resolve to either
    // entry key; NativeActivity cannot prove their absence in that case.
    bool unresolved_name = false;
};
inline constexpr std::size_t manifest_activity_native_bytes = 128;
static_assert(sizeof(ManifestNativeEntry) <= manifest_activity_native_bytes);
// Public Android 15 configChanges flags; recognizing a bit does not implement
// the corresponding device change or Activity recreation behavior.
inline constexpr std::uint32_t manifest_config_changes_mask = 0x5000ffff;
struct Activity {
    std::string name;
    std::string target;
    bool launcher = false, intent_filter = false;
    DisplayValue label, icon;
    ManifestBoolean enabled, exported;
    ManifestInteger screen_orientation;
    ManifestInteger theme;
    DisplayValue permission{manifest_absent_type, 0, {}};
};
// Manifest inventory is independent of the single launcher selected for execution.
// Legacy component/filter records use fixed allowances plus retained strings.
// Raw metadata additionally accounts actual vector/string capacities within
// the same bound. XML input, string-pool and node limits remain separate.
inline constexpr std::size_t manifest_activity_count = 8192;
inline constexpr std::size_t manifest_activity_bytes = 4 * 1024 * 1024;
inline constexpr std::size_t manifest_activity_record_bytes = 256;
static_assert(sizeof(Activity) <= manifest_activity_record_bytes);
// Retain the original filter subtree without treating it as a routing policy.
// Node order and parent indices preserve relative-filter groups and unknown
// extensions. Attribute namespaces and typed resource references stay distinct.
struct ManifestFilterAttribute {
    std::string ns, name;
    DisplayValue value;
};
struct ManifestFilterNode {
    std::string ns, name;
    std::optional<std::size_t> parent;
    std::vector<ManifestFilterAttribute> attributes;
};
struct ManifestIntentFilter {
    std::vector<ManifestFilterNode> nodes;
};
inline constexpr std::size_t manifest_activity_filters_bytes = 32;
inline constexpr std::size_t manifest_filter_record_bytes = 32;
inline constexpr std::size_t manifest_filter_node_bytes = 128;
inline constexpr std::size_t manifest_filter_attribute_bytes = 128;
static_assert(sizeof(std::vector<ManifestIntentFilter>) <= manifest_activity_filters_bytes);
static_assert(sizeof(ManifestIntentFilter) <= manifest_filter_record_bytes);
static_assert(sizeof(ManifestFilterNode) <= manifest_filter_node_bytes);
static_assert(sizeof(ManifestFilterAttribute) <= manifest_filter_attribute_bytes);
struct ManifestInfo {
    std::string package_id;
    // Empty only when android:name is absent; otherwise package-qualified.
    std::string application_name;
    // Empty when no application android:appComponentFactory is declared.
    std::string app_component_factory_name;
    std::string version_name;
    // Preserve actual attribute presence/type independently of legacy display text.
    // A literal beginning with @resource: remains a literal, and empty differs from absent.
    bool version_name_present = false;
    std::optional<std::uint32_t> version_name_resource;
    std::optional<std::uint32_t> version_code;
    std::optional<std::uint32_t> version_code_major;
    std::optional<std::uint32_t> min_sdk;
    std::optional<std::uint32_t> target_sdk;
    ManifestInteger application_theme;
    std::optional<bool> extract_native_libs;
    std::string split;
    std::string config_for_split;
    std::string required_split_types, split_types;
    ManifestBoolean feature_split, isolated_splits, split_required, has_code;
    std::vector<std::string> required_splits;
    std::vector<std::string> permissions;
    std::vector<Activity> activities;
    // Actual signed declarations, not service execution or resolution authority.
    // False preserves unknown/unmodeled names and hand-constructed inventories.
    std::vector<std::string> declared_services;
    bool service_inventory_bound = false;
    DisplayValue label, icon, round_icon;
    ManifestBoolean enabled;
    DisplayValue permission{manifest_absent_type, 0, {}};
    // Parsed manifests retain one compact value per Activity/alias. An empty
    // vector also represents all-absent values in hand-constructed metadata.
    std::vector<ManifestInteger> activity_config_changes;
    // Raw SDK input used with configChanges; aliases remain unbound.
    std::vector<ManifestInteger> activity_recreate_on_config_changes;
    // Aligned with declarations, including aliases. Each selected component
    // owns its metadata; an empty vector means both keys absent everywhere.
    std::vector<ManifestNativeEntry> activity_native_entries;
    // Aligned raw direct Activity/alias metadata declarations. Bound establishes
    // complete raw inventory only, not resolved names/values or alias inheritance.
    std::vector<std::vector<ManifestMetaDataEntry>> activity_meta_data;
    bool activity_meta_data_bound = false;
    // One filter inventory per Activity/alias; alias filters belong to the alias,
    // independently of its executable target. Empty outer storage represents
    // all-empty inventories in hand-constructed metadata, as with configChanges.
    std::vector<std::vector<ManifestIntentFilter>> activity_intent_filters;
    // Application-level raw android:supportsRtl. Absence defaults false only
    // at a consumer with known held-manifest provenance; references/unknown
    // encodings must not silently become a known false ApplicationInfo bit.
    ManifestBoolean supports_rtl;
};
// Fixed record allowances plus retained activity/filter text and actual service
// name capacities. Misaligned
// side metadata and arithmetic/budget overflow return 4 MiB + 1.
// Empty side vectors represent all-absent metadata and receive the same fixed
// per-Activity allowance as parsed/padded inventories. No routing is performed.
std::size_t activity_metadata_size(const ManifestInfo &manifest) noexcept;
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
