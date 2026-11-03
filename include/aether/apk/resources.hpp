#pragma once
#include "aether/apk/inspect.hpp"
#include <functional>
#include <map>
#include <set>

namespace aether::apk {
struct PackageView;
enum class ResourceNamePolicy {
    // Frozen presentation renderers retain their recorded fallback/ICO bytes.
    legacy,
    compiled,
    // Runtime-only compiled tables, including fixed feature package IDs and
    // optimized symbolic names. Numeric identities remain authoritative.
    optimized,
};
struct ResourceParseOptions {
    ResourceNamePolicy names = ResourceNamePolicy::legacy;
    bool retain_bags = false;
    bool metadata_preview = false;
};
struct ResourceValue {
    std::uint32_t data = 0;
    std::uint8_t type = 0;
};
enum class StyleAttributeStatus { found, absent, unresolved };
struct StyleAttributeResult {
    StyleAttributeStatus status = StyleAttributeStatus::absent;
    ResourceValue value;
    std::uint32_t unresolved_style = 0;
    // Actual defining bag/source facts, distinct from the merged value.data.
    // native_flags includes every observed participating ancestor; only complete
    // provenance proves that no unresolved ancestor flags remain omitted.
    std::uint32_t native_flags = 0, source_id = 0, source_data = 0, source_style = 0;
    std::uint16_t density = 0;
    // SDK bags use the authenticated SDK source rather than an app source slot.
    // Old three-member aggregate producers remain explicitly incomplete.
    bool sdk_source = false, provenance_complete = false;
};
struct ResourceBagItem {
    std::uint32_t key = 0;
    ResourceValue value;
};
enum class ResourceSelectionPolicy { frozen_artwork, neutral_runtime, runtime_display };
struct ResourceConfiguration {
    // Neutral locale/device selection. These defaults and the artwork policy
    // are frozen; runtime callers provide their explicit virtual target.
    std::uint16_t density = 640, sdk = 35;
    ResourceSelectionPolicy policy = ResourceSelectionPolicy::frozen_artwork;
    // Explicit virtual-display targets; unused by the two retained policies.
    std::uint8_t orientation = 0; // Android configuration: 1 portrait, 2 landscape.
    std::uint16_t width_dp = 0, height_dp = 0, smallest_width_dp = 0;
    bool operator==(const ResourceConfiguration &) const = default;
};
struct ResourceEntry {
    std::uint32_t id = 0, data = 0;
    std::uint8_t value_type = 0;
    std::string type, name, container;
    std::uint16_t density = 0, sdk = 0;
    std::uint8_t orientation = 0;
    std::uint16_t width_dp = 0, height_dp = 0, smallest_width_dp = 0;
    // Encoded FLAG_COMPLEX, independent of symbolic type names and value type.
    bool complex = false;
    // Actual selected source facts. data remains the internal merged-pool value;
    // source_data retains the original encoded pool index/reference/scalar bits.
    std::uint32_t native_flags = 0, source_data = 0, source_id = 0;
};
struct ResourceSource {
    std::string container;
    std::uint32_t string_base = 0, string_count = 0;
};
class ResourceTable {
  public:
    static ResourceTable parse(Bytes bytes, std::string_view container = {},
                               const ResourceConfiguration *configuration = nullptr,
                               ResourceParseOptions options = {});
    static ResourceTable compose(const PackageView &package, std::string_view package_name,
                                 const ResourceConfiguration *configuration = nullptr,
                                 ResourceParseOptions options = {});
    void merge(ResourceTable other);
    const std::string &package_name() const noexcept { return package_; }
    const std::map<std::uint32_t, ResourceEntry> &entries() const noexcept { return entries_; }
    // source_id is a one-based slot in this actual held ARSC source registry.
    // AssetManager assigns its own positive cookie when binding these sources.
    std::span<const ResourceSource> sources() const noexcept { return sources_; }
    std::optional<std::uint32_t> declaration_flags(std::uint32_t id) const noexcept;
    std::u16string pooled_string(std::uint32_t source_id, std::uint32_t original_index,
                                std::size_t maximum_code_units) const;

    std::uint32_t identifier(std::string_view name, std::string_view type, std::string_view package) const;
    std::u16string text(std::uint32_t id, bool strip_styles = false) const;
    std::u16string text(ResourceValue value, bool strip_styles = false) const;
    // Child overrides are conclusive without resolving a missing parent. Only
    // a complete parent-zero chain proves absence; unresolved IDs retain their
    // identity for a separately authenticated platform-style consumer.
    StyleAttributeResult style_attribute(std::uint32_t style, std::uint32_t attribute,
                                        const std::function<void(std::uint64_t)> &charge_work = {}) const;
    std::vector<ResourceBagItem> bag(std::uint32_t id) const;
    std::string_view container(std::uint32_t id) const;
    const ResourceEntry &value(std::uint32_t id) const;
    std::string_view string_value(const ResourceEntry &entry) const;

  private:
    struct Bag {
        std::uint32_t parent = 0;
        std::vector<ResourceBagItem> items;
        bool duplicate_keys = false;
    };
    std::string package_;
    std::map<std::uint32_t, std::string> packages_;
    std::vector<std::string> strings_;
    std::set<std::uint32_t> styled_strings_;
    std::map<std::uint32_t, ResourceEntry> entries_;
    std::vector<ResourceSource> sources_;
    std::map<std::uint32_t, std::uint32_t> declared_flags_;

    std::map<std::uint32_t, Bag> bags_;
    std::size_t bag_items_ = 0;
    std::size_t encoded_bytes_ = 0, decoded_bytes_ = 0, chunks_ = 0, metadata_bytes_ = 0;
    std::optional<ResourceConfiguration> configuration_;
    bool metadata_preview_ = false;
    bool optimized_runtime_ = false;
    const ResourceEntry &resolve(std::uint32_t id) const;
};
} // namespace aether::apk
