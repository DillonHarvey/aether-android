#pragma once
#include "aether/apk/inspect.hpp"
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
struct ResourceBagItem {
    std::uint32_t key = 0;
    ResourceValue value;
};
enum class ResourceSelectionPolicy { frozen_artwork, neutral_runtime };
struct ResourceConfiguration {
    // Neutral locale/device selection. These defaults and the artwork policy
    // are frozen; runtime callers provide their explicit virtual target.
    std::uint16_t density = 640, sdk = 35;
    ResourceSelectionPolicy policy = ResourceSelectionPolicy::frozen_artwork;
    bool operator==(const ResourceConfiguration &) const = default;
};
struct ResourceEntry {
    std::uint32_t id = 0, data = 0;
    std::uint8_t value_type = 0;
    std::string type, name, container;
    std::uint16_t density = 0, sdk = 0;
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
    std::uint32_t identifier(std::string_view name, std::string_view type, std::string_view package) const;
    std::u16string text(std::uint32_t id, bool strip_styles = false) const;
    std::u16string text(ResourceValue value, bool strip_styles = false) const;
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
    std::map<std::uint32_t, Bag> bags_;
    std::size_t bag_items_ = 0;
    std::size_t encoded_bytes_ = 0, decoded_bytes_ = 0, chunks_ = 0, metadata_bytes_ = 0;
    std::optional<ResourceConfiguration> configuration_;
    bool metadata_preview_ = false;
    bool optimized_runtime_ = false;
    const ResourceEntry &resolve(std::uint32_t id) const;
};
} // namespace aether::apk
