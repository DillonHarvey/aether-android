#pragma once
#include "aether/apk/resources.hpp"
#include <array>
#include <functional>
#include <string>
#include <string_view>

namespace aether::android {
// Borrowed per-query host accounting; never retained in the immutable catalog.
// Metadata-only callers may omit it. Active runtime consumers supply their
// existing aggregate execution ledger, and callback exceptions propagate.
using SdkResourceWork = std::function<void(std::uint64_t)>;
enum class SdkResourceStatus { found, absent, unresolved, unsupported };
struct SdkScalarResult {
    SdkResourceStatus status = SdkResourceStatus::unresolved;
    apk::ResourceValue value{};
    bool complex = false;
    std::uint32_t resource_id = 0; // Selected ID after staged-alias remapping.
    std::uint16_t density = 0;
    std::uint32_t native_flags = 0, source_data = 0;
};
// The caller owns immutable authenticated bytes for this object's entire life.
// Construct once per table. Only a bounded chunk directory is retained; there
// are no expanded resource records, strings, bags, or mutable query caches.
class SdkResourceCatalog final {
  public:
    explicit SdkResourceCatalog(apk::Bytes);
    SdkResourceCatalog(const SdkResourceCatalog &) = delete;
    SdkResourceCatalog &operator=(const SdkResourceCatalog &) = delete;
    apk::StyleAttributeResult style_attribute(std::uint32_t style, std::uint32_t attribute,
                                              const apk::ResourceConfiguration &,
                                              const SdkResourceWork &work = {}) const;
    // Metadata-only continuation after another source already selected a child.
    // No attribute value is selected; source failures leave explicit incomplete
    // ancestry while caller work/cancellation failures still propagate.
    apk::StyleAttributeResult style_ancestry_flags(std::uint32_t style,
                                                   const apk::ResourceConfiguration &,
                                                   const SdkResourceWork &work = {}) const;
    SdkScalarResult scalar(std::uint32_t id, const apk::ResourceConfiguration &,
                           const SdkResourceWork &work = {}) const;
    // Declared ASCII type/name identity, independent of configuration selection.
    // Returns zero only for absence. Uses the actual package name pools and
    // staged aliases; ambiguous or unsupported names never acquire guessed IDs.
    // No expanded strings, cache, or additional metadata allocation is retained.
    std::uint32_t identifier(std::string_view type, std::string_view name,
                             const SdkResourceWork &work = {}) const;
    // Caller bounds logical UTF16 units and accounts returned capacity/overhead.
    // Only requested unstyled content is decoded; no pool expansion or cache.
    std::u16string pooled_string(std::uint32_t index, std::size_t maximum_code_units,
                                 const SdkResourceWork &work = {}) const;

  private:
    struct TypeRecord {
        std::uint32_t begin = 0, end = 0, entries = 0, keys = 0;
        std::uint8_t package = 0, type = 0;
        bool style = false;
        std::uint32_t spec_flags_offset = 0;
    };
    struct AliasRecord { std::uint32_t offset = 0, count = 0; };
    struct Entry {
        SdkResourceStatus status = SdkResourceStatus::absent;
        apk::ResourceValue value{};
        std::uint32_t key = 0, parent = 0, maps = 0, map_offset = 0, resource_id = 0;
        std::uint16_t density = 0;
        std::uint32_t native_flags = 0, source_data = 0;
        bool complex = false, style = false;
    };
    // Same structural chunk ceiling as the existing runtime resource parser.
    static constexpr std::size_t maximum_chunks = 8192;
    apk::Bytes bytes_;
    std::array<TypeRecord, maximum_chunks> types_{};
    std::array<AliasRecord, 256> aliases_{};
    std::size_t type_count_ = 0, alias_count_ = 0;
    std::uint32_t strings_ = 0, strings_offset_ = 0, strings_size_ = 0;
    std::uint32_t remap(std::uint32_t, const SdkResourceWork &work = {}) const;
    Entry read_entry(const TypeRecord &, std::uint32_t chunk_offset, std::uint32_t entry,
                      const SdkResourceWork &work = {}) const;
    Entry lookup(std::uint32_t, const apk::ResourceConfiguration &,
                  const SdkResourceWork &work = {}) const;
    apk::StyleAttributeResult style_attribute_impl(std::uint32_t style, std::uint32_t attribute,
                                                   const apk::ResourceConfiguration &,
                                                   const SdkResourceWork &, bool ancestry_only) const;
};
} // namespace aether::android
