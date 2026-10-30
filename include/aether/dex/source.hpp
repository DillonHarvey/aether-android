#pragma once
#include "aether/dex/limits.hpp"
#include "aether/dex/linker.hpp"
#include <string_view>

namespace aether::dex {
enum class ClassLoadAllocationPhase : std::uint32_t {
    none=0,lookup=1,source=2,archive_read=3,archive_hash=4,parse_header=5,
    parse_map=6,parse_strings=7,parse_types=8,parse_prototypes=9,parse_fields=10,
    parse_methods=11,parse_code=12,parse_classes=13,parse_annotations=14,
    link_account=15,link_merge=16,link_validate=17,definition_index=18,complete=19,
    code_units=20,code_handler_list=21,code_handler_types=22,code_handler_index=23,
    code_try_regions=24,code_try_publish=25,code_storage_publish=26
};
// Lookup itself never executes or initializes a class. A selected file must
// pass the complete structural DEX parser before any definition is published.
class ClassSource {
  public:
    virtual ~ClassSource() = default;
    virtual std::optional<std::size_t> source_for(std::string_view descriptor) const = 0;
    virtual std::string_view source_name(std::size_t index) const = 0;
    virtual DexImage load(std::size_t index) = 0;
};
class ClassLoader {
  public:
    ClassLoader(DexImage &target, std::shared_ptr<ClassSource> source, LinkLimits limits = {});
    ~ClassLoader();
    ClassLoader(const ClassLoader &) = delete;
    ClassLoader &operator=(const ClassLoader &) = delete;
    void ensure(std::string_view descriptor);
    const Class *definition(std::string_view descriptor);
    void check() const;
    // First allocation stage for the latest outer ensure, even after poisoning.
    ClassLoadAllocationPhase allocation_failure_phase() const noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::dex
