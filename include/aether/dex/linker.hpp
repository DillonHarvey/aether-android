#pragma once
#include "aether/dex/image.hpp"
#include <memory>
#include <functional>
#include <string_view>

namespace aether::dex {
struct LinkLimits {
    std::size_t files = 64;
    // Aggregate decoded input structures, payloads and retained operand maps.
    // The independent LPAC process-commit limit remains authoritative for all
    // allocator/container overhead and the other runtime subsystems.
    std::uint64_t metadata_bytes = 96ULL * 1024 * 1024;
};
class Linker {
  public:
    explicit Linker(LinkLimits limits = {});
    // Incremental target must begin empty and outlive this linker. Existing
    // identities stay stable; a failed add/validation poisons the linker.
    Linker(DexImage &target, LinkLimits limits = {});
    ~Linker();
    Linker(const Linker &) = delete;
    Linker &operator=(const Linker &) = delete;
    // Each input must pass parse independently. Consume one file at a time.
    // Any failed add/finish poisons the linker; a partial image cannot escape.
    // A true parent definition owns this exact descriptor. Keep its app-side
    // IDs symbolic; never publish the competing declaration or executable body.
    using ParentClass = std::function<bool(std::string_view)>;
    void add(DexImage image, std::string source, const ParentClass &parent = {});
    // Host-only reference admission: the caller must first establish an exact
    // implemented bootstrap/provider declaration. A request tuple is not that
    // authority. Reuses stable IDs and the same metadata budget/indexes as add;
    // creates no declaration, code body or DEX source. A failed admission poisons
    // this linker, so no partially interned image may subsequently execute.
    Index intern_provider_method(std::string_view owner, std::string_view name,
                                 std::string_view descriptor);
    void validate();
    DexImage finish();

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::dex
