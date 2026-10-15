#pragma once
#include "aether/dex/image.hpp"
#include <memory>

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
    void add(DexImage image, std::string source);
    void validate();
    DexImage finish();

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::dex
