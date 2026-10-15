#pragma once
#include "aether/apk/archive.hpp"
#include "aether/dex/source.hpp"

namespace aether::dex {
struct ArchiveDexInput {
    std::shared_ptr<apk::Archive> archive;
    apk::DexInfo file;
};
// Compact class-to-file inventory, not an executable decoded image. Retains no
// expanded DEX file between calls. Archive backing bytes must remain immutable.
class ArchiveSource final : public ClassSource {
  public:
    ArchiveSource(std::shared_ptr<apk::Archive> archive, std::span<const apk::DexInfo> files);
    explicit ArchiveSource(std::span<const ArchiveDexInput> files);
    ~ArchiveSource();
    std::optional<std::size_t> source_for(std::string_view descriptor) const override;
    std::string_view source_name(std::size_t index) const override;
    DexImage load(std::size_t index) override;
    std::size_t indexed_classes() const noexcept;
    std::size_t index_bytes() const noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::dex
