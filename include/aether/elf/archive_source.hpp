#pragma once
#include "aether/apk/archive.hpp"
#include "aether/elf/guest_loader.hpp"

namespace aether::elf {
// Shared by a dependency graph, bounding repeated decompression work as well as
// the parser's independent retained-metadata and guest-mapping budgets.
struct ArchiveScanBudget {
    std::uint64_t scanned_bytes = 0;
};
class ArchiveSource final : public ModuleSource {
  public:
    ArchiveSource(apk::Archive &archive, std::size_t index, std::string expected_sha256,
                  std::shared_ptr<ArchiveScanBudget> budget);
    std::uint64_t size() const noexcept override;
    std::vector<std::uint8_t> read(std::uint64_t offset, std::size_t size) override;
    void stream(const std::function<void(std::uint64_t, Bytes)> &visitor) override;

  private:
    void charge();
    apk::Archive &archive_;
    std::size_t index_;
    std::uint64_t size_;
    std::string expected_;
    std::shared_ptr<ArchiveScanBudget> budget_;
};
} // namespace aether::elf
