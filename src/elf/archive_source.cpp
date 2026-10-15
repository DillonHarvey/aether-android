#include "aether/elf/archive_source.hpp"
#include "aether/apk/hash.hpp"
#include <array>

namespace aether::elf {
ArchiveSource::ArchiveSource(apk::Archive &archive, std::size_t index, std::string expected_sha256,
                             std::shared_ptr<ArchiveScanBudget> budget)
    : archive_(archive), index_(index), size_(archive.entries().at(index).bytes),
      expected_(std::move(expected_sha256)), budget_(std::move(budget)) {
    if (!budget_ || expected_.size() != 64 || !size_ || size_ > streamed_native_bytes)
        throw ElfError("AETHER_ELF_SOURCE", "Invalid archive-backed native source or 128 MiB file bound");
}
std::uint64_t ArchiveSource::size() const noexcept { return size_; }
void ArchiveSource::charge() {
    constexpr std::uint64_t maximum = 1024ULL * 1024 * 1024;
    if (budget_->scanned_bytes > maximum || size_ > maximum - budget_->scanned_bytes)
        throw ElfError("AETHER_ELF_LIMIT", "Native dependency graph exceeds 1 GiB of archive scan work");
    budget_->scanned_bytes += size_;
}
std::vector<std::uint8_t> ArchiveSource::read(std::uint64_t offset, std::size_t size) {
    if (offset > size_ || size > size_ - offset || size > 16 * 1024 * 1024)
        throw ElfError("AETHER_ELF_BOUNDS", "Native metadata read exceeds its source or retained bound");
    charge();
    const std::array ranges{apk::ArchiveRange{offset, size}};
    auto result = archive_.read_ranges(index_, ranges, true);
    if (result.sha256 != expected_)
        throw ElfError("AETHER_ELF_INTEGRITY", "Native source differs from the inspected APK member");
    return std::move(result.ranges.front());
}
void ArchiveSource::stream(const std::function<void(std::uint64_t, Bytes)> &visitor) {
    charge();
    apk::Sha256 hash;
    archive_.stream(index_, [&](std::uint64_t offset, Bytes bytes) {
        hash.update(bytes);
        visitor(offset, bytes);
    });
    if (hash.finish() != expected_)
        throw ElfError("AETHER_ELF_INTEGRITY", "Native segment stream differs from the inspected APK member");
}
} // namespace aether::elf
