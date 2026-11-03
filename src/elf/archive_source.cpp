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
    const std::array ranges{ModuleRange{offset, size}};
    auto result = read_ranges(ranges);
    return std::move(result.front());
}
std::vector<std::vector<std::uint8_t>> ArchiveSource::read_ranges(std::span<const ModuleRange> ranges) {
    constexpr std::uint64_t maximum = 16ULL * 1024 * 1024;
    if (ranges.size() > 16)
        throw ElfError("AETHER_ELF_LIMIT", "Native metadata batch exceeds 16 read ranges");
    std::array<apk::ArchiveRange, 16> selected{};
    std::uint64_t retained = 0;
    for (std::size_t n = 0; n < ranges.size(); ++n) {
        const auto &range = ranges[n];
        if (range.offset > size_ || range.size > size_ - range.offset || range.size > maximum - retained)
            throw ElfError("AETHER_ELF_BOUNDS", "Native metadata batch exceeds its source or 16 MiB retained bound");
        retained += range.size;
        selected[n] = {range.offset, range.size};
    }
    if (ranges.empty())
        return {};
    charge();
    auto result = archive_.read_ranges(index_, std::span(selected).first(ranges.size()), true);
    if (result.sha256 != expected_)
        throw ElfError("AETHER_ELF_INTEGRITY", "Native source differs from the inspected APK member");
    return std::move(result.ranges);
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
