#pragma once
#include "aether/apk/inspect.hpp"
#include <functional>
#include <memory>

namespace aether::apk {
// Package readers use case-sensitive archive identities and never extract member
// names to host paths. The default Windows policy remains available to callers
// requiring conservative host-name collision checks. Neither mode permits extraction.
enum class ArchiveNames { windows, case_sensitive };
struct ArchiveEntry {
    std::string path;
    std::uint32_t compressed_bytes;
    std::uint32_t bytes;
    bool directory;
    std::uint32_t crc32;
    std::uint64_t data_offset;
    bool stored;
};
struct ArchiveRange {
    std::uint64_t offset, bytes;
};
struct ArchiveRead {
    std::vector<std::vector<std::uint8_t>> ranges;
    std::string sha256;
};
class Archive {
  public:
    Archive(Bytes bytes, const InspectLimits &limits, ArchiveNames names = ArchiveNames::windows);
    ~Archive();
    Archive(const Archive &) = delete;
    Archive &operator=(const Archive &) = delete;
    const std::vector<ArchiveEntry> &entries() const;
    std::uint64_t buffer_limit() const;
    std::vector<std::uint8_t> read(std::size_t index);
    // Zero-copy access to a stored member after full CRC validation. The caller
    // must retain the original immutable backing bytes for the view's lifetime.
    // Deflated members are refused, never silently materialized or extracted.
    Bytes stored_view(std::size_t index) const;
    // Metadata preview ONLY: borrow a structurally validated stored extent
    // without reading unrelated payload bytes to compute its outer CRC. The
    // inner reader still checks each consumed member. This confers no integrity,
    // signing, installation or execution authority. Never use for admission.
    Bytes stored_preview_extent(std::size_t index) const;
    // Chunks are borrowed, ordered, at most 64 KiB, and valid only during the callback.
    // A result is valid only after this call completes its full size/CRC verification.
    // Visitors must not reenter this Archive or mutate its backing input.
    void stream(std::size_t index, const std::function<void(std::uint64_t, Bytes)> &visitor);
    // At most 1024 bounded ranges, returned in request order. The complete member
    // is validated, including bytes outside the requested ranges; nothing is extracted.
    ArchiveRead read_ranges(std::size_t index, std::span<const ArchiveRange> ranges,
                            bool compute_sha256 = false);

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
NativeInfo inspect_native_member(Archive &archive, std::size_t index, std::string abi);
} // namespace aether::apk
