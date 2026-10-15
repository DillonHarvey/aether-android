#pragma once
#include "aether/host/windows/unique_handle.hpp"
#include <array>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace aether::shell {
using IconDigest = std::array<std::uint8_t, 32>;
IconDigest icon_digest(std::span<const std::uint8_t> bytes);
std::wstring icon_hex(const IconDigest &digest);
std::filesystem::path icon_cache_root();
// Background startup only; validates/pins the private installed host and every
// ancestor. No command arguments are derived from an untrusted package path.
bool launch_icon_service(const std::filesystem::path &executable);
// This owns only local disk handles. No archive parsing or payload reads occur.
// Read mode pins all ancestors and denies source writes/replacement for the worker.
class IconSource final {
  public:
    explicit IconSource(const std::filesystem::path &path, bool read = false);
    HANDLE handle() const noexcept { return file_.get(); }
    const IconDigest &identity() const noexcept { return identity_; }
    std::uint64_t size() const noexcept { return size_; }
    const std::filesystem::path &path() const noexcept { return path_; }
    bool unchanged() const;

  private:
    std::filesystem::path path_;
    std::vector<host::UniqueHandle> directories_;
    host::UniqueHandle file_;
    IconDigest identity_{};
    std::uint64_t size_ = 0;
};
enum class CacheState : std::uint32_t { missing, ready, retry_later };
struct CachedIcon {
    CacheState state = CacheState::missing;
    std::filesystem::path path;
    IconDigest digest{};
    std::uint64_t retry_at = 0;
    std::uint32_t attempts = 0;
};
struct CacheCleanup {
    std::uint32_t removed = 0, preserved = 0;
};
// Strict layout checks only for our seven raw BGRA/DIB frames. No image decoder.
bool valid_cached_icon(std::span<const std::uint8_t> bytes) noexcept;
class IconCache final {
  public:
    explicit IconCache(std::filesystem::path root = icon_cache_root(), bool create = false);
    CachedIcon lookup(const IconDigest &source) const;
    // Writer operations are serialized by the broker. Every artifact is written
    // directly at its final content-addressed path. Readers require a complete,
    // checksummed commit record, and never observe an in-progress ICO as a hit.
    bool commit(const IconDigest &source, std::span<const std::uint8_t> icon);
    void failure(const IconDigest &source);
    void touch(const IconDigest &source);
    void prune(std::uint64_t quota = 256ULL * 1024 * 1024);
    // Explicit maintenance after the matching broker has stopped. Delete only
    // fully verified artifacts; preserve unknown, corrupt, redirected or busy entries.
    CacheCleanup clear();
    const std::filesystem::path &root() const noexcept { return root_; }

  private:
    std::filesystem::path root_;
    std::vector<host::UniqueHandle> directories_;
    unsigned writes_since_prune_ = 32;
};
} // namespace aether::shell
