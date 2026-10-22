#pragma once
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace aether::host {
enum class FileError {
    none,
    missing,
    denied,
    exists,
    bad_descriptor,
    invalid,
    unsupported,
    descriptor_limit,
    quota,
    io,
    would_block
};
struct FileResult {
    std::int64_t value = -1;
    FileError error = FileError::none;
};
struct FileOpen {
    bool read = false, write = false, create = false, exclusive = false, truncate = false;
};
struct DirectoryEntry {
    std::string name;
    std::uint64_t inode = 0;
    std::uint8_t type = 0; // Linux DT_* values; never a host path or handle.
};
inline constexpr std::size_t directory_entry_limit = 12, directory_name_limit = 255,
                             directory_payload_limit = 4096;
inline bool valid_directory_entry(const DirectoryEntry &entry) noexcept {
    const auto &name = entry.name;
    if (name.empty() || name.size() > directory_name_limit || name == "." || name == ".." ||
        name.find('\0') != std::string::npos || name.find_first_of("/\\") != std::string::npos)
        return false;
    switch (entry.type) {
    case 0: case 1: case 2: case 4: case 6: case 8: case 10: case 12: case 14: break;
    default: return false;
    }
    // Require canonical UTF-8, including exclusion of surrogate code points.
    for (std::size_t i = 0; i < name.size();) {
        const auto first = static_cast<unsigned char>(name[i++]);
        if (first < 0x80) continue;
        unsigned extra = 0, code = 0, minimum = 0;
        if (first >= 0xc2 && first <= 0xdf) { extra = 1; code = first & 31; minimum = 0x80; }
        else if (first >= 0xe0 && first <= 0xef) { extra = 2; code = first & 15; minimum = 0x800; }
        else if (first >= 0xf0 && first <= 0xf4) { extra = 3; code = first & 7; minimum = 0x10000; }
        else return false;
        if (extra > name.size() - i) return false;
        while (extra--) {
            const auto next = static_cast<unsigned char>(name[i++]);
            if ((next & 0xc0) != 0x80) return false;
            code = (code << 6) | (next & 63);
        }
        if (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return false;
    }
    return true;
}
// Android flock operations, including LOCK_NB. No path or host handle crosses this API.
inline bool valid_file_lock(std::uint32_t operation) noexcept {
    const auto mode=operation&~4U;return !(operation&~15U) && (mode==1 || mode==2 || mode==8);
}
enum class FileAccessScope:std::uint32_t {files_root,data_root,files_leaf,data_leaf};
inline bool valid_file_access(FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept {
    if(mode&~7U)return false;
    if(scope==FileAccessScope::files_root || scope==FileAccessScope::data_root)return name.empty();
    if(scope!=FileAccessScope::files_leaf && scope!=FileAccessScope::data_leaf)return false;
    if(name.empty() || name.size()>127 || name.front()=='.' || name.back()=='.' || name.find("..")!=std::string_view::npos)return false;
    for(const auto c:name)if(!((c>='a' && c<='z') || (c>='0' && c<='9') || c=='_' || c=='-' || c=='.'))return false;
    return true;
}
class FileService {
  public:
    virtual ~FileService() = default;
    // Observe the provider-owned private root; never returns or accepts a host path.
    virtual FileResult private_root() noexcept { return {-1, FileError::unsupported}; }
    // Read-only observation of one app-data-root leaf, separate from files/.
    // Returns 1 for a real regular file; missing/denied/failure retain typed errors.
    virtual FileResult observe_data_file(std::string_view) { return {-1, FileError::unsupported}; }
    // Bounded snapshot of the held private root, excluding . and ... Errors preserve output.
    virtual FileResult list_directory(std::vector<DirectoryEntry> &) { return {-1, FileError::unsupported}; }
    virtual FileResult open(std::string_view name, FileOpen options) = 0;
    virtual FileResult read(int descriptor, std::span<std::uint8_t> output) noexcept = 0;
    virtual FileResult write(int descriptor, std::span<const std::uint8_t> input) noexcept = 0;
    virtual FileResult close(int descriptor) noexcept = 0;
    // Explicit durability barrier for a writable descriptor; never implied by close.
    virtual FileResult flush(int) noexcept { return {-1, FileError::unsupported}; }
    virtual FileResult lock(int,std::uint32_t) noexcept { return {-1, FileError::unsupported}; }
    virtual FileResult access(FileAccessScope,std::string_view,std::uint32_t) noexcept { return {-1,FileError::unsupported}; }
};
// Opens one-component names relative to a held directory handle. No guest path is a host path.
class HostFileService final : public FileService {
  public:
    explicit HostFileService(const std::filesystem::path &root);
    ~HostFileService() override;
    HostFileService(const HostFileService &) = delete;
    HostFileService &operator=(const HostFileService &) = delete;
    FileResult private_root() noexcept override;
    FileResult observe_data_file(std::string_view name) override;
    FileResult list_directory(std::vector<DirectoryEntry> &output) override;
    FileResult open(std::string_view name, FileOpen options) override;
    FileResult read(int descriptor, std::span<std::uint8_t> output) noexcept override;
    FileResult write(int descriptor, std::span<const std::uint8_t> input) noexcept override;
    FileResult close(int descriptor) noexcept override;
    FileResult flush(int descriptor) noexcept override;
    FileResult lock(int descriptor,std::uint32_t operation) noexcept override;
    FileResult access(FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept override;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::host
