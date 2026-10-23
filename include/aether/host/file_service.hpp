#pragma once
#include <cstdint>
#include <array>
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
    would_block,
    is_directory,
    not_directory,
    not_empty,
    not_seekable
};
struct FileResult {
    std::int64_t value = -1;
    FileError error = FileError::none;
};
// Metadata for one held private regular file. No Windows path, ID or handle.
struct FileMetadata {
    std::uint64_t size = 0, identity = 0; // Provider-scoped opaque, nonzero regular-file identity.
    std::uint64_t allocated_bytes = 0; // Actual provider allocation, distinct from logical size.
    std::int64_t access_seconds = 0, modified_seconds = 0, changed_seconds = 0;
    std::uint32_t access_nanoseconds = 0, modified_nanoseconds = 0, changed_nanoseconds = 0;
    bool readonly = false;
    std::uint32_t links = 1; // Held regular files are linked once, or unlinked through this provider.
};
inline constexpr std::uint64_t private_file_size_limit = 1024 * 1024;
inline bool valid_file_metadata(const FileMetadata &value) noexcept {
    return value.identity != 0 && value.size <= private_file_size_limit && value.allocated_bytes <= INT64_MAX &&
           value.access_nanoseconds < 1'000'000'000 && value.modified_nanoseconds < 1'000'000'000 &&
           value.changed_nanoseconds < 1'000'000'000 && value.links <= 1;
}
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
enum class FileRemoveMode:std::uint32_t {file,directory,either};
inline constexpr std::size_t private_path_limit = 1023, private_path_depth = 8, private_namespace_limit = 32;
inline bool valid_file_path(std::string_view name, bool empty = false) noexcept {
    if (name.empty()) return empty;
    if (name.size() > private_path_limit) return false;
    unsigned depth = 0;
    while (!name.empty()) {
        const auto slash = name.find('/');
        const auto part = name.substr(0, slash);
        if (++depth > private_path_depth || part.empty() || part.size() > 127 || part.front() == '.' ||
            part.back() == '.' || part.find("..") != std::string_view::npos) return false;
        for (const auto c : part)
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) return false;
        if (slash == std::string_view::npos) break;
        name.remove_prefix(slash + 1);
        if (name.empty()) return false;
    }
    return true;
}
inline bool valid_file_access(FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept {
    if(mode&~7U)return false;
    if(scope==FileAccessScope::files_root || scope==FileAccessScope::data_root)return name.empty();
    return (scope==FileAccessScope::files_leaf || scope==FileAccessScope::data_leaf) && valid_file_path(name);
}
inline bool valid_file_remove(FileAccessScope scope, std::string_view name, FileRemoveMode mode) noexcept {
    return (scope == FileAccessScope::files_leaf || scope == FileAccessScope::data_leaf) &&
           static_cast<std::uint32_t>(mode) <= static_cast<std::uint32_t>(FileRemoveMode::either) &&
           valid_file_access(scope, name, 0);
}
// A rooted logical path, or a path anchored at one owned provider directory descriptor.
struct FilePathRef {
    FileAccessScope scope=FileAccessScope::files_leaf;
    int directory=-1;
    std::string_view name;
    bool directory_required=false;
};
struct FileRenameRelocation {
    int descriptor=-1;
    std::uint64_t identity=0;
    FileAccessScope scope=FileAccessScope::files_leaf;
    std::array<char,1024> name{};
    std::uint32_t name_length=0;
    bool directory=false,unlinked=false;
};
struct FileRenameInfo {
    std::uint64_t source_identity=0,replaced_identity=0;
    bool directory=false,unchanged=false;
    std::uint32_t relocation_count=0;
    std::array<FileRenameRelocation,64> relocations{};
};
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
    // One safe regular leaf in the typed app-private namespace; no host path.
    virtual FileResult open_scoped(FileAccessScope scope, std::string_view name, FileOpen options) {
        return scope == FileAccessScope::files_leaf ? open(name, options) : FileResult{-1, FileError::unsupported};
    }
    // Directory descriptors own actual held objects. Relative operations never reopen a saved path.
    virtual FileResult make_directory(FileAccessScope, std::string_view, std::uint32_t) noexcept {return {-1,FileError::unsupported};}
    virtual FileResult open_directory(FileAccessScope, std::string_view) {return {-1,FileError::unsupported};}
    virtual FileResult directory_valid(int) noexcept {return {-1,FileError::unsupported};}
    virtual FileResult open_relative(int, std::string_view, FileOpen) {return {-1,FileError::unsupported};}
    virtual FileResult open_directory_relative(int, std::string_view) {return {-1,FileError::unsupported};}
    virtual FileResult make_directory_relative(int, std::string_view, std::uint32_t) noexcept {return {-1,FileError::unsupported};}
    virtual FileResult access_relative(int, std::string_view, std::uint32_t) noexcept {return {-1,FileError::unsupported};}
    virtual FileResult remove_relative(int, std::string_view, FileRemoveMode, bool = false) noexcept {return {-1,FileError::unsupported};}
    // Success is zero; failure preserves output. No-op success has no relocation rows.
    virtual FileResult rename_path(const FilePathRef&,const FilePathRef&,FileRenameInfo&) noexcept {return {-1,FileError::unsupported};}
    virtual FileResult read(int descriptor, std::span<std::uint8_t> output) noexcept = 0;
    virtual FileResult write(int descriptor, std::span<const std::uint8_t> input) noexcept = 0;
    virtual FileResult close(int descriptor) noexcept = 0;
    // Explicit durability barrier for a writable descriptor; never implied by close.
    virtual FileResult flush(int) noexcept { return {-1, FileError::unsupported}; }
    virtual FileResult lock(int,std::uint32_t) noexcept { return {-1, FileError::unsupported}; }
    // Success returns zero; every failure preserves the caller's output.
    virtual FileResult metadata(int, FileMetadata &) noexcept { return {-1, FileError::unsupported}; }
    // One actual namespace removal. Success returns the positive opaque removed identity.
    // directory_required preserves the final slash's directory requirement without following a reparse point.
    virtual FileResult remove(FileAccessScope, std::string_view, FileRemoveMode, bool = false) noexcept {
        return {-1, FileError::unsupported};
    }
    // SEEK_SET/CUR/END (0/1/2), bounded by the existing private-file profile.
    // Failed seeks preserve the shared open-description offset.
    virtual FileResult seek(int, std::int64_t, unsigned) noexcept { return {-1, FileError::unsupported}; }
    virtual FileResult access(FileAccessScope,std::string_view,std::uint32_t) noexcept { return {-1,FileError::unsupported}; }
    virtual FileResult access_path(FileAccessScope scope,std::string_view name,std::uint32_t mode,bool directory_required) noexcept {return directory_required?FileResult{-1,FileError::unsupported}:access(scope,name,mode);}
    virtual FileResult access_relative_path(int parent,std::string_view name,std::uint32_t mode,bool directory_required) noexcept {return directory_required?FileResult{-1,FileError::unsupported}:access_relative(parent,name,mode);}

};
// Walks bounded safe components through held normal directory handles. No guest path is a host path.
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
    FileResult open_scoped(FileAccessScope scope, std::string_view name, FileOpen options) override;
    FileResult make_directory(FileAccessScope scope, std::string_view name, std::uint32_t mode) noexcept override;
    FileResult open_directory(FileAccessScope scope, std::string_view name) override;
    FileResult directory_valid(int descriptor) noexcept override;
    FileResult open_relative(int parent, std::string_view name, FileOpen options) override;
    FileResult open_directory_relative(int parent, std::string_view name) override;
    FileResult make_directory_relative(int parent, std::string_view name, std::uint32_t mode) noexcept override;
    FileResult access_relative(int parent, std::string_view name, std::uint32_t mode) noexcept override;
    FileResult access_path(FileAccessScope scope, std::string_view name, std::uint32_t mode, bool directory_required) noexcept override;
    FileResult access_relative_path(int parent, std::string_view name, std::uint32_t mode, bool directory_required) noexcept override;
    FileResult remove_relative(int parent, std::string_view name, FileRemoveMode mode, bool directory_required = false) noexcept override;
    FileResult rename_path(const FilePathRef &source,const FilePathRef &destination,FileRenameInfo &output) noexcept override;
    FileResult read(int descriptor, std::span<std::uint8_t> output) noexcept override;
    FileResult write(int descriptor, std::span<const std::uint8_t> input) noexcept override;
    FileResult close(int descriptor) noexcept override;
    FileResult flush(int descriptor) noexcept override;
    FileResult metadata(int descriptor, FileMetadata &output) noexcept override;
    FileResult remove(FileAccessScope scope, std::string_view name, FileRemoveMode mode, bool directory_required = false) noexcept override;
    FileResult seek(int descriptor, std::int64_t offset, unsigned whence) noexcept override;
    FileResult lock(int descriptor,std::uint32_t operation) noexcept override;
    FileResult access(FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept override;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::host
