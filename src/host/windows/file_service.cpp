#include "aether/host/file_service.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <windows.h>
#include <winternl.h>

namespace aether::host {
namespace {
constexpr std::uint64_t maximum_file = 1024 * 1024;
constexpr DWORD advisory_lock_offset=static_cast<DWORD>(maximum_file*2);
FileError error(DWORD value) {
    switch (value) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        return FileError::missing;
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
    case ERROR_CANT_ACCESS_FILE:
        return FileError::denied;
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:
        return FileError::exists;
    case ERROR_INVALID_HANDLE:
        return FileError::bad_descriptor;
    case ERROR_INVALID_PARAMETER:
    case ERROR_INVALID_NAME:
        return FileError::invalid;
    case ERROR_DISK_FULL:
    case ERROR_HANDLE_DISK_FULL:
        return FileError::quota;
    default:
        return FileError::io;
    }
}
bool safe_name(std::string_view name) {
    if (name.empty() || name.size() > 127 || name.front() == '.' || name.back() == '.' ||
        name.find("..") != std::string_view::npos)
        return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
    });
}
} // namespace
struct HostFileService::Impl {
    struct File {
        HANDLE handle = INVALID_HANDLE_VALUE;
        bool read = false, write = false;
        std::uint32_t lock_mode=0;
        FileResult release() noexcept {
            const auto held=handle;handle=INVALID_HANDLE_VALUE;
            DWORD failure=ERROR_SUCCESS;
            if(lock_mode){OVERLAPPED region{};region.Offset=advisory_lock_offset;if(!UnlockFileEx(held,0,1,0,&region))failure=GetLastError();}
            lock_mode=0;
            if(!CloseHandle(held))return {-1,error(GetLastError())};
            return failure?FileResult{-1,error(failure)}:FileResult{0,FileError::none};
        }
    };
    HANDLE root = INVALID_HANDLE_VALUE;
    std::array<File, 64> files{};
    ~Impl() {
        for (auto &file : files)
            if (file.handle != INVALID_HANDLE_VALUE)
                (void)file.release();
        if (root != INVALID_HANDLE_VALUE)
            CloseHandle(root);
    }
    File *find(int fd) noexcept {
        if (fd < 3 || fd - 3 >= static_cast<int>(files.size()))
            return nullptr;
        auto &file = files[static_cast<std::size_t>(fd - 3)];
        return file.handle == INVALID_HANDLE_VALUE ? nullptr : &file;
    }
};
HostFileService::HostFileService(const std::filesystem::path &root) : impl_(std::make_unique<Impl>()) {
    if (!root.is_absolute())
        throw std::runtime_error("Host file root must be an explicit absolute directory");
    impl_->root =
        CreateFileW(root.c_str(), FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    BY_HANDLE_FILE_INFORMATION info{};
    if (impl_->root == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(impl_->root, &info) ||
        !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        throw std::runtime_error("Cannot hold a non-reparse scoped directory");
}
HostFileService::~HostFileService() = default;
FileResult HostFileService::private_root() noexcept {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(impl_->root, &info))
        return {-1, error(GetLastError())};
    if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return {-1, FileError::denied};
    return {0, FileError::none};
}
FileResult HostFileService::list_directory(std::vector<DirectoryEntry> &output) {
    std::vector<DirectoryEntry> entries;
    std::size_t encoded = 24; // Standard result, then entry count.
    alignas(FILE_ID_BOTH_DIR_INFO) std::array<std::uint8_t, 4096> buffer{};
    bool restart = true;
    for (;;) {
        if (!GetFileInformationByHandleEx(impl_->root,
                restart ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo,
                buffer.data(), static_cast<DWORD>(buffer.size()))) {
            const auto failure = GetLastError();
            if (failure != ERROR_NO_MORE_FILES) return {-1, error(failure)};
            output.swap(entries);
            return {static_cast<std::int64_t>(output.size()), FileError::none};
        }
        restart = false;
        std::size_t offset = 0;
        for (;;) {
            constexpr auto header = offsetof(FILE_ID_BOTH_DIR_INFO, FileName);
            if (offset > buffer.size() - header) return {-1, FileError::io};
            const auto *info = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO *>(buffer.data() + offset);
            const auto remaining = buffer.size() - offset;
            if (info->FileNameLength % sizeof(wchar_t) || info->FileNameLength > remaining - header)
                return {-1, FileError::io};
            const std::wstring_view wide(info->FileName, info->FileNameLength / sizeof(wchar_t));
            // '@' is the reserved backing namespace for app-data-root siblings,
            // not a member of the guest private-files directory.
            if (wide != L"." && wide != L".." && (wide.empty() || wide.front() != L'@')) {
                if (wide.empty()) return {-1, FileError::io};
                const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(),
                    static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
                if (!count) return {-1, FileError::io};
                if (static_cast<std::size_t>(count) > directory_name_limit ||
                    entries.size() == directory_entry_limit ||
                    static_cast<std::size_t>(count) + 17 > directory_payload_limit - encoded)
                    return {-1, FileError::quota};
                DirectoryEntry entry{std::string(static_cast<std::size_t>(count), '\0'),
                    static_cast<std::uint64_t>(info->FileId.QuadPart),
                    static_cast<std::uint8_t>((info->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ? 0 :
                        (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 4 : 8)};
                if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(),
                        static_cast<int>(wide.size()), entry.name.data(), count, nullptr, nullptr) != count ||
                    !valid_directory_entry(entry)) return {-1, FileError::io};
                if (std::any_of(entries.begin(), entries.end(), [&](const auto &prior) { return prior.name == entry.name; }))
                    return {-1, FileError::io};
                encoded += entry.name.size() + 17;
                entries.push_back(std::move(entry));
            }
            if (!info->NextEntryOffset) break;
            if (info->NextEntryOffset < header + info->FileNameLength ||
                info->NextEntryOffset > remaining || info->NextEntryOffset % alignof(FILE_ID_BOTH_DIR_INFO))
                return {-1, FileError::io};
            offset += info->NextEntryOffset;
        }
    }
}
FileResult HostFileService::open(std::string_view name, FileOpen options) {
    if (!safe_name(name))
        return {-1, FileError::denied};
    if ((!options.read && !options.write) || (options.truncate && !options.write) ||
        (options.exclusive && !options.create))
        return {-1, FileError::invalid};
    const auto slot = std::find_if(impl_->files.begin(), impl_->files.end(),
                                   [](const auto &f) { return f.handle == INVALID_HANDLE_VALUE; });
    if (slot == impl_->files.end())
        return {-1, FileError::descriptor_limit};
    std::wstring wide(name.begin(), name.end());
    UNICODE_STRING relative{};
    relative.Length = static_cast<USHORT>(wide.size() * sizeof(wchar_t));
    relative.MaximumLength = relative.Length;
    relative.Buffer = wide.data();
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = impl_->root;
    attributes.ObjectName = &relative; // Case-sensitive lookup; names are restricted to lower ASCII.
    IO_STATUS_BLOCK io{};
    HANDLE handle = INVALID_HANDLE_VALUE;
    const ACCESS_MASK access = FILE_READ_ATTRIBUTES | SYNCHRONIZE | (options.read ? FILE_READ_DATA : 0) |
                               (options.write ? FILE_WRITE_DATA : 0);
    // FILE_OPEN=1, FILE_CREATE=2, FILE_OPEN_IF=3. Never truncate before handle validation.
    const ULONG disposition = options.create ? (options.exclusive ? 2u : 3u) : 1u;
    constexpr ULONG synchronous_nonalert = 0x20, non_directory = 0x40, open_reparse = 0x00200000;
    const auto status =
        NtCreateFile(&handle, access, &attributes, &io, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, disposition,
                     synchronous_nonalert | non_directory | open_reparse, nullptr, 0);
    if (status < 0)
        return {-1, error(RtlNtStatusToDosError(status))};
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    if (GetFileType(handle) != FILE_TYPE_DISK || !GetFileInformationByHandle(handle, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
        info.nNumberOfLinks != 1 || !GetFileSizeEx(handle, &size) || size.QuadPart < 0 ||
        static_cast<std::uint64_t>(size.QuadPart) > maximum_file) {
        CloseHandle(handle);
        return {-1, FileError::denied};
    }
    if (options.truncate && !SetEndOfFile(handle)) {
        const auto failure = error(GetLastError());
        CloseHandle(handle);
        return {-1, failure};
    }
    *slot = {handle, options.read, options.write};
    return {3 + (slot - impl_->files.begin()), FileError::none};
}
FileResult HostFileService::observe_data_file(std::string_view name) {
    if (!safe_name(name)) return {-1, FileError::denied};
    // '@' cannot occur in the existing files/ name alphabet. This mapping is
    // injective and preserves all existing flat-file names without migration.
    const std::wstring mapped = L"@" + std::wstring(name.begin(), name.end());
    UNICODE_STRING relative{};
    relative.Length = static_cast<USHORT>(mapped.size() * sizeof(wchar_t));
    relative.MaximumLength = relative.Length;
    relative.Buffer = const_cast<wchar_t *>(mapped.data());
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = impl_->root;
    attributes.ObjectName = &relative;
    IO_STATUS_BLOCK io{};
    HANDLE raw = INVALID_HANDLE_VALUE;
    constexpr ULONG synchronous_nonalert = 0x20, non_directory = 0x40, open_reparse = 0x00200000;
    const auto status = NtCreateFile(&raw, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &io, nullptr,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, 1u,
        synchronous_nonalert | non_directory | open_reparse, nullptr, 0);
    if (status < 0) return {-1, error(RtlNtStatusToDosError(status))};
    struct Close { HANDLE value; ~Close() { CloseHandle(value); } } close{raw};
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    if (GetFileType(raw) != FILE_TYPE_DISK || !GetFileInformationByHandle(raw, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
        info.nNumberOfLinks != 1 || !GetFileSizeEx(raw, &size) || size.QuadPart < 0 ||
        static_cast<std::uint64_t>(size.QuadPart) > maximum_file) return {-1, FileError::denied};
    return {1, FileError::none};
}
FileResult HostFileService::read(int descriptor, std::span<std::uint8_t> output) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file || !file->read)
        return {-1, FileError::bad_descriptor};
    if (output.size() > maximum_file)
        return {-1, FileError::invalid};
    DWORD count = 0;
    if (!ReadFile(file->handle, output.data(), static_cast<DWORD>(output.size()), &count, nullptr))
        return {-1, error(GetLastError())};
    return {count, FileError::none};
}
FileResult HostFileService::write(int descriptor, std::span<const std::uint8_t> input) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file || !file->write)
        return {-1, FileError::bad_descriptor};
    LARGE_INTEGER zero{}, position{};
    if (!SetFilePointerEx(file->handle, zero, &position, FILE_CURRENT))
        return {-1, error(GetLastError())};
    if (position.QuadPart < 0 || static_cast<std::uint64_t>(position.QuadPart) > maximum_file ||
        input.size() > maximum_file - static_cast<std::uint64_t>(position.QuadPart))
        return {-1, FileError::quota};
    DWORD count = 0;
    // One write attempt only; short writes are returned to the guest.
    if (!WriteFile(file->handle, input.data(), static_cast<DWORD>(input.size()), &count, nullptr))
        return {-1, error(GetLastError())};
    return {count, FileError::none};
}
FileResult HostFileService::flush(int descriptor) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file || !file->write)
        return {-1, FileError::bad_descriptor};
    // One attempt only. A failure is never retried or reported as durable.
    return FlushFileBuffers(file->handle) ? FileResult{0, FileError::none}
                                        : FileResult{-1, error(GetLastError())};
}
FileResult HostFileService::close(int descriptor) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file)
        return {-1, FileError::bad_descriptor};
    return file->release();
}
FileResult HostFileService::access(FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept {
    if(!valid_file_access(scope,name,mode))return {-1,FileError::invalid};
    try {
        const bool directory=scope==FileAccessScope::files_root || scope==FileAccessScope::data_root;
        std::wstring relative_name=directory?L"":scope==FileAccessScope::data_leaf?L"@"+std::wstring(name.begin(),name.end()):std::wstring(name.begin(),name.end());
        UNICODE_STRING relative{};relative.Length=static_cast<USHORT>(relative_name.size()*sizeof(wchar_t));relative.MaximumLength=relative.Length;relative.Buffer=relative_name.data();
        OBJECT_ATTRIBUTES attributes{};attributes.Length=sizeof(attributes);attributes.RootDirectory=impl_->root;attributes.ObjectName=&relative;
        ACCESS_MASK rights=FILE_READ_ATTRIBUTES|SYNCHRONIZE;
        if(mode&4)rights|=directory?FILE_LIST_DIRECTORY:FILE_READ_DATA;
        if(mode&2)rights|=directory?FILE_ADD_FILE:FILE_WRITE_DATA;
        if(directory && (mode&1))rights|=FILE_TRAVERSE;
        IO_STATUS_BLOCK io{};HANDLE handle=INVALID_HANDLE_VALUE;
        constexpr ULONG synchronous_nonalert=0x20,open_reparse=0x00200000;
        const auto status=NtCreateFile(&handle,rights,&attributes,&io,nullptr,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ|FILE_SHARE_WRITE,1u,synchronous_nonalert|open_reparse|(directory?1u:0x40u),nullptr,0);
        if(status<0)return {-1,error(RtlNtStatusToDosError(status))};
        struct Close {HANDLE handle;~Close(){CloseHandle(handle);}} close{handle};
        BY_HANDLE_FILE_INFORMATION info{};LARGE_INTEGER size{};
        if(GetFileType(handle)!=FILE_TYPE_DISK || !GetFileInformationByHandle(handle,&info) || (info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) || static_cast<bool>(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=directory)return {-1,FileError::denied};
        if(!directory && (info.nNumberOfLinks!=1 || !GetFileSizeEx(handle,&size) || size.QuadPart<0 || static_cast<std::uint64_t>(size.QuadPart)>maximum_file))return {-1,FileError::denied};
        // Private guest regular files use the existing non-executable data profile.
        if(!directory && (mode&1))return {-1,FileError::denied};
        return {0,FileError::none};
    }catch(...){return {-1,FileError::io};}
}
FileResult HostFileService::lock(int descriptor,std::uint32_t operation) noexcept {
    const auto file=impl_->find(descriptor);if(!file)return {-1,FileError::bad_descriptor};
    if(!valid_file_lock(operation))return {-1,FileError::invalid};
    const auto mode=operation&~4U;
    if(mode==file->lock_mode || (mode==8 && !file->lock_mode))return {0,FileError::none};
    // One reserved byte beyond every permitted data/read-request span. Windows enforces conflict
    // across independently opened handles without making guest data I/O mandatory-locking.
    OVERLAPPED region{};region.Offset=advisory_lock_offset;
    if(file->lock_mode) {
        if(!UnlockFileEx(file->handle,0,1,0,&region))return {-1,error(GetLastError())};
        file->lock_mode=0;
    }
    if(mode==8)return {0,FileError::none};
    const DWORD flags=LOCKFILE_FAIL_IMMEDIATELY|(mode==2?LOCKFILE_EXCLUSIVE_LOCK:0);
    if(!LockFileEx(file->handle,flags,0,1,0,&region)) {
        const auto failure=GetLastError();
        if(failure==ERROR_LOCK_VIOLATION)return {-1,(operation&4)?FileError::would_block:FileError::unsupported};
        return {-1,error(failure)};
    }
    file->lock_mode=mode;return {0,FileError::none};
}

} // namespace aether::host
