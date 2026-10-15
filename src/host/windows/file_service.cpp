#include "aether/host/file_service.hpp"
#include <algorithm>
#include <array>
#include <stdexcept>
#include <string>
#include <windows.h>
#include <winternl.h>

namespace aether::host {
namespace {
constexpr std::uint64_t maximum_file = 1024 * 1024;
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
    };
    HANDLE root = INVALID_HANDLE_VALUE;
    std::array<File, 64> files{};
    ~Impl() {
        for (auto &file : files)
            if (file.handle != INVALID_HANDLE_VALUE)
                CloseHandle(file.handle);
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
        NtCreateFile(&handle, access, &attributes, &io, nullptr, FILE_ATTRIBUTE_NORMAL, 0, disposition,
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
FileResult HostFileService::close(int descriptor) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file)
        return {-1, FileError::bad_descriptor};
    const auto handle = file->handle;
    file->handle = INVALID_HANDLE_VALUE;
    return CloseHandle(handle) ? FileResult{0, FileError::none} : FileResult{-1, error(GetLastError())};
}
} // namespace aether::host
