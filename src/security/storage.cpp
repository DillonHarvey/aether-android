#include "aether/security/storage.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/security/protocol.hpp"
#include <Windows.h>
#include <aclapi.h>
#include <array>
#include <sddl.h>
#include <stdexcept>
#include <vector>

namespace aether::security {
namespace {
using host::UniqueHandle;
struct LocalOwner {
    void *value = nullptr;
    ~LocalOwner() { LocalFree(value); }
};
struct DirectoryLease {
    UniqueHandle semaphore;
    bool owned = false;
    ~DirectoryLease() {
        if (owned)
            ReleaseSemaphore(semaphore.get(), 1, nullptr);
    }
};
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(std::string("AETHER_STORAGE_POLICY: ") + message);
}
bool safe_name(std::string_view name) {
    if (name.empty() || name.size() > 127 || name.front() == '.' || name.back() == '.' ||
        name.find("..") != std::string_view::npos)
        return false;
    for (const auto c : name)
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
            return false;
    return true;
}
void verify_acl(HANDLE object, PSID owner, bool directory) {
    PSID actual_owner = nullptr;
    PACL acl = nullptr;
    LocalOwner actual;
    require(GetSecurityInfo(object, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                            &actual_owner, nullptr, &acl, nullptr,
                            reinterpret_cast<PSECURITY_DESCRIPTOR *>(&actual.value)) == ERROR_SUCCESS &&
                acl && EqualSid(owner, actual_owner),
            "Private storage owner or DACL is invalid");
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    require(GetSecurityDescriptorControl(actual.value, &control, &revision) &&
                (!directory || (control & SE_DACL_PROTECTED)) && acl->AceCount == 2,
            "Private storage DACL is not the protected broker policy");
    std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> system{};
    DWORD sid_size = static_cast<DWORD>(system.size());
    require(CreateWellKnownSid(WinLocalSystemSid, nullptr, system.data(), &sid_size),
            "Cannot obtain SYSTEM SID");
    bool owner_seen = false, system_seen = false;
    for (DWORD index = 0; index < acl->AceCount; ++index) {
        void *raw = nullptr;
        require(GetAce(acl, index, &raw), "Cannot inspect private storage ACE");
        const auto ace = static_cast<ACCESS_ALLOWED_ACE *>(raw);
        require(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
                    (directory ? ace->Header.AceFlags == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
                               : (ace->Header.AceFlags == 0 || ace->Header.AceFlags == INHERITED_ACE)) &&
                    ace->Mask == FILE_ALL_ACCESS,
                "Private storage ACE grants unexpected access");
        auto sid = const_cast<DWORD *>(&ace->SidStart);
        if (EqualSid(sid, owner) && !owner_seen)
            owner_seen = true;
        else if (EqualSid(sid, system.data()) && !system_seen)
            system_seen = true;
        else
            require(false, "Private storage ACE has an unexpected principal");
    }
    require(owner_seen && system_seen, "Private storage ACL is incomplete");
}
} // namespace
struct PrivateStorage::Impl {
    std::filesystem::path path;
    UniqueHandle directory;
    DirectoryLease lease;
    std::unique_ptr<host::HostFileService> files;
    explicit Impl(const std::filesystem::path &root) : path(root) {
        const auto parent = path.parent_path();
        require(path.is_absolute() && !path.filename().empty() && path.filename() != L"." &&
                    path.filename() != L"..",
                "Invalid trusted storage root");
        // The trusted caller supplies an existing final parent. Do not create arbitrary ancestors.
        UniqueHandle parent_handle(CreateFileW(
            parent.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        BY_HANDLE_FILE_INFORMATION parent_info{};
        require(parent_handle && GetFileInformationByHandle(parent_handle.get(), &parent_info) &&
                    (parent_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    !(parent_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT),
                "Parent is not a normal directory");
        HANDLE token_raw = nullptr;
        require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token_raw), "Cannot query storage owner");
        UniqueHandle token(token_raw);
        DWORD length = 0;
        GetTokenInformation(token.get(), TokenUser, nullptr, 0, &length);
        require(length && length <= 65536, "Cannot size owner identity");
        std::vector<std::uint8_t> bytes(length);
        require(GetTokenInformation(token.get(), TokenUser, bytes.data(), length, &length),
                "Cannot read owner identity");
        const auto owner = reinterpret_cast<const TOKEN_USER *>(bytes.data())->User.Sid;
        LocalOwner owner_text;
        require(ConvertSidToStringSidW(owner, reinterpret_cast<LPWSTR *>(&owner_text.value)),
                "Cannot encode owner SID");
        const auto identity = std::wstring(static_cast<const wchar_t *>(owner_text.value));
        const auto sddl =
            L"O:" + identity + L"G:" + identity + L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + identity + L")";
        LocalOwner descriptor;
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.c_str(), SDDL_REVISION_1,
                    reinterpret_cast<PSECURITY_DESCRIPTOR *>(&descriptor.value), nullptr),
                "Cannot construct storage ACL");
        SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), descriptor.value, FALSE};
        if (!CreateDirectoryW(path.c_str(), &security))
            require(GetLastError() == ERROR_ALREADY_EXISTS, "Cannot create private app directory");
        directory.reset(CreateFileW(path.c_str(), READ_CONTROL | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        BY_HANDLE_FILE_INFORMATION info{};
        require(directory && GetFileInformationByHandle(directory.get(), &info) &&
                    (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT),
                "Private storage root is not a normal held directory");
        const auto lease_name =
            L"Local\\Aether.PrivateStorage." + std::to_wstring(info.dwVolumeSerialNumber) + L"." +
            std::to_wstring(info.nFileIndexHigh) + L"." + std::to_wstring(info.nFileIndexLow);
        lease.semaphore.reset(CreateSemaphoreW(nullptr, 1, 1, lease_name.c_str()));
        require(lease.semaphore && WaitForSingleObject(lease.semaphore.get(), 0) == WAIT_OBJECT_0,
                "Private storage already has a live broker owner");
        lease.owned = true;
        verify_acl(directory.get(), owner, true);
        files = std::make_unique<host::HostFileService>(path);
        require(count_names() <= maximum_names, "Private storage already exceeds its file quota");
        // Existing files can have explicit ACLs that do not inherit the protected root policy.
        // Inspect every bounded child before permitting any worker to use this storage.
        for (const auto &entry : std::filesystem::directory_iterator(path)) {
            require(safe_name(entry.path().filename().string()), "Private storage has an unsupported name");
            UniqueHandle file(CreateFileW(
                entry.path().c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            BY_HANDLE_FILE_INFORMATION file_info{};
            LARGE_INTEGER file_size{};
            require(file && GetFileType(file.get()) == FILE_TYPE_DISK &&
                        GetFileInformationByHandle(file.get(), &file_info) &&
                        !(file_info.dwFileAttributes &
                          (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
                        file_info.nNumberOfLinks == 1 && GetFileSizeEx(file.get(), &file_size) &&
                        file_size.QuadPart >= 0 && file_size.QuadPart <= 1024 * 1024,
                    "Private storage has an unsafe or oversized existing file");
            verify_acl(file.get(), owner, false);
        }
    }
    std::size_t count_names() const {
        std::size_t count = 0;
        for (const auto &entry : std::filesystem::directory_iterator(path)) {
            (void)entry;
            if (++count > maximum_names)
                break;
        }
        return count;
    }
};
PrivateStorage::PrivateStorage(const std::filesystem::path &parent, std::uint64_t app_id)
    : PrivateStorage([&] {
          require(app_id != 0, "Invalid trusted app identity");
          return parent / (L"app_" + std::to_wstring(app_id));
      }()) {}
PrivateStorage::PrivateStorage(const std::filesystem::path &root) : impl_(std::make_unique<Impl>(root)) {}
PrivateStorage::~PrivateStorage() = default;
const std::filesystem::path &PrivateStorage::root() const noexcept { return impl_->path; }
host::FileResult PrivateStorage::open(std::string_view name, host::FileOpen options) {
    if (!safe_name(name))
        return {-1, host::FileError::denied};
    try {
        if (options.create && !std::filesystem::exists(impl_->path / std::string(name)) &&
            impl_->count_names() >= maximum_names)
            return {-1, host::FileError::quota};
        return impl_->files->open(name, options);
    } catch (...) {
        return {-1, host::FileError::io};
    }
}
host::FileResult PrivateStorage::read(int descriptor, std::span<std::uint8_t> output) noexcept {
    return impl_->files->read(descriptor, output);
}
host::FileResult PrivateStorage::write(int descriptor, std::span<const std::uint8_t> input) noexcept {
    return impl_->files->write(descriptor, input);
}
host::FileResult PrivateStorage::close(int descriptor) noexcept { return impl_->files->close(descriptor); }
} // namespace aether::security
