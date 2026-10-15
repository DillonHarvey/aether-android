#include "aether/security/worker_image.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/security/protocol.hpp"
#include <aclapi.h>
#include <algorithm>
#include <array>
#include <sddl.h>

namespace aether::security {
namespace {
using host::UniqueHandle;
constexpr DWORD read_execute = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
constexpr DWORD unsafe_access = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                                FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(
            std::string("AETHER_WORKER_IMAGE: ") + message +
            "; reinstall or rebuild the trusted runtime; Windows error=" + std::to_string(GetLastError()));
}
struct LocalOwner {
    void *value = nullptr;
    ~LocalOwner() { LocalFree(value); }
};
std::vector<std::uint8_t> user_sid() {
    HANDLE raw = nullptr;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw), "Cannot query runtime owner");
    UniqueHandle token(raw);
    DWORD size = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
    require(size && size <= 65536, "Cannot size runtime owner");
    std::vector<std::uint8_t> bytes(size);
    require(GetTokenInformation(token.get(), TokenUser, bytes.data(), size, &size),
            "Cannot read runtime owner");
    const auto sid = reinterpret_cast<const TOKEN_USER *>(bytes.data())->User.Sid;
    std::vector<std::uint8_t> copy(GetLengthSid(sid));
    require(CopySid(static_cast<DWORD>(copy.size()), copy.data(), sid), "Cannot retain runtime owner");
    return copy;
}
struct Descriptor {
    LocalOwner allocation;
    PSID owner = nullptr;
    PACL acl = nullptr;
    explicit Descriptor(HANDLE handle) {
        require(GetSecurityInfo(
                    handle, SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    &owner, nullptr, &acl, nullptr,
                    reinterpret_cast<PSECURITY_DESCRIPTOR *>(&allocation.value)) == ERROR_SUCCESS &&
                    owner && acl && IsValidSid(owner) && IsValidAcl(acl) && acl->AceCount <= 64,
                "Missing or invalid runtime owner/DACL");
    }
};
bool well_known(PSID sid, WELL_KNOWN_SID_TYPE type) { return IsWellKnownSid(sid, type) != FALSE; }
bool package(PSID sid, DWORD last) {
    const SID_IDENTIFIER_AUTHORITY authority = SECURITY_APP_PACKAGE_AUTHORITY;
    return *GetSidSubAuthorityCount(sid) == 2 &&
           std::equal(std::begin(authority.Value), std::end(authority.Value),
                      GetSidIdentifierAuthority(sid)->Value) &&
           *GetSidSubAuthority(sid, 0) == SECURITY_APP_PACKAGE_BASE_RID &&
           *GetSidSubAuthority(sid, 1) == last;
}
const ACCESS_ALLOWED_ACE &ace_at(PACL acl, DWORD index) {
    void *raw = nullptr;
    require(GetAce(acl, index, &raw), "Cannot inspect runtime ACE");
    const auto &ace = *static_cast<const ACCESS_ALLOWED_ACE *>(raw);
    require((ace.Header.AceType == ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceType == ACCESS_DENIED_ACE_TYPE) &&
                ace.Header.AceSize >= sizeof(ACCESS_ALLOWED_ACE),
            "Unsupported runtime ACE form");
    const auto sid = const_cast<DWORD *>(&ace.SidStart);
    require(IsValidSid(sid) &&
                GetLengthSid(sid) <= ace.Header.AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart),
            "Invalid runtime ACE identity");
    return ace;
}
void verify_image_acl(HANDLE file) {
    Descriptor descriptor(file);
    const auto owner = user_sid();
    require(EqualSid(descriptor.owner, const_cast<std::uint8_t *>(owner.data())), "Unexpected runtime owner");
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    require(GetSecurityDescriptorControl(descriptor.allocation.value, &control, &revision) &&
                (control & SE_DACL_PROTECTED) && descriptor.acl->AceCount == 4,
            "Worker image lacks the protected installation policy");
    unsigned seen = 0;
    for (DWORD index = 0; index < descriptor.acl->AceCount; ++index) {
        const auto &ace = ace_at(descriptor.acl, index);
        require(ace.Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceFlags == 0,
                "Worker image has unexpected inherited or deny entries");
        auto sid = const_cast<DWORD *>(&ace.SidStart);
        unsigned bit = 0;
        DWORD expected = FILE_ALL_ACCESS;
        if (EqualSid(sid, const_cast<std::uint8_t *>(owner.data())))
            bit = 1;
        else if (well_known(sid, WinLocalSystemSid))
            bit = 2;
        else if (package(sid, SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE)) {
            bit = 4;
            expected = read_execute;
        } else if (package(sid, SECURITY_BUILTIN_PACKAGE_ANY_RESTRICTED_PACKAGE)) {
            bit = 8;
            expected = read_execute;
        }
        require(bit && !(seen & bit) && ace.Mask == expected, "Worker image grants unexpected access");
        seen |= bit;
    }
    require(seen == 15, "Worker installation policy is incomplete");
}
DWORD maximum_access(HANDLE handle, HANDLE token) {
    Descriptor descriptor(handle);
    GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    std::array<std::uint8_t, 4096> privileges{};
    DWORD size = static_cast<DWORD>(privileges.size()), granted = 0;
    BOOL allowed = FALSE;
    require(AccessCheck(descriptor.allocation.value, token, MAXIMUM_ALLOWED, &mapping,
                        reinterpret_cast<PRIVILEGE_SET *>(privileges.data()), &size, &granted, &allowed),
            "Cannot inspect worker image access");
    return allowed ? granted : 0;
}
} // namespace
std::wstring worker_image_sddl() {
    auto owner = user_sid();
    LocalOwner text;
    require(ConvertSidToStringSidW(owner.data(), reinterpret_cast<LPWSTR *>(&text.value)),
            "Cannot encode runtime owner");
    return L"D:P(A;;FA;;;SY)(A;;FA;;;" + std::wstring(static_cast<const wchar_t *>(text.value)) +
           L")(A;;FRFX;;;S-1-15-2-1)(A;;FRFX;;;S-1-15-2-2)";
}
std::wstring runtime_directory_sddl() {
    auto owner = user_sid();
    LocalOwner text;
    require(ConvertSidToStringSidW(owner.data(), reinterpret_cast<LPWSTR *>(&text.value)),
            "Cannot encode runtime owner");
    const auto identity = std::wstring(static_cast<const wchar_t *>(text.value));
    return L"O:" + identity + L"G:" + identity + L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + identity + L")";
}
void verify_owned_runtime_file(HANDLE file) {
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    require(file && file != INVALID_HANDLE_VALUE && GetFileType(file) == FILE_TYPE_DISK &&
                GetFileInformationByHandle(file, &info) && info.nNumberOfLinks == 1 &&
                !(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) &&
                GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= 1024LL * 1024 * 1024,
            "Worker image is not a bounded regular single-link file");
    Descriptor descriptor(file);
    const auto owner = user_sid();
    require(EqualSid(descriptor.owner, const_cast<std::uint8_t *>(owner.data())),
            "Runtime file is not owned by this user");
}
void verify_runtime_directory(HANDLE directory) {
    BY_HANDLE_FILE_INFORMATION info{};
    require(directory && directory != INVALID_HANDLE_VALUE && GetFileType(directory) == FILE_TYPE_DISK &&
                GetFileInformationByHandle(directory, &info) &&
                (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT),
            "Runtime parent is not a normal directory");
    Descriptor descriptor(directory);
    const auto owner = user_sid();
    require(EqualSid(descriptor.owner, const_cast<std::uint8_t *>(owner.data())),
            "Runtime directory is not owned by this user");
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    require(GetSecurityDescriptorControl(descriptor.allocation.value, &control, &revision) &&
                (control & SE_DACL_PROTECTED) && descriptor.acl->AceCount == 2,
            "Runtime directory lacks the protected installation policy");
    unsigned seen = 0;
    for (DWORD index = 0; index < descriptor.acl->AceCount; ++index) {
        const auto &ace = ace_at(descriptor.acl, index);
        require(ace.Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
                    ace.Header.AceFlags == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) &&
                    ace.Mask == FILE_ALL_ACCESS,
                "Runtime directory has unexpected access entries");
        auto sid = const_cast<DWORD *>(&ace.SidStart);
        const unsigned bit = EqualSid(sid, const_cast<std::uint8_t *>(owner.data())) ? 1u
                             : well_known(sid, WinLocalSystemSid)                    ? 2u
                                                                                     : 0u;
        require(bit && !(seen & bit), "Runtime directory has an unexpected principal");
        seen |= bit;
    }
    require(seen == 3, "Runtime directory policy is incomplete");
}
struct WorkerImage::Impl {
    UniqueHandle directory, file;
    BY_HANDLE_FILE_INFORMATION identity{};
    explicit Impl(const std::filesystem::path &path) {
        require(path.is_absolute() && path.extension() == L".exe" &&
                    path.filename().wstring().find(L':') == std::wstring::npos,
                "Invalid runtime image path");
        directory.reset(CreateFileW(path.parent_path().c_str(),
                                    READ_CONTROL | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        verify_runtime_directory(directory.get());
        file.reset(CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        verify_owned_runtime_file(file.get());
        verify_image_acl(file.get());
        require(GetFileInformationByHandle(file.get(), &identity), "Cannot retain runtime image identity");
    }
};
WorkerImage::WorkerImage(const std::filesystem::path &path) : impl_(std::make_unique<Impl>(path)) {}
WorkerImage::~WorkerImage() = default;
WorkerImageAccess WorkerImage::verify_process(HANDLE process) const {
    verify_owned_runtime_file(impl_->file.get());
    verify_image_acl(impl_->file.get());
    verify_runtime_directory(impl_->directory.get());
    std::array<wchar_t, 32768> path{};
    DWORD length = static_cast<DWORD>(path.size());
    require(QueryFullProcessImageNameW(process, 0, path.data(), &length),
            "Cannot inspect launched image path");
    UniqueHandle launched(CreateFileW(path.data(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
                                      OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    BY_HANDLE_FILE_INFORMATION actual{};
    require(launched && GetFileInformationByHandle(launched.get(), &actual) &&
                actual.dwVolumeSerialNumber == impl_->identity.dwVolumeSerialNumber &&
                actual.nFileIndexHigh == impl_->identity.nFileIndexHigh &&
                actual.nFileIndexLow == impl_->identity.nFileIndexLow,
            "Launched image differs from the held runtime file");
    HANDLE token_raw = nullptr, duplicate_raw = nullptr;
    require(OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &token_raw),
            "Cannot inspect worker token");
    UniqueHandle token(token_raw);
    require(DuplicateTokenEx(token.get(), TOKEN_QUERY, nullptr, SecurityIdentification, TokenImpersonation,
                             &duplicate_raw),
            "Cannot inspect worker image permissions");
    UniqueHandle duplicate(duplicate_raw);
    const WorkerImageAccess access{maximum_access(impl_->file.get(), duplicate.get()),
                                   maximum_access(impl_->directory.get(), duplicate.get())};
    if (access.file != read_execute || (access.directory & unsafe_access))
        throw ProtocolError("AETHER_WORKER_IMAGE: unexpected effective image/directory access " +
                            std::to_string(access.file) + "/" + std::to_string(access.directory));
    return access;
}
} // namespace aether::security
