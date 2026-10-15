#include "aether/host/windows/unique_handle.hpp"
#include "aether/security/worker_image.hpp"
#include <aclapi.h>
#include <iostream>
#include <sddl.h>
#include <stdexcept>
#include <string_view>

namespace {
struct Descriptor {
    PSECURITY_DESCRIPTOR value = nullptr;
    explicit Descriptor(const std::wstring &sddl) {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &value,
                                                                  nullptr))
            throw std::runtime_error("Cannot construct runtime installation ACL");
    }
    ~Descriptor() { LocalFree(value); }
    void apply(HANDLE object) const {
        PACL acl = nullptr;
        BOOL present = FALSE, defaulted = FALSE;
        if (!GetSecurityDescriptorDacl(value, &present, &acl, &defaulted) || !present || !acl)
            throw std::runtime_error("Cannot read runtime installation ACL");
        const auto error = SetSecurityInfo(object, SE_FILE_OBJECT,
                                           DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                           nullptr, nullptr, acl, nullptr);
        if (error != ERROR_SUCCESS)
            throw std::runtime_error("Cannot apply runtime installation ACL; Windows error=" +
                                     std::to_string(error));
    }
};
void prepare_directory(const std::filesystem::path &path) {
    using namespace aether;
    if (!path.is_absolute() || path == path.root_path())
        throw std::runtime_error("An absolute non-root runtime directory is required");
    Descriptor policy(security::runtime_directory_sddl());
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), policy.value, FALSE};
    if (!CreateDirectoryW(path.c_str(), &attributes) && GetLastError() != ERROR_ALREADY_EXISTS)
        throw std::runtime_error("Cannot create runtime directory");
    host::UniqueHandle directory(
        CreateFileW(path.c_str(), READ_CONTROL | WRITE_DAC | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    // CMake can create the final output directory before the build step. Only an
    // empty, ordinary, current-user-owned directory may receive initial policy.
    BY_HANDLE_FILE_INFORMATION info{};
    if (!directory || !GetFileInformationByHandle(directory.get(), &info) ||
        !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        throw std::runtime_error("Runtime directory is not an ordinary held directory");
    if (std::filesystem::is_empty(path)) {
        PSID expected = nullptr, owner = nullptr;
        PSECURITY_DESCRIPTOR actual = nullptr;
        BOOL defaulted = FALSE;
        const auto status = GetSecurityInfo(directory.get(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                            &owner, nullptr, nullptr, nullptr, &actual);
        const bool owned = status == ERROR_SUCCESS &&
                           GetSecurityDescriptorOwner(policy.value, &expected, &defaulted) && owner &&
                           expected && EqualSid(owner, expected);
        LocalFree(actual);
        if (!owned)
            throw std::runtime_error("Runtime directory is not owned by this user");
        policy.apply(directory.get());
    }
    security::verify_runtime_directory(directory.get());
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    using namespace aether;
    try {
        if (argc != 3)
            throw std::runtime_error("Usage: aether_runtime_setup --prepare-directory <absolute-directory> | "
                                     "--provision <absolute-runtime.exe> | --verify <absolute-runtime.exe>");
        const std::filesystem::path path(argv[2]);
        if (std::wstring_view(argv[1]) == L"--verify") {
            security::WorkerImage verified(path);
            std::cout << "Aether runtime image: installation policy verified without changes.\n";
            return 0;
        }
        if (std::wstring_view(argv[1]) == L"--prepare-directory") {
            prepare_directory(path);
            std::cout << "Aether runtime directory: protected owner/SYSTEM policy verified.\n";
            return 0;
        }
        if (std::wstring_view(argv[1]) != L"--provision")
            throw std::runtime_error("Unknown runtime setup operation");
        if (!path.is_absolute() || path.extension() != L".exe" ||
            path.filename().wstring().find(L':') != std::wstring::npos)
            throw std::runtime_error("An absolute .exe installation path is required");
        host::UniqueHandle directory(
            CreateFileW(path.parent_path().c_str(), READ_CONTROL | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        security::verify_runtime_directory(directory.get());
        {
            host::UniqueHandle file(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE | WRITE_DAC,
                                                FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                                FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            security::verify_owned_runtime_file(file.get());
            Descriptor(security::worker_image_sddl()).apply(file.get());
        }
        security::WorkerImage verified(path);
        std::cout << "Aether runtime permissions provisioned: protected owner/SYSTEM; AppContainer/LPAC "
                     "read/execute only.\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "AETHER_RUNTIME_SETUP_FAILED: " << error.what() << "; Windows error=" << GetLastError()
                  << '\n';
        return 1;
    }
}
