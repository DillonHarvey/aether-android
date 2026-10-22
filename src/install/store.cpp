#include "aether/install/store.hpp"
#include "aether/apk/compatibility.hpp"
#include "aether/apk/launcher.hpp"
#include "aether/apk/package.hpp"
#include "aether/apk/preview.hpp"
#include "aether/common/prefix_strings.hpp"
#include "aether/common/text.hpp"
#include "aether/dex/fixture_hash.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/install/diagnostics.hpp"
#include "aether/install/runtime.hpp"
#include "aether/install/shell.hpp"
#include "aether/security/storage.hpp"
#include "aether/security/worker_image.hpp"
#include "private.hpp"
#include <Windows.h>
#include <aclapi.h>
#include <algorithm>
#include <array>
#include <bcrypt.h>
#include <cstring>
#include <future>
#include <map>
#include <sddl.h>
#include <shlobj.h>
#include <sstream>
#include <userenv.h>

namespace aether::install {
namespace {
using host::UniqueHandle;
constexpr std::size_t frame_size = 4096, digest_offset = frame_size - 64;
constexpr std::size_t maximum_records = 4096;
constexpr std::uint64_t maximum_package = UINT64_MAX;
constexpr std::string_view magic = "AETHREG1";
void require(bool value, std::string_view code, const char *message) {
    if (!value)
        throw InstallError(std::string(code), message);
}
void io(bool value, const char *message) { require(value, "AETHER_INSTALL_IO", message); }
void corrupt(bool value) {
    require(value, "AETHER_INSTALL_REGISTRY_CORRUPT", "Package registry failed format or integrity checks");
}
bool hex(std::string_view text, std::size_t size) {
    return text.size() == size && std::all_of(text.begin(), text.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}
bool package_name(std::string_view value) {
    if (value.empty() || value.size() > 223 || value.front() == '.' || value.back() == '.')
        return false;
    bool segment_start = true, separator = false;
    for (const auto c : value) {
        if (c == '.') {
            if (segment_start)
                return false;
            segment_start = true;
            separator = true;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
                  (!segment_start && c >= '0' && c <= '9')))
                return false;
            segment_start = false;
        }
    }
    return separator;
}
std::string_view state_name(State state) {
    switch (state) {
    case State::preparing:
        return "preparing";
    case State::installed:
        return "installed";
    case State::removing:
        return "removing";
    case State::removed:
        return "removed";
    case State::data_retained:
        return "data-retained";
    case State::installing_windows:
        return "installing-windows";
    case State::updating:
        return "updating";
    case State::update_committed:
        return "installed-update-cleanup-pending";
    case State::update_rolled_back:
        return "installed-rollback-cleanup-pending";
    }
    throw InstallError("AETHER_INSTALL_REGISTRY_CORRUPT", "Unknown installation state");
}
struct Descriptor {
    PSECURITY_DESCRIPTOR value = nullptr;
    explicit Descriptor(bool directory) {
        auto sddl = security::runtime_directory_sddl();
        if (!directory) {
            for (auto index = sddl.find(L";OICI;"); index != std::wstring::npos; index = sddl.find(L";OICI;"))
                sddl.replace(index, 6, L";;");
        }
        io(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &value,
                                                                nullptr) != FALSE,
           "Cannot create private package-store policy");
    }
    ~Descriptor() { LocalFree(value); }
    Descriptor(const Descriptor &) = delete;
    Descriptor &operator=(const Descriptor &) = delete;
};
void verify_file(HANDLE file, std::uint64_t limit, bool broker_file = false) {
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    require(GetFileType(file) == FILE_TYPE_DISK && GetFileInformationByHandle(file, &info) &&
                !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
                info.nNumberOfLinks == 1 && GetFileSizeEx(file, &size) && size.QuadPart >= 0 &&
                static_cast<std::uint64_t>(size.QuadPart) <= limit,
            "AETHER_INSTALL_PATH", "Store file is not a bounded regular single-link file");
    PSECURITY_DESCRIPTOR raw = nullptr;
    PSID owner = nullptr;
    PACL acl = nullptr;
    const auto status =
        GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
                        nullptr, &acl, nullptr, &raw);
    struct Release {
        PSECURITY_DESCRIPTOR value;
        ~Release() { LocalFree(value); }
    } release{raw};
    Descriptor expected(false);
    PSID expected_owner = nullptr;
    PACL expected_acl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    require(status == ERROR_SUCCESS && raw && owner && acl &&
                GetSecurityDescriptorOwner(expected.value, &expected_owner, &defaulted) &&
                GetSecurityDescriptorDacl(expected.value, &present, &expected_acl, &defaulted) &&
                EqualSid(owner, expected_owner) && GetSecurityDescriptorControl(raw, &control, &revision) &&
                (broker_file || (control & SE_DACL_PROTECTED)) && acl->AceCount == expected_acl->AceCount &&
                acl->AclSize == expected_acl->AclSize,
            "AETHER_INSTALL_POLICY", "Store file does not have the protected owner/SYSTEM policy");
    for (DWORD index = 0; index < acl->AceCount; ++index) {
        void *actual_raw = nullptr, *expected_raw = nullptr;
        io(GetAce(acl, index, &actual_raw) && GetAce(expected_acl, index, &expected_raw),
           "Cannot inspect store file policy");
        const auto *actual = static_cast<const ACCESS_ALLOWED_ACE *>(actual_raw);
        const auto *wanted = static_cast<const ACCESS_ALLOWED_ACE *>(expected_raw);
        require(
            actual->Header.AceType == wanted->Header.AceType &&
                actual->Header.AceSize == wanted->Header.AceSize &&
                (actual->Header.AceFlags == 0 || (broker_file && actual->Header.AceFlags == INHERITED_ACE)) &&
                actual->Mask == wanted->Mask &&
                EqualSid(const_cast<DWORD *>(&actual->SidStart), const_cast<DWORD *>(&wanted->SidStart)),
            "AETHER_INSTALL_POLICY", "Store file grants unexpected access");
    }
}
UniqueHandle open_directory(const std::filesystem::path &path, bool create, bool private_policy) {
    if (create) {
        Descriptor descriptor(true);
        SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor.value, FALSE};
        if (!CreateDirectoryW(path.c_str(), &attributes))
            io(GetLastError() == ERROR_ALREADY_EXISTS, "Cannot create the final package directory");
    }
    UniqueHandle handle(CreateFileW(path.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    BY_HANDLE_FILE_INFORMATION info{};
    require(handle && GetFileInformationByHandle(handle.get(), &info) &&
                (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT),
            "AETHER_INSTALL_PATH",
            "Store paths must be existing ordinary directories without junctions or links");
    if (private_policy) {
        try {
            security::verify_runtime_directory(handle.get());
        } catch (const std::exception &) {
            throw InstallError("AETHER_INSTALL_POLICY",
                               "Directory does not have the protected owner/SYSTEM policy");
        }
    }
    return handle;
}
bool missing(const std::filesystem::path &path) {
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
        return false;
    const auto error = GetLastError();
    io(error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND, "Cannot inspect package-store path");
    return true;
}
UniqueHandle open_file(const std::filesystem::path &path, DWORD access, DWORD creation, std::uint64_t limit,
                       DWORD sharing = 0, bool broker_file = false) {
    Descriptor descriptor(false);
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor.value, FALSE};
    UniqueHandle handle(CreateFileW(path.c_str(), access | READ_CONTROL, sharing, &attributes, creation,
                                    FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!handle) {
        const auto error = GetLastError();
        require(error != ERROR_SHARING_VIOLATION, "AETHER_INSTALL_BUSY",
                "Another operation holds this package store or file");
        throw InstallError("AETHER_INSTALL_IO", "Cannot open the final package-store file");
    }
    verify_file(handle.get(), limit, broker_file);
    return handle;
}
std::vector<std::uint8_t> read_all(HANDLE file) {
    LARGE_INTEGER size{}, zero{};
    io(GetFileSizeEx(file, &size) && size.QuadPart >= 0 && SetFilePointerEx(file, zero, nullptr, FILE_BEGIN),
       "Cannot read package-store file size");
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
    for (std::size_t offset = 0; offset < bytes.size();) {
        const auto count = static_cast<DWORD>((std::min)(bytes.size() - offset, std::size_t{1024 * 1024}));
        DWORD read = 0;
        io(ReadFile(file, bytes.data() + offset, count, &read, nullptr) && read > 0,
           "Package-store read was incomplete");
        offset += read;
    }
    return bytes;
}
void write_durable(HANDLE file, apk::Bytes bytes) {
    for (std::size_t offset = 0; offset < bytes.size();) {
        const auto count = static_cast<DWORD>((std::min)(bytes.size() - offset, std::size_t{1024 * 1024}));
        DWORD written = 0;
        io(WriteFile(file, bytes.data() + offset, count, &written, nullptr) && written > 0,
           "Package-store write was incomplete; use explicit repair before retrying");
        offset += written;
    }
    io(FlushFileBuffers(file) != FALSE,
       "Package-store flush failed; commit outcome is uncertain; inspect before retrying");
}
InstalledApp from_inspection(const apk::InspectResult &value, bool retained_record = false) {
    InstalledApp app;
    app.format = value.format;
    app.package_id = value.manifest.package_id;
    app.version_name = value.manifest.version_name;
    app.version_code = value.manifest.version_code.value_or(0);
    app.min_sdk = value.manifest.min_sdk.value_or(0);
    app.target_sdk = value.manifest.target_sdk.value_or(0);
    app.sha256 = value.sha256;
    app.package_bytes = value.archive_bytes;
    app.declared_permissions = value.manifest.permissions;
    auto selection = apk::select_launcher(value.manifest);
    // Earlier releases committed the sole declared launch class without static
    // eligibility checks. Keep those intact records inspectable/repairable;
    // new admission and held execution still require the current selector.
    // This is only a metadata comparison, never a launch fallback or a write.
    if (retained_record && !selection.activity && selection.declared == 1) {
        const auto declared = std::find_if(value.manifest.activities.begin(), value.manifest.activities.end(),
                                           [](const auto &activity) { return activity.launcher; });
        selection.activity = static_cast<std::size_t>(declared - value.manifest.activities.begin());
    }
    if (selection.activity) {
        const auto &activity = value.manifest.activities[*selection.activity];
        app.activity = activity.target.empty() ? activity.name : activity.target;
    }
    return app;
}
bool valid_signing(const InstalledApp &app) {
    if (app.format > apk::PackageFormat::xapk ||
        (app.format == apk::PackageFormat::xapk) != (app.signing == SigningState::verified_set))
        return false;
    if (!verified_signing(app.signing))
        return app.signing <= SigningState::unsupported && app.signer_certificates.empty();
    const auto &certificates = app.signer_certificates;
    return !certificates.empty() &&
           certificates.size() <= (app.signing == SigningState::verified_v3 ? 1u : 8u) &&
           (app.signing != SigningState::verified_v31 || certificates.size() == 2) &&
           std::all_of(certificates.begin(), certificates.end(),
                       [](const auto &value) { return hex(value, 64); }) &&
           std::is_sorted(certificates.begin(), certificates.end()) &&
           std::adjacent_find(certificates.begin(), certificates.end()) == certificates.end();
}
void record_signing(InstalledApp &app, const apk::SignatureReport &report) {
    require(report.status == "verified" || report.status == "unverified" || report.status == "unsupported",
            "AETHER_INSTALL_SIGNING_IDENTITY", "Unknown signing verification result");
    app.signing = report.verified()                ? (report.scheme == "apk-set" ? SigningState::verified_set
                                                      : report.scheme == "v3.1"  ? SigningState::verified_v31
                                                      : report.scheme == "v3"    ? SigningState::verified_v3
                                                                                 : SigningState::verified_v2)
                  : report.status == "unsupported" ? SigningState::unsupported
                                                   : SigningState::unverified;
    app.signer_certificates.clear();
    if (report.verified()) {
        require(report.scheme == "v2" || report.scheme == "v3" || report.scheme == "v3.1" ||
                    report.scheme == "apk-set",
                "AETHER_INSTALL_SIGNING_IDENTITY", "Unsupported verified signing scheme");
        for (const auto &signer : report.signers)
            app.signer_certificates.push_back(signer.certificate_sha256);
        std::sort(app.signer_certificates.begin(), app.signer_certificates.end());
    }
    require(valid_signing(app), "AETHER_INSTALL_SIGNING_IDENTITY", "Invalid verified signer identity set");
}
bool same_signing(const InstalledApp &left, const InstalledApp &right) {
    return left.signing == right.signing && left.signer_certificates == right.signer_certificates;
}
bool same_verified_identity(const InstalledApp &left, const InstalledApp &right) {
    return verified_signing(left.signing) && verified_signing(right.signing) &&
           left.signer_certificates == right.signer_certificates;
}
void verify_recorded_signing(const InstalledApp &app, const apk::SignatureReport &report) {
    // Old history stays unrecorded. A read or permission edit must not silently
    // promote a legacy installation into a persisted verified identity.
    if (app.signing == SigningState::not_recorded)
        return;
    InstalledApp actual;
    actual.format = app.format;
    record_signing(actual, report);
    // Older runtimes recorded v3/v3.1 as unsupported. The held bytes are still
    // checksum-bound; stronger verification must not rewrite that history.
    if (app.signing == SigningState::unsupported &&
        (actual.signing == SigningState::verified_v3 || actual.signing == SigningState::verified_v31))
        return;
    require(same_signing(app, actual), "AETHER_INSTALL_SIGNING_IDENTITY",
            "Installed APK signing identity differs from its committed signer record");
}
struct Encoder {
    std::array<std::uint8_t, frame_size> bytes{};
    std::size_t offset = 0;
    void number(std::uint64_t value) {
        corrupt(offset + 8 <= digest_offset);
        for (unsigned n = 0; n < 8; ++n)
            bytes[offset++] = static_cast<std::uint8_t>(value >> (n * 8));
    }
    void text(std::string_view value) {
        number(value.size());
        corrupt(value.size() <= 512 && value.size() <= digest_offset - offset);
        std::copy(value.begin(), value.end(), bytes.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += value.size();
    }
    void block(apk::Bytes value) {
        corrupt(value.size() <= digest_offset - offset);
        std::copy(value.begin(), value.end(), bytes.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += value.size();
    }
    void fingerprint(std::string_view value) {
        corrupt(hex(value, 64) && offset + 32 <= digest_offset);
        const auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        for (std::size_t index = 0; index < value.size(); index += 2)
            bytes[offset++] = static_cast<std::uint8_t>((digit(value[index]) << 4) | digit(value[index + 1]));
    }
};
struct Decoder {
    apk::Bytes bytes;
    std::size_t offset = 0;
    std::uint64_t number() {
        corrupt(offset + 8 <= digest_offset);
        std::uint64_t value = 0;
        for (unsigned n = 0; n < 8; ++n)
            value |= static_cast<std::uint64_t>(bytes[offset++]) << (n * 8);
        return value;
    }
    std::uint32_t u32() {
        const auto value = number();
        corrupt(value <= UINT32_MAX);
        return static_cast<std::uint32_t>(value);
    }
    std::string text() {
        const auto size = number();
        corrupt(size <= 512 && size <= digest_offset - offset);
        std::string result(reinterpret_cast<const char *>(bytes.data() + offset),
                           static_cast<std::size_t>(size));
        offset += static_cast<std::size_t>(size);
        return result;
    }
    std::string fingerprint() {
        corrupt(offset + 32 <= digest_offset);
        constexpr char digits[] = "0123456789abcdef";
        std::string result;
        for (unsigned index = 0; index < 32; ++index) {
            const auto value = bytes[offset++];
            result += digits[value >> 4];
            result += digits[value & 15];
        }
        return result;
    }
};
void metadata(Encoder &out, const InstalledApp &app) {
    out.text(app.id);
    out.text(app.package_id);
    out.text(app.version_name);
    out.text(app.activity);
    out.text(app.sha256);
    out.number(app.version_code);
    out.number(app.min_sdk);
    out.number(app.target_sdk);
    out.number(app.package_bytes);
    out.number(app.declared_permissions.size());
    try {
        out.block(encode_prefix_strings(app.declared_permissions));
    } catch (const std::invalid_argument &) {
        corrupt(false);
    }
}
InstalledApp metadata(Decoder &in, std::uint64_t schema) {
    InstalledApp app;
    app.id = in.text();
    app.package_id = in.text();
    app.version_name = in.text();
    app.activity = in.text();
    app.sha256 = in.text();
    app.version_code = in.u32();
    app.min_sdk = in.u32();
    app.target_sdk = in.u32();
    app.package_bytes = in.number();
    const auto count = in.number();
    if (schema >= 9) {
        try {
            auto decoded = decode_prefix_strings(in.bytes.subspan(in.offset, digest_offset - in.offset),
                                                 static_cast<std::size_t>(count));
            in.offset += decoded.consumed;
            app.declared_permissions = std::move(decoded.values);
        } catch (const std::invalid_argument &) {
            corrupt(false);
        }
    } else {
        corrupt(count <= 32);
        for (std::uint64_t n = 0; n < count; ++n)
            app.declared_permissions.push_back(in.text());
    }
    // A future fixture rebuild must not prevent reading/removing older records.
    // Admission applies at install (and eventually launch), not history decoding.
    corrupt(valid_app_id(app.id) && package_name(app.package_id) && hex(app.sha256, 64) &&
            app.package_bytes && app.package_bytes <= maximum_package);
    return app;
}
bool same_metadata(const InstalledApp &left, const InstalledApp &right) {
    Encoder a, b;
    metadata(a, left);
    metadata(b, right);
    return a.bytes == b.bytes && left.package_generation == right.package_generation &&
           left.format == right.format;
}
bool same_shell(const InstalledApp &left, const InstalledApp &right, bool compare_state = true) {
    return (!compare_state || left.shell == right.shell) && left.display_name == right.display_name &&
           left.shortcut_name == right.shortcut_name && left.launcher == right.launcher &&
           left.icon_sha256 == right.icon_sha256 && left.icon_generation == right.icon_generation &&
           left.icon_renderer == right.icon_renderer;
}
void clear_shell(InstalledApp &app) {
    app.shell = ShellState::none;
    app.display_name.clear();
    app.shortcut_name.clear();
    app.launcher.clear();
    app.icon_sha256.clear();
    app.icon_generation = 0;
    app.icon_renderer = 1;
    app.shell_verified.reset();
}
std::string new_id() {
    std::array<std::uint8_t, 16> random{};
    io(BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()),
                       BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0,
       "Cannot generate installation identity");
    constexpr char digits[] = "0123456789abcdef";
    std::string id;
    for (const auto byte : random) {
        id += digits[byte >> 4];
        id += digits[byte & 15];
    }
    return id;
}
void delete_file(const std::filesystem::path &path, std::uint64_t limit, bool broker_file = false) {
    if (missing(path))
        return;
    auto file = open_file(path, DELETE | FILE_READ_ATTRIBUTES, OPEN_EXISTING, limit, 0, broker_file);
    FILE_DISPOSITION_INFO disposition{TRUE};
    io(SetFileInformationByHandle(file.get(), FileDispositionInfo, &disposition, sizeof(disposition)) !=
           FALSE,
       "Cannot remove the selected app file");
}
bool data_name(std::wstring_view name, bool app_data = false) {
    if (app_data && name.starts_with(L'@')) name.remove_prefix(1);
    return !name.empty() && name.size() <= 127 && name.front() != L'.' && name.back() != L'.' &&
           name.find(L"..") == std::wstring_view::npos &&
           std::all_of(name.begin(), name.end(), [](wchar_t c) {
               return (c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') || c == L'_' || c == L'-' ||
                      c == L'.';
           });
}
struct AppLease {
    std::unique_ptr<RuntimeUseLease> runtime;
    std::vector<UniqueHandle> ancestors;
    UniqueHandle directory, lock, package;
};
} // namespace

host::UniqueHandle detail::hold_directory(const std::filesystem::path &path, bool create,
                                          bool private_policy) {
    return open_directory(path, create, private_policy);
}
host::UniqueHandle detail::private_file(const std::filesystem::path &path, DWORD access, DWORD creation,
                                        std::uint64_t limit, DWORD sharing, bool inherited) {
    return open_file(path, access, creation, limit, sharing, inherited);
}
std::vector<std::uint8_t> detail::read_contents(HANDLE file) { return read_all(file); }
void detail::replace_contents(HANDLE file, apk::Bytes bytes) {
    LARGE_INTEGER zero{};
    io(SetFilePointerEx(file, zero, nullptr, FILE_BEGIN) != FALSE, "Cannot seek derived icon");
    DWORD written = 0;
    io(WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
           written == bytes.size() && SetEndOfFile(file) && FlushFileBuffers(file),
       "Cannot commit derived icon; inspect the pending registration before explicit repair");
}

InstallError::InstallError(std::string value, std::string message)
    : std::runtime_error(std::move(message)), code(std::move(value)) {}
bool valid_app_id(std::string_view id) noexcept { return security::valid_installed_id(id); }
bool installed_state(State state) noexcept {
    return state == State::installed || state == State::update_committed ||
           state == State::update_rolled_back;
}
std::filesystem::path package_path(const InstalledApp &app, const std::filesystem::path &root) {
    require(valid_app_id(app.id) && app.package_generation <= maximum_records &&
                app.format <= apk::PackageFormat::xapk,
            "AETHER_INSTALL_PATH", "Invalid installed package path identity");
    const auto extension = app.format == apk::PackageFormat::xapk ? ".xapk" : ".apk";
    return root / app.id /
           ((app.package_generation ? "package-" + std::to_string(app.package_generation) : "package") +
            extension);
}
std::filesystem::path app_icon_path(const InstalledApp &app, const std::filesystem::path &root) {
    const auto package = package_path(app, root);
    require(app.icon_generation <= app.package_generation, "AETHER_INSTALL_PATH",
            "Invalid installed icon path identity");
    return package.parent_path() /
           (app.icon_generation ? "app-" + std::to_string(app.icon_generation) + ".ico" : "app.ico");
}
std::filesystem::path default_store_root() {
    PWSTR raw = nullptr;
    const auto result = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &raw);
    struct Release {
        PWSTR value;
        ~Release() { CoTaskMemFree(value); }
    } release{raw};
    io(SUCCEEDED(result) && raw, "Cannot resolve the current user's LocalAppData known folder");
    return std::filesystem::path(raw) / L"Aether";
}
std::string InstalledApp::json() const {
    const auto effective = installed_state(state) ? permissions : 0;
    std::ostringstream out;
    out << "{\"appId\":" << json_quote(id) << ",\"packageId\":" << json_quote(package_id)
        << ",\"packageFormat\":" << json_quote(format == apk::PackageFormat::xapk ? "xapk" : "apk")
        << ",\"displayName\":" << json_quote(display_name.empty() ? package_id : display_name)
        << ",\"versionName\":" << json_quote(version_name) << ",\"versionCode\":" << version_code
        << ",\"minSdk\":" << min_sdk << ",\"targetSdk\":" << target_sdk
        << ",\"activity\":" << json_quote(activity) << ",\"sha256\":" << json_quote(sha256)
        << ",\"packageBytes\":" << package_bytes << ",\"packageGeneration\":" << package_generation
        << ",\"abi\":"
        << json_quote(sha256 == dex::fixture::apk_sha256 ? "arm64-v8a" : "managed-or-arm64-v8a")
        << ",\"state\":" << json_quote(state_name(state))
        << ",\"signatureVerification\":" << json_quote(signing_status(signing))
        << ",\"signingIdentityRecorded\":" << (signing == SigningState::not_recorded ? "false" : "true")
        << ",\"publisherAuthenticated\":false,\"signerCertificatesSha256\":[";
    for (std::size_t index = 0; index < signer_certificates.size(); ++index)
        out << (index ? "," : "") << json_quote(signer_certificates[index]);
    out << "],\"admission\":"
        << json_quote(sha256 == dex::fixture::apk_sha256 ? "exact-first-party-sha256"
                                                         : "isolated-experimental")
        << ",\"developerOnly\":" << (sha256 == dex::fixture::apk_sha256 ? "true" : "false")
        << ",\"launchAvailable\":"
        << (installed_state(state) && shell != ShellState::pending &&
                    (permissions & security::installed_clock)
                ? "true"
                : "false")
        << ",\"windowsRegistration\":"
        << json_quote(shell == ShellState::none      ? "not-registered"
                      : shell == ShellState::pending ? "pending-repair"
                                                     : "registered")
        << ",\"windowsRegistrationVerified\":"
        << (shell_verified ? (*shell_verified ? "true" : "false") : "null")
        << ",\"shortcutName\":" << json_quote(shortcut_name) << ",\"sharedLauncher\":" << json_quote(launcher)
        << ",\"iconSha256\":" << json_quote(icon_sha256) << ",\"iconGeneration\":" << icon_generation
        << ",\"iconRendererVersion\":" << icon_renderer
        << ",\"appUserModelId\":" << json_quote("Aether.App." + id)
        << ",\"uninstallKey\":" << json_quote("Aether.App." + id)
        << ",\"keepData\":" << (keep_data ? "true" : "false")
        << ",\"brokerAppId\":" << json_quote(std::to_string(security::installed_broker_id(id)))
        << ",\"effectivePermissions\":[";
    if (effective & security::installed_clock)
        out << "\"monotonic-clock\"";
    if (effective & security::installed_files)
        out << ((effective & security::installed_clock) ? "," : "") << "\"private-files\"";
    if (effective & security::installed_wall_clock)
        out << ((effective & (security::installed_clock | security::installed_files)) ? "," : "") << "\"wall-clock\"";
    out << "],\"declaredPermissions\":[";
    bool first = true;
    for (const auto &permission : declared_permissions) {
        if (!first)
            out << ',';
        first = false;
        out << json_quote(permission);
    }
    out << "]}";
    return out.str();
}
PreparedInstall PreparedInstall::read(const std::filesystem::path &path) {
    PreparedInstall result;
    apk::InspectLimits limits;
    limits.archive_bytes = maximum_package;
    result.bytes_ = apk::read_package(path, limits);
    const auto bytes = apk::Bytes(result.bytes_);
    const auto format = apk::package_preview_format(bytes, limits);
    require(format != apk::PreviewFormat::apks && format != apk::PreviewFormat::apkm &&
                format != apk::PreviewFormat::aab,
            "AETHER_INSTALL_FORMAT_UNSUPPORTED",
            "APKS, APKM and AAB support preview only; installation is not implemented.");
    auto signing = std::async(std::launch::async, [bytes, format] {
        return apk::verify_package_signature(
            bytes, format == apk::PreviewFormat::xapk ? apk::PackageFormat::xapk : apk::PackageFormat::apk);
    });
    auto report = apk::inspect_package(bytes, limits, {.modern = true, .metadata_preview = true},
                                       apk::ScanScope::installation);
    const auto compatibility = apk::execution_compatibility(report);
    result.preview_ = {std::move(report), compatibility.installable, signing.get(), compatibility.reason};
    return result;
}
InstallPreview preview(const std::filesystem::path &path) { return PreparedInstall::read(path).preview(); }
InstalledApp PreparedInstall::commit(const std::filesystem::path &root, std::uint32_t permissions,
                                     const std::optional<InstalledApp> &current,
                                     const InstallProgress &progress) const {
    require(preview_.installable, "AETHER_INSTALL_UNSUPPORTED", preview_.reason.c_str());
    require(current.has_value() || ((permissions & security::installed_clock) &&
                                    !(permissions & ~security::installed_permission_mask)),
            "AETHER_INSTALL_PERMISSION_REQUIRED", "Monotonic time is required for installed launch");
    PackageStore store(root, current ? PackageStore::Access::existing_write : PackageStore::Access::write);
    if (current) {
        if (progress)
            progress(InstallStage::writing);
        auto result = store.update_bytes(bytes_, preview_, current->id, current->sha256);
        if (progress)
            progress(InstallStage::complete);
        return result;
    }
    return store.install_windows_bytes(bytes_, preview_.inspection, preview_.signing, permissions, progress);
}
std::string InstallPreview::json() const {
    return "{\"schemaVersion\":1,\"operation\":\"install-preview\",\"developerOnly\":false,\"installable\":" +
           std::string(installable ? "true" : "false") + ",\"signatureVerification\":" +
           json_quote(signing.verified() ? (signing.scheme == "apk-set" ? "verified-xapk-set"
                                                                        : "verified-apk-" + signing.scheme)
                                         : signing.status) +
           ",\"executionAvailable\":false,\"reason\":" + json_quote(reason) +
           ",\"inspection\":" + inspection.json(&signing) + "}";
}

struct PackageStore::Impl {
    std::unique_ptr<RuntimeUseLease> runtime;
    std::filesystem::path path;
    Access access;
    std::vector<UniqueHandle> directories;
    UniqueHandle registry;
    std::map<std::string, InstalledApp> apps;
    struct Update {
        InstalledApp previous, candidate;
    };
    std::map<std::string, Update> updates;
    std::string digest = std::string(64, '0');
    std::size_t records = 0, tail = 0;
    std::uint64_t registry_schema = 0;
    bool poisoned = false;
    explicit Impl(const std::filesystem::path &root, Access mode) : path(root), access(mode) {
        if (mode != Access::read)
            runtime = std::make_unique<RuntimeUseLease>(root);
        const auto native = path.wstring();
        require(path.is_absolute() && native.size() >= 4 && native.size() < 200 &&
                    ((native[0] >= L'A' && native[0] <= L'Z') || (native[0] >= L'a' && native[0] <= L'z')) &&
                    native[1] == L':' && (native[2] == L'\\' || native[2] == L'/') &&
                    !path.filename().empty(),
                "AETHER_INSTALL_PATH",
                "Store root must be an absolute local drive path shorter than 200 characters");
        auto ancestor = path.root_path();
        require(GetDriveTypeW(ancestor.c_str()) == DRIVE_FIXED, "AETHER_INSTALL_PATH",
                "Package stores require a local fixed drive");
        std::vector<std::filesystem::path> parts;
        for (const auto &part : path.relative_path()) {
            const auto name = part.wstring();
            require(!name.empty() && name != L"." && name != L".." && name.back() != L'.' &&
                        name.back() != L' ' && name.find_first_of(L":<>\"|?*") == std::wstring::npos &&
                        std::none_of(name.begin(), name.end(), [](wchar_t c) { return c < 32; }),
                    "AETHER_INSTALL_PATH", "Store path contains an unsafe or ambiguous component");
            parts.push_back(part);
        }
        for (std::size_t n = 0; n < parts.size(); ++n) {
            ancestor /= parts[n];
            const bool last = n + 1 == parts.size();
            if (last && mode == Access::read && missing(ancestor))
                return;
            directories.push_back(
                open_directory(ancestor, last && (mode == Access::write || mode == Access::recover), last));
        }
        const auto journal_path = path / L"registry.log";
        if (mode == Access::read && missing(journal_path)) {
            require(std::filesystem::is_empty(path), "AETHER_INSTALL_REGISTRY_MISSING",
                    "Nonempty package store has no registry; it cannot be adopted automatically");
            return;
        }
        if (missing(journal_path))
            require(std::filesystem::is_empty(path), "AETHER_INSTALL_REGISTRY_MISSING",
                    "Nonempty package store has no registry; it cannot be adopted automatically");
        registry =
            open_file(journal_path, GENERIC_READ | (mode == Access::read ? 0 : GENERIC_WRITE),
                      (mode == Access::read || mode == Access::existing_write) ? OPEN_EXISTING : OPEN_ALWAYS,
                      maximum_records * frame_size);
        load();
        if (tail && mode != Access::recover)
            throw InstallError(
                "AETHER_INSTALL_REGISTRY_INCOMPLETE",
                "Interrupted final registry frame; use repair --yes before changing the store");
    }
    void writable() const {
        require(access != Access::read && registry && !poisoned && !tail, "AETHER_INSTALL_STATE",
                "Store is read-only or needs recovery after an uncertain write");
    }
    void settled() const {
        writable();
        require(updates.empty(), "AETHER_UPDATE_RECOVERY_REQUIRED",
                "An update needs explicit repair before another store write");
    }
    void transition(const InstalledApp &app, bool apply = true, bool legacy_icons = false,
                    bool legacy_artwork = false, bool legacy_compiled = false) {
        corrupt(!(app.permissions & ~security::installed_permission_mask));
        corrupt(valid_shell_record(app));
        corrupt(valid_signing(app) && app.package_generation <= maximum_records);
        const auto previous = apps.find(app.id);
        if (previous == apps.end()) {
            corrupt(
                !app.keep_data && app.package_generation == 0 && app.shell == ShellState::none &&
                ((app.state == State::preparing && !app.permissions) ||
                 (app.state == State::installing_windows && (app.permissions & security::installed_clock))));
            for (const auto &[id, other] : apps) {
                (void)id;
                // Retained data reserves its package identity until explicitly removed.
                corrupt(other.package_id != app.package_id || other.state == State::removed);
                corrupt(security::installed_broker_id(other.id) != security::installed_broker_id(app.id));
            }
        } else {
            const auto &old = previous->second;
            if (app.state == State::updating) {
                corrupt(updates.empty() && old.state == State::installed && !app.keep_data &&
                        old.shell != ShellState::pending && old.package_id == app.package_id &&
                        app.version_code > old.version_code && app.sha256 != old.sha256 &&
                        app.package_generation == records + 1 && old.permissions == app.permissions &&
                        verified_signing(app.signing) &&
                        (same_verified_identity(old, app) || old.signing == SigningState::not_recorded ||
                         (old.signing == SigningState::unsupported &&
                          (app.signing == SigningState::verified_v3 ||
                           app.signing == SigningState::verified_v31 ||
                           app.signing == SigningState::verified_set))) &&
                        (old.shell == ShellState::none
                             ? app.shell == ShellState::none
                             : app.shell == ShellState::pending && old.launcher == app.launcher &&
                                   old.shortcut_name != app.shortcut_name && !app.icon_sha256.empty() &&
                                   app.icon_renderer == (legacy_artwork ? 1U : legacy_compiled ? 2U : 3U) &&
                                   app.icon_generation == (legacy_icons || old.icon_sha256.empty()
                                                               ? app.package_generation
                                                               : old.icon_generation)));
                for (const auto &[other_id, other] : apps) {
                    (void)other_id;
                    corrupt((other.state == State::installed && other.shell != ShellState::pending) ||
                            other.state == State::removed || other.state == State::data_retained);
                }
                if (apply) {
                    updates.emplace(app.id, Update{old, app});
                    apps[app.id] = app;
                }
                return;
            }
            if (old.state == State::updating) {
                corrupt(updates.contains(app.id));
                const auto &transaction = updates.at(app.id);
                const bool commit =
                    app.state == State::update_committed && same_metadata(old, app) &&
                    same_signing(old, app) && same_shell(old, app, false) &&
                    app.shell == (old.shell == ShellState::none ? ShellState::none : ShellState::ready);
                const bool rollback =
                    app.state == State::update_rolled_back && same_metadata(transaction.previous, app) &&
                    same_signing(transaction.previous, app) && same_shell(transaction.previous, app);
                corrupt((commit || rollback) && !app.keep_data && old.permissions == app.permissions);
                if (apply)
                    apps[app.id] = app;
                return;
            }
            if (old.state == State::update_committed || old.state == State::update_rolled_back) {
                corrupt(updates.contains(app.id) && app.state == State::installed && !app.keep_data &&
                        same_metadata(old, app) && same_signing(old, app) && same_shell(old, app) &&
                        old.permissions == app.permissions);
                if (apply) {
                    updates.erase(app.id);
                    apps[app.id] = app;
                }
                return;
            }
            corrupt(same_metadata(old, app) && same_signing(old, app));
            const bool settings = old.state == State::installed && app.state == State::installed &&
                                  !app.keep_data && old.permissions != app.permissions &&
                                  same_shell(old, app) && app.shell != ShellState::pending;
            const bool registration =
                old.state == State::installed && app.state == State::installed && !app.keep_data &&
                old.permissions == app.permissions &&
                ((old.shell == ShellState::none && app.shell == ShellState::pending &&
                  (legacy_artwork || app.icon_renderer == (legacy_compiled ? 2U : 3U)) &&
                  app.icon_generation == (app.icon_sha256.empty() ? 0 : app.package_generation)) ||
                 (same_shell(old, app, false) && old.shell != app.shell && old.shell != ShellState::none &&
                  app.shell != ShellState::none));
            const bool clearing = old.state == State::removing && app.shell == ShellState::none &&
                                  (app.state == State::removed || app.state == State::data_retained);
            const bool native_plan =
                old.state == State::installing_windows && app.state == State::installing_windows &&
                !app.keep_data && old.permissions == app.permissions && old.shell == ShellState::none &&
                (legacy_artwork || app.icon_renderer == (legacy_compiled ? 2U : 3U)) && app.shell == ShellState::pending;
            const bool native_commit =
                old.state == State::installing_windows && app.state == State::installed && !app.keep_data &&
                old.permissions == app.permissions && old.shell == ShellState::pending &&
                app.shell == ShellState::ready && same_shell(old, app, false);
            corrupt(settings || registration || native_plan || native_commit ||
                    (old.permissions == app.permissions && (same_shell(old, app) || clearing) &&
                     ((old.state == State::preparing &&
                       (app.state == State::installed || app.state == State::removing) && !app.keep_data) ||
                      (old.state == State::installed && app.state == State::removing) ||
                      (old.state == State::installing_windows && app.state == State::removing &&
                       !app.keep_data) ||
                      (old.state == State::data_retained && app.state == State::removing && !app.keep_data) ||
                      (old.state == State::removing && old.keep_data == app.keep_data &&
                       app.state == (app.keep_data ? State::data_retained : State::removed)))));
        }
        if (apply)
            apps[app.id] = app;
    }
    void load() {
        const auto bytes = read_all(registry.get());
        tail = bytes.size() % frame_size;
        for (std::size_t offset = 0; offset + frame_size <= bytes.size(); offset += frame_size) {
            const apk::Bytes frame(bytes.data() + offset, frame_size);
            const std::string stored(reinterpret_cast<const char *>(frame.data() + digest_offset), 64);
            corrupt(hex(stored, 64) && apk::sha256(frame.first(digest_offset)) == stored);
            Decoder in{frame};
            corrupt(in.text() == magic);
            const auto schema = in.number();
            corrupt((schema >= 1 && schema <= 14) && in.number() == records + 1 && in.text() == digest);
            corrupt(schema >= registry_schema);
            const auto state = in.number();
            const auto keep = in.number();
            corrupt(state >= 1 && state <= (schema >= 7 ? 9u : schema >= 5 ? 6u : 5u) && keep <= 1);
            auto app = metadata(in, schema);
            app.permissions = schema >= 2 ? in.u32() : 0;
            if (schema >= 3) {
                app.shell = static_cast<ShellState>(in.u32());
                app.display_name = in.text();
                app.shortcut_name = in.text();
                app.launcher = in.text();
            }
            if (schema >= 4)
                app.icon_sha256 = in.text();
            if (schema >= 6) {
                app.signing = static_cast<SigningState>(in.u32());
                corrupt(app.signing <= (schema >= 12   ? SigningState::verified_set
                                        : schema >= 11 ? SigningState::verified_v31
                                        : schema >= 10 ? SigningState::verified_v3
                                                       : SigningState::verified_v2));
                const auto count = in.number();
                corrupt(count <= 8);
                for (std::uint64_t index = 0; index < count; ++index)
                    app.signer_certificates.push_back(in.fingerprint());
            }
            app.package_generation = schema >= 7 ? in.number() : 0;
            app.icon_generation = schema >= 8               ? in.number()
                                  : app.icon_sha256.empty() ? 0
                                                            : app.package_generation;
            app.format = schema >= 12 ? static_cast<apk::PackageFormat>(in.u32()) : apk::PackageFormat::apk;
            app.icon_renderer = schema >= 13 ? in.u32() : 1;
            app.state = static_cast<State>(state);
            app.keep_data = keep != 0;
            corrupt(std::all_of(frame.begin() + static_cast<std::ptrdiff_t>(in.offset),
                                frame.begin() + digest_offset, [](auto value) { return value == 0; }));
            corrupt(schema >= 14 || app.icon_renderer <= 2);
            transition(app, true, schema < 8, schema < 13, schema < 14);
            digest = stored;
            registry_schema = schema;
            ++records;
        }
    }
    void append(const InstalledApp &app) {
        writable();
        require(records < maximum_records, "AETHER_INSTALL_LIMIT",
                "Package registry record limit reached; no compaction is implemented");
        transition(app, false);
        Encoder out;
        out.text(magic);
        out.number(14);
        out.number(records + 1);
        out.text(digest);
        out.number(static_cast<std::uint32_t>(app.state));
        out.number(app.keep_data ? 1 : 0);
        metadata(out, app);
        out.number(app.permissions);
        out.number(static_cast<std::uint32_t>(app.shell));
        out.text(app.display_name);
        out.text(app.shortcut_name);
        out.text(app.launcher);
        out.text(app.icon_sha256);
        out.number(static_cast<std::uint32_t>(app.signing));
        out.number(app.signer_certificates.size());
        for (const auto &certificate : app.signer_certificates)
            out.fingerprint(certificate);
        out.number(app.package_generation);
        out.number(app.icon_generation);
        out.number(static_cast<std::uint32_t>(app.format));
        out.number(app.icon_renderer);
        const auto next = apk::sha256(apk::Bytes(out.bytes).first(digest_offset));
        std::copy(next.begin(), next.end(), out.bytes.begin() + digest_offset);
        LARGE_INTEGER position{};
        position.QuadPart = static_cast<LONGLONG>(records * frame_size);
        io(SetFilePointerEx(registry.get(), position, nullptr, FILE_BEGIN) != FALSE,
           "Cannot seek package registry");
        poisoned = true;
        write_durable(registry.get(), out.bytes);
        transition(app);
        digest = next;
        registry_schema = 14;
        ++records;
        poisoned = false;
    }
    InstalledApp find(std::string_view id) const {
        require(valid_app_id(id), "AETHER_INSTALL_ID",
                "App ID must be exactly 32 lowercase hexadecimal characters");
        const auto found = apps.find(std::string(id));
        require(found != apps.end(), "AETHER_INSTALL_NOT_FOUND", "No installation has this app ID");
        return found->second;
    }
    apk::SignatureReport validate_package(const InstalledApp &app,
                                          apk::InspectResult *inspected = nullptr) const {
        auto directory = open_directory(path / app.id, false, true);
        auto file =
            open_file(package_path(app, path), GENERIC_READ, OPEN_EXISTING, maximum_package, FILE_SHARE_READ);
        const auto bytes = read_all(file.get());
        require(bytes.size() == app.package_bytes && apk::sha256(bytes) == app.sha256,
                "AETHER_INSTALL_INTEGRITY", "Installed APK differs from the committed package checksum");
        auto inspection =
            apk::inspect_package(bytes, {}, {.modern = app.icon_renderer >= 2,
                                  .metadata_preview = app.icon_renderer >= 3},
                                 inspected ? apk::ScanScope::full : apk::ScanScope::installation);
        auto actual = from_inspection(inspection, true);
        auto signing = apk::verify_package_signature(bytes, inspection.format);
        verify_recorded_signing(app, signing);
        actual.id = app.id;
        actual.package_generation = app.package_generation;
        require(same_metadata(app, actual), "AETHER_INSTALL_INTEGRITY",
                "Stored metadata differs from the installed APK");
        if (inspected)
            *inspected = std::move(inspection);
        return signing;
    }
    void check_update(const InstalledApp &old, const InstallPreview &candidate) const {
        require(old.state == State::installed && old.shell != ShellState::pending, "AETHER_UPDATE_STATE",
                "Update requires a settled installed app; explicitly repair unfinished operations");
        require(candidate.installable, "AETHER_UPDATE_UNSUPPORTED", candidate.reason.c_str());
        require(old.package_id == candidate.inspection.manifest.package_id, "AETHER_UPDATE_PACKAGE",
                "The proposed APK has a different package identity");
        require(candidate.inspection.manifest.version_code.value_or(0) > old.version_code &&
                    candidate.inspection.sha256 != old.sha256,
                "AETHER_UPDATE_VERSION", "An update must have a strictly greater Android version code");
        require(candidate.signing.verified(), "AETHER_UPDATE_SIGNER",
                "Updates require supported verified APK signatures; key-changing updates are unsupported");
        require(verified_signing(old.signing) || old.signing == SigningState::not_recorded ||
                    (old.signing == SigningState::unsupported &&
                     (candidate.signing.scheme == "v3" || candidate.signing.scheme == "v3.1" ||
                      candidate.signing.scheme == "apk-set")),
                "AETHER_UPDATE_SIGNER", "The installed version has no verified signing identity");
        const auto verified = validate_package(old);
        require(verified.verified(), "AETHER_UPDATE_SIGNER",
                "The intact installed APK must also have supported verified APK signatures");
        InstalledApp previous_signing, next_signing;
        previous_signing.format = old.format;
        next_signing.format = candidate.inspection.format;
        record_signing(previous_signing, verified);
        record_signing(next_signing, candidate.signing);
        require(same_verified_identity(previous_signing, next_signing), "AETHER_UPDATE_SIGNER",
                "The complete verified certificate set differs; signing-key rotation is unsupported");
    }
    void restore_update(std::string_view id) {
        auto previous = updates.at(std::string(id)).previous;
        validate_package(previous);
        if (previous.shell != ShellState::none) {
            previous.shell = ShellState::pending;
            apply_shell_update(previous, updates.at(std::string(id)).candidate, path);
            previous.shell = ShellState::ready;
        }
        previous.state = State::update_rolled_back;
        append(previous);
    }
    InstalledApp finish_update(std::string_view id) {
        auto current = find(id);
        require(current.state == State::update_committed || current.state == State::update_rolled_back,
                "AETHER_UPDATE_STATE", "Update cleanup requires a durable version decision");
        const auto transaction = updates.at(current.id);
        const bool committed = current.state == State::update_committed;
        const auto &retired = committed ? transaction.previous : transaction.candidate;
        validate_package(current);
        if (current.shell != ShellState::none) {
            auto projection = current;
            projection.shell = ShellState::pending;
            apply_shell_update(projection, retired, path);
        }
        retire_shell_update(retired, current, path);
        const auto obsolete = package_path(retired, path);
        if (!missing(obsolete)) {
            auto file = open_file(obsolete, GENERIC_READ | DELETE, OPEN_EXISTING, retired.package_bytes);
            const auto bytes = read_all(file.get());
            require((!committed && bytes.size() < retired.package_bytes) ||
                        (bytes.size() == retired.package_bytes && apk::sha256(bytes) == retired.sha256),
                    "AETHER_UPDATE_CONFLICT",
                    "Retired package has unknown content; it is preserved for explicit disposition");
            FILE_DISPOSITION_INFO disposition{TRUE};
            io(SetFileInformationByHandle(file.get(), FileDispositionInfo, &disposition,
                                          sizeof(disposition)) != FALSE,
               "Cannot retire the previous package version; explicitly repair update cleanup");
        }
        current.state = State::installed;
        current.shell_verified =
            current.shell == ShellState::ready ? std::optional<bool>(true) : std::nullopt;
        append(current);
        return current;
    }
    std::shared_ptr<AppLease> hold_app(const InstalledApp &app, bool allow_missing = false) const {
        auto lease = std::make_shared<AppLease>();
        const auto app_path = path / app.id;
        if (allow_missing && missing(app_path))
            return lease;
        for (const auto &directory : directories) {
            HANDLE duplicate = nullptr;
            io(DuplicateHandle(GetCurrentProcess(), directory.get(), GetCurrentProcess(), &duplicate, 0,
                               FALSE, DUPLICATE_SAME_ACCESS) != FALSE,
               "Cannot retain the installed application's path identity");
            lease->ancestors.emplace_back(duplicate);
        }
        lease->directory = open_directory(app_path, false, true);
        lease->lock =
            open_file(app_path / L"session.lock", GENERIC_READ | GENERIC_WRITE | DELETE, OPEN_ALWAYS, 0);
        return lease;
    }
    void cleanup(const InstalledApp &app, AppLease &lease) {
        auto shell_lease = hold_shell_registration();
        remove_shell_registration(app, path);
        const auto app_path = path / app.id;
        if (missing(app_path))
            return;
        require(lease.directory && lease.lock, "AETHER_INSTALL_STATE", "Removal requires the app lease");
        for (const auto &entry : std::filesystem::directory_iterator(app_path))
            require(entry.path().filename() == package_path(app, path).filename() ||
                        entry.path().filename() == L"data" || entry.path().filename() == L"audit" ||
                        entry.path().filename() == L"session.lock",
                    "AETHER_INSTALL_PATH",
                    "Unexpected app material prevents removal; unrelated files are preserved");
        for (const auto *name : {L"data", L"audit"}) {
            const auto data_path = app_path / name;
            if (missing(data_path))
                continue;
            auto data = open_directory(data_path, false, true);
            if (!app.keep_data) {
                std::vector<std::filesystem::path> children;
                for (const auto &entry : std::filesystem::directory_iterator(data_path)) {
                    const auto maximum_children = std::wstring_view(name) == L"audit"
                                                      ? security::PrivateStorage::maximum_audit_names
                                                      : security::PrivateStorage::maximum_names;
                    require(children.size() < maximum_children &&
                                data_name(entry.path().filename().wstring(), std::wstring_view(name) == L"data"),
                            "AETHER_INSTALL_PATH", "Unsupported data entry prevents removal");
                    auto file =
                        open_file(entry.path(), FILE_READ_ATTRIBUTES, OPEN_EXISTING, 1024 * 1024, 0, true);
                    children.push_back(entry.path());
                }
                for (const auto &child : children)
                    delete_file(child, 1024 * 1024, true);
                data.reset();
                io(RemoveDirectoryW(data_path.c_str()) != FALSE,
                   "Cannot remove the app's empty data directory");
            }
        }
        // This profile is derived only from the recorded opaque ID. Windows reports
        // success for an absent profile. A failure leaves an explicit removal intent.
        const auto profile = L"Aether.Installed." + utf16(app.id);
        require(SUCCEEDED(DeleteAppContainerProfile(profile.c_str())), "AETHER_INSTALL_PROFILE",
                "Cannot remove the app's Windows isolation profile; close it and explicitly repair");
        delete_file(package_path(app, path), maximum_package);
        if (!app.keep_data) {
            FILE_DISPOSITION_INFO disposition{TRUE};
            io(SetFileInformationByHandle(lease.lock.get(), FileDispositionInfo, &disposition,
                                          sizeof(disposition)) != FALSE,
               "Cannot remove the app session lease file");
            lease.lock.reset();
            lease.directory.reset();
            io(RemoveDirectoryW(app_path.c_str()) != FALSE, "Cannot remove the selected app directory");
        }
    }
};
PackageStore::PackageStore(const std::filesystem::path &root, Access access)
    : impl_(std::make_unique<Impl>(root, access)) {
    if (access != Access::read)
        remember_runtime_store(root);
}
PackageStore::~PackageStore() = default;
const std::filesystem::path &PackageStore::root() const noexcept { return impl_->path; }
std::vector<InstalledApp> PackageStore::list() const {
    std::vector<InstalledApp> result;
    for (const auto &[id, app] : impl_->apps) {
        (void)id;
        if (app.state != State::removed)
            result.push_back(app);
    }
    return result;
}
InstalledApp PackageStore::info(std::string_view id) const {
    auto app = impl_->find(id);
    if (installed_state(app.state)) {
        impl_->validate_package(app);
        if (app.shell != ShellState::none) {
            auto lease = hold_shell_registration();
            app.shell_verified = inspect_shell_registration(app, impl_->path);
        }
    }
    return app;
}
AppDiagnostics PackageStore::diagnostics(std::string_view id) const {
    AppDiagnostics report;
    report.app = impl_->find(id);
    const auto &app = report.app;
    report.lifecycle = state_name(app.state);
    auto add = [&](std::string name, std::string status, std::string code, std::string detail) {
        report.checks.push_back({std::move(name), std::move(status), std::move(code), std::move(detail)});
    };
    const bool selected = installed_state(app.state);
    const bool retired = app.state == State::removed || app.state == State::data_retained;
    add("installation",
        app.state == State::installed ? "pass"
        : retired                     ? "information"
                                      : "fail",
        app.state == State::installed || retired ? "" : "AETHER_INSTALL_STATE",
        app.state == State::installed ? "The journal records a completed installation."
        : retired ? "The installation was removed; its historical grants do not authorize launch."
                  : "An unfinished transaction requires explicit repair; no repair was attempted.");
    if (selected) {
        try {
            apk::InspectResult inspection;
            report.observed_signature = impl_->validate_package(app, &inspection);
            const auto compatibility = apk::execution_compatibility(inspection);
            add("package", "pass", "",
                "Held APK bytes and metadata match; available signing checks succeeded.");
            add("signing", verified_signing(app.signing) ? "pass" : "information", "",
                app.signing == SigningState::not_recorded
                    ? "Current signature was inspected; legacy history has no recorded signing decision."
                : verified_signing(app.signing)
                    ? "The complete verified APK certificate set matches; publisher trust is not "
                      "established."
                    : "The historical signing decision is preserved; current verification is reported "
                      "separately. "
                      "No verified publisher is claimed.");
            add("formatAdmission", compatibility.installable ? "pass" : "fail",
                compatibility.installable ? "" : "AETHER_INSTALL_UNSUPPORTED",
                compatibility.installable
                    ? "The package meets current format admission; Android API behavior has not been tested."
                    : "Current format admission refuses this package; inspect the APK for supported-format "
                      "details.");
        } catch (const std::exception &error) {
            report.observed_signature.reset();
            const auto *install = dynamic_cast<const InstallError *>(&error);
            const auto *inspect = dynamic_cast<const apk::InspectError *>(&error);
            add("package", "fail",
                install   ? install->code
                : inspect ? inspect->diagnostic.code
                          : "AETHER_DIAGNOSTICS_PACKAGE",
                "Package validation could not complete. Preserve the app and investigate the diagnostic "
                "code; nothing was repaired.");
            add("signing", "not-checked", "",
                "Current signing identity was not established from an intact selected package.");
            add("formatAdmission", "not-checked", "",
                "Package validation must succeed before format admission can be assessed.");
        }
    } else {
        for (const auto name : {"package", "signing", "formatAdmission"})
            add(name, "not-checked", "", "No committed installed generation is selected for this state.");
    }
    const bool clock = (app.permissions & security::installed_clock) != 0;
    add("permissions",
        !selected ? "information"
        : clock   ? "pass"
                  : "fail",
        selected && !clock ? "AETHER_INSTALL_PERMISSION_REQUIRED" : "",
        !selected ? "Historical grants are ineffective while the app is not installed."
        : clock   ? "The required clock grant is recorded. No permission was changed."
                : "Installed launch requires an explicit clock grant through settings; the current denial is "
                  "preserved.");
    if (app.shell == ShellState::none)
        add("windowsRegistration", "information", "", "This app has no recorded Windows registration.");
    else {
        try {
            const auto lease = hold_shell_registration();
            const bool matches = inspect_shell_registration(app, impl_->path);
            add("windowsRegistration", matches && app.shell == ShellState::ready ? "pass" : "fail",
                matches && app.shell == ShellState::ready ? "" : "AETHER_SHELL_STATE",
                matches && app.shell == ShellState::ready
                    ? "Recorded icon, Start shortcut and uninstall values match; Windows UI was not observed."
                    : "Windows registration is incomplete or differs from the journal; no repair was "
                      "attempted.");
        } catch (const std::exception &error) {
            const auto *install = dynamic_cast<const InstallError *>(&error);
            add("windowsRegistration", "fail", install ? install->code : "AETHER_DIAGNOSTICS_WINDOWS",
                "Windows registration could not be inspected; conflicting material is preserved.");
        }
    }
    return report;
}
std::string UpdatePreview::json(const InstallPreview &candidate) const {
    return "{\"schemaVersion\":1,\"operation\":\"update-preview\",\"updateable\":" +
           std::string(updateable ? "true" : "false") +
           ",\"adoptsLegacyIdentity\":" + (adopts_legacy_identity ? "true" : "false") +
           ",\"code\":" + json_quote(code) + ",\"reason\":" + json_quote(reason) +
           ",\"current\":" + current.json() + ",\"candidate\":" + candidate.json() + "}";
}
UpdatePreview PackageStore::review_update(const InstallPreview &candidate, std::string_view id) const {
    UpdatePreview result;
    result.current = impl_->find(id);
    try {
        require(impl_->updates.empty(), "AETHER_UPDATE_RECOVERY_REQUIRED",
                "An unfinished update requires explicit repair");
        impl_->check_update(result.current, candidate);
        // Preview is read-only, including when a legacy app has no session.lock.
        const auto lock_path = impl_->path / result.current.id / L"session.lock";
        UniqueHandle lock;
        if (!missing(lock_path))
            lock = open_file(lock_path, GENERIC_READ, OPEN_EXISTING, 0);
        if (result.current.shell != ShellState::none) {
            auto shell_lease = hold_shell_registration();
            require(inspect_shell_registration(result.current, impl_->path), "AETHER_UPDATE_STATE",
                    "Repair the existing Windows registration before updating");
        }
        result.updateable = true;
        result.adopts_legacy_identity = result.current.signing == SigningState::not_recorded;
        result.reason = "Verified newer APK with the same complete certificate set. App identity, data and "
                        "permissions are preserved.";
        if (result.adopts_legacy_identity)
            result.reason += " This decision also adopts the intact legacy APK's verified identity.";
    } catch (const InstallError &error) {
        result.code = error.code;
        result.reason = error.what();
    }
    return result;
}
InstalledApp update_package(const std::filesystem::path &path, const std::filesystem::path &root,
                            std::string_view id, std::string_view expected_current_sha256,
                            std::string_view expected_sha256) {
    require(valid_app_id(id) && hex(expected_current_sha256, 64) && hex(expected_sha256, 64),
            "AETHER_UPDATE_CONFIRMATION_REQUIRED",
            "Confirm the app ID and both current and proposed SHA-256 checksums from update preview");
    const auto bytes = apk::read_package(path);
    InstallPreview candidate;
    candidate.inspection = apk::inspect_package(bytes, {}, {.modern = true, .metadata_preview = true},
                                                apk::ScanScope::installation);
    require(candidate.inspection.sha256 == expected_sha256, "AETHER_INSTALL_SOURCE_CHANGED",
            "The proposed APK changed after review; inspect it and confirm again");
    candidate.signing = apk::verify_package_signature(bytes, candidate.inspection.format);
    const auto compatibility = apk::execution_compatibility(candidate.inspection);
    candidate.installable = compatibility.installable;
    candidate.reason = compatibility.reason;
    require(candidate.installable, "AETHER_UPDATE_UNSUPPORTED", candidate.reason.c_str());
    require(candidate.signing.verified(), "AETHER_UPDATE_SIGNER",
            "Updates require supported verified APK v2/v3 signatures");
    PackageStore store(root, PackageStore::Access::existing_write);
    return store.update_bytes(bytes, candidate, id, expected_current_sha256);
}
InstalledApp PackageStore::update_bytes(apk::Bytes bytes, const InstallPreview &candidate,
                                        std::string_view id, std::string_view expected_current_sha256) {
    impl_->settled();
    const auto previous = impl_->find(id);
    require(previous.sha256 == expected_current_sha256, "AETHER_UPDATE_CURRENT_CHANGED",
            "The installed version changed after review; inspect both versions and confirm again");
    impl_->check_update(previous, candidate);
    require(impl_->records + 8 <= maximum_records, "AETHER_INSTALL_LIMIT",
            "Insufficient registry capacity for an update, recovery and future removal");
    for (const auto &[other_id, other] : impl_->apps) {
        (void)other_id;
        require((other.state == State::installed && other.shell != ShellState::pending) ||
                    other.state == State::removed || other.state == State::data_retained,
                "AETHER_UPDATE_RECOVERY_REQUIRED",
                "Explicitly repair unfinished store operations before updating");
    }
    auto lease = impl_->hold_app(previous);
    lease->package = open_file(package_path(previous, impl_->path), GENERIC_READ, OPEN_EXISTING,
                               previous.package_bytes, FILE_SHARE_READ);
    // Retain the old file identity and deny writes/deletion through the version decision.
    impl_->validate_package(previous);
    auto shell_lease = hold_shell_registration();
    auto next = from_inspection(candidate.inspection);
    next.id = previous.id;
    next.package_generation = impl_->records + 1;
    next.permissions = previous.permissions;
    next.state = State::updating;
    record_signing(next, candidate.signing);
    require(missing(package_path(next, impl_->path)), "AETHER_UPDATE_CONFLICT",
            "The proposed version's final path is occupied; unrelated material is preserved");
    if (previous.shell != ShellState::none)
        plan_shell_update(previous, next, *candidate.inspection.presentation, impl_->path);
    try {
        impl_->append(next);
        {
            auto file = open_file(package_path(next, impl_->path), GENERIC_READ | GENERIC_WRITE, CREATE_NEW,
                                  maximum_package);
            write_durable(file.get(), bytes);
            require(apk::sha256(read_all(file.get())) == next.sha256, "AETHER_INSTALL_INTEGRITY",
                    "New package version failed durable readback");
        }
        if (next.shell != ShellState::none) {
            apply_shell_update(next, previous, impl_->path);
            next.shell = ShellState::ready;
        }
        next.state = State::update_committed;
        impl_->append(next);
        lease->package.reset();
        return impl_->finish_update(id);
    } catch (const std::exception &error) {
        const std::string original = error.what();
        if (impl_->poisoned)
            throw InstallError("AETHER_UPDATE_INCOMPLETE",
                               "Update persistence is uncertain for app " + previous.id +
                                   ". Explicit repair must reread the journal. " + original);
        if (!impl_->updates.contains(previous.id))
            throw;
        if (impl_->find(id).state == State::update_committed)
            throw InstallError("AETHER_UPDATE_CLEANUP",
                               "The new version is committed for app " + previous.id +
                                   ". Explicit repair must finish retiring old material. " + original);
        try {
            impl_->restore_update(id);
            lease->package.reset();
            impl_->finish_update(id);
        } catch (const std::exception &recovery) {
            throw InstallError("AETHER_UPDATE_INCOMPLETE",
                               "Update did not complete for app " + previous.id +
                                   ". Explicit repair is required: " + recovery.what() +
                                   ". Original failure: " + original);
        }
        throw InstallError("AETHER_UPDATE_ROLLED_BACK",
                           "The previous version and Windows registration were restored for app " +
                               previous.id + ". Update failure: " + original);
    }
}
InstalledApp PackageStore::install_fixture(const std::filesystem::path &path) {
    return install_package(path, dex::fixture::apk_sha256, true);
}
InstalledApp PackageStore::install_package(const std::filesystem::path &path,
                                           std::string_view expected_sha256, bool fixture_only) {
    impl_->settled();
    apk::InspectLimits limits;
    limits.archive_bytes = maximum_package;
    const auto bytes = apk::read_package(path, limits);
    // One held source read produces both metadata and the exact final package bytes.
    const auto report = apk::inspect_package(bytes, limits, {}, apk::ScanScope::installation);
    require(!fixture_only || report.sha256 == dex::fixture::apk_sha256, "AETHER_INSTALL_UNSUPPORTED",
            "--developer-fixture accepts only the exact self-authored development fixture");
    require(report.sha256 == expected_sha256, "AETHER_INSTALL_SOURCE_CHANGED",
            "The APK changed after inspection; review its current checksum before installing");
    const auto compatibility = apk::execution_compatibility(report);
    require(compatibility.installable, "AETHER_INSTALL_UNSUPPORTED", compatibility.reason.c_str());
    const auto signing = apk::verify_package_signature(bytes, report.format);
    for (const auto &[id, old] : impl_->apps) {
        (void)id;
        if (old.package_id == report.manifest.package_id && old.state != State::removed) {
            require(old.state == State::installed && old.sha256 == report.sha256, "AETHER_INSTALL_CONFLICT",
                    "This package identity is reserved by an existing or interrupted installation; inspect "
                    "or repair it");
            impl_->validate_package(old);
            return old;
        }
    }
    // Reserve enough journal capacity for intent, commit and subsequent recovery/removal.
    require(impl_->records + 6 <= maximum_records, "AETHER_INSTALL_LIMIT",
            "Insufficient registry capacity for installation and both retention/removal decisions");
    auto app = from_inspection(report);
    record_signing(app, signing);
    app.id = new_id();
    require(!impl_->apps.contains(app.id) && missing(impl_->path / app.id), "AETHER_INSTALL_CONFLICT",
            "Generated app identity already exists");
    for (const auto &[id, old] : impl_->apps) {
        (void)old;
        require(security::installed_broker_id(id) != security::installed_broker_id(app.id),
                "AETHER_INSTALL_CONFLICT", "Generated broker identity already exists");
    }
    impl_->append(app);
    // Intent precedes material creation. An interrupted operation is never installed
    // and explicit repair deletes only the fixed names beneath this recorded ID.
    auto directory = open_directory(impl_->path / app.id, true, true);
    auto data = open_directory(impl_->path / app.id / L"data", true, true);
    auto file =
        open_file(package_path(app, impl_->path), GENERIC_READ | GENERIC_WRITE, CREATE_NEW, maximum_package);
    write_durable(file.get(), bytes);
    require(apk::sha256(read_all(file.get())) == report.sha256, "AETHER_INSTALL_INTEGRITY",
            "Final package bytes failed readback validation");
    app.state = State::installed;
    impl_->append(app);
    return app;
}
InstalledApp install_windows(const std::filesystem::path &path, const std::filesystem::path &root,
                             std::string_view expected_sha256, std::uint32_t permissions) {
    require(hex(expected_sha256, 64), "AETHER_INSTALL_CONFIRMATION_REQUIRED",
            "Windows installation requires the SHA-256 from the reviewed package preview");
    require((permissions & security::installed_clock) &&
                !(permissions & ~security::installed_permission_mask),
            "AETHER_INSTALL_PERMISSION_REQUIRED",
            "Explicit clock permission is required for installed launch");
    apk::InspectLimits limits;
    limits.archive_bytes = maximum_package;
    const auto bytes = apk::read_package(path, limits);
    const auto report = apk::inspect_package(bytes, limits, {.modern = true, .metadata_preview = true},
                                       apk::ScanScope::installation);
    require(report.sha256 == expected_sha256, "AETHER_INSTALL_SOURCE_CHANGED",
            "The APK changed after inspection. Inspect the current source and confirm it again");
    const auto compatibility = apk::execution_compatibility(report);
    require(compatibility.installable, "AETHER_INSTALL_UNSUPPORTED", compatibility.reason.c_str());
    const auto signing = apk::verify_package_signature(bytes, report.format);
    // An invalid/stale source or permission decision cannot create even a store.
    PackageStore store(root, PackageStore::Access::write);
    return store.install_windows_bytes(bytes, report, signing, permissions);
}
InstalledApp PackageStore::install_windows_bytes(apk::Bytes bytes, const apk::InspectResult &report,
                                                 const apk::SignatureReport &signing,
                                                 std::uint32_t permissions, const InstallProgress &progress) {
    impl_->settled();
    for (const auto &[id, old] : impl_->apps) {
        (void)id;
        require(old.package_id != report.manifest.package_id || old.state == State::removed,
                "AETHER_INSTALL_CONFLICT",
                "This package already has an installation or retained state. Its permissions are unchanged");
    }
    require(impl_->records + 8 <= maximum_records, "AETHER_INSTALL_LIMIT",
            "Insufficient registry capacity for Windows installation, cleanup and future removal");
    auto app = from_inspection(report);
    record_signing(app, signing);
    app.id = new_id();
    app.state = State::installing_windows;
    app.permissions = permissions; // Not effective until the final installed/ready frame.
    require(!impl_->apps.contains(app.id) && missing(impl_->path / app.id), "AETHER_INSTALL_CONFLICT",
            "Generated app identity already exists");
    for (const auto &[id, old] : impl_->apps) {
        (void)old;
        require(security::installed_broker_id(id) != security::installed_broker_id(app.id),
                "AETHER_INSTALL_CONFLICT", "Generated broker identity already exists");
    }
    try {
        auto shell_lease = hold_shell_registration();
        impl_->append(app);
        if (progress)
            progress(InstallStage::writing);
        {
            auto directory = open_directory(impl_->path / app.id, true, true);
            auto data = open_directory(impl_->path / app.id / L"data", true, true);
            auto file = open_file(package_path(app, impl_->path), GENERIC_READ | GENERIC_WRITE, CREATE_NEW,
                                  maximum_package);
            write_durable(file.get(), bytes);
            require(apk::sha256(read_all(file.get())) == report.sha256, "AETHER_INSTALL_INTEGRITY",
                    "Final package bytes failed readback validation");
        }
        if (progress)
            progress(InstallStage::registering);
        auto lease = impl_->hold_app(app);
        plan_shell_registration(app, impl_->path, report.presentation.get());
        impl_->append(app);
        apply_shell_registration(app, impl_->path, report.presentation.get());
        if (progress)
            progress(InstallStage::finishing);
        app.state = State::installed;
        app.shell = ShellState::ready;
        app.shell_verified = true;
        impl_->append(app);
        if (progress)
            progress(InstallStage::complete);
        return app;
    } catch (const std::exception &original) {
        const std::string original_message = original.what();
        if (impl_->poisoned)
            throw InstallError("AETHER_INSTALL_INCOMPLETE",
                               "Installation commit is uncertain for app " + app.id +
                                   ". Explicit repair must reread the journal. " + original_message);
        if (!impl_->apps.contains(app.id))
            throw;
        // One cleanup of this fresh installation follows failure. This is not a
        // retry of the requested write and never removes an existing application.
        try {
            auto recorded = impl_->find(app.id);
            auto lease = impl_->hold_app(recorded, true);
            auto shell_lease = hold_shell_registration();
            recorded.state = State::removing;
            recorded.keep_data = false;
            impl_->append(recorded);
            impl_->cleanup(recorded, *lease);
            clear_shell(recorded);
            recorded.state = State::removed;
            impl_->append(recorded);
        } catch (const std::exception &cleanup) {
            throw InstallError("AETHER_INSTALL_INCOMPLETE",
                               "Installation did not complete for app " + app.id +
                                   ". Explicit repair is required after resolving: " + cleanup.what() +
                                   ". Original failure: " + original_message);
        }
        throw;
    }
}
InstalledApp PackageStore::uninstall(std::string_view id, bool keep_data) {
    impl_->settled();
    auto app = impl_->find(id);
    require(app.state == State::installed || app.state == State::data_retained || app.state == State::removed,
            "AETHER_INSTALL_STATE", "Interrupted operation needs repair before uninstall");
    if (app.state == State::removed || (app.state == State::data_retained && keep_data))
        return app;
    require(impl_->records + 2 <= maximum_records, "AETHER_INSTALL_LIMIT",
            "Insufficient registry capacity for removal");
    auto lease = impl_->hold_app(app, true);
    auto shell_lease = hold_shell_registration();
    app.state = State::removing;
    app.keep_data = keep_data;
    impl_->append(app);
    impl_->cleanup(app, *lease);
    clear_shell(app);
    app.state = keep_data ? State::data_retained : State::removed;
    impl_->append(app);
    return app;
}
InstalledApp PackageStore::set_permissions(std::string_view id, std::uint32_t allow, std::uint32_t deny,
                                           const std::optional<PermissionReview> &review) {
    impl_->settled();
    require(!((allow | deny) & ~security::installed_permission_mask) && !(allow & deny),
            "AETHER_INSTALL_PERMISSION", "Unsupported or contradictory permission decision");
    auto app = impl_->find(id);
    if (review) {
        require(review->sha256.size() == 64 &&
                    std::all_of(review->sha256.begin(), review->sha256.end(),
                                [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }) &&
                    !(review->permissions & ~security::installed_permission_mask),
                "AETHER_SETTINGS_REVIEW", "The reviewed package checksum or permission set is invalid");
        require(app.sha256 == review->sha256 && app.permissions == review->permissions,
                "AETHER_SETTINGS_CHANGED",
                "The installed package or permissions changed after review; review the current settings");
    }
    require(app.state == State::installed, "AETHER_INSTALL_STATE", "Settings require an installed app");
    require(app.shell != ShellState::pending, "AETHER_SHELL_STATE",
            "Finish Windows registration repair before changing permissions");
    auto lease = impl_->hold_app(app);
    if (review)
        impl_->validate_package(app);
    const auto next = (app.permissions | allow) & ~deny;
    if (next == app.permissions)
        return app;
    require(impl_->records + 5 <= maximum_records, "AETHER_INSTALL_LIMIT",
            "Insufficient registry capacity for settings and subsequent removal");
    app.permissions = next;
    impl_->append(app);
    return app;
}
InstalledApp PackageStore::register_windows(std::string_view id) {
    impl_->settled();
    auto app = info(id);
    require(app.state == State::installed && (app.permissions & security::installed_clock),
            "AETHER_SHELL_STATE",
            "Windows registration requires an intact installed app and its clock grant");
    require(app.shell != ShellState::pending, "AETHER_SHELL_STATE",
            "An interrupted Windows registration requires repair --yes");
    auto lease = impl_->hold_app(app);
    auto shell_lease = hold_shell_registration();
    if (app.shell == ShellState::ready && inspect_shell_registration(app, impl_->path))
        return app;
    validate_shell_ownership(app, impl_->path);
    require(impl_->records + 6 <= maximum_records, "AETHER_INSTALL_LIMIT",
            "Insufficient journal capacity for Windows registration and removal");
    if (app.shell == ShellState::none)
        plan_shell_registration(app, impl_->path);
    else
        app.shell = ShellState::pending;
    impl_->append(app);
    apply_shell_registration(app, impl_->path);
    app.shell = ShellState::ready;
    app.shell_verified = true;
    impl_->append(app);
    return app;
}
security::InstalledActivity PackageStore::prepare_launch(std::string_view id) {
    const auto app = impl_->find(id);
    require(installed_state(app.state), "AETHER_INSTALL_STATE", "Only an installed app can launch");
    require(app.shell != ShellState::pending, "AETHER_SHELL_STATE",
            "Windows registration is interrupted; use repair --yes before launch");
    require((app.permissions & security::installed_clock) != 0, "AETHER_INSTALL_PERMISSION_REQUIRED",
            "Installed launch requires monotonic time; explicitly grant it with settings --app-id ID "
            "--allow-clock "
            "--yes");
    auto runtime = std::make_unique<RuntimeUseLease>(impl_->path);
    auto lease = impl_->hold_app(app);
    lease->runtime = std::move(runtime);
    lease->package = open_file(package_path(app, impl_->path), GENERIC_READ, OPEN_EXISTING, maximum_package,
                               FILE_SHARE_READ);
    auto bytes = std::make_shared<const std::vector<std::uint8_t>>(read_all(lease->package.get()));
    require(bytes->size() == app.package_bytes && apk::sha256(*bytes) == app.sha256,
            "AETHER_INSTALL_INTEGRITY", "Installed APK no longer matches its committed checksum");
    const auto inspection = apk::inspect_package(*bytes, {}, {}, apk::ScanScope::installation);
    const auto compatibility = apk::execution_compatibility(inspection);
    require(compatibility.installable, "AETHER_INSTALL_UNSUPPORTED", compatibility.reason.c_str());
    verify_recorded_signing(app, apk::verify_package_signature(*bytes, inspection.format));
    auto actual = from_inspection(inspection);
    actual.id = app.id;
    actual.package_generation = app.package_generation;
    require(same_metadata(app, actual), "AETHER_INSTALL_INTEGRITY", "Installed metadata differs from APK");
    remember_runtime_store(impl_->path);
    const auto data = impl_->path / app.id / L"data", audit = impl_->path / app.id / L"audit";
    lease->ancestors.push_back(open_directory(data, false, true));
    lease->ancestors.push_back(open_directory(audit, true, true));
    return {app.id,
            app.permissions,
            data,
            audit,
            std::move(bytes),
            lease,
            lease->package.get(),
            shell_relaunch(app, impl_->path),
            app.icon_renderer};
}
std::size_t PackageStore::recover() {
    require(impl_->access == Access::recover, "AETHER_INSTALL_STATE",
            "Recovery requires an explicit writable repair session");
    std::size_t repaired = 0;
    if (impl_->tail) {
        LARGE_INTEGER end{};
        end.QuadPart = static_cast<LONGLONG>(impl_->records * frame_size);
        io(SetFilePointerEx(impl_->registry.get(), end, nullptr, FILE_BEGIN) &&
               SetEndOfFile(impl_->registry.get()) && FlushFileBuffers(impl_->registry.get()),
           "Cannot remove the incomplete final journal frame");
        impl_->tail = 0;
        ++repaired;
    }
    // Complete the one pending version decision before other maintenance can
    // consume its reserved journal capacity or alter the app's permissions.
    while (!impl_->updates.empty()) {
        const auto id = impl_->updates.begin()->first;
        auto lease = impl_->hold_app(impl_->find(id));
        auto shell_lease = hold_shell_registration();
        if (impl_->find(id).state == State::updating)
            impl_->restore_update(id);
        impl_->finish_update(id);
        ++repaired;
    }
    for (const auto &original : list()) {
        auto app = original;
        if (app.state == State::preparing || app.state == State::installing_windows ||
            app.state == State::removing) {
            auto lease = impl_->hold_app(app, true);
            auto shell_lease = hold_shell_registration();
            require(impl_->records + (app.state == State::removing ? 1 : 2) <= maximum_records,
                    "AETHER_INSTALL_LIMIT", "Insufficient registry capacity for recovery");
            if (app.state != State::removing) {
                app.state = State::removing;
                app.keep_data = false;
                impl_->append(app);
            }
            impl_->cleanup(app, *lease);
            clear_shell(app);
            app.state = app.keep_data ? State::data_retained : State::removed;
            impl_->append(app);
            ++repaired;
        } else if (app.state == State::installed) {
            impl_->validate_package(app);
            if (app.shell != ShellState::none) {
                auto lease = impl_->hold_app(app);
                auto shell_lease = hold_shell_registration();
                if (app.shell == ShellState::ready && inspect_shell_registration(app, impl_->path))
                    continue;
                validate_shell_ownership(app, impl_->path);
                require(impl_->records + 6 <= maximum_records, "AETHER_INSTALL_LIMIT",
                        "Insufficient journal capacity for Windows repair and removal");
                if (app.shell == ShellState::ready) {
                    app.shell = ShellState::pending;
                    impl_->append(app);
                }
                apply_shell_registration(app, impl_->path);
                app.shell = ShellState::ready;
                impl_->append(app);
                ++repaired;
            }
        }
    }
    return repaired;
}
} // namespace aether::install
