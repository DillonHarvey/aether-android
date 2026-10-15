#include "aether/install/shell.hpp"
#include "aether/apk/artwork.hpp"
#include "aether/apk/package.hpp"
#include "aether/common/text.hpp"
#include "aether/dex/fixture_hash.hpp"
#include "aether/security/worker_image.hpp"
#include "private.hpp"
#include <Windows.h>
#include <propsys.h>

#include <aclapi.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <propkey.h>
#include <propvarutil.h>
#include <sddl.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <wrl/client.h>

namespace aether::install {
namespace {
using host::UniqueHandle;
using Microsoft::WRL::ComPtr;
constexpr std::uint64_t link_limit = 64 * 1024;
constexpr std::uint64_t icon_limit = 512 * 1024;
constexpr wchar_t uninstall_parent[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
void require(bool value, const char *code, const char *message) {
    if (!value)
        throw InstallError(code, message);
}
void check(HRESULT status, const char *operation) {
    if (FAILED(status))
        throw InstallError("AETHER_SHELL_IO", std::string(operation) + "; HRESULT=" +
                                                  std::to_string(static_cast<std::uint32_t>(status)));
}
struct Apartment {
    HRESULT status = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    Apartment() { check(status, "Initialize Windows Shell services"); }
    ~Apartment() { CoUninitialize(); }
};
struct Key {
    HKEY value = nullptr;
    ~Key() {
        if (value)
            RegCloseKey(value);
    }
    Key() = default;
    Key(const Key &) = delete;
    Key &operator=(const Key &) = delete;
};
struct ShellLease {
    UniqueHandle mutex;
    ShellLease() {
        const auto policy = security::runtime_directory_sddl();
        const auto end = policy.find(L"G:");
        require(policy.starts_with(L"O:") && end != std::wstring::npos, "AETHER_SHELL_POLICY",
                "Cannot identify the Windows registration owner");
        const auto name = L"Local\\Aether.ShellRegistration." + policy.substr(2, end - 2);
        mutex.reset(CreateMutexW(nullptr, FALSE, name.c_str()));
        require(static_cast<bool>(mutex), "AETHER_SHELL_IO", "Cannot create the registration lease");
        const auto wait = WaitForSingleObject(mutex.get(), 0);
        require(wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED, "AETHER_SHELL_BUSY",
                "Another Windows registration operation is in progress");
    }
    ~ShellLease() { ReleaseMutex(mutex.get()); }
};
struct Descriptor {
    PSECURITY_DESCRIPTOR value = nullptr;
    Descriptor() {
        auto policy = security::runtime_directory_sddl();
        for (auto at = policy.find(L";OICI;FA;"); at != std::wstring::npos; at = policy.find(L";OICI;FA;"))
            policy.replace(at, 9, L";;KA;");
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(policy.c_str(), SDDL_REVISION_1, &value,
                                                                     nullptr) != FALSE,
                "AETHER_SHELL_POLICY", "Cannot construct the private registration policy");
    }
    ~Descriptor() { LocalFree(value); }
};
bool path_exists(const std::filesystem::path &path) {
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES)
        return true;
    require(GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND,
            "AETHER_SHELL_PATH", "Cannot inspect Windows shortcut location");
    return false;
}
struct Programs {
    std::filesystem::path root = programs_directory();
    std::vector<UniqueHandle> held;
    explicit Programs(bool create) {
        require(root.is_absolute() && root.native().size() < 200 &&
                    GetDriveTypeW(root.root_path().c_str()) == DRIVE_FIXED,
                "AETHER_SHELL_UNSUPPORTED",
                "Start menu integration requires a bounded local fixed-drive folder");
        auto path = root.root_path();
        for (const auto &part : root.relative_path()) {
            path /= part;
            const bool final = path == root;
            if (final && !create && !path_exists(path))
                return;
            held.push_back(detail::hold_directory(path, final && create, final));
        }
    }
};
bool safe_leaf(std::string_view value) {
    if (value.size() < 5 || value.size() > 160 || !value.ends_with(".lnk"))
        return false;
    const auto stem = value.substr(0, value.size() - 4);
    const auto characters = utf16(value);
    auto device = utf16(stem.substr(0, stem.find('.')));
    while (!device.empty() && device.back() == L' ')
        device.pop_back();
    std::transform(device.begin(), device.end(), device.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(c >= L'a' && c <= L'z' ? c - L'a' + L'A' : c);
    });
    const bool reserved = device == L"CON" || device == L"PRN" || device == L"AUX" || device == L"NUL" ||
                          (device.size() == 4 && (device.starts_with(L"COM") || device.starts_with(L"LPT")) &&
                           ((device[3] >= L'0' && device[3] <= L'9') || device[3] == 0xb9 ||
                            device[3] == 0xb2 || device[3] == 0xb3));
    return !stem.empty() && stem.front() != '.' && stem.back() != '.' && stem.back() != ' ' &&
           stem.find_first_of("<>:\"/\\|?*") == std::string_view::npos &&
           std::none_of(characters.begin(), characters.end(),
                        [](wchar_t c) {
                            return c < 32 || (c >= 0x7f && c <= 0x9f) || (c >= 0x2028 && c <= 0x202e) ||
                                   (c >= 0x2066 && c <= 0x2069) || c == 0x200e || c == 0x200f || c == 0x061c;
                        }) &&
           !reserved;
}
std::filesystem::path icon_path(const InstalledApp &app, const std::filesystem::path &store) {
    return app.icon_sha256.empty() ? std::filesystem::path(utf16(app.launcher)) : app_icon_path(app, store);
}
apk::Artwork package_artwork(const InstalledApp &app, const std::filesystem::path &store) {
    auto directory = detail::hold_directory(store / app.id, false, true);
    auto package = detail::private_file(package_path(app, store), GENERIC_READ, OPEN_EXISTING, UINT64_MAX,
                                        FILE_SHARE_READ);
    const auto bytes = detail::read_contents(package.get());
    require(bytes.size() == app.package_bytes && apk::sha256(bytes) == app.sha256, "AETHER_INSTALL_INTEGRITY",
            "Installed package changed before deriving Windows artwork");
    return *apk::inspect_package(bytes, {}, {.modern = app.icon_renderer == 2}).presentation;
}
bool icon_matches(const InstalledApp &app, const std::filesystem::path &store) {
    if (app.icon_sha256.empty())
        return true; // Schema 3 keeps its recorded shared-executable icon location.
    const auto path = icon_path(app, store);
    if (!path_exists(path))
        return false;
    auto directory = detail::hold_directory(store / app.id, false, true);
    auto file = detail::private_file(path, GENERIC_READ, OPEN_EXISTING, icon_limit, FILE_SHARE_READ);
    return apk::sha256(detail::read_contents(file.get())) == app.icon_sha256;
}
void validate_icon_content(const InstalledApp &app, const std::filesystem::path &store, apk::Bytes bytes,
                           bool rolled_back_candidate = false) {
    if (apk::sha256(bytes) == app.icon_sha256 || (bytes.empty() && app.shell == ShellState::pending))
        return;
    if (rolled_back_candidate && app.shell == ShellState::pending && app.package_generation != 0) {
        // Only retirement may recognize a short write. Derive the complete icon
        // from the intact recorded APK, then require an exact proper prefix.
        const auto artwork = package_artwork(app, store);
        const auto expected = apk::icon_file(artwork.bitmap, app.icon_renderer);
        if (artwork.label == app.display_name && apk::sha256(expected) == app.icon_sha256 &&
            bytes.size() < expected.size() && std::equal(bytes.begin(), bytes.end(), expected.begin()))
            return;
    }
    throw InstallError("AETHER_SHELL_CONFLICT",
                       "Derived icon has unknown content; conflicting material is preserved");
}
void validate_icon_ownership(const InstalledApp &app, const std::filesystem::path &store) {
    if (app.icon_sha256.empty() || !path_exists(icon_path(app, store)))
        return;
    auto directory = detail::hold_directory(store / app.id, false, true);
    auto file = detail::private_file(icon_path(app, store), GENERIC_READ, OPEN_EXISTING, icon_limit);
    const auto bytes = detail::read_contents(file.get());
    validate_icon_content(app, store, bytes);
}
void apply_icon(const InstalledApp &app, const std::filesystem::path &store) {
    if (app.icon_sha256.empty() || icon_matches(app, store))
        return;
    const auto artwork = package_artwork(app, store);
    const auto bytes = apk::icon_file(artwork.bitmap, app.icon_renderer);
    require(apk::sha256(bytes) == app.icon_sha256 && artwork.label == app.display_name,
            "AETHER_SHELL_INTEGRITY", "Current artwork does not match the recorded registration intent");
    auto directory = detail::hold_directory(store / app.id, false, true);
    auto file =
        detail::private_file(icon_path(app, store), GENERIC_READ | GENERIC_WRITE, OPEN_ALWAYS, icon_limit);
    const auto existing = detail::read_contents(file.get());
    require(existing.empty() && app.shell == ShellState::pending, "AETHER_SHELL_CONFLICT",
            "Unknown icon bytes cannot be replaced by repair");
    detail::replace_contents(file.get(), bytes);
    require(apk::sha256(detail::read_contents(file.get())) == app.icon_sha256, "AETHER_SHELL_INTEGRITY",
            "Derived icon failed readback");
}
std::wstring identity(const InstalledApp &app) { return L"Aether.App." + utf16(app.id); }
std::wstring registry_path(const InstalledApp &app) { return std::wstring(uninstall_parent) + identity(app); }
std::optional<std::wstring> read_string(HKEY key, const wchar_t *name) {
    DWORD type = 0, bytes = 0;
    auto status = RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes);
    if (status == ERROR_FILE_NOT_FOUND)
        return {};
    require(status == ERROR_SUCCESS && type == REG_SZ && bytes >= sizeof(wchar_t) && bytes <= 4096 &&
                bytes % sizeof(wchar_t) == 0,
            "AETHER_SHELL_CONFLICT", "Windows registration contains an unexpected value type or size");
    std::wstring result(bytes / sizeof(wchar_t), L'\0');
    status = RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE *>(result.data()), &bytes);
    require(status == ERROR_SUCCESS && result.back() == L'\0' && result.find(L'\0') == result.size() - 1,
            "AETHER_SHELL_CONFLICT", "Windows registration contains a malformed string");
    result.pop_back();
    return result;
}
std::optional<DWORD> read_number(HKEY key, const wchar_t *name) {
    DWORD type = 0, value = 0, size = sizeof(value);
    const auto status = RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE *>(&value), &size);
    if (status == ERROR_FILE_NOT_FOUND)
        return {};
    require(status == ERROR_SUCCESS && type == REG_DWORD && size == sizeof(value), "AETHER_SHELL_CONFLICT",
            "Windows registration contains a malformed number");
    return value;
}
void set_string(HKEY key, const wchar_t *name, const std::wstring &value) {
    require(value.size() < 2048, "AETHER_SHELL_LIMIT", "Windows registration string exceeds its bound");
    check(
        HRESULT_FROM_WIN32(RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE *>(value.c_str()),
                                          static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)))),
        "Write Windows application registration");
}
void set_number(HKEY key, const wchar_t *name, DWORD value) {
    check(HRESULT_FROM_WIN32(
              RegSetValueExW(key, name, 0, REG_DWORD, reinterpret_cast<const BYTE *>(&value), sizeof(value))),
          "Write Windows application registration number");
}
using Values = std::map<std::wstring, std::wstring>;
Values strings(const InstalledApp &app, const std::filesystem::path &store) {
    return {{L"AetherAppId", utf16(app.id)},
            {L"AetherStore", store.wstring()},
            {L"AetherRuntime", utf16(app.launcher)},
            {L"AetherSignatureStatus", L"unverified"},
            {L"DisplayName", utf16(app.display_name)},
            {L"DisplayVersion", utf16(app.version_name)},
            {L"Publisher", app.sha256 == dex::fixture::apk_sha256
                               ? L"Installed through Aether (unsigned development fixture)"
                               : L"Installed through Aether (publisher not authenticated)"},
            {L"DisplayIcon", quote_windows_argument(icon_path(app, store).wstring()) + L",0"},
            {L"InstallLocation", (store / app.id).wstring()},
            {L"UninstallString",
             quote_windows_argument(utf16(app.launcher)) + L" " + shell_arguments(app, store, L"uninstall")}};
}
std::map<std::wstring, DWORD> numbers(const InstalledApp &app) {
    return {{L"AetherRegistrationVersion", 1},
            {L"NoModify", 1},
            {L"NoRepair", 1},
            {L"EstimatedSize", static_cast<DWORD>((app.package_bytes + 1023) / 1024)}};
}
void verify_key_policy(HKEY key) {
    PSECURITY_DESCRIPTOR raw = nullptr;
    PSID owner = nullptr, expected_owner = nullptr;
    PACL acl = nullptr, expected_acl = nullptr;
    Descriptor expected;
    BOOL present = FALSE, defaulted = FALSE;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    const auto error =
        GetSecurityInfo(key, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
                        nullptr, &acl, nullptr, &raw);
    struct Release {
        PSECURITY_DESCRIPTOR value;
        ~Release() { LocalFree(value); }
    } release{raw};
    require(error == ERROR_SUCCESS && owner && acl &&
                GetSecurityDescriptorOwner(expected.value, &expected_owner, &defaulted) &&
                GetSecurityDescriptorDacl(expected.value, &present, &expected_acl, &defaulted) &&
                EqualSid(owner, expected_owner) && GetSecurityDescriptorControl(raw, &control, &revision) &&
                (control & SE_DACL_PROTECTED) && acl->AclSize == expected_acl->AclSize &&
                std::memcmp(acl, expected_acl, acl->AclSize) == 0,
            "AETHER_SHELL_POLICY", "Windows registration does not have the protected owner/SYSTEM policy");
}
void verify_key(HKEY key, const InstalledApp &app, const std::filesystem::path &store, bool pending) {
    DWORD children = 0, values = 0;
    check(HRESULT_FROM_WIN32(RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &children, nullptr, nullptr,
                                              &values, nullptr, nullptr, nullptr, nullptr)),
          "Inspect Windows registration");
    require(children == 0 && values <= 16, "AETHER_SHELL_CONFLICT",
            "Windows registration has unexpected child material");
    verify_key_policy(key);
    if (!values && pending)
        return; // An explicit journal intent can recover an interrupted empty owned leaf.
    const auto recorded_id = read_string(key, L"AetherAppId");
    const auto recorded_store = read_string(key, L"AetherStore");
    if (pending && values == 1 && recorded_id == utf16(app.id) && !recorded_store)
        return;
    require(recorded_id == utf16(app.id) && recorded_store == store.wstring(), "AETHER_SHELL_CONFLICT",
            "Windows registration belongs to another installation");
    const auto expected_strings = strings(app, store);
    const auto expected_numbers = numbers(app);
    for (DWORD index = 0; index < values; ++index) {
        std::array<wchar_t, 128> name{};
        DWORD length = static_cast<DWORD>(name.size());
        check(HRESULT_FROM_WIN32(
                  RegEnumValueW(key, index, name.data(), &length, nullptr, nullptr, nullptr, nullptr)),
              "Enumerate Windows registration values");
        require(expected_strings.contains(std::wstring(name.data(), length)) ||
                    expected_numbers.contains(std::wstring(name.data(), length)),
                "AETHER_SHELL_CONFLICT", "Unknown Windows registration values are preserved");
    }
}
bool open_key(Key &key, const InstalledApp &app, bool create) {
    const auto path = registry_path(app);
    if (!create) {
        const auto status = RegOpenKeyExW(HKEY_CURRENT_USER, path.c_str(), REG_OPTION_OPEN_LINK,
                                          KEY_READ | KEY_WRITE | DELETE | KEY_WOW64_64KEY, &key.value);
        if (status == ERROR_FILE_NOT_FOUND)
            return false;
        check(HRESULT_FROM_WIN32(status), "Open Windows application registration");
    } else {
        if (open_key(key, app, false))
            return true;
        Descriptor descriptor;
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor.value, FALSE};
        DWORD disposition = 0;
        check(HRESULT_FROM_WIN32(RegCreateKeyExW(
                  HKEY_CURRENT_USER, path.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                  KEY_READ | KEY_WRITE | DELETE | KEY_WOW64_64KEY, &attributes, &key.value, &disposition)),
              "Create Windows application registration");
    }
    DWORD type = 0, size = 0;
    const auto link = RegQueryValueExW(key.value, L"SymbolicLinkValue", nullptr, &type, nullptr, &size);
    require(link == ERROR_FILE_NOT_FOUND, "AETHER_SHELL_PATH", "Registry symbolic links are unsupported");
    return true;
}
void set_property(IPropertyStore *store, REFPROPERTYKEY key, const std::wstring &text) {
    PROPVARIANT value{};
    check(InitPropVariantFromString(text.c_str(), &value), "Create shortcut identity value");
    const auto status = store->SetValue(key, value);
    PropVariantClear(&value);
    check(status, "Set shortcut identity");
}
bool link_matches(const std::filesystem::path &path, const InstalledApp &app,
                  const std::filesystem::path &store) {
    if (!path_exists(path))
        return false;
    auto held = detail::private_file(path, FILE_READ_ATTRIBUTES, OPEN_EXISTING, link_limit,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, true);
    Apartment apartment;
    ComPtr<IShellLinkW> link;
    check(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link)),
          "Open shortcut services");
    ComPtr<IPersistFile> file;
    check(link.As(&file), "Open persisted shortcut");
    if (FAILED(file->Load(path.c_str(), STGM_READ)))
        return false;
    std::array<wchar_t, 2048> target{}, arguments{}, icon{};
    int icon_index = -1;
    check(link->GetPath(target.data(), static_cast<int>(target.size()), nullptr, SLGP_RAWPATH),
          "Read shortcut target");
    check(link->GetArguments(arguments.data(), static_cast<int>(arguments.size())),
          "Read shortcut arguments");
    check(link->GetIconLocation(icon.data(), static_cast<int>(icon.size()), &icon_index),
          "Read shortcut icon");
    ComPtr<IPropertyStore> properties;
    check(link.As(&properties), "Read shortcut identity");
    PROPVARIANT value{};
    check(properties->GetValue(PKEY_AppUserModel_ID, &value), "Read shortcut AppUserModelID");
    const bool match = value.vt == VT_LPWSTR && value.pwszVal && identity(app) == value.pwszVal &&
                       utf16(app.launcher) == target.data() &&
                       icon_path(app, store).wstring() == icon.data() && icon_index == 0 &&
                       shell_arguments(app, store, L"launch") == arguments.data();
    PropVariantClear(&value);
    return match;
}
std::optional<std::wstring> link_identity(const std::filesystem::path &path) {
    auto held = detail::private_file(path, FILE_READ_ATTRIBUTES, OPEN_EXISTING, link_limit,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, true);
    Apartment apartment;
    ComPtr<IShellLinkW> link;
    check(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link)),
          "Inspect shortcut ownership");
    ComPtr<IPersistFile> file;
    check(link.As(&file), "Read shortcut ownership");
    if (FAILED(file->Load(path.c_str(), STGM_READ)))
        return {};
    ComPtr<IPropertyStore> properties;
    check(link.As(&properties), "Read shortcut ownership properties");
    PROPVARIANT value{};
    const auto status = properties->GetValue(PKEY_AppUserModel_ID, &value);
    std::optional<std::wstring> result;
    if (SUCCEEDED(status) && value.vt == VT_LPWSTR && value.pwszVal)
        result = value.pwszVal;
    PropVariantClear(&value);
    return result;
}
bool empty_pending_link(const std::filesystem::path &path, const InstalledApp &app) {
    if (app.shell != ShellState::pending)
        return false;
    auto file = detail::private_file(path, FILE_READ_ATTRIBUTES, OPEN_EXISTING, link_limit,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, true);
    LARGE_INTEGER size{};
    require(GetFileSizeEx(file.get(), &size) != FALSE, "AETHER_SHELL_IO",
            "Cannot inspect the pending shortcut placeholder");
    return size.QuadPart == 0;
}
void validate_shell_entries(const InstalledApp &app, const std::filesystem::path &store) {
    Programs programs(false);
    const auto path = programs.root / utf16(app.shortcut_name);
    if (path_exists(path)) {
        const auto owner = link_identity(path);
        require(owner == identity(app) || (!owner && empty_pending_link(path, app)), "AETHER_SHELL_CONFLICT",
                "The recorded shortcut has no matching app identity; conflicting material is preserved");
    }
    Key key;
    if (open_key(key, app, false))
        verify_key(key.value, app, store, app.shell == ShellState::pending);
}
std::vector<std::uint8_t> recorded_icon(const InstalledApp &app, const std::filesystem::path &store) {
    const auto artwork = package_artwork(app, store);
    auto bytes = apk::icon_file(artwork.bitmap, app.icon_renderer);
    require(artwork.label == app.display_name && apk::sha256(bytes) == app.icon_sha256,
            "AETHER_SHELL_INTEGRITY", "Package artwork differs from the recorded update identity");
    return bytes;
}
void replace_update_icon(const InstalledApp &selected, const InstalledApp &other,
                         const std::filesystem::path &store) {
    const auto expected = recorded_icon(selected, store);
    auto directory = detail::hold_directory(store / selected.id, false, true);
    const auto path = icon_path(selected, store);
    const bool existed = path_exists(path);
    auto file = detail::private_file(path, GENERIC_READ | GENERIC_WRITE, OPEN_ALWAYS, icon_limit);
    const auto existing = detail::read_contents(file.get());
    const auto digest = apk::sha256(existing);
    if (digest == selected.icon_sha256)
        return;
    const auto prefix = [&](const auto &complete) {
        return existing.size() < complete.size() &&
               std::equal(existing.begin(), existing.end(), complete.begin());
    };
    require(digest == other.icon_sha256 || prefix(expected) || prefix(recorded_icon(other, store)),
            "AETHER_SHELL_CONFLICT",
            "Update icon is neither a recorded version nor an exact interrupted write; it is preserved");
    // Keep the existing file identity. Durable truncation prevents a short write
    // from leaving an unrecognizable mixture of old and new icon bytes.
    LARGE_INTEGER zero{};
    require(SetFilePointerEx(file.get(), zero, nullptr, FILE_BEGIN) && SetEndOfFile(file.get()) &&
                FlushFileBuffers(file.get()),
            "AETHER_SHELL_IO", "Icon replacement was interrupted; explicitly repair the update");
    detail::replace_contents(file.get(), expected);
    require(detail::read_contents(file.get()) == expected, "AETHER_SHELL_INTEGRITY",
            "Updated icon failed durable readback");
    file.reset();
    SHChangeNotify(existed ? SHCNE_UPDATEITEM : SHCNE_CREATE, SHCNF_PATHW, path.c_str(), nullptr);
}
} // namespace

std::shared_ptr<const void> hold_shell_registration() { return std::make_shared<ShellLease>(); }

std::wstring quote_windows_argument(std::wstring_view value) {
    std::wstring result = L"\"";
    std::size_t slashes = 0;
    for (const auto c : value) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        result.append(slashes * (c == L'\"' ? 2 : 1) + (c == L'\"' ? 1 : 0), L'\\');
        result += c;
        slashes = 0;
    }
    result.append(slashes * 2, L'\\');
    return result + L'\"';
}
std::filesystem::path shell_launcher() {
    std::array<wchar_t, 32768> path{};
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    require(size && size < path.size(), "AETHER_SHELL_PATH", "Cannot locate the shared Windows launcher");
    return std::filesystem::path(std::wstring(path.data(), size)).parent_path() / L"aether-shell.exe";
}
std::filesystem::path programs_directory() {
    PWSTR value = nullptr;
    check(SHGetKnownFolderPath(FOLDERID_Programs, KF_FLAG_DEFAULT, nullptr, &value),
          "Find the user Start menu");
    struct Release {
        PWSTR value;
        ~Release() { CoTaskMemFree(value); }
    } release{value};
    return std::filesystem::path(value) / L"Aether Apps";
}
std::wstring shell_arguments(const InstalledApp &app, const std::filesystem::path &store,
                             std::wstring_view operation) {
    require(valid_app_id(app.id) && (operation == L"launch" || operation == L"uninstall"), "AETHER_SHELL_ID",
            "Invalid Windows entry point identity");
    return std::wstring(operation) + L" --app-id " + utf16(app.id) + L" --store " +
           quote_windows_argument(store.wstring());
}
bool valid_shell_record(const InstalledApp &app) {
    if (app.shell == ShellState::none)
        return app.display_name.empty() && app.shortcut_name.empty() && app.launcher.empty() &&
               app.icon_sha256.empty() && app.icon_generation == 0 && app.icon_renderer == 1;
    if (app.shell != ShellState::pending && app.shell != ShellState::ready)
        return false;
    const auto launcher = std::filesystem::path(utf16(app.launcher));
    const auto native = launcher.native();
    if (native.size() < 4 || native[1] != L':' || (native[2] != L'\\' && native[2] != L'/') ||
        !((native[0] >= L'A' && native[0] <= L'Z') || (native[0] >= L'a' && native[0] <= L'z')))
        return false;
    for (const auto &part : launcher.relative_path()) {
        const auto name = part.native();
        if (name.empty() || name == L"." || name == L".." || name.back() == L'.' || name.back() == L' ' ||
            name.find_first_of(L":<>\"|?*") != std::wstring::npos ||
            std::any_of(name.begin(), name.end(), [](wchar_t c) { return c < 32; }))
            return false;
    }
    return !app.display_name.empty() && app.display_name.size() <= 128 && safe_leaf(app.shortcut_name) &&
           (app.icon_renderer == 1 || app.icon_renderer == 2) &&
           (!app.icon_sha256.empty() || app.icon_renderer == 1) &&
           app.icon_generation <= app.package_generation &&
           (!app.icon_sha256.empty() || app.icon_generation == 0) &&
           (app.icon_sha256.empty() ||
            (app.icon_sha256.size() == 64 &&
             std::all_of(app.icon_sha256.begin(), app.icon_sha256.end(),
                         [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }))) &&
           launcher.is_absolute() && launcher.filename() == L"aether-shell.exe" &&
           app.launcher.size() <= 512 && app.launcher.find('"') == std::string::npos &&
           std::none_of(app.display_name.begin(), app.display_name.end(),
                        [](unsigned char c) { return c < 32; });
}
security::InstalledRelaunch shell_relaunch(const InstalledApp &app, const std::filesystem::path &store) {
    require(valid_shell_record(app), "AETHER_SHELL_ID", "Invalid Windows relaunch record");
    if (app.shell == ShellState::none)
        return {{}, {}, {}, "Windows registration is required for taskbar relaunch"};
    require(app.shell == ShellState::ready, "AETHER_SHELL_STATE", "Windows relaunch requires registration");
    // A leading @ is Shell indirect-resource syntax, not a literal APK label.
    // Keep such labels visible without allowing them to select a host resource.
    const auto label = app.display_name.starts_with('@') ? "Aether - " + app.display_name : app.display_name;
    const auto command = quote_windows_argument(utf16(app.launcher)) + L" relaunch --app-id " + utf16(app.id);
    const auto icon = quote_windows_argument(icon_path(app, store).wstring()) + L",0";
    // The native HWND property store rejects strings beyond 255 UTF-16 units.
    // Do not truncate a path/command or turn a valid ordinary launch into failure.
    if (command.size() > 255 || icon.size() > 255)
        return {{},
                {},
                {},
                "AETHER_SHELL_RELAUNCH_LIMIT: launcher or icon exceeds the Windows window "
                "property limit of 255 UTF-16 characters; use the registered Start shortcut"};
    return {utf8(command), label, utf8(icon), {}};
}
security::InstalledActivity prepare_shell_relaunch(std::string_view id) {
    require(valid_app_id(id), "AETHER_INSTALL_ID", "Invalid registered application ID");
    const auto root = [&] {
        InstalledApp locator;
        locator.id = id;
        Key key;
        require(open_key(key, locator, false), "AETHER_SHELL_NOT_REGISTERED",
                "This app no longer has a Windows registration; remove its stale taskbar pin");
        verify_key_policy(key.value);
        const auto path = read_string(key.value, L"AetherStore");
        require(read_string(key.value, L"AetherAppId") == utf16(id) && path && !path->empty() &&
                    path->size() < 200 &&
                    read_string(key.value, L"AetherRuntime") == shell_launcher().wstring() &&
                    read_number(key.value, L"AetherRegistrationVersion") == 1u,
                "AETHER_SHELL_CONFLICT", "The Windows locator does not match this app and shared runtime");
        return std::filesystem::path(*path);
    }();
    // Windows is a locator only. Lock the authoritative store, then recheck all
    // current projections under the same Shell coordination as update/uninstall.
    // No registry command, permission or package path is ever executed here.
    PackageStore store(root);
    const auto shell_lease = hold_shell_registration();
    const auto app = store.info(id);
    require(app.shell == ShellState::ready && app.launcher == utf8(shell_launcher().wstring()) &&
                inspect_shell_registration(app, root),
            "AETHER_SHELL_INTEGRITY", "Windows registration needs explicit repair before taskbar relaunch");
    return store.prepare_launch(id);
}
void plan_shell_registration(InstalledApp &app, const std::filesystem::path &store) {
    require(app.shell == ShellState::none, "AETHER_SHELL_STATE",
            "Registration is already recorded; use repair");
    Programs programs(false);
    const auto launcher = shell_launcher();
    UniqueHandle executable(CreateFileW(launcher.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    BY_HANDLE_FILE_INFORMATION info{};
    require(executable && GetFileInformationByHandle(executable.get(), &info) && info.nNumberOfLinks == 1 &&
                !(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)),
            "AETHER_SHELL_RUNTIME_MISSING",
            "Build or install the shared aether-shell.exe before registering apps");
    app.launcher = utf8(launcher.wstring());
    app.icon_renderer = 2;
    const auto artwork = package_artwork(app, store);
    app.display_name = artwork.label;
    app.icon_sha256 = apk::sha256(apk::icon_file(artwork.bitmap, app.icon_renderer));
    app.icon_generation = app.package_generation;
    require(!path_exists(icon_path(app, store)), "AETHER_SHELL_CONFLICT",
            "Unrecorded icon file already exists; unrelated material is preserved");
    const auto stem = apk::shortcut_stem(app.display_name);
    app.shortcut_name = stem + ".lnk";
    if (path_exists(programs.root / utf16(app.shortcut_name)))
        app.shortcut_name = stem + " (" + app.id + ").lnk";
    require(!path_exists(programs.root / utf16(app.shortcut_name)), "AETHER_SHELL_CONFLICT",
            "Shortcut name is already occupied");
    Key key;
    require(!open_key(key, app, false), "AETHER_SHELL_CONFLICT", "Windows application key already exists");
    app.shell = ShellState::pending;
    require(valid_shell_record(app), "AETHER_SHELL_UNSUPPORTED",
            "Application identity exceeds Windows registration limits");
}
void plan_shell_update(const InstalledApp &previous, InstalledApp &candidate, const apk::Artwork &artwork,
                       const std::filesystem::path &store) {
    require(previous.id == candidate.id && previous.shell == ShellState::ready &&
                candidate.shell == ShellState::none &&
                candidate.package_generation != previous.package_generation,
            "AETHER_UPDATE_STATE", "Windows update requires the same settled installed identity");
    validate_shell_ownership(previous, store);
    require(inspect_shell_registration(previous, store), "AETHER_UPDATE_STATE",
            "Repair the existing Windows registration before updating");
    candidate.launcher = previous.launcher;
    require(artwork.renderer_version == 2, "AETHER_UPDATE_STATE",
            "New Windows artwork requires the current recorded renderer");
    candidate.icon_renderer = artwork.renderer_version;
    candidate.display_name = artwork.label;
    candidate.icon_sha256 = apk::sha256(apk::icon_file(artwork.bitmap, candidate.icon_renderer));
    candidate.icon_generation =
        previous.icon_sha256.empty() ? candidate.package_generation : previous.icon_generation;
    Programs programs(false);
    const auto stem = apk::shortcut_stem(candidate.display_name);
    candidate.shortcut_name = stem + ".lnk";
    if (path_exists(programs.root / utf16(candidate.shortcut_name)))
        candidate.shortcut_name =
            stem + " (" + candidate.id + "-" + std::to_string(candidate.package_generation) + ").lnk";
    require(!path_exists(programs.root / utf16(candidate.shortcut_name)) &&
                (icon_path(candidate, store) == icon_path(previous, store) ||
                 !path_exists(icon_path(candidate, store))),
            "AETHER_UPDATE_CONFLICT",
            "A final update icon or shortcut path is occupied; unrelated material is preserved");
    // The shortcut is distinct; the recorded icon path survives every update.
    // The update pair authorizes replacement and reconstruction on rollback.
    candidate.shell = ShellState::pending;
    require(valid_shell_record(candidate), "AETHER_SHELL_UNSUPPORTED",
            "Updated application identity exceeds Windows registration limits");
}
void retire_shell_update(const InstalledApp &retired, const InstalledApp &current,
                         const std::filesystem::path &store) {
    if (retired.shell == ShellState::none)
        return;
    require(valid_shell_record(retired) && valid_shell_record(current) && retired.id == current.id &&
                retired.package_generation != current.package_generation &&
                retired.shortcut_name != current.shortcut_name,
            "AETHER_UPDATE_STATE", "Update retirement requires distinct recorded version paths");
    auto directory = detail::hold_directory(store / retired.id, false, true);
    UniqueHandle retired_icon;
    if (!retired.icon_sha256.empty() && icon_path(retired, store) != icon_path(current, store) &&
        path_exists(icon_path(retired, store))) {
        retired_icon =
            detail::private_file(icon_path(retired, store), GENERIC_READ | DELETE, OPEN_EXISTING, icon_limit);
        validate_icon_content(retired, store, detail::read_contents(retired_icon.get()),
                              current.state == State::update_rolled_back);
    }
    Programs programs(false);
    const auto path = programs.root / utf16(retired.shortcut_name);
    if (path_exists(path)) {
        const auto owner = link_identity(path);
        // A different valid app can reuse an already retired filename. Preserve
        // it; an unreadable nonempty link remains an explicit cleanup conflict.
        require(owner || empty_pending_link(path, retired), "AETHER_SHELL_CONFLICT",
                "Retired shortcut has unknown content and is preserved");
        if (owner == identity(retired) || !owner) {
            auto file =
                detail::private_file(path, DELETE | FILE_READ_ATTRIBUTES, OPEN_EXISTING, link_limit, 0, true);
            FILE_DISPOSITION_INFO disposition{TRUE};
            require(SetFileInformationByHandle(file.get(), FileDispositionInfo, &disposition,
                                               sizeof(disposition)) != FALSE,
                    "AETHER_SHELL_IO", "Cannot retire the obsolete update shortcut");
            file.reset();
            SHChangeNotify(SHCNE_DELETE, SHCNF_PATHW, path.c_str(), nullptr);
        }
    }
    if (retired_icon) {
        FILE_DISPOSITION_INFO disposition{TRUE};
        require(SetFileInformationByHandle(retired_icon.get(), FileDispositionInfo, &disposition,
                                           sizeof(disposition)) != FALSE,
                "AETHER_SHELL_IO", "Cannot retire the obsolete update icon");
    }
}
void apply_shell_registration(const InstalledApp &app, const std::filesystem::path &store) {
    require(valid_shell_record(app) && app.shell != ShellState::none, "AETHER_SHELL_STATE",
            "No registration intent exists");
    // Recheck before touching either projection, including resumed pending intents.
    validate_shell_ownership(app, store);
    if (inspect_shell_registration(app, store))
        return;
    apply_icon(app, store);
    Programs programs(true);
    const auto path = programs.root / utf16(app.shortcut_name);
    if (!link_matches(path, app, store)) {
        auto held = detail::private_file(path, FILE_READ_ATTRIBUTES, OPEN_ALWAYS, link_limit,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE, true);
        Apartment apartment;
        ComPtr<IShellLinkW> link;
        check(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link)),
              "Create Windows shortcut");
        check(link->SetPath(utf16(app.launcher).c_str()), "Set shared launcher path");
        check(link->SetArguments(shell_arguments(app, store, L"launch").c_str()),
              "Set installed app arguments");
        check(link->SetWorkingDirectory(std::filesystem::path(utf16(app.launcher)).parent_path().c_str()),
              "Set runtime working directory");
        check(link->SetDescription(utf16(app.display_name + " - installed through Aether").c_str()),
              "Set shortcut description");
        check(link->SetIconLocation(icon_path(app, store).c_str(), 0), "Set recorded application icon");
        check(link->SetShowCmd(SW_SHOWNORMAL), "Set native launch visibility");
        ComPtr<IPropertyStore> properties;
        check(link.As(&properties), "Set shortcut properties");
        set_property(properties.Get(), PKEY_AppUserModel_ID, identity(app));
        check(properties->Commit(), "Commit shortcut identity");
        ComPtr<IPersistFile> file;
        check(link.As(&file), "Persist shortcut");
        check(file->Save(path.c_str(), TRUE), "Save final Start shortcut");
        {
            auto durable = detail::private_file(path, GENERIC_WRITE, OPEN_EXISTING, link_limit,
                                                FILE_SHARE_READ | FILE_SHARE_WRITE, true);
            require(FlushFileBuffers(durable.get()) != FALSE, "AETHER_SHELL_IO",
                    "Cannot flush the final Start shortcut");
        }
        held.reset();
    }
    Key key;
    (void)open_key(key, app, true);
    verify_key(key.value, app, store, app.shell == ShellState::pending);
    // Identity markers are the first values; a partial owned leaf remains repairable.
    set_string(key.value, L"AetherAppId", utf16(app.id));
    set_string(key.value, L"AetherStore", store.wstring());
    for (const auto &[name, value] : strings(app, store))
        set_string(key.value, name.c_str(), value);
    for (const auto &[name, value] : numbers(app))
        set_number(key.value, name.c_str(), value);
    check(HRESULT_FROM_WIN32(RegFlushKey(key.value)), "Flush Windows application registration");
    require(inspect_shell_registration(app, store), "AETHER_SHELL_INTEGRITY",
            "Windows registrations failed readback");
    SHChangeNotify(SHCNE_CREATE, SHCNF_PATHW, path.c_str(), nullptr);
}
void validate_shell_ownership(const InstalledApp &app, const std::filesystem::path &store) {
    if (app.shell == ShellState::none)
        return;
    validate_icon_ownership(app, store);
    validate_shell_entries(app, store);
}
void apply_shell_update(const InstalledApp &selected, const InstalledApp &other,
                        const std::filesystem::path &store) {
    require(valid_shell_record(selected) && valid_shell_record(other) &&
                selected.shell == ShellState::pending && other.shell != ShellState::none &&
                selected.id == other.id && selected.launcher == other.launcher &&
                selected.package_generation != other.package_generation,
            "AETHER_UPDATE_STATE", "Icon replacement requires the journal's recorded update pair");
    if (!other.icon_sha256.empty() && !selected.icon_sha256.empty() &&
        icon_path(selected, store) == icon_path(other, store)) {
        validate_shell_entries(selected, store);
        replace_update_icon(selected, other, store);
    }
    apply_shell_registration(selected, store);
}
bool inspect_shell_registration(const InstalledApp &app, const std::filesystem::path &store) {
    if (app.shell == ShellState::none)
        return false;
    require(valid_shell_record(app), "AETHER_SHELL_STATE", "Invalid recorded registration identity");
    if (!icon_matches(app, store))
        return false;
    Programs programs(false);
    if (!link_matches(programs.root / utf16(app.shortcut_name), app, store))
        return false;
    Key key;
    if (!open_key(key, app, false))
        return false;
    verify_key(key.value, app, store, app.shell == ShellState::pending);
    for (const auto &[name, value] : strings(app, store))
        if (read_string(key.value, name.c_str()) != value)
            return false;
    for (const auto &[name, value] : numbers(app))
        if (read_number(key.value, name.c_str()) != value)
            return false;
    return true;
}
void remove_shell_registration(const InstalledApp &app, const std::filesystem::path &store) {
    if (app.shell == ShellState::none)
        return;
    require(valid_shell_record(app), "AETHER_SHELL_STATE", "Invalid recorded registration identity");
    validate_icon_ownership(app, store);
    Programs programs(false);
    Key key;
    const bool registered = open_key(key, app, false);
    if (registered)
        verify_key(key.value, app, store, app.shell == ShellState::pending);
    const auto path = programs.root / utf16(app.shortcut_name);
    bool remove_link = path_exists(path);
    if (remove_link) {
        const auto owner = link_identity(path);
        if (owner && *owner != identity(app) && !registered) {
            remove_link = false; // Another app reused the name after an interrupted removal.
        } else {
            require(owner == identity(app) || (!owner && empty_pending_link(path, app)),
                    "AETHER_SHELL_CONFLICT",
                    "The shortcut identity changed; unrelated material is preserved");
        }
    }
    if (registered) {
        check(HRESULT_FROM_WIN32(
                  RegDeleteKeyExW(HKEY_CURRENT_USER, registry_path(app).c_str(), KEY_WOW64_64KEY, 0)),
              "Remove the selected Windows application entry");
    }
    if (remove_link) {
        auto file =
            detail::private_file(path, DELETE | FILE_READ_ATTRIBUTES, OPEN_EXISTING, link_limit, 0, true);
        FILE_DISPOSITION_INFO disposition{TRUE};
        require(SetFileInformationByHandle(file.get(), FileDispositionInfo, &disposition,
                                           sizeof(disposition)) != FALSE,
                "AETHER_SHELL_IO", "Cannot remove the selected Start shortcut");
        file.reset();
        SHChangeNotify(SHCNE_DELETE, SHCNF_PATHW, path.c_str(), nullptr);
    }
    if (!app.icon_sha256.empty() && path_exists(icon_path(app, store))) {
        auto directory = detail::hold_directory(store / app.id, false, true);
        auto file = detail::private_file(icon_path(app, store), DELETE | FILE_READ_ATTRIBUTES, OPEN_EXISTING,
                                         icon_limit);
        FILE_DISPOSITION_INFO disposition{TRUE};
        require(SetFileInformationByHandle(file.get(), FileDispositionInfo, &disposition,
                                           sizeof(disposition)) != FALSE,
                "AETHER_SHELL_IO", "Cannot remove the selected app's derived icon");
    }
}
} // namespace aether::install
