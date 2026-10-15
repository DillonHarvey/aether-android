#include "runtime_registration.hpp"
#include "aether/common/text.hpp"
#include "aether/install/runtime_setup.hpp"
#include "aether/install/shell.hpp"
#include "aether/security/worker_image.hpp"
#include "aether/uninstall_controller.hpp"
#include <Windows.h>
#include <aclapi.h>
#include <array>
#include <cstring>
#include <map>
#include <optional>
#include <sddl.h>
#include <utility>

namespace aether::install {
std::filesystem::path windows_powershell() {
    std::array<wchar_t, 32768> path{};
    const auto size = GetSystemDirectoryW(path.data(), static_cast<UINT>(path.size()));
    if (!size || size >= path.size())
        throw InstallError("AETHER_SETUP_CONTROLLER", "Cannot locate the Windows uninstall controller");
    return std::filesystem::path(std::wstring(path.data(), size)) / L"WindowsPowerShell" / L"v1.0" /
           L"powershell.exe";
}
namespace detail {
namespace {
constexpr wchar_t key_path[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Aether.Runtime";
void ensure(bool ok, const char *message) {
    if (!ok)
        throw InstallError("AETHER_SETUP_REGISTRATION", message);
}
void checked(LSTATUS status, const char *message) {
    if (status != ERROR_SUCCESS)
        throw InstallError("AETHER_SETUP_REGISTRATION",
                           std::string(message) + "; Windows error=" + std::to_string(status));
}
struct Key {
    HKEY value = nullptr;
    ~Key() {
        if (value)
            RegCloseKey(value);
    }
    Key() = default;
    Key(Key &&other) noexcept : value(std::exchange(other.value, nullptr)) {}
    Key &operator=(Key &&other) noexcept {
        if (value)
            RegCloseKey(value);
        value = std::exchange(other.value, nullptr);
        return *this;
    }
};
struct Policy {
    PSECURITY_DESCRIPTOR value = nullptr;
    Policy() {
        auto sddl = security::runtime_directory_sddl();
        for (auto at = sddl.find(L";OICI;FA;"); at != std::wstring::npos; at = sddl.find(L";OICI;FA;"))
            sddl.replace(at, 9, L";;KA;");
        ensure(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &value,
                                                                    nullptr),
               "Cannot construct the runtime registration policy");
    }
    ~Policy() { LocalFree(value); }
};
void verify_policy(HKEY key) {
    Policy expected;
    PSECURITY_DESCRIPTOR actual = nullptr;
    PSID owner = nullptr, wanted_owner = nullptr;
    PACL acl = nullptr, wanted_acl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    const auto status =
        GetSecurityInfo(key, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
                        nullptr, &acl, nullptr, &actual);
    struct Free {
        PSECURITY_DESCRIPTOR value;
        ~Free() { LocalFree(value); }
    } release{actual};
    ensure(status == ERROR_SUCCESS && owner && acl &&
               GetSecurityDescriptorOwner(expected.value, &wanted_owner, &defaulted) && wanted_owner &&
               GetSecurityDescriptorDacl(expected.value, &present, &wanted_acl, &defaulted) && present &&
               wanted_acl && EqualSid(owner, wanted_owner) &&
               GetSecurityDescriptorControl(actual, &control, &revision) && (control & SE_DACL_PROTECTED) &&
               acl->AclSize == wanted_acl->AclSize && std::memcmp(acl, wanted_acl, acl->AclSize) == 0,
           "Runtime Windows registration has an unexpected owner or access policy");
}
Key open(bool write = false, bool create = false) {
    Key parent;
    const std::wstring path(key_path);
    for (std::size_t begin = 0; begin < path.size();) {
        const auto end = path.find(L'\\', begin);
        const bool last = end == std::wstring::npos;
        const auto part = path.substr(begin, last ? path.size() - begin : end - begin);
        Key next;
        const auto access = KEY_READ | KEY_WOW64_64KEY | (write ? KEY_WRITE | DELETE : 0);
        auto status = RegOpenKeyExW(parent.value ? parent.value : HKEY_CURRENT_USER, part.c_str(),
                                    REG_OPTION_OPEN_LINK, access, &next.value);
        if (status == ERROR_FILE_NOT_FOUND && create) {
            Policy policy;
            SECURITY_ATTRIBUTES attributes{sizeof(attributes), policy.value, FALSE};
            DWORD disposition = 0;
            checked(RegCreateKeyExW(parent.value ? parent.value : HKEY_CURRENT_USER, part.c_str(), 0, nullptr,
                                    REG_OPTION_NON_VOLATILE, access, last ? &attributes : nullptr,
                                    &next.value, &disposition),
                    "Create runtime Windows registration");
            ensure(!last || disposition == REG_CREATED_NEW_KEY,
                   "Runtime Windows registration appeared during installation");
            status = ERROR_SUCCESS;
        } else if (last && create && status == ERROR_SUCCESS)
            ensure(false, "An existing runtime Windows registration is preserved");
        if (status == ERROR_FILE_NOT_FOUND)
            return {};
        checked(status, "Open runtime Windows registration");
        DWORD type = 0, length = 0;
        ensure(RegQueryValueExW(next.value, L"SymbolicLinkValue", nullptr, &type, nullptr, &length) ==
                   ERROR_FILE_NOT_FOUND,
               "Registry links are not accepted for runtime Windows registration");
        if (last)
            verify_policy(next.value);
        parent = std::move(next);
        if (last)
            break;
        begin = end + 1;
    }
    return parent;
}
struct Value {
    DWORD kind = REG_SZ;
    std::vector<BYTE> bytes;
    bool operator==(const Value &) const = default;
};
Value string_value(const std::wstring &value) {
    const auto *first = reinterpret_cast<const BYTE *>(value.c_str());
    return {REG_SZ, {first, first + (value.size() + 1) * sizeof(wchar_t)}};
}
Value number_value(DWORD value) {
    const auto *first = reinterpret_cast<const BYTE *>(&value);
    return {REG_DWORD, {first, first + sizeof(value)}};
}
using Values = std::map<std::wstring, Value>;
Values values(const std::filesystem::path &root, const std::string &identity) {
    return {{L"AetherIdentity", string_value(utf16(identity))},
            {L"InstallLocation", string_value(root.wstring())},
            {L"DisplayName", string_value(L"Aether runtime (development)")},
            {L"DisplayVersion", string_value(L"0.1.0")},
            {L"DisplayIcon",
             string_value(quote_windows_argument((root / L"aether-setup.exe").wstring()) + L",0")},
            {L"UninstallString", string_value(uninstall_command(root, identity, false))},
            {L"QuietUninstallString", string_value(uninstall_command(root, identity, true))},
            {L"NoModify", number_value(1)},
            {L"NoRepair", number_value(1)}};
}
Values inspect(HKEY key, const Values &expected, bool allow_missing) {
    DWORD children = 0, count = 0;
    checked(RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &children, nullptr, nullptr, &count, nullptr,
                             nullptr, nullptr, nullptr),
            "Inspect runtime Windows registration");
    ensure(children == 0 && count <= expected.size() && (allow_missing || count == expected.size()),
           "Incomplete or unrelated runtime Windows registration is preserved");
    Values present;
    for (DWORD index = 0; index < count; ++index) {
        std::array<wchar_t, 128> name{};
        DWORD length = static_cast<DWORD>(name.size());
        checked(RegEnumValueW(key, index, name.data(), &length, nullptr, nullptr, nullptr, nullptr),
                "Read runtime Windows value name");
        const std::wstring field(name.data(), length);
        ensure(expected.contains(field), "Unrelated runtime Windows value is preserved");
        Value actual;
        DWORD size = 0;
        checked(RegQueryValueExW(key, field.c_str(), nullptr, &actual.kind, nullptr, &size),
                "Inspect runtime Windows value");
        ensure(size <= 65536 && actual.kind == expected.at(field).kind &&
                   size == expected.at(field).bytes.size(),
               "Changed runtime Windows value is preserved");
        actual.bytes.resize(size);
        checked(RegQueryValueExW(key, field.c_str(), nullptr, &actual.kind, actual.bytes.data(), &size),
                "Read runtime Windows value");
        ensure(actual == expected.at(field), "Changed runtime Windows value is preserved");
        present.emplace(field, std::move(actual));
    }
    return present;
}
std::wstring literal(std::wstring_view value) {
    std::wstring result = L"'";
    for (const auto c : value)
        result += c == L'\'' ? L"''" : std::wstring(1, c);
    return result + L"'";
}
std::wstring base64(std::wstring_view value) {
    constexpr wchar_t alphabet[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const auto *bytes = reinterpret_cast<const BYTE *>(value.data());
    const auto size = value.size() * sizeof(wchar_t);
    std::wstring result;
    for (std::size_t n = 0; n < size; n += 3) {
        const auto bits = (static_cast<unsigned>(bytes[n]) << 16) |
                          (n + 1 < size ? static_cast<unsigned>(bytes[n + 1]) << 8 : 0) |
                          (n + 2 < size ? bytes[n + 2] : 0);
        result += alphabet[(bits >> 18) & 63];
        result += alphabet[(bits >> 12) & 63];
        result += n + 1 < size ? alphabet[(bits >> 6) & 63] : L'=';
        result += n + 2 < size ? alphabet[bits & 63] : L'=';
    }
    return result;
}
} // namespace
std::wstring uninstall_command(const std::filesystem::path &root, const std::string &identity, bool quiet) {
    const auto script = L"$root=" + literal(root.wstring()) + L";$identity=" + literal(utf16(identity)) +
                        L";$quiet=$" + (quiet ? std::wstring(L"true") : std::wstring(L"false")) + L";\n" +
                        utf16(uninstall_controller);
    auto command = quote_windows_argument(windows_powershell().wstring()) +
                   L" -NoProfile -WindowStyle Hidden -EncodedCommand " + base64(script);
    ensure(command.size() < 32760, "Runtime uninstall controller exceeds the Windows command limit");
    return command;
}
bool runtime_registration_absent() { return !open().value; }
void verify_runtime_registration(const std::filesystem::path &root, const std::string &identity,
                                 bool allow_missing) {
    auto key = open();
    ensure(key.value || allow_missing, "Runtime Windows registration is missing");
    if (key.value)
        (void)inspect(key.value, values(root, identity), allow_missing);
}
void register_runtime(const std::filesystem::path &root, const std::string &identity, bool repair) {
    auto key = repair ? open(true) : Key{};
    if (key.value)
        (void)inspect(key.value, values(root, identity), true);
    else
        key = open(true, true);
    for (const auto &[name, value] : values(root, identity))
        checked(RegSetValueExW(key.value, name.c_str(), 0, value.kind, value.bytes.data(),
                               static_cast<DWORD>(value.bytes.size())),
                "Write runtime Windows registration");
    checked(RegFlushKey(key.value), "Flush runtime Windows registration");
    (void)inspect(key.value, values(root, identity), false);
}
void unregister_runtime(const std::filesystem::path &root, const std::string &identity) {
    auto key = open(true);
    if (!key.value)
        return;
    (void)inspect(key.value, values(root, identity), true);
    key = {};
    checked(RegDeleteKeyExW(HKEY_CURRENT_USER, key_path, KEY_WOW64_64KEY, 0),
            "Remove runtime Windows registration");
    ensure(runtime_registration_absent(), "Runtime Windows registration removal failed readback");
}
std::string runtime_registration_json(const std::filesystem::path &root, const std::string &identity) {
    auto key = open();
    const auto present = key.value ? inspect(key.value, values(root, identity), true) : Values{};
    std::string out = "[";
    for (const auto &[name, value] : present) {
        if (out.back() != '[')
            out += ',';
        std::string text;
        if (value.kind == REG_SZ)
            text = utf8(std::wstring_view(reinterpret_cast<const wchar_t *>(value.bytes.data()),
                                          value.bytes.size() / 2 - 1));
        else {
            DWORD number = 0;
            std::memcpy(&number, value.bytes.data(), sizeof(number));
            text = std::to_string(number);
        }
        out += "{\"name\":" + json_quote(utf8(name)) +
               ",\"kind\":" + json_quote(value.kind == REG_SZ ? "String" : "DWord") +
               ",\"value\":" + json_quote(text) + '}';
    }
    return out + ']';
}
} // namespace detail
} // namespace aether::install
