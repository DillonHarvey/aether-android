#include "aether/install/explorer.hpp"
#include "aether/common/text.hpp"
#include "aether/install/runtime.hpp"
#include "aether/install/runtime_setup.hpp"
#include "aether/install/shell.hpp"
#include "aether/security/worker_image.hpp"
#include "aether/shell/icon_cache.hpp"
#include "aether/shell/icon_service.hpp"
#include "aether/shell/icons.hpp"
#include "private.hpp"
#include <Windows.h>
#include <aclapi.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <sddl.h>
#include <set>
#include <shlobj.h>
#include <utility>

namespace aether::install {
namespace {
constexpr wchar_t classes[] = L"Software\\Classes\\";
constexpr wchar_t progid[] = L"Aether.APK";
constexpr wchar_t application[] = L"Applications\\aether-shell.exe";
constexpr wchar_t verb[] = L"*\\shell\\Aether.Install";
constexpr wchar_t record_name[] = L"AetherRegistration";
const std::array<std::wstring, 4> shared_parents = {L"Applications", L"*", L"*\\shell", L"CLSID"};
const std::array<std::wstring, 5> package_ids = {progid, L"Aether.XAPK", L"Aether.APKS", L"Aether.APKM",
                                                 L"Aether.AAB"};
const std::wstring icon_class = L"CLSID\\" + std::wstring(shell::icon_handler_id);
std::vector<std::wstring> owned_roots(bool modern) {
    std::vector<std::wstring> result{progid, application, verb};
    if (modern) {
        result.insert(result.end(), package_ids.begin() + 1, package_ids.end());
        result.push_back(icon_class);
    }
    return result;
}
enum class HandlerState : std::uint32_t { pending = 1, ready, removing };
struct Configuration {
    HandlerState state = HandlerState::pending;
    std::uint32_t created_parents = 0;
    std::uint32_t version = 2;
    std::filesystem::path launcher, store, icon_library, previous_icon;
    bool legacy_prior = false;
};
void require(bool condition, const char *code, const char *message) {
    if (!condition)
        throw InstallError(code, message);
}
void check(LSTATUS status, const char *operation) {
    if (status != ERROR_SUCCESS)
        throw InstallError("AETHER_EXPLORER_IO",
                           std::string(operation) + "; Windows error=" + std::to_string(status));
}
void conflict(bool condition, const char *message) {
    require(condition, "AETHER_EXPLORER_CONFLICT", message);
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
    Key(const Key &) = delete;
    Key &operator=(const Key &) = delete;
};
struct Descriptor {
    PSECURITY_DESCRIPTOR value = nullptr;
    Descriptor() {
        auto policy = security::runtime_directory_sddl();
        for (auto at = policy.find(L";OICI;FA;"); at != std::wstring::npos; at = policy.find(L";OICI;FA;"))
            policy.replace(at, 9, L";;KA;");
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(policy.c_str(), SDDL_REVISION_1, &value,
                                                                     nullptr),
                "AETHER_EXPLORER_POLICY", "Cannot create the private Explorer registration policy");
    }
    ~Descriptor() { LocalFree(value); }
};
void private_policy(HKEY key) {
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
            "AETHER_EXPLORER_POLICY",
            "Explorer registration does not have the protected owner/SYSTEM policy");
}
bool owned_path(std::wstring_view path) {
    for (const auto &relative : owned_roots(true)) {
        const auto root = std::wstring(classes) + relative;
        if (path == root || path.starts_with(root + L"\\"))
            return true;
    }
    return false;
}
Key open(std::wstring_view relative, bool write = false, bool create = false, HKEY hive = HKEY_CURRENT_USER) {
    const auto path = std::wstring(classes) + std::wstring(relative);
    Key held;
    std::wstring traversed;
    for (std::size_t begin = 0; begin < path.size();) {
        const auto end = path.find(L'\\', begin);
        const auto part = path.substr(begin, end == std::wstring::npos ? path.size() - begin : end - begin);
        if (!traversed.empty())
            traversed += L'\\';
        traversed += part;
        Key next;
        const auto access = KEY_READ | KEY_WOW64_64KEY | (write ? KEY_WRITE | DELETE : 0);
        const auto parent = held.value ? held.value : hive;
        auto status = RegOpenKeyExW(parent, part.c_str(), REG_OPTION_OPEN_LINK, access, &next.value);
        if (status == ERROR_FILE_NOT_FOUND && create) {
            Descriptor descriptor;
            SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor.value, FALSE};
            check(RegCreateKeyExW(parent, part.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, access,
                                  owned_path(traversed) ? &attributes : nullptr, &next.value, nullptr),
                  "Create Explorer registration key");
            status = ERROR_SUCCESS;
        }
        if (status == ERROR_FILE_NOT_FOUND)
            return {};
        check(status, "Open Explorer registration key");
        DWORD type = 0, bytes = 0;
        auto link_status =
            RegQueryValueExW(next.value, L"SymbolicLinkValue", nullptr, &type, nullptr, &bytes);
        if (hive == HKEY_CURRENT_USER && traversed == L"Software\\Classes" && link_status == ERROR_SUCCESS) {
            // Windows itself aliases HKCU\Software\Classes to this user's
            // mounted Classes hive. Accept only that documented exact target.
            const auto policy = security::runtime_directory_sddl();
            const auto owner_end = policy.find(L"G:");
            require(policy.starts_with(L"O:") && owner_end != std::wstring::npos, "AETHER_EXPLORER_POLICY",
                    "Cannot identify the current user's Classes hive");
            const auto leaf = policy.substr(2, owner_end - 2) + L"_Classes";
            const auto expected = L"\\Registry\\User\\" + leaf;
            std::wstring actual(expected.size(), L'\0');
            require(type == REG_LINK && bytes == expected.size() * sizeof(wchar_t), "AETHER_EXPLORER_PATH",
                    "The per-user Classes alias has an unexpected target");
            check(RegQueryValueExW(next.value, L"SymbolicLinkValue", nullptr, &type,
                                   reinterpret_cast<BYTE *>(actual.data()), &bytes),
                  "Verify the Windows Classes alias");
            require(type == REG_LINK && bytes == expected.size() * sizeof(wchar_t) &&
                        CompareStringOrdinal(actual.c_str(), static_cast<int>(actual.size()),
                                             expected.c_str(), static_cast<int>(expected.size()),
                                             TRUE) == CSTR_EQUAL,
                    "AETHER_EXPLORER_PATH", "The per-user Classes alias does not identify this user");
            next = {};
            check(RegOpenKeyExW(HKEY_USERS, leaf.c_str(), REG_OPTION_OPEN_LINK, access, &next.value),
                  "Open this user's verified Classes hive");
            link_status = RegQueryValueExW(next.value, L"SymbolicLinkValue", nullptr, &type, nullptr, &bytes);
        }
        require(link_status == ERROR_FILE_NOT_FOUND, "AETHER_EXPLORER_PATH",
                "Registry links are unsupported; existing registrations are preserved");
        held = std::move(next);
        if (end == std::wstring::npos)
            break;
        begin = end + 1;
    }
    return held;
}
struct Value {
    DWORD type = REG_NONE;
    std::vector<std::uint8_t> bytes;
    bool operator==(const Value &) const = default;
};
Value string_value(const std::wstring &text) {
    const auto *first = reinterpret_cast<const std::uint8_t *>(text.c_str());
    return {REG_SZ, {first, first + (text.size() + 1) * sizeof(wchar_t)}};
}
std::optional<Value> read(HKEY key, const wchar_t *name) {
    Value result;
    DWORD length = 0;
    auto status = RegQueryValueExW(key, name, nullptr, &result.type, nullptr, &length);
    if (status == ERROR_FILE_NOT_FOUND)
        return {};
    check(status, "Read Explorer registration value size");
    conflict(length <= 8192, "Explorer registration value exceeds its bound");
    result.bytes.resize(length);
    check(RegQueryValueExW(key, name, nullptr, &result.type, result.bytes.data(), &length),
          "Read Explorer registration value");
    conflict(length == result.bytes.size(), "Explorer registration changed while reading");
    return result;
}
void write(HKEY key, const wchar_t *name, const Value &value) {
    check(
        RegSetValueExW(key, name, 0, value.type, value.bytes.data(), static_cast<DWORD>(value.bytes.size())),
        "Write Explorer registration value");
}
void flush(HKEY key) { check(RegFlushKey(key), "Flush Explorer registration"); }
std::pair<DWORD, DWORD> counts(HKEY key) {
    DWORD children = 0, values = 0;
    check(RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &children, nullptr, nullptr, &values, nullptr,
                           nullptr, nullptr, nullptr),
          "Inspect Explorer registration key");
    return {children, values};
}
Value encode(const Configuration &config) {
    Value value{REG_BINARY, {'A', 'E', 'T', 'H', 'E', 'X', 'P', '1'}};
    value.bytes.back() = static_cast<std::uint8_t>('0' + config.version);
    const auto number = [&](std::uint32_t item) {
        for (unsigned shift = 0; shift < 32; shift += 8)
            value.bytes.push_back(static_cast<std::uint8_t>(item >> shift));
    };
    number(static_cast<std::uint32_t>(config.state));
    number(config.created_parents);
    for (const auto &path : {config.launcher, config.store}) {
        const auto text = utf8(path.wstring());
        number(static_cast<std::uint32_t>(text.size()));
        value.bytes.insert(value.bytes.end(), text.begin(), text.end());
    }
    if (config.version >= 2) {
        for (const auto &path : {config.icon_library, config.previous_icon}) {
            const auto text = utf8(path.wstring());
            number(static_cast<std::uint32_t>(text.size()));
            value.bytes.insert(value.bytes.end(), text.begin(), text.end());
        }
        number(config.legacy_prior ? 1 : 0);
    }
    const auto hash = apk::sha256(value.bytes);
    value.bytes.insert(value.bytes.end(), hash.begin(), hash.end());
    return value;
}
bool path_syntax(const std::filesystem::path &path, std::size_t limit) {
    const auto text = path.native();
    if (!path.is_absolute() || text.size() < 4 || text.size() >= limit ||
        text.find(L'%') != std::wstring::npos || text[1] != L':' || (text[2] != L'\\' && text[2] != L'/') ||
        !((text[0] >= L'A' && text[0] <= L'Z') || (text[0] >= L'a' && text[0] <= L'z')))
        return false;
    for (const auto &part : path.relative_path()) {
        const auto name = part.native();
        if (name.empty() || name == L"." || name == L".." || name.back() == L'.' || name.back() == L' ' ||
            name.find_first_of(L":<>\"|?*") != std::wstring::npos ||
            std::any_of(name.begin(), name.end(), [](wchar_t c) { return c < 32; }))
            return false;
    }
    return true;
}
bool library_syntax(const Configuration &config, const std::filesystem::path &path) {
    const auto hash = path.parent_path().filename().native();
    return path_syntax(path, 512) && path.filename() == L"AetherShellIcons.dll" && hash.size() == 64 &&
           std::all_of(hash.begin(), hash.end(),
                       [](wchar_t c) { return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'); }) &&
           path.parent_path().parent_path() == config.launcher.parent_path() / L"shell-icons";
}
Configuration decode(const Value &value) {
    const auto &bytes = value.bytes;
    const auto valid = [&](bool condition) {
        require(condition, "AETHER_EXPLORER_RECORD",
                "Explorer registration intent is invalid; unknown material is preserved");
    };
    valid(value.type == REG_BINARY && bytes.size() >= 88 && bytes.size() <= 4096);
    const std::string magic(bytes.begin(), bytes.begin() + 8);
    valid(magic == "AETHEXP1" || magic == "AETHEXP2");
    valid(apk::sha256(apk::Bytes(bytes).first(bytes.size() - 64)) ==
          std::string(bytes.end() - 64, bytes.end()));
    std::size_t at = 8;
    const auto number = [&] {
        valid(at + 4 <= bytes.size() - 64);
        std::uint32_t result = 0;
        for (unsigned shift = 0; shift < 32; shift += 8)
            result |= static_cast<std::uint32_t>(bytes[at++]) << shift;
        return result;
    };
    Configuration result;
    result.version = magic.back() == '2' ? 2 : 1;
    const auto state = number();
    valid(state >= 1 && state <= 3);
    result.state = static_cast<HandlerState>(state);
    result.created_parents = number();
    valid(result.created_parents < (1u << (result.version == 1 ? 3 : shared_parents.size())));
    for (auto *path : {&result.launcher, &result.store}) {
        const auto size = number();
        valid(size && size <= 1024 && at + size <= bytes.size() - 64);
        *path = utf16(std::string(reinterpret_cast<const char *>(bytes.data() + at), size));
        at += size;
    }
    if (result.version >= 2) {
        for (auto *path : {&result.icon_library, &result.previous_icon}) {
            const auto size = number();
            valid(size <= 1024 && at + size <= bytes.size() - 64);
            *path = utf16(std::string(reinterpret_cast<const char *>(bytes.data() + at), size));
            at += size;
        }
        const auto legacy = number();
        valid(legacy <= 1);
        result.legacy_prior = legacy != 0;
        valid(library_syntax(result, result.icon_library));
        valid(result.previous_icon.empty() || library_syntax(result, result.previous_icon));
        valid(!result.legacy_prior || result.previous_icon.empty());
        valid(result.state != HandlerState::ready || (result.previous_icon.empty() && !result.legacy_prior));
    }
    valid(at == bytes.size() - 64 && path_syntax(result.launcher, 512) && path_syntax(result.store, 200) &&
          result.launcher.filename() == L"aether-shell.exe");
    return result;
}
std::wstring command(const Configuration &config) {
    return quote_windows_argument(config.launcher.wstring()) + L" install --apk \"%1\" --store " +
           quote_windows_argument(config.store.wstring());
}
std::wstring owner_id(const Configuration &config) {
    const auto text = utf8(config.launcher.wstring()) + "\n" + utf8(config.store.wstring());
    return utf16(apk::sha256(apk::Bytes(reinterpret_cast<const std::uint8_t *>(text.data()), text.size())));
}
using Values = std::map<std::wstring, Value>;
using Tree = std::map<std::wstring, Values>;
Tree projections(const Configuration &config) {
    const auto run = string_value(command(config)),
               icon =
                   string_value(quote_windows_argument(config.version == 1 ? config.launcher.wstring()
                                                                           : config.icon_library.wstring()) +
                                (config.version == 1 ? L",0" : L",-101"));
    Tree tree = {
        {progid, {{L"", string_value(L"Android package (Aether)")}, {L"AllowSilentDefaultTakeOver", {}}}},
        {std::wstring(progid) + L"\\Application",
         {{L"ApplicationName", string_value(L"Aether")},
          {L"ApplicationDescription", string_value(L"Inspect and install supported Android packages")},
          {L"ApplicationIcon", icon}}},
        {std::wstring(progid) + L"\\DefaultIcon", {{L"", icon}}},
        {std::wstring(progid) + L"\\shell", {{L"", string_value(L"open")}}},
        {std::wstring(progid) + L"\\shell\\open",
         {{L"", string_value(L"Install with Aether")}, {L"MultiSelectModel", string_value(L"Single")}}},
        {std::wstring(progid) + L"\\shell\\open\\command", {{L"", run}}},
        {verb,
         {{L"AetherOwner", string_value(owner_id(config))},
          {L"", string_value(L"Install with Aether")},
          {L"Icon", icon},
          {L"NeverDefault", string_value(L"")},
          {L"AppliesTo", string_value(L"System.FileExtension:=\".apk\"")},
          {L"MultiSelectModel", string_value(L"Single")}}},
        {std::wstring(verb) + L"\\command", {{L"", run}}}};
    tree[application] = {{L"FriendlyAppName", string_value(L"Aether")},
                         {L"AetherOwner", string_value(owner_id(config))},
                         {L"AllowSilentDefaultTakeOver", {}}};
    tree[std::wstring(application) + L"\\SupportedTypes"] = {{L".apk", string_value(L"")}};
    for (const auto *suffix : {L"\\DefaultIcon", L"\\shell", L"\\shell\\open", L"\\shell\\open\\command"})
        tree[std::wstring(application) + suffix] = tree.at(std::wstring(progid) + suffix);
    if (config.version == 1)
        return tree;
    const std::array<std::wstring, 5> names = {L"Android package (Aether)", L"Android XAPK (Aether)",
                                               L"Android APK set (Aether)", L"Android APKM (Aether)",
                                               L"Android publishing bundle (Aether)"};
    const std::array<std::wstring, 5> extensions = {L".apk", L".xapk", L".apks", L".apkm", L".aab"};
    for (std::size_t index = 0; index < package_ids.size(); ++index) {
        const auto &id = package_ids[index];
        if (index) {
            for (const auto *suffix : {L"", L"\\Application", L"\\DefaultIcon", L"\\shell", L"\\shell\\open",
                                       L"\\shell\\open\\command"})
                tree[id + suffix] = tree.at(std::wstring(progid) + suffix);
            tree[id][L""] = string_value(names[index]);
            tree[id][L"AetherOwner"] = string_value(owner_id(config));
            tree[id + L"\\shell\\open"][L""] = string_value(L"Inspect with Aether");
        }
        if (index == 4)
            tree[id + L"\\Application"][L"ApplicationIcon"] =
                string_value(quote_windows_argument(config.icon_library.wstring()) + L",-102");
        tree[id + L"\\DefaultIcon"][L""] = string_value(L"%1");
        tree[id + L"\\shellex"] = {};
        tree[id + L"\\shellex\\IconHandler"] = {{L"", string_value(shell::icon_handler_id)}};
        tree[std::wstring(application) + L"\\SupportedTypes"][extensions[index]] = string_value(L"");
    }
    tree[std::wstring(application) + L"\\DefaultIcon"][L""] = string_value(L"%1");
    tree[std::wstring(application) + L"\\shellex"] = {};
    tree[std::wstring(application) + L"\\shellex\\IconHandler"] = {
        {L"", string_value(shell::icon_handler_id)}};
    tree[icon_class] = {{L"", string_value(L"Aether package icon handler")},
                        {L"AetherOwner", string_value(owner_id(config))}};
    tree[icon_class + L"\\InprocServer32"] = {
        {L"", string_value(config.icon_library.wstring())},
        {L"ThreadingModel", string_value(L"Apartment")},
        {L"AetherBroker", string_value((config.launcher.parent_path() / L"aether.exe").wstring())}};
    return tree;
}
Tree previous_projections(const Configuration &config) {
    if (!config.legacy_prior && config.previous_icon.empty())
        return {};
    auto previous = config;
    previous.version = config.legacy_prior ? 1 : 2;
    previous.icon_library = config.previous_icon;
    previous.previous_icon.clear();
    previous.legacy_prior = false;
    return projections(previous);
}
bool verify(const Configuration &config) {
    const auto tree = projections(config);
    const auto previous = previous_projections(config);
    bool complete = true;
    for (const auto &[path, expected] : tree) {
        auto key = open(path);
        if (!key.value) {
            complete = false;
            continue;
        }
        private_policy(key.value);
        const auto [children, values] = counts(key.value);
        std::set<std::wstring> allowed_children;
        for (const auto &[candidate, ignored] : tree) {
            (void)ignored;
            if (candidate.starts_with(path + L"\\")) {
                const auto child = candidate.substr(path.size() + 1);
                if (child.find(L'\\') == std::wstring::npos)
                    allowed_children.insert(child);
            }
        }
        conflict(children <= allowed_children.size() && values <= expected.size() + (path == progid ? 1 : 0),
                 "Unknown Explorer registration material is preserved");
        for (DWORD index = 0; index < children; ++index) {
            std::array<wchar_t, 128> name{};
            DWORD length = static_cast<DWORD>(name.size());
            check(RegEnumKeyExW(key.value, index, name.data(), &length, nullptr, nullptr, nullptr, nullptr),
                  "Read Explorer child name");
            conflict(allowed_children.contains(std::wstring(name.data(), length)),
                     "Unknown Explorer child is preserved");
        }
        for (DWORD index = 0; index < values; ++index) {
            std::array<wchar_t, 128> name{};
            DWORD length = static_cast<DWORD>(name.size());
            check(RegEnumValueW(key.value, index, name.data(), &length, nullptr, nullptr, nullptr, nullptr),
                  "Read Explorer value name");
            const std::wstring field(name.data(), length);
            if (path == progid && field == record_name)
                continue;
            conflict(expected.contains(field), "Unknown Explorer value is preserved");
            const auto actual = read(key.value, field.c_str());
            conflict(actual == expected.at(field) ||
                         (previous.contains(path) && previous.at(path).contains(field) &&
                          actual == previous.at(path).at(field)),
                     "Explorer value differs from the owned registration; unrelated content is preserved");
        }
        for (const auto &[name, value] : expected)
            complete = complete && read(key.value, name.c_str()) == value;
        if (expected.contains(L"AetherOwner") && (children || values))
            conflict(read(key.value, L"AetherOwner") == string_value(owner_id(config)),
                     "Explorer verb ownership does not match its intent");
    }
    return complete;
}
struct Notification {
    bool changed = false;
    bool enabled = true;
    ~Notification() {
        if (changed && enabled)
            SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    }
};
void commit(HKEY root, const Configuration &config) {
    write(root, record_name, encode(config));
    flush(root);
    require(read(root, record_name) == encode(config), "AETHER_EXPLORER_IO",
            "Explorer intent failed durable readback");
}
void validate_runtime(const Configuration &config, const PackageStore *held_store) {
    require(path_syntax(config.launcher, 512) && path_syntax(config.store, 200), "AETHER_EXPLORER_PATH",
            "Explorer registration requires bounded absolute local paths without '%' Shell placeholders");
    std::vector<host::UniqueHandle> held;
    auto path = config.launcher.root_path();
    require(GetDriveTypeW(path.c_str()) == DRIVE_FIXED, "AETHER_EXPLORER_PATH",
            "Explorer runtime must be on a local fixed drive");
    for (const auto &part : config.launcher.parent_path().relative_path()) {
        path /= part;
        held.push_back(detail::hold_directory(path, false, false));
    }
    host::UniqueHandle file(CreateFileW(config.launcher.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    BY_HANDLE_FILE_INFORMATION information{};
    require(file && GetFileInformationByHandle(file.get(), &information) && information.nNumberOfLinks == 1 &&
                !(information.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)),
            "AETHER_EXPLORER_RUNTIME",
            "The shared aether-shell.exe is missing, busy or not an ordinary single-link file");
    if (config.version >= 2) {
        require(library_syntax(config, config.icon_library), "AETHER_EXPLORER_PATH",
                "The Shell module must use this runtime's immutable content-addressed path");
        held.push_back(detail::hold_directory(config.launcher.parent_path(), false, true));
        held.push_back(detail::hold_directory(config.icon_library.parent_path().parent_path(), false, true));
        held.push_back(detail::hold_directory(config.icon_library.parent_path(), false, true));
        auto library = detail::private_file(config.icon_library, GENERIC_READ, OPEN_EXISTING,
                                            64ull * 1024 * 1024, FILE_SHARE_READ);
        require(apk::sha256(detail::read_contents(library.get())) ==
                    utf8(config.icon_library.parent_path().filename().native()),
                "AETHER_EXPLORER_RUNTIME", "The installed Shell module differs from its content identity");
    }
    if (held_store) {
        require(CompareStringOrdinal(held_store->root().c_str(), -1, config.store.c_str(), -1, TRUE) ==
                    CSTR_EQUAL,
                "AETHER_EXPLORER_RUNTIME", "The held package store differs from the Explorer registration");
        (void)held_store->list();
    } else {
        PackageStore store(config.store); // Read-only validation never creates a package store.
    }
}
void absent_roots(const std::vector<std::wstring> &roots) {
    for (const auto &path : roots)
        conflict(!open(path).value && !open(path, false, false, HKEY_LOCAL_MACHINE).value,
                 "An existing Explorer handler conflicts with Aether; it is preserved");
}
shell::CacheCleanup cleanup_cache(const Configuration &config) {
    if (config.version < 2)
        return {};
    const auto stopped =
        shell::stop_icon_service(shell::icon_endpoint(), config.launcher.parent_path() / L"aether.exe");
    require(stopped == shell::IconStopResult::not_running || stopped == shell::IconStopResult::stopped,
            "AETHER_EXPLORER_BUSY",
            "The icon service is busy or belongs to another runtime. Owned removal is recorded; explicitly "
            "retry after that service exits. No unrelated process was stopped.");
    const auto path = shell::icon_cache_root();
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        const auto error = GetLastError();
        require(error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND, "AETHER_EXPLORER_CACHE",
                "The owned icon cache cannot be inspected; explicitly retry removal");
        return {};
    }
    return shell::IconCache(path).clear();
}
void delete_key(std::wstring_view path) {
    auto key = open(path, true);
    if (!key.value)
        return;
    const auto [children, values] = counts(key.value);
    (void)values;
    conflict(children == 0, "Explorer removal encountered an unexpected child");
    key = {};
    check(RegDeleteKeyExW(HKEY_CURRENT_USER, (std::wstring(classes) + std::wstring(path)).c_str(),
                          KEY_WOW64_64KEY, 0),
          "Remove owned Explorer key");
}
ExplorerRegistration result(const Configuration &config, bool verified, bool notified) {
    return {config.state == HandlerState::ready     ? "registered"
            : config.state == HandlerState::pending ? "pending-repair"
                                                    : "removing",
            utf8(config.launcher.wstring()),
            utf8(config.store.wstring()),
            utf8(command(config)),
            utf8(config.icon_library.wstring()),
            verified,
            notified};
}
} // namespace

std::string ExplorerRegistration::json() const {
    return "{\"schemaVersion\":2,\"operation\":\"explorer\",\"state\":" + json_quote(state) +
           ",\"verified\":" + (verified ? "true" : "false") +
           ",\"perUser\":true,\"progId\":\"Aether.APK\",\"verb\":\"Aether.Install\","
           "\"openWithApplication\":\"Applications\\\\aether-shell.exe\","
           "\"sharedLauncher\":" +
           json_quote(launcher) + ",\"store\":" + json_quote(store) +
           ",\"installCommand\":" + json_quote(command) + ",\"iconLibrary\":" + json_quote(icon_library) +
           ",\"iconHandlerClsid\":" + json_quote(utf8(shell::icon_handler_id)) + ",\"offeredExtensions\":" +
           (icon_library.empty() ? "[\".apk\"]" : "[\".apk\",\".xapk\",\".apks\",\".apkm\",\".aab\"]") +
           ",\"dynamicIconsRequireEffectiveAssociation\":true,"
           "\"defaultSelectionGuidance\":\"Choose Aether in Windows Default apps or Open with for package "
           "types whose file icons you want Aether to provide. Another selected application's ProgID "
           "may prevent this icon handler from being used.\"" +
           ",\"defaultAssociationChanged\":false,\"shellNotified\":" + (notified ? "true" : "false") +
           ",\"cacheArtifactsRemoved\":" + std::to_string(cache_removed) +
           ",\"cacheEntriesPreserved\":" + std::to_string(cache_preserved) + "}";
}
ExplorerRegistration explorer_registration(ExplorerOperation operation,
                                           std::optional<std::filesystem::path> store,
                                           std::optional<std::filesystem::path> runtime,
                                           std::optional<std::filesystem::path> verified_icon_library,
                                           bool notify_shell, const PackageStore *held_store) {
    require(!store || operation == ExplorerOperation::register_handler, "AETHER_CLI_USAGE",
            "--store is only accepted when registering the Explorer handler");
    require(!verified_icon_library || runtime, "AETHER_EXPLORER_RUNTIME",
            "A verified Shell module requires an explicitly held runtime");
    require(!held_store || (runtime && verified_icon_library), "AETHER_EXPLORER_RUNTIME",
            "A held store requires the native installer's verified runtime and Shell module");
    std::unique_ptr<RuntimeUseLease> runtime_use;
    if (!runtime && operation != ExplorerOperation::status && operation != ExplorerOperation::check_upgrade)
        runtime_use = std::make_unique<RuntimeUseLease>();
    auto lease = hold_shell_registration();
    const bool modifying =
        operation != ExplorerOperation::status && operation != ExplorerOperation::check_upgrade;
    auto root = open(progid, modifying);
    std::optional<Configuration> existing;
    if (root.value) {
        private_policy(root.value);
        const auto record = read(root.value, record_name);
        conflict(
            record.has_value(),
            "The Aether application key has no recorded ownership intent; existing material is preserved");
        existing = decode(*record);
    }
    if (operation == ExplorerOperation::status) {
        if (!existing)
            absent_roots(owned_roots(true));
        return existing
                   ? result(*existing, verify(*existing) && existing->state == HandlerState::ready, false)
                   : ExplorerRegistration{};
    }
    Notification notification;
    notification.enabled = notify_shell;
    Configuration config;
    if (existing) {
        config = *existing;
        conflict(
            config.launcher == (runtime ? *runtime / L"aether-shell.exe" : shell_launcher()),
            "This Explorer registration belongs to another runtime location; use that runtime for removal");
        conflict(!store || *store == config.store, "This Explorer registration uses another package store");
        const bool complete = verify(config);
        if (operation == ExplorerOperation::check_upgrade) {
            require(verified_icon_library && library_syntax(config, *verified_icon_library) &&
                        config.state != HandlerState::removing,
                    "AETHER_EXPLORER_STATE", "Explorer removal must finish before a module upgrade");
            require(config.state == HandlerState::ready || config.icon_library == *verified_icon_library,
                    "AETHER_EXPLORER_STATE",
                    "Finish the recorded Explorer repair before changing its module");
            if (config.version == 1) {
                auto additions = owned_roots(true);
                additions.erase(additions.begin(), additions.begin() + 3);
                absent_roots(additions);
            }
            return result(config, complete && config.state == HandlerState::ready, false);
        }
        if (operation == ExplorerOperation::register_handler) {
            require(config.state == HandlerState::ready && complete, "AETHER_EXPLORER_STATE",
                    "Existing Explorer registration needs explicit repair or removal");
            // Complete legacy registrations can be explicitly upgraded here;
            // pending projections still require the existing repair operation.
        }
    } else {
        if (operation != ExplorerOperation::register_handler) {
            absent_roots(owned_roots(true));
            return {};
        }
        config.launcher = runtime ? *runtime / L"aether-shell.exe" : shell_launcher();
        config.store = store ? *store : default_store_root();
        config.icon_library = verified_icon_library ? *verified_icon_library
                                                    : runtime_icon_library(config.launcher.parent_path());
        validate_runtime(config, held_store);
        absent_roots(owned_roots(true));
        for (std::size_t index = 0; index < shared_parents.size(); ++index)
            if (!open(shared_parents[index]).value)
                config.created_parents |= 1u << index;
        root = open(progid, true, true);
        private_policy(root.value);
        conflict(counts(root.value) == std::pair<DWORD, DWORD>{0, 0},
                 "Explorer ownership changed before registration");
        notification.changed = true;
        commit(root.value, config); // Intent precedes every derived Windows value.
    }
    if (operation == ExplorerOperation::remove || config.state == HandlerState::removing) {
        notification.changed = true;
        config.state = HandlerState::removing;
        commit(root.value, config);
        const auto tree = projections(config);
        for (auto node = tree.rbegin(); node != tree.rend(); ++node)
            if (node->first != progid)
                delete_key(node->first);
        const auto cache = cleanup_cache(config);
        root = {};
        delete_key(progid);
        for (std::size_t index = shared_parents.size(); index-- > 0;)
            if (config.created_parents & (1u << index)) {
                auto parent = open(shared_parents[index], true);
                if (parent.value && counts(parent.value) == std::pair<DWORD, DWORD>{0, 0}) {
                    parent = {};
                    delete_key(shared_parents[index]);
                }
            }
        auto classes_key = open(L"", true);
        flush(classes_key.value);
        require(!open(progid).value && !open(verb).value && !open(application).value, "AETHER_EXPLORER_IO",
                "Explorer removal failed readback");
        ExplorerRegistration removed;
        removed.notified = notify_shell;
        removed.cache_removed = cache.removed;
        removed.cache_preserved = cache.preserved;
        return removed;
    }
    const auto desired =
        verified_icon_library ? *verified_icon_library : runtime_icon_library(config.launcher.parent_path());
    if (config.version == 1 || config.icon_library != desired) {
        require(config.state == HandlerState::ready && !config.legacy_prior && config.previous_icon.empty(),
                "AETHER_EXPLORER_STATE", "Finish the recorded Explorer repair before changing its module");
        if (config.version == 1) {
            auto additions = owned_roots(true);
            additions.erase(additions.begin(), additions.begin() + 3);
            absent_roots(additions);
            if (!open(L"CLSID").value)
                config.created_parents |= 1u << 3;
            config.legacy_prior = true;
        } else
            config.previous_icon = config.icon_library;
        config.version = 2;
        config.icon_library = desired;
    } else if (existing && operation == ExplorerOperation::register_handler)
        return result(config, true, false);
    validate_runtime(config, held_store);
    // An explicit registration/repair creates only the private cache root.
    // Existing artwork, failure evidence and unrecognized entries are retained.
    (void)shell::IconCache(shell::icon_cache_root(), true);
    config.state = HandlerState::pending;
    notification.changed = true;
    commit(root.value, config);
    for (const auto &[path, values] : projections(config)) {
        auto key = open(path, true, true);
        private_policy(key.value);
        if (values.contains(L"AetherOwner"))
            write(key.value, L"AetherOwner", string_value(owner_id(config)));
        for (const auto &[name, value] : values)
            write(key.value, name.c_str(), value);
        flush(key.value);
    }
    require(verify(config), "AETHER_EXPLORER_IO",
            "Explorer registration failed readback; explicit repair is required");
    config.state = HandlerState::ready;
    config.previous_icon.clear();
    config.legacy_prior = false;
    commit(root.value, config);
    return result(config, true, notify_shell);
}
} // namespace aether::install
