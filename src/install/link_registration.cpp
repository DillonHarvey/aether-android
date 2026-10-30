#include "aether/install/link_registration.hpp"
#include "aether/common/text.hpp"
#include "aether/host/document_service.hpp"
#include "aether/install/shell.hpp"
#include "aether/security/worker_image.hpp"
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
constexpr wchar_t handlers[] = L"Software\\Aether\\LinkHandlers";
constexpr wchar_t registered_apps[] = L"Software\\RegisteredApplications";
constexpr wchar_t intent_name[] = L"AetherRegistration";
constexpr std::string_view magic = "AETLNK1";
constexpr std::string_view file_magic = "AETLNK2";
constexpr std::size_t record_limit = 8192, handler_limit = 4096;
enum class Phase : std::uint32_t { pending = 1, ready, removing };
struct Configuration {
    Phase phase = Phase::pending;
    std::string id;
    std::filesystem::path launcher, store;
    std::vector<std::string> schemes;
    std::vector<FileAssociation> files;
};
[[noreturn]] void fail(const char *code, const char *message) { throw InstallError(code, message); }
void require(bool okay, const char *message) { if (!okay) fail("AETHER_LINK_REGISTRATION_CONFLICT", message); }
void check(LSTATUS status) { if (status != ERROR_SUCCESS) fail("AETHER_LINK_REGISTRATION_IO", "Windows link registration could not complete; existing material is preserved"); }
struct Key {
    HKEY value = nullptr;
    ~Key() { if (value) RegCloseKey(value); }
    Key() = default;
    Key(Key &&other) noexcept : value(std::exchange(other.value, nullptr)) {}
    Key &operator=(Key &&other) noexcept {
        if (value) RegCloseKey(value);
        value = std::exchange(other.value, nullptr); return *this;
    }
    Key(const Key &) = delete;
    Key &operator=(const Key &) = delete;
};
struct Descriptor {
    PSECURITY_DESCRIPTOR value = nullptr;
    Descriptor() {
        auto policy = security::runtime_directory_sddl();
        for (auto at = policy.find(L";OICI;FA;"); at != policy.npos; at = policy.find(L";OICI;FA;"))
            policy.replace(at, 9, L";;KA;");
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(policy.c_str(), SDDL_REVISION_1, &value, nullptr) != FALSE,
                "Cannot construct the owned link-registration policy");
    }
    ~Descriptor() { LocalFree(value); }
};
void private_policy(HKEY key) {
    PSECURITY_DESCRIPTOR actual = nullptr;
    PSID owner = nullptr, expected_owner = nullptr;
    PACL acl = nullptr, expected_acl = nullptr;
    Descriptor expected;
    BOOL present = FALSE, defaulted = FALSE;
    const auto status = GetSecurityInfo(key, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                        &owner, nullptr, &acl, nullptr, &actual);
    struct Release { PSECURITY_DESCRIPTOR value; ~Release() { LocalFree(value); } } release{actual};
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
    require(status == ERROR_SUCCESS && owner && acl &&
        GetSecurityDescriptorOwner(expected.value, &expected_owner, &defaulted) &&
        GetSecurityDescriptorDacl(expected.value, &present, &expected_acl, &defaulted) && present && expected_acl &&
        EqualSid(owner, expected_owner) && GetSecurityDescriptorControl(actual, &control, &revision) &&
        (control & SE_DACL_PROTECTED) && acl->AclSize == expected_acl->AclSize &&
        std::memcmp(acl, expected_acl, acl->AclSize) == 0, "Link registration has an unexpected owner or ACL");
}
std::wstring record_root(std::string_view id) { return std::wstring(handlers) + L"\\" + utf16(id); }
std::wstring progid(std::string_view id) { return L"Aether.Link." + utf16(id); }
std::wstring class_root(std::string_view id) { return L"Software\\Classes\\" + progid(id); }
std::wstring file_progid(std::string_view id) { return L"Aether.File." + utf16(id); }
std::wstring file_class_root(std::string_view id) { return L"Software\\Classes\\" + file_progid(id); }
bool owned(std::wstring_view path, std::string_view id) {
    if (id.empty()) return false;
    for (const auto &root : {record_root(id), class_root(id), file_class_root(id)})
        if (path == root || (path.starts_with(root) && path.size() > root.size() && path[root.size()] == L'\\')) return true;
    return false;
}
// Open every component itself, never traverse a registry link. The sole
// Windows-owned Classes alias is accepted only for this exact user's hive.
Key open(std::wstring_view path, bool writable = false, bool create = false,
         std::string_view id = {}, HKEY hive = HKEY_CURRENT_USER) {
    Key held;
    std::wstring traversed;
    std::size_t begin = 0;
    while (begin < path.size()) {
        const auto end = path.find(L'\\', begin);
        const auto part = std::wstring(path.substr(begin, end == path.npos ? path.size() - begin : end - begin));
        require(!part.empty(), "Link registration path has an empty component");
        if (!traversed.empty()) traversed += L'\\';
        traversed += part;
        const bool private_key = owned(traversed, id);
        const auto access = KEY_READ | KEY_WOW64_64KEY | (writable ? KEY_WRITE | DELETE : 0);
        Key next;
        const auto parent = held.value ? held.value : hive;
        auto status = RegOpenKeyExW(parent, part.c_str(), REG_OPTION_OPEN_LINK, access, &next.value);
        if (status == ERROR_FILE_NOT_FOUND && create) {
            Descriptor descriptor;
            SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor.value, FALSE};
            check(RegCreateKeyExW(parent, part.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, access,
                                  private_key ? &attributes : nullptr, &next.value, nullptr));
            status = ERROR_SUCCESS;
        }
        if (status == ERROR_FILE_NOT_FOUND) return {};
        check(status);
        DWORD type = 0, bytes = 0;
        auto link = RegQueryValueExW(next.value, L"SymbolicLinkValue", nullptr, &type, nullptr, &bytes);
        if (hive == HKEY_CURRENT_USER && traversed == L"Software\\Classes" && link == ERROR_SUCCESS) {
            const auto policy = security::runtime_directory_sddl();
            const auto owner_end = policy.find(L"G:");
            require(policy.starts_with(L"O:") && owner_end != policy.npos, "Cannot identify the current Classes hive");
            const auto leaf = policy.substr(2, owner_end - 2) + L"_Classes";
            const auto expected = L"\\Registry\\User\\" + leaf;
            std::wstring actual(expected.size(), L'\0');
            require(type == REG_LINK && bytes == expected.size() * sizeof(wchar_t), "Classes alias target differs from the current user");
            check(RegQueryValueExW(next.value, L"SymbolicLinkValue", nullptr, &type, reinterpret_cast<BYTE *>(actual.data()), &bytes));
            require(type == REG_LINK && bytes == expected.size() * sizeof(wchar_t) &&
                CompareStringOrdinal(actual.data(), static_cast<int>(actual.size()), expected.data(), static_cast<int>(expected.size()), TRUE) == CSTR_EQUAL,
                "Classes alias target differs from the current user");
            next = {};
            check(RegOpenKeyExW(HKEY_USERS, leaf.c_str(), REG_OPTION_OPEN_LINK, access, &next.value));
            link = RegQueryValueExW(next.value, L"SymbolicLinkValue", nullptr, &type, nullptr, &bytes);
        }
        require(link == ERROR_FILE_NOT_FOUND, "Registry links in link registration are preserved");
        if (private_key) private_policy(next.value);
        held = std::move(next);
        if (end == path.npos) break;
        begin = end + 1;
    }
    return held;
}
struct Value {
    DWORD type = REG_NONE;
    std::vector<std::uint8_t> bytes;
    bool operator==(const Value &) const = default;
};
std::optional<Value> read(HKEY key, const std::wstring &name) {
    Value result; DWORD size = 0;
    auto status = RegQueryValueExW(key, name.c_str(), nullptr, &result.type, nullptr, &size);
    if (status == ERROR_FILE_NOT_FOUND) return {};
    check(status); require(size <= record_limit, "Link registration value exceeds its bound");
    result.bytes.resize(size);
    check(RegQueryValueExW(key, name.c_str(), nullptr, &result.type, result.bytes.data(), &size));
    require(size == result.bytes.size(), "Link registration changed while being read");
    return result;
}
void write(HKEY key, const std::wstring &name, const Value &value) {
    check(RegSetValueExW(key, name.c_str(), 0, value.type, value.bytes.data(), static_cast<DWORD>(value.bytes.size())));
}
void flush(HKEY key) { check(RegFlushKey(key)); }
Value text(std::wstring_view value) {
    Value result{REG_SZ, {}};
    result.bytes.reserve((value.size() + 1) * sizeof(wchar_t));
    for (const auto unit : value) { result.bytes.push_back(static_cast<std::uint8_t>(unit)); result.bytes.push_back(static_cast<std::uint8_t>(unit >> 8)); }
    result.bytes.push_back(0); result.bytes.push_back(0); return result;
}
bool same_path(const std::filesystem::path &left, const std::filesystem::path &right) {
    return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) == CSTR_EQUAL;
}
bool path_syntax(const std::filesystem::path &path, std::size_t bound) {
    const auto value = path.native();
    auto canonical = path.lexically_normal(); canonical.make_preferred();
    if (!path.is_absolute() || value != canonical.native() || value.size() < 4 || value.size() >= bound ||
        value[1] != L':' || value[2] != L'\\' || value.find(L'%') != value.npos ||
        !((value[0] >= L'A' && value[0] <= L'Z') || (value[0] >= L'a' && value[0] <= L'z'))) return false;
    for (const auto &part : path.relative_path()) {
        const auto leaf = part.native();
        if (leaf.empty() || leaf == L"." || leaf == L".." || leaf.back() == L'.' || leaf.back() == L' ' ||
            leaf.find_first_of(L":<>\"|?*") != leaf.npos || std::any_of(leaf.begin(), leaf.end(), [](wchar_t unit) { return unit < 32; })) return false;
    }
    return true;
}
std::vector<std::string> canonical_schemes(const std::vector<std::string> &input) {
    require(input.size() <= 32, "Link offers permit at most 32 explicit schemes");
    for (const auto &scheme : input) {
        require(!scheme.empty() && scheme.size() <= 64 && scheme.front() >= 'a' && scheme.front() <= 'z' &&
            std::all_of(scheme.begin(), scheme.end(), [](char unit) {
                return (unit >= 'a' && unit <= 'z') || (unit >= '0' && unit <= '9') || unit == '+' || unit == '-' || unit == '.';
            }), "Scheme offers require bounded canonical lowercase RFC names");
        require(scheme != "file" && scheme != "content" && scheme != "intent" && scheme != "android.resource",
                "This scheme requires unsupported file, provider, grant or embedded-Intent behavior");
    }
    auto result = input;
    std::sort(result.begin(), result.end());
    require(std::adjacent_find(result.begin(), result.end()) == result.end(), "Scheme offers must be distinct");
    return result;
}
std::vector<FileAssociation> canonical_files(const std::vector<FileAssociation> &input) {
    require(input.size() <= 32, "File offers permit at most 32 explicit extension/MIME pairs");
    for (const auto &file : input) {
        // Simple extensions match filesystem::path::extension directly. No
        // wildcard, compound suffix, registry path or default selection enters.
        require(file.extension.size() >= 2 && file.extension.size() <= 16 && file.extension.front() == '.' &&
            std::all_of(file.extension.begin() + 1, file.extension.end(), [](char unit) {
                return (unit >= 'a' && unit <= 'z') || (unit >= '0' && unit <= '9');
            }), "File offers require a dot and one to 15 lowercase ASCII letters or digits");
        require(host::valid_document_mime(file.mime_type), "File offers require an explicit canonical document MIME type");
    }
    auto result = input;
    std::sort(result.begin(), result.end(), [](const auto &left, const auto &right) {
        return left.extension < right.extension;
    });
    require(std::adjacent_find(result.begin(), result.end(), [](const auto &left, const auto &right) {
        return left.extension == right.extension;
    }) == result.end(), "File offers must use distinct extensions");
    return result;
}
void validate(const Configuration &config) {
    require(security::valid_installed_id(config.id) && path_syntax(config.launcher, 512) && path_syntax(config.store, 200) &&
        config.launcher.filename() == L"aether-shell.exe", "Link registration identity or fixed paths are invalid");
    require(canonical_schemes(config.schemes) == config.schemes, "Recorded scheme offers are not canonical");
    require(canonical_files(config.files) == config.files, "Recorded file offers are not canonical");
    require(!config.schemes.empty() || !config.files.empty(), "At least one explicit scheme or file offer is required");
}
Value encode(const Configuration &config) {
    const auto schema = config.files.empty() ? magic : file_magic;
    Value result; result.type = REG_BINARY; result.bytes.assign(schema.begin(), schema.end());
    const auto number = [&](std::uint32_t value) { for (unsigned shift = 0; shift < 32; shift += 8) result.bytes.push_back(static_cast<std::uint8_t>(value >> shift)); };
    const auto string = [&](std::string_view value) {
        require(value.size() <= record_limit && result.bytes.size() + value.size() + 4 + 64 <= record_limit, "Link registration intent exceeds its bound");
        number(static_cast<std::uint32_t>(value.size())); result.bytes.insert(result.bytes.end(), value.begin(), value.end());
    };
    number(static_cast<std::uint32_t>(config.phase)); string(config.id); string(utf8(config.launcher.wstring())); string(utf8(config.store.wstring()));
    number(static_cast<std::uint32_t>(config.schemes.size())); for (const auto &scheme : config.schemes) string(scheme);
    if (!config.files.empty()) {
        number(static_cast<std::uint32_t>(config.files.size()));
        for (const auto &file : config.files) { string(file.extension); string(file.mime_type); }
    }
    require(result.bytes.size() + 64 <= record_limit, "Link registration intent exceeds its bound");
    const auto hash = apk::sha256(result.bytes); result.bytes.insert(result.bytes.end(), hash.begin(), hash.end()); return result;
}
Configuration decode(const Value &value) {
    require(value.type == REG_BINARY && value.bytes.size() >= magic.size() + 84 && value.bytes.size() <= record_limit,
        "Link registration intent is invalid");
    const bool legacy = std::equal(magic.begin(), magic.end(), value.bytes.begin());
    require(legacy || std::equal(file_magic.begin(), file_magic.end(), value.bytes.begin()), "Link registration intent version is invalid");
    const auto payload = apk::Bytes(value.bytes).first(value.bytes.size() - 64);
    require(apk::sha256(payload) == std::string(value.bytes.end() - 64, value.bytes.end()), "Link registration intent checksum differs");
    std::size_t at = magic.size();
    const auto number = [&] {
        require(at <= payload.size() && payload.size() - at >= 4, "Link intent contains a truncated integer");
        std::uint32_t result = 0; for (unsigned shift = 0; shift < 32; shift += 8) result |= static_cast<std::uint32_t>(payload[at++]) << shift;
        return result;
    };
    const auto string = [&](std::size_t bound) {
        const auto size = number(); require(size <= bound && size <= payload.size() - at, "Link intent contains truncated or oversized text");
        std::string result(reinterpret_cast<const char *>(payload.data() + at), size); at += size;
        require(result.find('\0') == result.npos, "Link intent contains embedded null text"); return result;
    };
    Configuration result;
    const auto phase = number(); require(phase >= 1 && phase <= 3, "Link intent phase is unknown"); result.phase = static_cast<Phase>(phase);
    result.id = string(32);
    try { result.launcher = utf16(string(2048)); result.store = utf16(string(800)); }
    catch (const std::invalid_argument &) { fail("AETHER_LINK_REGISTRATION_CONFLICT", "Link intent contains invalid path encoding"); }
    const auto count = number(); require(count <= 32 && (!legacy || count), "Link intent contains invalid scheme offers");
    for (std::uint32_t index = 0; index < count; ++index) result.schemes.push_back(string(64));
    if (!legacy) {
        const auto file_count = number(); require(file_count && file_count <= 32, "Link intent contains invalid file offers");
        for (std::uint32_t index = 0; index < file_count; ++index)
            result.files.push_back({string(16), string(255)});
    }
    require(at == payload.size(), "Link intent contains trailing material"); validate(result); return result;
}
using Tree = std::map<std::wstring, std::map<std::wstring, Value>>;
std::wstring command(const Configuration &config) {
    return quote_windows_argument(config.launcher.wstring()) + L" link-activation " + utf16(config.id) + L" \"%1\"";
}
std::wstring file_command(const Configuration &config) {
    return quote_windows_argument(config.launcher.wstring()) + L" file-activation " + utf16(config.id) + L" \"%1\"";
}
Tree projections(const Configuration &config) {
    const auto primary = record_root(config.id), type = class_root(config.id), capability = primary + L"\\Capabilities";
    const auto icon = text(quote_windows_argument(config.launcher.wstring()) + L",0");
    const auto label = text(L"Aether installed app " + utf16(config.id));
    Tree result{
        {primary, {{intent_name, encode(config)}}},
        {capability, {{L"ApplicationName", text(progid(config.id))},
            {L"ApplicationDescription", text(config.files.empty() ? L"Review links in an installed Aether app" :
                L"Review links and selected files in an installed Aether app")}, {L"ApplicationIcon", icon}}},
        {capability + L"\\UrlAssociations", {}},
        {type, {{L"", label}, {L"URL Protocol", text(L"")}, {L"AllowSilentDefaultTakeOver", {}}, {L"AetherOwner", text(utf16(config.id))}}},
        {type + L"\\DefaultIcon", {{L"", icon}}},
        {type + L"\\shell", {{L"", text(L"open")}}},
        {type + L"\\shell\\open", {{L"", text(L"Review link with Aether")}}},
        {type + L"\\shell\\open\\command", {{L"", text(command(config))}}}
    };
    for (const auto &scheme : config.schemes) result[capability + L"\\UrlAssociations"].emplace(utf16(scheme), text(progid(config.id)));
    if (!config.files.empty()) {
        const auto file_type = file_class_root(config.id);
        result[capability + L"\\FileAssociations"] = {};
        for (const auto &file : config.files)
            result[capability + L"\\FileAssociations"].emplace(utf16(file.extension), text(file_progid(config.id)));
        result[file_type] = {{L"", label}, {L"AllowSilentDefaultTakeOver", {}}, {L"AetherOwner", text(utf16(config.id))}};
        result[file_type + L"\\DefaultIcon"] = {{L"", icon}};
        result[file_type + L"\\shell"] = {{L"", text(L"open")}};
        result[file_type + L"\\shell\\open"] = {{L"", text(L"Review file with Aether")}, {L"MultiSelectModel", text(L"Single")}};
        result[file_type + L"\\shell\\open\\command"] = {{L"", text(file_command(config))}};
    }
    return result;
}
std::pair<DWORD, DWORD> counts(HKEY key) {
    DWORD children = 0, values = 0;
    check(RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &children, nullptr, nullptr, &values, nullptr, nullptr, nullptr, nullptr));
    return {children, values};
}
bool verify(const Configuration &config) {
    require(!open(class_root(config.id), false, false, {}, HKEY_LOCAL_MACHINE).value, "A machine-wide ProgID with this identity is preserved");
    require(!open(file_class_root(config.id), false, false, {}, HKEY_LOCAL_MACHINE).value,
        "A machine-wide file ProgID with this identity is preserved");
    if (config.files.empty())
        require(!open(file_class_root(config.id)).value, "Unrecorded file ProgID is preserved");
    auto machine_apps = open(registered_apps, false, false, {}, HKEY_LOCAL_MACHINE);
    require(!machine_apps.value || !read(machine_apps.value, progid(config.id)), "A machine-wide RegisteredApplications offer with this identity is preserved");
    const auto tree = projections(config);
    bool complete = true;
    for (const auto &[path, values] : tree) {
        auto node = open(path, false, false, config.id);
        if (!node.value) { complete = false; continue; }
        std::set<std::wstring> children;
        for (const auto &[other, ignored] : tree) {
            (void)ignored;
            if (other.starts_with(path + L"\\")) {
                const auto child = other.substr(path.size() + 1); if (child.find(L'\\') == child.npos) children.insert(child);
            }
        }
        const auto [child_count, value_count] = counts(node.value);
        require(child_count <= children.size() && value_count <= values.size(), "Unknown link registration material is preserved");
        for (DWORD index = 0; index < child_count; ++index) {
            std::array<wchar_t, 256> name{}; DWORD size = static_cast<DWORD>(name.size());
            check(RegEnumKeyExW(node.value, index, name.data(), &size, nullptr, nullptr, nullptr, nullptr));
            require(children.contains(std::wstring(name.data(), size)), "Unknown link registration child is preserved");
        }
        for (DWORD index = 0; index < value_count; ++index) {
            std::array<wchar_t, 256> name{}; DWORD size = static_cast<DWORD>(name.size());
            check(RegEnumValueW(node.value, index, name.data(), &size, nullptr, nullptr, nullptr, nullptr));
            const auto field = std::wstring(name.data(), size); const auto expected = values.find(field);
            require(expected != values.end() && read(node.value, field) == expected->second, "Unknown or changed link registration value is preserved");
        }
        for (const auto &[name, expected] : values) { (void)expected; if (!read(node.value, name)) complete = false; }
    }
    auto applications = open(registered_apps);
    const auto offered = applications.value ? read(applications.value, progid(config.id)) : std::nullopt;
    if (!offered) complete = false;
    else require(*offered == text(record_root(config.id) + L"\\Capabilities"), "A foreign RegisteredApplications value is preserved");
    return complete;
}
std::optional<Configuration> inventory(std::string_view id) {
    auto primary = open(record_root(id), false, false, id);
    if (!primary.value) {
        require(!open(class_root(id)).value && !open(class_root(id), false, false, {}, HKEY_LOCAL_MACHINE).value,
                "Unrecorded link ProgID is preserved");
        require(!open(file_class_root(id)).value && !open(file_class_root(id), false, false, {}, HKEY_LOCAL_MACHINE).value,
                "Unrecorded file ProgID is preserved");
        auto applications = open(registered_apps);
        require(!applications.value || !read(applications.value, progid(id)), "Unrecorded RegisteredApplications value is preserved");
        auto machine_apps = open(registered_apps, false, false, {}, HKEY_LOCAL_MACHINE);
        require(!machine_apps.value || !read(machine_apps.value, progid(id)), "A machine-wide RegisteredApplications offer with this identity is preserved");
        return {};
    }
    const auto value = read(primary.value, intent_name);
    require(value.has_value(), "Link registration has no recorded ownership intent");
    auto config = decode(*value); require(config.id == id, "Link ownership identity differs from its key"); return config;
}
void commit(const Configuration &config) {
    auto primary = open(record_root(config.id), true, true, config.id);
    write(primary.value, intent_name, encode(config)); flush(primary.value);
    require(read(primary.value, intent_name) == encode(config), "Link registration intent failed durable readback");
}
void apply(const Configuration &config) {
    for (const auto &[path, values] : projections(config)) {
        auto node = open(path, true, true, config.id);
        for (const auto &[name, value] : values) {
            const auto current = read(node.value, name);
            require(!current || *current == value, "Changed link registration is preserved before projection");
            if (!current) write(node.value, name, value);
        }
        flush(node.value);
    }
    auto applications = open(registered_apps, true, true);
    const auto name = progid(config.id);
    const auto expected = text(record_root(config.id) + L"\\Capabilities");
    const auto current = read(applications.value, name);
    require(!current || *current == expected, "Foreign RegisteredApplications value is preserved");
    if (!current) write(applications.value, name, expected);
    flush(applications.value);
}
void delete_owned(std::wstring_view path, std::string_view id, const std::map<std::wstring, Value> &expected) {
    auto node = open(path, true, false, id); if (!node.value) return;
    const auto [children, values] = counts(node.value);
    require(children == 0 && values <= expected.size(), "Unknown material prevents link registration removal");
    for (DWORD index = 0; index < values; ++index) {
        std::array<wchar_t, 256> name{}; DWORD length = static_cast<DWORD>(name.size());
        check(RegEnumValueW(node.value, index, name.data(), &length, nullptr, nullptr, nullptr, nullptr));
        const auto field = std::wstring(name.data(), length);
        const auto value = expected.find(field);
        require(value != expected.end() && read(node.value, field) == value->second,
                "Changed link registration value is preserved before removal");
    }
    node = {};
    check(RegDeleteKeyExW(HKEY_CURRENT_USER, std::wstring(path).c_str(), KEY_WOW64_64KEY, 0));
}
struct Notification {
    bool enabled, changed = false;
    ~Notification() { if (enabled && changed) SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr); }
};
LinkRegistration result(const Configuration &config, bool complete, bool notified) {
    return {config.phase == Phase::ready ? "registered" : config.phase == Phase::pending ? "pending-repair" : "removing",
            complete && config.phase == Phase::ready, notified, config.schemes, config.files};
}
} // namespace

std::string LinkRegistration::json() const {
    std::string result = "{\"schemaVersion\":1,\"operation\":\"link-handlers\",\"state\":" + json_quote(state) +
        ",\"verified\":" + (verified ? "true" : "false") + ",\"shellNotified\":" + (notified ? "true" : "false") +
        ",\"perUser\":true,\"defaultAssociationWritten\":false,\"userChoiceWritten\":false,\"effectiveDefaultChecked\":false,\"schemes\":[";
    for (std::size_t index = 0; index < schemes.size(); ++index) { if (index) result += ','; result += json_quote(schemes[index]); }
    result += "],\"files\":[";
    for (std::size_t index = 0; index < files.size(); ++index) {
        if (index) result += ',';
        result += "{\"extension\":" + json_quote(files[index].extension) + ",\"mimeType\":" + json_quote(files[index].mime_type) + '}';
    }
    return result + "]}";
}
LinkRegistration link_registration(LinkRegistrationOperation operation, const InstalledApp &app,
                                   const std::filesystem::path &store, const std::vector<std::string> &schemes,
                                   bool notify, const std::vector<FileAssociation> &files) {
    require(security::valid_installed_id(app.id), "Link registration requires a valid app identity");
    require((schemes.empty() && files.empty()) || operation == LinkRegistrationOperation::register_handler,
        "Scheme and file choices are accepted only for explicit registration");
    require(operation >= LinkRegistrationOperation::status && operation <= LinkRegistrationOperation::check_upgrade,
            "Unknown link registration operation");
    const bool ordinary = operation == LinkRegistrationOperation::status || operation == LinkRegistrationOperation::register_handler ||
                          operation == LinkRegistrationOperation::repair;
    auto shell = hold_shell_registration();
    auto existing = inventory(app.id);
    // Ordinary app removal also calls this for apps that never offered links.
    // No shell projection, launcher or registration write is needed in that case.
    if (!existing && operation == LinkRegistrationOperation::remove) return {};
    require(path_syntax(store, 200), "Link registration requires a bounded fixed store path");
    if (ordinary) {
        require(path_syntax(utf16(app.launcher), 512) && installed_state(app.state) && app.shell == ShellState::ready &&
            same_path(utf16(app.launcher), shell_launcher()) &&
            inspect_shell_registration(app, store), "Link registration requires this runtime's intact installed app registration");
        require(GetDriveTypeW(store.root_path().c_str()) == DRIVE_FIXED &&
            GetDriveTypeW(std::filesystem::path(utf16(app.launcher)).root_path().c_str()) == DRIVE_FIXED,
            "Link offers require local fixed-drive runtime and store paths");
    }
    if (existing) require(same_path(existing->store, store) &&
                            (app.launcher.empty() || same_path(existing->launcher, utf16(app.launcher))),
                          "Recorded link offers belong to another runtime or package store");
    if (existing && operation == LinkRegistrationOperation::remove && app.launcher.empty())
        require(same_path(existing->launcher, shell_launcher()),
                "An offer without a journal launcher binding must be removed by its owning runtime");
    const bool complete = existing ? verify(*existing) : false;
    if (operation == LinkRegistrationOperation::status || operation == LinkRegistrationOperation::check_upgrade)
        return existing ? result(*existing, complete, false) : LinkRegistration{};
    Notification notification{notify};
    if (!existing && operation != LinkRegistrationOperation::register_handler) return {};
    Configuration config;
    if (existing) {
        config = *existing;
        if (operation == LinkRegistrationOperation::register_handler) {
            require(canonical_schemes(schemes) == config.schemes && canonical_files(files) == config.files,
                "Existing offers require their recorded scheme and file choices");
            require(config.phase == Phase::ready && complete, "Existing link offers need explicit repair or removal");
            return result(config, true, false);
        }
    } else {
        config.id = app.id; config.launcher = utf16(app.launcher); config.store = store;
        config.schemes = canonical_schemes(schemes); config.files = canonical_files(files); validate(config);
        (void)encode(config); // Refuse the combined existing 8 KiB budget before creating an owned key.
        auto parent = open(handlers);
        if (parent.value) {
            const auto [children, values] = counts(parent.value);
            require(values == 0 && children < handler_limit, "Link handler ownership exceeds the bounded dependency inventory");
        }
        // The primary key must still be empty before writing the first intent.
        auto primary = open(record_root(config.id), true, true, config.id);
        require(counts(primary.value) == std::pair<DWORD, DWORD>{0, 0}, "Link ownership changed before registration");
        notification.changed = true; primary = {}; commit(config);
    }
    if (operation == LinkRegistrationOperation::remove || config.phase == Phase::removing) {
        notification.changed = true; config.phase = Phase::removing; commit(config);
        auto applications = open(registered_apps, true);
        if (applications.value && read(applications.value, progid(config.id))) {
            require(read(applications.value, progid(config.id)) == text(record_root(config.id) + L"\\Capabilities"),
                    "RegisteredApplications changed before removal");
            check(RegDeleteValueW(applications.value, progid(config.id).c_str())); flush(applications.value);
        }
        const auto tree = projections(config);
        for (auto node = tree.rbegin(); node != tree.rend(); ++node) delete_owned(node->first, config.id, node->second);
        // Flush deletion metadata through retained shared containers without
        // deleting or adopting those containers or any sibling registration.
        auto primary_parent = open(handlers, true);
        if (primary_parent.value) flush(primary_parent.value);
        auto classes_parent = open(L"Software\\Classes", true);
        if (classes_parent.value) flush(classes_parent.value);
        require(!inventory(config.id), "Link removal failed readback");
        LinkRegistration removed; removed.notified = notify; return removed;
    }
    if (config.phase == Phase::ready && complete) return result(config, true, false);
    notification.changed = true; config.phase = Phase::pending; commit(config); apply(config);
    require(verify(config), "Link registration projections failed readback");
    config.phase = Phase::ready; commit(config);
    require(verify(config), "Ready link registration failed readback");
    return result(config, true, notify);
}
bool link_registration_present(const std::filesystem::path &runtime) {
    auto shell = hold_shell_registration();
    auto parent = open(handlers); if (!parent.value) return false;
    const auto [children, values] = counts(parent.value);
    require(values == 0 && children <= handler_limit, "Unknown or excessive link-handler ownership blocks runtime removal");
    if (!children) return false;
    // Legacy runtimes may have paths outside the stricter new-offer syntax.
    // Dependency inspection compares their actual canonical path without
    // imposing new registration restrictions on an unrelated installation.
    auto target_runtime = runtime.lexically_normal(); target_runtime.make_preferred();
    require(target_runtime.is_absolute(), "Runtime dependency path must be absolute");
    bool found = false;
    for (DWORD index = 0; index < children; ++index) {
        std::array<wchar_t, 64> name{}; DWORD length = static_cast<DWORD>(name.size());
        check(RegEnumKeyExW(parent.value, index, name.data(), &length, nullptr, nullptr, nullptr, nullptr));
        const auto id = utf8(std::wstring(name.data(), length));
        require(security::valid_installed_id(id), "Unknown link-handler identity blocks runtime removal");
        const auto config = inventory(id); require(config.has_value(), "Link ownership disappeared during dependency inspection");
        (void)verify(*config);
        found = found || same_path(config->launcher.parent_path(), target_runtime);
    }
    return found;
}
} // namespace aether::install
