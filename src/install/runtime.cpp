#include "aether/install/runtime.hpp"
#include "aether/common/text.hpp"
#include "aether/install/explorer.hpp"
#include "aether/install/link_registration.hpp"
#include "aether/install/runtime_setup.hpp"
#include "aether/install/shell.hpp"
#include "aether/install/store.hpp"
#include "aether/security/worker_image.hpp"
#include "aether/shell/icon_service.hpp"
#include "private.hpp"
#include "runtime_registration.hpp"
#include <TlHelp32.h>
#include <Windows.h>
#include <aclapi.h>
#include <algorithm>
#include <array>
#include <bcrypt.h>
#include <cstring>
#include <iostream>
#include <optional>
#include <sddl.h>
#include <set>
#include <shlobj.h>

namespace aether::install {
namespace {
using host::UniqueHandle;
constexpr wchar_t record_file[] = L"runtime.registry", lease_file[] = L"runtime.lease";
constexpr std::size_t frame_size = 65536, digest_offset = frame_size - 64, max_frames = 1024;
constexpr std::size_t max_catalogue_payloads = 256;
constexpr std::uint64_t max_image = 256ull * 1024 * 1024;
enum class Phase : std::uint64_t { preparing = 1, ready, removing, upgrading };
struct Payload {
    std::string path, sha256;
    std::uint64_t size = 0;
    bool worker = false;
    bool operator==(const Payload &) const = default;
};
struct Record {
    Phase phase = Phase::preparing;
    std::filesystem::path root;
    std::vector<Payload> files;
    std::vector<std::filesystem::path> stores;
    std::string native_id;
    std::vector<Payload> pending;
    std::string icon_library, pending_icon_library;
    std::uint64_t schema = 1;
    std::uint64_t compatibility = 1;
};
void require(bool ok, const char *code, const char *message) {
    if (!ok)
        throw InstallError(code, message);
}
void io(bool ok, const char *message) { require(ok, "AETHER_RUNTIME_IO", message); }
void corrupt(bool ok) {
    require(ok, "AETHER_RUNTIME_RECORD",
            "Runtime catalogue failed format or integrity checks; existing material is preserved");
}
bool missing(const std::filesystem::path &path) {
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
        return false;
    const auto error = GetLastError();
    io(error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND, "Cannot inspect runtime path");
    return true;
}
bool same_path(const std::filesystem::path &a, const std::filesystem::path &b) {
    return CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) == CSTR_EQUAL;
}
bool below(const std::filesystem::path &child, const std::filesystem::path &parent) {
    auto path = child;
    while (!path.empty()) {
        if (same_path(path, parent))
            return true;
        if (path == path.parent_path())
            break;
        path = path.parent_path();
    }
    return false;
}
void validate_path(const std::filesystem::path &path) {
    const auto text = path.native();
    auto canonical = path.lexically_normal();
    canonical.make_preferred();
    require(text == canonical.native(), "AETHER_RUNTIME_PATH",
            "Runtime/store paths must use canonical backslash-separated components");
    require(path.is_absolute() && text.size() >= 4 && text.size() < 200 &&
                ((text[0] >= L'A' && text[0] <= L'Z') || (text[0] >= L'a' && text[0] <= L'z')) &&
                text[1] == L':' && text[2] == L'\\' && !path.filename().empty(),
            "AETHER_RUNTIME_PATH",
            "Runtime/store paths must be canonical absolute local paths shorter than 200 characters");
    require(GetDriveTypeW(path.root_path().c_str()) == DRIVE_FIXED, "AETHER_RUNTIME_PATH",
            "A runtime requires a local fixed drive");
    for (const auto &part : path.relative_path()) {
        const auto name = part.native();
        require(!name.empty() && name != L"." && name != L".." && name.back() != L'.' &&
                    name.back() != L' ' && name.find_first_of(L":<>\"|?*") == std::wstring::npos &&
                    std::none_of(name.begin(), name.end(), [](wchar_t c) { return c < 32; }),
                "AETHER_RUNTIME_PATH", "Runtime/store paths contain an unsafe or ambiguous component");
    }
}
std::filesystem::path current_image() {
    std::array<wchar_t, 32768> path{};
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    io(size && size < path.size(), "Cannot resolve this shared runtime");
    return std::filesystem::path(std::wstring(path.data(), size));
}
std::filesystem::path current_root() { return current_image().parent_path(); }
void verify_resolved_path(HANDLE handle, const std::filesystem::path &path) {
    std::array<wchar_t, 32768> name{};
    const auto size = GetFinalPathNameByHandleW(handle, name.data(), static_cast<DWORD>(name.size()),
                                                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    io(size && size < name.size(), "Cannot resolve a runtime/store directory identity");
    const std::wstring resolved(name.data(), size);
    require(resolved.starts_with(L"\\\\?\\") && same_path(std::filesystem::path(resolved.substr(4)), path),
            "AETHER_RUNTIME_PATH", "Runtime/store paths must not use alternate directory names");
}
std::vector<UniqueHandle> ancestors(const std::filesystem::path &root) {
    validate_path(root);
    std::vector<UniqueHandle> held;
    auto path = root.root_path();
    for (const auto &part : root.parent_path().relative_path()) {
        path /= part;
        held.push_back(detail::hold_directory(path, false, false));
        verify_resolved_path(held.back().get(), path);
    }
    return held;
}
UniqueHandle directory(const std::filesystem::path &path, bool deleting = false) {
    UniqueHandle file(CreateFileW(
        path.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | (deleting ? DELETE : 0),
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    require(static_cast<bool>(file), "AETHER_RUNTIME_BUSY",
            "Runtime directory is busy or unavailable; no running app will be stopped automatically");
    try {
        security::verify_runtime_directory(file.get());
    } catch (const std::exception &) {
        throw InstallError("AETHER_RUNTIME_POLICY",
                           "Runtime directory has an unexpected installation policy");
    }
    verify_resolved_path(file.get(), path);
    return file;
}
UniqueHandle use_file(const std::filesystem::path &root, bool exclusive, bool create = false) {
    try {
        return detail::private_file(root / lease_file, GENERIC_READ | (exclusive ? DELETE : 0),
                                    create ? CREATE_NEW : OPEN_EXISTING, 0, exclusive ? 0 : FILE_SHARE_READ);
    } catch (const InstallError &error) {
        if (error.code == "AETHER_INSTALL_BUSY")
            throw InstallError(
                "AETHER_RUNTIME_BUSY",
                "This runtime has a live host or maintenance operation; close it before explicitly retrying");
        throw;
    }
}
struct Writer {
    std::vector<std::uint8_t> bytes;
    void number(std::uint64_t value) {
        for (unsigned shift = 0; shift < 64; shift += 8)
            bytes.push_back(static_cast<std::uint8_t>(value >> shift));
    }
    void text(std::string_view value) {
        number(value.size());
        bytes.insert(bytes.end(), value.begin(), value.end());
    }
};
struct Reader {
    apk::Bytes bytes;
    std::size_t at = 0;
    std::uint64_t number() {
        corrupt(at + 8 <= bytes.size());
        std::uint64_t value = 0;
        for (unsigned shift = 0; shift < 64; shift += 8)
            value |= static_cast<std::uint64_t>(bytes[at++]) << shift;
        return value;
    }
    std::string text(std::size_t limit) {
        const auto length = number();
        corrupt(length <= limit && length <= bytes.size() - at);
        const std::string value(reinterpret_cast<const char *>(bytes.data() + at),
                                static_cast<std::size_t>(length));
        at += static_cast<std::size_t>(length);
        return value;
    }
};
bool hex(std::string_view text) {
    return text.size() == 64 && std::all_of(text.begin(), text.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}
bool icon_payload(std::string_view name) {
    return name.size() == 97 && name.starts_with("shell-icons/") && hex(name.substr(12, 64)) &&
           name.substr(76) == "/AetherShellIcons.dll";
}
bool payload_name(std::string_view name, bool worker) {
    if (worker)
        return name == "runtime/aether_worker.exe" || name == "runtime/aether_graphics_worker.exe" ||
               name == "runtime/aether_icon_worker.exe";
    if (icon_payload(name))
        return true;
    if (name == "aether.exe" || name == "aether-shell.exe" || name == "aether_runtime_setup.exe" ||
        name == "aether-setup.exe")
        return true;
    if (!name.starts_with("licenses/") || !name.ends_with(".txt") || name.size() > 160)
        return false;
    const auto leaf = name.substr(9);
    return !leaf.empty() && leaf.front() != '.' && leaf.find("..") == std::string_view::npos &&
           std::all_of(leaf.begin(), leaf.end(), [](char c) {
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                      c == '_' || c == '-' || c == '.';
           });
}
bool same_layout(const std::vector<Payload> &a, const std::vector<Payload> &b) {
    return a.size() == b.size() &&
           std::equal(a.begin(), a.end(), b.begin(),
                      [](const auto &x, const auto &y) { return x.path == y.path && x.worker == y.worker; });
}
bool additive_layout(const std::vector<Payload> &previous, const std::vector<Payload> &next) {
    // Versioned DLLs are immutable, retained installed payloads. New metadata
    // workers, notices and DLL versions are the only permitted layout additions.
    for (const auto &item : previous) {
        const auto at = std::find_if(next.begin(), next.end(),
                                     [&](const auto &other) { return other.path == item.path; });
        if (at == next.end() || at->worker != item.worker || (icon_payload(item.path) && *at != item))
            return false;
    }
    for (const auto &item : next)
        if (std::none_of(previous.begin(), previous.end(),
                         [&](const auto &old) { return old.path == item.path; }) &&
            item.path != "runtime/aether_icon_worker.exe" && !item.path.starts_with("licenses/") &&
            !icon_payload(item.path))
            return false;
    return true;
}
bool selected_icon(const std::vector<Payload> &files, std::string_view path) {
    return icon_payload(path) &&
           std::any_of(files.begin(), files.end(), [&](const auto &item) { return item.path == path; });
}
std::string single_icon(const std::vector<Payload> &files) {
    std::string result;
    for (const auto &file : files)
        if (icon_payload(file.path)) {
            require(result.empty(), "AETHER_SETUP_BUNDLE", "A distribution must select exactly one icon DLL");
            result = file.path;
        }
    require(!result.empty(), "AETHER_SETUP_BUNDLE", "The versioned icon DLL is missing");
    return result;
}
struct Catalogue {
    UniqueHandle file;
    Record record;
    std::size_t count = 0, tail = 0;
    std::string digest = std::string(64, '0');
    Catalogue(const std::filesystem::path &root, bool write, bool create = false, bool repair = false,
              bool allow_tail = false) {
        file = detail::private_file(root / record_file, GENERIC_READ | (write ? GENERIC_WRITE | DELETE : 0),
                                    create ? CREATE_NEW : OPEN_EXISTING, max_frames * frame_size,
                                    write ? 0 : FILE_SHARE_READ);
        record.root = root;
        const auto all = detail::read_contents(file.get());
        tail = all.size() % frame_size;
        for (std::size_t offset = 0; offset + frame_size <= all.size(); offset += frame_size) {
            const apk::Bytes frame(all.data() + offset, frame_size);
            const std::string stored(reinterpret_cast<const char *>(frame.data() + digest_offset), 64);
            corrupt(hex(stored) && apk::sha256(frame.first(digest_offset)) == stored);
            Reader reader{frame.first(digest_offset)};
            corrupt(reader.text(16) == "AETHRUNTIME1");
            const auto version = reader.number();
            corrupt((version >= 1 && version <= 5) && reader.number() == count + 1 &&
                    reader.text(64) == digest);
            const auto phase = reader.number();
            corrupt(phase >= 1 && phase <= (version >= 3 ? 4u : 3u));
            Record next;
            next.schema = version;
            next.phase = static_cast<Phase>(phase);
            next.root = utf16(reader.text(800));
            corrupt(same_path(next.root, root));
            const auto files = reader.number();
            corrupt(files <= (version >= 5 ? max_catalogue_payloads : 96));
            std::set<std::string> names;
            for (std::uint64_t n = 0; n < files; ++n) {
                Payload item;
                item.path = reader.text(160);
                item.sha256 = reader.text(64);
                item.size = reader.number();
                const auto kind = reader.number();
                corrupt(kind <= 1);
                item.worker = kind != 0;
                if (version >= 5 && item.path.empty()) {
                    corrupt(!item.worker && hex(item.sha256));
                    item.path = "shell-icons/" + item.sha256 + "/AetherShellIcons.dll";
                }
                corrupt(payload_name(item.path, item.worker) && hex(item.sha256) && item.size &&
                        item.size <= max_image && names.insert(item.path).second);
                corrupt(!icon_payload(item.path) ||
                        (version >= 4 && item.path.substr(12, 64) == item.sha256));
                next.files.push_back(std::move(item));
            }
            corrupt(std::count_if(next.files.begin(), next.files.end(), [](const auto &item) { return !icon_payload(item.path); }) <= 96);
            const auto stores = reader.number();
            corrupt(stores <= 32);
            for (std::uint64_t n = 0; n < stores; ++n) {
                const std::filesystem::path path(utf16(reader.text(800)));
                validate_path(path);
                corrupt(!below(path, root) && !below(root, path) &&
                        std::none_of(next.stores.begin(), next.stores.end(),
                                     [&](const auto &other) { return same_path(path, other); }));
                next.stores.push_back(path);
            }
            if (version >= 2) {
                next.native_id = reader.text(64);
                corrupt(hex(next.native_id) || (version >= 3 && next.native_id.empty()));
            }
            if (version >= 3) {
                next.compatibility = reader.number();
                corrupt(next.compatibility >= 1 && next.compatibility <= current_runtime_compatibility);
                const auto pending = reader.number();
                corrupt(pending <= (version >= 5 ? max_catalogue_payloads : 96));
                std::set<std::string> pending_names;
                for (std::uint64_t n = 0; n < pending; ++n) {
                    Payload item;
                    item.path = reader.text(160);
                    item.sha256 = reader.text(64);
                    item.size = reader.number();
                    const auto kind = reader.number();
                    corrupt(kind <= 1);
                    item.worker = kind != 0;
                    if (version >= 5 && item.path.empty()) {
                        corrupt(!item.worker && hex(item.sha256));
                        item.path = "shell-icons/" + item.sha256 + "/AetherShellIcons.dll";
                    }
                    corrupt(payload_name(item.path, item.worker) && hex(item.sha256) && item.size &&
                            item.size <= max_image && pending_names.insert(item.path).second);
                    corrupt(!icon_payload(item.path) ||
                            (version >= 4 && item.path.substr(12, 64) == item.sha256));
                    next.pending.push_back(std::move(item));
                }
                corrupt(version < 5 || next.compatibility >= 9);
                corrupt(std::count_if(next.pending.begin(), next.pending.end(), [](const auto &item) { return !icon_payload(item.path); }) <= 96);
                corrupt((next.phase == Phase::upgrading) == !next.pending.empty());
                corrupt(next.pending.empty() || (version >= 4 ? additive_layout(next.files, next.pending)
                                                              : same_layout(next.files, next.pending)));
            }
            if (version >= 4) {
                next.icon_library = reader.text(160);
                next.pending_icon_library = reader.text(160);
                corrupt(next.icon_library.empty() || selected_icon(next.files, next.icon_library));
                corrupt(next.phase == Phase::upgrading
                            ? selected_icon(next.pending, next.pending_icon_library)
                            : next.pending_icon_library.empty());
                if (!next.files.empty() && next.phase != Phase::upgrading) {
                    corrupt(selected_icon(next.files, next.icon_library));
                    corrupt(names.contains("runtime/aether_icon_worker.exe"));
                }
            }
            corrupt(std::none_of(reader.bytes.begin() + static_cast<std::ptrdiff_t>(reader.at),
                                 reader.bytes.end(), [](auto byte) { return byte != 0; }));
            corrupt(next.native_id.empty() ? ((next.phase == Phase::preparing) == next.files.empty())
                                           : names.contains("aether-setup.exe"));
            if (next.phase == Phase::preparing)
                corrupt(next.stores.empty());
            if (next.phase != Phase::preparing || !next.native_id.empty()) {
                corrupt(next.files.size() >= 6);
                for (const auto *required :
                     {"aether.exe", "aether-shell.exe", "aether_runtime_setup.exe",
                      "runtime/aether_worker.exe", "runtime/aether_graphics_worker.exe"})
                    corrupt(names.contains(required));
            }
            if (count) {
                corrupt(next.schema >= record.schema);
                corrupt(next.compatibility >= record.compatibility &&
                        (next.compatibility == record.compatibility || next.phase == Phase::upgrading));
                corrupt(record.native_id == next.native_id);
                corrupt(!record.native_id.empty() || record.phase != Phase::preparing ||
                        next.phase != Phase::removing);
                corrupt(record.phase != Phase::removing || next.phase == Phase::removing);
                corrupt(record.phase == Phase::preparing || next.phase != Phase::preparing);
                if (next.phase == Phase::removing || next.phase == Phase::upgrading ||
                    record.phase == Phase::upgrading)
                    corrupt(record.stores == next.stores);
                if (record.phase == Phase::upgrading) {
                    corrupt(next.phase == Phase::ready && next.files == record.pending);
                    corrupt(next.icon_library == record.pending_icon_library);
                } else if (record.phase != Phase::preparing || !record.native_id.empty()) {
                    corrupt(record.files == next.files);
                    corrupt(next.icon_library == record.icon_library);
                }
                if (next.phase == Phase::upgrading)
                    corrupt(record.phase == Phase::ready &&
                            (next.files != next.pending || next.icon_library != next.pending_icon_library ||
                             next.compatibility > record.compatibility));
                if (next.schema != record.schema && next.schema >= 3)
                    corrupt(next.phase == Phase::upgrading);
            } else
                corrupt(next.phase == Phase::preparing && next.stores.empty());
            record = std::move(next);
            digest = stored;
            ++count;
        }
        require(create || count, "AETHER_RUNTIME_RECORD",
                "Runtime catalogue has no durable ownership record");
        require(
            !tail || repair || allow_tail, "AETHER_RUNTIME_INCOMPLETE",
            "Runtime catalogue has an interrupted final frame; explicit runtime repair --yes is required");
        if (repair)
            repair_tail();
    }
    void repair_tail() {
        if (tail) {
            LARGE_INTEGER end{};
            end.QuadPart = static_cast<LONGLONG>(count * frame_size);
            io(SetFilePointerEx(file.get(), end, nullptr, FILE_BEGIN) && SetEndOfFile(file.get()) &&
                   FlushFileBuffers(file.get()),
               "Cannot truncate interrupted runtime catalogue tail");
            tail = 0;
        }
    }
    void commit() {
        const auto limit = record.phase == Phase::removing ? max_frames : max_frames - 1;
        require(!tail && count < limit, "AETHER_RUNTIME_LIMIT",
                "Runtime catalogue is incomplete or at its bounded history limit");
        Writer out;
        out.text("AETHRUNTIME1");
        out.number(record.schema >= 3 ? record.schema : record.native_id.empty() ? 1 : 2);
        out.number(count + 1);
        out.text(digest);
        out.number(static_cast<std::uint64_t>(record.phase));
        out.text(utf8(record.root.wstring()));
        out.number(record.files.size());
        for (const auto &item : record.files) {
            out.text(record.schema >= 5 && icon_payload(item.path) ? "" : item.path);
            out.text(item.sha256);
            out.number(item.size);
            out.number(item.worker ? 1 : 0);
        }
        out.number(record.stores.size());
        for (const auto &path : record.stores)
            out.text(utf8(path.wstring()));
        if (!record.native_id.empty() || record.schema >= 3)
            out.text(record.native_id);
        if (record.schema >= 3) {
            out.number(record.compatibility);
            out.number(record.pending.size());
            for (const auto &item : record.pending) {
                out.text(record.schema >= 5 && icon_payload(item.path) ? "" : item.path);
                out.text(item.sha256);
                out.number(item.size);
                out.number(item.worker ? 1 : 0);
            }
        }
        if (record.schema >= 4) {
            out.text(record.icon_library);
            out.text(record.pending_icon_library);
        }
        require(out.bytes.size() <= digest_offset, "AETHER_RUNTIME_LIMIT",
                "Runtime catalogue frame exceeds its bound");
        out.bytes.resize(digest_offset);
        const auto checksum = apk::sha256(out.bytes);
        out.bytes.insert(out.bytes.end(), checksum.begin(), checksum.end());
        LARGE_INTEGER end{};
        io(SetFilePointerEx(file.get(), end, nullptr, FILE_END), "Cannot position runtime catalogue");
        DWORD written = 0;
        io(WriteFile(file.get(), out.bytes.data(), static_cast<DWORD>(out.bytes.size()), &written, nullptr) &&
               written == out.bytes.size() && FlushFileBuffers(file.get()),
           "Runtime intent write is uncertain; explicit repair is required");
        const auto bytes = detail::read_contents(file.get());
        io(bytes.size() == (count + 1) * frame_size &&
               std::equal(out.bytes.begin(), out.bytes.end(),
                          bytes.end() - static_cast<std::ptrdiff_t>(frame_size)),
           "Runtime intent failed durable readback");
        ++count;
        digest = checksum;
    }
};
struct Root {
    std::filesystem::path path;
    std::vector<UniqueHandle> parents;
    UniqueHandle held, lease;
    Root(const std::filesystem::path &root, bool exclusive, bool deleting = false)
        : path(root), parents(ancestors(root)), held(directory(root)), lease(use_file(root, exclusive)) {
        if (deleting) {
            BY_HANDLE_FILE_INFORMATION before{}, after{};
            io(GetFileInformationByHandle(held.get(), &before), "Cannot inspect runtime directory identity");
            held.reset();
            held = directory(root, true);
            io(GetFileInformationByHandle(held.get(), &after) &&
                   before.dwVolumeSerialNumber == after.dwVolumeSerialNumber &&
                   before.nFileIndexHigh == after.nFileIndexHigh &&
                   before.nFileIndexLow == after.nFileIndexLow,
               "Runtime directory identity changed during removal preflight");
        }
    }
};
struct PendingShellNotice {
    bool changed = false;
    ~PendingShellNotice() {
        if (changed)
            SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    }
};
void worker_policy(HANDLE file, bool partial = false) {
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    require(GetFileType(file) == FILE_TYPE_DISK && GetFileInformationByHandle(file, &info) &&
                info.nNumberOfLinks == 1 &&
                !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
                GetFileSizeEx(file, &size) && size.QuadPart >= (partial ? 0 : 1) &&
                static_cast<std::uint64_t>(size.QuadPart) <= max_image,
            "AETHER_RUNTIME_POLICY", "Runtime worker is not a bounded regular single-link file");
    PSECURITY_DESCRIPTOR raw = nullptr, expected = nullptr, owner_policy = nullptr;
    PSID owner = nullptr, wanted_owner = nullptr;
    PACL acl = nullptr, wanted_acl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    const auto status =
        GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
                        nullptr, &acl, nullptr, &raw);
    struct Free {
        PSECURITY_DESCRIPTOR &a, &b, &c;
        ~Free() {
            LocalFree(a);
            LocalFree(b);
            LocalFree(c);
        }
    } free{raw, expected, owner_policy};
    io(ConvertStringSecurityDescriptorToSecurityDescriptorW(security::worker_image_sddl().c_str(),
                                                            SDDL_REVISION_1, &expected, nullptr),
       "Cannot construct worker verification policy");
    io(ConvertStringSecurityDescriptorToSecurityDescriptorW(security::runtime_directory_sddl().c_str(),
                                                            SDDL_REVISION_1, &owner_policy, nullptr),
       "Cannot construct runtime ownership policy");
    require(status == ERROR_SUCCESS && owner && acl &&
                GetSecurityDescriptorOwner(owner_policy, &wanted_owner, &defaulted) && wanted_owner &&
                EqualSid(owner, wanted_owner) &&
                GetSecurityDescriptorDacl(expected, &present, &wanted_acl, &defaulted) && present &&
                wanted_acl && GetSecurityDescriptorControl(raw, &control, &revision) &&
                (control & SE_DACL_PROTECTED) && acl->AclSize == wanted_acl->AclSize &&
                std::memcmp(acl, wanted_acl, acl->AclSize) == 0,
            "AETHER_RUNTIME_POLICY", "Runtime worker has an unexpected installation policy");
}
UniqueHandle payload_file(const std::filesystem::path &root, const Payload &item, bool deleting,
                          bool writing = false, bool partial = false, bool added = false) {
    const auto path = root / utf16(item.path);
    const auto access =
        GENERIC_READ | (deleting ? DELETE : 0) | (writing ? GENERIC_WRITE | (added ? WRITE_DAC : 0) : 0);
    if (!item.worker)
        return detail::private_file(path, access, OPEN_EXISTING, max_image, writing ? 0 : FILE_SHARE_READ,
                                    true);
    UniqueHandle file(CreateFileW(path.c_str(), access, writing ? 0 : FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                  FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    require(static_cast<bool>(file), "AETHER_RUNTIME_BUSY",
            "A runtime image is busy or unavailable; no files have been replaced");
    LARGE_INTEGER size{};
    require(GetFileSizeEx(file.get(), &size) && size.QuadPart >= (partial ? 0 : 1) &&
                static_cast<std::uint64_t>(size.QuadPart) <= max_image,
            "AETHER_RUNTIME_PAYLOAD", "Runtime worker size exceeds the payload bound");
    try {
        worker_policy(file.get(), partial);
    } catch (const InstallError &) {
        if (!partial || !added)
            throw;
        // A durable additive intent may have stopped between creation of a
        // private new worker and provisioning its narrower execution policy.
        // Accept only that private policy; never adopt an arbitrary broad ACL.
        file.reset();
        file = detail::private_file(path, access, OPEN_EXISTING, max_image, 0);
    }
    return file;
}
struct Inventory {
    std::vector<UniqueHandle> directories, files;
    std::vector<Payload> payload;
    bool complete = true;
};
Inventory payload_inventory(const std::filesystem::path &root, const std::vector<Payload> *expected,
                            bool deleting, const RuntimeBundle *upgrade = nullptr, bool resuming = false,
                            const std::vector<Payload> *candidate = nullptr, bool repairing = false) {
    Inventory result;
    const std::set<std::wstring> root_allowed = {
        L"aether.exe",       L"aether-shell.exe", L"aether_runtime_setup.exe",
        L"aether-setup.exe", L"runtime",          L"licenses",
        L"shell-icons",      record_file,         lease_file};
    for (const auto &entry : std::filesystem::directory_iterator(root))
        require(root_allowed.contains(entry.path().filename().wstring()), "AETHER_RUNTIME_CONFLICT",
                "Runtime directory contains unrecorded material; it is preserved");
    std::set<std::string> allowed;
    if (expected)
        for (const auto &item : *expected)
            allowed.insert(item.path);
    if (resuming && candidate)
        for (const auto &item : *candidate)
            allowed.insert(item.path);
    if (expected && !missing(root / L"aether-setup.exe"))
        require(allowed.contains("aether-setup.exe"), "AETHER_RUNTIME_CONFLICT",
                "An unrecorded installer image is preserved");
    for (const auto *leaf : {L"runtime", L"licenses", L"shell-icons"}) {
        const bool icons = std::wstring_view(leaf) == L"shell-icons";
        const bool worker = std::wstring_view(leaf) == L"runtime";
        const auto prefix = utf8(leaf) + '/';
        const auto path = root / leaf;
        const bool recorded = std::any_of(allowed.begin(), allowed.end(),
                                          [&](const auto &name) { return name.starts_with(prefix); });
        if (missing(path)) {
            require(expected != nullptr, "AETHER_RUNTIME_PAYLOAD",
                    "A required runtime payload directory is missing");
            if (recorded && !resuming)
                result.complete = false;
            continue;
        }
        require(!expected || !icons || recorded, "AETHER_RUNTIME_CONFLICT",
                "An unrecorded shell icon directory is preserved");
        result.directories.push_back(directory(path, deleting));
        for (const auto &entry : std::filesystem::directory_iterator(path)) {
            std::string relative = prefix + utf8(entry.path().filename().native());
            if (icons) {
                require(hex(utf8(entry.path().filename().native())), "AETHER_RUNTIME_CONFLICT",
                        "An unknown shell icon version directory is preserved");
                relative += "/AetherShellIcons.dll";
            }
            require(payload_name(relative, worker) && (!expected || allowed.contains(relative)),
                    "AETHER_RUNTIME_CONFLICT", "Runtime payload contains unknown material; it is preserved");
            if (icons) {
                result.directories.push_back(directory(entry.path(), deleting));
                for (const auto &child : std::filesystem::directory_iterator(entry.path()))
                    require(child.path().filename() == L"AetherShellIcons.dll", "AETHER_RUNTIME_CONFLICT",
                            "Unknown material in a shell icon directory is preserved");
            }
            if (!expected) {
                require(result.payload.size() < max_catalogue_payloads, "AETHER_RUNTIME_LIMIT",
                        "Runtime payload exceeds the bounded retained-payload catalogue");
                result.payload.push_back({relative, {}, 0, worker});
            }
        }
    }
    if (expected) {
        result.payload = *expected;
        if (candidate)
            for (const auto &item : *candidate)
                if (std::none_of(expected->begin(), expected->end(),
                                 [&](const auto &old) { return old.path == item.path; }))
                    result.payload.push_back(item);
    } else {
        for (const auto *leaf : {"aether.exe", "aether-shell.exe", "aether_runtime_setup.exe"})
            result.payload.push_back({leaf, {}, 0, false});
        if (!missing(root / L"aether-setup.exe"))
            result.payload.push_back({"aether-setup.exe", {}, 0, false});
        require(result.payload.size() >= 8 && result.payload.size() <= max_catalogue_payloads &&
                    std::count_if(result.payload.begin(), result.payload.end(),
                                  [](const auto &item) { return item.worker; }) == 3,
                "AETHER_RUNTIME_PAYLOAD",
                "All three workers, the icon DLL and distribution licences are required");
        (void)single_icon(result.payload);
    }
    require(std::count_if(result.payload.begin(), result.payload.end(),
                          [](const auto &item) { return !icon_payload(item.path); }) <= 96,
            "AETHER_RUNTIME_LIMIT", "Non-icon runtime inventory exceeds its original bound");
    std::sort(result.payload.begin(), result.payload.end(),
              [](const auto &a, const auto &b) { return a.path < b.path; });
    for (auto &item : result.payload) {
        const bool added = expected && std::none_of(expected->begin(), expected->end(),
                                                    [&](const auto &old) { return old.path == item.path; });
        if (missing(root / utf16(item.path))) {
            require(expected != nullptr, "AETHER_RUNTIME_PAYLOAD",
                    "A required runtime payload file is missing");
            if (!added)
                result.complete = false;
            result.files.emplace_back();
            continue;
        }
        require(!added || resuming, "AETHER_RUNTIME_CONFLICT",
                "An added runtime path already exists without a recorded upgrade intent");
        const RuntimePayload *replacement = nullptr;
        if (upgrade) {
            const auto at = std::find_if(upgrade->files.begin(), upgrade->files.end(),
                                         [&](const auto &value) { return value.path == item.path; });
            if (at != upgrade->files.end())
                replacement = &*at;
        }
        // An Explorer-loaded immutable DLL is held read-only. Only changed
        // in-place leaves need an exclusive writable identity before intent.
        WIN32_FILE_ATTRIBUTE_DATA extent{};
        const bool short_repair =
            repairing &&
            GetFileAttributesExW((root / utf16(item.path)).c_str(), GetFileExInfoStandard, &extent) &&
            ((std::uint64_t(extent.nFileSizeHigh) << 32) | extent.nFileSizeLow) < item.size;
        const bool writing =
            replacement &&
            (short_repair || (resuming && (added || !icon_payload(item.path))) ||
             item.size != replacement->bytes.size() || item.sha256 != apk::sha256(replacement->bytes));
        auto file = payload_file(root, item, deleting, writing, resuming, added || repairing);
        const auto bytes = detail::read_contents(file.get());
        require((resuming || !bytes.empty()) && bytes.size() <= max_image, "AETHER_RUNTIME_PAYLOAD",
                "Runtime payload size is invalid");
        const auto hash = apk::sha256(bytes);
        const bool prefix = resuming && writing && replacement && bytes.size() <= replacement->bytes.size() &&
                            std::equal(bytes.begin(), bytes.end(), replacement->bytes.begin());
        if (expected)
            require((item.size == bytes.size() && item.sha256 == hash) || prefix, "AETHER_RUNTIME_CONFLICT",
                    "A runtime payload differs from its recorded bytes; it is preserved");
        else {
            item.size = bytes.size();
            item.sha256 = hash;
        }
        require(!icon_payload(item.path) || prefix || item.path.substr(12, 64) == hash,
                "AETHER_RUNTIME_CONFLICT", "A versioned shell DLL differs from its content identity");
        result.files.push_back(std::move(file));
    }
    return result;
}
std::vector<UniqueHandle> payload_directories(const std::filesystem::path &root,
                                              const std::vector<Payload> &files) {
    std::vector<UniqueHandle> result;
    std::set<std::filesystem::path> paths;
    for (const auto &item : files) {
        const auto parent = std::filesystem::path(utf16(item.path)).parent_path();
        if (parent.empty())
            continue;
        if (!parent.parent_path().empty())
            paths.insert(parent.parent_path());
        paths.insert(parent);
    }
    for (const auto &path : paths)
        result.push_back(detail::hold_directory(root / path, true, true));
    return result;
}
struct Dependencies {
    std::vector<std::string> apps, blockers;
    bool link_offers = false;
    // Keep inspected journals locked until removal finishes. Another runtime
    // must not introduce a dependency after this preflight.
    std::vector<std::unique_ptr<PackageStore>> stores;
    const PackageStore *held_store(const std::string &path) const {
        const std::filesystem::path expected(utf16(path));
        for (const auto &store : stores)
            if (same_path(store->root(), expected))
                return store.get();
        return nullptr;
    }
    std::string json() const {
        std::string out = "\"applications\":[";
        for (const auto &app : apps) {
            if (out.back() != '[')
                out += ',';
            out += app;
        }
        out += "],\"blockers\":[";
        for (const auto &blocker : blockers) {
            if (out.back() != '[')
                out += ',';
            out += json_quote(blocker);
        }
        return out + "],\"linkOffersPresent\":" + (link_offers ? "true" : "false");
    }
    bool empty() const { return apps.empty() && blockers.empty() && !link_offers; }
};
Dependencies dependencies(const Record &record, bool native_removal = false) {
    Dependencies result;
    try { result.link_offers = link_registration_present(record.root); }
    catch (const std::exception &) {
        result.blockers.push_back("Link handler ownership cannot be verified; inspect its recorded offers before runtime removal.");
    }
    auto paths = record.stores;
    const auto default_root = default_store_root();
    if (std::none_of(paths.begin(), paths.end(),
                     [&](const auto &path) { return same_path(path, default_root); }))
        paths.push_back(default_root);
    for (const auto &path : paths) {
        try {
            const bool indexed = std::any_of(record.stores.begin(), record.stores.end(),
                                             [&](const auto &known) { return same_path(known, path); });
            require(!indexed || !missing(path / L"registry.log"), "AETHER_RUNTIME_STORE_MISSING",
                    "An indexed store journal is missing; its dependencies cannot be inferred");
            auto store = std::make_unique<PackageStore>(path);
            for (const auto &app : store->list())
                result.apps.push_back("{\"store\":" + json_quote(utf8(path.wstring())) +
                                      ",\"app\":" + app.json() + '}');
            result.stores.push_back(std::move(store));
        } catch (const std::exception &error) {
            result.blockers.push_back(utf8(path.wstring()) + ": " + error.what());
        }
    }
    try {
        const auto explorer = explorer_registration(ExplorerOperation::status);
        if (!native_removal && !explorer.launcher.empty() &&
            same_path(std::filesystem::path(utf16(explorer.launcher)).parent_path(), record.root))
            result.blockers.push_back("This runtime owns Explorer registration. Use its explorer remove "
                                      "--yes command before removing the runtime.");
    } catch (const std::exception &error) {
        result.blockers.push_back(std::string("Explorer ownership cannot be verified: ") + error.what());
    }
    return result;
}
std::string describe(const Record &record, const Dependencies &uses, bool complete, bool checked,
                     bool removal_ready) {
    const auto state = record.phase == Phase::preparing   ? "preparing"
                       : record.phase == Phase::ready     ? "ready"
                       : record.phase == Phase::upgrading ? "upgrading"
                                                          : "removing";
    std::string out = "{\"schemaVersion\":1,\"operation\":\"runtime\",\"state\":" + json_quote(state) +
                      ",\"root\":" + json_quote(utf8(record.root.wstring())) +
                      ",\"payloadChecked\":" + (checked ? "true" : "false") +
                      ",\"payloadComplete\":" + (checked ? (complete ? "true" : "false") : "null") +
                      ",\"removalReady\":" + (removal_ready ? "true" : "false") + ",\"stores\":[";
    for (const auto &store : record.stores) {
        if (out.back() != '[')
            out += ',';
        out += json_quote(utf8(store.wstring()));
    }
    return out + "]," + uses.json() + '}';
}
void mark_delete(HANDLE file, bool loaded_library = false) {
    if (loaded_library) {
        // Request deletion of this held, verified single-link version. Windows
        // can still refuse an image mapping; never terminate Explorer or report
        // cleanup complete while the mapped file remains.
        FILE_DISPOSITION_INFO_EX disposition{FILE_DISPOSITION_FLAG_DELETE |
                                             FILE_DISPOSITION_FLAG_POSIX_SEMANTICS};
        if (SetFileInformationByHandle(file, FileDispositionInfoEx, &disposition, sizeof(disposition)))
            return;
    }
    FILE_DISPOSITION_INFO disposition{TRUE};
    if (!SetFileInformationByHandle(file, FileDispositionInfo, &disposition, sizeof(disposition))) {
        const auto error = GetLastError();
        std::array<wchar_t, 32768> path{};
        const auto size = GetFinalPathNameByHandleW(file, path.data(), static_cast<DWORD>(path.size()),
                                                    FILE_NAME_NORMALIZED);
        const auto name = size && size < path.size() ? utf8(std::wstring(path.data(), size))
                                                     : std::string("held runtime file");
        throw InstallError("AETHER_RUNTIME_IO",
                           "Owned runtime removal is incomplete (Windows error " + std::to_string(error) +
                               ") at " + name + "; close conflicting handles and explicitly retry removal");
    }
}
void remove_icon_payloads(Inventory &files) {
    for (std::size_t n = 0; n < files.payload.size(); ++n)
        if (files.files[n] && icon_payload(files.payload[n].path)) {
            try {
                mark_delete(files.files[n].get(), true);
                files.files[n].reset();
            } catch (const InstallError &error) {
                throw InstallError(
                    "AETHER_RUNTIME_ICON_IN_USE",
                    "The owned icon DLL could not be removed. Explorer registration is removed; setup "
                    "and the removal record remain. Close applications using Aether package icons, then "
                    "explicitly run uninstall again. " +
                        std::string(error.what()));
            }
        }
}
} // namespace

struct RuntimeUseLease::Impl {
    Root root;
    explicit Impl(const std::filesystem::path &path) : root(path, false) {
        Catalogue state(path, false);
        require(state.record.phase == Phase::ready, "AETHER_RUNTIME_STATE",
                "This managed runtime is not ready; finish explicit installation, upgrade or removal first");
    }
};
RuntimeUseLease::RuntimeUseLease(const std::filesystem::path &store) {
    const auto root = current_root();
    if (!missing(root / record_file)) {
        impl_ = std::make_unique<Impl>(root);
        if (!store.empty()) {
            validate_path(store);
            require(!below(store, root) && !below(root, store), "AETHER_RUNTIME_STORE",
                    "Runtime binaries and package stores must use separate directory trees");
            auto parents = ancestors(store);
            if (!missing(store)) {
                auto existing = detail::hold_directory(store, false, false);
                verify_resolved_path(existing.get(), store);
            }
        }
    }
}
RuntimeUseLease::~RuntimeUseLease() = default;

namespace {
std::vector<Payload> native_inventory(const std::vector<RuntimePayload> &input) {
    require(input.size() >= 7 && input.size() <= 96, "AETHER_SETUP_BUNDLE",
            "Invalid runtime distribution file count");
    std::vector<Payload> result;
    std::set<std::string> names;
    std::uint64_t total = 0;
    for (const auto &item : input) {
        const bool worker = item.path.starts_with("runtime/");
        require(payload_name(item.path, worker) && names.insert(item.path).second && !item.bytes.empty() &&
                    item.bytes.size() <= max_image,
                "AETHER_SETUP_BUNDLE", "Invalid runtime distribution file");
        total += item.bytes.size();
        require(total <= 512ull * 1024 * 1024, "AETHER_SETUP_BUNDLE",
                "Runtime distribution exceeds its size bound");
        const auto hash = apk::sha256(item.bytes);
        require(!icon_payload(item.path) || item.path.substr(12, 64) == hash, "AETHER_SETUP_BUNDLE",
                "The versioned shell DLL path does not match its content hash");
        result.push_back({item.path, hash, item.bytes.size(), worker});
    }
    for (const auto *name : {"aether.exe", "aether-shell.exe", "aether_runtime_setup.exe", "aether-setup.exe",
                             "runtime/aether_worker.exe", "runtime/aether_graphics_worker.exe",
                             "runtime/aether_icon_worker.exe"})
        require(names.contains(name), "AETHER_SETUP_BUNDLE", "Required runtime distribution file is missing");
    std::sort(result.begin(), result.end(), [](const auto &a, const auto &b) { return a.path < b.path; });
    (void)single_icon(result);
    return result;
}
std::string native_identity() {
    std::array<std::uint8_t, 32> bytes{};
    io(BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
                       BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0,
       "Cannot create a runtime installation identity");
    return apk::sha256(bytes);
}
void provision_worker(HANDLE file) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    io(ConvertStringSecurityDescriptorToSecurityDescriptorW(security::worker_image_sddl().c_str(),
                                                            SDDL_REVISION_1, &descriptor, nullptr),
       "Cannot construct worker installation policy");
    struct Free {
        PSECURITY_DESCRIPTOR value;
        ~Free() { LocalFree(value); }
    } release{descriptor};
    PACL acl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    io(GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) && present && acl &&
           SetSecurityInfo(file, SE_FILE_OBJECT,
                           DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr,
                           acl, nullptr) == ERROR_SUCCESS,
       "Cannot provision worker installation policy");
    worker_policy(file);
}
void remove_owned_explorer(const std::filesystem::path &root) {
    const auto existing = explorer_registration(ExplorerOperation::status);
    if (!existing.launcher.empty() &&
        same_path(std::filesystem::path(utf16(existing.launcher)).parent_path(), root))
        (void)explorer_registration(ExplorerOperation::remove, {}, root);
}
void stop_owned_icon_broker(const std::filesystem::path &root) {
    // Verify the selected catalogue under a shared lease before contacting a
    // process. The broker must release its own shared lease before the caller
    // can obtain the exclusive maintenance lease. Other hosts remain untouched.
    Root selected(root, false);
    Catalogue catalogue(root, false, false, false, true);
    if (catalogue.record.schema < 4)
        return;
    const auto result = shell::stop_icon_service(shell::icon_endpoint(), root / L"aether.exe");
    require(result != shell::IconStopResult::unavailable, "AETHER_RUNTIME_BUSY",
            "The selected runtime's icon service could not be stopped and settled; no runtime files were "
            "changed. Explicitly retry after it exits.");
}
UniqueHandle controller_process(DWORD pid) {
    require(pid && pid != GetCurrentProcessId(), "AETHER_SETUP_CONTROLLER",
            "A Windows controller process is required");
    UniqueHandle process(
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE | SYNCHRONIZE, FALSE, pid));
    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    PROCESSENTRY32W entry{sizeof(entry)};
    bool parent = false;
    if (snapshot && Process32FirstW(snapshot.get(), &entry)) {
        do {
            if (entry.th32ProcessID == GetCurrentProcessId()) {
                parent = entry.th32ParentProcessID == pid;
                break;
            }
        } while (Process32NextW(snapshot.get(), &entry));
    }
    std::array<wchar_t, 32768> image{};
    DWORD size = static_cast<DWORD>(image.size());
    require(parent && process && QueryFullProcessImageNameW(process.get(), 0, image.data(), &size) &&
                same_path(std::filesystem::path(std::wstring(image.data(), size)), windows_powershell()) &&
                WaitForSingleObject(process.get(), 0) == WAIT_TIMEOUT,
            "AETHER_SETUP_CONTROLLER",
            "Uninstall cleanup requires the installed Windows PowerShell controller");
    UniqueHandle token;
    HANDLE raw = nullptr;
    require(OpenProcessToken(process.get(), TOKEN_QUERY, &raw), "AETHER_SETUP_CONTROLLER",
            "Cannot verify controller user");
    token.reset(raw);
    std::array<std::uint8_t, 1024> data{};
    DWORD needed = 0;
    PSECURITY_DESCRIPTOR policy = nullptr;
    PSID owner = nullptr;
    BOOL defaulted = FALSE;
    io(ConvertStringSecurityDescriptorToSecurityDescriptorW(security::runtime_directory_sddl().c_str(),
                                                            SDDL_REVISION_1, &policy, nullptr),
       "Cannot construct controller ownership policy");
    struct Free {
        PSECURITY_DESCRIPTOR value;
        ~Free() { LocalFree(value); }
    } release{policy};
    require(
        GetTokenInformation(token.get(), TokenUser, data.data(), static_cast<DWORD>(data.size()), &needed) &&
            GetSecurityDescriptorOwner(policy, &owner, &defaulted) && owner &&
            EqualSid(reinterpret_cast<TOKEN_USER *>(data.data())->User.Sid, owner),
        "AETHER_SETUP_CONTROLLER", "Uninstall controller must run as this runtime's owner");
    return process;
}
struct RemoteHandles {
    HANDLE process;
    std::vector<HANDLE> handles;
    bool transferred = false;
    explicit RemoteHandles(HANDLE value) : process(value) {}
    ~RemoteHandles() {
        if (!transferred)
            for (const auto remote : handles) {
                HANDLE local = nullptr;
                if (DuplicateHandle(process, remote, GetCurrentProcess(), &local, 0, FALSE,
                                    DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE))
                    CloseHandle(local);
            }
    }
    void add(HANDLE handle) {
        HANDLE copy = nullptr;
        io(DuplicateHandle(GetCurrentProcess(), handle, process, &copy, 0, FALSE, DUPLICATE_SAME_ACCESS),
           "Cannot transfer the held runtime identity to its Windows controller");
        handles.push_back(copy);
    }
    std::string json() const {
        std::string result = "[";
        for (const auto handle : handles) {
            if (result.back() != '[')
                result += ',';
            result += std::to_string(reinterpret_cast<std::uintptr_t>(handle));
        }
        return result + ']';
    }
};
} // namespace

RuntimeSetupStatus inspect_runtime_setup(const std::filesystem::path &root, bool installing) {
    try {
        auto parents = ancestors(root);
        auto shell = hold_shell_registration();
        if (installing) {
            require(missing(root), "AETHER_RUNTIME_EXISTS",
                    "This destination already exists. Choose a new directory; existing installations are "
                    "preserved.");
            require(
                detail::runtime_registration_absent(), "AETHER_SETUP_REGISTRATION",
                "An Aether runtime is already registered in Windows. Remove it before installing another.");
            return {"available", "Ready to install for your Windows account.", true};
        }
        Root target(root, false);
        Catalogue state(root, false);
        require(state.record.phase != Phase::upgrading, "AETHER_RUNTIME_STATE",
                "Complete the recorded runtime upgrade before removal");
        require(!state.record.native_id.empty(), "AETHER_RUNTIME_UNMANAGED",
                "This directory was not installed by AetherSetup.");
        detail::verify_runtime_registration(root, state.record.native_id, true);
        const auto uses = dependencies(state.record, true);
        if (!uses.empty()) {
            std::string message =
                "Remove installed Android apps and retained app data before removing Aether.";
            if (uses.link_offers)
                message += "\nThis runtime still owns link offers. Remove each with link-handlers remove "
                           "--app-id ID --store ROOT --yes before removing Aether.";
            for (const auto &blocker : uses.blockers)
                message += "\n" + blocker;
            return {"blocked", message, false};
        }
        return {state.record.phase == Phase::ready ? "ready" : "incomplete",
                "No installed apps, retained app data or link offers require this runtime. Package journals will be kept.",
                true};
    } catch (const std::exception &error) {
        return {"unavailable", error.what(), false};
    }
}
std::filesystem::path runtime_icon_library(const std::filesystem::path &root) {
    Root target(root, false);
    Catalogue state(root, false);
    require(state.record.phase == Phase::ready && state.record.schema >= 4 &&
                selected_icon(state.record.files, state.record.icon_library),
            "AETHER_EXPLORER_RUNTIME", "A ready installed runtime with the icon component is required");
    const auto path = root / utf16(state.record.icon_library);
    auto parent = detail::hold_directory(path.parent_path().parent_path(), false, true);
    auto version = detail::hold_directory(path.parent_path(), false, true);
    auto file = detail::private_file(path, GENERIC_READ, OPEN_EXISTING, max_image, FILE_SHARE_READ);
    require(apk::sha256(detail::read_contents(file.get())) == state.record.icon_library.substr(12, 64),
            "AETHER_RUNTIME_CONFLICT", "The selected icon module differs from its catalogue identity");
    return path;
}
void install_runtime(const std::filesystem::path &root, const std::vector<RuntimePayload> &payload,
                     bool offer_explorer) {
    PendingShellNotice notice; // Declared before leases: notify only after the ready state is accessible.
    auto inventory = native_inventory(payload);
    auto parents = ancestors(root);
    auto shell = hold_shell_registration();
    require(missing(root), "AETHER_RUNTIME_EXISTS",
            "AetherSetup requires a new destination; existing files are preserved");
    require(detail::runtime_registration_absent(), "AETHER_SETUP_REGISTRATION",
            "Another Aether runtime is registered in Windows");
    if (offer_explorer) {
        const auto explorer = explorer_registration(ExplorerOperation::status);
        require(explorer.launcher.empty(), "AETHER_EXPLORER_CONFLICT",
                "An existing Aether Explorer handler is preserved");
    }
    auto held = detail::hold_directory(root, true, true);
    auto lease = use_file(root, true, true);
    Catalogue state(root, true, true);
    state.record.schema = 5;
    state.record.compatibility = current_runtime_compatibility;
    state.record.native_id = native_identity();
    state.record.files = std::move(inventory);
    state.record.icon_library = single_icon(state.record.files);
    state.commit(); // Exact expected bytes and native identity precede copying.
    auto directories = payload_directories(root, state.record.files);
    for (const auto &item : payload) {
        auto file = detail::private_file(root / utf16(item.path), GENERIC_READ | GENERIC_WRITE | WRITE_DAC,
                                         CREATE_NEW, max_image);
        detail::replace_contents(file.get(), item.bytes);
        io(detail::read_contents(file.get()) == item.bytes, "Runtime payload failed durable readback");
        if (item.path.starts_with("runtime/"))
            provision_worker(file.get());
    }
    auto verified = payload_inventory(root, &state.record.files, false);
    require(verified.complete, "AETHER_SETUP_BUNDLE", "The runtime distribution is incomplete");
    detail::register_runtime(root, state.record.native_id);
    if (offer_explorer) {
        notice.changed = true;
        (void)explorer_registration(ExplorerOperation::register_handler, default_store_root(), root,
                                    root / utf16(state.record.icon_library), false);
    }
    state.record.phase = Phase::ready;
    state.commit();
}
namespace {
void write_payload(const std::filesystem::path &root, Inventory &files, const RuntimeBundle &bundle,
                   const std::vector<Payload> &previous, bool repairing = false) {
    for (std::size_t n = 0; n < files.payload.size(); ++n) {
        const auto item = std::find_if(bundle.files.begin(), bundle.files.end(), [&](const auto &value) {
            return value.path == files.payload[n].path;
        });
        if (item == bundle.files.end())
            continue; // Retained immutable DLL or historical notice, already verified.
        if (!files.files[n]) {
            files.files[n] = detail::private_file(
                root / utf16(item->path), GENERIC_READ | GENERIC_WRITE | WRITE_DAC, CREATE_NEW, max_image);
            detail::replace_contents(files.files[n].get(), item->bytes);
            if (files.payload[n].worker)
                provision_worker(files.files[n].get());
        }
        const auto handle = files.files[n].get();
        if (detail::read_contents(handle) != item->bytes) {
            // Truncate durably first: a recoverable interrupted leaf is empty or
            // an exact prefix of the recorded candidate, never a guessed mixture.
            LARGE_INTEGER zero{};
            io(SetFilePointerEx(handle, zero, nullptr, FILE_BEGIN) && SetEndOfFile(handle) &&
                   FlushFileBuffers(handle),
               "Runtime upgrade was interrupted; explicitly resume with the same distribution");
            DWORD written = 0;
            io(WriteFile(handle, item->bytes.data(), static_cast<DWORD>(item->bytes.size()), &written,
                         nullptr) &&
                   written == item->bytes.size() && FlushFileBuffers(handle),
               "Runtime upgrade write is uncertain; explicitly resume with the same distribution");
        }
        io(detail::read_contents(handle) == item->bytes, "Runtime upgrade failed durable payload readback");
        if (files.payload[n].worker) {
            const bool added = std::none_of(previous.begin(), previous.end(),
                                            [&](const auto &old) { return old.path == item->path; });
            if (added || repairing)
                provision_worker(handle);
            else
                worker_policy(handle);
        }
    }
}
Dependencies upgrade_dependencies(const Record &record) {
    if (!record.native_id.empty())
        detail::verify_runtime_registration(record.root, record.native_id, false);
    auto uses = dependencies(record, true);
    require(uses.blockers.empty(), "AETHER_RUNTIME_DEPENDENCIES",
            "An enrolled/default store or Explorer registration cannot be verified; inspect runtime status");
    for (const auto &store : uses.stores)
        for (const auto &app : store->list())
            require(app.state == State::installed || app.state == State::data_retained,
                    "AETHER_RUNTIME_DEPENDENCIES",
                    "Finish pending app installation, update or removal before upgrading its runtime");
    return uses;
}
void upgrade_location(const std::filesystem::path &root) {
    validate_path(root);
    require(
        !below(current_image(), root), "AETHER_RUNTIME_SELF_UPGRADE",
        "Run upgrade from an external AetherSetup distribution; the installed runtime cannot replace itself");
}
} // namespace
RuntimeSetupStatus inspect_runtime_upgrade(const std::filesystem::path &root) {
    try {
        upgrade_location(root);
        Root target(root, false);
        Catalogue state(root, false, false, false, true);
        require(state.record.phase == Phase::ready || state.record.phase == Phase::upgrading,
                "AETHER_RUNTIME_STATE",
                "Only a ready runtime or its recorded interrupted upgrade can be upgraded");
        auto shell = hold_shell_registration();
        const auto uses = upgrade_dependencies(state.record);
        return {
            state.record.phase == Phase::upgrading ? "upgrading" : "ready",
            "Existing launcher paths, installed apps, permission decisions and package stores will be kept. "
            "The icon service stops after approval; other running Aether apps must be closed. "
            "The compatible distribution and all runtime files are checked again before writing. "
            "If interrupted, explicitly resume with the same distribution.",
            true};
    } catch (const std::exception &error) {
        return {"unavailable", error.what(), false};
    }
}
RuntimeSetupStatus inspect_runtime_repair(const std::filesystem::path &root) {
    try {
        upgrade_location(root);
        Root target(root, false);
        Catalogue state(root, false, false, false, true);
        require(!state.record.native_id.empty() && state.record.schema >= 4 &&
                    (state.record.phase == Phase::ready || state.record.phase == Phase::preparing),
                "AETHER_RUNTIME_STATE",
                "Repair requires a current native runtime. Resume an interrupted upgrade with its exact "
                "distribution, or upgrade a legacy runtime first.");
        auto shell = hold_shell_registration();
        detail::verify_runtime_registration(root, state.record.native_id, true);
        const auto uses = dependencies(state.record, true);
        require(uses.blockers.empty(), "AETHER_RUNTIME_DEPENDENCIES",
                "An application store or Explorer ownership record cannot be verified");
        return {"repairable",
                "The exact installed distribution restores missing runtime files and owned Windows entries. "
                "Interrupted file prefixes can be completed; unrecognized changed files are preserved. "
                "The icon service stops after approval. Close running Aether apps before repair.",
                true};
    } catch (const std::exception &error) {
        return {"unavailable", error.what(), false};
    }
}
std::string repair_runtime(const std::filesystem::path &root, const RuntimeBundle &bundle) {
    PendingShellNotice notice;
    require(bundle.compatibility == current_runtime_compatibility, "AETHER_RUNTIME_COMPATIBILITY",
            "Repair requires this runtime's exact compatible distribution");
    const auto candidate = native_inventory(bundle.files);
    upgrade_location(root);
    RuntimeUseLease executing;
    stop_owned_icon_broker(root);
    Root target(root, true);
    Catalogue state(root, true, false, false, true);
    require(!state.record.native_id.empty() && state.record.schema >= 4 &&
                (state.record.phase == Phase::ready || state.record.phase == Phase::preparing),
            "AETHER_RUNTIME_STATE", "Repair requires a current ready or preparing native runtime");
    require(state.record.compatibility == bundle.compatibility &&
                state.record.icon_library == single_icon(candidate) &&
                std::all_of(candidate.begin(), candidate.end(),
                            [&](const auto &file) {
                                return std::find(state.record.files.begin(), state.record.files.end(),
                                                 file) != state.record.files.end();
                            }),
            "AETHER_RUNTIME_REPAIR_BUNDLE",
            "Repair requires the exact recorded installed distribution; different bytes are preserved");
    auto shell = hold_shell_registration();
    detail::verify_runtime_registration(root, state.record.native_id, true);
    const auto uses = dependencies(state.record, true);
    require(uses.blockers.empty(), "AETHER_RUNTIME_DEPENDENCIES",
            "Application stores or Explorer ownership could not be verified; no repair writes were made");
    const auto explorer = explorer_registration(ExplorerOperation::status);
    const bool owns_explorer = !explorer.launcher.empty() &&
                               same_path(std::filesystem::path(utf16(explorer.launcher)).parent_path(), root);
    if (owns_explorer)
        (void)explorer_registration(ExplorerOperation::check_upgrade, {}, root,
                                    root / utf16(state.record.icon_library));
    auto files =
        payload_inventory(root, &state.record.files, false, &bundle, true, &state.record.files, true);
    for (std::size_t n = 0; n < files.files.size(); ++n)
        if (!files.files[n])
            require(
                std::any_of(candidate.begin(), candidate.end(),
                            [&](const auto &file) { return file.path == files.payload[n].path; }),
                "AETHER_RUNTIME_REPAIR_BUNDLE",
                "A missing retained historical payload is not in this distribution; it cannot be guessed");
    state.repair_tail(); // Only after exact bundle, ownership and all existing leaves pass preflight.
    auto directories = payload_directories(root, state.record.files);
    write_payload(root, files, bundle, state.record.files, true);
    files.files.clear();
    detail::register_runtime(root, state.record.native_id, true);
    if (owns_explorer) {
        notice.changed = true;
        (void)explorer_registration(ExplorerOperation::repair, {}, root,
                                    root / utf16(state.record.icon_library), false,
                                    uses.held_store(explorer.store));
    }
    if (state.record.phase == Phase::preparing) {
        state.record.phase = Phase::ready;
        state.commit();
    }
    return "{\"schemaVersion\":1,\"operation\":\"runtime-repair\",\"state\":\"ready\","
           "\"packageStoresPreserved\":true,\"unrecognizedFilesPreserved\":true}";
}
std::string upgrade_runtime(const std::filesystem::path &root, const RuntimeBundle &bundle) {
    PendingShellNotice notice;
    require(bundle.compatibility == current_runtime_compatibility, "AETHER_RUNTIME_COMPATIBILITY",
            "Upgrade requires runtime compatibility contract 27 (native conversion target state schema 11 and IME metadata command schema 10; actual TextEdit operation history and actual input connection; edit events and text reveal; text-bound selection; bounded read-only document provider operations; owned link offers and native activation cleanup; reviewed original-Intent choice startup schema 2; catalogue schema 5; package schemas 1-14; same-event Unicode key metadata, editable text/value actions, scroll geometry/actions, view descriptions, checked/semantic view publication, owned toast activation, consented playback and historical icons); older or incompatible "
            "distributions are "
            "refused");
    auto candidate = native_inventory(bundle.files);
    const auto candidate_icon = single_icon(candidate);
    upgrade_location(root);
    RuntimeUseLease executing;
    stop_owned_icon_broker(root);
    Root target(root, true);
    Catalogue state(root, true, false, false, true);
    require(state.record.phase == Phase::ready || state.record.phase == Phase::upgrading,
            "AETHER_RUNTIME_STATE",
            "Only a ready runtime or its recorded interrupted upgrade can be upgraded");
    // Legacy developer installations have no native setup/Windows identity.
    // Upgrade their existing leaves only; do not silently adopt them as native.
    if (state.record.native_id.empty() &&
        std::none_of(state.record.files.begin(), state.record.files.end(),
                     [](const auto &item) { return item.path == "aether-setup.exe"; }))
        std::erase_if(candidate, [](const auto &item) { return item.path == "aether-setup.exe"; });
    for (const auto &old : state.record.files)
        if (std::none_of(candidate.begin(), candidate.end(),
                         [&](const auto &item) { return item.path == old.path; })) {
            require(icon_payload(old.path) || old.path.starts_with("licenses/"),
                    "AETHER_RUNTIME_COMPATIBILITY", "The distribution removed a required runtime path");
            candidate.push_back(old);
        }
    std::sort(candidate.begin(), candidate.end(),
              [](const auto &a, const auto &b) { return a.path < b.path; });
    require(candidate.size() <= max_catalogue_payloads && additive_layout(state.record.files, candidate),
            "AETHER_RUNTIME_COMPATIBILITY", "The upgrade exceeds the bounded additive runtime layout");
    require(std::count_if(candidate.begin(), candidate.end(), [](const auto &item) { return !icon_payload(item.path); }) <= 96,
            "AETHER_RUNTIME_COMPATIBILITY", "Non-icon runtime layout exceeds its original bound");
    const bool resuming = state.record.phase == Phase::upgrading;
    require(!resuming || state.record.compatibility == bundle.compatibility, "AETHER_RUNTIME_COMPATIBILITY",
            "An interrupted upgrade requires its recorded runtime compatibility contract");
    require(!resuming ||
                (state.record.pending == candidate && state.record.pending_icon_library == candidate_icon),
            "AETHER_RUNTIME_UPGRADE_BUNDLE",
            "An interrupted upgrade requires the exact recorded distribution; different bytes are preserved");
    require(state.count <= max_frames - (resuming ? 2 : 3), "AETHER_RUNTIME_LIMIT",
            "Runtime catalogue lacks space for the upgrade decision and reserved removal frame");
    auto shell = hold_shell_registration();
    const auto uses = upgrade_dependencies(state.record);
    const auto registered = explorer_registration(ExplorerOperation::status);
    const bool owns_explorer =
        !registered.launcher.empty() &&
        same_path(std::filesystem::path(utf16(registered.launcher)).parent_path(), root);
    if (owns_explorer)
        (void)explorer_registration(ExplorerOperation::check_upgrade, {}, root, root / utf16(candidate_icon));
    // Acquire and validate every writable final identity before recording intent.
    // No images, app records, registrations or directories are copied or renamed.
    auto files = payload_inventory(root, &state.record.files, false, &bundle, resuming, &candidate);
    require(files.complete, "AETHER_RUNTIME_PAYLOAD",
            "A required runtime file is missing; it is not recreated");
    // Complete frames, the exact pending distribution and all held existing
    // identities must pass preflight before discarding an interrupted append.
    state.repair_tail();
    if (!resuming && state.record.compatibility == bundle.compatibility &&
        state.record.files == candidate && state.record.icon_library == candidate_icon)
        return "{\"schemaVersion\":1,\"operation\":\"runtime-upgrade\",\"state\":\"unchanged\","
               "\"packageStoresPreserved\":true,\"launcherPathsPreserved\":true}";
    if (!resuming) {
        state.record.schema = 5;
        state.record.compatibility = current_runtime_compatibility;
        state.record.phase = Phase::upgrading;
        state.record.pending = candidate;
        state.record.pending_icon_library = candidate_icon;
        state.commit();
    }
    auto directories = payload_directories(root, candidate);
    write_payload(root, files, bundle, state.record.files);
    files.files.clear(); // Release writable leaves before registration re-verifies the final images.
    if (owns_explorer) {
        notice.changed = true;
        (void)explorer_registration(ExplorerOperation::repair, {}, root, root / utf16(candidate_icon), false,
                                    uses.held_store(registered.store));
    }
    state.record.files = candidate;
    state.record.icon_library = candidate_icon;
    state.record.pending_icon_library.clear();
    state.record.pending.clear();
    state.record.phase = Phase::ready;
    state.commit();
    return "{\"schemaVersion\":1,\"operation\":\"runtime-upgrade\",\"state\":\"ready\",\"resumed\":" +
           std::string(resuming ? "true" : "false") +
           ",\"packageStoresPreserved\":true,\"launcherPathsPreserved\":true}";
}
std::wstring runtime_uninstall_command(const std::filesystem::path &root, bool quiet) {
    Root target(root, false);
    Catalogue state(root, false);
    require(!state.record.native_id.empty(), "AETHER_RUNTIME_UNMANAGED",
            "This runtime has no native uninstall identity");
    auto shell = hold_shell_registration();
    detail::verify_runtime_registration(root, state.record.native_id, true);
    return detail::uninstall_command(root, state.record.native_id, quiet);
}
std::string remove_runtime(const std::filesystem::path &root, DWORD controller_pid) {
    const bool self = same_path(root, current_root());
    require(!self || controller_pid, "AETHER_SETUP_CONTROLLER",
            "Installed runtime removal requires its Windows controller");
    require(!controller_pid || (self && same_path(current_image(), root / L"aether-setup.exe")),
            "AETHER_SETUP_CONTROLLER",
            "Cleanup transfer is only available from the recorded installed setup image");
    auto controller = controller_pid ? controller_process(controller_pid) : UniqueHandle{};
    if (self)
        io(SetCurrentDirectoryW(windows_powershell().parent_path().c_str()),
           "Cannot release the installer's working directory");
    stop_owned_icon_broker(root);
    Root target(root, true, true);
    Catalogue state(root, true);
    require(state.record.phase != Phase::upgrading, "AETHER_RUNTIME_STATE",
            "Complete the recorded runtime upgrade before removal");
    require(!state.record.native_id.empty(), "AETHER_RUNTIME_UNMANAGED",
            "AetherSetup only removes its recorded native installations");
    auto shell = hold_shell_registration();
    detail::verify_runtime_registration(root, state.record.native_id, true);
    const auto uses = dependencies(state.record, true);
    require(uses.empty(), "AETHER_RUNTIME_DEPENDENCIES",
            "Installed apps, retained data, link offers or unreadable ownership records still require Aether. "
            "Remove owned offers with link-handlers remove --app-id ID --store ROOT --yes before runtime removal.");
    auto files = payload_inventory(root, &state.record.files, true);
    auto own = files.files.size();
    for (std::size_t n = 0; n < files.payload.size(); ++n)
        if (files.payload[n].path == "aether-setup.exe")
            own = n;
    require(!self || (own < files.files.size() && files.files[own]), "AETHER_SETUP_CONTROLLER",
            "The recorded native setup image is missing");
    if (state.record.phase != Phase::removing) {
        state.record.phase = Phase::removing;
        state.commit();
    }
    remove_owned_explorer(root);
    // Resolve mapped DLLs before removing setup, its dependencies or the
    // catalogue. An in-use image must leave a working explicit cleanup path.
    remove_icon_payloads(files);
    for (std::size_t n = 0; n < files.files.size(); ++n)
        if (files.files[n] && (!self || n != own)) {
            mark_delete(files.files[n].get(), icon_payload(files.payload[n].path));
            files.files[n].reset();
        }
    for (auto dir = files.directories.rbegin(); dir != files.directories.rend(); ++dir) {
        mark_delete(dir->get());
        dir->reset();
    }
    for (const auto &entry : std::filesystem::directory_iterator(root))
        require(entry.path().filename() == record_file || entry.path().filename() == lease_file ||
                    (self && entry.path().filename() == L"aether-setup.exe"),
                "AETHER_RUNTIME_CONFLICT",
                "Unrelated material appeared during runtime removal and is preserved");
    if (self) {
        RemoteHandles transfer(controller.get());
        transfer.handles.reserve(target.parents.size() + 4);
        transfer.add(files.files[own].get());
        transfer.add(state.file.get());
        transfer.add(target.lease.get());
        transfer.add(target.held.get());
        for (const auto &parent : target.parents)
            transfer.add(parent.get());
        const auto output =
            "{\"schemaVersion\":1,\"state\":\"cleanup\",\"root\":" + json_quote(utf8(root.wstring())) +
            ",\"identity\":" + json_quote(state.record.native_id) + ",\"handles\":" + transfer.json() +
            ",\"hashes\":[" + json_quote(files.payload[own].sha256) + ',' +
            json_quote(apk::sha256(detail::read_contents(state.file.get()))) +
            "],\"registration\":" + detail::runtime_registration_json(root, state.record.native_id) + '}';
        transfer.transferred = true;
        return output;
    }
    // External original distribution also provides explicit interrupted cleanup.
    detail::unregister_runtime(root, state.record.native_id);
    mark_delete(state.file.get());
    state.file.reset();
    mark_delete(target.lease.get());
    target.lease.reset();
    mark_delete(target.held.get());
    target.held.reset();
    require(missing(root), "AETHER_RUNTIME_IO",
            "Runtime removal is incomplete; a conflicting handle is still open");
    return "{\"schemaVersion\":1,\"state\":\"removed\",\"packageStoresPreserved\":true}";
}

void remember_runtime_store(const std::filesystem::path &store) {
    const auto root = current_root();
    if (missing(root / record_file))
        return;
    RuntimeUseLease active;
    const auto validate_store = [&] {
        validate_path(store);
        require(!below(store, root) && !below(root, store), "AETHER_RUNTIME_STORE",
                "Runtime binaries and package stores must use separate directory trees");
    };
    {
        // Ordinary launches already belong to an enrolled store. Shared reads
        // let independent preparations coexist without requesting a journal write.
        Catalogue current(root, false);
        require(current.record.phase == Phase::ready, "AETHER_RUNTIME_STATE",
                "Runtime is not ready for package changes");
        validate_store();
        if (std::any_of(current.record.stores.begin(), current.record.stores.end(),
                        [&](const auto &known) { return same_path(known, store); }))
            return;
    } // Close the shared catalogue handle before acquiring exclusive write access.
    Catalogue state(root, true);
    require(state.record.phase == Phase::ready, "AETHER_RUNTIME_STATE",
            "Runtime is not ready for package changes");
    validate_store();
    if (std::any_of(state.record.stores.begin(), state.record.stores.end(),
                    [&](const auto &known) { return same_path(known, store); }))
        return;
    require(state.record.stores.size() < 32, "AETHER_RUNTIME_LIMIT",
            "Runtime has 32 tracked stores; explicitly forget an empty store before adding another");
    require(!missing(store / L"registry.log"), "AETHER_RUNTIME_STORE",
            "A store must have an opened journal before runtime enrollment");
    state.record.stores.push_back(store);
    state.commit();
}
bool is_runtime_command(const std::vector<std::string> &arguments) {
    for (const auto &arg : arguments) {
        if (arg != "--json" && arg != "--verbose")
            return arg == "runtime";
    }
    return false;
}
int runtime_cli(const std::vector<std::string> &arguments, bool json) {
    std::string action, root_text, store_text, bundle_text;
    bool command = false, yes = false;
    std::set<std::string> options;
    for (std::size_t n = 0; n < arguments.size(); ++n) {
        const auto &arg = arguments[n];
        if (arg.starts_with("--")) {
            require(options.insert(arg).second, "AETHER_CLI_USAGE",
                    "A runtime option was specified more than once");
            if (arg == "--json" || arg == "--verbose")
                continue;
            if (arg == "--yes") {
                yes = true;
                continue;
            }
            require((arg == "--root" || arg == "--store" || arg == "--bundle") && n + 1 < arguments.size() &&
                        !arguments[n + 1].empty() && !arguments[n + 1].starts_with('-'),
                    "AETHER_CLI_USAGE", "Unknown runtime option or missing path");
            (arg == "--root" ? root_text : arg == "--store" ? store_text : bundle_text) = arguments[++n];
        } else if (!command && arg == "runtime")
            command = true;
        else {
            require(command && action.empty(), "AETHER_CLI_USAGE", "runtime requires one operation");
            action = arg;
        }
    }
    const bool read_only = action == "status" || action == "check-removal";
    require(read_only || action == "prepare" || action == "finalize" || action == "repair" ||
                action == "forget-store" || action == "remove" || action == "upgrade",
            "AETHER_CLI_USAGE",
            "Use runtime status, prepare, finalize, check-removal, forget-store, repair, upgrade or remove");
    require(!yes || !read_only, "AETHER_CLI_USAGE", "Read-only runtime commands do not accept --yes");
    require(read_only || yes, "AETHER_INSTALL_CONFIRMATION_REQUIRED", "Runtime changes require --yes");
    require((action == "forget-store") == !store_text.empty(), "AETHER_CLI_USAGE",
            "Only forget-store requires --store");
    require((action == "upgrade") == !bundle_text.empty(), "AETHER_CLI_USAGE",
            "Only runtime upgrade requires --bundle PATH");
    require(action != "prepare" || !root_text.empty(), "AETHER_CLI_USAGE",
            "runtime prepare requires a new absolute --root");
    const auto root = root_text.empty() ? current_root() : std::filesystem::path(utf16(root_text));
    validate_path(root);
    std::optional<RuntimeUseLease> executing_runtime;
    if (!same_path(root, current_root()))
        executing_runtime.emplace();
    std::string output;
    int exit_code = 0;
    if (action == "upgrade") {
        output = upgrade_runtime(root, read_runtime_bundle(utf16(bundle_text)));
    } else if (action == "prepare") {
        auto held = ancestors(root);
        require(
            missing(root), "AETHER_RUNTIME_EXISTS",
            "Runtime preparation requires a new destination; existing installations are never overwritten");
        auto target = detail::hold_directory(root, true, true);
        auto lease = use_file(root, true, true);
        Catalogue state(root, true, true);
        state.record.schema = 5;
        state.record.compatibility = current_runtime_compatibility;
        state.commit();
        auto workers = detail::hold_directory(root / L"runtime", true, true);
        auto licences = detail::hold_directory(root / L"licenses", true, true);
        output = describe(state.record, {}, false, false, false);
    } else if (missing(root / record_file)) {
        require(
            action == "status", "AETHER_RUNTIME_UNMANAGED",
            "This directory has no managed runtime intent; it cannot be adopted or removed automatically");
        output = "{\"schemaVersion\":1,\"operation\":\"runtime\",\"state\":\"unmanaged\",\"root\":" +
                 json_quote(utf8(root.wstring())) + ",\"removalReady\":false}";
    } else {
        const bool removing = action == "remove", removal_check = action == "check-removal";
        require(!(removing || removal_check) || !same_path(root, current_root()),
                "AETHER_RUNTIME_SELF_REMOVE",
                "Use an external installer/runtime CLI for removal or its exclusive preflight; a runtime "
                "cannot remove its own executing image");
        if (removing || action == "repair")
            stop_owned_icon_broker(root);
        Root target(root, action != "status", removing);
        Catalogue state(root, !read_only, false, action == "repair");
        if (action == "finalize") {
            require(state.record.native_id.empty() && state.record.phase == Phase::preparing &&
                        same_path(root, current_root()),
                    "AETHER_RUNTIME_STATE", "Finalize must run from the freshly installed preparing runtime");
            auto files = payload_inventory(root, nullptr, false);
            state.record.files = std::move(files.payload);
            state.record.icon_library = single_icon(state.record.files);
            state.record.phase = Phase::ready;
            state.commit();
            output = describe(state.record, {}, true, true, false);
        } else if (action == "forget-store") {
            require(state.record.phase == Phase::ready, "AETHER_RUNTIME_STATE",
                    "Only a ready runtime can forget an empty store");
            const std::filesystem::path store(utf16(store_text));
            validate_path(store);
            const auto at = std::find_if(state.record.stores.begin(), state.record.stores.end(),
                                         [&](const auto &known) { return same_path(known, store); });
            require(at != state.record.stores.end() && !missing(store / L"registry.log"),
                    "AETHER_RUNTIME_STORE", "Only a tracked, readable store can be forgotten");
            PackageStore packages(store);
            require(packages.list().empty(), "AETHER_RUNTIME_DEPENDENCIES",
                    "Installed, pending or retained apps still require this store");
            state.record.stores.erase(at);
            state.commit();
            output = describe(state.record, {}, false, false, false);
        } else if (removing || removal_check) {
            require(state.record.native_id.empty(), "AETHER_RUNTIME_NATIVE_SETUP",
                    "Use AetherSetup uninstall for this runtime and its Windows registration");
            require(state.record.phase != Phase::preparing && state.record.phase != Phase::upgrading,
                    "AETHER_RUNTIME_STATE",
                    "Preparing runtime removal requires a completed payload record; unknown partial payloads "
                    "are preserved");
            const auto uses = dependencies(state.record);
            if (!uses.empty()) {
                require(!removing, "AETHER_RUNTIME_DEPENDENCIES",
                        "Runtime removal is blocked by applications, retained data, unreadable stores or "
                        "Explorer ownership; inspect runtime status first");
                output = describe(state.record, uses, false, false, false);
                exit_code = 1;
            } else {
                auto files = payload_inventory(root, &state.record.files, removing);
                if (removal_check)
                    output = describe(state.record, uses, files.complete, true, true);
                else {
                    if (state.record.phase != Phase::removing) {
                        state.record.phase = Phase::removing;
                        state.commit();
                    }
                    remove_icon_payloads(files);
                    for (std::size_t n = 0; n < files.files.size(); ++n)
                        if (files.files[n]) {
                            mark_delete(files.files[n].get(), icon_payload(files.payload[n].path));
                            files.files[n].reset();
                        }
                    for (auto dir = files.directories.rbegin(); dir != files.directories.rend(); ++dir) {
                        mark_delete(dir->get());
                        dir->reset();
                    }
                    for (const auto &entry : std::filesystem::directory_iterator(root))
                        require(entry.path().filename() == record_file ||
                                    entry.path().filename() == lease_file,
                                "AETHER_RUNTIME_CONFLICT",
                                "New unrelated runtime material was preserved during removal");
                    mark_delete(state.file.get());
                    state.file.reset();
                    mark_delete(target.lease.get());
                    target.lease.reset();
                    mark_delete(target.held.get());
                    target.held.reset();
                    require(missing(root), "AETHER_RUNTIME_IO",
                            "Runtime removal has not completed; a conflicting handle may still be open");
                    output =
                        "{\"schemaVersion\":1,\"operation\":\"runtime\",\"state\":\"removed\",\"root\":" +
                        json_quote(utf8(root.wstring())) + ",\"packageStoresPreserved\":true}";
                }
            }
        } else
            output = describe(state.record, dependencies(state.record), false, false, false);
    }
    if (json)
        std::cout << output << '\n';
    else
        std::cout << "Aether shared runtime: " << output << '\n';
    return exit_code;
}
} // namespace aether::install
