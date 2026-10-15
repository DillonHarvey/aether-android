#include "aether/shell/icon_cache.hpp"
#include "aether/security/worker_image.hpp"
#include "aether/shell/icons.hpp"
#include <ShlObj.h>
#include <aclapi.h>
#include <algorithm>
#include <bcrypt.h>
#include <cstring>
#include <map>
#include <sddl.h>
#include <stdexcept>

namespace aether::shell {
namespace {
using host::UniqueHandle;
using Bytes = std::span<const std::uint8_t>;
constexpr std::size_t icon_limit = 512 * 1024, record_size = 144;
constexpr std::array<std::uint8_t, 8> record_magic{'A', 'E', 'T', 'H', 'I', 'C', '0', '2'};
void require(bool condition, const char *message) {
    if (!condition)
        throw std::runtime_error(message);
}
struct Policy {
    PSECURITY_DESCRIPTOR value = nullptr;
    explicit Policy(bool directory) {
        auto sddl = security::runtime_directory_sddl();
        if (!directory)
            for (auto at = sddl.find(L";OICI;"); at != sddl.npos; at = sddl.find(L";OICI;"))
                sddl.replace(at, 6, L";;");
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &value,
                                                                     nullptr) != FALSE,
                "AETHER_ICON_CACHE_POLICY: cannot create owner/SYSTEM policy");
    }
    ~Policy() { LocalFree(value); }
    Policy(const Policy &) = delete;
    Policy &operator=(const Policy &) = delete;
};
void private_file(HANDLE file) {
    BY_HANDLE_FILE_INFORMATION info{};
    require(file && file != INVALID_HANDLE_VALUE && GetFileType(file) == FILE_TYPE_DISK &&
                GetFileInformationByHandle(file, &info) && info.nNumberOfLinks == 1 &&
                !(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)),
            "AETHER_ICON_CACHE_FILE: not a regular single-link file");
    PSECURITY_DESCRIPTOR raw = nullptr;
    PSID owner = nullptr, wanted_owner = nullptr;
    PACL acl = nullptr, wanted_acl = nullptr;
    const auto status =
        GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
                        nullptr, &acl, nullptr, &raw);
    struct Release {
        PSECURITY_DESCRIPTOR p;
        ~Release() { LocalFree(p); }
    } release{raw};
    Policy wanted(false);
    BOOL present = FALSE, defaulted = FALSE;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    require(status == ERROR_SUCCESS && owner && acl &&
                GetSecurityDescriptorOwner(wanted.value, &wanted_owner, &defaulted) &&
                GetSecurityDescriptorDacl(wanted.value, &present, &wanted_acl, &defaulted) &&
                EqualSid(owner, wanted_owner) && GetSecurityDescriptorControl(raw, &control, &revision) &&
                (control & SE_DACL_PROTECTED) && acl->AceCount == wanted_acl->AceCount,
            "AETHER_ICON_CACHE_POLICY: wrong owner or unprotected policy");
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void *actual = nullptr, *expected = nullptr;
        require(GetAce(acl, i, &actual) && GetAce(wanted_acl, i, &expected), "Cannot read cache ACL");
        const auto a = static_cast<const ACE_HEADER *>(actual), b = static_cast<const ACE_HEADER *>(expected);
        require(a->AceSize == b->AceSize && std::memcmp(a, b, a->AceSize) == 0,
                "AETHER_ICON_CACHE_POLICY: unexpected file permissions");
    }
}
std::vector<UniqueHandle> parents(const std::filesystem::path &path) {
    const auto text = path.native();
    const std::size_t start = text.starts_with(L"\\\\?\\") ? 4 : 0;
    require(text.size() > start + 3 && text[start + 1] == L':' && text[start + 2] == L'\\' &&
                text.find(L':', start + 2) == text.npos && text.size() < 32768 &&
                GetDriveTypeW(text.substr(start, 3).c_str()) == DRIVE_FIXED,
            "AETHER_ICON_LOCAL_ONLY: fixed local disk required");
    std::vector<std::filesystem::path> paths{text.substr(0, start + 3)};
    for (auto at = text.find(L'\\', start + 3); at != text.npos; at = text.find(L'\\', at + 1))
        paths.emplace_back(text.substr(0, at));
    require(paths.size() <= 256, "AETHER_ICON_PATH_LIMIT: directory depth exceeds 256");
    std::vector<UniqueHandle> held;
    for (const auto &p : paths) {
        UniqueHandle handle(CreateFileW(p.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        nullptr, OPEN_EXISTING,
                                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        FILE_ATTRIBUTE_TAG_INFO info{};
        require(handle &&
                    GetFileInformationByHandleEx(handle.get(), FileAttributeTagInfo, &info, sizeof(info)) &&
                    (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    !(info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT),
                "AETHER_ICON_REPARSE: inaccessible or redirected ancestor");
        held.push_back(std::move(handle));
    }
    return held;
}
void put(std::vector<std::uint8_t> &out, std::uint64_t value, unsigned bytes = 8) {
    for (unsigned i = 0; i < bytes; ++i)
        out.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
}
std::uint64_t number(Bytes data, std::size_t offset, unsigned bytes = 4) noexcept {
    if (offset > data.size() || bytes > data.size() - offset)
        return UINT64_MAX;
    std::uint64_t value = 0;
    for (unsigned i = 0; i < bytes; ++i)
        value |= std::uint64_t(data[offset + i]) << (i * 8);
    return value;
}
std::uint64_t now() {
    FILETIME time{};
    GetSystemTimeAsFileTime(&time);
    return (std::uint64_t(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}
IconDigest source_identity(HANDLE file, const std::filesystem::path &path, std::uint64_t &size) {
    FILE_ID_INFO id{};
    FILE_BASIC_INFO basic{};
    FILE_STANDARD_INFO standard{};
    require(
        GetFileType(file) == FILE_TYPE_DISK &&
            GetFileInformationByHandleEx(file, FileIdInfo, &id, sizeof(id)) &&
            GetFileInformationByHandleEx(file, FileBasicInfo, &basic, sizeof(basic)) &&
            GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard)) &&
            !standard.Directory && !standard.DeletePending && standard.EndOfFile.QuadPart > 0 &&
            !(basic.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE |
                                      FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_RECALL_ON_OPEN)),
        "AETHER_ICON_INPUT: inaccessible, offline or non-regular source");
    std::vector<std::uint8_t> bytes;
    put(bytes, icon_content_version);
    put(bytes, id.VolumeSerialNumber);
    bytes.insert(bytes.end(), std::begin(id.FileId.Identifier), std::end(id.FileId.Identifier));
    size = static_cast<std::uint64_t>(standard.EndOfFile.QuadPart);
    put(bytes, size);
    put(bytes, static_cast<std::uint64_t>(basic.CreationTime.QuadPart));
    put(bytes, static_cast<std::uint64_t>(basic.LastWriteTime.QuadPart));
    put(bytes, static_cast<std::uint64_t>(basic.ChangeTime.QuadPart));
    const auto &name = path.native();
    bytes.insert(bytes.end(), reinterpret_cast<const std::uint8_t *>(name.data()),
                 reinterpret_cast<const std::uint8_t *>(name.data() + name.size()));
    return icon_digest(bytes);
}
UniqueHandle open(const std::filesystem::path &path, DWORD access, DWORD creation = OPEN_EXISTING) {
    Policy policy(false);
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), policy.value, FALSE};
    UniqueHandle file(CreateFileW(path.c_str(), access | READ_CONTROL, FILE_SHARE_READ, &attributes, creation,
                                  FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    require(static_cast<bool>(file), "AETHER_ICON_CACHE_IO: cannot open protected artifact");
    private_file(file.get());
    return file;
}
std::vector<std::uint8_t> read(HANDLE file, std::size_t bound) {
    LARGE_INTEGER size{};
    require(GetFileSizeEx(file, &size) && size.QuadPart >= 0 &&
                static_cast<std::uint64_t>(size.QuadPart) <= bound,
            "AETHER_ICON_CACHE_LIMIT: artifact exceeds bound");
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
    DWORD got = 0;
    require(ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &got, nullptr) &&
                got == bytes.size(),
            "AETHER_ICON_CACHE_IO: incomplete artifact");
    return bytes;
}
void write(HANDLE file, Bytes bytes) {
    DWORD written = 0;
    require(WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
                written == bytes.size() && FlushFileBuffers(file),
            "AETHER_ICON_CACHE_IO: incomplete final write");
}
std::filesystem::path record_path(const std::filesystem::path &root, const IconDigest &source) {
    return root / (icon_hex(source) + L".ref");
}
std::vector<std::uint8_t> record(const IconDigest &source, const IconDigest &artifact, CacheState state,
                                 std::uint32_t attempts, std::uint64_t retry) {
    std::vector<std::uint8_t> data(record_magic.begin(), record_magic.end());
    put(data, icon_cache_version, 4);
    put(data, static_cast<unsigned>(state), 4);
    data.insert(data.end(), source.begin(), source.end());
    data.insert(data.end(), artifact.begin(), artifact.end());
    put(data, now());
    put(data, retry);
    put(data, attempts, 4);
    put(data, 0, 4);
    put(data, 0);
    const auto hash = icon_digest(data);
    data.insert(data.end(), hash.begin(), hash.end());
    require(data.size() == record_size, "Cache record programming error");
    return data;
}
CachedIcon parse_record(Bytes bytes, const IconDigest &source) {
    require(bytes.size() == record_size &&
                std::equal(record_magic.begin(), record_magic.end(), bytes.begin()) &&
                number(bytes, 8) == icon_cache_version && number(bytes, 12) >= 1 && number(bytes, 12) <= 2 &&
                std::equal(source.begin(), source.end(), bytes.begin() + 16) && number(bytes, 100) == 0 &&
                number(bytes, 104, 8) == 0 && number(bytes, 96) <= 6,
            "AETHER_ICON_CACHE_RECORD: invalid commit record");
    const auto checksum = icon_digest(bytes.first(record_size - 32));
    require(std::equal(checksum.begin(), checksum.end(), bytes.end() - 32),
            "AETHER_ICON_CACHE_RECORD: incomplete commit or checksum mismatch");
    CachedIcon result;
    result.state = static_cast<CacheState>(number(bytes, 12));
    std::copy_n(bytes.begin() + 48, result.digest.size(), result.digest.begin());
    result.retry_at = number(bytes, 88, 8);
    result.attempts = static_cast<std::uint32_t>(number(bytes, 96));
    return result;
}
void write_record(const std::filesystem::path &root, const IconDigest &source, Bytes bytes) {
    const auto path = record_path(root, source);
    // An old record is changed only through its verified, exclusively writable
    // handle. A partial direct write has no valid checksum and is a cache miss.
    auto file = open(path, GENERIC_READ | GENERIC_WRITE, OPEN_ALWAYS);
    LARGE_INTEGER zero{};
    require(SetFilePointerEx(file.get(), zero, nullptr, FILE_BEGIN) && SetEndOfFile(file.get()),
            "AETHER_ICON_CACHE_IO: cannot begin final commit");
    write(file.get(), bytes);
}
bool digest_name(std::wstring_view name, std::wstring_view extension, IconDigest &digest) {
    if (name.size() != 64 + extension.size() || !name.ends_with(extension))
        return false;
    for (std::size_t i = 0; i < 32; ++i) {
        const auto hex = [](wchar_t c) {
            return c >= L'0' && c <= L'9' ? c - L'0' : c >= L'a' && c <= L'f' ? c - L'a' + 10 : -1;
        };
        const auto hi = hex(name[2 * i]), lo = hex(name[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        digest[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}
void remove_file(const std::filesystem::path &path, std::size_t limit, const IconDigest *expected) {
    auto file = open(path, GENERIC_READ | DELETE);
    const auto data = read(file.get(), limit);
    require(!expected || (valid_cached_icon(data) && icon_digest(data) == *expected),
            "AETHER_ICON_CACHE_TAMPERED: unknown modified artifact preserved");
    FILE_DISPOSITION_INFO remove{TRUE};
    require(SetFileInformationByHandle(file.get(), FileDispositionInfo, &remove, sizeof(remove)) != FALSE,
            "AETHER_ICON_CACHE_BUSY: artifact remains in use");
}
} // namespace
IconDigest icon_digest(std::span<const std::uint8_t> bytes) {
    require(bytes.size() <= UINT32_MAX, "Icon hash input exceeds bound");
    IconDigest result{};
    require(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, const_cast<PUCHAR>(bytes.data()),
                       static_cast<ULONG>(bytes.size()), result.data(),
                       static_cast<ULONG>(result.size())) >= 0,
            "AETHER_ICON_HASH: SHA-256 failed");
    return result;
}
std::wstring icon_hex(const IconDigest &digest) {
    constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring text;
    text.reserve(64);
    for (auto byte : digest) {
        text.push_back(digits[byte >> 4]);
        text.push_back(digits[byte & 15]);
    }
    return text;
}
std::filesystem::path icon_cache_root() {
    PWSTR raw = nullptr;
    const auto result = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DONT_VERIFY, nullptr, &raw);
    struct Release {
        PWSTR p;
        ~Release() { CoTaskMemFree(p); }
    } release{raw};
    require(SUCCEEDED(result) && raw, "AETHER_ICON_CACHE_ROOT: LocalAppData unavailable");
    return std::filesystem::path(raw) / L"Aether" / L"IconCache";
}
bool launch_icon_service(const std::filesystem::path &executable) {
    try {
        require(executable.filename() == L"aether.exe" &&
                    executable.native().find(L'\"') == std::wstring::npos,
                "Invalid registered icon host");
        auto pinned = parents(executable);
        UniqueHandle directory(
            CreateFileW(executable.parent_path().c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        security::verify_runtime_directory(directory.get());
        auto file = open(executable, GENERIC_READ);
        security::verify_owned_runtime_file(file.get());
        std::wstring command = L"\"" + executable.native() + L"\" shell-icons serve";
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESHOWWINDOW;
        startup.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION process{};
        require(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                               CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr,
                               executable.parent_path().c_str(), &startup, &process) != FALSE,
                "Cannot start the installed icon service");
        UniqueHandle process_handle(process.hProcess), thread_handle(process.hThread);
        return true;
    } catch (...) {
        return false;
    }
}
IconSource::IconSource(const std::filesystem::path &path, bool read) {
    const auto normalized = icon_input_path(path.native());
    require(!normalized.empty(), "AETHER_ICON_PATH: unsupported local package path");
    path_ = normalized;
    directories_ = parents(path_);
    file_.reset(CreateFileW(path_.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL, nullptr));
    require(static_cast<bool>(file_), "AETHER_ICON_INPUT: cannot open stable package metadata");
    identity_ = source_identity(file_.get(), path_, size_);
    if (read) {
        // Reject offline/recall files before requesting payload access. The first
        // handle pins the identity throughout this second open.
        UniqueHandle payload(CreateFileW(path_.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                         FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL, nullptr));
        std::uint64_t length = 0;
        require(payload && source_identity(payload.get(), path_, length) == identity_,
                "AETHER_ICON_INPUT: source changed before read access");
        file_ = std::move(payload);
    }
}
bool IconSource::unchanged() const {
    std::uint64_t size = 0;
    return source_identity(file_.get(), path_, size) == identity_;
}
bool valid_cached_icon(Bytes data) noexcept {
    constexpr std::array<unsigned, 7> sizes{16, 24, 32, 48, 64, 128, 256};
    if (data.size() > icon_limit || number(data, 0, 2) != 0 || number(data, 2, 2) != 1 ||
        number(data, 4, 2) != 7)
        return false;
    std::size_t offset = 6 + 16 * sizes.size();
    for (std::size_t i = 0; i < sizes.size(); ++i) {
        const auto size = sizes[i];
        const auto entry = 6 + i * 16;
        const auto extent = 40 + size * size * 4 + ((size + 31) / 32) * 4 * size;
        if (number(data, entry, 1) != size % 256 || number(data, entry + 1, 1) != size % 256 ||
            number(data, entry + 2, 2) != 0 || number(data, entry + 4, 2) != 1 ||
            number(data, entry + 6, 2) != 32 || number(data, entry + 8) != extent ||
            number(data, entry + 12) != offset || number(data, offset) != 40 ||
            number(data, offset + 4) != size || number(data, offset + 8) != size * 2 ||
            number(data, offset + 12, 2) != 1 || number(data, offset + 14, 2) != 32 ||
            number(data, offset + 16) != 0 || number(data, offset + 20) != size * size * 4 ||
            number(data, offset + 24, 8) != 0 || number(data, offset + 32, 8) != 0)
            return false;
        offset += extent;
    }
    return offset == data.size();
}
IconCache::IconCache(std::filesystem::path root, bool create) : root_(std::move(root)) {
    root_ = std::filesystem::absolute(root_).lexically_normal();
    // The store root is shared with installed apps. Do not change its policy.
    if (create && root_ == icon_cache_root()) {
        auto pinned = parents(root_.parent_path());
        Policy policy(true);
        SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), policy.value, FALSE};
        require(CreateDirectoryW(root_.parent_path().c_str(), &attributes) ||
                    GetLastError() == ERROR_ALREADY_EXISTS,
                "Cannot create Aether data root");
    }
    directories_ = parents(root_);
    if (create) {
        Policy policy(true);
        SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), policy.value, FALSE};
        require(CreateDirectoryW(root_.c_str(), &attributes) || GetLastError() == ERROR_ALREADY_EXISTS,
                "AETHER_ICON_CACHE_ROOT: cannot create final cache directory");
    }
    UniqueHandle root_handle(CreateFileW(root_.c_str(),
                                         FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                         FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    security::verify_runtime_directory(root_handle.get());
    directories_.push_back(std::move(root_handle));
}
CachedIcon IconCache::lookup(const IconDigest &source) const {
    try {
        auto file = open(record_path(root_, source), GENERIC_READ);
        auto result = parse_record(read(file.get(), record_size), source);
        if (result.state == CacheState::retry_later)
            return result.retry_at > now() ? result
                                           : CachedIcon{CacheState::missing, {}, {}, 0, result.attempts};
        result.path = root_ / (icon_hex(result.digest) + L".ico");
        auto artifact = open(result.path, GENERIC_READ);
        const auto bytes = read(artifact.get(), icon_limit);
        require(valid_cached_icon(bytes) && icon_digest(bytes) == result.digest,
                "AETHER_ICON_CACHE_TAMPERED: invalid cached image");
        return result;
    } catch (...) {
        return {};
    }
}
bool IconCache::commit(const IconDigest &source, Bytes icon) {
    require(valid_cached_icon(icon),
            "AETHER_ICON_CACHE_FORMAT: only original seven-size DIB icons are accepted");
    if (writes_since_prune_ >= 32) {
        prune(239ULL * 1024 * 1024); // Headroom for at most 32 bounded direct writes.
        writes_since_prune_ = 0;
    }
    ++writes_since_prune_;
    const auto previous = lookup(source);
    const auto digest = icon_digest(icon);
    const auto path = root_ / (icon_hex(digest) + L".ico");
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        auto file = open(path, GENERIC_WRITE, CREATE_NEW);
        write(file.get(), icon);
    } else {
        auto file = open(path, GENERIC_READ);
        require(icon_digest(read(file.get(), icon_limit)) == digest,
                "AETHER_ICON_CACHE_TAMPERED: existing content-addressed artifact preserved");
    }
    write_record(root_, source, record(source, digest, CacheState::ready, 0, 0));
    return previous.state != CacheState::ready || previous.digest != digest;
}
void IconCache::failure(const IconDigest &source) {
    if (writes_since_prune_ >= 32) {
        prune(239ULL * 1024 * 1024);
        writes_since_prune_ = 0;
    }
    ++writes_since_prune_;
    const auto previous = lookup(source);
    const auto attempts = std::min(6U, previous.attempts + 1);
    const auto seconds = std::min(600ULL, 30ULL << (attempts - 1));
    write_record(root_, source,
                 record(source, {}, CacheState::retry_later, attempts, now() + seconds * 10000000));
}
void IconCache::touch(const IconDigest &source) {
    auto file = open(record_path(root_, source), GENERIC_READ | FILE_WRITE_ATTRIBUTES);
    parse_record(read(file.get(), record_size), source);
    FILETIME time{};
    GetSystemTimeAsFileTime(&time);
    require(SetFileTime(file.get(), nullptr, &time, nullptr) != FALSE, "Cannot touch cache access time");
}
void IconCache::prune(std::uint64_t quota) {
    struct Entry {
        std::filesystem::path path;
        IconDigest source{}, artifact{};
        std::uint64_t accessed = 0;
        bool ready = false;
    };
    struct Image {
        std::filesystem::path path;
        IconDigest digest{};
        std::uint64_t size = 0, accessed = 0;
    };
    std::vector<Entry> entries;
    std::map<std::wstring, unsigned> references;
    std::map<std::wstring, Image> images;
    std::uint64_t total = 0;
    std::size_t visited = 0;
    for (const auto &item : std::filesystem::directory_iterator(root_)) {
        require(++visited <= 8192, "AETHER_ICON_CACHE_QUOTA: too many entries; unknown files preserved");
        WIN32_FILE_ATTRIBUTE_DATA attributes{};
        require(GetFileAttributesExW(item.path().c_str(), GetFileExInfoStandard, &attributes) != FALSE,
                "Cannot inspect cache entry extent");
        if (attributes.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
            continue;
        const auto length = (std::uint64_t(attributes.nFileSizeHigh) << 32) | attributes.nFileSizeLow;
        total += length; // Unknown and incomplete ordinary files consume quota, but are never deleted.
        IconDigest digest{};
        try {
            const auto name = item.path().filename().native();
            auto file = open(item.path(), GENERIC_READ);
            const auto accessed = (std::uint64_t(attributes.ftLastAccessTime.dwHighDateTime) << 32) |
                                  attributes.ftLastAccessTime.dwLowDateTime;
            if (digest_name(name, L".ref", digest)) {
                const auto value = parse_record(read(file.get(), record_size), digest);
                entries.push_back(
                    {item.path(), digest, value.digest, accessed, value.state == CacheState::ready});
                if (value.state == CacheState::ready)
                    ++references[icon_hex(value.digest)];
            } else if (digest_name(name, L".ico", digest) && length <= icon_limit) {
                images.emplace(icon_hex(digest), Image{item.path(), digest, length, accessed});
            }
        } catch (...) {
            // Corrupt, redirected, foreign or incomplete artifacts are not disposable.
        }
    }
    // Unreferenced completed artifacts can remain after interruption or replacement.
    // Their exact hash, raw-DIB format and private ACL must all match before deletion.
    std::vector<Image> orphans;
    for (const auto &[name, value] : images)
        if (!references.contains(name))
            orphans.push_back(value);
    std::sort(orphans.begin(), orphans.end(),
              [](const auto &a, const auto &b) { return a.accessed < b.accessed; });
    for (const auto &value : orphans) {
        if (total <= quota && visited < 8000)
            break;
        remove_file(value.path, icon_limit, &value.digest);
        total -= value.size;
        --visited;
    }
    std::sort(entries.begin(), entries.end(),
              [](const auto &a, const auto &b) { return a.accessed < b.accessed; });
    auto remaining = entries.size();
    for (const auto &entry : entries) {
        if (total <= quota && remaining < 4000 && visited < 8000)
            break;
        // Revalidate the record through the same no-write-sharing handle used to
        // mark it for deletion; never remove an unknown modified record.
        {
            auto file = open(entry.path, GENERIC_READ | DELETE);
            parse_record(read(file.get(), record_size), entry.source);
            FILE_DISPOSITION_INFO remove{TRUE};
            require(SetFileInformationByHandle(file.get(), FileDispositionInfo, &remove, sizeof(remove)) !=
                        FALSE,
                    "AETHER_ICON_CACHE_BUSY: commit remains in use");
        }
        total -= record_size;
        --remaining;
        --visited;
        if (entry.ready) {
            const auto name = icon_hex(entry.artifact);
            if (--references.at(name) == 0) {
                const auto image = images.find(name);
                if (image != images.end()) {
                    remove_file(image->second.path, icon_limit, &entry.artifact);
                    total -= image->second.size;
                    --visited;
                }
            }
        }
    }
    require(total <= quota && remaining < 4000 && visited < 8000,
            "AETHER_ICON_CACHE_QUOTA: bounded cleanup could not make space; unknown files preserved");
}
CacheCleanup IconCache::clear() {
    CacheCleanup result;
    std::vector<UniqueHandle> owned;
    std::size_t visited = 0;
    for (const auto &entry : std::filesystem::directory_iterator(root_)) {
        require(++visited <= 8192,
                "AETHER_ICON_CACHE_QUOTA: cleanup exceeds the entry bound; no files were deleted");
        try {
            IconDigest digest{};
            const auto name = entry.path().filename().native();
            const bool reference = digest_name(name, L".ref", digest);
            require(reference || digest_name(name, L".ico", digest), "Unknown cache entry");
            auto file = open(entry.path(), GENERIC_READ | DELETE);
            if (reference)
                (void)parse_record(read(file.get(), record_size), digest);
            else {
                const auto bytes = read(file.get(), icon_limit);
                require(valid_cached_icon(bytes) && icon_digest(bytes) == digest,
                        "Unknown modified cache artwork");
            }
            owned.push_back(std::move(file));
        } catch (const std::exception &) {
            ++result.preserved;
        }
    }
    for (auto &file : owned) {
        FILE_DISPOSITION_INFO disposition{TRUE};
        require(SetFileInformationByHandle(file.get(), FileDispositionInfo, &disposition,
                                           sizeof(disposition)) != FALSE,
                "AETHER_ICON_CACHE_BUSY: owned cleanup is incomplete; explicitly retry maintenance");
        file.reset();
        ++result.removed;
    }
    return result;
}
} // namespace aether::shell
