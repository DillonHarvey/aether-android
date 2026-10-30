#include "aether/host/windows/document_service.hpp"
#include "aether/common/text.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include <algorithm>
#include <array>
#include <bcrypt.h>
#include <limits>
#include <stdexcept>
#include <type_traits>

namespace aether::host {
namespace {
[[noreturn]] void invalid(const char *message) {
    throw std::runtime_error(std::string("AETHER_DOCUMENT_SOURCE_INVALID: ") + message);
}
[[noreturn]] void unavailable() {
    throw std::runtime_error("AETHER_DOCUMENT_SOURCE_UNAVAILABLE: The selected document cannot be held for read-only access");
}
FileError error(DWORD value) noexcept {
    switch (value) {
    case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND: return FileError::missing;
    case ERROR_ACCESS_DENIED: case ERROR_SHARING_VIOLATION: case ERROR_CANT_ACCESS_FILE: return FileError::denied;
    case ERROR_INVALID_HANDLE: return FileError::bad_descriptor;
    case ERROR_INVALID_PARAMETER: case ERROR_INVALID_NAME: return FileError::invalid;
    default: return FileError::io;
    }
}
bool reserved(std::wstring_view value) noexcept {
    const auto dot = value.find(L'.');
    value = value.substr(0, dot);
    std::array<wchar_t, 8> upper{};
    if (value.size() >= upper.size()) return false;
    for (std::size_t index = 0; index < value.size(); ++index)
        upper[index] = value[index] >= L'a' && value[index] <= L'z' ?
            static_cast<wchar_t>(value[index] - (L'a' - L'A')) : value[index];
    const auto stem = std::wstring_view(upper.data(), value.size());
    if (stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" ||
        stem == L"CONIN$" || stem == L"CONOUT$" || stem == L"CLOCK$") return true;
    return stem.size() == 4 && (stem.starts_with(L"COM") || stem.starts_with(L"LPT")) &&
        ((stem[3] >= L'1' && stem[3] <= L'9') || stem[3] == 0x00b9 || stem[3] == 0x00b2 || stem[3] == 0x00b3);
}
void validate_path(const std::filesystem::path &path) {
    const auto value = path.native();
    auto canonical = path.lexically_normal(); canonical.make_preferred();
    if (value.size() < 4 || value.size() >= MAX_PATH || value != canonical.native() || !path.is_absolute() ||
        value[1] != L':' || value[2] != L'\\' || path.filename().empty() ||
        !((value[0] >= L'A' && value[0] <= L'Z') || (value[0] >= L'a' && value[0] <= L'z')))
        invalid("Only bounded canonical absolute local file paths are supported");
    for (const auto &part : path.relative_path()) {
        const auto leaf = part.native();
        if (leaf.empty() || leaf == L"." || leaf == L".." || leaf.back() == L'.' || leaf.back() == L' ' || reserved(leaf) ||
            leaf.find_first_of(L":<>\"|?*") != leaf.npos || std::any_of(leaf.begin(), leaf.end(), [](wchar_t unit) {
                return unit < 32 || (unit >= 0x7f && unit <= 0x9f);
            })) invalid("Selected document path has an unsupported component");
    }
    if (GetDriveTypeW(path.root_path().c_str()) != DRIVE_FIXED)
        invalid("Selected document must be on a local fixed drive");
}
bool resolved_path(HANDLE file, const std::filesystem::path &expected) {
    std::array<wchar_t, MAX_PATH + 8> value{};
    const auto size = GetFinalPathNameByHandleW(file, value.data(), static_cast<DWORD>(value.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!size || size >= value.size()) return false;
    const auto wanted = L"\\\\?\\" + expected.native();
    return CompareStringOrdinal(value.data(), static_cast<int>(size), wanted.data(), static_cast<int>(wanted.size()), TRUE) == CSTR_EQUAL;
}
UniqueHandle hold_directory(const std::filesystem::path &path) {
    UniqueHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    BY_HANDLE_FILE_INFORMATION info{};
    FILE_STANDARD_INFO standard{};
    if (!file || GetFileType(file.get()) != FILE_TYPE_DISK || !GetFileInformationByHandle(file.get(), &info) ||
        !GetFileInformationByHandleEx(file.get(), FileStandardInfo, &standard, sizeof(standard)) ||
        !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        !standard.Directory || standard.DeletePending || !resolved_path(file.get(), path)) unavailable();
    return file;
}
struct Identity {
    DWORD volume = 0, high = 0, low = 0;
    std::uint64_t size = 0;
};
FileResult identify(HANDLE file, Identity &output) noexcept {
    BY_HANDLE_FILE_INFORMATION info{};
    FILE_STANDARD_INFO standard{};
    if (GetFileType(file) != FILE_TYPE_DISK) return {-1, FileError::denied};
    if (!GetFileInformationByHandle(file, &info) ||
        !GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard))) return {-1, error(GetLastError())};
    if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) || standard.Directory ||
        standard.DeletePending || info.nNumberOfLinks != 1 || standard.NumberOfLinks != 1 || standard.EndOfFile.QuadPart < 0)
        return {-1, FileError::denied};
    const auto size = static_cast<std::uint64_t>(standard.EndOfFile.QuadPart);
    if (size > document_size_limit) return {-1, FileError::quota};
    output = {info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow, size};
    return {0, FileError::none};
}
std::string random_uri() {
    std::array<unsigned char, 16> nonce{};
    if (BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        unavailable();
    constexpr char digits[] = "0123456789abcdef";
    std::string result(document_uri_prefix);
    for (const auto byte : nonce) { result.push_back(digits[byte >> 4]); result.push_back(digits[byte & 15]); }
    return result;
}
struct Lock {
    SRWLOCK &value;
    explicit Lock(SRWLOCK &mutex) noexcept : value(mutex) { AcquireSRWLockExclusive(&value); }
    ~Lock() { ReleaseSRWLockExclusive(&value); }
};
class HeldDocument final : public DocumentService {
    struct Cursor { int descriptor = 0; std::uint64_t position = 0; };
    SRWLOCK mutex_ = SRWLOCK_INIT;
    UniqueHandle file_;
    std::vector<UniqueHandle> ancestors_;
    const DocumentInfo info_;
    const Identity identity_;
    std::array<Cursor, document_stream_limit> streams_{};
    int next_descriptor_ = 3;
    bool revoked_ = false;
    Cursor *find(int descriptor) noexcept {
        if (descriptor < 3) return nullptr;
        for (auto &cursor : streams_) if (cursor.descriptor == descriptor) return &cursor;
        return nullptr;
    }
    FileResult current() const noexcept {
        if (revoked_ || !file_) return {-1, FileError::denied};
        Identity actual;
        const auto result = identify(file_.get(), actual);
        if (result.error != FileError::none) return result;
        if (actual.volume != identity_.volume || actual.high != identity_.high || actual.low != identity_.low || actual.size != identity_.size)
            return {-1, FileError::io};
        return {0, FileError::none};
    }
  public:
    HeldDocument(UniqueHandle file, std::vector<UniqueHandle> ancestors, DocumentInfo info, Identity identity)
        : file_(std::move(file)), ancestors_(std::move(ancestors)), info_(std::move(info)), identity_(identity) {}
    ~HeldDocument() override { revoke_documents(); }
    FileResult describe(std::string_view uri, DocumentInfo &output) noexcept override {
        Lock lock(mutex_);
        if (uri != info_.uri) return {-1, FileError::denied};
        const auto result = current(); if (result.error != FileError::none) return result;
        try {
            DocumentInfo copy = info_;
            static_assert(std::is_nothrow_move_assignable_v<DocumentInfo>);
            output = std::move(copy);
            return {0, FileError::none};
        } catch (...) { return {-1, FileError::io}; }
    }
    FileResult open_document(std::string_view uri) noexcept override {
        Lock lock(mutex_);
        if (uri != info_.uri) return {-1, FileError::denied};
        const auto result = current(); if (result.error != FileError::none) return result;
        for (auto &cursor : streams_) if (!cursor.descriptor) {
            if (next_descriptor_ == std::numeric_limits<int>::max()) return {-1, FileError::descriptor_limit};
            cursor = {next_descriptor_++, 0}; return {cursor.descriptor, FileError::none};
        }
        return {-1, FileError::descriptor_limit};
    }
    FileResult read_document(int descriptor, std::span<std::uint8_t> output) noexcept override {
        Lock lock(mutex_);
        auto *cursor = find(descriptor);
        if (!cursor || revoked_) return {-1, FileError::bad_descriptor};
        const auto result = current(); if (result.error != FileError::none) return result;
        if (cursor->position > info_.size) return {-1, FileError::io};
        const auto count = static_cast<DWORD>(std::min<std::uint64_t>(output.size(), info_.size - cursor->position));
        if (!count) return {0, FileError::none};
        LARGE_INTEGER offset{}; offset.QuadPart = static_cast<LONGLONG>(cursor->position);
        if (!SetFilePointerEx(file_.get(), offset, nullptr, FILE_BEGIN)) return {-1, error(GetLastError())};
        DWORD received = 0;
        if (!ReadFile(file_.get(), output.data(), count, &received, nullptr)) return {-1, error(GetLastError())};
        if (!received || received > count) return {-1, FileError::io};
        cursor->position += received;
        return {received, FileError::none};
    }
    FileResult close_document(int descriptor) noexcept override {
        Lock lock(mutex_);
        auto *cursor = find(descriptor);
        if (!cursor || revoked_) return {-1, FileError::bad_descriptor};
        *cursor = {}; // Consume exactly once; never recycle a descriptor identity.
        return {0, FileError::none};
    }
    void revoke_documents() noexcept override {
        Lock lock(mutex_);
        if (revoked_) return;
        revoked_ = true;
        streams_.fill({});
        file_.reset(); // Close once and clear ownership even if CloseHandle fails; never retry.
        ancestors_.clear();
    }
};
} // namespace

PreparedDocumentSource prepare_document_source(const std::filesystem::path &path, std::string_view canonical_mime) {
    if (!valid_document_mime(canonical_mime)) invalid("Document MIME type must be explicit and canonical");
    validate_path(path);
    DocumentInfo info;
    try { info.display_name = utf8(path.filename().wstring()); }
    catch (const std::invalid_argument &) { invalid("Document display name is not valid Unicode"); }
    if (info.display_name.empty() || info.display_name.size() > 255) invalid("Document display name exceeds its metadata profile");
    info.mime_type = canonical_mime;
    std::vector<UniqueHandle> ancestors;
    ancestors.reserve(path.native().size() / 2);
    auto current = path.root_path();
    ancestors.push_back(hold_directory(current));
    for (const auto &part : path.parent_path().relative_path()) {
        current /= part;
        ancestors.push_back(hold_directory(current));
    }
    UniqueHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!file || !resolved_path(file.get(), path)) unavailable();
    Identity identity;
    const auto result = identify(file.get(), identity);
    if (result.error == FileError::quota)
        throw std::runtime_error("AETHER_DOCUMENT_SOURCE_LIMIT: Selected document exceeds the existing 1 MiB profile");
    if (result.error != FileError::none) unavailable();
    info.size = identity.size;
    info.uri = random_uri();
    if (!valid_document_info(info)) invalid("Document metadata is outside the supported profile");
    auto service = std::make_shared<HeldDocument>(std::move(file), std::move(ancestors), info, identity);
    return {std::move(info), std::move(service)};
}
} // namespace aether::host
