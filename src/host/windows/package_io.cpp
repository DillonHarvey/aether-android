#include "aether/apk/hash.hpp"
#include "aether/apk/inspect.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <bcrypt.h>
#include <limits>

namespace aether::apk {
std::vector<std::uint8_t> read_package(const std::filesystem::path &path, const InspectLimits &limits) {
    host::UniqueHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!file)
        throw InspectError("AETHER_APK_READ_FAILED", "apk-read",
                           "Cannot open the requested APK for stable read access");
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(file.get(), &length) || length.QuadPart < 0)
        throw InspectError("AETHER_APK_READ_FAILED", "apk-read", "Cannot determine the package size");
    if (static_cast<std::uint64_t>(length.QuadPart) > limits.archive_bytes)
        throw InspectError("AETHER_APK_LIMIT", "apk-read",
                           "Package exceeds the configured archive size limit");
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(length.QuadPart));
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto request = static_cast<DWORD>((std::min)(bytes.size() - offset, std::size_t{1024 * 1024}));
        DWORD copied = 0;
        if (!ReadFile(file.get(), bytes.data() + offset, request, &copied, nullptr) || copied == 0)
            throw InspectError("AETHER_APK_READ_FAILED", "apk-read", "Package read was incomplete");
        offset += copied;
    }
    return bytes;
}

namespace {
void check(NTSTATUS status) {
    if (status < 0)
        throw InspectError("AETHER_HASH_FAILED", "hash", "Windows hash operation failed");
}
struct HashHandle {
    BCRYPT_HASH_HANDLE value = nullptr;
    bool finished = false;
    explicit HashHandle(BCRYPT_ALG_HANDLE algorithm) {
        check(BCryptCreateHash(algorithm, &value, nullptr, 0, nullptr, 0, 0));
    }
    ~HashHandle() {
        if (value)
            BCryptDestroyHash(value);
    }
    HashHandle(const HashHandle &) = delete;
    HashHandle &operator=(const HashHandle &) = delete;
    void require_open() const {
        if (finished)
            throw InspectError("AETHER_HASH_FAILED", "hash", "Hash was already finalized");
    }
};
void update(HashHandle &context, Bytes bytes) {
    context.require_open();
    for (std::size_t offset = 0; offset < bytes.size();) {
        const auto count = static_cast<ULONG>((std::min)(bytes.size() - offset, std::size_t{1024 * 1024}));
        check(BCryptHashData(context.value, const_cast<PUCHAR>(bytes.data() + offset), count, 0));
        offset += count;
    }
}
std::string finish(HashHandle &context, ULONG digest_size) {
    context.require_open();
    context.finished = true;
    std::array<unsigned char, 32> digest{};
    check(BCryptFinishHash(context.value, digest.data(), digest_size, 0));
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (ULONG i = 0; i < digest_size; ++i) {
        const auto byte = digest[i];
        result += hex[byte >> 4];
        result += hex[byte & 15];
    }
    return result;
}
std::string hash(Bytes bytes, BCRYPT_ALG_HANDLE algorithm, ULONG digest_size) {
    HashHandle context(algorithm);
    update(context, bytes);
    return finish(context, digest_size);
}
} // namespace
struct Sha256::Impl {
    HashHandle context{BCRYPT_SHA256_ALG_HANDLE};
};
Sha256::Sha256() : impl_(std::make_unique<Impl>()) {}
Sha256::~Sha256() = default;
void Sha256::update(Bytes bytes) { apk::update(impl_->context, bytes); }
std::string Sha256::finish() { return apk::finish(impl_->context, 32); }
std::string sha256(Bytes bytes) { return hash(bytes, BCRYPT_SHA256_ALG_HANDLE, 32); }
std::string sha1(Bytes bytes) { return hash(bytes, BCRYPT_SHA1_ALG_HANDLE, 20); }
} // namespace aether::apk
