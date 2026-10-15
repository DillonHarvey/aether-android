#include "aether/apk/inspect.hpp"
#include "aether/common/text.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/install/runtime_setup.hpp"
#include "aether/install/store.hpp"
#include <array>
#include <set>

namespace aether::install {
namespace {
void bundle_check(bool ok) {
    if (!ok)
        throw InstallError("AETHER_SETUP_BUNDLE",
                           "This installer has no intact bounded Aether distribution payload");
}
struct Cursor {
    apk::Bytes bytes;
    std::size_t at = 0;
    std::uint64_t number() {
        bundle_check(at <= bytes.size() && bytes.size() - at >= 8);
        std::uint64_t value = 0;
        for (unsigned shift = 0; shift < 64; shift += 8)
            value |= static_cast<std::uint64_t>(bytes[at++]) << shift;
        return value;
    }
    std::string text(std::size_t bound) {
        const auto length = number();
        bundle_check(length <= bound && length <= bytes.size() - at);
        std::string value(reinterpret_cast<const char *>(bytes.data() + at),
                          static_cast<std::size_t>(length));
        at += static_cast<std::size_t>(length);
        return value;
    }
};
} // namespace
RuntimeBundle read_runtime_bundle(const std::filesystem::path &image) {
    host::UniqueHandle file(CreateFileW(image.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                        FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    bundle_check(file && GetFileInformationByHandle(file.get(), &info) && info.nNumberOfLinks == 1 &&
                 !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
                 GetFileSizeEx(file.get(), &size) && size.QuadPart >= 96 &&
                 size.QuadPart <= 512ll * 1024 * 1024);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
    DWORD got = 0;
    bundle_check(ReadFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &got, nullptr) &&
                 got == bytes.size());
    const auto footer = bytes.size() - 96;
    const std::array<std::uint8_t, 16> magic = {'A', 'E', 'T', 'H', 'E', 'R', 'B', 'U',
                                                'N', 'D', 'L', 'E', '1', 0,   0,   0};
    auto actual_magic = magic;
    actual_magic[12] = bytes[footer + 12];
    bundle_check((actual_magic[12] == '1' || actual_magic[12] == '2') &&
                 std::equal(actual_magic.begin(), actual_magic.end(),
                            bytes.begin() + static_cast<std::ptrdiff_t>(footer)));
    Cursor tail{apk::Bytes(bytes).subspan(footer + 16, 16)};
    const auto manifest_at = tail.number(), manifest_size = tail.number();
    bundle_check(manifest_size <= 65536 && manifest_at <= footer && manifest_size == footer - manifest_at);
    const apk::Bytes manifest(bytes.data() + manifest_at, static_cast<std::size_t>(manifest_size));
    bundle_check(apk::sha256(apk::Bytes(bytes).first(footer)) ==
                 std::string(reinterpret_cast<const char *>(bytes.data() + footer + 32), 64));
    Cursor in{manifest};
    RuntimeBundle result;
    if (actual_magic[12] == '2')
        result.compatibility = in.number();
    const auto count = in.number();
    bundle_check(count >= 7 && count <= 96);
    std::set<std::string> names;
    std::uint64_t previous_end = 0;
    for (std::uint64_t n = 0; n < count; ++n) {
        RuntimePayload item;
        item.path = in.text(160);
        const auto offset = in.number(), length = in.number();
        const auto digest = in.text(64);
        bundle_check(names.insert(item.path).second && length && length <= 256ull * 1024 * 1024 &&
                     offset == previous_end && offset <= manifest_at && length <= manifest_at - offset);
        previous_end = offset + length;
        const apk::Bytes data(bytes.data() + offset, static_cast<std::size_t>(length));
        bundle_check(apk::sha256(data) == digest);
        item.bytes.assign(data.begin(), data.end());
        result.files.push_back(std::move(item));
    }
    bundle_check(in.at == manifest.size() && previous_end == manifest_at &&
                 result.files.front().path == "aether-setup.exe");
    return result;
}
} // namespace aether::install
