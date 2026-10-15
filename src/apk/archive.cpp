#include "aether/apk/archive.hpp"
#include "aether/apk/bytes.hpp"
#include "aether/apk/hash.hpp"
#include "aether/common/text.hpp"
#include <Windows.h>
#include <algorithm>
#include <exception>
#include <miniz.h>
#include <numeric>
#include <set>

namespace aether::apk {
namespace {
[[noreturn]] void invalid(std::string message) {
    throw InspectError("AETHER_ZIP_INVALID", "zip", std::move(message));
}
[[noreturn]] void unsupported(std::string message) {
    throw InspectError("AETHER_ZIP_UNSUPPORTED", "zip", std::move(message));
}
[[noreturn]] void limit(std::string message) {
    throw InspectError("AETHER_APK_LIMIT", "zip", std::move(message));
}
std::wstring path_key(const std::string &name, ArchiveNames names) {
    auto bad = [] {
        throw InspectError("AETHER_ZIP_UNSAFE_PATH", "zip",
                           "Archive contains an unsafe or ambiguous member path");
    };
    if (name.empty() || name.size() > 511 || name.front() == '/' || name.find('\\') != std::string::npos)
        bad();
    std::wstring wide;
    try {
        wide = utf16(name);
    } catch (const std::invalid_argument &) {
        bad();
    }
    for (const unsigned char c : name)
        if (c < 32 || c == 127 || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' ||
            c == '|')
            bad();
    std::size_t start = 0;
    while (start < name.size()) {
        const auto end = name.find('/', start);
        auto part = name.substr(start, end == std::string::npos ? end : end - start);
        if (end == std::string::npos) {
            // APK resource leaves may end in dots (for example res/n/a.).
            // Members are read into memory, never extracted to host paths.
            // Preserve the archive name, but fold leaf dots for collision and
            // file-as-parent checks so a and a. cannot become Windows aliases.
            const auto last = part.find_last_not_of('.');
            if (last == std::string::npos)
                bad();
            wide.resize(wide.size() - (part.size() - last - 1));
            part.resize(last + 1);
        }
        if (part.empty() || part == "." || part == ".." || part.back() == '.' || part.back() == ' ')
            bad();
        auto base = part.substr(0, part.find('.'));
        for (auto &c : base)
            if (c >= 'a' && c <= 'z')
                c = static_cast<char>(c - 'a' + 'A');
        if (base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CONIN$" ||
            base == "CONOUT$" ||
            (base.size() == 4 && (base.starts_with("COM") || base.starts_with("LPT")) && base[3] >= '1' &&
             base[3] <= '9'))
            bad();
        if ((base.starts_with("COM") || base.starts_with("LPT")) &&
            (base.substr(3) == "\xc2\xb9" || base.substr(3) == "\xc2\xb2" || base.substr(3) == "\xc2\xb3"))
            bad();
        if (end == std::string::npos)
            break;
        start = end + 1;
    }
    if (!wide.empty() && wide.back() == L'/')
        wide.pop_back();
    if (names == ArchiveNames::case_sensitive)
        return wide;
    std::wstring key(wide.size(), L'\0');
    if (LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, wide.data(), static_cast<int>(wide.size()),
                      key.data(), static_cast<int>(key.size()), nullptr, nullptr, 0) == 0)
        bad();
    return key;
}
void check_extra(const View &view, std::size_t start, std::size_t size, bool local_padding = false) {
    const auto end = start + size;
    (void)view.slice(start, size);
    while (start < end) {
        if (end - start < 4) {
            // Android zipalign appends zero bytes to the local extra field.
            // Only that zero tail is padding; central fields and nonzero
            // truncated records must still satisfy the ordinary TLV format.
            const auto tail = view.slice(start, end - start);
            if (local_padding && std::all_of(tail.begin(), tail.end(), [](auto byte) { return byte == 0; }))
                return;
            invalid("Truncated ZIP extra field");
        }
        const auto tag = view.u16(start);
        const auto length = view.u16(start + 2);
        if (length > end - start - 4)
            invalid("ZIP extra field extends beyond its header");
        if (tag == 1)
            unsupported("ZIP64 entries are not supported by this inspector");
        start += 4 + length;
    }
}
std::vector<ArchiveEntry> preflight(Bytes bytes, const InspectLimits &limits, ArchiveNames name_policy) {
    if (bytes.size() > limits.archive_bytes)
        limit("Archive size limit exceeded");
    const View view(bytes, "zip");
    if (bytes.size() < 22)
        invalid("ZIP end record is absent");
    std::optional<std::size_t> end_record;
    const std::size_t lower = bytes.size() > 65557 ? bytes.size() - 65557 : 0;
    for (std::size_t at = bytes.size() - 22;; --at) {
        if (view.u32(at) == 0x06054b50 && view.u16(at + 20) == bytes.size() - at - 22) {
            end_record = at;
            break;
        }
        if (at == lower)
            break;
    }
    if (!end_record)
        invalid("ZIP end record or comment length is invalid");
    const auto end = *end_record;
    if (view.u16(end + 4) != 0 || view.u16(end + 6) != 0 || view.u16(end + 8) != view.u16(end + 10))
        unsupported("Multi-disk ZIP is not supported");
    const auto count = view.u16(end + 10);
    const auto central_size = view.u32(end + 12);
    const std::size_t central_start = view.u32(end + 16);
    if (count == 0xffff || central_size == 0xffffffff || central_start == 0xffffffff ||
        (end >= 20 && view.u32(end - 20) == 0x07064b50))
        unsupported("ZIP64 archives are not supported");
    if (count > limits.entry_count || central_size > limits.central_bytes)
        limit("ZIP entry count or directory size limit exceeded");
    if (central_start > end || central_size != end - central_start)
        invalid("ZIP central directory extent is inconsistent");
    std::vector<ArchiveEntry> entries;
    std::set<std::wstring> names;
    std::set<std::wstring> file_names;
    std::vector<std::pair<std::size_t, std::size_t>> ranges;
    std::uint64_t total = 0;
    std::size_t cursor = central_start;
    for (std::uint32_t i = 0; i < count; ++i) {
        if (cursor > end || end - cursor < 46 || view.u32(cursor) != 0x02014b50)
            invalid("Invalid central-directory entry");
        const auto flags = view.u16(cursor + 8);
        const auto method = view.u16(cursor + 10);
        const auto crc = view.u32(cursor + 16);
        const auto compressed = view.u32(cursor + 20);
        const auto expanded = view.u32(cursor + 24);
        const auto name_size = view.u16(cursor + 28);
        const auto extra_size = view.u16(cursor + 30);
        const auto comment_size = view.u16(cursor + 32);
        const auto attrs = view.u32(cursor + 38);
        const std::size_t local = view.u32(cursor + 42);
        const std::size_t record_size = 46ULL + name_size + extra_size + comment_size;
        if (record_size > end - cursor)
            invalid("Central-directory member exceeds directory bounds");
        if (view.u16(cursor + 34) != 0)
            unsupported("Multi-disk member is unsupported");
        if ((flags & ~0x080eU) != 0 || (method != 0 && method != 8))
            unsupported("Encrypted ZIP, unknown flags or compression method");
        if (compressed == 0xffffffff || expanded == 0xffffffff || local == 0xffffffff)
            unsupported("ZIP64 member is unsupported");
        if (expanded > limits.entry_bytes)
            limit("Expanded member size limit exceeded");
        total += expanded;
        if (total > limits.total_bytes)
            limit("Total expanded archive size limit exceeded");
        if (std::uint64_t{expanded} >
            (std::max)(std::uint64_t{compressed}, std::uint64_t{1024}) * limits.ratio)
            limit("Member expansion ratio limit exceeded");
        if (method == 0 && compressed != expanded)
            invalid("Stored member sizes disagree");
        const auto name = view.string(cursor + 46, name_size);
        const auto key = path_key(name, name_policy);
        if (!names.insert(key).second)
            throw InspectError("AETHER_ZIP_DUPLICATE_PATH", "zip",
                               name_policy == ArchiveNames::windows
                                   ? "Duplicate or Windows-colliding member names"
                                   : "Duplicate or trailing-dot-colliding member names");
        const auto type = (attrs >> 16) & 0170000;
        const bool directory = name.back() == '/';
        if (!directory)
            file_names.insert(key);
        if (type != 0 && type != 0100000 && type != 0040000)
            throw InspectError("AETHER_ZIP_UNSAFE_PATH", "zip",
                               "Symlink or special-file ZIP entry is forbidden");
        if ((type == 0040000 && !directory) || (type == 0100000 && directory) || (directory && expanded != 0))
            invalid("Directory metadata is inconsistent");
        check_extra(view, cursor + 46 + name_size, extra_size);
        if (local > central_start || central_start - local < 30 || view.u32(local) != 0x04034b50)
            invalid("Invalid local ZIP header");
        if (view.u16(local + 6) != flags || view.u16(local + 8) != method ||
            view.u16(local + 26) != name_size || view.string(local + 30, name_size) != name)
            invalid("Local and central ZIP headers disagree");
        if ((flags & 8) == 0 && (view.u32(local + 14) != crc || view.u32(local + 18) != compressed ||
                                 view.u32(local + 22) != expanded))
            invalid("Local member size or CRC disagrees");
        const auto local_extra = view.u16(local + 28);
        check_extra(view, local + 30 + name_size, local_extra, true);
        std::size_t member_end = local + 30 + name_size + local_extra;
        if (member_end > central_start || compressed > central_start - member_end)
            invalid("Compressed member exceeds data region");
        const auto data_offset = member_end;
        member_end += compressed;
        if ((flags & 8) != 0) {
            if (central_start - member_end < 12)
                invalid("Missing ZIP data descriptor");
            if (view.u32(member_end) == 0x08074b50)
                member_end += 4;
            if (central_start - member_end < 12 || view.u32(member_end) != crc ||
                view.u32(member_end + 4) != compressed || view.u32(member_end + 8) != expanded)
                invalid("Invalid ZIP data descriptor");
            member_end += 12;
        }
        ranges.emplace_back(local, member_end);
        entries.push_back({name, compressed, expanded, directory, crc, data_offset, method == 0});
        cursor += record_size;
    }
    if (cursor != end)
        invalid("Unexpected data in ZIP central directory");
    for (const auto &name : names) {
        for (auto slash = name.find(L'/'); slash != std::wstring::npos; slash = name.find(L'/', slash + 1)) {
            if (file_names.contains(name.substr(0, slash)))
                throw InspectError("AETHER_ZIP_UNSAFE_PATH", "zip",
                                   "A regular file is also used as a parent directory");
        }
    }
    std::sort(ranges.begin(), ranges.end());
    for (std::size_t i = 0; i < ranges.size(); ++i) {
        if ((i == 0 && ranges[i].first != 0) || (i != 0 && ranges[i].first < ranges[i - 1].second))
            invalid("Overlapping or prefixed ZIP members");
    }
    return entries;
}
} // namespace

struct Archive::Impl {
    mz_zip_archive zip{};
    Bytes bytes;
    bool initialized = false;
    std::vector<ArchiveEntry> entries;
    std::uint64_t buffer_bytes = 0;
    ~Impl() {
        if (initialized)
            mz_zip_reader_end(&zip);
    }
};
Archive::Archive(Bytes bytes, const InspectLimits &limits, ArchiveNames names)
    : impl_(std::make_unique<Impl>()) {
    impl_->entries = preflight(bytes, limits, names);
    impl_->bytes = bytes;
    impl_->buffer_bytes = limits.buffer_bytes;
    if (!mz_zip_reader_init_mem(&impl_->zip, bytes.data(), bytes.size(), 0))
        invalid("ZIP library rejected archive metadata");
    impl_->initialized = true;
    if (mz_zip_reader_get_num_files(&impl_->zip) != impl_->entries.size())
        invalid("ZIP entry count is inconsistent");
}
Archive::~Archive() = default;
const std::vector<ArchiveEntry> &Archive::entries() const { return impl_->entries; }
std::uint64_t Archive::buffer_limit() const { return impl_->buffer_bytes; }
Bytes Archive::stored_view(std::size_t index) const {
    const auto bytes = stored_preview_extent(index);
    const auto &entry = impl_->entries[index];
    mz_ulong crc = MZ_CRC32_INIT;
    for (std::size_t at = 0; at < bytes.size();) {
        const auto chunk = bytes.subspan(at, (std::min)(bytes.size() - at, std::size_t{64 * 1024}));
        crc = mz_crc32(crc, chunk.data(), chunk.size());
        at += chunk.size();
    }
    if (crc != entry.crc32)
        invalid("Stored ZIP member failed CRC validation");
    return bytes;
}
Bytes Archive::stored_preview_extent(std::size_t index) const {
    if (index >= impl_->entries.size())
        invalid("Invalid archive member index");
    const auto &entry = impl_->entries[index];
    if (!entry.stored || entry.directory)
        unsupported("Borrowed ZIP member access requires a stored regular file");
    return impl_->bytes.subspan(static_cast<std::size_t>(entry.data_offset), entry.bytes);
}
std::vector<std::uint8_t> Archive::read(std::size_t index) {
    if (index >= impl_->entries.size())
        invalid("Invalid archive member index");
    const ArchiveRange range{0, impl_->entries[index].bytes};
    auto result = read_ranges(index, std::span(&range, 1));
    return std::move(result.ranges.front());
}
void Archive::stream(std::size_t index, const std::function<void(std::uint64_t, Bytes)> &visitor) {
    if (index >= impl_->entries.size())
        invalid("Invalid archive member index");
    const auto &entry = impl_->entries[index];
    struct Context {
        const std::function<void(std::uint64_t, Bytes)> &visitor;
        std::uint64_t expected, offset = 0;
        mz_ulong crc = MZ_CRC32_INIT;
        std::exception_ptr error;
    } context{visitor, entry.bytes};
    // Never unwind a C++ exception through miniz's C frames. It must release
    // its bounded Deflate dictionary before the original exception propagates.
    const auto callback = [](void *opaque, mz_uint64 offset, const void *data,
                             std::size_t size) noexcept -> std::size_t {
        auto &state = *static_cast<Context *>(opaque);
        try {
            if (offset != state.offset || offset > state.expected || size > state.expected - offset)
                invalid("ZIP stream exceeded its declared member extent");
            const auto bytes = Bytes(static_cast<const std::uint8_t *>(data), size);
            for (std::size_t at = 0; at < size;) {
                const auto chunk = bytes.subspan(at, (std::min)(size - at, std::size_t{64 * 1024}));
                state.crc = mz_crc32(state.crc, chunk.data(), chunk.size());
                state.visitor(state.offset, chunk);
                state.offset += chunk.size();
                at += chunk.size();
            }
            return size;
        } catch (...) {
            state.error = std::current_exception();
            return 0;
        }
    };
    const bool success = mz_zip_reader_extract_to_callback(&impl_->zip, static_cast<mz_uint>(index), callback,
                                                           &context, 0) != 0;
    if (context.error)
        std::rethrow_exception(context.error);
    // Check even empty members: miniz's early empty/directory return skips CRC.
    if (!success || context.offset != entry.bytes || context.crc != entry.crc32)
        invalid("ZIP member failed decompression, size or CRC validation");
}
ArchiveRead Archive::read_ranges(std::size_t index, std::span<const ArchiveRange> ranges,
                                 bool compute_sha256) {
    if (index >= impl_->entries.size())
        invalid("Invalid archive member index");
    if (ranges.size() > 1024)
        limit("Archive read range count limit exceeded");
    const auto size = impl_->entries[index].bytes;
    std::uint64_t retained = 0;
    for (const auto &range : ranges) {
        if (range.offset > size || range.bytes > size - range.offset)
            throw InspectError("AETHER_PARSE_BOUNDS", "zip", "Read range exceeds archive member");
        if (range.bytes > impl_->buffer_bytes - retained)
            limit("Archive read buffer limit exceeded; this consumer requires a bounded in-memory member");
        retained += range.bytes;
    }
    ArchiveRead result;
    for (const auto &range : ranges)
        result.ranges.emplace_back(static_cast<std::size_t>(range.bytes));
    std::vector<std::size_t> order(ranges.size());
    std::iota(order.begin(), order.end(), 0);
    std::sort(order.begin(), order.end(),
              [&](auto a, auto b) { return ranges[a].offset < ranges[b].offset; });
    const auto hash = compute_sha256 ? std::make_unique<Sha256>() : nullptr;
    std::size_t first = 0;
    stream(index, [&](std::uint64_t offset, Bytes chunk) {
        if (hash)
            hash->update(chunk);
        while (first < order.size() && ranges[order[first]].offset + ranges[order[first]].bytes <= offset)
            ++first;
        for (auto at = first; at < order.size(); ++at) {
            const auto i = order[at];
            const auto &range = ranges[i];
            if (range.offset >= offset + chunk.size())
                break;
            const auto begin = (std::max)(offset, range.offset);
            const auto end = (std::min)(offset + chunk.size(), range.offset + range.bytes);
            if (begin < end)
                std::copy_n(chunk.data() + (begin - offset), static_cast<std::size_t>(end - begin),
                            result.ranges[i].data() + (begin - range.offset));
        }
    });
    if (hash)
        result.sha256 = hash->finish();
    return result;
}
} // namespace aether::apk
