#include "aether/apk/archive.hpp"
#include "aether/apk/bytes.hpp"
#include "aether/common/text.hpp"
#include <algorithm>
#include <array>
#include <map>

namespace aether::apk {
namespace {
using RangeReader = std::function<std::vector<std::vector<std::uint8_t>>(std::span<const ArchiveRange>)>;
void require_extent(std::uint64_t size, std::uint64_t offset, std::uint64_t bytes) {
    if (offset > size || bytes > size - offset)
        throw InspectError("AETHER_PARSE_BOUNDS", "elf-inspect",
                           "A structure exceeds its containing byte range");
}
bool elf_magic(Bytes bytes) {
    return bytes.size() >= 4 && bytes[0] == 0x7f && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F';
}
NativeInfo inspect_headers(Bytes header, std::uint64_t file_size, std::string abi, const RangeReader &read) {
    auto bad = [](std::string message) {
        throw InspectError("AETHER_ELF_INVALID", "elf-inspect", std::move(message));
    };
    View view(header, "elf-inspect");
    if (header.size() < 52 || !elf_magic(header) || view.u8(5) != 1 || view.u8(6) != 1)
        bad("Expected little-endian ELF");
    const bool wide = view.u8(4) == 2;
    if (!wide && view.u8(4) != 1)
        bad("Invalid ELF class");
    const std::size_t header_size = wide ? 64 : 52;
    (void)view.slice(0, header_size);
    if (view.u16(16) != 3 || view.u32(20) != 1 || view.u16(wide ? 52 : 40) != header_size)
        bad("Expected ELF shared-object header");
    const auto machine = view.u16(18);
    const std::map<std::string, std::pair<std::uint16_t, bool>> machines = {{"arm64-v8a", {183, true}},
                                                                            {"armeabi-v7a", {40, false}},
                                                                            {"x86", {3, false}},
                                                                            {"x86_64", {62, true}}};
    if (const auto it = machines.find(abi);
        it != machines.end() && (it->second.first != machine || it->second.second != wide))
        bad("ELF machine/class disagrees with the APK ABI directory");
    auto word = [&](const View &source, std::size_t offset) -> std::uint64_t {
        return wide ? source.u64(offset) : source.u32(offset);
    };
    const auto phoff = word(view, wide ? 32 : 28);
    const auto phsize = view.u16(wide ? 54 : 42), phcount = view.u16(wide ? 56 : 44);
    if (phsize != (wide ? 56 : 32) || phcount == 0 || phcount > 8192)
        bad("Invalid ELF program-header table");
    const std::array program_range{ArchiveRange{phoff, std::uint64_t{phsize} * phcount}};
    require_extent(file_size, program_range[0].offset, program_range[0].bytes);
    const auto program_bytes = read(program_range);
    const View programs(program_bytes.front(), "elf-inspect");
    struct Segment {
        std::uint64_t offset, address, bytes;
    };
    std::vector<Segment> loads;
    std::optional<Segment> dynamic;
    for (std::uint16_t i = 0; i < phcount; ++i) {
        const auto at = std::size_t{i} * phsize;
        const auto type = programs.u32(at);
        const auto offset = word(programs, at + (wide ? 8 : 4));
        const auto address = word(programs, at + (wide ? 16 : 8));
        const auto size = word(programs, at + (wide ? 32 : 16));
        const auto memory = word(programs, at + (wide ? 40 : 20));
        if (size > memory || address > UINT64_MAX - memory)
            bad("Invalid ELF segment sizes");
        require_extent(file_size, offset, size);
        if (type == 1)
            loads.push_back({offset, address, size});
        if (type == 2) {
            if (dynamic)
                bad("Duplicate ELF dynamic segment");
            dynamic = Segment{offset, address, size};
        }
    }
    if (loads.empty())
        bad("ELF has no loadable segments");
    NativeInfo result;
    result.abi = std::move(abi);
    result.machine = machine;
    result.metadata_status = "headers-and-needed-only";
    if (!dynamic)
        return result;
    const std::size_t entry_size = wide ? 16 : 8;
    if (dynamic->bytes % entry_size != 0 || dynamic->bytes / entry_size > 65536)
        bad("Invalid ELF dynamic table size");
    const std::array dynamic_range{ArchiveRange{dynamic->offset, dynamic->bytes}};
    const auto dynamic_bytes = read(dynamic_range);
    const View table(dynamic_bytes.front(), "elf-inspect");
    std::optional<std::uint64_t> strings_address, strings_size;
    std::vector<std::uint64_t> needed;
    bool terminated = false;
    for (std::size_t at = 0; at < dynamic->bytes; at += entry_size) {
        const auto tag = word(table, at), value = word(table, at + entry_size / 2);
        if (tag == 0) {
            terminated = true;
            break;
        }
        if (tag == 1) {
            if (needed.size() >= 1024)
                bad("ELF dependency count limit exceeded");
            needed.push_back(value);
        }
        if (tag == 5) {
            if (strings_address)
                bad("Duplicate ELF string table address");
            strings_address = value;
        }
        if (tag == 10) {
            if (strings_size)
                bad("Duplicate ELF string table size");
            strings_size = value;
        }
    }
    if (!terminated)
        bad("ELF dynamic table lacks DT_NULL");
    if (!needed.empty()) {
        if (!strings_address || !strings_size)
            bad("ELF DT_NEEDED lacks a string table");
        std::optional<std::uint64_t> file_offset;
        for (const auto &load : loads) {
            if (*strings_address >= load.address && *strings_address - load.address <= load.bytes &&
                *strings_size <= load.bytes - (*strings_address - load.address)) {
                if (file_offset)
                    bad("Ambiguous ELF string-table mapping");
                file_offset = load.offset + (*strings_address - load.address);
            }
        }
        if (!file_offset)
            bad("ELF string table is not in file-backed load memory");
        // Validate the entire table extent, but retain only bounded DT_NEEDED
        // windows. A very large string table never becomes a large allocation.
        require_extent(file_size, *file_offset, *strings_size);
        std::vector<ArchiveRange> string_ranges;
        for (const auto offset : needed) {
            if (offset >= *strings_size)
                bad("DT_NEEDED string offset is invalid");
            string_ranges.push_back(
                {*file_offset + offset, (std::min)(*strings_size - offset, std::uint64_t{4097})});
        }
        const auto names = read(string_ranges);
        for (const auto &bytes : names) {
            const auto end = std::find(bytes.begin(), bytes.end(), 0);
            if (end == bytes.end() || end == bytes.begin())
                bad("Unterminated or empty DT_NEEDED string");
            const std::string name(bytes.begin(), end);
            try {
                (void)utf16(name);
            } catch (const std::invalid_argument &) {
                bad("Invalid UTF-8 dependency name");
            }
            result.dependencies.push_back(name);
        }
    }
    return result;
}
} // namespace
NativeInfo inspect_elf(Bytes bytes, std::string abi) {
    return inspect_headers(bytes.first((std::min)(bytes.size(), std::size_t{64})), bytes.size(),
                           std::move(abi), [&](std::span<const ArchiveRange> ranges) {
                               std::vector<std::vector<std::uint8_t>> result;
                               for (const auto &range : ranges) {
                                   require_extent(bytes.size(), range.offset, range.bytes);
                                   const auto part = bytes.subspan(static_cast<std::size_t>(range.offset),
                                                                   static_cast<std::size_t>(range.bytes));
                                   result.emplace_back(part.begin(), part.end());
                               }
                               return result;
                           });
}
NativeInfo inspect_native_member(Archive &archive, std::size_t index, std::string abi) {
    const auto &entry = archive.entries().at(index);
    NativeInfo result;
    std::string digest;
    // Reuse one bounded decompression for ordinary libraries. The allocation is
    // released before inspecting the next member; larger libraries still retain
    // only their header, program/dynamic tables and bounded dependency windows.
    if (entry.bytes <= (std::min)(archive.buffer_limit(), std::uint64_t{16 * 1024 * 1024})) {
        const auto contents = archive.read(index);
        digest = sha256(contents);
        if (elf_magic(contents))
            result = inspect_elf(contents, abi);
        else
            result.is_elf = false;
    } else {
        const std::array header_range{ArchiveRange{0, (std::min)(entry.bytes, std::uint32_t{64})}};
        const auto header = archive.read_ranges(index, header_range, true);
        digest = header.sha256;
        if (elf_magic(header.ranges.front()))
            result = inspect_headers(header.ranges.front(), entry.bytes, abi,
                                     [&](std::span<const ArchiveRange> ranges) {
                                         return archive.read_ranges(index, ranges).ranges;
                                     });
        else
            result.is_elf = false;
    }
    if (!result.is_elf) {
        // Preserve opaque native-directory data without interpreting nested payloads.
        // The isolated loader still requires a valid ELF for any actual native load.
        result.abi = std::move(abi);
        result.metadata_status = "opaque-non-elf";
    }
    result.file = {entry.path, entry.compressed_bytes, entry.bytes, std::move(digest)};
    return result;
}
} // namespace aether::apk
