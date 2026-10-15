#include "aether/apk/bytes.hpp"
#include <algorithm>
#include <array>
#include <miniz.h>
#include <set>

namespace aether::apk {
DexInfo inspect_dex(Bytes bytes) {
    auto bad = [](std::string message) {
        throw InspectError("AETHER_DEX_INVALID", "dex-inspect", std::move(message));
    };
    View view(bytes, "dex-inspect");
    if (bytes.size() < 112 || view.string(0, 4) != "dex\n" || view.u8(7) != 0)
        bad("Invalid DEX magic or truncated header");
    const auto version = view.string(4, 3);
    if (version != "035" && version != "037" && version != "038" && version != "039" && version != "040")
        throw InspectError(
            "AETHER_DEX_UNSUPPORTED", "dex-inspect",
            "Only standard DEX 035/037/038/039/040 headers are supported; containers/compact DEX are not");
    if (view.u32(32) != bytes.size() || view.u32(36) != 112 || view.u32(40) != 0x12345678)
        bad("DEX size, header or endian tag is invalid");
    if (mz_adler32(MZ_ADLER32_INIT, bytes.data() + 12, bytes.size() - 12) != view.u32(8))
        bad("DEX Adler-32 checksum mismatch");
    constexpr char hex[] = "0123456789abcdef";
    std::string signature;
    for (const auto byte : view.slice(12, 20)) {
        signature += hex[byte >> 4];
        signature += hex[byte & 15];
    }
    if (sha1(bytes.subspan(32)) != signature)
        bad("DEX SHA-1 signature mismatch");
    const auto data_size = view.u32(104), data_offset = view.u32(108);
    if (data_offset < 112 || data_offset % 4 != 0 || data_size != bytes.size() - data_offset)
        bad("Invalid DEX data region");
    (void)view.slice(data_offset, data_size);
    const auto link_size = view.u32(44), link_offset = view.u32(48);
    if ((link_size == 0) != (link_offset == 0))
        bad("Invalid DEX link region");
    if (link_size != 0)
        (void)view.slice(link_offset, link_size);
    constexpr std::array<std::size_t, 6> widths = {4, 4, 12, 8, 8, 32};
    std::vector<std::pair<std::size_t, std::size_t>> tables;
    for (std::size_t i = 0; i < widths.size(); ++i) {
        const auto count = view.u32(56 + i * 8), offset = view.u32(60 + i * 8);
        if ((count == 0) != (offset == 0))
            bad("DEX empty table has a nonzero offset");
        if (count != 0) {
            const auto size = std::size_t{count} * widths[i];
            if (offset < 112 || offset % 4 != 0 || offset > data_offset || size > data_offset - offset)
                bad("DEX identifier table lies outside its region");
            (void)view.slice(offset, size);
            tables.emplace_back(offset, offset + size);
        }
    }
    std::sort(tables.begin(), tables.end());
    for (std::size_t i = 1; i < tables.size(); ++i)
        if (tables[i].first < tables[i - 1].second)
            bad("Overlapping DEX tables");
    const auto map_offset = view.u32(52);
    if (map_offset < data_offset || map_offset % 4 != 0)
        bad("DEX map is missing or misaligned");
    const auto map_count = view.u32(map_offset);
    if (map_count == 0 || map_count > 4096)
        bad("Invalid DEX map item count");
    (void)view.slice(std::size_t{map_offset} + 4, std::size_t{map_count} * 12);
    std::set<std::uint16_t> map_types;
    std::uint32_t previous = 0;
    for (std::uint32_t i = 0; i < map_count; ++i) {
        const std::size_t at = std::size_t{map_offset} + 4 + std::size_t{i} * 12;
        const auto type = view.u16(at);
        const auto count = view.u32(at + 4), offset = view.u32(at + 8);
        if (view.u16(at + 2) != 0 || count == 0 || offset >= bytes.size() || (i != 0 && offset <= previous) ||
            !map_types.insert(type).second)
            bad("Invalid or overlapping DEX map item");
        if (type == 0 && (count != 1 || offset != 0))
            bad("Invalid DEX header map entry");
        if (type >= 1 && type <= 6 &&
            (count != view.u32(56 + std::size_t{type - 1U} * 8) ||
             offset != view.u32(60 + std::size_t{type - 1U} * 8)))
            bad("DEX map disagrees with identifier table header");
        if (type == 0x1000 && (count != 1 || offset != map_offset))
            bad("DEX map self-reference is invalid");
        previous = offset;
    }
    if (!map_types.contains(0) || !map_types.contains(0x1000))
        bad("DEX map lacks required header or map item");
    for (std::uint16_t type = 1; type <= 6; ++type)
        if (view.u32(56 + std::size_t{type - 1U} * 8) != 0 && !map_types.contains(type))
            bad("DEX map omits an identifier table");
    DexInfo result;
    result.version = version;
    result.strings = view.u32(56);
    result.methods = view.u32(88);
    result.classes = view.u32(96);
    return result;
}
} // namespace aether::apk
