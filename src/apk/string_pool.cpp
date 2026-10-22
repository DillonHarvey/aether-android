#include "aether/apk/string_pool.hpp"
#include "aether/apk/bytes.hpp"
#include "aether/common/text.hpp"

namespace aether::apk {
std::vector<std::string> parse_string_pool(Bytes bytes, std::string_view phase, std::string_view kind,
                                           bool extended_table, std::vector<std::uint32_t> *styled_strings) {
    const auto bad = [&](std::string message) {
        throw InspectError("AETHER_" + std::string(kind) + "_INVALID", std::string(phase),
                           std::move(message));
    };
    const View view(bytes, std::string(phase));
    if (view.size() < 28 || view.u16(2) < 28 || view.u16(2) > view.size() || view.u16(0) != 1 ||
        view.u32(4) != view.size() || (view.u16(2) & 3))
        bad("String-pool header is truncated");
    const auto count = view.u32(8);
    const auto styles = view.u32(12);
    const auto flags = view.u32(16);
    const std::size_t start = view.u32(20);
    const std::size_t style_start = view.u32(24);
    const std::size_t offsets = view.u16(2);
    if (count > (extended_table ? 262144u : 65536u) || styles > count || (flags & ~0x101U) != 0)
        bad("String-pool count or flags are invalid");
    if (styles != 0 && !extended_table)
        throw InspectError("AETHER_" + std::string(kind) + "_UNSUPPORTED", std::string(phase),
                           "Styled strings are unsupported");
    const std::size_t string_end = styles ? style_start : view.size();
    if ((!styles && style_start != 0) || offsets + (std::uint64_t{count} + styles) * 4 > start ||
        start > string_end || string_end > view.size() || (styles && (style_start & 3)))
        bad("Invalid string-pool regions");
    // A string may never borrow its terminator or content from style data.
    const View strings_view(bytes.first(string_end), std::string(phase));
    std::vector<std::string> strings;
    strings.reserve(count);
    std::vector<std::uint32_t> utf16_lengths;
    if (styles)
        utf16_lengths.reserve(count);
    std::size_t decoded_bytes = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::size_t relative = view.u32(offsets + std::size_t{i} * 4);
        if (relative >= string_end - start)
            bad("String offset exceeds its pool");
        std::size_t cursor = start + relative;
        if ((flags & 0x100) != 0) {
            auto length8 = [&]() -> std::uint32_t {
                const auto first = strings_view.u8(cursor++);
                if ((first & 0x80) == 0)
                    return first;
                return (std::uint32_t{first & 0x7fU} << 8) | strings_view.u8(cursor++);
            };
            const auto utf16_size = length8();
            const auto byte_size = length8();
            const auto text = strings_view.string(cursor, byte_size);
            if (strings_view.u8(cursor + byte_size) != 0 || text.find('\0') != std::string::npos)
                bad("Unterminated or embedded-NUL pool string");
            try {
                // AAPT2 can encode supplementary characters as paired three-byte
                // surrogate units (CESU-8). Normalize those pairs to standard UTF-8.
                // Overlong sequences, lone surrogates and invalid scalars still fail.
                std::wstring decoded;
                for (std::size_t at = 0; at < text.size();) {
                    const auto first = static_cast<std::uint8_t>(text[at++]);
                    std::uint32_t scalar = first;
                    unsigned tail = 0;
                    std::uint32_t minimum = 0;
                    if (first >= 0xc2 && first <= 0xdf) {
                        scalar = first & 31u;
                        tail = 1;
                        minimum = 0x80;
                    } else if (first >= 0xe0 && first <= 0xef) {
                        scalar = first & 15u;
                        tail = 2;
                        minimum = 0x800;
                    } else if (first >= 0xf0 && first <= 0xf4) {
                        scalar = first & 7u;
                        tail = 3;
                        minimum = 0x10000;
                    } else if (first >= 0x80)
                        bad("Invalid UTF-8 leading byte");
                    if (tail > text.size() - at)
                        bad("Truncated UTF-8 sequence");
                    for (unsigned n = 0; n < tail; ++n) {
                        const auto next = static_cast<std::uint8_t>(text[at++]);
                        if ((next & 0xc0) != 0x80)
                            bad("Invalid UTF-8 continuation byte");
                        scalar = (scalar << 6) | (next & 63u);
                    }
                    if (scalar < minimum || scalar > 0x10ffff)
                        bad("Invalid UTF-8 scalar");
                    if (scalar <= 0xffff)
                        decoded.push_back(static_cast<wchar_t>(scalar));
                    else {
                        scalar -= 0x10000;
                        decoded.push_back(static_cast<wchar_t>(0xd800 + (scalar >> 10)));
                        decoded.push_back(static_cast<wchar_t>(0xdc00 + (scalar & 1023u)));
                    }
                }
                if (decoded.size() != utf16_size)
                    bad("UTF-8/UTF-16 string lengths disagree");
                strings.push_back(utf8(decoded));
                if (styles)
                    utf16_lengths.push_back(utf16_size);
            } catch (const std::invalid_argument &) {
                bad("Invalid UTF-8 in string pool");
            }
        } else {
            std::uint32_t length = strings_view.u16(cursor);
            cursor += 2;
            if ((length & 0x8000) != 0) {
                length = ((length & 0x7fff) << 16) | strings_view.u16(cursor);
                cursor += 2;
            }
            if (length > 32768)
                bad("String length limit exceeded");
            (void)strings_view.slice(cursor, std::size_t{length} * 2 + 2);
            std::wstring wide;
            wide.reserve(length);
            for (std::uint32_t j = 0; j < length; ++j) {
                const auto ch = strings_view.u16(cursor + std::size_t{j} * 2);
                if (ch == 0)
                    bad("Embedded NUL in UTF-16 pool string");
                wide += static_cast<wchar_t>(ch);
            }
            if (strings_view.u16(cursor + std::size_t{length} * 2) != 0)
                bad("Unterminated UTF-16 pool string");
            try {
                strings.push_back(utf8(wide));
                if (styles)
                    utf16_lengths.push_back(length);
            } catch (const std::invalid_argument &) {
                bad("Invalid UTF-16 in string pool");
            }
        }
        decoded_bytes += strings.back().size();
        if (decoded_bytes > 16 * 1024 * 1024)
            bad("String pool decoded size limit exceeded");
    }
    // Validate every span even if its string is not selected by a resource.
    std::size_t span_work = 0;
    for (std::uint32_t i = 0; i < styles; ++i) {
        const auto relative = view.u32(offsets + (std::size_t(count) + i) * 4);
        if (relative == UINT32_MAX)
            continue;
        if ((relative & 3) || relative >= view.size() - style_start)
            bad("Style offset exceeds its pool");
        bool styled = false;
        for (std::size_t at = style_start + relative;; at += 12) {
            if (++span_work > 262144)
                bad("String style work limit exceeded");
            const auto name = view.u32(at);
            if (name == UINT32_MAX)
                break;
            const auto first = view.u32(at + 4), last = view.u32(at + 8);
            if (name >= count || first > last || last >= utf16_lengths[i])
                bad("Invalid string style name or UTF-16 range");
            styled = true;
        }
        if (styled && styled_strings)
            styled_strings->push_back(i);
    }
    return strings;
}
} // namespace aether::apk
