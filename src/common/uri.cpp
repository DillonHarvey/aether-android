#include "aether/common/uri.hpp"
#include <span>
#include <vector>

namespace aether::uri {
namespace {
// Original Aether algorithms shared by Android value objects and package
// resolution. Android15 Uri/UriCodec: frameworks/base revision
// 4e43ad12e1b211f15152e9c5b16b0fe88e6b93f3. No source implementation imported.
void bounded(std::u16string_view text) {
    if (text.size() > text_units) throw Error(Error::Kind::limit, "Uri text exceeds 4096 UTF-16 units");
}
int hex(char16_t unit) noexcept {
    if (unit >= u'0' && unit <= u'9') return static_cast<int>(unit - u'0');
    if (unit >= u'a' && unit <= u'f') return static_cast<int>(unit - u'a') + 10;
    if (unit >= u'A' && unit <= u'F') return static_cast<int>(unit - u'A') + 10;
    return -1;
}
void append_utf8(std::u16string &out, std::span<const std::uint8_t> bytes) {
    for (std::size_t at = 0; at < bytes.size();) {
        const auto lead = bytes[at++];
        if (lead < 0x80) { out += static_cast<char16_t>(lead); continue; }
        const unsigned count = lead >= 0xc2 && lead <= 0xdf ? 2u :
                               lead >= 0xe0 && lead <= 0xef ? 3u :
                               lead >= 0xf0 && lead <= 0xf4 ? 4u : 0u;
        if (!count) { out += u'\ufffd'; continue; }
        std::uint32_t point = lead & (count == 2 ? 0x1fu : count == 3 ? 0x0fu : 0x07u);
        unsigned consumed = 1;
        for (; consumed < count && at < bytes.size(); ++consumed) {
            const auto next = bytes[at];
            if (next < 0x80 || next > 0xbf ||
                (consumed == 1 && ((lead == 0xe0 && next < 0xa0) ||
                                   (lead == 0xed && next > 0x9f) ||
                                   (lead == 0xf0 && next < 0x90) ||
                                   (lead == 0xf4 && next > 0x8f)))) break;
            point = (point << 6) | (next & 0x3fu);
            ++at;
        }
        if (consumed != count) out += u'\ufffd';
        else if (point < 0x10000) out += static_cast<char16_t>(point);
        else {
            point -= 0x10000;
            out += static_cast<char16_t>(0xd800u + (point >> 10));
            out += static_cast<char16_t>(0xdc00u + (point & 0x3ffu));
        }
    }
}
std::size_t port_separator(std::u16string_view authority) noexcept {
    for (auto at = authority.size(); at;) {
        const auto unit = authority[--at];
        if (unit == u':') return at;
        if (unit < u'0' || unit > u'9') return authority.npos;
    }
    return authority.npos;
}
} // namespace

std::u16string decode(std::u16string_view encoded) {
    bounded(encoded);
    std::u16string result;
    result.reserve(encoded.size());
    std::vector<std::uint8_t> pending;
    pending.reserve(encoded.size());
    const auto flush = [&] { append_utf8(result, pending); pending.clear(); };
    for (std::size_t at = 0; at < encoded.size();) {
        const auto unit = encoded[at++];
        if (unit != u'%') {
            flush();
            result += unit; // Uri.decode leaves '+' and raw UTF-16 units intact.
            continue;
        }
        std::uint8_t value = 0;
        for (unsigned digit = 0; digit < 2; ++digit) {
            if (at == encoded.size()) {
                flush();
                result += u'\ufffd';
                return result;
            }
            const auto nibble = hex(encoded[at++]);
            if (nibble < 0) {
                flush();
                result += u'\ufffd';
                break;
            }
            value = static_cast<std::uint8_t>(value * 16u + static_cast<unsigned>(nibble));
        }
        // UriCodec still enqueues the partial byte after a non-hex digit. It
        // does not reinterpret the malformed escape as literal percent text.
        pending.push_back(value);
    }
    flush();
    return result;
}
Parsed::Parsed(std::u16string_view text)
    : text(text), colon(text.npos), fragment(text.npos) {
    bounded(text);
    colon = text.find(u':');
    fragment = text.find(u'#', colon == text.npos ? 0 : colon);
}
std::size_t Parsed::start() const noexcept { return colon == text.npos ? 0 : colon + 1; }
bool Parsed::hierarchical() const noexcept {
    return colon == text.npos || (start() < text.size() && text[start()] == u'/');
}
std::optional<Slice> Parsed::authority() const {
    const auto at = start();
    if (text.size() - at < 2 || text[at] != u'/' || text[at + 1] != u'/') return {};
    auto end = text.find_first_of(u"/\\?#", at + 2);
    if (end == text.npos) end = text.size();
    return Slice{at + 2, end};
}
std::optional<Slice> Parsed::part(Part part) const {
    switch (part) {
    case Part::scheme:
        return colon == text.npos ? std::optional<Slice>{} : std::optional<Slice>{Slice{0, colon}};
    case Part::scheme_specific_part:
        return Slice{start(), fragment == text.npos ? text.size() : fragment};
    case Part::fragment:
        return fragment == text.npos ? std::optional<Slice>{} : std::optional<Slice>{Slice{fragment + 1, text.size()}};
    case Part::authority:
        return authority();
    case Part::user_info: {
        const auto auth = authority();
        if (!auth) return {};
        const auto user = uri::user_info(text.substr(auth->first, auth->last - auth->first));
        if (!user) return {};
        return Slice{auth->first + user->first, auth->first + user->last};
    }
    case Part::query: {
        const auto query = text.find(u'?', colon == text.npos ? 0 : colon);
        if (query == text.npos || (fragment != text.npos && fragment < query)) return {};
        return Slice{query + 1, fragment == text.npos ? text.size() : fragment};
    }
    case Part::path: {
        if (!hierarchical()) return {};
        auto first = start();
        if (const auto auth = authority()) first = auth->last;
        auto last = text.find_first_of(u"?#", first);
        if (last == text.npos) last = text.size();
        return Slice{first, last};
    }
    }
    throw Error(Error::Kind::part, "Unsupported encoded Uri component slot");
}
std::optional<Slice> user_info(std::u16string_view encoded_authority) {
    bounded(encoded_authority);
    const auto separator = encoded_authority.rfind(u'@');
    return separator == encoded_authority.npos ? std::optional<Slice>{} : std::optional<Slice>{Slice{0, separator}};
}
std::u16string host(std::u16string_view encoded_authority) {
    bounded(encoded_authority);
    const auto user = encoded_authority.rfind(u'@'), port_at = port_separator(encoded_authority);
    const auto begin = user == encoded_authority.npos ? 0 : user + 1;
    const auto end = port_at == encoded_authority.npos ? encoded_authority.size() : port_at;
    return decode(encoded_authority.substr(begin, end - begin));
}
std::int32_t port(std::u16string_view encoded_authority) {
    bounded(encoded_authority);
    const auto separator = port_separator(encoded_authority);
    if (separator == encoded_authority.npos || separator + 1 == encoded_authority.size()) return -1;
    std::uint32_t value = 0;
    for (auto at = separator + 1; at < encoded_authority.size(); ++at) {
        const auto digit = static_cast<std::uint32_t>(encoded_authority[at] - u'0');
        if (value > (0x7fffffffu - digit) / 10u) return -1;
        value = value * 10u + digit;
    }
    return static_cast<std::int32_t>(value);
}
} // namespace aether::uri
