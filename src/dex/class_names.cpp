#include "class_names.hpp"
#include "aether/dex/image.hpp"
#include <array>

namespace aether::dex {
std::optional<std::string> binary_descriptor(std::u16string_view name) {
    if (name.size() > 1024)
        throw DexError("AETHER_DEX_CLASS_LIMIT", "Reflective class name exceeds 1024 UTF-16 units");
    if (name.empty())
        return {};
    std::size_t dimensions = 0;
    while (dimensions < name.size() && name[dimensions] == u'[')
        ++dimensions;
    if (dimensions > 255 || dimensions == name.size())
        return {};
    std::string result(dimensions, '[');
    auto component = name.substr(dimensions);
    if (dimensions) {
        if (component.size() == 1 &&
            std::u16string_view(u"ZBSCIJFD").find(component[0]) != std::u16string_view::npos) {
            result += static_cast<char>(component[0]);
            return result;
        }
        if (component.size() < 3 || component.front() != u'L' || component.back() != u';')
            return {};
        component = component.substr(1, component.size() - 2);
    }
    result += 'L';
    bool segment = false;
    for (const auto c : component) {
        if (c == u'.') {
            if (!segment)
                return {};
            result += '/';
            segment = false;
        } else {
            if (c <= 0x20 || c == u'/' || c == u'[' || c == u';')
                return {};
            segment = true;
            // Match DEX modified UTF-8, preserving individual UTF-16 units.
            if (c < 0x80)
                result += static_cast<char>(c);
            else if (c < 0x800) {
                result += static_cast<char>(0xc0 | (c >> 6));
                result += static_cast<char>(0x80 | (c & 63));
            } else {
                result += static_cast<char>(0xe0 | (c >> 12));
                result += static_cast<char>(0x80 | ((c >> 6) & 63));
                result += static_cast<char>(0x80 | (c & 63));
            }
        }
    }
    if (!segment)
        return {};
    result += ';';
    return result;
}
std::u16string binary_name(std::string_view descriptor) {
    if (descriptor.size() == 1) {
        static constexpr std::string_view types = "VZBSCIJFD";
        static constexpr std::array<std::u16string_view, 9> names{
            u"void", u"boolean", u"byte", u"short", u"char", u"int", u"long", u"float", u"double"};
        const auto at = types.find(descriptor[0]);
        if (at != std::string_view::npos)
            return std::u16string(names[at]);
    }
    if (descriptor.starts_with('L') && descriptor.ends_with(';'))
        descriptor = descriptor.substr(1, descriptor.size() - 2);
    std::u16string result;
    for (std::size_t n = 0; n < descriptor.size();) {
        const auto first = static_cast<std::uint8_t>(descriptor[n++]);
        std::uint16_t value = first;
        unsigned continuation = 0;
        if ((first & 0xe0) == 0xc0) {
            value = first & 31;
            continuation = 1;
        } else if ((first & 0xf0) == 0xe0) {
            value = first & 15;
            continuation = 2;
        } else if (first >= 0x80 || !first)
            throw DexError("AETHER_DEX_CLASS_NAME", "Invalid modified UTF-8 class identity");
        for (unsigned i = 0; i < continuation; ++i) {
            if (n == descriptor.size() || (static_cast<std::uint8_t>(descriptor[n]) & 0xc0) != 0x80)
                throw DexError("AETHER_DEX_CLASS_NAME", "Truncated modified UTF-8 class identity");
            value =
                static_cast<std::uint16_t>((value << 6) | (static_cast<std::uint8_t>(descriptor[n++]) & 63));
        }
        if ((continuation == 1 && value < 0x80) || (continuation == 2 && value < 0x800))
            throw DexError("AETHER_DEX_CLASS_NAME", "Overlong modified UTF-8 class identity");
        result += value == '/' ? u'.' : static_cast<char16_t>(value);
    }
    return result;
}
} // namespace aether::dex
