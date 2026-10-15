#include "aether/apk/xml.hpp"
#include "aether/apk/bytes.hpp"
#include "aether/apk/string_pool.hpp"
#include <algorithm>

namespace aether::apk {
namespace {
[[noreturn]] void bad(std::string message) {
    throw InspectError("AETHER_AXML_INVALID", "binary-xml", std::move(message));
}
} // namespace
void walk_binary_xml(Bytes bytes, const std::function<void(const XmlElement &, bool)> &visitor) {
    constexpr auto absent = 0xffffffffu;
    if (bytes.size() > 8 * 1024 * 1024)
        bad("Binary XML exceeds 8 MiB limit");
    View document(bytes, "binary-xml");
    if (bytes.size() < 8 || document.u16(0) != 3)
        throw InspectError("AETHER_AXML_UNSUPPORTED", "binary-xml", "Expected Android binary XML");
    if (document.u16(2) != 8 || document.u32(4) != bytes.size())
        bad("AXML document header/length is invalid");
    std::vector<std::string> strings;
    bool have_pool = false, have_root = false, have_resource_map = false, root_closed = false;
    std::vector<std::pair<std::string, std::string>> stack;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> namespaces;
    std::vector<std::size_t> depths;
    std::size_t nodes = 0;
    const auto str = [&](std::uint32_t index, bool optional = false) -> std::string {
        if (index == absent && optional)
            return {};
        if (index >= strings.size())
            bad("String reference is out of bounds");
        return strings[index];
    };
    const auto namespace_valid = [&](const std::string &ns) {
        return ns.empty() || std::any_of(namespaces.begin(), namespaces.end(),
                                         [&](const auto &n) { return str(n.second) == ns; });
    };
    for (std::size_t offset = 8; offset < bytes.size();) {
        if (++nodes > 65536)
            bad("Binary XML node count limit exceeded");
        const auto type = document.u16(offset), header = document.u16(offset + 2);
        const auto size = document.u32(offset + 4);
        if (header < 8 || size < header || (size & 3))
            bad("Invalid AXML chunk size");
        const auto chunk = document.slice(offset, size);
        View view(chunk, "axml-chunk");
        if (type == 1) {
            if (have_pool || have_root)
                bad("Repeated or misplaced string pool");
            strings = parse_string_pool(chunk, "binary-xml", "AXML");
            have_pool = true;
        } else {
            if (!have_pool)
                bad("XML node precedes string pool");
            if (type == 0x180) {
                if (have_root || have_resource_map || header != 8 || (size - 8) / 4 > strings.size())
                    bad("Invalid AXML resource map");
                have_resource_map = true;
            } else if (type == 0x100 || type == 0x101) {
                if (header != 16 || size != 24)
                    bad("Invalid namespace node");
                const auto pair = std::pair{view.u32(16), view.u32(20)};
                (void)str(pair.first);
                (void)str(pair.second);
                if (type == 0x100) {
                    if (namespaces.size() >= 128 || root_closed)
                        bad("Invalid namespace nesting");
                    namespaces.push_back(pair);
                    depths.push_back(stack.size());
                } else {
                    if (namespaces.empty() || namespaces.back() != pair || depths.back() != stack.size())
                        bad("Unbalanced namespace nodes");
                    namespaces.pop_back();
                    depths.pop_back();
                }
            } else if (type == 0x102) {
                if (header != 16 || size < 36 || stack.size() >= 128 || root_closed)
                    bad("Invalid start-element node");
                XmlElement element{str(view.u32(16), true), str(view.u32(20)), {}};
                if (!namespace_valid(element.ns))
                    bad("Element uses an undeclared namespace");
                const auto start = view.u16(24), width = view.u16(26), count = view.u16(28);
                if (start < 20 || width != 20 || count > 256 ||
                    16ull + start + std::uint64_t(count) * width > size)
                    bad("Invalid attribute region");
                for (auto special : {view.u16(30), view.u16(32), view.u16(34)})
                    if (special > count)
                        bad("Invalid special attribute index");
                std::size_t retained = element.ns.size() + element.name.size();
                for (std::uint16_t i = 0; i < count; ++i) {
                    const auto at = 16ull + start + std::size_t(i) * width;
                    const auto key = std::pair{str(view.u32(at), true), str(view.u32(at + 4))};
                    if (!namespace_valid(key.first))
                        bad("Attribute uses an undeclared namespace");
                    if (view.u32(at + 8) != absent)
                        (void)str(view.u32(at + 8));
                    if (view.u16(at + 12) != 8 || view.u8(at + 14))
                        bad("Malformed typed attribute value");
                    XmlValue value{view.u8(at + 15), view.u32(at + 16), {}};
                    if (value.type == 3)
                        value.text = str(value.data);
                    retained += key.first.size() + key.second.size() + value.text.size();
                    if (retained > 4 * 1024 * 1024)
                        bad("XML element metadata exceeds 4 MiB");
                    if (!element.attributes.emplace(key, std::move(value)).second)
                        bad("Duplicate XML attribute");
                }
                have_root = true;
                stack.emplace_back(element.ns, element.name);
                visitor(element, true);
            } else if (type == 0x103) {
                if (header != 16 || size != 24 || stack.empty())
                    bad("Invalid end-element node");
                XmlElement element{str(view.u32(16), true), str(view.u32(20)), {}};
                if (stack.back() != std::pair{element.ns, element.name})
                    bad("Mismatched element close");
                visitor(element, false);
                stack.pop_back();
                if (stack.empty())
                    root_closed = true;
            } else
                throw InspectError("AETHER_AXML_UNSUPPORTED", "binary-xml",
                                   "Unsupported binary XML node type");
        }
        offset += size;
    }
    if (!have_root || !root_closed || !stack.empty() || !namespaces.empty())
        bad("Incomplete or unbalanced binary XML");
}
} // namespace aether::apk
