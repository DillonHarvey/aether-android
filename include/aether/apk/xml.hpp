#pragma once
#include "aether/apk/inspect.hpp"
#include <functional>
#include <map>

namespace aether::apk {
struct XmlValue {
    std::uint8_t type;
    std::uint32_t data;
    std::string text;
};
using XmlAttributes = std::map<std::pair<std::string, std::string>, XmlValue>;
struct XmlElement {
    std::string ns, name;
    XmlAttributes attributes;
};
// Shared streaming AXML validation. Elements/attributes are borrowed only for
// the callback; no unbounded retained XML tree is built by the parser.
void walk_binary_xml(Bytes bytes, const std::function<void(const XmlElement &, bool start)> &visitor);
} // namespace aether::apk
