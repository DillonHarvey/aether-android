#pragma once
#include "aether/apk/artwork.hpp"
#include "aether/apk/resources.hpp"
#include "aether/apk/xml.hpp"

namespace aether::apk {
struct DrawableNode {
    XmlElement element;
    std::vector<DrawableNode> children;
};
using ColorResolver = std::function<std::uint32_t(const XmlValue &)>;
IconBitmap render_vector(const DrawableNode &root, const ColorResolver &color);
IconBitmap render_drawable(const PackageView &package, ResourceTable &resources, const DisplayValue &value,
                           std::string_view container, std::string &source, std::string &entry);
const XmlValue *drawable_attribute(const DrawableNode &node, std::string_view name);
void drawable_attributes(const DrawableNode &node, std::initializer_list<std::string_view> allowed);
double drawable_number(const XmlValue *value, double fallback);
[[noreturn]] void drawable_error(std::string message, std::string_view kind = "UNSUPPORTED");
} // namespace aether::apk
