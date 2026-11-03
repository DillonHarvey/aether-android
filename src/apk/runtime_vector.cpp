#include "aether/apk/runtime_vector.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <limits>
#include <utility>

namespace aether::apk {
namespace {
[[noreturn]] void bad(const char *kind, const char *message) {
    throw InspectError(std::string("AETHER_VECTOR_") + kind, "runtime-vector", message);
}
std::size_t add(std::size_t a, std::size_t b) {
    if (b > SIZE_MAX - a) bad("LIMIT", "Vector storage extent overflows");
    return a + b;
}
std::size_t multiply(std::size_t a, std::size_t b) {
    if (a && b > SIZE_MAX / a) bad("LIMIT", "Vector storage product overflows");
    return a * b;
}
constexpr std::string_view android_namespace = "http://schemas.android.com/apk/res/android";
struct AttributeIdentity { std::uint32_t id; std::string_view name; };
// Canonical public Android API35 attr metadata, independently checked against
// the held SDK35 ARSC and AOSP android15-release public-final.xml. These are
// platform declarations, never app resource IDs or symbolic-name heuristics.
constexpr std::array<AttributeIdentity, 29> attributes{{
    {0x01010003, "name"}, {0x01010159, "width"}, {0x01010155, "height"},
    {0x01010402, "viewportWidth"}, {0x01010403, "viewportHeight"}, {0x0101031f, "alpha"},
    {0x01010121, "tint"}, {0x010103fb, "tintMode"}, {0x010103ea, "autoMirrored"},
    {0x01010326, "rotation"}, {0x010101b5, "pivotX"}, {0x010101b6, "pivotY"},
    {0x01010324, "scaleX"}, {0x01010325, "scaleY"}, {0x0101045a, "translateX"},
    {0x0101045b, "translateY"}, {0x01010405, "pathData"}, {0x01010404, "fillColor"},
    {0x01010406, "strokeColor"}, {0x010104cc, "fillAlpha"}, {0x010104cb, "strokeAlpha"},
    {0x01010407, "strokeWidth"}, {0x0101040d, "strokeMiterLimit"}, {0x0101040b, "strokeLineCap"},
    {0x0101040c, "strokeLineJoin"}, {0x0101051e, "fillType"}, {0x01010408, "trimPathStart"},
    {0x01010409, "trimPathEnd"}, {0x0101040a, "trimPathOffset"},
}};
struct CanonicalAttributeMatch {
    std::string_view name;
    std::uint32_t seen_bit;
};
consteval bool valid_canonical_attributes() {
    if (attributes.empty() || attributes.size() >
        static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::digits)) return false;
    for (std::size_t i = 0; i < attributes.size(); ++i) {
        if ((attributes[i].id & 0xffff0000u) != 0x01010000u || attributes[i].name.empty()) return false;
        for (std::size_t j = 0; j < i; ++j)
            if (attributes[i].id == attributes[j].id || attributes[i].name == attributes[j].name) return false;
    }
    return true;
}
static_assert(valid_canonical_attributes(),
              "Vector canonical SDK attribute identities must be unique and fit their seen mask");
std::optional<CanonicalAttributeMatch> canonical_vector_attribute(
    std::uint32_t resource_id, const std::function<void(std::uint64_t)> &charge_work) {
    for (std::size_t i = 0; i < attributes.size(); ++i) {
        charge_work(1);
        if (resource_id == attributes[i].id)
            return CanonicalAttributeMatch{attributes[i].name, std::uint32_t{1} << i};
    }
    return std::nullopt;
}
class Parser {
    const RuntimeXmlDocument &document_;
    const RuntimeVectorResolver &resolve_;
    const std::function<void(std::uint64_t)> &work_;
    std::size_t limit_, name_at_ = 0, retained_bytes_ = 0;
    RuntimeVector out_;

    static constexpr std::size_t fixed_bytes = sizeof(RuntimeVectorNode);
    void admit(std::size_t dynamic, std::size_t transient = 0) const {
        const auto bytes = add(add(add(sizeof(Parser), fixed_bytes), dynamic), transient);
        if (bytes > limit_) bad("LIMIT", "Vector parsing exceeds admitted aggregate working bytes");
    }
    std::string_view attribute_name(const RuntimeXmlAttribute &attribute,
                                    std::uint32_t *seen = nullptr) const {
        const auto ns = document_.optional_string(attribute.namespace_index);
        const auto name = document_.string(attribute.name_index);
        work_(add(add(ns.size(), name.size()), 1));
        if (ns != android_namespace)
            bad("UNSUPPORTED", "Vector attribute uses an unsupported namespace");
        const auto canonical = canonical_vector_attribute(attribute.resource_id, work_);
        if (!canonical) bad("UNSUPPORTED", "Vector attribute has no supported canonical SDK identity");
        if (seen) {
            if (*seen & canonical->seen_bit) bad("INVALID", "Vector repeats a canonical attribute identity");
            *seen |= canonical->seen_bit;
        }
        return canonical->name;
    }
    RuntimeVectorScalar scalar(const RuntimeXmlAttribute &attribute) const {
        RuntimeVectorScalar value{attribute.type, attribute.data};
        if (value.type == 1 || value.type == 2) {
            if (!resolve_) bad("UNSUPPORTED", "Vector resource/theme scalar has no owning resolver");
            work_(1);
            value = resolve_(value.type, value.data);
            if (value.type == 1 || value.type == 2)
                bad("UNSUPPORTED", "Vector resource/theme scalar remains unresolved");
        }
        return value;
    }
    double number(const RuntimeXmlAttribute &attribute) const {
        const auto value = scalar(attribute);
        double result;
        if (value.type == 4) result = std::bit_cast<float>(value.data);
        else if (value.type == 0x10 || value.type == 0x11)
            result = static_cast<std::int32_t>(value.data);
        else bad("UNSUPPORTED", "Vector numeric attribute is not a float or integer");
        // Android's vector properties are float values. Preserve that precision
        // rather than letting a wider intermediate accept a different geometry.
        const auto narrowed = static_cast<float>(result);
        if (!std::isfinite(narrowed)) bad("INVALID", "Vector numeric attribute is not finite");
        return narrowed;
    }
    double alpha(const RuntimeXmlAttribute &attribute) const {
        const auto result = number(attribute);
        if (result < 0 || result > 1) bad("INVALID", "Vector alpha is outside zero to one");
        return result;
    }
    std::uint8_t choice(const RuntimeXmlAttribute &attribute, std::uint8_t maximum) const {
        const auto value = scalar(attribute);
        if (value.type != 0x10 && value.type != 0x11)
            bad("UNSUPPORTED", "Vector enumeration is not an encoded integer");
        if (value.data > maximum) bad("UNSUPPORTED", "Vector enumeration value is unsupported");
        return static_cast<std::uint8_t>(value.data);
    }
    std::uint32_t color(const RuntimeXmlAttribute &attribute) const {
        const auto value = scalar(attribute);
        if (value.type < 0x1c || value.type > 0x1f)
            bad("UNSUPPORTED", "Vector paint is not a resolved scalar color");
        return value.data;
    }
    std::uint32_t dimension(const RuntimeXmlAttribute &attribute) const {
        const auto value = scalar(attribute);
        if (value.type != 5) bad("UNSUPPORTED", "Vector intrinsic size is not a resolved dimension");
        if ((value.data & 15) > 5)
            bad("UNSUPPORTED", "Vector intrinsic dimension unit is unsupported");
        constexpr double radix[]{1. / 256, 1. / 32768, 1. / 8388608, 1. / 2147483648.};
        const auto amount = static_cast<std::int32_t>(value.data & 0xffffff00u) *
                            radix[(value.data >> 4) & 3];
        if (!std::isfinite(amount) || amount <= 0)
            bad("INVALID", "Vector intrinsic dimensions must be positive");
        return value.data;
    }
    void name(const RuntimeXmlAttribute &attribute, std::size_t &offset, std::size_t &length) {
        if (attribute.type != 3) bad("UNSUPPORTED", "Vector name is not a literal string");
        const auto text = document_.string(attribute.data);
        if (text.size() > out_.names.size() - name_at_)
            bad("INVALID", "Vector name storage does not match the decoded document");
        work_(text.size());
        offset = name_at_;
        length = text.size();
        std::copy(text.begin(), text.end(), out_.names.begin() + name_at_);
        name_at_ += text.size();
    }
    void root(const RuntimeXmlNode &node) {
        bool width = false, height = false, viewport_width = false, viewport_height = false;
        for (const auto &attribute : document_.node_attributes(node)) {
            const auto key = attribute_name(attribute);
            if (key == "width") { out_.width_dimension = dimension(attribute); width = true; }
            else if (key == "height") { out_.height_dimension = dimension(attribute); height = true; }
            else if (key == "viewportWidth") { out_.viewport_width = number(attribute); viewport_width = true; }
            else if (key == "viewportHeight") { out_.viewport_height = number(attribute); viewport_height = true; }
            else if (key == "alpha") out_.alpha = alpha(attribute);
            else if (key == "tint") out_.tint = color(attribute);
            else if (key == "tintMode") {
                const auto value = scalar(attribute);
                if ((value.type != 0x10 && value.type != 0x11) || value.data != 5)
                    bad("UNSUPPORTED", "Only SRC_IN vector tint is represented");
            } else if (key == "autoMirrored") {
                const auto value = scalar(attribute);
                if (value.type != 0x12) bad("UNSUPPORTED", "Vector autoMirrored is not an encoded boolean");
                out_.auto_mirrored = value.data != 0;
            } else if (key == "name") name(attribute, out_.name_offset, out_.name_length);
            else bad("UNSUPPORTED", "Unsupported vector root attribute");
        }
        if (!width || !height || !viewport_width || !viewport_height ||
            out_.viewport_width <= 0 || out_.viewport_height <= 0)
            bad("INVALID", "Vector requires positive intrinsic dimensions and viewport");
    }
    void group(RuntimeVectorNode &result, const RuntimeXmlNode &node) {
        for (const auto &attribute : document_.node_attributes(node)) {
            const auto key = attribute_name(attribute);
            if (key == "name") name(attribute, result.name_offset, result.name_length);
            else if (key == "rotation") result.rotation = number(attribute);
            else if (key == "pivotX") result.pivot_x = number(attribute);
            else if (key == "pivotY") result.pivot_y = number(attribute);
            else if (key == "scaleX") result.scale_x = number(attribute);
            else if (key == "scaleY") result.scale_y = number(attribute);
            else if (key == "translateX") result.translate_x = number(attribute);
            else if (key == "translateY") result.translate_y = number(attribute);
            else bad("UNSUPPORTED", "Unsupported vector group attribute");
        }
    }
    void path(RuntimeVectorNode &result, const RuntimeXmlNode &node) {
        const RuntimeXmlAttribute *data = nullptr;
        for (const auto &attribute : document_.node_attributes(node)) {
            const auto key = attribute_name(attribute);
            if (key == "name") name(attribute, result.name_offset, result.name_length);
            else if (key == "pathData") data = &attribute;
            else if (key == "fillType") result.fill_type = choice(attribute, 1);
            else if (result.kind == RuntimeVectorNodeKind::clip)
                bad("UNSUPPORTED", "Unsupported vector clip attribute");
            else if (key == "fillColor") result.fill_color = color(attribute);
            else if (key == "strokeColor") result.stroke_color = color(attribute);
            else if (key == "fillAlpha") result.fill_alpha = alpha(attribute);
            else if (key == "strokeAlpha") result.stroke_alpha = alpha(attribute);
            else if (key == "strokeWidth") {
                result.stroke_width = number(attribute);
                if (result.stroke_width < 0) bad("INVALID", "Vector stroke width is negative");
            } else if (key == "strokeMiterLimit") {
                result.miter_limit = number(attribute);
                if (result.miter_limit < 0) bad("INVALID", "Vector stroke miter limit is negative");
            } else if (key == "strokeLineCap") result.line_cap = choice(attribute, 2);
            else if (key == "strokeLineJoin") result.line_join = choice(attribute, 2);
            else if (key == "trimPathStart" || key == "trimPathOffset") {
                if (number(attribute) != 0) bad("UNSUPPORTED", "Nondefault vector path trimming is unsupported");
            } else if (key == "trimPathEnd") {
                if (number(attribute) != 1) bad("UNSUPPORTED", "Nondefault vector path trimming is unsupported");
            } else bad("UNSUPPORTED", "Unsupported vector path attribute");
        }
        // Android permits absent/TYPE_NULL data, and typed-attribute retrieval
        // normalizes raw reference-zero @null to TYPE_NULL. All contribute an
        // empty path, not fabricated geometry or a malformed-input claim.
        if (!data || (data->type == 0 && data->data <= 1) ||
            (data->type == 1 && data->data == 0)) return;
        if (data->type != 3)
            bad("UNSUPPORTED", "Vector pathData must be a literal owned XML string");
        admit(retained_bytes_, sizeof(RuntimePath));
        result.path = parse_runtime_path(document_.string(data->data),
                                        limit_ - sizeof(Parser) - fixed_bytes - retained_bytes_ - sizeof(RuntimePath),
                                        work_);
        retained_bytes_ = add(retained_bytes_, result.path.storage_bytes());
        // Android PathParser consumes float[] arguments. Generic path parsing
        // retains doubles; narrow each actual argument at this Android boundary.
        for (auto &command : result.path.commands) {
            work_(1 + command.count);
            for (std::uint8_t i = 0; i < command.count; ++i) {
                if (std::abs(command.arguments[i]) > std::numeric_limits<float>::max())
                    bad("INVALID", "Vector path coordinate exceeds finite float range");
                const auto narrowed = static_cast<float>(command.arguments[i]);
                if (!std::isfinite(narrowed)) bad("INVALID", "Vector path coordinate exceeds finite float range");
                command.arguments[i] = narrowed;
            }
        }
        admit(retained_bytes_);
    }

  public:
    Parser(const RuntimeXmlDocument &document, const RuntimeVectorResolver &resolve,
           std::size_t working_bytes, const std::function<void(std::uint64_t)> &work)
        : document_(document), resolve_(resolve), work_(work), limit_(working_bytes) {}
    RuntimeVector run() {
        if (!work_) bad("INVALID", "Vector parsing requires host-owned work accounting");
        admit(0);
        std::size_t elements = 0, names = 0;
        for (const auto &node : document_.nodes) {
            work_(1);
            if (node.kind != RuntimeXmlNodeKind::element_start) continue;
            elements = add(elements, 1);
            std::uint32_t seen_attributes = 0;
            for (const auto &attribute : document_.node_attributes(node)) {
                const auto key = attribute_name(attribute, &seen_attributes);
                if (key == "name" && attribute.type == 3)
                    names = add(names, document_.string(attribute.data).size());
            }
        }
        if (!elements) bad("INVALID", "Vector XML has no root element");
        // Fixed-count allocation from the actual document avoids old/new growth
        // overlap and arbitrary icon node-count limits.
        admit(add(multiply(elements - 1, sizeof(RuntimeVectorNode)), names));
        out_.nodes.reserve(elements - 1);
        work_(names); // Actual value-initialization writes, separate from name copying.
        out_.names.resize(names);
        retained_bytes_ = add(multiply(out_.nodes.capacity(), sizeof(RuntimeVectorNode)), out_.names.capacity());
        admit(retained_bytes_);
        bool seen = false, closed = false, saw_path = false;
        std::size_t root_xml = runtime_vector_root, current_xml = runtime_vector_root;
        std::size_t current = runtime_vector_root;
        for (std::size_t index = 0; index < document_.nodes.size(); ++index) {
            const auto &node = document_.nodes[index];
            work_(1);
            if (node.kind == RuntimeXmlNodeKind::namespace_start ||
                node.kind == RuntimeXmlNodeKind::namespace_end) continue;
            if (node.kind == RuntimeXmlNodeKind::text)
                bad("UNSUPPORTED", "Vector XML text nodes are unsupported");
            if (node.kind == RuntimeXmlNodeKind::element_end) {
                if (!seen || closed || node.matching != current_xml)
                    bad("INVALID", "Vector XML element ancestry is inconsistent");
                if (current == runtime_vector_root) { closed = true; current_xml = runtime_vector_root; }
                else {
                    current = out_.nodes[current].parent;
                    current_xml = current == runtime_vector_root ? root_xml : out_.nodes[current].xml_node;
                }
                continue;
            }
            if (node.kind != RuntimeXmlNodeKind::element_start)
                bad("UNSUPPORTED", "Unsupported vector XML node kind");
            const auto ns = document_.optional_string(node.namespace_index);
            const auto tag = document_.string(node.name_index);
            work_(add(add(ns.size(), tag.size()), 1));
            if (!ns.empty()) bad("UNSUPPORTED", "Namespaced vector elements are unsupported");
            if (!seen) {
                if (tag != "vector" || node.parent != runtime_xml_absent)
                    bad("UNSUPPORTED", "Drawable XML root is not vector");
                seen = true;
                root_xml = current_xml = index;
                root(node);
                continue;
            }
            if (closed || node.parent != current_xml ||
                (current != runtime_vector_root && out_.nodes[current].kind != RuntimeVectorNodeKind::group))
                bad("INVALID", "Vector children require the current vector or group parent");
            RuntimeVectorNode result;
            result.parent = current;
            result.xml_node = index;
            if (tag == "group") result.kind = RuntimeVectorNodeKind::group;
            else if (tag == "path") { result.kind = RuntimeVectorNodeKind::path; saw_path = true; }
            else if (tag == "clip-path") result.kind = RuntimeVectorNodeKind::clip;
            else bad("UNSUPPORTED", "Unsupported vector element, including gradients or animated nodes");
            out_.nodes.push_back(std::move(result));
            current = out_.nodes.size() - 1;
            current_xml = index;
            if (out_.nodes[current].kind == RuntimeVectorNodeKind::group) group(out_.nodes[current], node);
            else path(out_.nodes[current], node);
        }
        if (!seen || !closed || current != runtime_vector_root || name_at_ != out_.names.size())
            bad("INVALID", "Vector XML/model did not close consistently");
        if (!saw_path) bad("INVALID", "Vector requires at least one path element");
        return std::move(out_);
    }
};
} // namespace
std::size_t RuntimeVector::storage_bytes() const noexcept {
    std::size_t bytes = nodes.capacity() * sizeof(RuntimeVectorNode) + names.capacity();
    for (const auto &node : nodes) bytes += node.path.storage_bytes();
    return bytes;
}
RuntimeVector parse_runtime_vector(const RuntimeXmlDocument &document,
                                  const RuntimeVectorResolver &resolve,
                                  std::size_t working_bytes,
                                  const std::function<void(std::uint64_t)> &charge_work) {
    return Parser(document, resolve, working_bytes, charge_work).run();
}
} // namespace aether::apk
