#include "drawable.hpp"
#include "aether/apk/bytes.hpp"
#include "aether/apk/package.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cmath>
#include <set>
#include <src/webp/decode.h>

namespace aether::apk {
[[noreturn]] void drawable_error(std::string message, std::string_view kind) {
    throw InspectError("AETHER_DRAWABLE_" + std::string(kind), "apk-artwork", std::move(message));
}
const XmlValue *drawable_attribute(const DrawableNode &node, std::string_view name) {
    const auto found =
        node.element.attributes.find({"http://schemas.android.com/apk/res/android", std::string(name)});
    return found == node.element.attributes.end() ? nullptr : &found->second;
}
void drawable_attributes(const DrawableNode &node, std::initializer_list<std::string_view> allowed) {
    if (!node.element.ns.empty())
        drawable_error("Namespaced drawable elements are unsupported");
    for (const auto &[name, value] : node.element.attributes) {
        (void)value;
        if (name.first != "http://schemas.android.com/apk/res/android" ||
            std::find(allowed.begin(), allowed.end(), name.second) == allowed.end())
            drawable_error("Unsupported drawable attribute: " + name.second);
    }
}
double drawable_number(const XmlValue *value, double fallback) {
    if (!value)
        return fallback;
    double result = 0;
    if (value->type == 4)
        result = std::bit_cast<float>(value->data);
    else if (value->type == 0x10 || value->type == 0x11)
        result = static_cast<std::int32_t>(value->data);
    else if (value->type == 3) {
        const auto parsed =
            std::from_chars(value->text.data(), value->text.data() + value->text.size(), result);
        if (parsed.ec != std::errc{} || parsed.ptr != value->text.data() + value->text.size())
            drawable_error("Invalid drawable number", "INVALID");
    } else
        drawable_error("Unsupported drawable number type");
    if (!std::isfinite(result) || std::abs(result) > 1000000)
        drawable_error("Drawable number exceeds finite bounds", "LIMIT");
    return result;
}
namespace {
constexpr unsigned side = 512;
IconBitmap blank() { return {side, side, std::vector<std::uint8_t>(side * side * 4)}; }
std::array<std::uint8_t, 4> rgba(std::uint32_t color) {
    return {static_cast<std::uint8_t>(color >> 16), static_cast<std::uint8_t>(color >> 8),
            static_cast<std::uint8_t>(color), static_cast<std::uint8_t>(color >> 24)};
}
void over(std::uint8_t *destination, const std::uint8_t *source) {
    const unsigned alpha = source[3] * 255u + destination[3] * (255u - source[3]);
    for (unsigned c = 0; c < 3; ++c)
        destination[c] = static_cast<std::uint8_t>(
            alpha ? (source[c] * source[3] * 255u + destination[c] * destination[3] * (255u - source[3]) +
                     alpha / 2) /
                        alpha
                  : 0);
    destination[3] = static_cast<std::uint8_t>((alpha + 127) / 255);
}
void layer(IconBitmap &out, const IconBitmap &in, std::array<double, 4> insets = {}) {
    const double width = side - insets[0] - insets[2], height = side - insets[1] - insets[3];
    if (width <= 0 || height <= 0)
        drawable_error("Inset consumes the drawable", "INVALID");
    for (unsigned y = 0; y < side; ++y)
        for (unsigned x = 0; x < side; ++x) {
            const auto sx = (x + .5 - insets[0]) / width * in.width - .5;
            const auto sy = (y + .5 - insets[1]) / height * in.height - .5;
            if (sx < -.5 || sy < -.5 || sx >= in.width - .5 || sy >= in.height - .5)
                continue;
            // Bilinear interpolation in premultiplied space avoids dark alpha halos.
            const auto ix = static_cast<int>(std::floor(sx)), iy = static_cast<int>(std::floor(sy));
            double sum[4]{};
            for (int by = 0; by < 2; ++by)
                for (int bx = 0; bx < 2; ++bx) {
                    const auto px = std::clamp(ix + bx, 0, static_cast<int>(in.width) - 1);
                    const auto py = std::clamp(iy + by, 0, static_cast<int>(in.height) - 1);
                    const auto p = &in.rgba[(std::size_t(py) * in.width + px) * 4];
                    const double w = (bx ? sx - ix : 1 - sx + ix) * (by ? sy - iy : 1 - sy + iy);
                    for (unsigned c = 0; c < 3; ++c)
                        sum[c] += w * p[c] * p[3];
                    sum[3] += w * p[3];
                }
            std::array<std::uint8_t, 4> pixel{};
            for (unsigned c = 0; c < 3; ++c)
                pixel[c] = static_cast<std::uint8_t>(std::clamp(sum[3] ? sum[c] / sum[3] : 0., 0., 255.));
            pixel[3] = static_cast<std::uint8_t>(std::clamp(std::round(sum[3]), 0., 255.));
            over(&out.rgba[(std::size_t(y) * side + x) * 4], pixel.data());
        }
}
class Renderer {
    const PackageView &package_;
    ResourceTable &resources_;
    std::set<std::string> active_;
    std::size_t read_bytes_ = 0, nodes_ = 0;
    double canvas_dp_ = 48;

  public:
    std::string source, entry;
    Renderer(const PackageView &package, ResourceTable &resources)
        : package_(package), resources_(resources) {}
    double inset(const XmlValue *value) {
        if (!value)
            return 0;
        const auto v = resolve(*value);
        constexpr double radix[]{1. / 256, 1. / 32768, 1. / 8388608, 1. / 2147483648.};
        const auto number = static_cast<std::int32_t>(v.data & 0xffffff00u) * radix[(v.data >> 4) & 3];
        double result;
        if (v.type == 6 && (v.data & 15) <= 1)
            result = number * side;
        else if (v.type == 5 && (v.data & 15) == 1)
            result = number * side / canvas_dp_;
        else if ((v.type == 0x10 || v.type == 0x11) && !v.data)
            result = 0;
        else
            drawable_error("Inset requires a dimension in dp or a fraction");
        if (!std::isfinite(result) || result < 0 || result >= side)
            drawable_error("Invalid drawable inset", "INVALID");
        return result;
    }
    XmlValue resolve(XmlValue value, std::string *container = nullptr) {
        if (value.type == 3 && value.text.starts_with('@')) {
            const auto name = std::string_view(value.text).substr(1);
            std::uint32_t id = 0;
            if (name.starts_with("0x")) {
                const auto parsed = std::from_chars(name.data() + 2, name.data() + name.size(), id, 16);
                if (parsed.ec != std::errc{} || parsed.ptr != name.data() + name.size())
                    drawable_error("Invalid resource ID", "INVALID");
            } else
                id = resources_.identifier(name, "drawable", resources_.package_name());
            if (!id)
                drawable_error("Named drawable resource was not found", "NOT_FOUND");
            value = {1, id, {}};
        }
        if (value.type == 1) {
            const auto &resource = resources_.value(value.data);
            value = {resource.value_type, resource.data, {}};
            if (container)
                *container = resource.container;
            if (value.type == 3)
                value.text = resources_.string_value(resource);
        }
        return value;
    }
    std::uint32_t color(XmlValue value) {
        value = resolve(std::move(value));
        if (value.type >= 0x1c && value.type <= 0x1f)
            return value.data;
        if (value.type == 3 && value.text.starts_with('#')) {
            auto text = std::string_view(value.text).substr(1);
            std::uint32_t number = 0;
            const auto parsed = std::from_chars(text.data(), text.data() + text.size(), number, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
                drawable_error("Invalid color", "INVALID");
            if (text.size() == 6)
                return number | 0xff000000u;
            if (text.size() == 8)
                return number;
            if (text.size() == 3 || text.size() == 4) {
                std::uint32_t expanded = text.size() == 3 ? 0xff000000u : 0;
                for (unsigned c = 0; c < text.size(); ++c)
                    expanded |= ((number >> (c * 4)) & 15u) * 17u << (c * 8);
                return expanded;
            }
        }
        drawable_error("Unsupported color or theme reference");
    }
    IconBitmap paint(XmlValue value, std::string container) {
        value = resolve(std::move(value), &container);
        if ((value.type >= 0x1c && value.type <= 0x1f) || (value.type == 3 && value.text.starts_with('#'))) {
            auto out = blank();
            const auto pixel = rgba(color(value));
            for (std::size_t i = 0; i < out.rgba.size(); i += 4)
                std::copy(pixel.begin(), pixel.end(), out.rgba.begin() + i);
            return out;
        }
        if (value.type != 3 || !value.text.starts_with("res/") || value.text.size() > 511)
            drawable_error("Drawable is not a supported packaged resource");
        const auto identity = container + "!/" + value.text;
        if (active_.size() >= 32)
            drawable_error("Drawable reference depth exceeds 32", "LIMIT");
        if (!active_.insert(identity).second)
            drawable_error("Cyclic drawable reference", "CYCLE");
        struct Pop {
            std::set<std::string> &set;
            const std::string &key;
            ~Pop() { set.erase(key); }
        } pop{active_, identity};
        auto &archive = *package_.part(container).archive;
        const auto &entries = archive.entries();
        const auto found =
            std::find_if(entries.begin(), entries.end(), [&](const auto &e) { return e.path == value.text; });
        if (found == entries.end() || found->directory)
            drawable_error("Declared drawable member is absent", "NOT_FOUND");
        if (found->bytes > 4 * 1024 * 1024 || found->bytes > 8 * 1024 * 1024 - read_bytes_)
            drawable_error("Drawable byte budget exceeded", "LIMIT");
        read_bytes_ += found->bytes;
        const auto bytes = archive.read(static_cast<std::size_t>(found - entries.begin()));
        if (entry.empty())
            entry = container.empty() ? value.text : identity;
        if (value.text.ends_with(".png")) {
            if (source.empty())
                source = "png";
            return decode_icon_png(bytes, true);
        }
        if (value.text.ends_with(".webp")) {
            if (source.empty())
                source = "webp";
            WebPBitstreamFeatures features{};
            if (WebPGetDecoderVersion() != 0x010600)
                drawable_error("Unexpected WebP decoder version", "INVALID");
            if (WebPGetFeatures(bytes.data(), bytes.size(), &features) != VP8_STATUS_OK)
                drawable_error("Invalid WebP header", "INVALID");
            if (features.has_animation)
                drawable_error("Animated WebP icons are unsupported");
            if (features.width <= 0 || features.height <= 0 || features.width > 512 || features.height > 512)
                drawable_error("WebP dimensions exceed 512", "LIMIT");
            const View view(bytes, "webp");
            if (bytes.size() < 12 || view.string(0, 4) != "RIFF" ||
                std::uint64_t(view.u32(4)) + 8 != bytes.size() || view.string(8, 4) != "WEBP")
                drawable_error("Invalid WebP RIFF extent", "INVALID");
            IconBitmap out{static_cast<unsigned>(features.width), static_cast<unsigned>(features.height),
                           std::vector<std::uint8_t>(std::size_t(features.width) * features.height * 4)};
            if (!WebPDecodeRGBAInto(bytes.data(), bytes.size(), out.rgba.data(), out.rgba.size(),
                                    features.width * 4))
                drawable_error("WebP decoding failed", "INVALID");
            return out;
        }
        if (!value.text.ends_with(".xml"))
            drawable_error("Unsupported drawable resource format");
        DrawableNode root;
        std::vector<DrawableNode *> stack;
        std::size_t retained = 0;
        walk_binary_xml(bytes, [&](const XmlElement &element, bool start) {
            if (!start) {
                stack.pop_back();
                return;
            }
            if (++nodes_ > 2048 || stack.size() >= 32)
                drawable_error("Drawable XML node/depth budget exceeded", "LIMIT");
            for (const auto &[key, val] : element.attributes)
                retained += key.first.size() + key.second.size() + val.text.size() + 64;
            if (retained > 1024 * 1024)
                drawable_error("Drawable XML metadata exceeds 1 MiB", "LIMIT");
            DrawableNode *next = &root;
            if (!stack.empty()) {
                stack.back()->children.emplace_back();
                next = &stack.back()->children.back();
            }
            next->element = element;
            stack.push_back(next);
        });
        if (source.empty())
            source = root.element.name;
        return node(root, container);
    }
    IconBitmap child(const DrawableNode &value, const std::string &container) {
        if (const auto ref = drawable_attribute(value, "drawable")) {
            if (!value.children.empty())
                drawable_error("Drawable reference and child are ambiguous", "INVALID");
            return paint(*ref, container);
        }
        if (value.children.size() != 1)
            drawable_error("Expected exactly one drawable child", "INVALID");
        return node(value.children.front(), container);
    }
    IconBitmap node(const DrawableNode &value, const std::string &container) {
        const auto &name = value.element.name;
        if (name == "vector")
            return render_vector(value, [&](const XmlValue &v) { return color(v); });
        if (name == "adaptive-icon") {
            drawable_attributes(value, {});
            const DrawableNode *foreground = nullptr, *background = nullptr;
            for (const auto &v : value.children) {
                drawable_attributes(v, {"drawable"});
                if (v.element.name == "foreground" && !foreground)
                    foreground = &v;
                else if (v.element.name == "background" && !background)
                    background = &v;
                else if (v.element.name != "monochrome")
                    drawable_error("Invalid adaptive icon layers", "INVALID");
            }
            if (!foreground || !background)
                drawable_error("Adaptive icon requires both colored layers", "INVALID");
            auto out = blank();
            // Android's 108dp layer canvas exposes a centered 72dp viewport.
            // The 66dp safe zone survives our rounded-square mask.
            const auto previous_dp = canvas_dp_;
            canvas_dp_ = 108;
            constexpr double margin = -static_cast<double>(side) / 4.0;
            layer(out, child(*background, container), {margin, margin, margin, margin});
            layer(out, child(*foreground, container), {margin, margin, margin, margin});
            canvas_dp_ = previous_dp;
            for (unsigned y = 0; y < side; ++y)
                for (unsigned x = 0; x < side; ++x) {
                    const double dx = std::max(std::abs(x + .5 - side / 2.) - side * .30, 0.);
                    const double dy = std::max(std::abs(y + .5 - side / 2.) - side * .30, 0.);
                    if (dx * dx + dy * dy > side * side * .04)
                        out.rgba[(std::size_t(y) * side + x) * 4 + 3] = 0;
                }
            return out;
        }
        if (name == "bitmap") {
            drawable_attributes(value,
                                {"src", "antialias", "filter", "dither", "gravity", "tileMode", "alpha"});
            if (!value.children.empty())
                drawable_error("BitmapDrawable has children", "INVALID");
            if (const auto mode = drawable_attribute(value, "tileMode");
                mode && drawable_number(mode, -1) != -1)
                drawable_error("Tiled bitmap drawable is unsupported");
            if (const auto gravity = drawable_attribute(value, "gravity");
                gravity && drawable_number(gravity, 119) != 119)
                drawable_error("Non-fill bitmap gravity is unsupported");
            const auto src = drawable_attribute(value, "src");
            if (!src)
                drawable_error("Bitmap source is absent", "INVALID");
            auto out = paint(*src, container);
            const auto alpha = drawable_number(drawable_attribute(value, "alpha"), 1);
            if (alpha < 0 || alpha > 1)
                drawable_error("Invalid bitmap alpha", "INVALID");
            for (std::size_t i = 3; i < out.rgba.size(); i += 4)
                out.rgba[i] = static_cast<std::uint8_t>(std::round(out.rgba[i] * alpha));
            return out;
        }
        if (name == "inset") {
            drawable_attributes(value,
                                {"drawable", "inset", "insetLeft", "insetTop", "insetRight", "insetBottom"});
            const auto all = inset(drawable_attribute(value, "inset"));
            std::array<double, 4> edges{all, all, all, all};
            constexpr std::string_view names[]{"insetLeft", "insetTop", "insetRight", "insetBottom"};
            for (unsigned i = 0; i < 4; ++i)
                if (const auto v = drawable_attribute(value, names[i]))
                    edges[i] = inset(v);
            auto out = blank();
            layer(out, child(value, container), edges);
            return out;
        }
        if (name == "layer-list") {
            drawable_attributes(value, {});
            if (value.children.empty() || value.children.size() > 32)
                drawable_error("Layer count outside 1..32", "LIMIT");
            auto out = blank();
            for (const auto &item : value.children) {
                if (item.element.name != "item")
                    drawable_error("LayerDrawable expects item children", "INVALID");
                drawable_attributes(item, {"drawable", "id", "left", "top", "right", "bottom", "gravity"});
                if (drawable_number(drawable_attribute(item, "gravity"), 119) != 119)
                    drawable_error("Non-fill layer gravity is unsupported");
                layer(out, child(item, container),
                      {inset(drawable_attribute(item, "left")), inset(drawable_attribute(item, "top")),
                       inset(drawable_attribute(item, "right")), inset(drawable_attribute(item, "bottom"))});
            }
            return out;
        }
        drawable_error("Unsupported drawable element: " + name);
    }
};
} // namespace
IconBitmap render_drawable(const PackageView &package, ResourceTable &resources, const DisplayValue &value,
                           std::string_view container, std::string &source, std::string &entry) {
    Renderer renderer(package, resources);
    auto bitmap = renderer.paint({static_cast<std::uint8_t>(value.type), value.reference, value.literal},
                                 std::string(container));
    source = renderer.source.empty() ? "color" : renderer.source;
    entry = renderer.entry;
    return bitmap;
}
} // namespace aether::apk
