#include "drawable.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <numbers>

namespace aether::apk {
namespace {
constexpr unsigned side = 512;
struct Point {
    double x = 0, y = 0;
    Point operator+(Point p) const { return {x + p.x, y + p.y}; }
    Point operator-(Point p) const { return {x - p.x, y - p.y}; }
    Point operator*(double a) const { return {x * a, y * a}; }
};
double norm(Point p) { return std::hypot(p.x, p.y); }
struct Matrix {
    double a = 1, b = 0, c = 0, d = 1, x = 0, y = 0;
    Point apply(Point p) const { return {a * p.x + c * p.y + x, b * p.x + d * p.y + y}; }
    Matrix operator*(const Matrix &m) const {
        const auto p = apply({m.x, m.y});
        return {a * m.a + c * m.b, b * m.a + d * m.b, a * m.c + c * m.d, b * m.c + d * m.d, p.x, p.y};
    }
};
struct Contour {
    std::vector<Point> points;
    bool closed = false;
};
using Paths = std::vector<Contour>;
class PathReader {
    std::string_view text_;
    std::size_t at_ = 0, points_ = 0;
    Paths paths_;
    Point current_, start_, control_;
    char previous_ = 0;
    void skip() {
        while (at_ < text_.size() && (text_[at_] == ',' || text_[at_] == ' ' || text_[at_] == '\n' ||
                                      text_[at_] == '\r' || text_[at_] == '\t'))
            ++at_;
    }
    double number() {
        skip();
        if (at_ == text_.size())
            drawable_error("Truncated vector coordinate", "INVALID");
        if (text_[at_] == '+')
            ++at_;
        double n = 0;
        const auto parsed = std::from_chars(text_.data() + at_, text_.data() + text_.size(), n);
        if (parsed.ec != std::errc{} || parsed.ptr == text_.data() + at_ || !std::isfinite(n) ||
            std::abs(n) > 1000000)
            drawable_error("Invalid vector coordinate", "INVALID");
        at_ = static_cast<std::size_t>(parsed.ptr - text_.data());
        return n;
    }
    Point point(bool relative) {
        const auto x = number(), y = number();
        return Point{x, y} + (relative ? current_ : Point{});
    }
    void add(Point p) {
        if (paths_.empty() || paths_.back().closed)
            drawable_error("Vector path must start with moveto", "INVALID");
        if (++points_ > 8192)
            drawable_error("Vector flattened-point quota exceeded", "LIMIT");
        paths_.back().points.push_back(p);
    }
    void cubic(Point a, Point b, Point end) {
        const auto begin = current_;
        for (unsigned n = 1; n <= 48; ++n) {
            const double t = n / 48., u = 1 - t;
            add(begin * (u * u * u) + a * (3 * u * u * t) + b * (3 * u * t * t) + end * (t * t * t));
        }
        control_ = b;
        current_ = end;
    }
    void quadratic(Point a, Point end) {
        const auto begin = current_;
        for (unsigned n = 1; n <= 48; ++n) {
            const double t = n / 48., u = 1 - t;
            add(begin * (u * u) + a * (2 * u * t) + end * (t * t));
        }
        control_ = a;
        current_ = end;
    }
    void arc(bool relative) {
        double rx = std::abs(number()), ry = std::abs(number());
        const double angle = number() * std::numbers::pi / 180.;
        const double large = number(), sweep = number();
        if ((large != 0 && large != 1) || (sweep != 0 && sweep != 1))
            drawable_error("Invalid arc flags", "INVALID");
        const auto end = point(relative), begin = current_;
        if (norm(end - begin) < 1e-12) {
            current_ = end;
            return;
        }
        if (rx == 0 || ry == 0) {
            add(end);
            current_ = end;
            return;
        }
        const double c = std::cos(angle), s = std::sin(angle);
        const auto delta = (begin - end) * .5;
        const double x = c * delta.x + s * delta.y, y = -s * delta.x + c * delta.y;
        const double scale = x * x / (rx * rx) + y * y / (ry * ry);
        if (scale > 1) {
            rx *= std::sqrt(scale);
            ry *= std::sqrt(scale);
        }
        const double ratio = std::max(0., (rx * rx * ry * ry - rx * rx * y * y - ry * ry * x * x) /
                                              (rx * rx * y * y + ry * ry * x * x));
        const double factor = (large == sweep ? -1 : 1) * std::sqrt(ratio);
        const double cx = factor * rx * y / ry, cy = -factor * ry * x / rx;
        const auto center = Point{c * cx - s * cy, s * cx + c * cy} + (begin + end) * .5;
        const double from = std::atan2((y - cy) / ry, (x - cx) / rx);
        double extent = std::atan2((-y - cy) / ry, (-x - cx) / rx) - from;
        if (!sweep && extent > 0)
            extent -= 2 * std::numbers::pi;
        if (sweep && extent < 0)
            extent += 2 * std::numbers::pi;
        const auto steps = static_cast<unsigned>(std::ceil(std::abs(extent) * 24)) + 1;
        for (unsigned n = 1; n <= steps; ++n) {
            const double t = from + extent * n / steps;
            add(center + Point{c * rx * std::cos(t) - s * ry * std::sin(t),
                               s * rx * std::cos(t) + c * ry * std::sin(t)});
        }
        current_ = end;
    }

  public:
    explicit PathReader(std::string_view text) : text_(text) {}
    Paths parse() {
        if (text_.empty() || text_.size() > 65536)
            drawable_error("Vector path data size is outside bounds", "LIMIT");
        char command = 0;
        while (true) {
            skip();
            if (at_ == text_.size())
                break;
            const char next = text_[at_];
            if ((next >= 'A' && next <= 'Z') || (next >= 'a' && next <= 'z')) {
                command = next;
                ++at_;
            } else if (!command)
                drawable_error("Missing vector command", "INVALID");
            const bool relative = command >= 'a' && command <= 'z';
            const char kind = static_cast<char>(relative ? command - 'a' + 'A' : command);
            if (kind == 'M') {
                const auto p = point(relative);
                paths_.push_back({});
                add(p);
                current_ = start_ = p;
                command = relative ? 'l' : 'L';
            } else if (kind == 'L') {
                const auto p = point(relative);
                add(p);
                current_ = p;
            } else if (kind == 'H') {
                current_.x = number() + (relative ? current_.x : 0);
                add(current_);
            } else if (kind == 'V') {
                current_.y = number() + (relative ? current_.y : 0);
                add(current_);
            } else if (kind == 'C') {
                const auto a = point(relative), b = point(relative), end = point(relative);
                cubic(a, b, end);
            } else if (kind == 'S') {
                const auto a = previous_ == 'C' || previous_ == 'S' ? current_ * 2 - control_ : current_;
                const auto b = point(relative), end = point(relative);
                cubic(a, b, end);
            } else if (kind == 'Q') {
                const auto a = point(relative), end = point(relative);
                quadratic(a, end);
            } else if (kind == 'T') {
                const auto a = previous_ == 'Q' || previous_ == 'T' ? current_ * 2 - control_ : current_;
                const auto end = point(relative);
                quadratic(a, end);
            } else if (kind == 'A')
                arc(relative);
            else if (kind == 'Z') {
                if (paths_.empty() || paths_.back().closed)
                    drawable_error("Invalid closepath", "INVALID");
                paths_.back().closed = true;
                current_ = start_;
                command = 0;
            } else
                drawable_error("Unknown vector path command", "INVALID");
            previous_ = kind;
        }
        return std::move(paths_);
    }
};
using Mask = std::vector<std::uint8_t>;
Mask fill(Paths paths, const Matrix &matrix, bool even_odd, std::size_t &budget) {
    std::size_t count = 0;
    for (auto &path : paths)
        for (auto &p : path.points) {
            p = matrix.apply(p);
            ++count;
            if (!std::isfinite(p.x) || !std::isfinite(p.y) || std::abs(p.x) > 1000000 ||
                std::abs(p.y) > 1000000)
                drawable_error("Vector transform exceeds bounds", "LIMIT");
        }
    if (count > (16 * 1024 * 1024 - budget) / side)
        drawable_error("Vector raster work budget exceeded", "LIMIT");
    budget += count * side;
    Mask mask(side * side);
    std::vector<std::pair<double, int>> crossings;
    crossings.reserve(count);
    for (unsigned y = 0; y < side; ++y) {
        crossings.clear();
        const double row = y + .5;
        for (const auto &path : paths) {
            if (path.points.size() < 2)
                continue;
            auto a = path.points.back();
            for (const auto b : path.points) {
                if ((a.y <= row && b.y > row) || (b.y <= row && a.y > row))
                    crossings.emplace_back(a.x + (row - a.y) / (b.y - a.y) * (b.x - a.x), b.y > a.y ? 1 : -1);
                a = b;
            }
        }
        std::sort(crossings.begin(), crossings.end());
        int winding = 0;
        for (std::size_t i = 0; i + 1 < crossings.size(); ++i) {
            winding += crossings[i].second;
            if (!(even_odd ? winding % 2 != 0 : winding != 0))
                continue;
            const auto left =
                static_cast<unsigned>(std::clamp(std::ceil(crossings[i].first - .5), 0., double(side)));
            const auto right =
                static_cast<unsigned>(std::clamp(std::ceil(crossings[i + 1].first - .5), 0., double(side)));
            std::fill(mask.begin() + y * side + left, mask.begin() + y * side + right, 255);
        }
    }
    return mask;
}
void paint(IconBitmap &out, const Mask &mask, const Mask &clip, std::uint32_t color, double opacity) {
    if (opacity < 0 || opacity > 1)
        drawable_error("Vector opacity is outside 0..1", "INVALID");
    const unsigned alpha = static_cast<unsigned>(std::round((color >> 24) * opacity));
    const std::array<unsigned, 3> channels{(color >> 16) & 255, (color >> 8) & 255, color & 255};
    for (std::size_t i = 0; i < mask.size(); ++i)
        if (mask[i] && clip[i]) {
            auto *p = &out.rgba[i * 4];
            const unsigned total = alpha * 255 + p[3] * (255 - alpha);
            for (unsigned c = 0; c < 3; ++c)
                p[c] = static_cast<std::uint8_t>(
                    total ? (channels[c] * alpha * 255 + p[c] * p[3] * (255 - alpha) + total / 2) / total
                          : 0);
            p[3] = static_cast<std::uint8_t>((total + 127) / 255);
        }
}
Paths stroke(const Paths &paths, double width, unsigned cap, unsigned join, double miter) {
    Paths shapes;
    auto polygon = [&](std::vector<Point> p) {
        double area = 0;
        for (std::size_t i = 0; i < p.size(); ++i) {
            const auto a = p[i], b = p[(i + 1) % p.size()];
            area += a.x * b.y - b.x * a.y;
        }
        if (area < 0)
            std::reverse(p.begin(), p.end());
        shapes.push_back({std::move(p), true});
    };
    const auto disc = [&](Point p) {
        std::vector<Point> points;
        for (unsigned i = 0; i < 32; ++i) {
            const double a = 2 * std::numbers::pi * i / 32;
            points.push_back(p + Point{std::cos(a), std::sin(a)} * (width / 2));
        }
        polygon(std::move(points));
    };
    for (const auto &path : paths) {
        const auto count = path.points.size();
        if (count < 2)
            continue;
        std::vector<Point> normals(count), directions(count);
        const auto edges = path.closed ? count : count - 1;
        for (std::size_t i = 0; i < edges; ++i) {
            auto a = path.points[i], b = path.points[(i + 1) % count];
            const auto d = b - a;
            const auto length = norm(d);
            if (length < 1e-12)
                continue;
            directions[i] = d * (1 / length);
            normals[i] = Point{-d.y, d.x} * (width / (2 * length));
            const auto n = normals[i];
            if (!path.closed && cap == 2) {
                if (i == 0)
                    a = a - directions[i] * (width / 2);
                if (i + 1 == edges)
                    b = b + directions[i] * (width / 2);
            }
            polygon({a + n, b + n, b - n, a - n});
        }
        for (std::size_t i = path.closed ? 0 : 1; i < (path.closed ? count : count - 1); ++i) {
            const auto a = normals[(i + edges - 1) % edges], b = normals[i], center = path.points[i];
            if (join == 1) {
                disc(center);
                continue;
            }
            const auto d1 = directions[(i + edges - 1) % edges], d2 = directions[i];
            const double denominator = 1 + d1.x * d2.x + d1.y * d2.y;
            for (double sign : {-1., 1.}) {
                const auto tip =
                    denominator > 1e-9 ? (a + b) * (sign / denominator) : Point{1000000, 1000000};
                if (join == 0 && norm(tip) <= miter * width / 2)
                    polygon({center + a * sign, center + tip, center + b * sign, center});
                else
                    polygon({center + a * sign, center + b * sign, center});
            }
        }
        if (!path.closed && cap == 1) {
            disc(path.points.front());
            disc(path.points.back());
        }
    }
    return shapes;
}
class VectorRenderer {
    const ColorResolver &color_;
    IconBitmap out_{side, side, std::vector<std::uint8_t>(side * side * 4)};
    std::size_t budget_ = 0, nodes_ = 0;
    static double number(const DrawableNode &node, std::string_view name, double value) {
        return drawable_number(drawable_attribute(node, name), value);
    }
    void group(const DrawableNode &node, Matrix matrix, Mask clip, unsigned depth) {
        if (depth > 32)
            drawable_error("Vector group depth exceeds 32", "LIMIT");
        for (const auto &child : node.children) {
            if (++nodes_ > 512)
                drawable_error("Vector node quota exceeded", "LIMIT");
            const auto &name = child.element.name;
            if (name == "group") {
                drawable_attributes(child, {"name", "rotation", "pivotX", "pivotY", "scaleX", "scaleY",
                                            "translateX", "translateY"});
                const double angle = number(child, "rotation", 0) * std::numbers::pi / 180;
                const double px = number(child, "pivotX", 0), py = number(child, "pivotY", 0);
                const double sx = number(child, "scaleX", 1), sy = number(child, "scaleY", 1);
                Matrix local{std::cos(angle) * sx,
                             std::sin(angle) * sx,
                             -std::sin(angle) * sy,
                             std::cos(angle) * sy,
                             0,
                             0};
                const auto shifted = local.apply({-px, -py});
                local.x = shifted.x + px + number(child, "translateX", 0);
                local.y = shifted.y + py + number(child, "translateY", 0);
                group(child, matrix * local, clip, depth + 1);
                continue;
            }
            if (name != "path" && name != "clip-path")
                drawable_error("Unsupported vector element: " + name);
            if (!child.children.empty())
                drawable_error("Nested path/gradient is unsupported");
            if (name == "clip-path")
                drawable_attributes(child, {"name", "pathData", "fillType"});
            else
                drawable_attributes(child,
                                    {"name", "pathData", "fillColor", "fillAlpha", "fillType", "strokeColor",
                                     "strokeAlpha", "strokeWidth", "strokeLineCap", "strokeLineJoin",
                                     "strokeMiterLimit", "trimPathStart", "trimPathEnd", "trimPathOffset"});
            const auto data = drawable_attribute(child, "pathData");
            if (!data || data->type != 3)
                drawable_error("Missing literal vector path data", "INVALID");
            const auto paths = PathReader(data->text).parse();
            const auto fill_type = number(child, "fillType", 0);
            if (fill_type != 0 && fill_type != 1)
                drawable_error("Unsupported vector fill type");
            auto mask = fill(paths, matrix, fill_type == 1, budget_);
            if (name == "clip-path") {
                for (std::size_t i = 0; i < clip.size(); ++i)
                    clip[i] &= mask[i];
                continue;
            }
            if (number(child, "trimPathStart", 0) != 0 || number(child, "trimPathEnd", 1) != 1 ||
                number(child, "trimPathOffset", 0) != 0)
                drawable_error("Trimmed vector paths are unsupported");
            if (const auto color = drawable_attribute(child, "fillColor"))
                paint(out_, mask, clip, color_(*color), number(child, "fillAlpha", 1));
            const auto width = number(child, "strokeWidth", 0);
            if (width < 0)
                drawable_error("Negative stroke width", "INVALID");
            if (const auto color = drawable_attribute(child, "strokeColor"); color && width > 0) {
                const auto cap = number(child, "strokeLineCap", 0), join = number(child, "strokeLineJoin", 0),
                           miter = number(child, "strokeMiterLimit", 4);
                if (cap < 0 || cap > 2 || join < 0 || join > 2 || std::floor(cap) != cap ||
                    std::floor(join) != join || miter < 1)
                    drawable_error("Invalid vector stroke style", "INVALID");
                mask =
                    fill(stroke(paths, width, static_cast<unsigned>(cap), static_cast<unsigned>(join), miter),
                         matrix, false, budget_);
                paint(out_, mask, clip, color_(*color), number(child, "strokeAlpha", 1));
            }
        }
    }

  public:
    explicit VectorRenderer(const ColorResolver &color) : color_(color) {}
    IconBitmap run(const DrawableNode &root) {
        drawable_attributes(root, {"name", "width", "height", "viewportWidth", "viewportHeight", "alpha",
                                   "tint", "tintMode", "autoMirrored"});
        const double width = number(root, "viewportWidth", 0), height = number(root, "viewportHeight", 0);
        if (width <= 0 || height <= 0)
            drawable_error("Vector viewport must be positive", "INVALID");
        group(root, {side / width, 0, 0, side / height, 0, 0}, Mask(side * side, 255), 0);
        const auto alpha = number(root, "alpha", 1);
        if (alpha < 0 || alpha > 1)
            drawable_error("Invalid vector alpha", "INVALID");
        const auto tint = drawable_attribute(root, "tint");
        std::uint32_t color = 0;
        if (tint) {
            if (number(root, "tintMode", 5) != 5)
                drawable_error("Only src-in vector tint is supported");
            color = color_(*tint);
        }
        for (std::size_t i = 0; i < out_.rgba.size(); i += 4) {
            double coverage = alpha;
            if (tint) {
                out_.rgba[i] = static_cast<std::uint8_t>(color >> 16);
                out_.rgba[i + 1] = static_cast<std::uint8_t>(color >> 8);
                out_.rgba[i + 2] = static_cast<std::uint8_t>(color);
                coverage *= (color >> 24) / 255.;
            }
            out_.rgba[i + 3] = static_cast<std::uint8_t>(std::round(out_.rgba[i + 3] * coverage));
        }
        return std::move(out_);
    }
};
} // namespace
IconBitmap render_vector(const DrawableNode &root, const ColorResolver &color) {
    return VectorRenderer(color).run(root);
}
} // namespace aether::apk
