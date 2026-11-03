#include "aether/android/software_canvas.hpp"
#include <algorithm>
#include <cmath>
#include <limits>
#include <optional>
#include <stdexcept>
#include <utility>

namespace aether::android {
namespace {
void validate_canvas_premultiplied_pixel(const CanvasPixel &pixel) {
    const auto alpha = pixel[3];
    if (pixel[0] > alpha || pixel[1] > alpha || pixel[2] > alpha)
        throw std::runtime_error("AETHER_CANVAS_BUFFER: pixel is not premultiplied RGBA8");
}
void validate_canvas_sampling(CanvasSampling sampling) {
    if (sampling != CanvasSampling::nearest && sampling != CanvasSampling::linear)
        throw std::runtime_error("AETHER_CANVAS_BUFFER: bitmap sampling mode is invalid");
}
void require_work(CanvasWork work) {
    if (!work.charge)
        throw std::runtime_error("AETHER_CANVAS_WORK: raster processing requires its existing work owner");
}
std::size_t checked_canvas_extent(std::uint32_t width, std::uint32_t height,
                                  std::size_t stride, std::size_t available_bytes) {
    if (!width || !height)
        throw std::runtime_error("AETHER_CANVAS_BUFFER: bitmap dimensions must be nonzero");
    constexpr auto maximum = std::numeric_limits<std::size_t>::max();
    if (static_cast<std::uintmax_t>(width) > static_cast<std::uintmax_t>(maximum / 4u))
        throw std::runtime_error("AETHER_CANVAS_LIMIT: bitmap row extent is not representable");
    const auto row_bytes = static_cast<std::size_t>(width) * 4u;
    if (stride < row_bytes)
        throw std::runtime_error("AETHER_CANVAS_BUFFER: bitmap stride is smaller than its pixel row");
    const auto rows = static_cast<std::uintmax_t>(height) - 1u;
    if (rows > static_cast<std::uintmax_t>((maximum - row_bytes) / stride))
        throw std::runtime_error("AETHER_CANVAS_LIMIT: bitmap storage extent is not representable");
    const auto extent = static_cast<std::size_t>(rows) * stride + row_bytes;
    if (extent > available_bytes)
        throw std::runtime_error("AETHER_CANVAS_LIMIT: bitmap storage exceeds its admitted byte allowance");
    return extent;
}
std::size_t checked_canvas_storage(std::size_t payload_bytes, std::size_t metadata_bytes,
                                   std::size_t available_bytes) {
    // All old/live owners remain charged outside this new owner's remainder.
    if (metadata_bytes > available_bytes || payload_bytes > available_bytes - metadata_bytes)
        throw std::runtime_error("AETHER_CANVAS_LIMIT: Canvas storage exceeds admitted working bytes");
    return metadata_bytes + payload_bytes;
}
bool canvas_buffers_overlap(std::span<const std::uint8_t> source,
                            std::span<const std::uint8_t> target) noexcept {
    if (source.empty() || target.empty()) return false;
    const auto source_begin = reinterpret_cast<std::uintptr_t>(source.data());
    const auto target_begin = reinterpret_cast<std::uintptr_t>(target.data());
    if (source_begin <= target_begin) return target_begin - source_begin < source.size();
    return source_begin - target_begin < target.size();
}
std::optional<CanvasClip> classify_canvas_draw_bounds(CanvasRectF rectangle,
                                                       const CanvasClip &clip) noexcept {
    const float width = rectangle.right - rectangle.left, height = rectangle.bottom - rectangle.top;
    if (!std::isfinite(rectangle.left) || !std::isfinite(rectangle.top) ||
        !std::isfinite(rectangle.right) || !std::isfinite(rectangle.bottom) ||
        !std::isfinite(width) || !std::isfinite(height) || width <= 0 || height <= 0 ||
        clip.left >= clip.right || clip.top >= clip.bottom)
        return {};
    const auto edge = [](float value, std::int32_t low, std::int32_t high) noexcept {
        const double rounded = std::floor(static_cast<double>(value) + 0.5);
        return static_cast<std::int32_t>(std::clamp(rounded, static_cast<double>(low), static_cast<double>(high)));
    };
    CanvasClip result{edge(rectangle.left, clip.left, clip.right), edge(rectangle.top, clip.top, clip.bottom),
                      edge(rectangle.right, clip.left, clip.right), edge(rectangle.bottom, clip.top, clip.bottom)};
    if (result.left >= result.right || result.top >= result.bottom) return {};
    return result;
}
CanvasPixel load_canvas_pixel(const CanvasBitmapView &view, std::uint32_t x, std::uint32_t y) {
    // Extent/stride and bounded sample coordinates are proved before this call.
    const auto at = std::size_t(y) * view.stride + std::size_t(x) * 4;
    const auto bytes = view.premultiplied_rgba;
    const CanvasPixel result{bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]};
    validate_canvas_premultiplied_pixel(result);
    return result;
}
// Coordinates use source pixel-center indices: the first pixel's center is 0.
CanvasPixel sample_nearest(const CanvasBitmapView &view, double x, double y) {
    if (!std::isfinite(x) || !std::isfinite(y))
        throw std::runtime_error("AETHER_CANVAS_BUFFER: bitmap sample coordinates must be finite");
    x = std::clamp(x, 0., double(view.width - 1));
    y = std::clamp(y, 0., double(view.height - 1));
    return load_canvas_pixel(view, static_cast<std::uint32_t>(std::floor(x + .5)),
                             static_cast<std::uint32_t>(std::floor(y + .5)));
}
CanvasPixel sample_linear(const CanvasBitmapView &view, double x, double y) {
    if (!std::isfinite(x) || !std::isfinite(y))
        throw std::runtime_error("AETHER_CANVAS_BUFFER: bitmap sample coordinates must be finite");
    x = std::clamp(x, 0., double(view.width - 1));
    y = std::clamp(y, 0., double(view.height - 1));
    const auto floor_x = std::floor(x), floor_y = std::floor(y);
    const auto x0 = static_cast<std::uint32_t>(floor_x), y0 = static_cast<std::uint32_t>(floor_y);
    const auto x1 = x0 < view.width - 1 ? x0 + 1 : x0;
    const auto y1 = y0 < view.height - 1 ? y0 + 1 : y0;
    const double fx = x - floor_x, fy = y - floor_y;
    const auto p00 = load_canvas_pixel(view, x0, y0), p10 = load_canvas_pixel(view, x1, y0);
    const auto p01 = load_canvas_pixel(view, x0, y1), p11 = load_canvas_pixel(view, x1, y1);
    CanvasPixel result{};
    for (std::size_t channel = 0; channel < result.size(); ++channel) {
        const auto top = p00[channel] * (1 - fx) + p10[channel] * fx;
        const auto bottom = p01[channel] * (1 - fx) + p11[channel] * fx;
        result[channel] = static_cast<std::uint8_t>(
            std::clamp(std::floor(top * (1 - fy) + bottom * fy + .5), 0., 255.));
    }
    return result;
}
CanvasPixel compose_src_over(CanvasPixel source, CanvasPixel destination) noexcept {
    if (!source[3]) return destination;
    if (source[3] == 255) return source;
    const unsigned inverse = 255u - source[3];
    CanvasPixel result{};
    for (std::size_t channel = 0; channel < result.size(); ++channel)
        result[channel] = static_cast<std::uint8_t>(unsigned(source[channel]) +
            (unsigned(destination[channel]) * inverse + 127u) / 255u);
    return result;
}
struct SpriteOrigin { std::int32_t x, y; };
std::optional<SpriteOrigin> sprite_origin(const CanvasBitmapView &bitmap, CanvasRectF local,
                                          CanvasPlacement placement, CanvasSampling sampling) noexcept {
    const float translate_x = local.left + static_cast<float>(placement.origin_x);
    const float translate_y = local.top + static_cast<float>(placement.origin_y);
    if (!std::isfinite(translate_x) || !std::isfinite(translate_y)) return {};
    if (sampling == CanvasSampling::linear &&
        (std::floor(double(translate_x)) != double(translate_x) ||
         std::floor(double(translate_y)) != double(translate_y)))
        return {};
    const auto x = std::floor(double(translate_x) + .5), y = std::floor(double(translate_y) + .5);
    constexpr auto low = std::numeric_limits<std::int32_t>::min();
    constexpr auto high = std::numeric_limits<std::int32_t>::max();
    if (x < low || x > high || y < low || y > high) return {};
    const float scale_x = (local.right - local.left) / static_cast<float>(bitmap.width);
    const float scale_y = (local.bottom - local.top) / static_cast<float>(bitmap.height);
    const float right = translate_x + scale_x * static_cast<float>(bitmap.width);
    const float bottom = translate_y + scale_y * static_cast<float>(bitmap.height);
    if (!std::isfinite(scale_x) || !std::isfinite(scale_y) || scale_x <= 0 || scale_y <= 0 ||
        !std::isfinite(right) || !std::isfinite(bottom))
        return {};
    if (std::floor(double(right) + .5) != x + bitmap.width ||
        std::floor(double(bottom) + .5) != y + bitmap.height)
        return {};
    return SpriteOrigin{static_cast<std::int32_t>(x), static_cast<std::int32_t>(y)};
}
// A checkpoint cadence, never an app budget or an extra resource allowance.
constexpr std::uint32_t pixels_per_checkpoint = 256;
} // namespace

CanvasPixel canvas_color_pixel(std::uint32_t argb) noexcept {
    const auto alpha = argb >> 24;
    const auto component = [alpha](std::uint32_t channel) noexcept {
        return static_cast<std::uint8_t>((channel * alpha + 127u) / 255u);
    };
    return {component((argb >> 16) & 255u), component((argb >> 8) & 255u),
            component(argb & 255u), static_cast<std::uint8_t>(alpha)};
}
CanvasSampling canvas_bitmap_sampling(std::uint32_t screen_density,
                                      std::uint32_t bitmap_density) noexcept {
    return screen_density != 0 && screen_density != bitmap_density ? CanvasSampling::linear : CanvasSampling::nearest;
}
SoftwareCanvas::SoftwareCanvas(std::uint32_t width, std::uint32_t height, CanvasPixel clear,
                               std::size_t working_bytes, CanvasWork work) {
    validate_canvas_premultiplied_pixel(clear);
    require_work(work);
    constexpr auto maximum_clip_extent = static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    if (width > maximum_clip_extent || height > maximum_clip_extent)
        throw std::runtime_error("AETHER_CANVAS_LIMIT: framebuffer dimensions exceed represented clip coordinates");
    if (std::uintmax_t(width) > std::numeric_limits<std::size_t>::max() / 4u)
        throw std::runtime_error("AETHER_CANVAS_LIMIT: framebuffer stride is not representable");
    const auto stride = std::size_t(width) * 4;
    const auto payload = checked_canvas_extent(width, height, stride, working_bytes);
    (void)checked_canvas_storage(payload, sizeof(*this), working_bytes);
    work.charge(work.context, static_cast<std::uint64_t>(payload));
    auto pixels = std::make_unique<std::uint8_t[]>(payload); // Real zero initialization.
    if (clear != CanvasPixel{}) {
        for (std::size_t at = 0; at < payload;) {
            const auto count = std::min<std::size_t>(payload - at, std::size_t(pixels_per_checkpoint) * 4);
            work.charge(work.context, static_cast<std::uint64_t>(count));
            for (std::size_t byte = 0; byte < count; byte += 4)
                std::copy(clear.begin(), clear.end(), pixels.get() + at + byte);
            at += count;
        }
    }
    width_ = width; height_ = height; stride_ = stride; pixel_bytes_ = payload;
    pixels_ = std::move(pixels);
}
SoftwareCanvas::SoftwareCanvas(SoftwareCanvas &&other) noexcept
    : width_(std::exchange(other.width_, 0)), height_(std::exchange(other.height_, 0)),
      stride_(std::exchange(other.stride_, 0)), pixel_bytes_(std::exchange(other.pixel_bytes_, 0)),
      pixels_(std::move(other.pixels_)), failed_(std::exchange(other.failed_, false)) {}
SoftwareCanvas &SoftwareCanvas::operator=(SoftwareCanvas &&other) noexcept {
    if (this != &other) {
        width_ = std::exchange(other.width_, 0); height_ = std::exchange(other.height_, 0);
        stride_ = std::exchange(other.stride_, 0); pixel_bytes_ = std::exchange(other.pixel_bytes_, 0);
        pixels_ = std::move(other.pixels_); failed_ = std::exchange(other.failed_, false);
    }
    return *this;
}
std::span<const std::uint8_t> SoftwareCanvas::bytes() const {
    if (failed_) throw std::runtime_error("AETHER_CANVAS_STATE: failed raster transaction has no publishable pixels");
    return {pixels_.get(), pixel_bytes_};
}
void SoftwareCanvas::draw_bitmap(const CanvasBitmapView &bitmap, CanvasRectF destination,
                                 CanvasPlacement placement, CanvasSampling sampling, CanvasWork work) {
    try {
        if (failed_ || !pixels_) throw std::runtime_error("AETHER_CANVAS_STATE: raster target is not live");
        require_work(work);
        validate_canvas_sampling(sampling);
        const auto required = checked_canvas_extent(bitmap.width, bitmap.height, bitmap.stride,
                                                    std::numeric_limits<std::size_t>::max());
        if (required > bitmap.premultiplied_rgba.size())
            throw std::runtime_error("AETHER_CANVAS_BUFFER: bitmap extent exceeds its owned pixel bytes");
        if (canvas_buffers_overlap(bitmap.premultiplied_rgba, {pixels_.get(), pixel_bytes_}))
            throw std::runtime_error("AETHER_CANVAS_UNSUPPORTED: self-blit requires an owned source snapshot");
        placement.clip.left = std::clamp(placement.clip.left, 0, static_cast<std::int32_t>(width_));
        placement.clip.right = std::clamp(placement.clip.right, 0, static_cast<std::int32_t>(width_));
        placement.clip.top = std::clamp(placement.clip.top, 0, static_cast<std::int32_t>(height_));
        placement.clip.bottom = std::clamp(placement.clip.bottom, 0, static_cast<std::int32_t>(height_));
        const float local_width = destination.right - destination.left;
        const float local_height = destination.bottom - destination.top;
        if (!std::isfinite(local_width) || !std::isfinite(local_height) || local_width <= 0 || local_height <= 0)
            return;
        const CanvasRectF absolute{destination.left + static_cast<float>(placement.origin_x),
                                   destination.top + static_cast<float>(placement.origin_y),
                                   destination.right + static_cast<float>(placement.origin_x),
                                   destination.bottom + static_cast<float>(placement.origin_y)};
        const auto bounds = classify_canvas_draw_bounds(absolute, placement.clip);
        if (!bounds) return;
        // Rect-to-rect scaling and traversal translation are represented in
        // float, like the actual destination geometry. Do not subtract the
        // pre-conversion integer origin in a different precision domain.
        const float scale_x = local_width / static_cast<float>(bitmap.width);
        const float scale_y = local_height / static_cast<float>(bitmap.height);
        if (!std::isfinite(scale_x) || !std::isfinite(scale_y) || scale_x <= 0 || scale_y <= 0)
            return; // Noninvertible/nonfinite drawing matrix has no pixels.
        const auto sprite = sprite_origin(bitmap, destination, placement, sampling);
        for (auto y = bounds->top; y < bounds->bottom; ++y) {
            for (auto x = bounds->left; x < bounds->right;) {
                const auto count = std::min<std::uint32_t>(static_cast<std::uint32_t>(bounds->right - x), pixels_per_checkpoint);
                // Actual pixel-byte reads plus output bytes; linear always reads
                // four taps, nearest one, and both read/write the destination.
                const std::uint64_t bytes_per_pixel = sampling == CanvasSampling::linear ? 24u : 12u;
                work.charge(work.context, std::uint64_t(count) * bytes_per_pixel);
                for (std::uint32_t index = 0; index < count; ++index) {
                    const auto target_x = x + static_cast<std::int32_t>(index);
                    double source_x = (double(target_x) + .5 - double(absolute.left)) / double(scale_x) - .5;
                    double source_y = (double(y) + .5 - double(absolute.top)) / double(scale_y) - .5;
                    if (sprite) {
                        source_x = double(target_x) - sprite->x;
                        source_y = double(y) - sprite->y;
                    }
                    const auto source = sampling == CanvasSampling::linear ? sample_linear(bitmap, source_x, source_y) :
                                                                            sample_nearest(bitmap, source_x, source_y);
                    const auto at = std::size_t(y) * stride_ + std::size_t(target_x) * 4;
                    const CanvasPixel previous{pixels_[at], pixels_[at + 1], pixels_[at + 2], pixels_[at + 3]};
                    const auto composed = compose_src_over(source, previous);
                    std::copy(composed.begin(), composed.end(), pixels_.get() + at);
                }
                x += static_cast<std::int32_t>(count);
            }
        }
    } catch (...) {
        failed_ = true;
        throw;
    }
}
void SoftwareCanvas::draw_color(CanvasPixel color, CanvasClip local_bounds,
                                CanvasPlacement placement, CanvasWork work) {
    if (failed_ || !pixels_)
        throw std::runtime_error("AETHER_CANVAS_STATE: Canvas cannot continue a failed or moved frame");
    try {
        require_work(work);
        work.charge(work.context, 1);
        validate_canvas_premultiplied_pixel(color);
        if (local_bounds.left >= local_bounds.right || local_bounds.top >= local_bounds.bottom)
            return;
        // Translate in the integer domain: large local coordinates must not
        // overflow or lose precision before clipping to admitted frame pixels.
        const auto left = std::max({std::int64_t(local_bounds.left) + placement.origin_x,
                                    std::int64_t(placement.clip.left), std::int64_t(0)});
        const auto top = std::max({std::int64_t(local_bounds.top) + placement.origin_y,
                                   std::int64_t(placement.clip.top), std::int64_t(0)});
        const auto right = std::min({std::int64_t(local_bounds.right) + placement.origin_x,
                                     std::int64_t(placement.clip.right), std::int64_t(width_)});
        const auto bottom = std::min({std::int64_t(local_bounds.bottom) + placement.origin_y,
                                      std::int64_t(placement.clip.bottom), std::int64_t(height_)});
        if (left >= right || top >= bottom || !color[3]) return;
        for (auto y = top; y < bottom; ++y) {
            for (auto x = left; x < right;) {
                const auto count = static_cast<std::uint32_t>(
                    std::min<std::int64_t>(right - x, pixels_per_checkpoint));
                // Four destination bytes read and four written per pixel;
                // the authenticated constant source color owns no pixel buffer.
                work.charge(work.context, std::uint64_t(count) * 8u);
                for (std::uint32_t index = 0; index < count; ++index) {
                    const auto at = std::size_t(y) * stride_ + std::size_t(x + index) * 4u;
                    const CanvasPixel previous{pixels_[at], pixels_[at + 1], pixels_[at + 2], pixels_[at + 3]};
                    const auto composed = compose_src_over(color, previous);
                    std::copy(composed.begin(), composed.end(), pixels_.get() + at);
                }
                x += count;
            }
        }
    } catch (...) {
        failed_ = true;
        throw;
    }
}
} // namespace aether::android
