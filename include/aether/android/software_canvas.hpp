#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace aether::android {
using CanvasPixel = std::array<std::uint8_t, 4>;
// Convert an actual Android straight ARGB color to this kernel's premultiplied
// RGBA8 storage. Alpha/filter mutation belongs to the real Drawable/Paint owner.
CanvasPixel canvas_color_pixel(std::uint32_t argb) noexcept;
struct CanvasRectF {
    float left = 0, top = 0, right = 0, bottom = 0;
};
struct CanvasClip {
    std::int32_t left = 0, top = 0, right = 0, bottom = 0;
};
struct CanvasPlacement {
    std::int32_t origin_x = 0, origin_y = 0;
    CanvasClip clip;
};
struct CanvasBitmapView {
    std::uint32_t width = 0, height = 0;
    std::size_t stride = 0;
    // Borrowed authenticated, already premultiplied RGBA8. The owner stays
    // rooted and immutable for the entire nonreentrant raster operation.
    std::span<const std::uint8_t> premultiplied_rgba;
};
enum class CanvasSampling { nearest, linear };
// Actual null-Paint software policy. Density does not rescale RectF coordinates.
CanvasSampling canvas_bitmap_sampling(std::uint32_t screen_density,
                                      std::uint32_t bitmap_density) noexcept;
struct CanvasWork {
    void *context = nullptr;
    // Required trusted, nonallocating, nonreentrant debit. The normal binding
    // calls ManagedRuntime::charge_provider_work; it must not collect or yield.
    void (*charge)(void *, std::uint64_t) = nullptr;
};

// Partial software raster kernel, not a Java Canvas provider or proof that a
// generic View can be presented. No guest handles, callbacks or HWNDs are owned.
// Actual Activity/root/configuration/incarnation custody belongs to the caller.
class SoftwareCanvas final {
  public:
    // working_bytes is the existing aggregate remainder for this entire
    // object and its new pixels. Every other live owner, including an old
    // framebuffer during replacement, must remain charged by the caller.
    // clear is an actual caller-proven premultiplied background, never a
    // synthetic fallback. Zeroing and any additional clear are metered.
    SoftwareCanvas(std::uint32_t width, std::uint32_t height, CanvasPixel clear,
                   std::size_t working_bytes, CanvasWork work);
    ~SoftwareCanvas() = default;
    SoftwareCanvas(const SoftwareCanvas &) = delete;
    SoftwareCanvas &operator=(const SoftwareCanvas &) = delete;
    SoftwareCanvas(SoftwareCanvas &&other) noexcept;
    SoftwareCanvas &operator=(SoftwareCanvas &&other) noexcept;

    // Full-source Rect -> RectF, null-Paint software drawing only. Placement is
    // real traversal translation and an integer non-AA clip in framebuffer
    // pixels. Other transforms/paint effects are not represented as supported.
    // A failed transaction cannot expose or continue its partial pixel output.
    void draw_bitmap(const CanvasBitmapView &bitmap, CanvasRectF destination,
                     CanvasPlacement placement, CanvasSampling sampling, CanvasWork work);
    // Integer local drawable bounds, translated and intersected with the real
    // placement/framebuffer clip. Premultiplied solid SRC_OVER only; no AA,
    // shader, color filter or implicit drawable-alpha conversion is performed.
    void draw_color(CanvasPixel color, CanvasClip local_bounds,
                    CanvasPlacement placement, CanvasWork work);
    std::uint32_t width() const noexcept { return width_; }
    std::uint32_t height() const noexcept { return height_; }
    std::size_t stride() const noexcept { return stride_; }
    std::span<const std::uint8_t> bytes() const;
    // Includes this object's metadata and exact owned pixel elements. An
    // enclosing object's sizeof already includes embedded Canvas metadata:
    // charge sizeof(outer)-sizeof(SoftwareCanvas)+storage_bytes(), not twice.
    std::size_t storage_bytes() const noexcept { return sizeof(*this) + pixel_bytes_; }
    bool failed() const noexcept { return failed_; }

  private:
    std::uint32_t width_ = 0, height_ = 0;
    std::size_t stride_ = 0, pixel_bytes_ = 0;
    std::unique_ptr<std::uint8_t[]> pixels_;
    bool failed_ = false;
};
} // namespace aether::android
