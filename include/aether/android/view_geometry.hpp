#pragma once
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>

namespace aether::android::geometry {
inline constexpr std::uint32_t mode_mask = 0xc0000000u;
inline constexpr std::uint32_t unspecified = 0u;
inline constexpr std::uint32_t exactly = 0x40000000u;
inline constexpr std::uint32_t at_most = 0x80000000u;
inline constexpr std::uint32_t measured_size_mask = 0x00ffffffu;
inline constexpr std::uint32_t measured_state_mask = 0xff000000u;
inline constexpr std::uint32_t measured_too_small = 0x01000000u;
inline constexpr std::int32_t match_parent = -1, wrap_content = -2;

constexpr std::uint32_t make_measure_spec(std::int32_t size, std::uint32_t mode) noexcept {
    return (static_cast<std::uint32_t>(size) & ~mode_mask) | (mode & mode_mask);
}
constexpr std::uint32_t measure_mode(std::uint32_t spec) noexcept { return spec & mode_mask; }
constexpr std::int32_t measure_size(std::uint32_t spec) noexcept {
    return static_cast<std::int32_t>(spec & ~mode_mask);
}
// Java frame getters preserve int subtraction, independently of raster admission.
constexpr std::int32_t java_frame_difference(std::int32_t end, std::int32_t start) noexcept {
    return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(end) - static_cast<std::uint32_t>(start));
}
struct PixelFrame {
    std::int32_t left = 0, top = 0, right = 0, bottom = 0;
    constexpr std::int32_t width() const noexcept { return java_frame_difference(right, left); }
    constexpr std::int32_t height() const noexcept { return java_frame_difference(bottom, top); }
    bool operator==(const PixelFrame &) const = default;
};
struct Insets { std::int32_t left = 0, top = 0, right = 0, bottom = 0; };
struct MeasuredSize {
    std::uint32_t width_and_state = 0, height_and_state = 0;
    constexpr std::int32_t width() const noexcept { return static_cast<std::int32_t>(width_and_state & measured_size_mask); }
    constexpr std::int32_t height() const noexcept { return static_cast<std::int32_t>(height_and_state & measured_size_mask); }
    constexpr std::uint32_t state() const noexcept {
        return (width_and_state & measured_state_mask) | ((height_and_state >> 16) & (measured_state_mask >> 16));
    }
};
struct LinearMeasuredSize {
    MeasuredSize measured;
    std::int32_t total_length = 0;
};
enum class Visibility : std::uint32_t { visible = 0, invisible = 4, gone = 8 };
enum class LinearOrientation : std::uint32_t { horizontal = 0, vertical = 1 };
struct LayoutParams {
    std::int32_t width = wrap_content, height = wrap_content;
    Insets margins;
    std::int32_t gravity = -1;
    float weight = 0;
};
struct ChildGeometry {
    LayoutParams parameters;
    Visibility visibility = Visibility::visible;
    MeasuredSize measured;
};
class GeometryError final : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};
struct MeasureInput {
    std::uint32_t width_spec = 0, height_spec = 0;
    Insets padding;
    std::int32_t minimum_width = 0, minimum_height = 0;
    bool measure_all_children = false;
    bool baseline_aligned = true;
    LinearOrientation orientation = LinearOrientation::horizontal;
    bool use_largest_child = false, has_dividers = false;
    std::int32_t baseline_child_index = -1;
};
struct LayoutInput {
    // Frame is local to this parent's parent; callbacks receive local child frames.
    PixelFrame frame;
    Insets padding;
    std::int32_t gravity = 0x00800033; // Actual Android START | TOP default.
    LinearOrientation orientation = LinearOrientation::horizontal;
    bool right_to_left = false;
    bool baseline_aligned = true, has_dividers = false;
    // The actual result of the corresponding measure pass, including padding.
    // Required for LinearLayout; frame layout does not consume this field.
    std::optional<std::int32_t> measured_total_length;
};
struct MeasureHooks {
    void *context = nullptr;
    MeasuredSize (*measure)(void *, std::size_t child, std::uint32_t width_spec, std::uint32_t height_spec) = nullptr;
    // Actual parent setMeasuredDimension, without guest execution. FrameLayout
    // invokes this before its second child pass, exactly as its SDK algorithm.
    void (*commit_parent)(void *, MeasuredSize) = nullptr;
    void (*charge)(void *, std::uint64_t actual_work) = nullptr;
};
struct LayoutHooks {
    void *context = nullptr;
    void (*layout)(void *, std::size_t child, PixelFrame frame) = nullptr;
    void (*charge)(void *, std::uint64_t actual_work) = nullptr;
};
// Adapters own traced original operands, immutable child snapshots and current-tree
// authority. Each guest hook must revalidate that authority and all dependent
// LayoutParams/visibility/configuration facts before returning; an unsupported
// mutation must diagnose rather than compute from stale captured facts. Kernels
// never replay hooks or roll back parent/child state committed before a later
// failure. Admission of a completed host presentation is a separate operation.
LayoutParams default_frame_parameters() noexcept;
LayoutParams default_linear_parameters(bool vertical) noexcept;
LayoutParams generated_frame_parameters(const LayoutParams &source, bool source_has_margins,
                                        bool source_is_frame, std::uint32_t target_sdk) noexcept;
bool child_participates_in_layout(Visibility visibility) noexcept;
bool child_participates_in_measure(Visibility visibility, bool measure_all_children) noexcept;
std::int32_t default_size(std::int32_t suggested, std::uint32_t spec) noexcept;
std::uint32_t resolve_size_and_state(std::int32_t desired, std::uint32_t spec, std::uint32_t child_state) noexcept;
std::uint32_t child_measure_spec(std::uint32_t parent_spec, std::int32_t consumed, std::int32_t dimension);
std::int32_t checked_layout_coordinate(std::int64_t value);
void validate_realized_frame(const PixelFrame &frame);
MeasuredSize measure_frame_layout(std::span<ChildGeometry> children, const MeasureInput &input, MeasureHooks hooks);
LinearMeasuredSize measure_linear_layout(std::span<ChildGeometry> children, const MeasureInput &input, MeasureHooks hooks);
void layout_frame_layout(std::span<const ChildGeometry> children, const LayoutInput &input, LayoutHooks hooks);
void layout_linear_layout(std::span<const ChildGeometry> children, const LayoutInput &input, LayoutHooks hooks);
} // namespace aether::android::geometry
