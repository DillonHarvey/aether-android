#include "aether/android/view_geometry.hpp"
#include <algorithm>
#include <cmath>
#include <initializer_list>
#include <limits>

namespace aether::android::geometry {
namespace {
[[noreturn]] void unsupported(const char *message) { throw GeometryError(message); }
std::int32_t sum(std::initializer_list<std::int32_t> values) {
    std::int64_t result = 0;
    for (const auto value : values) result += value;
    return checked_layout_coordinate(result);
}
std::int32_t difference(std::int32_t first, std::int32_t second) {
    return checked_layout_coordinate(std::int64_t{first} - second);
}
void check_visibility(Visibility visibility) {
    if (visibility != Visibility::visible && visibility != Visibility::invisible && visibility != Visibility::gone)
        unsupported("AETHER_LAYOUT_STATE: child visibility is not an actual Android visibility value");
}
void check_parameters(const LayoutParams &parameters) {
    if (parameters.width < wrap_content || parameters.height < wrap_content)
        unsupported("AETHER_LAYOUT_UNSUPPORTED: container layout dimension is neither a pixel size, MATCH_PARENT nor WRAP_CONTENT");
}
void require_hooks(MeasureHooks hooks) {
    if (!hooks.measure || !hooks.commit_parent || !hooks.charge)
        unsupported("AETHER_LAYOUT_STATE: measurement requires actual guest dispatch and aggregate work hooks");
}
void require_hooks(LayoutHooks hooks) {
    if (!hooks.layout || !hooks.charge)
        unsupported("AETHER_LAYOUT_STATE: layout requires actual guest dispatch and aggregate work hooks");
}
void check_orientation(LinearOrientation orientation) {
    if (orientation != LinearOrientation::horizontal && orientation != LinearOrientation::vertical)
        unsupported("AETHER_LAYOUT_UNSUPPORTED: unknown LinearLayout orientation");
}
std::uint32_t absolute_gravity(std::int32_t value, bool right_to_left) noexcept {
    auto gravity = static_cast<std::uint32_t>(value);
    if (gravity & 0x00800000u) {
        if ((gravity & 0x00800003u) == 0x00800003u) {
            gravity &= ~0x00800003u;
            gravity |= right_to_left ? 5u : 3u;
        } else if ((gravity & 0x00800005u) == 0x00800005u) {
            gravity &= ~0x00800005u;
            gravity |= right_to_left ? 3u : 5u;
        }
        gravity &= ~0x00800000u;
    }
    return gravity;
}
std::int32_t horizontal_position(std::int32_t left, std::int32_t right, std::int32_t width,
                                 const Insets &margins, std::uint32_t gravity) {
    if ((gravity & 7u) == 1u)
        return checked_layout_coordinate(std::int64_t{left} +
            (std::int64_t{right} - left - width) / 2 + margins.left - margins.right);
    if ((gravity & 7u) == 5u)
        return checked_layout_coordinate(std::int64_t{right} - width - margins.right);
    return sum({left, margins.left});
}
std::int32_t vertical_position(std::int32_t top, std::int32_t bottom, std::int32_t height,
                               const Insets &margins, std::uint32_t gravity, bool default_uses_margin = true) {
    if ((gravity & 0x70u) == 0x10u)
        return checked_layout_coordinate(std::int64_t{top} +
            (std::int64_t{bottom} - top - height) / 2 + margins.top - margins.bottom);
    if ((gravity & 0x70u) == 0x50u)
        return checked_layout_coordinate(std::int64_t{bottom} - height - margins.bottom);
    if ((gravity & 0x70u) == 0x30u || default_uses_margin) return sum({top, margins.top});
    return top;
}
PixelFrame child_frame(std::int32_t left, std::int32_t top, const MeasuredSize &measured) {
    PixelFrame frame{left, top, sum({left, measured.width()}), sum({top, measured.height()})};
    validate_realized_frame(frame);
    return frame;
}
void check_linear_child(const ChildGeometry &child) {
    check_visibility(child.visibility);
    if (!child_participates_in_layout(child.visibility)) return;
    check_parameters(child.parameters);
    if (!std::isfinite(child.parameters.weight) || child.parameters.weight != 0)
        unsupported("AETHER_LAYOUT_UNSUPPORTED: weighted LinearLayout measurement is not implemented");
}
} // namespace

LayoutParams default_frame_parameters() noexcept {
    LayoutParams result{};
    result.width = match_parent;
    result.height = match_parent;
    return result;
}
LayoutParams default_linear_parameters(bool vertical) noexcept {
    LayoutParams result{};
    result.width = vertical ? match_parent : wrap_content;
    result.height = wrap_content;
    return result;
}
LayoutParams generated_frame_parameters(const LayoutParams &source, bool source_has_margins,
                                       bool source_is_frame, std::uint32_t target_sdk) noexcept {
    LayoutParams result{};
    result.width = source.width;
    result.height = source.height;
    if (target_sdk >= 24 && source_has_margins) result.margins = source.margins;
    if (target_sdk >= 24 && source_is_frame) result.gravity = source.gravity;
    return result;
}
bool child_participates_in_layout(Visibility visibility) noexcept {
    return static_cast<std::uint32_t>(visibility) != 8u;
}
bool child_participates_in_measure(Visibility visibility, bool measure_all_children) noexcept {
    return measure_all_children || child_participates_in_layout(visibility);
}
std::int32_t default_size(std::int32_t suggested, std::uint32_t spec) noexcept {
    const auto mode = measure_mode(spec);
    return mode == exactly || mode == at_most ? measure_size(spec) : suggested;
}
std::uint32_t resolve_size_and_state(std::int32_t desired, std::uint32_t spec, std::uint32_t child_state) noexcept {
    auto result = static_cast<std::uint32_t>(desired);
    if (measure_mode(spec) == exactly) result = static_cast<std::uint32_t>(measure_size(spec));
    else if (measure_mode(spec) == at_most && measure_size(spec) < desired)
        result = static_cast<std::uint32_t>(measure_size(spec)) | measured_too_small;
    return result | (child_state & measured_state_mask);
}
std::uint32_t child_measure_spec(std::uint32_t parent_spec, std::int32_t consumed, std::int32_t dimension) {
    const auto available = std::max(0, java_frame_difference(measure_size(parent_spec), consumed));
    const auto mode = measure_mode(parent_spec);
    if (mode != exactly && mode != at_most && mode != unspecified) return make_measure_spec(0, unspecified);
    if (dimension >= 0) return make_measure_spec(dimension, exactly);
    if (dimension != match_parent && dimension != wrap_content) return make_measure_spec(0, unspecified);
    if (mode == exactly) return make_measure_spec(available, dimension == match_parent ? exactly : at_most);
    return make_measure_spec(available, mode);
}
std::int32_t checked_layout_coordinate(std::int64_t value) {
    if (value < std::numeric_limits<std::int32_t>::min() || value > std::numeric_limits<std::int32_t>::max())
        throw GeometryError("AETHER_LAYOUT_UNSUPPORTED: computed pixel coordinate exceeds int32 geometry");
    return static_cast<std::int32_t>(value);
}
void validate_realized_frame(const PixelFrame &frame) {
    const auto width = std::int64_t{frame.right} - frame.left;
    const auto height = std::int64_t{frame.bottom} - frame.top;
    if (width < 0 || height < 0 || width > std::numeric_limits<std::int32_t>::max() ||
        height > std::numeric_limits<std::int32_t>::max())
        throw GeometryError("AETHER_LAYOUT_UNSUPPORTED: realized frame requires nonnegative int32 pixel extents");
}

MeasuredSize measure_frame_layout(std::span<ChildGeometry> children, const MeasureInput &input, MeasureHooks hooks) {
    require_hooks(hooks);
    const auto horizontal_padding = sum({input.padding.left, input.padding.right});
    const auto vertical_padding = sum({input.padding.top, input.padding.bottom});
    const bool collect_match = measure_mode(input.width_spec) != exactly || measure_mode(input.height_spec) != exactly;
    std::size_t match_count = 0;
    std::int32_t maximum_width = 0, maximum_height = 0;
    std::uint32_t state = 0;
    for (std::size_t index = 0; index < children.size(); ++index) {
        hooks.charge(hooks.context, 1);
        const auto child = children[index];
        check_visibility(child.visibility);
        if (!child_participates_in_measure(child.visibility, input.measure_all_children)) continue;
        check_parameters(child.parameters);
        const auto &parameters = child.parameters;
        const auto width_consumed = sum({horizontal_padding, parameters.margins.left, parameters.margins.right});
        const auto height_consumed = sum({vertical_padding, parameters.margins.top, parameters.margins.bottom});
        const auto measured = hooks.measure(hooks.context, index,
            child_measure_spec(input.width_spec, width_consumed, parameters.width),
            child_measure_spec(input.height_spec, height_consumed, parameters.height));
        children[index].measured = measured;
        maximum_width = std::max(maximum_width, sum({measured.width(), parameters.margins.left, parameters.margins.right}));
        maximum_height = std::max(maximum_height, sum({measured.height(), parameters.margins.top, parameters.margins.bottom}));
        state |= measured.state();
        if (collect_match && (parameters.width == match_parent || parameters.height == match_parent)) ++match_count;
    }
    const auto desired_width = std::max(input.minimum_width, sum({maximum_width, horizontal_padding}));
    const auto desired_height = std::max(input.minimum_height, sum({maximum_height, vertical_padding}));
    const MeasuredSize result{resolve_size_and_state(desired_width, input.width_spec, state),
                              resolve_size_and_state(desired_height, input.height_spec, state << 16)};
    hooks.commit_parent(hooks.context, result);
    // The SDK FrameLayout second pass occurs only for multiple collected MATCH_PARENT children.
    if (match_count > 1) {
        for (std::size_t index = 0; index < children.size(); ++index) {
            hooks.charge(hooks.context, 1);
            const auto child = children[index];
            const auto &parameters = child.parameters;
            if (!child_participates_in_measure(child.visibility, input.measure_all_children) ||
                (parameters.width != match_parent && parameters.height != match_parent)) continue;
            const auto width_consumed = sum({horizontal_padding, parameters.margins.left, parameters.margins.right});
            const auto height_consumed = sum({vertical_padding, parameters.margins.top, parameters.margins.bottom});
            const auto width_spec = parameters.width == match_parent
                ? make_measure_spec(std::max(0, difference(result.width(), width_consumed)), exactly)
                : child_measure_spec(input.width_spec, width_consumed, parameters.width);
            const auto height_spec = parameters.height == match_parent
                ? make_measure_spec(std::max(0, difference(result.height(), height_consumed)), exactly)
                : child_measure_spec(input.height_spec, height_consumed, parameters.height);
            children[index].measured = hooks.measure(hooks.context, index, width_spec, height_spec);
        }
    }
    return result;
}

LinearMeasuredSize measure_linear_layout(std::span<ChildGeometry> children, const MeasureInput &input, MeasureHooks hooks) {
    require_hooks(hooks);
    check_orientation(input.orientation);
    const bool vertical = input.orientation == LinearOrientation::vertical;
    if (input.use_largest_child || input.has_dividers || input.baseline_child_index >= 0 ||
        (!vertical && input.baseline_aligned))
        unsupported("AETHER_LAYOUT_UNSUPPORTED: LinearLayout largest-child, dividers and baseline profiles require their real algorithms");
    const auto cross_spec = vertical ? input.width_spec : input.height_spec;
    // Uniform cross-axis measurement temporarily mutates the actual managed LP.
    // Specs alone cannot represent that observable operation through these hooks.
    for (const auto &child : children) {
        hooks.charge(hooks.context, 1);
        check_linear_child(child);
        if (child_participates_in_layout(child.visibility) && measure_mode(cross_spec) != exactly &&
            (vertical ? child.parameters.width : child.parameters.height) == match_parent)
            unsupported("AETHER_LAYOUT_UNSUPPORTED: LinearLayout uniform cross-axis pass requires actual temporary LayoutParams mutation");
    }
    const auto horizontal_padding = sum({input.padding.left, input.padding.right});
    const auto vertical_padding = sum({input.padding.top, input.padding.bottom});
    std::int32_t total = 0, cross_maximum = 0;
    std::uint32_t state = 0;
    for (std::size_t index = 0; index < children.size(); ++index) {
        hooks.charge(hooks.context, 1);
        const auto child = children[index];
        if (!child_participates_in_layout(child.visibility)) continue;
        const auto &parameters = child.parameters;
        const auto width_consumed = sum({horizontal_padding, parameters.margins.left, parameters.margins.right, vertical ? 0 : total});
        const auto height_consumed = sum({vertical_padding, parameters.margins.top, parameters.margins.bottom, vertical ? total : 0});
        const auto measured = hooks.measure(hooks.context, index,
            child_measure_spec(input.width_spec, width_consumed, parameters.width),
            child_measure_spec(input.height_spec, height_consumed, parameters.height));
        children[index].measured = measured;
        const auto next = vertical
            ? sum({total, measured.height(), parameters.margins.top, parameters.margins.bottom})
            : sum({total, measured.width(), parameters.margins.left, parameters.margins.right});
        total = vertical || measure_mode(input.width_spec) != exactly ? std::max(total, next) : next;
        const auto cross = vertical
            ? sum({measured.width(), parameters.margins.left, parameters.margins.right})
            : sum({measured.height(), parameters.margins.top, parameters.margins.bottom});
        cross_maximum = std::max(cross_maximum, cross);
        state |= measured.state();
    }
    total = sum({total, vertical ? vertical_padding : horizontal_padding});
    const auto desired_width = std::max(input.minimum_width, vertical ? sum({cross_maximum, horizontal_padding}) : total);
    const auto desired_height = std::max(input.minimum_height, vertical ? total : sum({cross_maximum, vertical_padding}));
    const MeasuredSize measured{resolve_size_and_state(desired_width, input.width_spec, state),
        resolve_size_and_state(desired_height, input.height_spec, vertical ? 0u : state << 16)};
    hooks.commit_parent(hooks.context, measured);
    return {measured, total};
}

void layout_frame_layout(std::span<const ChildGeometry> children, const LayoutInput &input, LayoutHooks hooks) {
    require_hooks(hooks);
    validate_realized_frame(input.frame);
    const auto right = difference(input.frame.width(), input.padding.right);
    const auto bottom = difference(input.frame.height(), input.padding.bottom);
    for (std::size_t index = 0; index < children.size(); ++index) {
        hooks.charge(hooks.context, 1);
        const auto child = children[index];
        check_visibility(child.visibility);
        if (!child_participates_in_layout(child.visibility)) continue;
        check_parameters(child.parameters);
        const auto gravity = child.parameters.gravity == -1 ? 0x00800033 : child.parameters.gravity;
        const auto left = horizontal_position(input.padding.left, right, child.measured.width(), child.parameters.margins,
                                               absolute_gravity(gravity, input.right_to_left));
        const auto top = vertical_position(input.padding.top, bottom, child.measured.height(), child.parameters.margins,
                                           static_cast<std::uint32_t>(gravity));
        hooks.layout(hooks.context, index, child_frame(left, top, child.measured));
    }
}

void layout_linear_layout(std::span<const ChildGeometry> children, const LayoutInput &input, LayoutHooks hooks) {
    require_hooks(hooks);
    validate_realized_frame(input.frame);
    check_orientation(input.orientation);
    const bool vertical = input.orientation == LinearOrientation::vertical;
    if (!input.measured_total_length)
        unsupported("AETHER_LAYOUT_STATE: LinearLayout requires the total length retained from its actual measure pass");
    if (input.has_dividers || (!vertical && input.baseline_aligned))
        unsupported("AETHER_LAYOUT_UNSUPPORTED: LinearLayout divider or baseline layout is not implemented");
    const auto total = *input.measured_total_length;
    const auto gravity = absolute_gravity(input.gravity, input.right_to_left);
    const auto major = vertical ? gravity & 0x70u : gravity & 7u;
    const auto major_size = vertical ? input.frame.height() : input.frame.width();
    const auto major_padding = vertical ? input.padding.top : input.padding.left;
    std::int32_t cursor = major_padding;
    if ((vertical && major == 0x50u) || (!vertical && major == 5u))
        cursor = checked_layout_coordinate(std::int64_t{major_padding} + major_size - total);
    else if ((vertical && major == 0x10u) || (!vertical && major == 1u))
        cursor = checked_layout_coordinate(std::int64_t{major_padding} + (std::int64_t{major_size} - total) / 2);
    const auto right = difference(input.frame.width(), input.padding.right);
    const auto bottom = difference(input.frame.height(), input.padding.bottom);
    for (std::size_t step = 0; step < children.size(); ++step) {
        hooks.charge(hooks.context, 1);
        const auto index = !vertical && input.right_to_left ? children.size() - 1 - step : step;
        const auto child = children[index];
        check_linear_child(child);
        if (!child_participates_in_layout(child.visibility)) continue;
        auto child_gravity = child.parameters.gravity < 0 ? input.gravity : child.parameters.gravity;
        child_gravity = std::bit_cast<std::int32_t>(absolute_gravity(child_gravity, input.right_to_left));
        std::int32_t left = 0, top = 0;
        if (vertical) {
            cursor = sum({cursor, child.parameters.margins.top});
            left = horizontal_position(input.padding.left, right, child.measured.width(), child.parameters.margins,
                                        static_cast<std::uint32_t>(child_gravity));
            top = cursor;
        } else {
            cursor = sum({cursor, child.parameters.margins.left});
            left = cursor;
            top = vertical_position(input.padding.top, bottom, child.measured.height(), child.parameters.margins,
                                      static_cast<std::uint32_t>(child_gravity), false);
        }
        hooks.layout(hooks.context, index, child_frame(left, top, child.measured));
        cursor = vertical ? sum({cursor, child.measured.height(), child.parameters.margins.bottom})
                          : sum({cursor, child.measured.width(), child.parameters.margins.right});
    }
}
} // namespace aether::android::geometry
