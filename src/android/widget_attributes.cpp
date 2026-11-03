#include "aether/android/widget_attributes.hpp"
#include "aether/apk/inspect.hpp"

namespace aether::android {
std::span<const std::string_view> widget_attribute_names(WidgetStyleable styleable) {
    // android-15.0.0_r1 core/res/res/values/attrs.xml, direct attr children.
    // Source SHA256 b65fdd09f96bbadcd391509d380677036f8272d35c85f1921bf6a1cc758ffe35.
    // Factual names only, not imported platform constructor implementation.
    static constexpr std::string_view view_group[]{
        "animateLayoutChanges", "clipChildren", "clipToPadding", "layoutAnimation",
        "animationCache", "persistentDrawingCache", "alwaysDrawnWithCache",
        "addStatesFromChildren", "descendantFocusability", "touchscreenBlocksFocus",
        "splitMotionEvents", "layoutMode", "transitionGroup"
    };
    static constexpr std::string_view view_group_layout[]{"layout_width", "layout_height"};
    static constexpr std::string_view view_group_margin_layout[]{
        "layout_width", "layout_height", "layout_margin", "layout_marginLeft", "layout_marginTop",
        "layout_marginRight", "layout_marginBottom", "layout_marginStart", "layout_marginEnd",
        "layout_marginHorizontal", "layout_marginVertical"
    };
    static constexpr std::string_view linear_layout[]{
        "orientation", "gravity", "baselineAligned", "baselineAlignedChildIndex", "weightSum",
        "measureWithLargestChild", "divider", "showDividers", "dividerPadding"
    };
    static constexpr std::string_view linear_layout_layout[]{
        "layout_width", "layout_height", "layout_weight", "layout_gravity"
    };
    static constexpr std::string_view frame_layout[]{"measureAllChildren"};
    static constexpr std::string_view frame_layout_layout[]{"layout_gravity"};
    static constexpr std::string_view view_stub[]{"id", "layout", "inflatedId"};
    switch (styleable) {
    case WidgetStyleable::view_group: return view_group;
    case WidgetStyleable::view_group_layout: return view_group_layout;
    case WidgetStyleable::view_group_margin_layout: return view_group_margin_layout;
    case WidgetStyleable::linear_layout: return linear_layout;
    case WidgetStyleable::linear_layout_layout: return linear_layout_layout;
    case WidgetStyleable::frame_layout: return frame_layout;
    case WidgetStyleable::frame_layout_layout: return frame_layout_layout;
    case WidgetStyleable::view_stub: return view_stub;
    }
    throw apk::InspectError("AETHER_STYLEABLE_KIND", "widget-attributes",
                            "Widget styleable identity is outside the implemented SDK declaration set");
}
} // namespace aether::android
