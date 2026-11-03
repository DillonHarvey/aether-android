#pragma once
#include <span>
#include <string_view>

namespace aether::android {
enum class WidgetStyleable {
    view_group, view_group_layout, view_group_margin_layout,
    linear_layout, linear_layout_layout, frame_layout, frame_layout_layout, view_stub
};
// Exact separate SDK35 declaration-name inventories. Declaration order is not
// numeric styleable index order. Resolve through the actual catalog and keep
// constructor inheritance/query order with the consuming framework code.
// Borrowed static metadata only; an invalid enum is a precise host error.
std::span<const std::string_view> widget_attribute_names(WidgetStyleable styleable);
} // namespace aether::android
