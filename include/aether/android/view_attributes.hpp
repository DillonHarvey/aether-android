#pragma once
#include <span>
#include <string_view>

namespace aether::android {
// Exact SDK35 View declaration names, including removed placeholders.
// Static metadata only: callers resolve real IDs and charge their existing
// work ledger. Declaration order is not numeric styleable index order.
std::span<const std::string_view> view_attribute_names() noexcept;
} // namespace aether::android
