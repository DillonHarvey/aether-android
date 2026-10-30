#include "aether/apk/intent_value.hpp"
#include <algorithm>
#include <bit>
#include <limits>
#include <set>
#include <utility>

namespace aether::apk {
namespace {
[[noreturn]] void invalid(std::string_view message) {
    throw InspectError("AETHER_INTENT_VALUE_INVALID", "intent-value", std::string(message));
}
[[noreturn]] void limit() {
    throw InspectError("AETHER_INTENT_VALUE_LIMIT", "intent-value",
                       "Intent value exceeds the existing text or metadata profile");
}
std::int32_t category_hash(const std::optional<std::u16string> &value) noexcept {
    std::uint32_t hash = 0;
    if (value) for (const auto unit : *value) hash = hash * 31u + static_cast<std::uint16_t>(unit);
    return std::bit_cast<std::int32_t>(hash);
}
std::optional<std::u16string_view> view(const std::optional<std::u16string> &value) noexcept {
    return value ? std::optional<std::u16string_view>(*value) : std::nullopt;
}
void bounds(const IntentValue &value) {
    const auto text = [](std::u16string_view item) { if (item.size() > 4096) limit(); };
    for (const auto *item : {&value.action, &value.package, &value.data, &value.mime_type,
                             &value.resolved_mime_type, &value.identifier})
        if (*item) text(**item);
    if (value.component) { text(value.component->package); text(value.component->class_name); }
    if (value.categories) {
        if (value.categories->size() > 65536) limit();
        for (const auto &item : *value.categories) if (item) text(*item);
    }
    if (value.mime_state != IntentMimeState::resolved && value.mime_state != IntentMimeState::unresolved)
        invalid("Intent MIME state is unknown");
    if (value.mime_state == IntentMimeState::unresolved && value.resolved_mime_type)
        invalid("Unresolved Intent MIME state cannot contain a resolved filter type");
    if (value.mime_type && (value.mime_state != IntentMimeState::resolved ||
                            value.resolved_mime_type != value.mime_type))
        invalid("Explicit Intent MIME type requires the same resolved filter type");
    if (value.accounted_bytes() > manifest_activity_bytes) limit();
}
} // namespace

std::size_t IntentValue::accounted_bytes() const noexcept {
    std::size_t bytes = sizeof(*this);
    const auto add = [&](std::size_t count, std::size_t width = 1) {
        if (bytes > manifest_activity_bytes || count > (manifest_activity_bytes - bytes) / width)
            bytes = manifest_activity_bytes + 1;
        else bytes += count * width;
    };
    const auto text = [&](const std::u16string &value) {
        if (value.capacity() == std::numeric_limits<std::size_t>::max()) bytes = manifest_activity_bytes + 1;
        else add(value.capacity() + 1, sizeof(char16_t));
    };
    for (const auto *item : {&action, &package, &data, &mime_type, &resolved_mime_type, &identifier})
        if (*item) text(**item);
    if (component) { text(component->package); text(component->class_name); }
    if (categories) {
        add(categories->capacity(), sizeof(std::optional<std::u16string>));
        for (const auto &item : *categories) if (item) text(*item);
    }
    return bytes;
}
void IntentValue::validate() const {
    bounds(*this);
    if (!categories) return;
    std::optional<std::int32_t> previous;
    std::set<std::optional<std::u16string_view>> unique;
    for (const auto &item : *categories) {
        const auto hash = category_hash(item);
        if (previous && hash < *previous) invalid("Intent categories are not in signed Java hash order");
        if (!unique.emplace(view(item)).second) invalid("Intent categories contain an exact duplicate");
        previous = hash;
    }
}
void canonicalize_intent_categories(IntentValue &value) {
    bounds(value);
    if (!value.categories) return;
    // Keep all borrowed views stable until duplicate detection has finished.
    std::set<std::optional<std::u16string_view>> unique;
    std::vector<std::pair<std::int32_t, std::size_t>> order;
    order.reserve(value.categories->size());
    for (std::size_t index = 0; index < value.categories->size(); ++index) {
        const auto &item = (*value.categories)[index];
        if (unique.emplace(view(item)).second) order.emplace_back(category_hash(item), index);
    }
    std::stable_sort(order.begin(), order.end(), [](const auto &left, const auto &right) {
        return left.first < right.first;
    });
    unique.clear();
    std::vector<std::optional<std::u16string>> canonical;
    canonical.reserve(order.size());
    for (const auto &[hash, index] : order) {
        (void)hash;
        canonical.push_back(std::move((*value.categories)[index]));
    }
    value.categories->swap(canonical);
    value.validate();
}
ActivityIntentResolution resolve_intent_value(const ManifestInfo &manifest, const IntentValue &value,
                                             const ActivityIntentPolicy &policy) {
    value.validate();
    std::vector<std::optional<std::u16string_view>> categories;
    if (value.categories) {
        categories.reserve(value.categories->size());
        for (const auto &item : *value.categories) categories.push_back(view(item));
    }
    ActivityIntentRequest request;
    request.intent = {view(value.action), view(value.resolved_mime_type), view(value.data), categories,
                      value.mime_state, value.default_only};
    request.package = view(value.package);
    if (value.component) request.component = IntentComponentRequest{value.component->package, value.component->class_name};
    return resolve_activity_intent(manifest, request, policy);
}
} // namespace aether::apk
