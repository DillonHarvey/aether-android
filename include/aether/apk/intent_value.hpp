#pragma once
#include "aether/apk/intent_resolver.hpp"

namespace aether::apk {
struct IntentComponentValue {
    std::u16string package, class_name;
};
struct IntentValue {
    std::optional<std::u16string> action, package, data, mime_type, identifier;
    // Resolved filter MIME is separate from Intent.mType. Provider resolution
    // must never rewrite the raw type observable through Activity.getIntent.
    std::optional<std::u16string> resolved_mime_type;
    std::optional<IntentComponentValue> component;
    std::optional<std::vector<std::optional<std::u16string>>> categories;
    std::uint32_t flags = 0;
    IntentMimeState mime_state = IntentMimeState::resolved;
    bool default_only = false;
    // Value bounds/canonical ArraySet order only; this is not launch authority.
    void validate() const;
    std::size_t accounted_bytes() const noexcept;
};
// Stable signed Java String hash order, null hash zero, exact duplicate removal.
// Producers canonicalize before BOTH resolution and materialization; decoders
// validate canonical order rather than changing a received request's meaning.
void canonicalize_intent_categories(IntentValue &value);
ActivityIntentResolution resolve_intent_value(const ManifestInfo &manifest, const IntentValue &value,
                                             const ActivityIntentPolicy &policy = {});
} // namespace aether::apk
