#pragma once
#include "aether/apk/resources.hpp"
#include <functional>
#include <span>

namespace aether::android {
enum class StyledAttributePresence { present, absent, unresolved };
enum class StyledScalarStatus { ready, unsupported, unresolved };
enum class StyledValueOrigin { resource_table, xml_pool };
// An independent scalar snapshot: no borrowed table values or string views.
// Null/empty markers retain their data, but neither is a hasValue value.
struct StyledAttributeSnapshot {
    StyledAttributePresence presence = StyledAttributePresence::unresolved;
    StyledScalarStatus scalar = StyledScalarStatus::unresolved;
    apk::ResourceValue value{};
    std::uint32_t source_resource = 0; // First reference, retained for provenance.
    std::uint32_t resolved_resource = 0; // Last successfully selected reference (SDK value.resid).
    std::uint32_t unresolved_style = 0;
    std::uint32_t unresolved_resource = 0;
    // Source identity and original encoded data remain distinct from the legacy
    // scalar carrier, which deliberately suppresses unsupported string indices.
    // Literal Theme values have no selected resource ID/configuration density;
    // following a resource reference supplies its actual terminal facts.
    std::uint32_t native_flags = 0, source_id = 0, source_data = 0, source_style = 0;
    std::uint16_t density = 0;
    bool sdk_source = false, provenance_complete = false;
    // XML literals belong to their parser pool, never the selected ARSC pool.
    StyledValueOrigin value_origin = StyledValueOrigin::resource_table;
    // Originating XML resource or defining explicit/default style. A Theme-only
    // query has no explicit source-resource ID, independently of reference IDs.
    std::uint32_t source_resource_id = 0;
};
// Immutable compiled SDK35 metadata; unsupported selection stays explicit.
apk::StyleAttributeResult platform_style_attribute(std::uint32_t style, std::uint32_t attribute,
                                                   const apk::ResourceConfiguration &configuration = {},
                                                   const std::function<void(std::uint64_t)> &charge_work = {});
struct ThemeStyleLayer {
    std::uint32_t style = 0;
    bool force = false;
};
// SDK35 selection; an explicit nonzero style remains unchanged.
std::uint32_t select_default_theme(std::uint32_t requested, std::uint32_t target_sdk) noexcept;
// Raw selections for ApplyStyle precedence. These do not resolve references or
// turn a resource reference into an assumed style identity. Unknowns stay raw.
apk::StyleAttributeResult select_theme_attribute(const apk::ResourceTable &resources,
    std::span<const ThemeStyleLayer> layers, std::uint32_t attribute,
    const apk::ResourceConfiguration &configuration = {},
    const std::function<void(std::uint64_t)> &charge_work = {});
apk::StyleAttributeResult select_style_attribute(const apk::ResourceTable &resources,
    std::uint32_t style, std::uint32_t attribute,
    const apk::ResourceConfiguration &configuration = {},
    const std::function<void(std::uint64_t)> &charge_work = {});
// Resolve an authenticated copied XML/bag value against the final Theme. The
// caller chooses precedence first; raw undefined and reference-zero differ.
// XML pool strings stay explicitly unsupported unless a consumer owns the text.
StyledAttributeSnapshot resolve_styled_value(const apk::ResourceTable &resources,
    std::span<const ThemeStyleLayer> layers, const apk::StyleAttributeResult &selected,
    StyledValueOrigin origin, std::uint32_t source_resource_id,
    const apk::ResourceConfiguration &configuration = {},
    const std::function<void(std::uint64_t)> &charge_work = {});
// Layers are in application order. Attribute references see the final theme.
StyledAttributeSnapshot resolve_styled_attribute(const apk::ResourceTable &resources,
                                                std::span<const ThemeStyleLayer> layers,
                                                std::uint32_t attribute,
                                                const apk::ResourceConfiguration &configuration = {},
                                                const std::function<void(std::uint64_t)> &charge_work = {});
} // namespace aether::android
