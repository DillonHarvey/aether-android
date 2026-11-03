#include "aether/android/styled_attributes.hpp"
#include "aether/android/sdk_resources.hpp"
#include "aether/android/sdk_resource_image.hpp"
#include <algorithm>
#include <array>

namespace aether::android {
apk::StyleAttributeResult platform_style_attribute(std::uint32_t style, std::uint32_t attribute,
                                                   const apk::ResourceConfiguration &configuration,
                                                   const std::function<void(std::uint64_t)> &charge_work) {
    return embedded_sdk_resources().style_attribute(style, attribute, configuration, charge_work);
}

std::uint32_t select_default_theme(std::uint32_t requested, std::uint32_t target_sdk) noexcept {
    if (requested) return requested;
    if (target_sdk < 11) return 0x01030005u;
    if (target_sdk < 14) return 0x0103006bu;
    if (target_sdk < 24) return 0x01030128u;
    return 0x0103013fu;
}
namespace {
void charge(const std::function<void(std::uint64_t)> &work, std::uint64_t amount = 1) {
    if (work) work(amount);
}
bool bound_source(const apk::ResourceTable &resources, const apk::StyleAttributeResult &value,
                  const std::function<void(std::uint64_t)> &charge_work) {
    if (value.sdk_source) return value.source_id == 0 && value.source_style != 0;
    if (!value.source_id || value.source_id > resources.sources().size() || !value.source_style) return false;
    charge(charge_work);
    const auto defining = resources.entries().find(value.source_style);
    if (defining == resources.entries().end() || defining->second.source_id != value.source_id) return false;
    if (value.value.type != 3) return value.source_data == value.value.data;
    const auto &source = resources.sources()[value.source_id - 1];
    return value.source_data < source.string_count &&
        std::uint64_t(source.string_base) + value.source_data == value.value.data;
}
apk::StyleAttributeResult merged_attribute(const apk::ResourceTable &resources,
                                          std::span<const ThemeStyleLayer> layers,
                                          std::uint32_t attribute,
                                          const apk::ResourceConfiguration &configuration,
                                          const std::function<void(std::uint64_t)> &charge_work) {
    apk::StyleAttributeResult current; // Resources.newTheme is genuinely empty.
    for (const auto &layer : layers) {
        charge(charge_work);
        if (!layer.style) continue;
        auto selected = resources.style_attribute(layer.style, attribute, charge_work);
        if (selected.unresolved_style && (selected.unresolved_style >> 24) == 1) {
            const auto inherited = selected.status == apk::StyleAttributeStatus::found
                ? embedded_sdk_resources().style_ancestry_flags(selected.unresolved_style, configuration, charge_work)
                : platform_style_attribute(selected.unresolved_style, attribute, configuration, charge_work);
            const auto flags = selected.native_flags | inherited.native_flags;
            if (selected.status == apk::StyleAttributeStatus::unresolved) {
                selected = inherited;
                selected.native_flags = flags;
                // A directly requested SDK style has no unknown app prefix.
                // App ancestry flags are authoritative only for a runtime table
                // that retained its actual source registry.
                selected.provenance_complete = selected.provenance_complete &&
                    ((layer.style >> 24) == 1 || !resources.sources().empty());
            } else if (selected.status == apk::StyleAttributeStatus::found) {
                // A conclusive app child override must not be replaced by the
                // parent's value merely to finish its inherited bag flags.
                selected.native_flags = flags;
                selected.provenance_complete = inherited.provenance_complete && bound_source(resources, selected, charge_work);
                selected.unresolved_style = inherited.unresolved_style;
            }
        }
        if (selected.status == apk::StyleAttributeStatus::absent) continue;
        if (selected.status == apk::StyleAttributeStatus::unresolved) {
            if (layer.force || current.status != apk::StyleAttributeStatus::found)
                current = selected;
            continue;
        }
        const bool undefined = selected.value.type == 0 && selected.value.data != 1;
        if (undefined) {
            if (layer.force) {
                // SDK35 AssetManager2 erases an existing key, but inserts the
                // raw undefined entry when the key was absent. That stored key
                // still blocks a later nonforced value. Unknown old key
                // presence stays conservative until another forced value.
                if (current.status == apk::StyleAttributeStatus::found) current = {};
                else if (current.status == apk::StyleAttributeStatus::absent) current = selected;
            }
            continue;
        }
        if (layer.force || current.status == apk::StyleAttributeStatus::absent)
            current = selected;
        // A nonforced layer cannot settle an unknown older entry. Raw @empty
        // and reference-zero @null remain stored values until final resolution.
    }
    return current;
}
} // namespace
namespace {
StyledAttributeSnapshot resolve_attribute_value(const apk::ResourceTable &resources,
                                                std::span<const ThemeStyleLayer> layers,
                                                std::uint32_t attribute,
                                                const apk::ResourceConfiguration &configuration,
                                                const std::function<void(std::uint64_t)> &charge_work,
                                                const apk::StyleAttributeResult *initial_value,
                                                StyledValueOrigin origin, std::uint32_t source_resource_id) {
    StyledAttributeSnapshot result;
    result.value_origin = origin;
    result.source_resource_id = source_resource_id;
    struct Key {
        std::uint32_t id;
        bool attribute;
        bool operator==(const Key &) const = default;
    };
    std::array<Key, 32> visited{};
    // A seeded raw value is not a Theme lookup. Its synthetic zero reference
    // cannot collide with a real nonzero reference/attribute in cycle detection.
    Key cursor{attribute, initial_value == nullptr};
    bool provenance_complete = true;
    for (std::size_t depth = 0; depth < visited.size(); ++depth) {
        charge(charge_work);
        for (std::size_t previous = 0; previous < depth; ++previous) {
            charge(charge_work);
            if (visited[previous] == cursor)
                throw apk::InspectError("AETHER_RESOURCES_INVALID", "styled-attributes",
                                        "Cyclic theme attribute or resource reference");
        }
        visited[depth] = cursor;
        apk::ResourceValue value;
        if (cursor.attribute || (initial_value && depth == 0)) {
            const auto selected = initial_value && depth == 0 ? *initial_value :
                merged_attribute(resources, layers, cursor.id, configuration, charge_work);
            if (!initial_value || depth != 0) result.value_origin = StyledValueOrigin::resource_table;
            if (selected.status == apk::StyleAttributeStatus::absent) {
                result.presence = StyledAttributePresence::absent;
                result.scalar = StyledScalarStatus::ready;
                return result;
            }
            if (selected.status == apk::StyleAttributeStatus::unresolved) {
                result.unresolved_style = selected.unresolved_style;
                return result;
            }
            result.native_flags |= selected.native_flags;
            provenance_complete = provenance_complete && selected.provenance_complete;
            result.source_id = selected.source_id;
            result.source_data = selected.source_data;
            result.source_style = selected.source_style;
            result.sdk_source = selected.sdk_source;
            // Theme.GetAttribute returns a literal with an empty configuration.
            // The defining bag's selection density is not the value density.
            result.density = initial_value && depth == 0 ? selected.density : 0;
            value = selected.value;
        } else {
            result.value_origin = StyledValueOrigin::resource_table;
            auto selected_resource = cursor.id;
            charge(charge_work);
            const auto found = resources.entries().find(cursor.id);
            if (found == resources.entries().end()) {
                if ((cursor.id >> 24) != 1) {
                    result.unresolved_resource = cursor.id;
                    return result;
                }
                const auto selected = embedded_sdk_resources().scalar(cursor.id, configuration, charge_work);
                if (selected.resource_id) selected_resource = selected.resource_id;
                result.native_flags |= selected.native_flags;
                result.source_id = 0;
                result.source_data = selected.source_data;
                result.sdk_source = true;
                result.density = selected.density;
                if (selected.status == SdkResourceStatus::unsupported && selected.value.type == 3 && !selected.complex) {
                    result.presence = StyledAttributePresence::present;
                    result.scalar = StyledScalarStatus::unsupported;
                    result.value = {0, 3};
                    result.resolved_resource = selected_resource;
                    result.provenance_complete = provenance_complete;
                    return result;
                }
                if (selected.status != SdkResourceStatus::found || selected.complex) {
                    result.unresolved_resource = cursor.id;
                    if (selected.status == SdkResourceStatus::unsupported || selected.complex)
                        result.scalar = StyledScalarStatus::unsupported;
                    return result;
                }
                value = selected.value;
            } else {
                // An actual complex resource is not a scalar NULL, regardless of
                // its optimized symbolic name or the bag marker's zero value type.
                if (found->second.complex) {
                    result.scalar = StyledScalarStatus::unsupported;
                    result.unresolved_resource = cursor.id;
                    return result;
                }
                result.native_flags |= found->second.native_flags;
                result.source_id = found->second.source_id;
                result.source_data = found->second.source_data;
                result.sdk_source = false;
                result.density = found->second.density;
                provenance_complete = provenance_complete && result.source_id &&
                    result.source_id <= resources.sources().size();
                value = {found->second.data, found->second.value_type};
            }
            result.resolved_resource = selected_resource;
        }
        if (value.type == 2) {
            cursor = {value.data, true}; // Resolve against the final layered theme.
            continue;
        }
        if (value.type == 1 && value.data) {
            if (!result.source_resource) result.source_resource = value.data;
            cursor = {value.data, false};
            continue;
        }
        if (value.type == 1) value = {0, 0}; // @null is not a missing resource ID.
        result.value = value;
        result.provenance_complete = provenance_complete;
        if (!value.type) {
            result.presence = StyledAttributePresence::absent;
            result.scalar = StyledScalarStatus::ready;
        } else if (value.type == 3) {
            result.presence = StyledAttributePresence::present;
            result.scalar = StyledScalarStatus::unsupported;
            result.value.data = 0; // A string-pool index must never outlive its table.
        } else if ((value.type >= 4 && value.type <= 6) || (value.type >= 0x10 && value.type <= 0x1f)) {
            result.presence = StyledAttributePresence::present;
            result.scalar = StyledScalarStatus::ready;
        } else {
            // Dynamic references/attributes cannot prove final presence without
            // their package remapping; unknown scalar encodings stay unsupported.
            result.presence = value.type == 7 || value.type == 8
                                  ? StyledAttributePresence::unresolved : StyledAttributePresence::present;
            result.scalar = StyledScalarStatus::unsupported;
        }
        return result;
    }
    throw apk::InspectError("AETHER_RESOURCES_LIMIT", "styled-attributes",
                            "Theme attribute or resource reference exceeds 32 levels");
}
} // namespace
apk::StyleAttributeResult select_theme_attribute(const apk::ResourceTable &resources,
    std::span<const ThemeStyleLayer> layers, std::uint32_t attribute,
    const apk::ResourceConfiguration &configuration,
    const std::function<void(std::uint64_t)> &charge_work) {
    auto selected = merged_attribute(resources, layers, attribute, configuration, charge_work);
    // Theme.GetAttribute supplies an empty value configuration; the defining
    // bag's selection density is not the literal value's density.
    selected.density = 0;
    return selected;
}
apk::StyleAttributeResult select_style_attribute(const apk::ResourceTable &resources,
    std::uint32_t style, std::uint32_t attribute,
    const apk::ResourceConfiguration &configuration,
    const std::function<void(std::uint64_t)> &charge_work) {
    const std::array layers{ThemeStyleLayer{style, true}};
    auto selected = merged_attribute(resources, layers, attribute, configuration, charge_work);
    // SDK35 SelectedValue(bag, entry) also initializes an empty configuration.
    // A later actual resource-reference selection supplies its own density.
    selected.density = 0;
    return selected;
}
StyledAttributeSnapshot resolve_styled_value(const apk::ResourceTable &resources,
    std::span<const ThemeStyleLayer> layers, const apk::StyleAttributeResult &selected,
    StyledValueOrigin origin, std::uint32_t source_resource_id,
    const apk::ResourceConfiguration &configuration,
    const std::function<void(std::uint64_t)> &charge_work) {
    return resolve_attribute_value(resources, layers, 0, configuration, charge_work,
                                   &selected, origin, source_resource_id);
}
StyledAttributeSnapshot resolve_styled_attribute(const apk::ResourceTable &resources,
    std::span<const ThemeStyleLayer> layers, std::uint32_t attribute,
    const apk::ResourceConfiguration &configuration,
    const std::function<void(std::uint64_t)> &charge_work) {
    return resolve_attribute_value(resources, layers, attribute, configuration, charge_work,
                                   nullptr, StyledValueOrigin::resource_table, 0);
}
} // namespace aether::android
