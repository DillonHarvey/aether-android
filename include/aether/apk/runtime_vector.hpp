#pragma once
#include "aether/apk/runtime_path.hpp"
#include "aether/apk/runtime_xml.hpp"
#include <optional>

namespace aether::apk {
struct RuntimeVectorScalar {
    std::uint8_t type = 0;
    std::uint32_t data = 0;
};
// Resolves an actual resource/theme reference in its owning source and Theme.
// It must not invoke guest code. Returned references are not silently followed;
// the caller must supply the final supported scalar or throw its actual cause.
// The closure accumulates every resolved chain's source/configuration flags in
// the enclosing drawable binding; type/data alone do not carry that provenance.
using RuntimeVectorResolver =
    std::function<RuntimeVectorScalar(std::uint8_t type, std::uint32_t data)>;
inline constexpr std::size_t runtime_vector_root = SIZE_MAX;
enum class RuntimeVectorNodeKind : std::uint8_t { group, path, clip };
struct RuntimeVectorNode {
    RuntimeVectorNodeKind kind = RuntimeVectorNodeKind::path;
    // Nodes are in XML preorder. Root children use runtime_vector_root.
    std::size_t parent = runtime_vector_root;
    std::size_t xml_node = 0, name_offset = 0, name_length = 0;
    RuntimePath path;
    double rotation = 0, pivot_x = 0, pivot_y = 0;
    double scale_x = 1, scale_y = 1, translate_x = 0, translate_y = 0;
    // Straight ARGB. Missing fill/stroke both have Android's transparent default.
    std::uint32_t fill_color = 0, stroke_color = 0;
    double fill_alpha = 1, stroke_alpha = 1, stroke_width = 0, miter_limit = 4;
    std::uint8_t fill_type = 0, line_cap = 0, line_join = 0;
};
struct RuntimeVector {
    // Authentic resolved TYPE_DIMENSION data; convert using actual Resources
    // metrics when binding an instance. These are not viewport/pixel dimensions.
    std::uint32_t width_dimension = 0, height_dimension = 0;
    double viewport_width = 0, viewport_height = 0, alpha = 1;
    std::optional<std::uint32_t> tint;
    // Supported tint mode is SRC_IN only; absent tint has no compositing effect.
    bool auto_mirrored = false;
    std::size_t name_offset = 0, name_length = 0;
    std::vector<RuntimeVectorNode> nodes;
    std::vector<char> names;
    // Dynamic owned capacities only. Enclosing carrier accounts sizeof(*this).
    std::size_t storage_bytes() const noexcept;
};
// Original runtime vector parser, independent of frozen icon rendering.
// The owned model retains no XML, resolver or borrowed string references.
// working_bytes EXCLUDES the caller-owned document/input/callback/resolver and
// includes fixed parser/model storage plus all model/path growth peaks. Supply
// the remainder of the same host-owned aggregate admission, never a new budget.
// Work is charged through the required host callback; it may throw, must not
// reenter guests or mutate document, and parsing must not be replayed to refresh
// its allowance. Retained finite literals are not proof of finite interpreted
// relative endpoints, reflected controls, transforms or raster bounds; the
// eventual geometry consumer must check those derived operations separately.
// Nondefault trim, gradients, unknown effects and unsupported scalar types fail
// precisely. This model is not evidence of Canvas/raster/presentation support.
// InspectError codes AETHER_VECTOR_INVALID/_UNSUPPORTED/_LIMIT; bad_alloc and
// resolver/work exceptions propagate without producing a fallback drawable.
RuntimeVector parse_runtime_vector(const RuntimeXmlDocument &document,
                                  const RuntimeVectorResolver &resolve,
                                  std::size_t working_bytes,
                                  const std::function<void(std::uint64_t)> &charge_work);
} // namespace aether::apk
