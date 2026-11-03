#pragma once
#include "aether/android/display_configuration.hpp"
#include <cstdint>
#include <optional>

namespace aether::android {
// Host geometry is selected before resource composition. Binding that immutable
// lease to a later real View tree grants neither rendering nor Surface custody.
enum class ViewportPhase : std::uint64_t { launch_geometry = 1, bind_content = 2 };

struct ViewportIdentity {
    std::uint64_t activity = 0, content = 0, window_generation = 0;
    // Successful logical Window content commit, including same-root
    // reattachment. This is neither physical attachment-callback completion,
    // host visibility, semantic View mutation nor a completed-frame revision.
    std::uint64_t attachment_revision = 0;
    bool operator==(const ViewportIdentity &) const = default;
};

struct ViewportRequest {
    ViewportPhase phase = ViewportPhase::launch_geometry;
    std::int32_t requested_orientation = -1;
    // Launch requests have zero revision/identity. Binding supplies the actual
    // tree identity and the previously admitted, nonzero geometry revision.
    std::uint64_t geometry_revision = 0;
    ViewportIdentity identity;
};

struct ViewportAdmission {
    std::uint64_t geometry_revision = 0;
    // Physical pixels in the actual letterboxed viewport, with local origin
    // (0,0). The host retains the real origin/clip under geometry_revision.
    std::uint32_t width_px = 0, height_px = 0, host_dpi = 0;
    // Raw host DPI differs from Android density_dpi. Zero defaults are not
    // display facts: the host must return its authenticated derived values.
    DisplayConfiguration configuration{0, 0, 0, 0};
    // Launch acknowledgement has no Activity/tree yet. Binding echoes the
    // actual identity and retains exactly the original geometry/configuration.
    ViewportIdentity identity;
    // Explicit host virtual-display policy, not a desktop/monitor inference.
    // Absence is unknown; it must never acquire an implicit false default.
    std::optional<bool> has_navigation_bar;
};
} // namespace aether::android
