#pragma once
#include <cstdint>

namespace aether::android {
// Actual viewport-fill placement: a private root NativeContentView, or a root
// SurfaceView/proven MATCH_PARENT FrameLayout chain. Never accepts HWNDs or dimensions
// asserted by the guest. Transport context/sequence are carried separately.
struct NativeSurfaceRequest {
    enum class Action : std::uint64_t { admit = 1, abandon = 2 };
    Action action = Action::admit;
    std::uint64_t view = 0, window_generation = 0, producer = 0;
    std::int32_t requested_orientation = -1;
    std::uint64_t root = 0; // Actual content root, distinct from the consumer leaf.
};
struct NativeSurfaceAdmission {
    // All-zero is the explicit deferred-admission result, not a zero-sized
    // producer. It is valid only for admit, and leaves existing custody intact.
    std::uint64_t producer = 0, backend_token = 0;
    std::uint32_t width = 0, height = 0;
    std::int32_t format = 0;
};
} // namespace aether::android
