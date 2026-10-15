#pragma once
#include <cstdint>

namespace aether::graphics {
// Trusted parent-to-renderer control data only. This is not part of the guest GLES channel.
// The handle is an explicitly duplicated, unnamed NT texture handle in the receiver.
struct SharedWindowGrant {
    static constexpr std::uint64_t token_prefix = 0xb6e0000000000000ULL;
    std::uint64_t token = 0, generation = 0, handle = 0;
    std::uint32_t width = 0, height = 0, luid_low = 0, luid_high = 0;
    bool valid() const noexcept {
        return (token & 0xffff000000000000ULL) == token_prefix && (token & 0x0000ffffffffffffULL) &&
               generation && generation <= 65535 && handle && handle != UINT64_MAX && width &&
               width <= 1024 && height && height <= 1024;
    }
};
} // namespace aether::graphics
