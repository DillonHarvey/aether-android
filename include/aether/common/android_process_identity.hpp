#pragma once
#include <cstdint>

namespace aether {
// Virtual Android identifiers, not Windows identities or broker authority.
// This preserves the existing native per-instance UID policy exactly.
struct AndroidProcessIdentity {
    std::uint32_t uid = 0, user_id = 0;
};
constexpr AndroidProcessIdentity virtual_android_process_identity(std::uint64_t instance_id) noexcept {
    const auto uid = 10000u + static_cast<std::uint32_t>(instance_id % 10000u);
    return {uid, uid / 100000u}; // Android UserHandle.PER_USER_RANGE.
}
constexpr bool valid_virtual_android_process_identity(AndroidProcessIdentity value) noexcept {
    return value.uid >= 10000u && value.uid < 20000u && value.user_id == value.uid / 100000u;
}
} // namespace aether
