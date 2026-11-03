#pragma once
#include "aether/dex/runtime.hpp"
#include <cstdint>
#include <string_view>

namespace aether::android {
// Artifact-specific metadata, not an implementation or universal API35 claim.
// The callback charges the caller's existing context and may throw unchanged.
dex::HostBootstrapClassPresence api35_bootstrap_class_presence(
    std::string_view descriptor, void *owner,
    void (*charge)(void *, std::uint64_t));
}
