#pragma once
#include "aether/apk/inspect.hpp"
#include <functional>
#include <optional>
#include <string_view>

namespace aether::android {
class SdkResourceCatalog;
// Borrowed immutable PE resource bytes. The executable owns their lifetime;
// no decoded table, private-file access or heap copy is created here.
apk::Bytes embedded_sdk_resource_bytes();
// Exact listed SDK members only, borrowed from the same immutable executable.
// No filesystem fallback or ownership transfer. An unlisted path returns none;
// an absent/malformed expected PE resource is a host build error. The caller's
// existing work ledger predebits bounded member-name comparisons.
std::optional<apk::Bytes> embedded_sdk_resource_file(
    std::string_view path, const std::function<void(std::uint64_t)> &charge_work);
// One immutable bounded directory per process; constructed once, never per attribute.
const SdkResourceCatalog &embedded_sdk_resources();
} // namespace aether::android
