#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "aether/apk/package.hpp"
#include <functional>

namespace aether::android {
struct NativeAssetManagerAccess;
// Single host-owner adapter. The immutable package backing and guest memory
// outlive this object. Values returned to guests are opaque IDs or guest copies.
class NativeAssets final {
  public:
    NativeAssets(a64::GuestMemory &, const apk::PackageView &,
                 std::function<bool(a64::Address, std::uint64_t)> validate_java);
    NativeAssets(a64::GuestMemory &, const apk::PackageView &, NativeAssetManagerAccess);
    ~NativeAssets();
    NativeAssets(const NativeAssets &) = delete;
    NativeAssets &operator=(const NativeAssets &) = delete;
    a64::Fault invoke(std::string_view name, std::array<std::uint64_t, 31> &) noexcept;
    std::string_view last_error() const noexcept;
    // Observation only: no publication, JNI resolution or package authority.
    bool owns_manager(std::uint64_t) const noexcept;
    // Trusted lifecycle publication still authenticates the current JNI scope
    // and the canonical app manager through the same bound validator.
    std::uint64_t publish_manager(a64::Address environment, std::uint64_t java_manager);
    void shutdown();

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::android
