#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "aether/android/display_configuration.hpp"
#include <functional>

namespace aether::android {
// App-owned opaque configuration values, with no guest-visible host pointers.
// Updating the source does not modify previously copied native snapshots.
class NativeConfiguration final {
  public:
    using ManagerValidator = std::function<bool(std::uint64_t)>;
    NativeConfiguration(a64::GuestMemory &, DisplayConfiguration, ManagerValidator);
    ~NativeConfiguration();
    NativeConfiguration(const NativeConfiguration &) = delete;
    NativeConfiguration &operator=(const NativeConfiguration &) = delete;
    void update(DisplayConfiguration);
    a64::Fault invoke(std::string_view, std::array<std::uint64_t, 31> &) noexcept;
    std::string_view last_error() const noexcept;
    void shutdown() noexcept;
  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::android
