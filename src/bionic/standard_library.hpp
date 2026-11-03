#pragma once
#include "aether/bionic/guest_posix.hpp"
#include <array>
#include <thread>

namespace aether::bionic {
class NativeThreads;
enum class StandardLibraryOperation {
    random, seed_random, divide, divide_long_long, environment,
    address_error, signal_description, sort
};
// Original controlled-process implementation. Signal numbers/names and positive
// EAI values follow the installed Android NDK r30 AArch64 public ABI.
class NativeStandardLibrary final {
  public:
    NativeStandardLibrary(a64::GuestMemory &, NativeThreads &, const a64::AppContext &);
    ~NativeStandardLibrary();
    void runner(GuestPosixServices::PhdrRunner);
    a64::Address sys_signame_address();
    a64::Fault invoke(StandardLibraryOperation, a64::ServiceState &, bool full_frame) noexcept;
    std::string_view rejection() const noexcept { return rejection_; }
    bool switch_safe() const noexcept { return depth_ == 0; }
  private:
    static constexpr a64::Address constants_base = 0x3f900000, unknown_base = constants_base + 0x4000;
    static constexpr std::size_t constants_bytes = 0x4000;
    struct Unknown { std::int32_t signal = 0; bool owned = false; std::optional<a64::GuestMemory::WordIdentity> identity; };
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    const a64::AppContext &app_;
    const std::uint64_t app_id_;
    const std::thread::id owner_ = std::this_thread::get_id();
    GuestPosixServices::PhdrRunner runner_;
    std::array<a64::Address, 16> address_errors_{};
    std::array<a64::Address, 65> signals_{};
    std::array<Unknown, 64> unknown_{};
    std::optional<a64::GuestMemory::WordIdentity> constants_identity_;
    bool constants_owned_ = false;
    std::uint32_t random_state_ = 1;
    unsigned depth_ = 0;
    std::uint64_t comparisons_ = 0, remaining_ = 0, charged_ = 0;
    std::string_view rejection_;
    void constants();
    a64::Address signal_text(std::int32_t);
    a64::Fault sort(a64::ServiceState &, bool);
};
} // namespace aether::bionic
