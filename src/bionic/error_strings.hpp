#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <array>
#include <string_view>

namespace aether::bionic {
class NativeThreads;
class NativeErrorStrings {
  public:
    NativeErrorStrings(a64::GuestMemory &memory,NativeThreads &threads):memory_(memory),threads_(threads){}
    ~NativeErrorStrings();
    NativeErrorStrings(const NativeErrorStrings&)=delete;
    NativeErrorStrings &operator=(const NativeErrorStrings&)=delete;
    a64::Fault invoke(std::array<std::uint64_t,31> &) noexcept;
    std::string_view rejection() const noexcept {return rejection_;}
  private:
    struct Slot {a64::Address tls=0;std::uint32_t tid=0;};
    static constexpr a64::Address constants_base=0x3d000000,unknown_base=0x3d002000;
    static constexpr std::size_t constants_size=8192,unknown_size=64;
    a64::GuestMemory &memory_;NativeThreads &threads_;
    std::array<Slot,33> slots_{};
    bool constants_owned_=false,unknown_owned_=false;
    std::string_view rejection_;
    a64::Fault initialize_constants() noexcept;
};
}
