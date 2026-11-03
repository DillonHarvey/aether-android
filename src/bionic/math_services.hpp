#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <span>
#include <string_view>

namespace aether::bionic {
class NativeThreads;
// Original full-frame Android LP64 libm adapter. Host math values never contain
// guest pointers. The static name order is the operation number contract.
class NativeMathServices {
  public:
    NativeMathServices(a64::GuestMemory &memory,NativeThreads &threads):memory_(memory),threads_(threads){}
    static std::span<const std::string_view> names() noexcept;
    a64::Fault invoke(unsigned,a64::ServiceState &,bool full_frame) noexcept;
    std::string_view rejection() const noexcept{return rejection_;}
  private:
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    std::string_view rejection_;
};
}
