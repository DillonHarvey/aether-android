#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <string_view>

namespace aether::bionic {
class NativeWideMemory {
  public:
    explicit NativeWideMemory(a64::GuestMemory &memory):memory_(memory){}
    // wmemcpy, wcslen, wmemmove, wmemcmp, wmemchr, wmemset.
    // Guest wchar_t is unsigned 32-bit; at most 1 MiB per accessed span.
    a64::Fault invoke(unsigned,std::array<std::uint64_t,31> &) noexcept;
    std::string_view rejection() const noexcept {return rejection_;}
  private:
    a64::GuestMemory &memory_;
    std::string_view rejection_;
};
}
