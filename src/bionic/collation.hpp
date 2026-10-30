#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <array>
#include <string_view>

namespace aether::bionic {
// Bionic's C-only LC_COLLATE profile; locale aliases use the same operations.
class NativeCollation {
  public:
    explicit NativeCollation(a64::GuestMemory &memory):memory_(memory){}
    // strcoll, strxfrm, wcscoll, wcsxfrm. No errno or locale-state effects.
    a64::Fault invoke(unsigned,std::array<std::uint64_t,31> &) noexcept;
    std::string_view rejection() const noexcept {return rejection_;}
  private:
    a64::GuestMemory &memory_;
    std::string_view rejection_;
};
}
