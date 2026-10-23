#pragma once
#include "aether/a64/guest_cpu.hpp"
namespace aether::bionic {
class NativeAccess;
class NativeExecuting {
  public:
    NativeExecuting(a64::GuestMemory &memory,NativeAccess &access):memory_(memory),access_(access){}
    a64::Fault invoke(a64::Address error,a64::ServiceState &,bool full_frame) noexcept;
    std::string_view rejection() const noexcept {return rejection_;}
  private:
    a64::GuestMemory &memory_;NativeAccess &access_;
    std::string_view rejection_;
};
}
