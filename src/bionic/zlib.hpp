#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <memory>
namespace aether::bionic {
class NativeZlib {
  public:
    NativeZlib(a64::GuestMemory &,a64::Address allocate,a64::Address release);
    ~NativeZlib();
    a64::Fault invoke(unsigned operation,std::array<std::uint64_t,31> &) noexcept;
    std::string_view rejection()const noexcept;
  private:
    struct Impl;std::unique_ptr<Impl> impl_;
};
}
