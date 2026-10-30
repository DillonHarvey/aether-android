#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <string_view>

namespace aether::bionic {
class NativeAbortMessage {
  public:
    NativeAbortMessage(a64::GuestMemory &memory,const a64::AppContext &app)
        :memory_(memory),app_(app){}
    a64::Fault invoke(std::array<std::uint64_t,31> &) noexcept;
    std::string_view rejection()const noexcept{return rejection_;}
  private:
    a64::GuestMemory &memory_;
    const a64::AppContext &app_;
    std::string_view rejection_;
};
}
