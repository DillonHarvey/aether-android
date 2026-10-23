#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "descriptors.hpp"
#include <string>
namespace aether::bionic {
enum class OpeningOperation {open,open_at,checked_open_at,access_at};
class NativeOpening {
  public:
    NativeOpening(a64::GuestMemory &memory,NativeDescriptors &descriptors,std::string_view package)
        :memory_(memory),descriptors_(descriptors),package_(package){}
    a64::Fault invoke(OpeningOperation,a64::Address error,std::array<std::uint64_t,31> &) noexcept;
    std::string_view rejection() const noexcept {return rejection_;}
  private:
    a64::GuestMemory &memory_;NativeDescriptors &descriptors_;std::string package_;
    std::string_view rejection_;
};
}
