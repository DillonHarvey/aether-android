#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "descriptors.hpp"
#include <string>
namespace aether::bionic {
class NativeRenaming final {
  public:
    NativeRenaming(a64::GuestMemory &memory,NativeDescriptors &descriptors,std::string_view package)
        :memory_(memory),descriptors_(descriptors),package_(package){}
    a64::Fault invoke(bool at,a64::Address error,std::array<std::uint64_t,31> &) noexcept;
  private:
    a64::GuestMemory &memory_;NativeDescriptors &descriptors_;std::string package_;
};
}
