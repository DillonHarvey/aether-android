#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <string>
namespace aether::bionic {
class NativeDescriptors;
enum class RemovingOperation {remove,unlink,unlink_at,remove_directory};
class NativeRemoving {
  public:
    NativeRemoving(a64::GuestMemory &,NativeDescriptors &,std::string_view package);
    a64::Fault invoke(RemovingOperation,a64::Address error,std::array<std::uint64_t,31> &) noexcept;
    std::string_view rejection() const noexcept {return rejection_;}
  private:
    a64::GuestMemory &memory_;NativeDescriptors &descriptors_;std::string package_;
    std::string_view rejection_;
};
}
