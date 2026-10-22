#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "aether/host/file_service.hpp"
#include <string>
namespace aether::bionic {
class NativeAccess {
  public:
    NativeAccess(a64::GuestMemory &,host::FileService *,std::string_view package);
    a64::Fault invoke(a64::Address error,std::array<std::uint64_t,31> &) noexcept;
  private:
    a64::GuestMemory &memory_;host::FileService *files_;std::string package_;
};
}
