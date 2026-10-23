#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "aether/host/file_service.hpp"
#include <string>
namespace aether::bionic {
class NativeAccess {
  public:
    NativeAccess(a64::GuestMemory &,host::FileService *,std::string_view package);
    a64::Fault invoke(a64::Address error,std::array<std::uint64_t,31> &) noexcept;
    // Only recognized app-private namespaces are authoritative for exec probes.
    // Success means eligible for a future image loader, never execution success.
    host::FileResult probe_executable(std::string_view path) noexcept;
    host::FileResult probe_link_path(std::string_view path) noexcept;
  private:
    host::FileResult query(std::string path,std::uint32_t mode,bool execution);
    a64::GuestMemory &memory_;host::FileService *files_;std::string package_;
};
}
