#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <array>
#include <memory>
#include <thread>
namespace aether::bionic {
class NativeThreads;
class NativeDescriptors;
enum class RuntimeOperation {
    socket_create, socket_operation, address_lookup, host_lookup, free_addresses,
    name_lookup, host_error, ioctl, lock_memory, advise_memory, query_schedule,
    query_affinity, set_affinity, clock_ticks, scale_double, control_message,
    set_times, filesystem_status, path_configuration, clock_sleep, change_mode, directory_fd
};
// The runtime exposes no network capability. Failed socket/DNS requests never
// contact a host resolver or reinterpret a private-file descriptor as a socket.
class NativeRuntimeServices {
  public:
    NativeRuntimeServices(a64::GuestMemory &, NativeThreads &, NativeDescriptors &, const a64::AppContext &);
    ~NativeRuntimeServices();
    a64::Fault invoke(RuntimeOperation, a64::ServiceState &, bool full_frame) noexcept;
    std::string_view rejection() const noexcept { return rejection_; }
  private:
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    NativeDescriptors &descriptors_;
    const a64::AppContext &app_;
    const std::thread::id owner_=std::this_thread::get_id();
    const std::uint64_t app_id_=app_.instance_id;
    struct HostError { std::weak_ptr<a64::ThreadRegisterState> owner; a64::Address tls=0; };
    std::array<HostError,64> host_errors_{};
    bool host_errors_owned_=false;
    std::string_view rejection_;
    a64::Address host_error();
};
}
