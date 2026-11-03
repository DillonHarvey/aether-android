#pragma once
#include "aether/bionic/guest_posix.hpp"
#include <array>
#include <cstddef>
#include <string_view>

namespace aether::bionic {
class NativeThreads;
class NativeOnce {
  public:
    NativeOnce(a64::GuestMemory &memory,NativeThreads &threads,const a64::AppContext &app)
        :memory_(memory),threads_(threads),app_(app){}
    void runner(GuestPosixServices::OnceRunner value);
    a64::Fault invoke(a64::ServiceState &,bool full_frame) noexcept;
    // Authenticated guest shim: claim x0=control,x1=initializer returns 1 with
    // ticket x2, or completed 0. Complete receives x0=control,x1=ticket.
    a64::Fault claim(a64::ServiceState &,bool full_frame,bool allow_deferred) noexcept;
    a64::Fault complete(a64::ServiceState &,bool full_frame) noexcept;
    void retire(std::uint32_t id,a64::Address tls,const std::shared_ptr<a64::ThreadRegisterState> &) noexcept;
    std::string_view rejection() const noexcept{return rejection_;}
    // Retained guest records own values only. Legacy runner scopes still bar switching.
    bool switch_safe() const noexcept { return depth_==0; }
  private:
    struct Record {
        a64::Address control=0,tls=0,mapping_base=0;
        std::size_t mapping_size=0;
        a64::Permission permissions=a64::Permission::none;
        std::uint32_t owner=0;
        unsigned depth=0;
        bool occupied=false,running=false;
        std::string_view failure;
        bool guest=false;
        std::uint64_t ticket=0,invocation=0;
        a64::Address shim_stack=0,stack_top=0;
        std::shared_ptr<a64::ThreadRegisterState> registers;
    };
    struct DeferredWait;
    void abandon_dead_owners() noexcept;
    a64::Fault validate_control(const Record &,std::uint32_t expected) const noexcept;
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    const a64::AppContext &app_;
    GuestPosixServices::OnceRunner runner_;
    std::array<Record,64> records_{};
    unsigned depth_=0;
    std::uint64_t next_ticket_=1;
    std::string_view rejection_;
};
}
