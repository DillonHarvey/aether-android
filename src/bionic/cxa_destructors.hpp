#pragma once
#include "aether/bionic/guest_posix.hpp"
#include <string_view>
#include <thread>
#include <vector>

namespace aether::bionic {
class NativeThreads;
// App-owned C++ termination callbacks. Guest values never become host pointers.
class NativeCxaDestructors {
  public:
    NativeCxaDestructors(a64::GuestMemory &memory,NativeThreads &threads,const a64::AppContext &app)
        :memory_(memory),threads_(threads),app_(app){}
    void runner(GuestPosixServices::CxaRunner);
    a64::Fault register_callback(std::array<std::uint64_t,31> &) noexcept;
    a64::Fault finalize(a64::ServiceState &,bool full_frame) noexcept;
    std::string_view rejection()const noexcept{return rejection_;}
  private:
    struct Record {a64::Address function,argument,dso;};
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    const a64::AppContext &app_;
    GuestPosixServices::CxaRunner runner_;
    std::vector<Record> records_;
    std::thread::id owner_=std::this_thread::get_id();
    unsigned depth_=0;
    std::uint64_t charged_=0,attempts_=0,scans_=0;
    a64::Fault campaign_fault_=a64::Fault::none;
    std::string_view rejection_,campaign_reason_;
    a64::Fault reject(std::string_view,a64::Fault=a64::Fault::unsupported_service) noexcept;
    a64::Fault guard() noexcept;
};
}
