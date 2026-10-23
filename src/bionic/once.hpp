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
    std::string_view rejection() const noexcept{return rejection_;}
  private:
    struct Record {
        a64::Address control=0,tls=0,mapping_base=0;
        std::size_t mapping_size=0;
        a64::Permission permissions=a64::Permission::none;
        std::uint32_t owner=0;
        unsigned depth=0;
        bool occupied=false,running=false;
        std::string_view failure;
    };
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    const a64::AppContext &app_;
    GuestPosixServices::OnceRunner runner_;
    std::array<Record,64> records_{};
    unsigned depth_=0;
    std::string_view rejection_;
};
}
