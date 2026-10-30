#pragma once
#include "aether/bionic/guest_posix.hpp"
#include <array>
#include <string_view>

namespace aether::bionic {
class NativeThreads;
class NativePhdr {
  public:
    NativePhdr(a64::GuestMemory &memory,NativeThreads &threads,const a64::AppContext &app)
        :memory_(memory),threads_(threads),app_(app){}
    ~NativePhdr();
    void provider(GuestPosixServices::ProgramHeaderLookup);
    void runner(GuestPosixServices::PhdrRunner);
    a64::Fault invoke(a64::ServiceState &,bool full_frame) noexcept;
    std::string_view rejection()const noexcept{return rejection_;}
  private:
    static constexpr a64::Address cache_base=0x3e100000;
    static constexpr std::size_t slot_bytes=0x4000,slot_count=16;
    struct Cache {
        std::string name;
        a64::Address load_bias=0;
        std::vector<std::uint8_t> headers;
        bool owned=false;
    };
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    const a64::AppContext &app_;
    GuestPosixServices::ProgramHeaderLookup provider_;
    GuestPosixServices::PhdrRunner runner_;
    std::array<Cache,slot_count> cache_{};
    unsigned depth_=0;
    std::string_view rejection_;
    a64::Fault prepare(std::size_t,const elf::ProgramHeaderInfo &);
};
}
