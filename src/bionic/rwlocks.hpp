#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <map>
namespace aether::bionic {
class NativeRwLocks {
  public:
    explicit NativeRwLocks(a64::GuestMemory &memory):memory_(memory){}
    a64::Fault invoke(unsigned,std::uint32_t,std::array<std::uint64_t,31> &) noexcept;
    std::string_view rejection()const noexcept{return rejection_;}
  private:
    struct Held {std::uint32_t writer=0,total=0;bool preference=false;std::map<std::uint32_t,std::uint32_t> readers;};
    a64::GuestMemory &memory_;std::map<a64::Address,Held> held_;std::string_view rejection_;
    a64::Fault call(unsigned,std::uint32_t,std::array<std::uint64_t,31> &);
};
}
