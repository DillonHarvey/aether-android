#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <map>
namespace aether::bionic {
class NativeMutexes {
  public:
    explicit NativeMutexes(a64::GuestMemory &memory):memory_(memory){}
    a64::Fault invoke(unsigned operation,std::uint32_t tid,std::array<std::uint64_t,31> &) noexcept;
    a64::Fault validate_wait(a64::Address address, std::uint32_t tid) const;
    std::string_view rejection()const noexcept{return rejection_;}
  private:
    struct Held {std::uint32_t owner,depth,type;};
    a64::GuestMemory &memory_;std::map<a64::Address,Held> held_;std::string_view rejection_;
    a64::Fault call(unsigned,std::uint32_t,std::array<std::uint64_t,31> &);
};
}
