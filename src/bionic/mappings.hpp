#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <map>

namespace aether::bionic {
enum class MappingOperation { map, unmap, protect };
class NativeMappings {
  public:
    explicit NativeMappings(a64::GuestMemory &memory):memory_(memory){}
    ~NativeMappings();
    a64::Fault invoke(MappingOperation,a64::Address error,std::array<std::uint64_t,31> &);
    std::string_view rejection() const noexcept {return rejection_;}
    std::uint64_t errors=0;
  private:
    static constexpr a64::Address first=0x70000000,limit=0x80000000;
    a64::GuestMemory &memory_;
    std::map<a64::Address,std::uint64_t> owned_;
    std::string_view rejection_;
    a64::Fault error(a64::Address,std::array<std::uint64_t,31> &,unsigned);
    a64::Fault reject(std::string_view);
    bool foreign(a64::Address,a64::Address) const;
    bool covered(a64::Address,a64::Address) const noexcept;
};
}
