#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "descriptors.hpp"
#include <map>
namespace aether::bionic {
class NativeStdio {
  public:
    NativeStdio(a64::GuestMemory &memory,NativeDescriptors *files):memory_(memory),files_(files){}
    ~NativeStdio();
    a64::Fault invoke(unsigned,a64::Address,std::array<std::uint64_t,31>&);
  private:
    struct Stream {int fd;bool read,write,eof=false,error=false;unsigned direction=0;};
    a64::GuestMemory &memory_;NativeDescriptors *files_;
    std::map<a64::Address,Stream> streams_;a64::Address next_=0x3a000000;
    a64::Fault fail(a64::Address,std::array<std::uint64_t,31>&,unsigned,std::uint64_t);
};
}
