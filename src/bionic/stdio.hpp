#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "descriptors.hpp"
#include <vector>
#include <map>
namespace aether::bionic {
class NativeStdio {
  public:
    NativeStdio(a64::GuestMemory &memory,NativeDescriptors &files,bool private_files):memory_(memory),files_(&files),private_files_(private_files){}
    static constexpr a64::Address standard_base=0x3e000000;
    void initialize();
    ~NativeStdio();
    // Existing stream operations 0-13; 14 ungetc, 15 fputc.
    a64::Fault invoke(unsigned,a64::Address,std::array<std::uint64_t,31>&);
    // Formatting uses owned streams and descriptors, never guest FILE fields.
    a64::Fault prepare_formatted(a64::Address handle,a64::Address error,
                                 std::array<std::uint64_t,31>&,bool &ready);
    a64::Fault write_formatted(a64::Address handle,a64::Address error,
                               std::span<const std::uint8_t>,std::array<std::uint64_t,31>&);
  private:
    static constexpr std::size_t pushback_limit=1024*1024;
    struct Stream {
        int fd;bool read,write,eof=false,error=false;unsigned direction=0;
        std::vector<std::uint8_t> pushed;
    };
    a64::GuestMemory &memory_;NativeDescriptors *files_;bool private_files_,standard_owned_=false;
    a64::Fault operate(unsigned,a64::Address,std::array<std::uint64_t,31>&);
    bool preflight_standard() const;
    bool sync_standard();
    std::map<a64::Address,Stream> streams_;a64::Address next_=0x3a000000;
    a64::Fault fail(a64::Address,std::array<std::uint64_t,31>&,unsigned,std::uint64_t);
};
}
