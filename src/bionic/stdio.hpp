#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "descriptors.hpp"
#include <vector>
#include <map>
namespace aether::bionic {
class NativeLocale;
class NativeStdio {
  public:
    NativeStdio(a64::GuestMemory &memory,NativeDescriptors &files,bool private_files,NativeLocale *locales=nullptr):memory_(memory),files_(&files),private_files_(private_files),locales_(locales){}
    static constexpr a64::Address standard_base=0x3e000000;
    void initialize();
    ~NativeStdio();
    // Existing 0-15; 16 fputs,17 puts,18 fgetpos,19 fsetpos,20 fdopen,
    // 21 freopen,22 fputwc,23 ungetwc,24 fgetwc (also getwc).
    a64::Fault invoke(unsigned,a64::Address,std::array<std::uint64_t,31>&);
    struct WriteCompletion {
        a64::Fault fault=a64::Fault::none;
        bool broken_pipe=false,continuation_unavailable=false;
        std::uint64_t committed_bytes=0;
    };
    // Full-context adapters consume these effects only after stream metadata,
    // errno and the actual stdio result have been committed. No guest progress
    // or signal handler runs while a Stream reference is borrowed.
    WriteCompletion invoke_output(unsigned,a64::Address,std::array<std::uint64_t,31>&);
    // Formatting uses owned streams and descriptors, never guest FILE fields.
    a64::Fault prepare_formatted(a64::Address handle,a64::Address error,
                                 std::array<std::uint64_t,31>&,bool &ready);
    a64::Fault write_formatted(a64::Address handle,a64::Address error,
                               std::span<const std::uint8_t>,std::array<std::uint64_t,31>&);
    WriteCompletion write_formatted_output(a64::Address handle,a64::Address error,
                                           std::span<const std::uint8_t>,std::array<std::uint64_t,31>&);
  private:
    static constexpr std::size_t pushback_limit=1024*1024;
    struct Stream {
        int fd;bool read,write,eof=false,error=false;unsigned direction=0;
        std::vector<std::uint8_t> pushed;
        int orientation=0; // 0 unoriented, -1 byte, +1 wide.
        unsigned encoding=0,wide_used=0,wide_expected=0;
        std::uint32_t wide_point=0,wide_minimum=0;
        std::vector<std::uint32_t> wide_pushed;
    };
    a64::GuestMemory &memory_;NativeDescriptors *files_;bool private_files_,standard_owned_=false;
    NativeLocale *locales_;
    a64::Fault orient(Stream &,bool wide);
    a64::Fault invoke_impl(unsigned,a64::Address,std::array<std::uint64_t,31>&,WriteCompletion *);
    a64::Fault operate(unsigned,a64::Address,std::array<std::uint64_t,31>&,WriteCompletion *);
    a64::Fault write_formatted_impl(a64::Address,a64::Address,std::span<const std::uint8_t>,
                                   std::array<std::uint64_t,31>&,WriteCompletion *);
    NativeDescriptors::WriteOutcome write_output(int,std::span<const std::uint8_t>,WriteCompletion *);
    bool preflight_standard() const;
    bool sync_standard();
    std::map<a64::Address,Stream> streams_;a64::Address next_=0x3a000000;
    a64::Fault fail(a64::Address,std::array<std::uint64_t,31>&,unsigned,std::uint64_t);
};
}
