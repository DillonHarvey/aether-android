#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "aether/host/native_log.hpp"
#include <string>
namespace aether::bionic {
bool native_log_symbol(std::string_view) noexcept;
class NativeLogging {
  public:
    NativeLogging(a64::GuestMemory &,host::NativeLogSink *);
    a64::Fault invoke(std::string_view,a64::ServiceState &,bool full_frame) noexcept;
    std::string_view rejection()const noexcept{return rejection_view_;}
    bool write_stream(int,std::span<const std::uint8_t>) noexcept;
    std::uint64_t messages()const noexcept{return messages_;}
  private:
    a64::GuestMemory &memory_;host::NativeLogSink *sink_;
    std::string rejection_;std::string_view rejection_view_;std::uint64_t messages_=0;
};
// Operations: vsnprintf, snprintf, __vsnprintf_chk, __snprintf_chk, __vsprintf_chk.
class NativeFormatting {
  public:
    explicit NativeFormatting(a64::GuestMemory &memory):memory_(memory){}
    a64::Fault invoke(unsigned,a64::ServiceState &,bool full_frame) noexcept;
    std::string_view rejection()const noexcept{return rejection_;}
  private:
    a64::GuestMemory &memory_;std::string_view rejection_;
};

}
