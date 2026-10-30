#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "aether/host/native_log.hpp"
#include "aether/host/file_service.hpp"
#include <string>
namespace aether::bionic {
bool native_log_symbol(std::string_view) noexcept;
class NativeLogging {
  public:
    NativeLogging(a64::GuestMemory &,host::NativeLogSink *,std::string_view program_tag={});
    a64::Fault invoke(std::string_view,a64::ServiceState &,bool full_frame) noexcept;
    // syslog, vsyslog, openlog, closelog, setlogmask. State belongs to this app.
    a64::Fault invoke_syslog(unsigned,a64::ServiceState &,bool full_frame,
                             a64::Address error,host::FileService &descriptors) noexcept;
    std::string_view rejection()const noexcept{return rejection_view_;}
    bool write_stream(int,std::span<const std::uint8_t>) noexcept;
    std::uint64_t messages()const noexcept{return messages_;}
  private:
    a64::GuestMemory &memory_;host::NativeLogSink *sink_;
    std::string rejection_;std::string_view rejection_view_;std::uint64_t messages_=0;
    std::string syslog_default_;
    a64::Address syslog_tag_=0;
    std::uint32_t syslog_options_=0,syslog_mask_=0xff;
};
// Operations: vsnprintf, snprintf, __vsnprintf_chk, __snprintf_chk, __vsprintf_chk.
class NativeFormatting {
  public:
    explicit NativeFormatting(a64::GuestMemory &memory):memory_(memory){}
    a64::Fault invoke(unsigned,a64::ServiceState &,bool full_frame) noexcept;
    // swprintf/vswprintf: destination and format use the guest's uint32 wchar ABI.
    a64::Fault invoke_wide(bool va_list,a64::Address error,a64::ServiceState &,bool full_frame) noexcept;
    // Render asprintf/vasprintf arguments without guest output or frame changes.
    // Output commits only on success; allocation_failed distinguishes ENOMEM.
    a64::Fault render_allocated(bool variadic_list,a64::Address error,a64::ServiceState &,bool full_frame,
                               std::string &output,bool &allocation_failed) noexcept;
    // Render stream arguments only. Standard output uses format x0/arguments x1;
    // explicit FILE output uses format x1/arguments x2. No terminator is added.
    a64::Fault render_stream(bool variadic_list,bool standard,a64::Address error,
                            a64::ServiceState &,bool full_frame,std::string &output,
                            bool &allocation_failed) noexcept;
    std::string_view rejection()const noexcept{return rejection_;}
  private:
    a64::GuestMemory &memory_;std::string_view rejection_;
};

}
