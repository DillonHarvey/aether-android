#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "aether/host/time_service.hpp"
#include <map>
namespace aether::bionic {
class NativeLocale;
class NativeCalendar {
  public:
    NativeCalendar(a64::GuestMemory &memory,const host::TimeService &time):memory_(memory),time_(time){}
    ~NativeCalendar();
    a64::Fault strftime(std::array<std::uint64_t,31> &,a64::Address error);
    a64::Fault localtime(std::array<std::uint64_t,31> &,a64::Address error);
    a64::Fault localtime_static(std::array<std::uint64_t,31> &,a64::Address error);
    a64::Fault gmtime(std::array<std::uint64_t,31> &,a64::Address error);
    a64::Fault gmtime_r(std::array<std::uint64_t,31> &,a64::Address error);
    a64::Fault ctime(std::array<std::uint64_t,31> &,a64::Address error);
    a64::Fault mktime(std::array<std::uint64_t,31> &,a64::Address error);
    a64::Fault difftime(a64::ServiceState &) noexcept;
    a64::Fault tzset(std::array<std::uint64_t,31> &,a64::Address error);
    a64::Fault strptime(std::array<std::uint64_t,31> &,a64::Address error);
    a64::Fault strftime_l(std::array<std::uint64_t,31> &,a64::Address error,const NativeLocale &);
    std::string_view rejection() const noexcept {return rejection_;}
  private:
    static constexpr a64::Address scratch_base=0x39040000;
    a64::GuestMemory &memory_;
    const host::TimeService &time_;
    std::map<std::string,a64::Address> zones_;
    bool scratch_owned_=false;
    std::string_view rejection_;
    void ensure_scratch();
    a64::Address zone_name(std::string_view);
    a64::Fault store_tm(const host::LocalTime &,a64::Address);
    a64::Fault convert(std::array<std::uint64_t,31> &,a64::Address,bool utc,bool reentrant);
    a64::Fault fail(std::array<std::uint64_t,31> &,a64::Address,unsigned,std::uint64_t result=0);
};
}
