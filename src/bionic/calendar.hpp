#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "aether/host/time_service.hpp"
#include <map>
namespace aether::bionic {
class NativeCalendar {
  public:
    NativeCalendar(a64::GuestMemory &memory,const host::TimeService &time):memory_(memory),time_(time){}
    ~NativeCalendar();
    a64::Fault strftime(std::array<std::uint64_t,31> &,a64::Address error);
    a64::Fault localtime(std::array<std::uint64_t,31> &,a64::Address error);
  private:
    a64::GuestMemory &memory_;
    const host::TimeService &time_;
    std::map<std::string,a64::Address> zones_;
};
}
