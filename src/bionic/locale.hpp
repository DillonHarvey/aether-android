#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <array>
#include <string_view>

namespace aether::bionic {
class NativeThreads;
class NativeLocale {
  public:
    static constexpr std::uint64_t global_locale=UINT64_MAX;
    static constexpr a64::Address objects_base=0x3b000000,objects_limit=0x3b100000,
        constants_base=0x3b200000,lconv_address=constants_base,
        c_name_address=constants_base+0x100,utf8_name_address=constants_base+0x110;
    NativeLocale(a64::GuestMemory &memory,NativeThreads &threads):memory_(memory),threads_(threads){}
    ~NativeLocale();
    NativeLocale(const NativeLocale&)=delete;
    NativeLocale &operator=(const NativeLocale&)=delete;
    void initialize();
    // newlocale, duplocale, freelocale, uselocale, setlocale, localeconv, MB_CUR_MAX.
    a64::Fault invoke(unsigned,std::array<std::uint64_t,31>&) noexcept;
    std::string_view rejection() const noexcept{return rejection_;}
  private:
    struct Object {a64::Address address=0;unsigned mode=0;};
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    std::array<Object,64> objects_{};
    a64::Address next_=objects_base;
    unsigned global_mode_=4;
    bool constants_owned_=false,initialized_=false;
    std::string_view rejection_;
    Object *object(a64::Address) noexcept;
    a64::Fault fail(std::array<std::uint64_t,31>&,unsigned) noexcept;
    a64::Fault allocate(std::array<std::uint64_t,31>&,unsigned);
};
}
