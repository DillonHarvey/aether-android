#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <array>
#include <string_view>

namespace aether::bionic {
class NativeThreads;
enum class MultibyteOperation {
    wcsnrtombs,wcsrtombs,wcrtomb,btowc,wctob,mbrtowc,mbrlen,mbsnrtowcs,mbsrtowcs,mbsinit,
    mbtowc,mblen,wctomb
};
// Original guest UTF-32/UTF-8 conversion. No host locale or character API.
// Each call may consume/produce at most 1 MiB; declared bounds remain full64.
class NativeMultibyte {
  public:
    NativeMultibyte(a64::GuestMemory &memory,NativeThreads &threads):memory_(memory),threads_(threads){}
    a64::Fault invoke(MultibyteOperation,std::array<std::uint64_t,31>&) noexcept;
    std::string_view rejection() const noexcept{return rejection_;}
  private:
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    // Underlying function-static states: wcsnrtombs, wcrtomb, mbrtowc,
    // mbrlen, mbsnrtowcs, mbtowc and wctomb. Their rt wrappers share the
    // underlying state; nonrestartable mblen instead uses a fresh local state.
    std::array<std::array<std::uint8_t,4>,7> private_states_{};
    std::string_view rejection_;
};
}
