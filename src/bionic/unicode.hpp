#pragma once
#include <cstdint>

namespace aether::bionic {
enum class UnicodeOperation : unsigned {
    alnum,alpha,blank,digit,graph,lower,print,punct,space,upper,xdigit,to_lower,to_upper
};
// Pure Android low32 wint_t -> normalized predicate / single code point.
std::uint32_t native_unicode(UnicodeOperation,std::uint32_t) noexcept;
}
