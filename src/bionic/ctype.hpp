#pragma once
#include <cstdint>
namespace aether::bionic {
enum class CharacterOperation : unsigned {
    wide_control,alnum,alpha,blank,control,digit,graph,lower,print,punct,space,upper,xdigit,
    to_lower,to_upper
};
// Android int/wint_t arguments and int results occupy their low 32 bits.
std::uint32_t native_character(CharacterOperation,std::uint32_t) noexcept;
}
