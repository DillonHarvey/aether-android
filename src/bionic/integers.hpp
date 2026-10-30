#pragma once
#include "aether/a64/guest_cpu.hpp"
namespace aether::bionic {
// kind: unsigned64, signed64, atoi32, atol/atoll64. Wide input supports kinds
// 0/1, reading raw guest uint32 wchar units with the same ASCII grammar.
a64::Fault convert_integer(a64::GuestMemory&,a64::Address,unsigned,std::array<std::uint64_t,31>&,bool wide=false);
}
