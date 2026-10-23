#pragma once
#include "aether/a64/guest_cpu.hpp"
namespace aether::bionic {
a64::Fault get_system_property(a64::GuestMemory &,std::array<std::uint64_t,31> &) noexcept;
}
