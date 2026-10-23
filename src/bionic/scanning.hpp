#pragma once
#include "aether/a64/guest_cpu.hpp"

namespace aether::bionic {
// Android LP64 sscanf: guest pointers in x2..x7, then eight-byte stack slots.
// vsscanf uses a copied, indirect AAPCS64 va_list; all destinations use GP slots.
// Floating, wide, allocating and positional conversions are explicitly unsupported.
a64::Fault scan_text(a64::GuestMemory &memory, a64::ServiceState &state, bool full_frame,
                     a64::Address error_address,bool argument_list=false);
} // namespace aether::bionic
