#pragma once
#include "aether/a64/guest_cpu.hpp"

namespace aether::bionic {
// Android LP64 sscanf: guest pointers in x2..x7, then eight-byte stack slots.
// Floating, wide, allocating and positional conversions are explicitly unsupported.
a64::Fault scan_text(a64::GuestMemory &memory, a64::ServiceState &state, bool full_frame,
                     a64::Address error_address);
} // namespace aether::bionic
