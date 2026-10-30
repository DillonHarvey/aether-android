#pragma once
#include "aether/a64/guest_cpu.hpp"

namespace aether::bionic {
// kind: strtof/strtod/strtold, wcstof/wcstod/wcstold, atof.
a64::Fault convert_floating(a64::GuestMemory &,a64::Address error,unsigned kind,a64::ServiceState &);
}
