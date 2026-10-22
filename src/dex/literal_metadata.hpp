#pragma once
#include "aether/dex/runtime.hpp"

namespace aether::dex {
// Bootstrap identities required by class literals. This catalogue supplies no
// object state, constructors, method bodies or host resource access.
std::optional<HostClass> literal_metadata_class(std::string_view descriptor);
}
