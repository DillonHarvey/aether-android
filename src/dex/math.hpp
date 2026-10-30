#pragma once
#include "aether/dex/runtime.hpp"

namespace aether::dex {
// Original Java Math floating operations. Exact bit operations do not depend on
// host rounding/denormal modes. Transcendentals use the Windows C++ math backend
// under a scoped nearest-even, gradual-underflow environment, never StrictMath.
std::optional<Value> invoke_math(std::string_view name, std::string_view signature,
                                 std::span<const Value> arguments);
}
