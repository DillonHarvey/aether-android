#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "aether/elf/guest_loader.hpp"
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace aether::bionic {
struct DynamicLinkCallbacks {
    std::function<void(std::string_view)> open;
    std::function<std::optional<elf::GuestSymbol>(std::string_view,std::string_view)> lookup;
};
// Trusted guest execution control, distinct from a recoverable module/source error.
struct DynamicLinkExecution {a64::Fault fault;};
// Diagnostic class only, never an exception message or a host path.
struct DynamicLinkSourceError {std::string code;};
}
