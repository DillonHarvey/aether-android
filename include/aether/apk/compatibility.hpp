#pragma once
#include "aether/apk/inspect.hpp"

namespace aether::apk {
// Format admission is not a promise that every referenced Android API exists.
// Execution still requires a confirmed installation and a verified LPAC worker.
struct Compatibility {
    bool installable = false;
    std::string reason;
    std::vector<std::string> dex_files; // Canonical numeric order, only on successful admission.
};
Compatibility execution_compatibility(const InspectResult &package);
} // namespace aether::apk
