#pragma once
#include "aether/security/worker.hpp"
#include <array>

namespace aether::security {
// Compiled first-party hostile-resource fixtures, selected only by the trusted test parent.
void run_resource_probe(HANDLE reader, HANDLE writer, std::uint64_t session, std::uint64_t scenario);
std::array<DWORD, 16> runtime_image_probe();
} // namespace aether::security
