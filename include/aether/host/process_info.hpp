#pragma once
#include <cstdint>
namespace aether::host {
// Current process/thread affinity on a single processor group, with no CPU-set
// overrides. Zero explicitly reports an unavailable/unsupported topology.
std::uint32_t available_processors() noexcept;
// The real host process identity, shared by its owned logical Java threads.
std::uint32_t current_process_id() noexcept;
} // namespace aether::host
