#pragma once
#include <cstdint>
#include <string>
namespace aether::host {
// Current process/thread affinity on a single processor group, with no CPU-set
// overrides. Zero explicitly reports an unavailable/unsupported topology.
std::uint32_t available_processors() noexcept;
// The real host process identity, shared by its owned logical Java threads.
std::uint32_t current_process_id() noexcept;
// Validated self-image basename only. Never exposes a host directory or command line.
std::string current_process_image_basename();
} // namespace aether::host
