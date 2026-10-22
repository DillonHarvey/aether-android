#pragma once
#include <cstdint>
#include <span>
namespace aether::host {
// Exactly 128 bits from the operating system cryptographic RNG. No retained
// handle, application seed, callback, clock or weaker fallback is used.
// On failure output is cleared and must not be published as random data.
bool secure_random_128(std::span<std::uint8_t,16> output) noexcept;
} // namespace aether::host
