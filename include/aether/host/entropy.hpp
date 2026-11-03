#pragma once
#include <cstdint>
#include <span>
namespace aether::host {
// Operating-system cryptographic bytes, with no retained handle or weaker fallback.
// Empty output succeeds; unsupported sizes or RNG failure clear the output.
bool secure_random(std::span<std::uint8_t> output) noexcept;
// Exactly 128 bits from the operating system cryptographic RNG. No retained
// handle, application seed, callback, clock or weaker fallback is used.
// On failure output is cleared and must not be published as random data.
bool secure_random_128(std::span<std::uint8_t,16> output) noexcept;
} // namespace aether::host
