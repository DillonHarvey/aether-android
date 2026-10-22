#pragma once
#include <cstdint>
namespace aether {
// Host control flow for one logical thread, never a guest Java exception.
struct ThreadExit final {std::uint64_t value;};
}
