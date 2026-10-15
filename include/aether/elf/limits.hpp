#pragma once
#include <cstddef>
#include <cstdint>

namespace aether::elf {
inline constexpr std::size_t native_graph_modules = 16;
inline constexpr std::uint64_t streamed_native_bytes = 128ULL * 1024 * 1024;
} // namespace aether::elf
