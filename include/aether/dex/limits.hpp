#pragma once
#include <cstdint>
namespace aether::dex {
inline constexpr std::uint64_t source_encoded_bytes = 1024ULL * 1024 * 1024;
inline constexpr std::uint64_t source_file_bytes = 64ULL * 1024 * 1024;
inline constexpr std::uint64_t decoded_file_bytes = 48ULL * 1024 * 1024;
} // namespace aether::dex
