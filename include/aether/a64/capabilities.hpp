#pragma once
#include <cstdint>

namespace aether::a64 {
// Conservative ARM64 Linux ABI capability words for the GuestCpu translator.
// Baseline scalar FP and Advanced SIMD have original execution fixtures. Optional
// ISA features require reviewed guest support before advertisement, independently
// of the x86 host CPU. In particular LSE atomics and ID-register CPUID are absent.
inline constexpr std::uint64_t guest_hwcap = (std::uint64_t{1} << 0) | (std::uint64_t{1} << 1);
inline constexpr std::uint64_t guest_hwcap2 = 0;
}
