#pragma once
#include "aether/dex/image.hpp"
#include <array>

namespace aether::dex {
enum class Format {
    unsupported,
    f10x,
    f12x,
    f22x,
    f32x,
    f11x,
    f11n,
    f21s,
    f31i,
    f21h,
    f51l,
    f21c,
    f31c,
    f22c,
    f23x,
    f35c,
    f3rc,
    f10t,
    f20t,
    f30t,
    f31t,
    f22t,
    f21t,
    f22s,
    f22b
};
struct Opcode {
    std::string_view name;
    Format format = Format::unsupported;
    std::uint8_t width = 0;
};
const std::array<Opcode, 256> &opcode_registry() noexcept;
struct Instruction {
    std::uint32_t pc = 0, next = 0, a = 0, b = 0, c = 0, index = 0;
    std::uint8_t opcode = 0;
    std::uint64_t literal = 0;
    std::int32_t branch = 0;
    std::int32_t switch_first = 0;
    std::vector<std::uint32_t> switch_targets;
    std::vector<std::uint16_t> arguments;
};
struct VerifiedCode {
    std::vector<Instruction> instructions;
    std::vector<Index> at; // no_index marks operands, payloads and their alignment padding.
};
// Checks formats, register/index bounds, call shapes and control-flow boundaries.
// Runtime checks enforce value types on every executed path (no untyped host reads).
VerifiedCode verify(const DexImage &image, Index method);
} // namespace aether::dex
