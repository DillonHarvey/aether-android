#include "math.hpp"
#include <bit>
#include <cfenv>
#include <cmath>
#include <cstdint>
#include <xmmintrin.h>

// MSVC's default /fp:precise still needs this declaration before code may
// depend on scoped rounding changes or restore a caller's floating environment.
#pragma fenv_access(on)

namespace aether::dex {
namespace {
constexpr std::uint64_t sign = 0x8000000000000000ULL;
constexpr std::uint64_t infinity = 0x7ff0000000000000ULL;
constexpr std::uint64_t fraction = 0x000fffffffffffffULL;
constexpr std::uint64_t one = 0x3ff0000000000000ULL;
constexpr std::uint64_t nan = 0x7ff8000000000000ULL;
bool is_nan(std::uint64_t bits) noexcept { return (bits & ~sign) > infinity; }
std::uint64_t quiet(std::uint64_t bits) noexcept { return bits | 0x0008000000000000ULL; }
std::uint64_t value_bits(Value value, bool single = false) {
    if (value.kind != (single ? ValueKind::word : ValueKind::wide))
        throw DexError("AETHER_DEX_VALUE_TYPE", "Math argument has the wrong register category");
    return single ? static_cast<std::uint32_t>(value.bits) : value.bits;
}
void arity(std::span<const Value> args, std::size_t expected) {
    if (args.size() != expected)
        throw DexError("AETHER_DEX_SIGNATURE", "Wrong Math argument count");
}
std::uint64_t integral(std::uint64_t bits, bool up) noexcept {
    const auto magnitude = bits & ~sign;
    if (magnitude >= infinity) return is_nan(bits) ? quiet(bits) : bits;
    if (!magnitude) return bits;
    const auto exponent = static_cast<int>(magnitude >> 52) - 1023;
    if (exponent >= 52) return bits;
    const bool negative = (bits & sign) != 0;
    if (exponent < 0) return negative ? (up ? sign : sign | one) : (up ? one : 0);
    const auto unit = std::uint64_t{1} << (52 - exponent);
    const auto mask = unit - 1;
    if (!(bits & mask)) return bits;
    auto result = bits & ~mask;
    if (negative != up) result += unit;
    return result;
}
std::uint64_t rounded(std::uint64_t bits, unsigned precision, unsigned exponent_bits,
                      int bias, unsigned output_bits) noexcept {
    const auto exponent_mask = (std::uint64_t{1} << exponent_bits) - 1;
    const auto exp = (bits >> precision) & exponent_mask;
    const auto mantissa_bits = bits & ((std::uint64_t{1} << precision) - 1);
    const bool negative = (bits & (std::uint64_t{1} << (precision + exponent_bits))) != 0;
    const auto minimum = std::uint64_t{1} << (output_bits - 1);
    if (exp == exponent_mask && mantissa_bits) return 0;
    const auto exponent = static_cast<int>(exp) - bias;
    if (exponent < -1) return 0;
    if (exponent >= static_cast<int>(output_bits - 1)) return negative ? minimum : minimum - 1;
    const auto mantissa = (std::uint64_t{1} << precision) | mantissa_bits;
    std::uint64_t result;
    if (exponent >= static_cast<int>(precision))
        result = mantissa << (exponent - precision);
    else {
        const auto shift = static_cast<unsigned>(static_cast<int>(precision) - exponent);
        result = mantissa >> shift;
        const auto remainder = mantissa & ((std::uint64_t{1} << shift) - 1);
        const auto half = std::uint64_t{1} << (shift - 1);
        // Java ties go toward positive infinity, including negative halves.
        if (negative ? remainder > half : remainder >= half) ++result;
    }
    return negative ? std::uint64_t{0} - result : result;
}
std::uint64_t nearest_even(std::uint64_t bits) noexcept {
    const auto magnitude = bits & ~sign;
    if (magnitude >= infinity) return is_nan(bits) ? quiet(bits) : bits;
    if (!magnitude) return bits;
    const auto exponent = static_cast<int>(magnitude >> 52) - 1023;
    if (exponent >= 52) return bits;
    if (exponent < 0) return (bits & sign) | (magnitude <= 0x3fe0000000000000ULL ? 0 : one);
    const auto unit = std::uint64_t{1} << (52 - exponent);
    const auto remainder = magnitude & (unit - 1);
    auto result = bits & ~(unit - 1);
    if (remainder > unit / 2 || (remainder == unit / 2 && ((magnitude >> (52 - exponent)) & 1)))
        result += unit;
    return result;
}
std::uint64_t extreme(std::uint64_t a, std::uint64_t b, bool maximum, bool single) noexcept {
    const auto s = single ? std::uint64_t{0x80000000} : sign;
    const auto inf = single ? std::uint64_t{0x7f800000} : infinity;
    const auto q = single ? std::uint64_t{0x00400000} : std::uint64_t{0x0008000000000000};
    if ((a & ~s) > inf) return a | q;
    if ((b & ~s) > inf) return b | q;
    if (!(a & ~s) && !(b & ~s)) return maximum ? a & b : a | b;
    // Ordered integer keys avoid host DAZ changing subnormal comparisons.
    const auto key = [s](std::uint64_t v) { return v & s ? (~v & (s | (s - 1))) : v | s; };
    const bool less = key(a) < key(b);
    return maximum ? (less ? b : a) : (less ? a : b);
}
class NearestEnvironment {
    fenv_t saved_{};
    unsigned mxcsr_;
  public:
    NearestEnvironment() : mxcsr_(_mm_getcsr()) {
        if (std::feholdexcept(&saved_) != 0)
            throw DexError("AETHER_DEX_MATH_ENVIRONMENT", "Cannot preserve the host floating environment");
        if (std::fesetround(FE_TONEAREST) != 0) {
            (void)std::fesetenv(&saved_);
            _mm_setcsr(mxcsr_);
            throw DexError("AETHER_DEX_MATH_ENVIRONMENT", "Nearest-even host math is unavailable");
        }
        _mm_setcsr((mxcsr_ & ~0xe07fu) | 0x1f80u);
    }
    ~NearestEnvironment() { (void)std::fesetenv(&saved_); _mm_setcsr(mxcsr_); }
    NearestEnvironment(const NearestEnvironment &) = delete;
    NearestEnvironment &operator=(const NearestEnvironment &) = delete;
};
bool odd_integer(std::uint64_t bits, bool &integer) noexcept {
    const auto magnitude = bits & ~sign;
    const auto exponent = static_cast<int>(magnitude >> 52) - 1023;
    if (exponent < 0) { integer = magnitude == 0; return false; }
    if (exponent > 52) { integer = true; return false; }
    const auto mantissa = (magnitude & fraction) | (std::uint64_t{1} << 52);
    const auto shift = static_cast<unsigned>(52 - exponent);
    integer = !(mantissa & ((std::uint64_t{1} << shift) - 1));
    return integer && ((mantissa >> shift) & 1);
}
std::uint64_t power(std::uint64_t a, std::uint64_t b) {
    const auto x = a & ~sign, y = b & ~sign;
    if (!y) return one;
    if (is_nan(b)) return quiet(b);
    if (is_nan(a)) return quiet(a);
    if (y == infinity) {
        if (x == one) return nan;
        return (x > one) != bool(b & sign) ? infinity : 0;
    }
    bool integer = false;
    const bool odd = odd_integer(b, integer);
    const auto result_sign = (a & sign) && odd ? sign : 0;
    if (!x) return result_sign | ((b & sign) ? infinity : 0);
    if (x == infinity) return result_sign | ((b & sign) ? 0 : infinity);
    if ((a & sign) && !integer) return nan;
    if (x == one) return result_sign | one;
    NearestEnvironment environment;
    const auto result = std::pow(std::bit_cast<double>(x), std::bit_cast<double>(b));
    return std::bit_cast<std::uint64_t>(result) | result_sign;
}
}
std::optional<Value> invoke_math(std::string_view name, std::string_view signature,
                                 std::span<const Value> args) {
    if (name == "round" && signature == "(F)I") {
        arity(args, 1);
        return Value::word(static_cast<std::uint32_t>(rounded(value_bits(args[0], true), 23, 8, 127, 32)));
    }
    if (name == "round" && signature == "(D)J") {
        arity(args, 1); return Value::wide(rounded(value_bits(args[0]), 52, 11, 1023, 64));
    }
    if ((name == "min" || name == "max") && (signature == "(FF)F" || signature == "(DD)D")) {
        arity(args, 2); const bool single = signature == "(FF)F";
        const auto bits = extreme(value_bits(args[0], single), value_bits(args[1], single), name == "max", single);
        return single ? Value::word(static_cast<std::uint32_t>(bits)) : Value::wide(bits);
    }
    if (name == "abs" && (signature == "(F)F" || signature == "(D)D")) {
        arity(args, 1); const bool single = signature == "(F)F";
        const auto bits = value_bits(args[0], single) & (single ? 0x7fffffffULL : ~sign);
        return single ? Value::word(static_cast<std::uint32_t>(bits)) : Value::wide(bits);
    }
    if (name == "copySign" && (signature == "(FF)F" || signature == "(DD)D")) {
        arity(args, 2); const bool single = signature == "(FF)F";
        const auto s = single ? std::uint64_t{0x80000000} : sign;
        const auto bits = (value_bits(args[0], single) & ~s) | (value_bits(args[1], single) & s);
        return single ? Value::word(static_cast<std::uint32_t>(bits)) : Value::wide(bits);
    }
    if (name == "pow" && signature == "(DD)D") {
        arity(args, 2); return Value::wide(power(value_bits(args[0]), value_bits(args[1])));
    }
    if (signature != "(D)D" || (name != "floor" && name != "ceil" && name != "rint" && name != "sin" && name != "sqrt"))
        return {};
    arity(args, 1); const auto bits = value_bits(args[0]);
    if (name == "floor" || name == "ceil") return Value::wide(integral(bits, name == "ceil"));
    if (name == "rint") return Value::wide(nearest_even(bits));
    if (is_nan(bits)) return Value::wide(quiet(bits));
    if (!(bits & ~sign)) return Value::wide(bits);
    if (name == "sin" && (bits & ~sign) == infinity) return Value::wide(nan);
    if (name == "sqrt" && (bits & sign)) return Value::wide(nan);
    NearestEnvironment environment;
    const auto input = std::bit_cast<double>(bits);
    return Value::wide(std::bit_cast<std::uint64_t>(name == "sin" ? std::sin(input) : std::sqrt(input)));
}
}
