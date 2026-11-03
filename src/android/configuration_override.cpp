#include "aether/android/configuration_override.hpp"
#include "aether/apk/inspect.hpp"
#include <bit>

namespace aether::android {
namespace {
[[noreturn]] void unsupported(const char *message) {
    throw apk::InspectError("AETHER_CONFIGURATION_OVERRIDE_UNSUPPORTED", "configuration-context", message);
}
void require_work(const ConfigurationOverrideWork &work) {
    if (!work) unsupported("Configuration operations require the existing shared work ledger");
}
constexpr std::size_t index_of(ConfigurationField field) noexcept { return static_cast<std::size_t>(field); }
bool same_partial_field(const ConfigurationValueFacts &a, const ConfigurationValueFacts &b,
                        std::size_t index) noexcept {
    return a.remainder_origin == b.remainder_origin && a.known[index] == b.known[index] &&
        !((a.numbers[index] ^ b.numbers[index]) & a.known[index]);
}
std::uint32_t float_hash_bits(std::uint32_t bits) noexcept {
    // Java Float.floatToIntBits canonicalizes every NaN payload.
    return (bits & 0x7f800000u) == 0x7f800000u && (bits & 0x007fffffu) ? 0x7fc00000u : bits;
}
} // namespace

ConfigurationValueFacts merge_configuration_override(const ConfigurationValueFacts &base,
    const ConfigurationValueFacts &raw, const ConfigurationOverrideWork &work) {
    require_work(work);
    if (raw.remainder_origin && raw.remainder_origin != base.remainder_origin)
        unsupported("Override has unmodeled fields from a different configuration source");
    if (raw.window_origin && raw.window_origin != base.window_origin)
        unsupported("Override has unmodeled fields from a different WindowConfiguration source");
    work(configuration_field_count * 2 + 6);
    auto result = base;
    for (std::size_t index = 0; index < configuration_field_count; ++index) {
        work(1);
        if (raw.known[index] != UINT32_MAX) {
            if (same_partial_field(base, raw, index)) continue;
            unsupported("Override cannot prove the defined-value decision for a scalar field");
        }
        const auto bits = raw.numbers[index];
        const auto field = static_cast<ConfigurationField>(index);
        if (field == ConfigurationField::font_scale) {
            if (std::bit_cast<float>(bits) > 0) {
                work(1); result.numbers[index] = bits; result.known[index] = UINT32_MAX;
            }
            continue;
        }
        const auto replace_part = [&](std::uint32_t mask) {
            work(1);
            if (bits & mask) {
                result.numbers[index] = (result.numbers[index] & ~mask) | (bits & mask);
                result.known[index] |= mask;
            }
        };
        if (field == ConfigurationField::screen_layout) {
            replace_part(0xc0u); // Layout direction is independently defined.
            replace_part(0x0fu); replace_part(0x30u); replace_part(0x300u);
            // SDK updateFrom also CLEARS COMPAT_NEEDED for a nonzero delta
            // whose compatibility bit is zero; it is not a set-only flag.
            work(1);
            if (bits) {
                result.numbers[index] = (result.numbers[index] & ~0x10000000u) | (bits & 0x10000000u);
                result.known[index] |= 0x10000000u;
            }
        } else if (field == ConfigurationField::color_mode) {
            replace_part(3u); replace_part(0xcu);
        } else if (field == ConfigurationField::ui_mode) {
            replace_part(0x0fu); replace_part(0x30u);
        } else if (bits) {
            work(1); result.numbers[index] = bits; result.known[index] = UINT32_MAX;
        }
    }
    work(4);
    // WindowConfiguration.updateFrom, unlike diff, ignores empty maxBounds.
    if (raw.max_bounds[2] > raw.max_bounds[0] && raw.max_bounds[3] > raw.max_bounds[1])
        result.max_bounds = raw.max_bounds;
    return result;
}

ConfigurationKeyMatch compare_configuration_override_keys(const ConfigurationValueFacts &a,
    const ConfigurationValueFacts &b, const ConfigurationOverrideWork &work) {
    require_work(work);
    bool unknown = a.remainder_origin != b.remainder_origin || a.window_origin != b.window_origin;
    bool float_hash_differs = false;
    for (std::size_t index = 0; index < configuration_field_count; ++index) {
        work(1);
        if (index == index_of(ConfigurationField::font_scale)) {
            if (a.known[index] == UINT32_MAX && b.known[index] == UINT32_MAX) {
                const auto av = std::bit_cast<float>(a.numbers[index]);
                const auto bv = std::bit_cast<float>(b.numbers[index]);
                if (av < bv || av > bv) return ConfigurationKeyMatch::different;
                float_hash_differs = float_hash_bits(a.numbers[index]) != float_hash_bits(b.numbers[index]);
            } else if (!same_partial_field(a, b, index)) unknown = true;
            continue;
        }
        if ((a.numbers[index] ^ b.numbers[index]) & a.known[index] & b.known[index])
            return ConfigurationKeyMatch::different;
        if (a.known[index] == UINT32_MAX && b.known[index] == UINT32_MAX) continue;
        if (!same_partial_field(a, b, index)) unknown = true;
    }
    for (std::size_t index = 0; index < a.max_bounds.size(); ++index) {
        work(1);
        if (a.max_bounds[index] != b.max_bounds[index]) return ConfigurationKeyMatch::different;
    }
    if (unknown) return ConfigurationKeyMatch::unknown;
    // With every other component proved equal, a different canonical font hash
    // proves a different ResourcesKey hash despite compareTo's NaN/zero quirks.
    return float_hash_differs ? ConfigurationKeyMatch::different : ConfigurationKeyMatch::equal;
}
} // namespace aether::android
