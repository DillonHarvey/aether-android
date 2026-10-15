#pragma once
#include "aether/a64/selftest.hpp"
#include "aether/jni/bridge.hpp"
#include <filesystem>

namespace aether::dex {
struct ManagedSelftestReport {
    std::vector<a64::Check> checks;
    RuntimeMetrics managed;
    jni::Metrics jni;
    a64::Metrics cpu;
    std::string apk_sha256, dex_sha256, native_sha256;
    std::uint32_t arithmetic = 0, round_trip = 0, reference_flags = 0, caught = 0;
    std::uint64_t wide_result = 0;
    double floating = 0;
    bool passed() const;
    std::string json() const;
    std::string text(bool verbose) const;
};
ManagedSelftestReport managed_selftest(const std::filesystem::path &apk);
} // namespace aether::dex
