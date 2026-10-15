#pragma once
#include "aether/a64/selftest.hpp"
#include "aether/bionic/guest_posix.hpp"
#include <filesystem>

namespace aether::elf {
struct NativeSelftestReport {
    std::vector<a64::Check> checks;
    a64::Metrics metrics;
    bionic::ServiceMetrics services;
    std::string fixture_sha256, dependency_sha256, greeting;
    std::uint64_t addition = 0, indirect_addition = 0, copy_sum = 0;
    std::uint64_t clock_before = 0, clock_guest = 0, clock_after = 0;
    std::size_t modules = 0, relocations = 0;
    std::vector<std::uint32_t> relocation_types;
    bool passed() const;
    std::string json() const;
    std::string text(bool verbose) const;
};
NativeSelftestReport native_selftest(const std::filesystem::path &fixture);
} // namespace aether::elf
