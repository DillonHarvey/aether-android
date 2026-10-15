#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <string>
#include <vector>
namespace aether::a64 {
struct Check {
    std::string name;
    bool passed;
    std::string detail;
};
struct SelftestReport {
    std::vector<Check> checks;
    Metrics metrics;
    std::uint64_t benchmark_iterations = 0, benchmark_checksum = 0, benchmark_nanoseconds = 0;
    std::uint64_t counter_frequency = 0;
    std::uint64_t private_writable_executable_regions = 0;
    bool passed() const;
    std::string json() const;
    std::string text(bool verbose) const;
};
SelftestReport translate_selftest();
} // namespace aether::a64
