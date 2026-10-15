#pragma once
#include "aether/a64/selftest.hpp"
#include "aether/graphics/guest.hpp"
#include "aether/host/time_service.hpp"
#include <filesystem>

namespace aether::graphics {
struct SelftestReport {
    std::string command = "graphics-selftest";
    std::vector<a64::Check> checks;
    std::string fixture_sha256, capture_path, capture_sha256, isolation_json;
    HostInfo host;
    Metrics graphics;
    a64::Metrics cpu;
    std::size_t relocations = 0;
    bool passed() const;
    std::string json() const;
    std::string text(bool verbose) const;
};
SelftestReport execute_graphics_fixture(std::vector<std::uint8_t> bytes, std::uint64_t app_id,
                                        host::TimeService &time, GraphicsChannel &channel,
                                        std::vector<std::uint8_t> &capture);
SelftestReport graphics_selftest(const std::filesystem::path &fixture);
} // namespace aether::graphics
