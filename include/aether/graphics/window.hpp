#pragma once
#include "aether/graphics/selftest.hpp"

namespace aether::graphics {
struct WindowFrame {
    std::string name;
    unsigned width = 0, height = 0;
    std::size_t offset = 0, bytes = 0;
};
struct WindowReport {
    SelftestReport rendering;
    bool selftest = false, created = false, closed = false;
    std::uint64_t messages = 0, paints = 0, resizes = 0, dpi_changes = 0, timer_reads = 0;
    std::uint64_t responsive_ticks = 0;
    unsigned dpi = 0, width = 0, height = 0;
    // Values queried by executing the fixture's ARM64 state getter, not host event counters.
    std::array<std::uint64_t, 15> guest{};
    std::vector<WindowFrame> frames;
    bool passed() const;
    std::string json() const;
    std::string text(bool verbose) const;
};
// Exact first-party ELF only. Selftest owns a hidden HWND and closes it automatically.
WindowReport run_graphics_window(const std::filesystem::path &fixture, bool selftest);
} // namespace aether::graphics
