#pragma once
#include "aether/security/graphics_protocol.hpp"
#include "aether/security/worker.hpp"

namespace aether::security {
enum class GraphicsWindowKind : std::uint64_t { read, open, draw, pointer, key, focus, close };
struct GraphicsWindowCommand {
    GraphicsWindowKind kind = GraphicsWindowKind::read;
    std::array<std::uint64_t, 4> arguments{};
    std::vector<std::uint8_t> encode() const;
    static GraphicsWindowCommand decode(std::span<const std::uint8_t> bytes);
};
struct GraphicsWindowState {
    graphics::GraphicsReply graphics;
    a64::Metrics cpu;
    std::array<std::uint64_t, 15> guest{};
    std::string fixture_hash, capture_hash;
    std::uint64_t relocations = 0, capture_bytes = 0;
    bool non_executable = false, closed = false, canaries = false;
    std::vector<std::uint8_t> encode() const;
    static GraphicsWindowState decode(std::span<const std::uint8_t> bytes);
};
void validate_graphics_window_refusal(const Frame &frame, std::uint64_t sequence, std::uint64_t session,
                                      bool reading, bool began);
// Invoked only after the worker has verified its LPAC token and inherited channel.
void run_graphics_window_worker(HANDLE reader, HANDLE writer, std::uint64_t session, std::uint64_t app_id,
                                bool read_recovery_probe);
} // namespace aether::security
