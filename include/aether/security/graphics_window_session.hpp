#pragma once
#include "aether/host/graphics_surface.hpp"
#include "aether/security/graphics_window_protocol.hpp"

namespace aether::security {
struct GraphicsWindowCompletion {
    std::uint64_t ticket = 0;
    GraphicsWindowKind kind = GraphicsWindowKind::read;
    bool unavailable = false;
    std::shared_ptr<const GraphicsWindowState> state;
};
struct GraphicsWindowDispatchMetrics {
    std::uint64_t submitted = 0, completed = 0, read_requests = 0, coalesced_reads = 0;
    std::uint64_t read_failures = 0, recovered_reads = 0, peak_outstanding = 0;
    std::uint32_t io_thread = 0, window_thread = 0;
};
// The UI owns the HWND lifetime and immutable publications. One I/O thread owns both
// isolated processes, the capability/audit broker and trusted GPU copy/presentation.
// pump() publishes ordered results without GPU, pipe or disk work.
class GraphicsWindowSession final {
  public:
    explicit GraphicsWindowSession(const std::filesystem::path &fixture, bool recovery_probe = false);
    ~GraphicsWindowSession();
    GraphicsWindowSession(const GraphicsWindowSession &) = delete;
    GraphicsWindowSession &operator=(const GraphicsWindowSession &) = delete;
    std::uint64_t attach_window(std::unique_ptr<host::HostSurface> surface);
    std::uint64_t submit(GraphicsWindowCommand command);
    std::vector<GraphicsWindowCompletion> pump();
    void set_notification(HWND window, UINT message);
    HANDLE event() const noexcept;
    void abort() noexcept;
    void shutdown(); // Owner thread: cancel/join I/O and release resources before destroying the HWND.
    bool ready() const;
    bool idle() const;
    bool read_pending() const;
    bool exited() const;
    std::uint32_t process_id() const;
    std::uint32_t graphics_process_id() const;
    const GraphicsWindowState &snapshot() const;
    const graphics::Metrics &graphics_metrics() const noexcept;
    const graphics::HostInfo &host_info() const noexcept;
    const std::vector<std::uint8_t> &fixture_pixels() const noexcept;
    GraphicsWindowDispatchMetrics dispatch_metrics() const;
    std::string isolation_json() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::security
