#pragma once
#include "aether/graphics/shared_window.hpp"
#include "aether/host/graphics_surface.hpp"
#include <memory>
#include <vector>

namespace aether::host {
struct PresentationMetrics {
    std::uint64_t frames = 0, occluded = 0, busy = 0, resizes = 0, captures = 0;
    std::uint32_t thread = 0;
};
// One I/O owner. No ANGLE, guest shader or guest pointers: only bounded GPU copies/Present.
// The UI retains the HostSurface and dispatches messages until this object has been released.
class GraphicsPresenter final {
  public:
    GraphicsPresenter(const SurfaceSnapshot &surface, std::uint64_t token, bool capture);
    ~GraphicsPresenter();
    bool resize(const SurfaceSnapshot &surface);
    graphics::SharedWindowGrant grant() const;
    void present();
    const PresentationMetrics &metrics() const noexcept;
    const std::vector<std::uint8_t> &
    pixels() const noexcept; // Last top-first back buffer; fixture proof only.

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::host
