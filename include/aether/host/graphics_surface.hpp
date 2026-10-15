#pragma once
#include <Windows.h>
#include <array>

namespace aether::host {
struct SurfaceSnapshot {
    HWND window = nullptr;
    DWORD owner = 0;
    const void *binding = nullptr;
    unsigned width = 0, height = 0;
};
// A borrowed, host-owned HWND. The owner must release this binding before WM_NCDESTROY.
// The property identifies this lifetime even if Windows later recycles the HWND value.
class HostSurface final {
  public:
    static constexpr unsigned maximum_dimension = 1024;
    explicit HostSurface(HWND window);
    ~HostSurface();
    HostSurface(const HostSurface &) = delete;
    HostSurface &operator=(const HostSurface &) = delete;
    bool alive() const noexcept;
    HWND native_window() const;
    std::array<unsigned, 2> extent() const;
    SurfaceSnapshot snapshot() const;
    // The owner retains this binding until all consumers have joined.
    static bool valid_snapshot(const SurfaceSnapshot &snapshot) noexcept;
    void invalidate() noexcept;

  private:
    HWND window_;
    DWORD owner_;
};
} // namespace aether::host
