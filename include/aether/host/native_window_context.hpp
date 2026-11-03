#pragma once
#include "aether/host/graphics_surface.hpp"
#include "aether/android/native_surface.hpp"
#include "aether/android/viewport.hpp"
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>

namespace aether::host {
// Host-only immutable snapshot. HWND/property addresses never enter guest IPC;
// only an explicitly admitted opaque token may be given to guest code.
struct NativeWindowSnapshot {
    SurfaceSnapshot surface;
    std::uint64_t token = 0;
};

// Construct/publish on the Activity UI owner. The context borrows one
// HostSurface lifetime: its owner must keep the marker and HWND alive until all
// I/O/renderer users have joined. close cancels readers but does not release the
// borrowed surface or destroy a window.
class NativeWindowContext final {
  public:
    NativeWindowContext();
    ~NativeWindowContext();
    NativeWindowContext(const NativeWindowContext &) = delete;
    NativeWindowContext &operator=(const NativeWindowContext &) = delete;
    void publish(const SurfaceSnapshot &);
    NativeWindowSnapshot wait_snapshot(std::chrono::steady_clock::time_point deadline) const;
    NativeWindowSnapshot snapshot() const;
    std::uint64_t token() const noexcept;
    static constexpr UINT surface_request_message = WM_APP + 6;
    using SurfaceOwner = std::function<android::NativeSurfaceAdmission(const android::NativeSurfaceRequest &)>;
    // Bind on the UI owner after the real hidden backing exists. Requests are
    // made by the single I/O owner; no guest pointer enters the sent message.
    void bind_surface_owner(HWND, SurfaceOwner);
    android::NativeSurfaceAdmission request_surface(const android::NativeSurfaceRequest &,
                                                    std::chrono::steady_clock::time_point deadline);
    void service_surface_request(std::uint64_t sequence) noexcept;
    // A distinct, token-free query of the real UI-owned viewport. Its hidden
    // HWND may supply launch geometry before resources are composed; neither
    // that query nor a later content binding admits a NativeSurface or pixels.
    static constexpr UINT viewport_request_message = WM_APP + 7;
    using ViewportOwner = std::function<android::ViewportAdmission(const android::ViewportRequest &)>;
    void bind_viewport_owner(HWND, ViewportOwner);
    android::ViewportAdmission request_viewport(const android::ViewportRequest &,
                                                std::chrono::steady_clock::time_point deadline);
    void service_viewport_request(std::uint64_t sequence) noexcept;
    void close() noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::host
