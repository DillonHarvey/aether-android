#include "aether/host/graphics_surface.hpp"
#include "aether/a64/guest_memory.hpp"

namespace aether::host {
namespace {
constexpr wchar_t binding_property[] = L"Aether.GraphicsSurface.Owner.v1";
[[noreturn]] void fail(const char *message) {
    throw a64::GuestError("AETHER_GRAPHICS_NATIVE_WINDOW", message);
}
} // namespace
HostSurface::HostSurface(HWND window) : window_(window), owner_(GetCurrentThreadId()) {
    DWORD process = 0;
    if (!window_ || GetWindowThreadProcessId(window_, &process) != owner_ || process != GetCurrentProcessId())
        fail("Graphics surface requires a window owned by this process and thread");
    if (GetPropW(window_, binding_property))
        fail("This window already has an Aether graphics binding");
    RECT bounds{};
    if (!GetClientRect(window_, &bounds) || bounds.right <= 0 || bounds.bottom <= 0 ||
        bounds.right > static_cast<LONG>(maximum_dimension) ||
        bounds.bottom > static_cast<LONG>(maximum_dimension))
        fail("Graphics window client area must be between 1 and 1024 pixels per axis");
    if (!SetPropW(window_, binding_property, this))
        fail("Cannot install the graphics window lifetime marker");
}
HostSurface::~HostSurface() { invalidate(); }
bool HostSurface::alive() const noexcept {
    DWORD process = 0;
    return window_ && GetCurrentThreadId() == owner_ &&
           GetWindowThreadProcessId(window_, &process) == owner_ && process == GetCurrentProcessId() &&
           GetPropW(window_, binding_property) == this;
}
HWND HostSurface::native_window() const {
    if (!alive())
        fail("Graphics window binding is stale or belongs to another thread");
    return window_;
}
std::array<unsigned, 2> HostSurface::extent() const {
    RECT bounds{};
    if (!GetClientRect(native_window(), &bounds) || bounds.right < 0 || bounds.bottom < 0 ||
        bounds.right > static_cast<LONG>(maximum_dimension) ||
        bounds.bottom > static_cast<LONG>(maximum_dimension))
        fail("Graphics window client area exceeds the supported bounds");
    return {static_cast<unsigned>(bounds.right), static_cast<unsigned>(bounds.bottom)};
}
void HostSurface::invalidate() noexcept {
    if (GetCurrentThreadId() != owner_)
        return;
    if (alive())
        RemovePropW(window_, binding_property);
    window_ = nullptr;
}
SurfaceSnapshot HostSurface::snapshot() const {
    const auto size = extent();
    return {window_, owner_, this, size[0], size[1]};
}
bool HostSurface::valid_snapshot(const SurfaceSnapshot &value) noexcept {
    DWORD process = 0;
    return value.window && value.binding && value.owner && value.width && value.height &&
           value.width <= maximum_dimension && value.height <= maximum_dimension &&
           GetWindowThreadProcessId(value.window, &process) == value.owner &&
           process == GetCurrentProcessId() && GetPropW(value.window, binding_property) == value.binding;
}
} // namespace aether::host
