#pragma once
#include "aether/elf/guest_loader.hpp"

namespace aether::host {
class HostSurface;
}
namespace aether::graphics {
class GraphicsChannel;
struct SharedWindowGrant;
struct ObservedWrite {
    a64::Address address;
    std::vector<std::uint8_t> bytes;
};
struct ApiEntry {
    std::string_view library, name;
};
std::span<const ApiEntry> api_registry() noexcept;
struct Metrics {
    std::uint64_t calls = 0, egl_calls = 0, gl_calls = 0, rejected = 0, api_errors = 0;
    std::uint64_t shader_compiles = 0, draws = 0, readbacks = 0, readback_bytes = 0;
    std::uint64_t swaps = 0, window_swaps = 0;
    std::size_t contexts = 0, surfaces = 0, shaders = 0, programs = 0, buffers = 0, buffer_bytes = 0;
    std::size_t window_bindings = 0, window_surfaces = 0;
    std::uint64_t cleanup_failures = 0;
};
struct HostInfo {
    std::string renderer, vendor, version, adapter;
    std::uint32_t vendor_id = 0, device_id = 0, feature_level = 0;
    bool hardware = false;
};
// One guest owner thread/app/address space. No host graphics handle is a guest value.
// AppContext::graphics_allowed is a development capability, not a production broker grant.
// Memory and app must outlive this object. Hardware creation is lazy and never uses WARP.
class GuestGraphicsServices final : public a64::GuestServices, public elf::ImportResolver {
  public:
    static constexpr a64::Address trampoline_base = 0x68000;
    static constexpr std::uint32_t first_service = 0xc00;
    GuestGraphicsServices(a64::GuestMemory &memory, const a64::AppContext &app,
                          GraphicsChannel *channel = nullptr);
    ~GuestGraphicsServices();
    GuestGraphicsServices(const GuestGraphicsServices &) = delete;
    GuestGraphicsServices &operator=(const GuestGraphicsServices &) = delete;
    static bool handles_service(std::uint32_t service) noexcept;
    bool has_library(std::string_view library) const noexcept override;
    std::optional<elf::GuestSymbol> resolve(std::string_view library, std::string_view name,
                                            std::string_view version) const override;
    a64::Fault invoke(std::uint32_t service, a64::Address instruction,
                      std::array<std::uint64_t, 31> &registers) noexcept override;
    a64::Fault invoke_frame(std::uint32_t service, a64::Address instruction,
                            a64::ServiceState &state) noexcept override;
    // Trusted adapter hook: records exact output writes for a copied-call arena, never guest pointers on IPC.
    a64::Fault invoke_observed(std::uint32_t service, a64::ServiceState &state,
                               std::vector<ObservedWrite> &writes);
    std::uint32_t pack_alignment() const noexcept;
    const Metrics &metrics() const noexcept;
    const HostInfo &host_info() const noexcept;
    std::string_view last_error() const noexcept;
    // Trusted host only. The returned token is an opaque guest EGLNativeWindowType.
    // Detach after guest EGL surfaces are released and before the HWND is destroyed.
    std::uint64_t attach_window(std::unique_ptr<host::HostSurface> surface);
    void detach_window(std::uint64_t token);
    void bind_shared_window(const SharedWindowGrant &grant);
    void shutdown();

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::graphics
