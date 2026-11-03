#pragma once
#include "aether/elf/guest_loader.hpp"
#include "aether/android/display_configuration.hpp"

namespace aether::apk { struct PackageView; }
namespace aether::android {
class NativeWindows;
// Native assets/directories retain the low 48-bit opaque-handle domain.
// Issued managed manager identities use a separate tagged domain; their lower
// bits identify an actually live managed owner, never a raw JNI reference.
inline constexpr std::uint64_t native_asset_manager_identity_tag = 0xa55d000000000000ULL;
inline constexpr std::uint64_t native_asset_manager_identity_mask = 0x0000ffffffffffffULL;

// Trusted live-owner callbacks. They do not allocate, collect, run guest code or
// retain JNI handles. The producer owns issued identity and actual source proof.
// A zero publication result is rejection; owns accepts only live issued tokens.
struct NativeAssetManagerAccess {
    std::function<std::uint64_t(a64::Address, std::uint64_t)> from_java;
    std::function<bool(std::uint64_t)> owns;
};
// Exact native declarations plus owned archive assets and native Loopers.
// Other declared functions explicitly refuse invocation.
// The supplied app and guest memory must outlive this single-owner adapter.
class NativePlatformServices final : public elf::ImportResolver, public a64::GuestServices {
  public:
    static constexpr a64::Address trampoline_base = 0x94000;
    static constexpr std::uint32_t first_service = 0xe00;
    NativePlatformServices(a64::GuestMemory &memory, const a64::AppContext &app);
    ~NativePlatformServices();
    NativePlatformServices(const NativePlatformServices &) = delete;
    NativePlatformServices &operator=(const NativePlatformServices &) = delete;
    static bool handles_service(std::uint32_t service) noexcept;
    // Trusted one-time binding. Immutable backing must outlive this adapter.
    void bind_assets(const apk::PackageView &,
                     std::function<bool(a64::Address, std::uint64_t)> validate_java);
    void bind_assets(const apk::PackageView &, NativeAssetManagerAccess);
    std::uint64_t publish_asset_manager(a64::Address environment, std::uint64_t java_manager);
    // Bind after the immutable asset source. Only a published manager from
    // that source can copy these actual display facts into a native snapshot.
    void bind_configuration(DisplayConfiguration);
    void update_configuration(DisplayConfiguration);
    using LooperService = std::function<a64::Fault(std::string_view, a64::ServiceState &, bool)>;
    void bind_looper(LooperService, std::function<std::string_view()> rejection);
    void bind_input_queue(LooperService, std::function<std::string_view()> rejection);
    // Trusted copied Activity work admission; the binding never runs guest work.
    void bind_activity_host_ops(LooperService, std::function<std::string_view()> rejection);
    // Trusted one-time shared binding of the session's producer/reference registry.
    // This does not admit a producer or authenticate a Java Surface by itself.
    void bind_windows(std::shared_ptr<NativeWindows>);
    bool has_library(std::string_view library) const noexcept override;
    std::optional<elf::GuestSymbol> resolve(std::string_view library, std::string_view name,
                                          std::string_view version) const override;
    a64::Fault invoke(std::uint32_t service, a64::Address instruction,
                      std::array<std::uint64_t, 31> &registers) noexcept override;
    a64::Fault invoke_frame(std::uint32_t service, a64::Address instruction,
                           a64::ServiceState &) noexcept override;
    std::string_view last_error() const noexcept;
    void shutdown();

  private:
    a64::Fault invoke_service(std::uint32_t, a64::Address, a64::ServiceState &, bool) noexcept;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::android
