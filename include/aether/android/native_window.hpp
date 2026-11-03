#pragma once
#include "aether/a64/guest_cpu.hpp"
#include <functional>

namespace aether::android {
struct NativeWindowGeometry {
    std::uint32_t width = 0, height = 0;
    std::int32_t format = 0;
};

class NativeWindows;
// A trusted Java Surface association can retain this producer independently
// of acquired NDK references. No HWND, HANDLE or host address is guest data.
class NativeWindowProducer final {
  public:
    ~NativeWindowProducer() = default;
    NativeWindowProducer(const NativeWindowProducer &) = delete;
    NativeWindowProducer &operator=(const NativeWindowProducer &) = delete;
  private:
    NativeWindowProducer(std::weak_ptr<const void>, std::uint64_t incarnation,
                         std::uint64_t backend_token, std::uint64_t native_id,
                         NativeWindowGeometry);
    std::weak_ptr<const void> owner_;
    const std::uint64_t incarnation_, backend_token_, native_id_;
    NativeWindowGeometry geometry_;
    std::uint32_t native_references_ = 0, activity_references_ = 0;
    bool abandoned_ = false;
    friend class NativeWindows;
};

// Host-only pin for an eventual EGL-surface ledger. The native pointer and
// renderer token deliberately differ. None of this structure is guest IPC.
struct NativeWindowBinding {
    std::uint64_t incarnation = 0, backend_token = 0;
    NativeWindowGeometry geometry;
    std::shared_ptr<const NativeWindowProducer> retained;
};

// Single-owner, session-local producer registry. Merely constructing this object creates no
// producer and authorizes no Java Surface or host window. Trusted publication
// must use a real acknowledged producer incarnation, actual geometry and the
// renderer's existing ACK-bound token; never synthesize these from guest input.
class NativeWindows final {
  public:
    using JavaResolver = std::function<std::shared_ptr<NativeWindowProducer>(a64::Address, std::uint64_t)>;
    NativeWindows();
    ~NativeWindows();
    NativeWindows(const NativeWindows &) = delete;
    NativeWindows &operator=(const NativeWindows &) = delete;
    std::shared_ptr<NativeWindowProducer> publish(std::uint64_t incarnation, std::uint64_t backend_token,
                                                 NativeWindowGeometry);
    void update(const std::shared_ptr<NativeWindowProducer> &, NativeWindowGeometry);
    void abandon(const std::shared_ptr<NativeWindowProducer> &);
    // Trusted Activity callback custody, separate from app-acquired references.
    // Guest release cannot consume this borrowed framework lifetime.
    std::uint64_t retain_activity(const std::shared_ptr<NativeWindowProducer> &);
    void release_activity(const std::shared_ptr<NativeWindowProducer> &);
    // One-time trusted JNI binding. It must validate the actual JNIEnv/reference
    // scope and return only that genuine current Java Surface's producer.
    void bind_java_resolver(JavaResolver);
    // Owning-thread teardown only. Clearing is terminal for Java admission;
    // existing acquired references and EGL pins keep their independent lives.
    void clear_java_resolver() noexcept;
    bool owned_by_current_thread() const noexcept;
    a64::Fault invoke(std::string_view name, std::array<std::uint64_t, 31> &) noexcept;
    std::string_view last_error() const noexcept;
    // Admission of a currently acquired or Activity-borrowed argument creates an independent
    // producer pin. Later query uses that pin even after the last NDK release.
    std::optional<NativeWindowBinding> resolve_for_egl(std::uint64_t native_id) const;
    std::optional<NativeWindowBinding> query_for_egl(const NativeWindowBinding &) const;
    void shutdown();

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::android
