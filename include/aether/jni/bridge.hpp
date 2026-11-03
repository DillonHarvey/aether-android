#pragma once
#include "aether/bionic/guest_posix.hpp"
#include "aether/android/native_activity.hpp"
#include "aether/dex/runtime.hpp"

namespace aether::audio { class GuestAudioServices; }
namespace aether::graphics { class GuestGraphicsServices; }
namespace aether::apk { struct PackageView; }
namespace aether::android { class NativeWindows; class NativeWindowProducer; struct DisplayConfiguration; struct NativeActivityRequest; struct NativeActivityPointerInput; }

namespace aether::jni {
// Actual managed-object identity is resolved by Bridge before publication.
// Both callbacks are trusted nonallocating/no-GC owner checks; issued tokens
// and their source/lifetime metadata remain with the managed producer.
struct ManagedAssetManagerAccess {
    std::function<std::uint64_t(dex::ObjectId)> publish;
    std::function<bool(std::uint64_t)> owns;
};
struct Metrics {
    std::uint64_t calls = 0, native_calls = 0, managed_callbacks = 0, on_load_calls = 0;
    std::uint64_t references_created = 0, automatic_local_deletions = 0, rejected_calls = 0;
    std::size_t local_references = 0, global_references = 0, string_buffers = 0;
};
// Owns guest-only tables, translator and native call stacks. The runtime, app,
// memory and clock must outlive this bridge. The ELF loader consumes module
// bytes/sources during construction; streamed files are not retained afterward.
// The caller must authorize all module bytes before executing managed/native code.
// An optional app-scoped audio adapter is borrowed and must also outlive the bridge.
class Bridge final : public dex::NativeInterface, public a64::GuestServices {
  public:
    static constexpr a64::Address environment = 0x60000, java_vm = 0x60008;
    Bridge(dex::ManagedRuntime &runtime, a64::GuestMemory &memory, const a64::AppContext &app,
           const host::TimeService &time, std::span<const elf::ModuleInput> modules, std::string root,
           host::FileService *files = nullptr, bool attach_interface = true, std::string_view package = {},
           audio::GuestAudioServices *audio = nullptr, graphics::GuestGraphicsServices *graphics = nullptr);
    ~Bridge();
    Bridge(const Bridge &) = delete;
    Bridge &operator=(const Bridge &) = delete;
    std::uint64_t capture_signal_mask(dex::ManagedRuntime&) override;
    void finish_logical_thread(dex::ManagedRuntime &) override;
    void discard_logical_thread(dex::ObjectId) noexcept override;
    bool supports_background() const noexcept override {return true;}
    bool pump_native_tasks(dex::ManagedRuntime &) override;
    std::optional<std::chrono::steady_clock::time_point> next_native_deadline() const override;
    // Known explicit roots include the pending/active JNI_OnLoad root.
    bool has_library(std::string_view root) const noexcept;
    void add_library(std::span<const elf::ModuleInput> modules, std::string root);
    using ModuleProvider=std::function<std::vector<elf::ModuleInput>(std::string_view)>;
    // Trusted app-scoped immutable module inventory, not a host filesystem loader.
    void set_module_provider(ModuleProvider provider);
    // Diagnostic-only observer borrowed through Bridge destruction. Configure
    // on the idle owner before initialization; callback rules are in GuestLoader.
    void set_initialization_observer(void *context,elf::InitializationObserver);
    // Trusted app source and exact canonical managed-manager check, bound while idle.
    void set_assets(const apk::PackageView &, std::function<bool(dex::ObjectId)> validate_manager);
    void set_assets(const apk::PackageView &, ManagedAssetManagerAccess);
    // Trusted idle-owner display updates. Existing AConfiguration objects stay
    // snapshots until the guest copies the actual current AssetManager config.
    void set_display_configuration(const android::DisplayConfiguration &);
    // Bind before initializers. The resolver returns the exact current managed
    // Surface association, independently of acquired native window references.
    void set_native_windows(std::shared_ptr<android::NativeWindows>,
                            std::function<std::shared_ptr<android::NativeWindowProducer>(dex::ObjectId)>);
    // Activity runtime setup only: join its existing managed main event loop to
    // the trusted default native owner before any library initializer runs.
    void bind_main_looper();
    // Trusted synchronous lifecycle of the actual main-thread NativeActivity.
    // library is its prepared SONAME; this does not force JNI_OnLoad.
    android::NativeActivityResult native_activity(const android::NativeActivityRequest &, std::string_view library, std::string_view function);
    // Trusted actual capture admission only; never invokes guest code or pumps.
    bool native_activity_pointer(const android::NativeActivityPointerInput &);
    bool native_activity_key(const android::NativeActivityKeyInput &);
    void set_native_input_completion_factory(android::NativeActivityInputCompletionFactory);
    void set_native_activity_host_work_factory(android::NativeActivityHostWorkFactory);
    void load_library(dex::ManagedRuntime &, std::u16string_view name) override;
    dex::Value invoke(dex::ManagedRuntime &, dex::Index method,
                      std::span<const dex::Value> arguments) override;
    a64::Fault invoke(std::uint32_t service, a64::Address instruction,
                      std::array<std::uint64_t, 31> &registers) noexcept override;
    a64::Fault invoke_frame(std::uint32_t service, a64::Address instruction,
                            a64::ServiceState &) noexcept override;
    std::optional<std::uint64_t> thread_exit_value(a64::Address tls) const noexcept override;
    std::shared_ptr<a64::ThreadRegisterState> thread_register_state(a64::Address trusted_tls) const override;
    a64::CpuFaultAction synchronous_fault(const a64::CpuException &, a64::ArchitecturalState &,
                                           const a64::CpuFaultBoundary &) noexcept override;
    bool pending_signal_entry(const a64::SignalEntry &, a64::Address trusted_tls,
                              std::uint64_t invocation) const noexcept override;
    bool event_pending() noexcept override;
    a64::Fault checkpoint(a64::ServiceState &) noexcept override;
    const Metrics &metrics() const noexcept;
    const a64::Metrics &cpu_metrics() const noexcept;
    // Idle physical-owner maintenance after native scopes have unwound. No
    // guest entry, task pumping or retained main-work accounting reset occurs.
    bool trim_translation_cache();
    std::string_view last_error() const noexcept;
    // Retire only after the retained main entry has unwound.
    void finish_main_work();
    void shutdown();

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::jni
