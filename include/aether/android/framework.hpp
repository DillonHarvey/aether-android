#pragma once
#include "aether/android/input.hpp"
#include "aether/apk/resources.hpp"
#include "aether/dex/runtime.hpp"
#include "aether/host/time_service.hpp"
#include "aether/host/file_service.hpp"
#include <map>

namespace aether::android {
// Android API dispatch/resource target, not a claim of complete Android conformance.
inline constexpr std::uint16_t compatibility_sdk = 35;
enum class ApiStatus { not_started, stub, partial, tested };
struct ApiSupport {
    std::string_view owner, name, signature;
    ApiStatus status;
    std::string_view behavior;
};
std::span<const ApiSupport> api_registry() noexcept;
std::string_view status_name(ApiStatus status) noexcept;
enum class Lifecycle { empty, created, started, resumed, paused, stopped, destroyed, failed };
enum class WindowSignal { activate, deactivate, minimize, restore, focus_gained, focus_lost, close };
std::string_view lifecycle_name(Lifecycle state) noexcept;
enum class ViewKind { linear_layout, text, button };
struct ViewState {
    dex::ObjectId object = 0, parent = 0, listener = 0;
    ViewKind kind = ViewKind::text;
    std::vector<dex::ObjectId> children;
    std::u16string text;
    std::int32_t id = -1, orientation = 0;
    bool enabled = true, pressed = false, focused = false;
    ViewBounds bounds;
};
struct FrameworkMetrics {
    std::uint64_t api_calls = 0, lifecycle_callbacks = 0, managed_clicks = 0;
    std::uint64_t denied_permissions = 0, unsupported_services = 0, view_revision = 0;
    std::uint64_t pointer_events = 0, key_events = 0;
};
// One activity and retained view tree per runtime. No Windows handles enter the guest.
// WindowSignal is the host-independent boundary used by the later Win32 event adapter.
class ActivitySession final : public dex::HostInterface {
  public:
    ActivitySession(dex::ManagedRuntime &runtime, std::string package, apk::ResourceTable resources,
                    const host::TimeService *time = nullptr, host::FileService *files = nullptr);
    ~ActivitySession();
    ActivitySession(const ActivitySession &) = delete;
    ActivitySession &operator=(const ActivitySession &) = delete;
    // Bind and run the declared Application before any Activity constructor.
    void initialize_application(std::string_view descriptor = "Landroid/app/Application;",
                                std::string_view factory_descriptor = {});
    dex::ObjectId application() const noexcept;
    void launch(std::string_view descriptor);
    void signal(WindowSignal signal);
    bool click(dex::ObjectId view);
    void place_views(std::span<const ViewPlacement> placements);
    bool pointer(const PointerInput &event);
    bool key(const KeyInput &event);
    void close();
    Lifecycle state() const noexcept;
    dex::ObjectId activity() const noexcept;
    dex::ObjectId content_view() const noexcept;
    const std::map<dex::ObjectId, ViewState> &views() const noexcept;
    const std::vector<std::string> &events() const noexcept;
    std::u16string_view standard_output(bool error) const noexcept;
    bool write_standard_output(dex::ManagedRuntime &, bool error, std::u16string_view) override;
    const FrameworkMetrics &metrics() const noexcept;
    const apk::ResourceTable &resources() const noexcept;
    std::optional<dex::HostClass> class_info(std::string_view descriptor) const override;
    bool method_is_static(const dex::DexImage &, dex::Index method) const override;
    std::optional<dex::Value> static_field(dex::ManagedRuntime &, dex::Index) override;
    dex::Value invoke(dex::ManagedRuntime &, dex::Index, std::span<const dex::Value>) override;
    std::unique_ptr<dex::HostInputStream> open_input_stream(dex::ManagedRuntime &, std::u16string_view) override;
    std::optional<dex::HostMethod> public_method(std::string_view owner, std::string_view name,
                                               std::span<const std::string> parameters) const override;
    std::optional<dex::HostField> public_field(std::string_view owner, std::string_view name) const override;
    std::optional<dex::HostField> declared_field(std::string_view owner, std::string_view name) const override;
    dex::Value read_reflected_field(dex::ManagedRuntime &, const dex::HostField &, dex::ObjectId) override;
    dex::Value invoke_reflected(dex::ManagedRuntime &, const dex::HostMethod &,
                                std::span<const dex::Value>) override;

  private:
    dex::Value invoke_api(dex::ManagedRuntime &, const ApiSupport &, std::span<const dex::Value>);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::android
