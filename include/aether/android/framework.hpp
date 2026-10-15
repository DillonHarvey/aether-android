#pragma once
#include "aether/android/input.hpp"
#include "aether/apk/resources.hpp"
#include "aether/dex/runtime.hpp"
#include <map>

namespace aether::android {
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
    ActivitySession(dex::ManagedRuntime &runtime, std::string package, apk::ResourceTable resources);
    ~ActivitySession();
    ActivitySession(const ActivitySession &) = delete;
    ActivitySession &operator=(const ActivitySession &) = delete;
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
    const FrameworkMetrics &metrics() const noexcept;
    const apk::ResourceTable &resources() const noexcept;
    std::optional<dex::HostClass> class_info(std::string_view descriptor) const override;
    bool method_is_static(const dex::DexImage &, dex::Index method) const override;
    dex::Value invoke(dex::ManagedRuntime &, dex::Index, std::span<const dex::Value>) override;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::android
