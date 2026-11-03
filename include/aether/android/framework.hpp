#pragma once
#include "aether/android/input.hpp"
#include "aether/android/drag.hpp"
#include "aether/android/display_configuration.hpp"
#include "aether/android/viewport.hpp"
#include "aether/android/profile.hpp"
#include "aether/common/android_process_identity.hpp"
#include "aether/android/native_surface.hpp"
#include "aether/android/native_window.hpp"
#include "aether/android/native_activity.hpp"
#include "aether/apk/resources.hpp"
#include "aether/apk/intent_value.hpp"
#include "aether/dex/runtime.hpp"
#include "aether/host/time_service.hpp"
#include "aether/host/file_service.hpp"
#include "aether/host/document_service.hpp"
#include "aether/host/notification_service.hpp"
#include "aether/host/clipboard_service.hpp"
#include <map>
#include <functional>
#include <string>

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
// Append signals to preserve the existing wire values, including close == 6.
enum class WindowSignal { activate, deactivate, minimize, restore, focus_gained, focus_lost, close, suspend, resume };
std::string_view lifecycle_name(Lifecycle state) noexcept;
enum class ImeEditKind { begin, update, commit, cursor, finish, cancel, conversion };
struct ImeConversionTarget {
    bool available = true;
    std::int32_t start = -1, end = -1;
    std::int32_t unchanged_prefix = -1; // Genuine native UTF-16 prefix, or no evidence.
    std::string previous_composition_sha256; // Complete prior native composition, explicit UTF-16LE bytes.
};
enum class ViewKind { linear_layout, text, button, checkbox, scroll_view, edit_text, surface_view, frame_layout, native_content, view = 9 };
inline constexpr std::size_t view_activation_limit = 256;
struct ViewActivation {
    std::uint64_t revision = 0;
    dex::ObjectId view = 0;
    std::uint64_t window_generation = 0;
};
struct AccessibilityCollectionInfo {
    std::int32_t row_count = -1, column_count = -1;
    bool hierarchical = false;
    std::int32_t selection_mode = 0;
    std::int32_t item_count = -1, important_item_count = -1;
};
struct AccessibilityCollectionItemInfo {
    std::int32_t row_index = -1, row_span = 1, column_index = -1, column_span = 1;
    bool heading = false, selected = false;
};
enum class AccessibilityMetadataStatus : std::uint64_t { none, ready, stale, mutated };
enum class CollectionSelectionOperation { replace, add, remove };
enum class SelectionOperation { replace, add, remove };
inline constexpr std::size_t editable_text_limit = 4096;
inline constexpr std::size_t text_edit_history_limit = 16;
inline constexpr std::size_t text_edit_history_units = editable_text_limit;
inline constexpr std::size_t text_mutation_history_limit = 64;
struct TextMutation {
    std::uint64_t revision = 0;
    std::int32_t start = 0, removed = 0, inserted = 0, before_length = 0;
};
enum class TextEditEventKind { composition, composition_finalized, conversion_target_changed };
struct TextEditEvent {
    // Session-global sequence: merging View histories preserves real edit order.
    std::uint64_t revision = 0;
    TextEditEventKind kind = TextEditEventKind::composition;
    std::u16string text;
    // Captured while this backing buffer was current for the same logical View.
    // Historical payload identity never follows a later backing-buffer swap.
    std::uint64_t buffer_revision = 0;
};
inline constexpr std::size_t view_description_limit = 4096;
inline constexpr std::size_t activity_description_limit = 65536;
struct ViewState {
    dex::ObjectId object = 0, parent = 0, listener = 0;
    ViewKind kind = ViewKind::text;
    std::vector<dex::ObjectId> children;
    std::u16string text;
    // Publication-only text. The original managed CharSequence stays traced
    // in the worker's charged per-View state and never crosses the wire.
    std::u16string content_description;
    std::int32_t id = -1, orientation = 0;
    bool enabled = true, pressed = false, focused = false;
    // Published semantic eligibility, not a serialized managed listener handle.
    bool clickable = false, checked = false;
    bool focusable = false;
    std::int32_t selection_start = -1, selection_end = -1;
    // Coalesced publication revisions from real edit notification paths, not
    // an event log. They remain zero for non-editable View kinds.
    std::uint64_t text_event_revision = 0, selection_event_revision = 0;
    // Exact current-buffer replacement deltas after this coverage revision.
    // A missing interval or backing-buffer swap retires older coverage.
    std::uint64_t text_mutation_base_revision = 0;
    std::vector<TextMutation> text_mutations;
    std::int32_t composing_start = -1, composing_end = -1;
    std::uint64_t composition_event_revision = 0, ime_token = 0;
    // Bounded actual-operation history, not a lossless delivery promise. The
    // dropped watermark includes eviction and unavailable payloads. Known
    // retained records may precede a later missing revision: a gap never
    // invalidates their actual payloads. Gaps must never be reconstructed
    // from a later whole-value snapshot.
    std::uint64_t text_edit_event_revision = 0, text_edit_dropped_revision = 0, text_buffer_revision = 0;
    std::vector<TextEditEvent> text_edit_events;
    std::int32_t conversion_start = -1, conversion_end = -1;
    bool conversion_available = true;
    // Measured vertical ScrollView geometry in virtual Android pixels.
    std::int32_t scroll_y = 0, scroll_range_y = 0, scroll_viewport_y = 0;
    ViewBounds bounds;
    std::optional<AccessibilityCollectionInfo> accessibility_collection;
    std::optional<AccessibilityCollectionItemInfo> accessibility_collection_item;
    dex::ObjectId accessibility_collection_owner = 0;
    std::uint64_t accessibility_metadata_revision = 0;
    bool accessibility_node_provider_present = false;
    std::uint32_t accessibility_actions = 0;
    // Verified app-library policy; Android CollectionInfo has no such field.
    std::optional<bool> accessibility_selection_required;
};
struct TextEditObservation {
    ViewState document;
    TextEditEvent event;
    std::uint64_t view_revision = 0;
    bool rooted = false;
};
struct SoftInputRequest {
    std::uint64_t revision = 0, window_generation = 0;
    dex::ObjectId view = 0;
    bool show = false, implicit = false;
};
struct SoftInputObservation {
    SoftInputRequest request;
    ViewState document;
    std::uint64_t view_revision = 0;
    bool rooted = false;
    Lifecycle lifecycle = Lifecycle::empty;
    bool window_focused = false;
};
// Synchronous trusted native request acknowledgement, never visibility proof.
// The sink cannot reenter guest execution; exceptions remain terminal.
using SoftInputObserver = std::function<bool(const SoftInputObservation &)>;
// Trusted C++ sink only. The record is borrowed synchronously for this call;
// retaining it requires an explicit copy. The sink must not reenter the session.
using TextEditObserver = std::function<void(const TextEditObservation &)>;
// Trusted held-package member read only; no host pathname or guest reentry.
// nullopt means the selected member is absent. Integrity errors propagate.
using ResourceFileReader = std::function<std::optional<std::vector<std::uint8_t>>(
    std::string_view container, std::string_view path, std::size_t max_bytes)>;
// Trusted software-session query behavior only; this is not an Android user,
// encryption state, host lock observation or storage/capability permission.
enum class ImplicitComponentQueryPolicy { unknown, interactive_session_both_classes };
// Trusted accessibility Binder lookup availability only; absence is neither a
// disabled accessibility-state value nor a claim about other Android services.
enum class AccessibilityBackendAvailability { unknown, service_absent };

// Immutable held-manifest facts. A literal (including empty) is distinct
// from an absent name and from an unresolved typed resource reference.
struct PackageMetadata {
    std::optional<std::u16string> version_name;
    std::optional<std::uint32_t> version_name_resource;
    std::uint32_t version_code = 0, version_code_major = 0;
    // Raw held-manifest title provenance. Empty literals stay distinct from
    // absent labels; unresolved typed values never become fallback text.
    apk::DisplayValue activity_label, application_label;
    std::u16string activity_name;
    // False means title provenance is unknown, including unmodeled alias
    // inheritance. It must not be presented as a known null or empty title.
    bool activity_label_bound = false;
    // Original application metadata, independent of Activity label provenance.
    // Missing metadata and a known absent manifest attribute remain distinct.
    apk::ManifestBoolean supports_rtl;
    std::optional<std::uint32_t> application_target_sdk;
    bool supports_rtl_bound = false;
    // Complete held base/split declaration inventory only. Unknown names or
    // absent source evidence must never become a known missing service.
    std::vector<std::string> declared_services;
    bool service_inventory_bound = false;
    // Original held declarations and ordered raw meta-data, including aliases,
    // duplicate keys and unresolved typed names/values. This flag proves only
    // raw inventory completeness, never a partially resolved Bundle.
    std::vector<apk::Activity> activities;
    std::vector<std::vector<apk::ManifestMetaDataEntry>> activity_meta_data;
    bool activity_meta_data_bound = false;
    // Aligned raw configChanges values preserve absence/unsupported kinds.
    std::vector<apk::ManifestInteger> activity_config_changes;
    std::vector<apk::ManifestInteger> activity_recreate_on_config_changes;
    apk::ManifestBoolean application_enabled;
    bool application_enabled_bound = false;
};
struct FrameworkMetrics {
    std::uint64_t api_calls = 0, lifecycle_callbacks = 0, managed_clicks = 0;
    std::uint64_t denied_permissions = 0, unsupported_services = 0, view_revision = 0;
    std::uint64_t pointer_events = 0, key_events = 0;
    // Accepted backend attempts and actual transport drops, never delivery proof.
    std::uint64_t android_log_attempts = 0, android_log_transport_drops = 0;
};
// One activity and retained view tree per runtime. No Windows handles enter the guest.
// WindowSignal is the host-independent boundary used by the later Win32 event adapter.
class ActivitySession final : public dex::HostInterface {
  public:
    ActivitySession(dex::ManagedRuntime &runtime, std::string package, apk::ResourceTable resources,
                    const host::TimeService *time = nullptr, host::FileService *files = nullptr,
                    DisplayConfiguration configuration = {}, host::NotificationService *notifications = nullptr,
                    host::DocumentService *documents = nullptr, host::ClipboardService *clipboard = nullptr);
    ~ActivitySession();
    // Initial owner binding, before any Activity construction; no reads/replay.
    void set_resource_file_reader(ResourceFileReader);
    // One initial trusted held-manifest binding; no package enumeration.
    void set_package_metadata(PackageMetadata);
    // Bind once before Application/guest work; only implicit PM matching uses it.
    void set_component_query_policy(ImplicitComponentQueryPolicy);
    // Bind once before all framework queries or guest work. These virtual
    // Android facts grant no host permission and expose no guest setter.
    void set_process_identity(AndroidProcessIdentity);
    void set_accessibility_backend_availability(AccessibilityBackendAvailability);
    // Exact effective manifest theme; absent/default/unresolved stays unknown.
    // Target SDK is bound before Application/default Context theme initialization.
    void set_target_sdk(std::uint32_t);
    void set_activity_theme(apk::ManifestInteger);
    // Initial trusted host lease only, before any Application/Theme/Activity.
    // Exact pixels and explicit virtual-display policy, never inverse-dp guesses.
    // No physical attachment, frame or visibility is granted by this binding.
    void set_launch_viewport(ViewportAdmission);
    // Initial trusted native lifecycle binding, before Activity construction.
    // No replay; terminal cleanup releases the sink without guest callbacks.
    // Save results are copied into the original callback Bundle; all other
    // lifecycle stages require an empty result.
    void set_native_activity_observer(NativeActivityObserver);
    void set_native_activity_pointer_observer(NativeActivityPointerObserver);
    void set_native_activity_key_observer(NativeActivityKeyObserver);
    void set_key_completion_observer(NativeKeyCompletionObserver);
    // Trusted ordered native completion, delivered later by the managed main
    // queue. The entry roots the original receivers and never requeues input.
    std::unique_ptr<dex::ManagedMainEntry> make_native_pointer_completion(const NativeActivityInputCompletion &);
    std::unique_ptr<dex::ManagedMainEntry> make_native_activity_work(const NativeActivityHostWork &);
    bool finishing() const noexcept;
    std::optional<ActivityFinishRequest> pending_finish_request() const;
    void acknowledge_finish_request(std::uint64_t ordinal);
    // Registration never replays history. The sink remains installed until
    // replaced/unset or session destruction; captured resources must outlive it.
    // Capture/sink failures are sticky, including errors in noexcept cleanup:
    // snapshot_views/guarded entries rethrow them. Transport users must reach
    // that failure boundary before reporting a command successfully completed.
    void set_text_edit_observer(TextEditObserver observer);
    void set_soft_input_observer(SoftInputObserver observer);
    std::vector<SoftInputRequest> soft_input_requests() const;
    bool claim_soft_input(std::uint64_t revision, std::uint64_t host_ime_token,
                          std::uint64_t expected_view_revision, std::u16string_view expected_text);
    bool drag(const DragInput &input);
    // Cheap idle/main-quantum and terminal boundary check for transport users:
    // rethrows sticky capture/sink failure and rejects active-sink reentry.
    // With no observer/failure this is a no-op; no tree snapshot is captured.
    void check_text_edit_observer() const;
    // Historical successful activations remain pending until exact-prefix
    // transport acknowledgement, including across Activity retirement.
    std::vector<ViewActivation> pending_view_activations() const;
    // Terminal custody may retain a valid completed prefix despite a later
    // sticky recorder failure. This does not clear or forgive that failure.
    std::vector<ViewActivation> terminal_view_activations() const;
    // Terminal unwind never invokes guest close callbacks or flushes queued
    // preferences. The broker's terminal lifetime revokes remaining grants.
    void prepare_terminal_cleanup() noexcept;
    void acknowledge_view_activations(std::uint64_t through);
    std::uint64_t view_activation_revision() const noexcept;
    void check_view_activations() const;
    std::uint64_t begin_view_activation(dex::ObjectId object) const noexcept override;
    void view_activated(dex::ObjectId object, std::uint64_t generation) noexcept override;
    void collection_selection_policy_write(dex::ManagedRuntime &runtime, dex::ObjectId object) override;
    bool prepare_accessibility_metadata(std::uint64_t expected_view_revision, dex::ObjectId expected_content);
    std::uint64_t accessibility_metadata_attempt() const noexcept;
    AccessibilityMetadataStatus accessibility_metadata_status() const noexcept;
    std::uint64_t accessibility_invalidation_revision() const noexcept;
    bool collection_selection(dex::ObjectId view, dex::ObjectId owner, std::uint64_t expected_metadata_revision,
                              std::uint64_t expected_view_revision, CollectionSelectionOperation operation);
    ActivitySession(const ActivitySession &) = delete;
    ActivitySession &operator=(const ActivitySession &) = delete;
    // Bind and run the declared Application before any Activity constructor.
    void initialize_application(std::string_view descriptor = "Landroid/app/Application;",
                                std::string_view factory_descriptor = {});
    dex::ObjectId application() const noexcept;
    // Fixed virtual-display profile: unspecified(-1), landscape(0), portrait(1).
    // Seed the exact manifest request before the Activity constructor/onCreate.
    void launch(std::string_view descriptor, std::int32_t requested_orientation = -1,
                std::uint32_t config_changes = 0, std::uint32_t target_sdk = 35,
                std::string_view component_name = {});
    // Actual resolved launch record. The component names the selected
    // declaration; descriptor remains the independently authorized target.
    void launch(std::string_view descriptor, const apk::IntentValue &intent,
                std::int32_t requested_orientation = -1, std::uint32_t config_changes = 0,
                std::uint32_t target_sdk = 35, std::string_view component_name = {});
    std::int32_t requested_orientation() const noexcept;
    const DisplayConfiguration &display_configuration() const noexcept;
    // Trusted capture metadata, not guest-visible dispatch authority.
    std::uint64_t window_generation() const noexcept;
    std::uint64_t input_generation() const noexcept;
    // The caller composes selected resources before handing over a configuration.
    // Application identity/services survive any required Activity recreation.
    void configure(const DisplayConfiguration &configuration, apk::ResourceTable resources);
    void signal(WindowSignal signal);
    bool click(dex::ObjectId view);
    // Focus the same enabled listener-backed views reached by current Tab
    // traversal. Never replace an active pointer gesture or synthesize a click.
    bool focus(dex::ObjectId view);
    bool toggle(dex::ObjectId view);
    // Relative small/page requests: -1/+1 and -2/+2, respectively.
    bool scroll(dex::ObjectId view, std::int32_t amount);
    bool set_scroll_percent(dex::ObjectId view, double percent);
    bool replace_text(dex::ObjectId view, std::u16string_view text);
    // Add/remove use the actual selection when executed, under exact buffer
    // and text-commit fences. Only a contiguous resulting selection is supported.
    bool set_selection(dex::ObjectId view, std::int32_t start, std::int32_t end,
                       std::u16string_view expected_text, std::uint64_t expected_buffer_revision,
                       std::uint64_t expected_text_revision, SelectionOperation operation);
    bool reveal_text_range(dex::ObjectId view, std::uint64_t expected_revision,
                           std::u16string_view expected_text, float top, float bottom, bool align_top);
    bool ime_edit(ImeEditKind kind, dex::ObjectId view, std::uint64_t token,
                  std::uint64_t expected_view_revision, std::u16string_view expected_text,
                  std::u16string_view text, std::int32_t cursor,
                  std::optional<ImeConversionTarget> conversion = {});
    void place_views(std::span<const ViewPlacement> placements);
    bool pointer(const PointerInput &event);
    bool key(const KeyInput &event);
    KeyDispatchOutcome dispatch_key(const KeyInput &event, std::uint64_t request);
    // Pure pre-dispatch observation for the transport's cancelled-vs-unhandled
    // witness. Never infer cancellation from state changed by a real callback.
    bool key_capture_current(const KeyInput &event) const noexcept;
    void close();
    Lifecycle state() const noexcept;
    dex::ObjectId activity() const noexcept;
    dex::ObjectId content_view() const noexcept;
    // Successful logical content-root commit incarnation; zero before the first
    // commit. Pair with the actual Activity, window generation and content root.
    // This is not physical View attachment, callback delivery or visibility.
    std::uint64_t attachment_revision() const noexcept;
    const std::map<dex::ObjectId, ViewState> &views() const noexcept;
    std::map<dex::ObjectId, ViewState> snapshot_views() const;
    const std::vector<std::string> &events() const noexcept;
    std::u16string_view standard_output(bool error) const noexcept;
    bool write_standard_output(dex::ManagedRuntime &, bool error, std::u16string_view) override;
    const FrameworkMetrics &metrics() const noexcept;
    const apk::ResourceTable &resources() const noexcept;
    // Trusted JNI join: only this session's rooted canonical manager is valid.
    bool owns_asset_manager(dex::ObjectId object) const noexcept;
    // Preparation runs under the existing admitted managed-work owner. The
    // publication/validation callbacks only inspect fixed live provider state.
    void prepare_native_asset_manager_sources();
    std::uint64_t publish_native_asset_manager(dex::ObjectId object) const noexcept;
    bool owns_native_asset_manager(std::uint64_t token) const noexcept;
    // The actual session registry is shared with JNI/EGL. No producer exists
    // until the observer acknowledges this root's real host backing.
    std::shared_ptr<NativeWindows> native_windows() const;
    std::shared_ptr<NativeWindowProducer> surface_producer(dex::ObjectId object) const;
    void set_native_surface_observer(std::function<NativeSurfaceAdmission(const NativeSurfaceRequest &)>);
    // Normal owner execution only: may admit backing and invoke managed
    // callbacks. Snapshots never call this operation.
    void reconcile_native_surface();
    std::optional<dex::HostClass> class_info(std::string_view descriptor) const override;
    // Opted-in hosted initialization lifecycle, including source-proven classes
    // with no own body; actual superclass initialization remains mandatory.
    // Unknown static effects are unsupported, never inferred absent.
    void initialize_class(dex::ManagedRuntime &, std::string_view descriptor) override;
    dex::HostBootstrapClassPresence bootstrap_class_presence(dex::ManagedRuntime &,
        std::string_view descriptor) const override;
    bool method_is_static(const dex::DexImage &, dex::Index method) const override;
    std::optional<dex::Value> static_field(dex::ManagedRuntime &, dex::Index) override;
    dex::Value invoke(dex::ManagedRuntime &, dex::Index, std::span<const dex::Value>) override;
    std::unique_ptr<dex::HostInputStream> open_input_stream(dex::ManagedRuntime &, std::u16string_view) override;
    std::optional<dex::HostMethod> public_method(std::string_view owner, std::string_view name,
                                               std::span<const std::string> parameters) const override;
    std::optional<dex::HostField> public_field(std::string_view owner, std::string_view name) const override;
    std::optional<dex::HostField> declared_field(std::string_view owner, std::string_view name) const override;
    dex::Value read_reflected_field(dex::ManagedRuntime &, const dex::HostField &, dex::ObjectId) override;
    void write_reflected_field(dex::ManagedRuntime &, const dex::HostField &, dex::ObjectId, dex::Value) override;
    dex::Value invoke_reflected(dex::ManagedRuntime &, const dex::HostMethod &,
                                std::span<const dex::Value>) override;

  private:
    void launch_impl(std::string_view descriptor, const apk::IntentValue *intent,
                     std::int32_t requested_orientation, std::uint32_t config_changes,
                     std::uint32_t target_sdk, std::string_view component_name);
    dex::Value invoke_api(dex::ManagedRuntime &, const ApiSupport &, std::span<const dex::Value>);
    dex::Value invoke_static_api_body(dex::ManagedRuntime &, const ApiSupport &, std::span<const dex::Value>);
    dex::Value invoke_api_body(dex::ManagedRuntime &, const ApiSupport &, std::span<const dex::Value>);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::android
