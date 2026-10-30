#pragma once
#include "aether/security/activity_session.hpp"
#include "aether/host/windows/document_service.hpp"

namespace aether::security {
struct ActivityTextEditEvent {
    dex::ObjectId view = 0;
    std::uint64_t buffer_revision = 0;
    android::TextEditEvent event;
};
struct ActivityTextEditGap {
    dex::ObjectId view = 0;
    std::uint64_t buffer_revision = 0, dropped_revision = 0;
};
struct ActivityTextMutation {
    dex::ObjectId view = 0;
    std::uint64_t buffer_revision = 0;
    android::TextMutation mutation;
};
struct ActivityTextMutationGap {
    dex::ObjectId view = 0;
    std::uint64_t buffer_revision = 0, through_revision = 0;
};
struct ActivityCompletion {
    std::uint64_t ticket = 0;
    ActivityCommandKind kind = ActivityCommandKind::refresh;
    bool handled = false, read_unavailable = false;
    // Per-request preparation outcome; never inferred from a later mailbox state.
    std::uint64_t accessibility_metadata_attempt = 0;
    std::uint64_t accessibility_invalidation_revision = 0;
    android::AccessibilityMetadataStatus accessibility_metadata_status = android::AccessibilityMetadataStatus::none;
    // Exact one-shot facts, independent of the latest-state mailbox and View lifetime.
    std::vector<android::ViewActivation> view_activations;
    // One-shot historical operation data, independent of the latest-state mailbox.
    std::vector<ActivityTextEditEvent> text_edit_events;
    std::vector<ActivityTextEditGap> text_edit_gaps;
    // Exact no-text replacement deltas survive latest-state coalescing.
    // A gap never invalidates independently retained earlier mutations.
    std::vector<ActivityTextMutation> text_mutations;
    std::vector<ActivityTextMutationGap> text_mutation_gaps;
};
struct ActivityTerminalActivation {
    android::ViewActivation activation;
    std::uint64_t ticket = 0;
};
struct ActivityTerminalActivationCustody {
    std::uint64_t through_revision = 0;
    std::vector<ActivityTerminalActivation> records;
};
struct ActivityDispatchMetrics {
    std::uint64_t submitted = 0, completed = 0, read_requests = 0, coalesced_reads = 0;
    std::uint64_t read_failures = 0, recovered_reads = 0, peak_outstanding = 0;
    std::uint32_t io_thread = 0;
};
struct ActivityPublication {
    std::shared_ptr<const ActivityState> state, last_live;
    // Receipt floor captured only with a genuine final worker snapshot.
    std::uint64_t text_edit_observation_revision = 0;
    std::uint32_t process_id = 0;
    std::uint64_t commands = 0, broker_calls = 0;
    bool exited = false;
    std::string audit = "[]";
    std::string durable_audit = "{}";
};
// One serial I/O thread owns IsolatedActivity. The UI submits bounded commands and
// consumes completions without waiting on pipes. One read may be pending at a time.
class ActivityDispatcher final {
  public:
    explicit ActivityDispatcher(const std::filesystem::path &apk, ActivityMode mode = ActivityMode::normal,
                                const std::filesystem::path &developer_output_root = {});
    explicit ActivityDispatcher(InstalledActivity application);
    ~ActivityDispatcher();
    ActivityDispatcher(const ActivityDispatcher &) = delete;
    ActivityDispatcher &operator=(const ActivityDispatcher &) = delete;
    std::uint64_t submit(ActivityCommand command);
    // Trusted explicit-review admission; service ownership never enters command IPC.
    std::uint64_t drop_document(host::PreparedDocumentSource source, ActivityCommand command);
    // Exact explicitly reviewed text stays host-only until brokered DROP delivery.
    std::uint64_t drop_text(std::u16string text, ActivityCommand command);
    void signal(android::WindowSignal value);
    void place_views(std::span<const android::ViewPlacement> placements);
    std::uint64_t configure(const android::DisplayConfiguration &configuration);
    void pointer(const android::PointerInput &input);
    std::uint64_t key(const android::KeyInput &input);
    std::uint64_t refresh();
    void close();
    void abort() noexcept;
    HANDLE completion_event() const noexcept;
    void set_notification(HWND window, UINT message); // Host-only HWND; detached before destruction.
    // UI-owner registration/lifetime only; no HWND or clipboard identity enters guest IPC.
    void bind_clipboard_window(HWND window);
    void retire_clipboard_window() noexcept;
    // Called on the UI thread. Commits the latest immutable validated state and
    // returns ordered acknowledgements, including unhandled native key decisions.
    std::vector<ActivityCompletion> consume();
    // One bounded mid-callback record. Receipt follows actual UI consumption,
    // not extraction; the worker remains paused until receipt or cancellation.
    std::shared_ptr<const android::TextEditObservation> take_text_edit_observation();
    // Validated non-idle command provenance, visible only while this UI owner
    // holds the single claimed record. Zero denotes an idle/startup observation.
    std::uint64_t text_edit_observation_ticket() const;
    void complete_text_edit_observation(std::uint64_t event_revision);
    std::shared_ptr<const android::SoftInputObservation> take_soft_input_observation();
    std::uint64_t soft_input_observation_ticket() const;
    void complete_soft_input_observation(std::uint64_t revision, bool accepted);
    // Independent of terminal failure: take, consume original providers, then receipt.
    std::shared_ptr<const ActivityTerminalActivationCustody> take_terminal_activations();
    void complete_terminal_activations(std::uint64_t through_revision);
    bool idle() const;
    bool read_pending() const;
    ActivityDispatchMetrics dispatch_metrics() const;
    const ActivityPublication &publication() const noexcept;
    const ActivityState &snapshot() const;
    const auto &views() const { return snapshot().views; }
    const auto &metrics() const { return snapshot().framework; }
    auto content_view() const { return snapshot().content; }
    auto state() const { return snapshot().lifecycle; }
    std::uint32_t probe(std::string_view name) const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::security
