#pragma once
#include "aether/android/framework.hpp"
#include "aether/android/display_configuration.hpp"
#include "aether/android/drag.hpp"
#include "aether/jni/bridge.hpp"
#include "aether/security/protocol.hpp"

namespace aether::security {
inline constexpr std::size_t activity_command_limit = 16 * 1024;
inline constexpr std::size_t activity_state_limit = 34 * 1024 * 1024;
inline constexpr std::size_t activity_terminal_activations_limit = 8 * 1024; // Includes the wire context.
enum class ActivityTerminalReason : std::uint64_t { guest_exit = 1, failure = 2 };
struct ActivityTerminalActivations {
    ActivityTerminalReason reason = ActivityTerminalReason::failure;
    std::uint64_t through_revision = 0;
    // Empty is terminal intent at the existing cursor, never an invented event.
    std::vector<android::ViewActivation> records;
};
std::vector<std::uint8_t> encode_activity_terminal_activations(const ActivityTerminalActivations &batch);
ActivityTerminalActivations decode_activity_terminal_activations(std::span<const std::uint8_t> bytes);
inline constexpr std::size_t activity_text_edit_observation_limit = 20 * 1024;
// One actual operation and its current editor document. This record codec does
// not activate a transport, create a provider, or encode retained View history.
std::vector<std::uint8_t> encode_activity_text_edit_observation(const android::TextEditObservation &observation);
android::TextEditObservation decode_activity_text_edit_observation(std::span<const std::uint8_t> bytes);
inline constexpr std::size_t activity_soft_input_observation_limit = activity_text_edit_observation_limit;
std::vector<std::uint8_t> encode_activity_soft_input_observation(const android::SoftInputObservation &observation);
android::SoftInputObservation decode_activity_soft_input_observation(std::span<const std::uint8_t> bytes);
enum class ActivityCommandKind : std::uint64_t { refresh, place, pointer, key, signal, close, configure, invoke, focus, toggle, scroll, set_scroll_percent, replace_text, set_selection, reveal_text_range, ime_edit, claim_soft_input, drag, prepare_accessibility_metadata, collection_selection };
struct ActivityCommand {
    ActivityCommandKind kind = ActivityCommandKind::refresh;
    android::WindowSignal signal = android::WindowSignal::activate;
    android::PointerInput pointer;
    android::KeyInput key;
    std::vector<android::ViewPlacement> placements;
    android::DisplayConfiguration configuration;
    dex::ObjectId view = 0; // Typed semantic accessibility action; never a host pointer.
    std::int32_t scroll_amount = 0;
    double scroll_percent = 0;
    std::u16string replacement_text;
    std::u16string expected_text; // Exact snapshot value; positional edits never rebase onto changed text.
    std::int32_t selection_start = 0, selection_end = 0;
    std::uint64_t expected_buffer_revision = 0, expected_text_revision = 0;
    android::SelectionOperation selection_operation = android::SelectionOperation::replace;
    std::uint64_t expected_view_revision = 0;
    dex::ObjectId collection_owner = 0;
    std::uint64_t expected_metadata_revision = 0;
    android::CollectionSelectionOperation collection_selection_operation = android::CollectionSelectionOperation::replace;
    float range_top = 0, range_bottom = 0;
    bool align_top = true;
    android::ImeEditKind ime_kind = android::ImeEditKind::begin;
    std::uint64_t ime_token = 0; // Session-local identity, never a HIMC or pointer.
    std::int32_t ime_cursor = 0;
    std::optional<android::ImeConversionTarget> ime_conversion;
    std::uint64_t soft_input_revision = 0;
    android::DragInput drag;
    std::vector<std::uint8_t> encode() const;
    static ActivityCommand decode(std::span<const std::uint8_t> bytes);
};
inline constexpr std::array<std::string_view, 8> activity_probes{
    "touches", "keys", "lastSource", "lastAction", "lastKey", "lastRepeat", "lastX", "lastY"};
struct ActivityState {
    std::string apk_hash, package, activity;
    android::Lifecycle lifecycle = android::Lifecycle::empty;
    dex::ObjectId content = 0;
    std::map<dex::ObjectId, android::ViewState> views;
    std::u16string trace;
    std::array<std::uint32_t, activity_probes.size()> probes{};
    android::FrameworkMetrics framework;
    dex::RuntimeMetrics managed;
    jni::Metrics jni;
    a64::Metrics cpu;
    bool handled = false;
    std::int32_t requested_orientation = -1; // Requested virtual display policy, never inferred from HWND.
    android::DisplayConfiguration configuration;
    std::vector<android::SoftInputRequest> soft_input_requests;
    // Global actual-operation facts survive removal of their source View.
    std::uint64_t view_activation_revision = 0;
    std::vector<android::ViewActivation> view_activations;
    // Collection values, provider presence and optional real widget policy share
    // each View's preparation tag; no managed/native handles enter the wire.
    std::uint64_t accessibility_metadata_attempt = 0, accessibility_invalidation_revision = 0;
    android::AccessibilityMetadataStatus accessibility_metadata_status = android::AccessibilityMetadataStatus::none;
    std::vector<std::uint8_t> encode() const;
    static ActivityState decode(std::span<const std::uint8_t> bytes);
    void validate() const;
};
// Ordered fragments retain the existing frame bound. Reassembly validates total size,
// identity and exact contiguous offsets before allocation/copying, with no pointer fields.
Frame activity_fragment(std::span<const std::uint8_t> bytes, std::size_t offset, Operation operation,
                        std::uint64_t sequence, std::uint64_t session);
void validate_activity_read_unavailable(const Frame &frame, std::uint64_t sequence, std::uint64_t session,
                                        bool reading, bool response_started);
class ActivityReassembly {
  public:
    ActivityReassembly(Operation operation, std::uint64_t sequence, std::uint64_t session, std::size_t limit);
    void accept(const Frame &frame);
    bool complete() const noexcept;
    std::vector<std::uint8_t> take();

  private:
    Operation operation_;
    std::uint64_t sequence_, session_;
    std::size_t limit_, total_ = 0;
    std::vector<std::uint8_t> bytes_;
};
} // namespace aether::security
