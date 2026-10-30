#pragma once
#include <Windows.h>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aether::host {
class TextLayout;
enum class AccessibilityKind { container, text, button, checkbox, scroll_view, edit_text };
enum class AccessibilitySelectionOperation { replace, add, remove };
enum class AccessibilityCollectionSelectionOperation { replace, add, remove };
struct AccessibilityTextMutation {
    std::uint64_t revision = 0;
    std::int32_t start = 0, removed = 0, inserted = 0, before_length = 0;
};
struct AccessibilityTextMutationRecord {
    std::uint64_t view = 0, buffer_revision = 0;
    AccessibilityTextMutation mutation;
};
struct AccessibilityTextMutationGap {
    std::uint64_t view = 0, buffer_revision = 0, through_revision = 0;
};
class AccessibilityInvocation; // Opaque once-only origin of an actual UIA Invoke request.
enum class AccessibilityActionKind { invoke, focus, toggle, scroll, set_scroll_percent, replace_text, move_caret, extend_selection, clipboard_access, ime_show_candidates, ime_hide_candidates, set_selection, reveal_text_range, collection_selection };
struct AccessibilityAction {
    AccessibilityActionKind kind = AccessibilityActionKind::invoke;
    std::uint64_t view = 0;
    std::int32_t scroll_amount = 0;
    double scroll_percent = 0;
    std::u16string replacement_text;
    std::int32_t caret_offset = 0;
    std::int32_t selection_end = 0;
    AccessibilitySelectionOperation selection_operation = AccessibilitySelectionOperation::replace;
    std::u16string expected_text;
    std::uint64_t expected_buffer_revision = 0, expected_text_revision = 0;
    std::uint64_t expected_view_revision = 0;
    float range_top = 0, range_bottom = 0;
    bool align_top = true;
    std::shared_ptr<AccessibilityInvocation> invocation; // Host-only; never enters guest IPC.
    std::uint64_t collection_owner = 0, expected_metadata_revision = 0;
    AccessibilityCollectionSelectionOperation collection_selection_operation = AccessibilityCollectionSelectionOperation::replace;
};
struct AccessibilityGrid {
    int rows = 0, columns = 0;
    int item_count = -1, important_item_count = -1;
    bool nonvirtual_subtree = false;
    int selection_mode = 0;
    std::uint64_t metadata_revision = 0;
    std::optional<bool> selection_required = std::nullopt; // Only an authenticated current policy getter may supply this; generic Android metadata stays unknown.
    bool operator==(const AccessibilityGrid &) const = default;
};
struct AccessibilityGridItem {
    std::uint64_t owner = 0;
    int row = 0, column = 0, row_span = 1, column_span = 1;
    bool selected = false;
    std::uint32_t actions = 0;
    bool operator==(const AccessibilityGridItem &) const = default;
};
struct AccessibilityNode {
    std::uint64_t id = 0, parent = 0;
    std::vector<std::uint64_t> children;
    AccessibilityKind kind = AccessibilityKind::text;
    std::u16string name;
    std::u16string value;
    RECT bounds{}; // Clipped physical screen pixels, from the trusted window layout.
    std::shared_ptr<const TextLayout> text_layout; // Same immutable shaping used by painting.
    POINT text_origin{}; // Unclipped text origin, physical screen pixels.
    RECT text_clip{}; // Content inset intersected with all visible ancestor clips.
    POINT view_origin{}; // Unclipped View origin, physical screen pixels.
    float text_scale = 1; // Physical pixels per logical layout unit.
    bool text_can_scroll = false; // Existing root ScrollView, never a grant.
    std::uint64_t source_view_revision = 0;
    std::uint64_t text_event_revision = 0, selection_event_revision = 0;
    std::uint64_t text_mutation_base_revision = 0;
    std::vector<AccessibilityTextMutation> text_mutations;
    std::uint64_t text_buffer_revision = 0, text_edit_event_revision = 0;
    std::int32_t composing_start = -1, composing_end = -1;
    std::uint64_t composition_event_revision = 0, ime_token = 0;
    std::int32_t conversion_start = -1, conversion_end = -1;
    bool conversion_available = true; // Unknown metadata is distinct from a known empty target.
    bool enabled = false, focused = false, offscreen = true, invokable = false, focusable = false;
    bool toggleable = false, checked = false;
    bool scrollable = false;
    std::int32_t caret_pos = -1, selection_start = -1, selection_end = -1;
    bool clipboard_available = false;
    std::int32_t scroll_y = 0, scroll_range_y = 0, scroll_viewport_y = 0;
    std::optional<AccessibilityGrid> grid;
    std::optional<AccessibilityGridItem> grid_item;
};
struct AccessibilitySnapshot {
    std::u16string name;
    RECT bounds{};
    std::uint64_t content = 0;
    std::vector<AccessibilityNode> nodes;
    bool active = false, foreground = false;
};
enum class AccessibilityTextEditKind { composition, composition_finalized, conversion_target_changed };
struct AccessibilityTextEditEvent {
    std::uint64_t view = 0, buffer_revision = 0, revision = 0;
    AccessibilityTextEditKind kind = AccessibilityTextEditKind::composition;
    std::u16string text;
};
struct AccessibilityTextEditGap {
    std::uint64_t view = 0, buffer_revision = 0, dropped_revision = 0;
};
struct AccessibilityTextEditResult {
    std::uint64_t attempted = 0, failed = 0, retired = 0;
};
// UIA reads immutable published values, never a guest runtime or a pipe. Actions
// are bounded requests marshalled back to the window's existing UI-thread queue.
class WindowAccessibility final {
  public:
    WindowAccessibility(HWND window, UINT action_message);
    ~WindowAccessibility();
    WindowAccessibility(const WindowAccessibility &) = delete;
    WindowAccessibility &operator=(const WindowAccessibility &) = delete;
    AccessibilityTextEditResult publish(AccessibilitySnapshot snapshot,
        std::vector<AccessibilityTextEditEvent> text_edits = {},
        std::vector<AccessibilityTextEditGap> text_edit_gaps = {});
    // One-shot actual operation payloads for existing semantic providers;
    // delivery does not wait for shaped geometry or create new providers.
    AccessibilityTextEditResult deliver_text_edits(std::vector<AccessibilityTextEditEvent> text_edits,
        std::vector<AccessibilityTextEditGap> text_edit_gaps);
    // UI-owner receipt fence, including an event currently inside a COM callback.
    bool text_edit_delivery_idle() const noexcept;
    bool text_edit_delivery_active() const noexcept;
    // Complete reachable editor manifest from a genuine current worker state.
    // Advance text anchors before geometry settles; never reuse old shaping.
    void advance_text_documents(std::vector<AccessibilityNode> current_editors,
        std::vector<AccessibilityTextMutationRecord> mutations,
        std::vector<AccessibilityTextMutationGap> gaps);
    // One genuine streamed editor observation is not a complete tree manifest.
    // It can retire only this editor and never introduces a new provider.
    void advance_text_document(AccessibilityNode editor, bool rooted);
    LRESULT object(WPARAM wp, LPARAM lp);
    std::optional<AccessibilityAction> next_action();
    // UI owner only. Consume the original provider receipt before any COM call;
    // successful callbacks may legitimately have removed the original control.
    // S_FALSE means no event attempt; native delivery failures are never retried.
    HRESULT complete_invoke(const std::shared_ptr<AccessibilityInvocation> &invocation, bool handled) noexcept;
    // Pin only an already exposed invokable identity for an actual worker fact.
    // No provider is introduced for a guest-only or never-published control.
    std::shared_ptr<AccessibilityInvocation> capture_invocation(std::uint64_t view);
    // Irreversibly retire dynamic guest projection before terminal historical
    // events. The connected host/provider identities remain until disconnect.
    void retire_for_terminal();
    // Close the action gate during layout acknowledgement without retiring
    // exposed View identities. The next publication reopens it normally.
    void suspend() noexcept;
    void disconnect() noexcept;

  private:
    void advance_text_documents_impl(std::vector<AccessibilityNode> current_editors,
        std::vector<AccessibilityTextMutationRecord> mutations,
        std::vector<AccessibilityTextMutationGap> gaps, std::uint64_t only_view);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::host
