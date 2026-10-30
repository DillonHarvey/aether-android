#include "aether/host/windows/accessibility.hpp"
#include "aether/host/windows/text_layout.hpp"
#include <objbase.h>
#include <oleauto.h>
#include <UIAutomation.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <atomic>
#include <deque>
#include <limits>
#include <iterator>
#include <map>
#include <mutex>
#include <new>
#include <stdexcept>
#include <utility>
#include <wrl/client.h>

namespace aether::host {
class AccessibilityInvocation final {
  public:
    const std::shared_ptr<void> connection;
    const Microsoft::WRL::ComPtr<IRawElementProviderSimple> provider;
    const std::uint64_t view, serial;
    bool consumed = false; // Protected by the originating connection's mutex.
    AccessibilityInvocation(std::shared_ptr<void> state, IRawElementProviderSimple *origin,
                            std::uint64_t id, std::uint64_t identity)
        : connection(std::move(state)), provider(origin), view(id), serial(identity) {}
};
namespace {
using Microsoft::WRL::ComPtr;
constexpr std::size_t maximum_nodes = 256, maximum_actions = 32;
constexpr std::size_t maximum_live_text_ranges = 4096;
struct RangeDocument {
    std::uint64_t buffer_revision = 0, text_revision = 0;
    std::u16string text;
};
struct RangeAnchor {
    std::uint64_t view = 0, serial = 0;
    std::int32_t start = 0, end = 0;
    std::shared_ptr<const RangeDocument> document;
    bool retired = false;
};
struct RangeQuota {};
struct GridCell {
    std::uint64_t view = 0, serial = 0;
    int row = 0, column = 0;
    bool operator==(const GridCell &) const = default;
};
struct GridProjection {
    AccessibilityGrid metadata;
    std::uint64_t owner_serial = 0, shape_epoch = 0;
    std::vector<GridCell> cells, children;
};
struct Entry {
    AccessibilityNode node;
    std::uint64_t serial = 0;
    std::uint64_t grid_owner = 0, grid_owner_serial = 0;
    std::shared_ptr<const GridProjection> grid_projection;
    std::uint64_t text_edit_attempted_revision = 0;
    std::shared_ptr<const RangeDocument> document;
    std::shared_ptr<const AccessibilityNode> pending_content;
    bool text_retired = false;
    const AccessibilityNode &current() const noexcept { return pending_content ? *pending_content : node; }
};
struct Request {
    AccessibilityAction action;
    std::uint64_t serial = 0, collection_owner_serial = 0, collection_shape = 0;
};
struct State {
    const DWORD owner = GetCurrentThreadId();
    std::mutex mutex;
    HWND window;
    UINT message;
    bool connected = true, active = false, foreground = false, actions_suspended = true, terminal = false;
    RECT bounds{};
    std::u16string name;
    std::uint64_t content = 0, next_serial = 1, next_grid_shape = 1;
    std::map<std::uint64_t, Entry> nodes;
    std::deque<Request> actions;
    // Weak ownership permits Release/destruction under this mutex without an
    // unregister callback or a State/range lifetime cycle.
    std::vector<std::weak_ptr<RangeAnchor>> range_anchors;
    State(HWND window_value, UINT message_value) : window(window_value), message(message_value) {}
};
// Caller holds the connection lock. A streamed editor retirement may make a
// previously complete cell matrix unavailable before the next full snapshot.
bool available_grid_nodes(const std::map<std::uint64_t, Entry> &nodes, std::uint64_t id) noexcept {
    const auto owner = nodes.find(id);
    if (!id || owner == nodes.end() ||
        owner->second.text_retired || !owner->second.node.grid || !owner->second.grid_projection) return false;
    const auto &projection = *owner->second.grid_projection;
    if (projection.owner_serial != owner->second.serial) return false;
    for (const auto child : owner->second.node.children) {
        const auto item = nodes.find(child);
        if (item == nodes.end() || item->second.text_retired || !item->second.node.grid_item ||
            item->second.node.parent != id || item->second.node.grid_item->owner != id ||
            item->second.grid_owner != id || item->second.grid_owner_serial != owner->second.serial) return false;
        const auto &metadata = *item->second.node.grid_item;
        const auto offset = static_cast<std::size_t>(metadata.row * projection.metadata.columns + metadata.column);
        if (offset >= projection.cells.size() || projection.cells[offset].view != child ||
            projection.cells[offset].serial != item->second.serial) return false;
    }
    return true;
}
// Full Selection requires a positively authenticated required/optional policy.
// Per-item action masks describe individual operations, never requiredness.
bool available_selection_nodes(const std::map<std::uint64_t, Entry> &nodes, std::uint64_t owner) noexcept {
    if (!available_grid_nodes(nodes, owner)) return false;
    const auto &node = nodes.at(owner).node;
    if (!node.grid->metadata_revision || (node.grid->selection_mode != 1 && node.grid->selection_mode != 2) ||
        !node.grid->selection_required.has_value()) return false;
    std::size_t selected = 0;
    for (const auto child : node.children) if (nodes.at(child).node.grid_item->selected) ++selected;
    return (node.grid->selection_mode != 1 || selected <= 1) && (!*node.grid->selection_required || selected != 0);
}
bool available_selection_item_nodes(const std::map<std::uint64_t, Entry> &nodes, std::uint64_t id) noexcept {
    const auto found = nodes.find(id);
    if (found == nodes.end() || found->second.text_retired || !found->second.node.grid_item) return false;
    const auto owner = found->second.node.grid_item->owner;
    return available_selection_nodes(nodes, owner) && found->second.node.parent == owner &&
        found->second.grid_owner == owner && found->second.grid_owner_serial == nodes.at(owner).serial;
}
// English Aether-native ItemStatus strings expose actual prepared facts,
// independent of the unavailable standard Selection policy contract.
std::u16string collection_item_status(const std::map<std::uint64_t, Entry> &nodes, std::uint64_t id) {
    const auto found = nodes.find(id);
    if (found == nodes.end() || found->second.text_retired) return {};
    const auto &entry = found->second;
    std::u16string status;
    if (available_grid_nodes(nodes, id) && entry.node.grid->metadata_revision) {
        switch (entry.node.grid->selection_mode) {
        case 0: status = u"Selection mode: none"; break;
        case 1: status = u"Selection mode: single"; break;
        case 2: status = u"Selection mode: multiple"; break;
        default: break;
        }
        if (!status.empty()) {
            std::size_t count = 0;
            for (const auto child : entry.node.children) if (nodes.at(child).node.grid_item->selected) ++count;
            status += u"; ";
            for (const auto digit : std::to_string(count)) status += static_cast<char16_t>(digit);
            status += u" selected";
        }
    }
    if (entry.node.grid_item) {
        const auto owner = nodes.find(entry.node.grid_item->owner);
        if (owner != nodes.end() && available_grid_nodes(nodes, owner->first) && owner->second.node.grid->metadata_revision &&
            entry.node.parent == owner->first && entry.grid_owner == owner->first && entry.grid_owner_serial == owner->second.serial) {
            if (!status.empty()) status += u"; ";
            status += entry.node.grid_item->selected ? u"Selected" : u"Not selected";
        }
    }
    return status;
}
IUnknown *collection_selection_pattern(const std::shared_ptr<State> &, std::uint64_t, bool);
HRESULT collection_selection_array(const std::shared_ptr<State> &, std::uint64_t, SAFEARRAY **);
bool available_grid(const State &state, std::uint64_t id) noexcept {
    return state.connected && !state.terminal && available_grid_nodes(state.nodes, id);
}
bool available_selection(const State &state, std::uint64_t id) noexcept {
    return state.connected && !state.terminal && available_selection_nodes(state.nodes, id);
}
bool available_selection_item(const State &state, std::uint64_t id) noexcept {
    return state.connected && !state.terminal && available_selection_item_nodes(state.nodes, id);
}
IRawElementProviderSimple *projected_element(const std::shared_ptr<State> &, std::uint64_t, const GridCell &);
IRawElementProviderFragment *projected_fragment(const std::shared_ptr<State> &, std::uint64_t, const GridCell &);
template <class Function> HRESULT guarded(Function &&function) noexcept {
    try { return function(); }
    catch (const RangeQuota &) { return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_QUOTA); }
    catch (const std::bad_alloc &) { return E_OUTOFMEMORY; }
    catch (...) { return E_UNEXPECTED; }
}
std::shared_ptr<RangeAnchor> register_range_anchor(State &state, std::uint64_t id, std::uint64_t serial) {
    // Caller holds State::mutex. Expired registrations consume no quota.
    std::erase_if(state.range_anchors, [](const auto &anchor) { return anchor.expired(); });
    if (state.range_anchors.size() >= maximum_live_text_ranges) throw RangeQuota{};
    auto anchor = std::make_shared<RangeAnchor>();
    anchor->view = id; anchor->serial = serial;
    anchor->document = state.nodes.at(id).document;
    state.range_anchors.push_back(anchor);
    return anchor;
}
void post_action_wake(const State &state) {
    if (!PostMessageW(state.window, state.message, 0, 0)) {
        const auto error = GetLastError();
        throw std::runtime_error("AETHER_UIA_ACTION_WAKE_FAILED: " +
            std::to_string(error ? error : ERROR_GEN_FAILURE));
    }
}
bool same_rectangle(const RECT &a, const RECT &b) noexcept {
    return a.left == b.left && a.top == b.top && a.right == b.right && a.bottom == b.bottom;
}
bool inside(const RECT &bounds, double x, double y) noexcept {
    return x >= bounds.left && x < bounds.right && y >= bounds.top && y < bounds.bottom;
}
bool empty(const RECT &bounds) noexcept {
    return bounds.right <= bounds.left || bounds.bottom <= bounds.top;
}
struct SafeArrayOwner {
    SAFEARRAY *value = nullptr;
    explicit SafeArrayOwner(SAFEARRAY *array) : value(array) {}
    ~SafeArrayOwner() { if (value) SafeArrayDestroy(value); }
    SafeArrayOwner(const SafeArrayOwner &) = delete;
    SafeArrayOwner &operator=(const SafeArrayOwner &) = delete;
    SAFEARRAY *release() noexcept { return std::exchange(value, nullptr); }
};
bool shaped_text(const AccessibilityNode &node) noexcept {
    return node.kind == AccessibilityKind::edit_text && node.text_layout &&
           node.text_layout->text() == node.value;
}
void validate_editor_document(const AccessibilityNode &node) {
    if (!node.id || node.kind != AccessibilityKind::edit_text || node.value.size() > 4096 ||
        !node.text_buffer_revision || node.text_mutations.size() > 64 ||
        node.text_mutation_base_revision > node.text_event_revision)
        throw std::invalid_argument("Invalid UI Automation current editor document");
    for (const auto position : {node.selection_start, node.selection_end, node.caret_pos})
        if (position < -1 || (position >= 0 && static_cast<std::size_t>(position) > node.value.size()))
            throw std::invalid_argument("Invalid UI Automation current editor selection");
    const auto marker_valid = [&](std::int32_t first, std::int32_t last) {
        return (first == -1 && last == -1) ||
            (first >= 0 && last > first && static_cast<std::size_t>(last) <= node.value.size());
    };
    if (!marker_valid(node.composing_start, node.composing_end) ||
        !marker_valid(node.conversion_start, node.conversion_end) ||
        (!node.conversion_available && node.conversion_start != -1) ||
        (node.conversion_start >= 0 && (node.composing_start < 0 ||
            node.conversion_start < node.composing_start || node.conversion_end > node.composing_end)))
        throw std::invalid_argument("Invalid UI Automation current editor composition");
    auto revision = node.text_mutation_base_revision;
    std::int32_t length = -1;
    for (const auto &mutation : node.text_mutations) {
        if (revision == UINT64_MAX || mutation.revision != revision + 1 ||
            mutation.before_length < 0 || mutation.before_length > 4096 ||
            (length >= 0 && mutation.before_length != length) ||
            mutation.start < 0 || mutation.start > mutation.before_length ||
            mutation.removed < 0 || mutation.removed > mutation.before_length - mutation.start ||
            mutation.inserted < 0 || mutation.inserted > 4096 - (mutation.before_length - mutation.removed) ||
            (!mutation.removed && !mutation.inserted))
            throw std::invalid_argument("Invalid UI Automation current mutation chain");
        revision = mutation.revision;
        length = mutation.before_length - mutation.removed + mutation.inserted;
    }
    if (revision != node.text_event_revision || (length >= 0 && static_cast<std::size_t>(length) != node.value.size()))
        throw std::invalid_argument("Incomplete UI Automation current mutation chain");
}
bool contiguous_selection(const AccessibilityNode &node, std::int32_t start, std::int32_t end,
                          AccessibilitySelectionOperation operation) noexcept {
    if (operation != AccessibilitySelectionOperation::replace && operation != AccessibilitySelectionOperation::add &&
        operation != AccessibilitySelectionOperation::remove) return false;
    // Degenerate add/remove requests move the insertion point. Missing or
    // degenerate current selections cannot split a nondegenerate result.
    if (operation == AccessibilitySelectionOperation::replace || start == end ||
        node.selection_start < 0 || node.selection_end < 0 || node.selection_start == node.selection_end) return true;
    const auto first = std::min(node.selection_start, node.selection_end);
    const auto last = std::max(node.selection_start, node.selection_end);
    if (operation == AccessibilitySelectionOperation::add) return end >= first && start <= last;
    return !(start > first && end < last); // Removing a strict interior would create two ranges.
}
// Preserve fractional physical pixels from shaping. In particular, a visible
// degenerate caret stays zero-width; a control's rectangle is never substituted.
std::optional<std::array<double, 4>> clipped_text_rectangle(const AccessibilityNode &node,
                                                          const TextRectangle &rectangle,
                                                          bool allow_caret) {
    if (!std::isfinite(rectangle.left) || !std::isfinite(rectangle.top) ||
        !std::isfinite(rectangle.width) || !std::isfinite(rectangle.height) ||
        rectangle.width < 0 || rectangle.height < 0)
        throw std::invalid_argument("Invalid shaped text rectangle");
    if (empty(node.text_clip) || rectangle.height == 0) return {};
    const double left = static_cast<double>(node.text_origin.x) + rectangle.left;
    const double top = static_cast<double>(node.text_origin.y) + rectangle.top;
    const double right = left + rectangle.width, bottom = top + rectangle.height;
    const auto clipped_top = std::max(top, static_cast<double>(node.text_clip.top));
    const auto clipped_bottom = std::min(bottom, static_cast<double>(node.text_clip.bottom));
    if (clipped_bottom <= clipped_top) return {};
    if (rectangle.width == 0) {
        if (!allow_caret || left < node.text_clip.left || left >= node.text_clip.right) return {};
        return std::array<double, 4>{left, clipped_top, 0, clipped_bottom - clipped_top};
    }
    const auto clipped_left = std::max(left, static_cast<double>(node.text_clip.left));
    const auto clipped_right = std::min(right, static_cast<double>(node.text_clip.right));
    if (clipped_right <= clipped_left) return {};
    return std::array<double, 4>{clipped_left, clipped_top, clipped_right - clipped_left,
                               clipped_bottom - clipped_top};
}
double vertical_percent(const AccessibilityNode &node) noexcept {
    return node.scroll_range_y ? 100.0 * node.scroll_y / node.scroll_range_y : UIA_ScrollPatternNoScroll;
}
double vertical_view_size(const AccessibilityNode &node) noexcept {
    return node.scroll_range_y ? 100.0 * node.scroll_viewport_y /
        (static_cast<double>(node.scroll_viewport_y) + node.scroll_range_y) : 100.0;
}
HRESULT text_variant(VARIANT *value, std::u16string_view text) noexcept {
    value->bstrVal = SysAllocStringLen(reinterpret_cast<const OLECHAR *>(text.data()),
                                      static_cast<UINT>(text.size()));
    if (!value->bstrVal) return E_OUTOFMEMORY;
    value->vt = VT_BSTR;
    return S_OK;
}
void boolean(VARIANT *value, bool enabled) noexcept {
    value->vt = VT_BOOL;
    value->boolVal = enabled ? VARIANT_TRUE : VARIANT_FALSE;
}

IRawElementProviderSimple *text_element(const std::shared_ptr<State> &state,
                                       std::uint64_t id, std::uint64_t serial);
// ITextRangeProvider groundwork for the unfinished TextEdit projection (CR-UIA-003).
// Uses the exact Windows SDK signatures from UIAutomationCore.h.
struct __declspec(uuid("B603EB3D-50EC-4CCF-9B27-24851AB47712")) OwnedTextRange : ITextRangeProvider {};
class TextRange final : public OwnedTextRange {
  public:
    std::atomic<ULONG> refs_{1};
    std::shared_ptr<State> state_;
    const std::uint64_t id_, serial_;
    std::shared_ptr<RangeAnchor> anchor_;
    std::int32_t &start_, &end_;
    TextRange(std::shared_ptr<State> state, std::uint64_t id, std::uint64_t serial)
        : state_(std::move(state)), id_(id), serial_(serial),
          anchor_(register_range_anchor(*state_, id_, serial_)), start_(anchor_->start), end_(anchor_->end) {}
    ~TextRange() = default;
    TextRange(const TextRange &) = delete;
    TextRange &operator=(const TextRange &) = delete;
    bool valid() const noexcept {
        if (!state_->connected) return false;
        const auto f = state_->nodes.find(id_);
        return f != state_->nodes.end() && f->second.serial == serial_ && !f->second.text_retired;
    }
    const AccessibilityNode &n() const { return state_->nodes.at(id_).current(); }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid == __uuidof(IUnknown) || iid == __uuidof(ITextRangeProvider) ||
            iid == __uuidof(OwnedTextRange)) {
            *output = static_cast<ITextRangeProvider *>(this);
            AddRef();
        } else return E_NOINTERFACE;
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return refs_.fetch_add(1, std::memory_order_relaxed) + 1; }
    ULONG STDMETHODCALLTYPE Release() override {
        const auto r = refs_.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (!r) delete this;
        return r;
    }
    HRESULT STDMETHODCALLTYPE Clone(ITextRangeProvider **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            const auto status = positional_status();
            if (FAILED(status)) return status;
            auto copy = std::make_unique<TextRange>(state_, id_, serial_);
            copy->start_ = start_; copy->end_ = end_;
            copy->anchor_->document = anchor_->document;
            *output = copy.release();
            return S_OK;
        });
    }
    HRESULT peer(ITextRangeProvider *other, ComPtr<OwnedTextRange> &owned, TextRange *&range) const {
        if (!other || FAILED(other->QueryInterface(IID_PPV_ARGS(owned.GetAddressOf()))))
            return E_INVALIDARG;
        range = static_cast<TextRange *>(owned.Get());
        return range->state_.get() == state_.get() && range->id_ == id_ && range->serial_ == serial_
                   ? S_OK : E_INVALIDARG;
    }
    static bool endpoint_valid(TextPatternRangeEndpoint endpoint) noexcept {
        return endpoint == TextPatternRangeEndpoint_Start || endpoint == TextPatternRangeEndpoint_End;
    }
    HRESULT STDMETHODCALLTYPE Compare(ITextRangeProvider *other, BOOL *output) override {
        if (!output) return E_POINTER;
        *output = FALSE;
        return guarded([&]() -> HRESULT {
            ComPtr<OwnedTextRange> owned;
            TextRange *range = nullptr;
            const auto result = peer(other, owned, range);
            if (FAILED(result)) return result;
            std::lock_guard lock(state_->mutex);
            const auto mine_status = positional_status(), peer_status = range->positional_status();
            if (FAILED(mine_status)) return mine_status;
            if (FAILED(peer_status)) return peer_status;
            *output = start_ == range->start_ && end_ == range->end_ ? TRUE : FALSE;
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE CompareEndpoints(TextPatternRangeEndpoint endpoint, ITextRangeProvider *other,
                                               TextPatternRangeEndpoint targetEndpoint, int *output) override {
        if (!output) return E_POINTER;
        *output = 0;
        if (!endpoint_valid(endpoint) || !endpoint_valid(targetEndpoint)) return E_INVALIDARG;
        return guarded([&]() -> HRESULT {
            ComPtr<OwnedTextRange> owned;
            TextRange *range = nullptr;
            const auto result = peer(other, owned, range);
            if (FAILED(result)) return result;
            std::lock_guard lock(state_->mutex);
            const auto mine_status = positional_status(), peer_status = range->positional_status();
            if (FAILED(mine_status)) return mine_status;
            if (FAILED(peer_status)) return peer_status;
            const auto mine = endpoint == TextPatternRangeEndpoint_Start ? start_ : end_;
            const auto theirs = targetEndpoint == TextPatternRangeEndpoint_Start ? range->start_ : range->end_;
            *output = mine - theirs;
            return S_OK;
        });
    }
    static bool rebase_anchor(const RangeAnchor &anchor, const AccessibilityNode &node,
                              std::int32_t &first, std::int32_t &last) noexcept {
        if (anchor.retired || !anchor.document) return false;
        const auto &captured_text = anchor.document->text;
        const auto captured_buffer_revision = anchor.document->buffer_revision;
        const auto captured_text_revision = anchor.document->text_revision;
        if (captured_buffer_revision != node.text_buffer_revision || anchor.start < 0 || anchor.end < anchor.start ||
            static_cast<std::size_t>(anchor.end) > captured_text.size() ||
            captured_text_revision > node.text_event_revision) return false;
        if (captured_text_revision == node.text_event_revision)
            return captured_text == node.value;
        // Rebase only through actual consecutive commits in this same buffer.
        // Each successful publication advances live anchors independently of
        // client reads. A gap between publications still retires the anchor.
        if (captured_text_revision < node.text_mutation_base_revision) return false;
        auto revision = captured_text_revision;
        auto length = static_cast<std::int32_t>(captured_text.size());
        for (const auto &mutation : node.text_mutations) {
            if (mutation.revision <= revision) continue;
            if (revision == UINT64_MAX || mutation.revision != revision + 1 || mutation.before_length != length ||
                mutation.start < 0 || mutation.removed < 0 || mutation.inserted < 0 || mutation.start > length ||
                (!mutation.removed && !mutation.inserted) ||
                mutation.removed > length - mutation.start ||
                mutation.inserted > 4096 - (length - mutation.removed)) return false;
            if (!mutation.removed) {
                // Pure insertions at the two outer edges stay outside a
                // nondegenerate range. A caret has forward affinity.
                if (first == last) {
                    if (first >= mutation.start) first = last = first + mutation.inserted;
                } else {
                    if (first >= mutation.start) first += mutation.inserted;
                    if (last > mutation.start) last += mutation.inserted;
                }
            } else {
                const auto removed_end = mutation.start + mutation.removed;
                const auto replaced_position = [&](std::int32_t position, bool forward) {
                    if (position < mutation.start) return position;
                    if (position >= removed_end) return position + mutation.inserted - mutation.removed;
                    return mutation.start + (forward ? mutation.inserted : 0);
                };
                // Inclusive replacement is this provider's declared policy:
                // a nondegenerate replaced range includes the new contents;
                // deletion collapses it. A caret follows replacement text.
                if (first == last) first = last = replaced_position(first, true);
                else {
                    first = replaced_position(first, false);
                    // An endpoint exactly before the removed interval stays
                    // before it; an interior ending endpoint includes its replacement.
                    last = last == mutation.start ? last : replaced_position(last, true);
                }
            }
            length = length - mutation.removed + mutation.inserted;
            if (first < 0 || last < first || last > length) return false;
            revision = mutation.revision;
        }
        if (revision != node.text_event_revision || static_cast<std::size_t>(length) != node.value.size())
            return false;
        return true;
    }
    HRESULT positional_status() const noexcept {
        if (!valid()) return UIA_E_ELEMENTNOTAVAILABLE;
        if (n().kind != AccessibilityKind::edit_text) return UIA_E_NOTSUPPORTED;
        if (anchor_->retired || !anchor_->document ||
            anchor_->document->buffer_revision != n().text_buffer_revision ||
            anchor_->document->text_revision != n().text_event_revision ||
            anchor_->document->text != n().value || start_ < 0 || end_ < start_ ||
            static_cast<std::size_t>(end_) > n().value.size()) return UIA_E_INVALIDOPERATION;
        return S_OK;
    }
    static HRESULT boundary_unit(TextUnit unit, TextBoundary &boundary) noexcept {
        // UIA requires unsupported units to promote to the next larger one.
        // The hosted plain editor has no independent Format or Page structure.
        switch (unit) {
        case TextUnit_Character: boundary = TextBoundary::character; break;
        case TextUnit_Format:
        case TextUnit_Word: boundary = TextBoundary::word; break;
        case TextUnit_Line: boundary = TextBoundary::line; break;
        case TextUnit_Paragraph: boundary = TextBoundary::paragraph; break;
        case TextUnit_Page:
        case TextUnit_Document: boundary = TextBoundary::document; break;
        default: return E_INVALIDARG;
        }
        return S_OK;
    }
    HRESULT boundary_points(TextBoundary boundary, std::vector<std::uint32_t> &points) const {
        const auto total = static_cast<std::uint32_t>(n().value.size());
        if (boundary == TextBoundary::document) {
            points = total ? std::vector<std::uint32_t>{0, total} : std::vector<std::uint32_t>{0};
            return S_OK;
        }
        if (!shaped_text(n())) return UIA_E_NOTSUPPORTED;
        points = n().text_layout->boundaries(boundary);
        // Native ICU has no character units for some nonempty control-only
        // strings. Empty points conveys that case without inventing a unit.
        if (points.empty() && boundary == TextBoundary::character && total) return S_OK;
        if (points.empty() || points.front() != 0 || points.back() != total ||
            points.size() > static_cast<std::size_t>(total) + 1 ||
            !std::is_sorted(points.begin(), points.end()) ||
            std::adjacent_find(points.begin(), points.end()) != points.end())
            throw std::invalid_argument("Invalid native text-unit boundaries");
        return S_OK;
    }
    static std::size_t containing_interval(const std::vector<std::uint32_t> &points,
                                            std::uint32_t position) {
        const auto after = std::upper_bound(points.begin(), points.end(), position);
        const auto index = static_cast<std::size_t>(after - points.begin() - 1);
        // At document end, use the preceding full unit, never an invented
        // out-of-document span or a duplicate zero-length final-line unit.
        return std::min(index, points.size() - 2);
    }
    static std::pair<std::uint32_t, int> step_boundary(const std::vector<std::uint32_t> &points,
                                                      std::uint32_t position, int count) {
        if (points.size() < 2 || !count) return {position, 0};
        if (count > 0) {
            const auto first = std::upper_bound(points.begin(), points.end(), position);
            const auto available = static_cast<std::int64_t>(points.end() - first);
            const auto steps = std::min(static_cast<std::int64_t>(count), available);
            if (!steps) return {position, 0};
            return {*(first + static_cast<std::ptrdiff_t>(steps - 1)), static_cast<int>(steps)};
        }
        const auto after = std::lower_bound(points.begin(), points.end(), position);
        const auto available = static_cast<std::int64_t>(after - points.begin());
        // Widen before negation so INT_MIN is an ordinary bounded request.
        const auto steps = std::min(-static_cast<std::int64_t>(count), available);
        if (!steps) return {position, 0};
        return {*(after - static_cast<std::ptrdiff_t>(steps)), -static_cast<int>(steps)};
    }
    HRESULT STDMETHODCALLTYPE ExpandToEnclosingUnit(TextUnit unit) override {
        TextBoundary boundary{};
        const auto mapped = boundary_unit(unit, boundary);
        if (FAILED(mapped)) return mapped;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            const auto current = positional_status();
            if (FAILED(current)) return current;
            std::vector<std::uint32_t> points;
            const auto status = boundary_points(boundary, points);
            if (FAILED(status)) return status;
            if (points.size() < 2) {
                // Empty documents, and control-only strings with no native
                // character units, normalize to document coverage. Movement
                // still reports zero units for the latter provider policy.
                start_ = 0;
                end_ = static_cast<std::int32_t>(n().value.size());
                return S_OK;
            }
            const auto index = containing_interval(points, static_cast<std::uint32_t>(start_));
            start_ = static_cast<std::int32_t>(points[index]);
            end_ = static_cast<std::int32_t>(points[index + 1]);
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE FindAttribute(TEXTATTRIBUTEID attribute, VARIANT value, BOOL backward,
                                             ITextRangeProvider **output) override {
        (void)backward; // Supported attributes are uniform across this plain editor.
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            const auto status = positional_status();
            if (FAILED(status)) return status;
            if (attribute != UIA_IsReadOnlyAttributeId && attribute != UIA_IsHiddenAttributeId) return S_OK;
            if (value.vt != VT_BOOL) return E_INVALIDARG;
            if (value.boolVal != VARIANT_FALSE) return S_OK;
            auto range = std::make_unique<TextRange>(state_, id_, serial_);
            range->start_ = start_; range->end_ = end_;
            *output = range.release();
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE FindText(BSTR text, BOOL backward, BOOL ignoreCase, ITextRangeProvider **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (!text || !SysStringLen(text)) return E_INVALIDARG;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            const auto status = positional_status();
            if (FAILED(status)) return status;
            const auto &value = n().value;
            const auto total = static_cast<std::int32_t>(value.size());
            const auto from = std::clamp(start_, 0, total);
            const auto to = std::clamp(end_, from, total);
            const auto length = SysStringLen(text);
            if (length > static_cast<UINT>(to - from)) return S_OK;
            const auto last = to - static_cast<std::int32_t>(length);
            for (auto position = backward ? last : from;
                 position >= from && position <= last; position += backward ? -1 : 1) {
                const auto match = CompareStringOrdinal(
                    reinterpret_cast<LPCWCH>(value.data() + position), static_cast<int>(length),
                    text, static_cast<int>(length), ignoreCase);
                if (!match) return HRESULT_FROM_WIN32(GetLastError());
                if (match != CSTR_EQUAL) continue;
                auto *range = new TextRange(state_, id_, serial_);
                range->start_ = position;
                range->end_ = position + static_cast<std::int32_t>(length);
                *output = range;
                return S_OK;
            }
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE GetAttributeValue(TEXTATTRIBUTEID attribute, VARIANT *output) override {
        if (!output) return E_POINTER;
        VariantInit(output);
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            const auto status = positional_status();
            if (FAILED(status)) return status;
            if (attribute == UIA_IsReadOnlyAttributeId || attribute == UIA_IsHiddenAttributeId) {
                boolean(output, false); // Plain editable text, not a password/hidden span model.
                return S_OK;
            }
            output->vt = VT_UNKNOWN;
            return UiaGetReservedNotSupportedValue(&output->punkVal);
        });
    }
    HRESULT STDMETHODCALLTYPE GetBoundingRectangles(SAFEARRAY **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            const auto current = positional_status();
            if (FAILED(current)) return current;
            if (!shaped_text(n())) return UIA_E_NOTSUPPORTED;
            // UIA specifies an empty array for a degenerate range. Caret
            // geometry is reserved for rendering and visible-position queries.
            if (start_ == end_) {
                SafeArrayOwner result(SafeArrayCreateVector(VT_R8, 0, 0));
                if (!result.value) return E_OUTOFMEMORY;
                *output = result.release();
                return S_OK;
            }
            const auto rectangles = n().text_layout->rectangles(static_cast<std::uint32_t>(start_),
                                                               static_cast<std::uint32_t>(end_ - start_));
            if (rectangles.size() > 2 * (n().value.size() + 1))
                throw std::invalid_argument("Shaped text rectangle count exceeds text bound");
            std::vector<double> values;
            values.reserve(rectangles.size() * 4);
            if (!n().offscreen)
                for (const auto &rectangle : rectangles)
                    if (const auto clipped = clipped_text_rectangle(n(), rectangle, false))
                        values.insert(values.end(), clipped->begin(), clipped->end());
            SafeArrayOwner result(SafeArrayCreateVector(VT_R8, 0, static_cast<ULONG>(values.size())));
            if (!result.value) return E_OUTOFMEMORY;
            for (LONG index = 0; index < static_cast<LONG>(values.size()); ++index) {
                const auto status = SafeArrayPutElement(result.value, &index, &values[static_cast<std::size_t>(index)]);
                if (FAILED(status)) return status;
            }
            *output = result.release();
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE GetEnclosingElement(IRawElementProviderSimple **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!valid()) return UIA_E_ELEMENTNOTAVAILABLE;
            *output = text_element(state_, id_, serial_);
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE GetText(int maxLength, BSTR *output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (maxLength < -1) return E_INVALIDARG;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            const auto status = positional_status();
            if (FAILED(status)) return status;
            const auto &text = n().value;
            const auto total = static_cast<std::int32_t>(text.size());
            const auto from = std::max(0, std::min(start_, total));
            const auto to = std::max(from, std::min(end_, total));
            const auto length = (maxLength >= 0 && static_cast<int>(to - from) > maxLength) ? maxLength : to - from;
            *output = SysAllocStringLen(reinterpret_cast<const OLECHAR *>(text.data() + from), length);
            return *output ? S_OK : E_OUTOFMEMORY;
        });
    }
    HRESULT STDMETHODCALLTYPE Move(TextUnit unit, int count, int *output) override {
        if (!output) return E_POINTER;
        *output = 0;
        TextBoundary boundary{};
        const auto mapped = boundary_unit(unit, boundary);
        if (FAILED(mapped)) return mapped;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            const auto current = positional_status();
            if (FAILED(current)) return current;
            if (!count) return S_OK; // Zero must not normalize a partial range.
            std::vector<std::uint32_t> points;
            const auto status = boundary_points(boundary, points);
            if (FAILED(status)) return status;
            if (points.size() < 2) return S_OK;
            if (start_ == end_) {
                const auto moved = step_boundary(points, static_cast<std::uint32_t>(start_), count);
                if (moved.second) start_ = end_ = static_cast<std::int32_t>(moved.first);
                *output = moved.second;
                return S_OK;
            }
            const auto first = static_cast<std::int64_t>(containing_interval(points, static_cast<std::uint32_t>(start_)));
            const auto last = static_cast<std::int64_t>(points.size() - 2);
            const auto target = std::clamp(first + static_cast<std::int64_t>(count), std::int64_t{0}, last);
            const auto moved = static_cast<int>(target - first);
            // A failed move at the document edge leaves the original range
            // unchanged. Successful moves normalize to exactly one full unit.
            if (moved) {
                start_ = static_cast<std::int32_t>(points[static_cast<std::size_t>(target)]);
                end_ = static_cast<std::int32_t>(points[static_cast<std::size_t>(target + 1)]);
            }
            *output = moved;
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE MoveEndpointByUnit(TextPatternRangeEndpoint endpoint, TextUnit unit, int count,
                                                  int *output) override {
        if (!output) return E_POINTER;
        *output = 0;
        if (!endpoint_valid(endpoint)) return E_INVALIDARG;
        TextBoundary boundary{};
        const auto mapped = boundary_unit(unit, boundary);
        if (FAILED(mapped)) return mapped;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            const auto current = positional_status();
            if (FAILED(current)) return current;
            if (!count) return S_OK;
            std::vector<std::uint32_t> points;
            const auto status = boundary_points(boundary, points);
            if (FAILED(status)) return status;
            const auto moved = step_boundary(points, static_cast<std::uint32_t>(
                endpoint == TextPatternRangeEndpoint_Start ? start_ : end_), count);
            if (moved.second) {
                if (endpoint == TextPatternRangeEndpoint_Start) {
                    start_ = static_cast<std::int32_t>(moved.first);
                    end_ = std::max(end_, start_);
                } else {
                    end_ = static_cast<std::int32_t>(moved.first);
                    start_ = std::min(start_, end_);
                }
            }
            *output = moved.second;
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE MoveEndpointByRange(TextPatternRangeEndpoint endpoint, ITextRangeProvider *other,
                                                   TextPatternRangeEndpoint targetEndpoint) override {
        if (!endpoint_valid(endpoint) || !endpoint_valid(targetEndpoint)) return E_INVALIDARG;
        return guarded([&]() -> HRESULT {
            ComPtr<OwnedTextRange> owned;
            TextRange *range = nullptr;
            const auto result = peer(other, owned, range);
            if (FAILED(result)) return result;
            std::lock_guard lock(state_->mutex);
            const auto mine_status = positional_status(), peer_status = range->positional_status();
            if (FAILED(mine_status)) return mine_status;
            if (FAILED(peer_status)) return peer_status;
            const auto total = static_cast<std::int32_t>(n().value.size());
            const auto position = std::clamp(targetEndpoint == TextPatternRangeEndpoint_Start
                                                  ? range->start_ : range->end_, 0, total);
            start_ = std::clamp(start_, 0, total);
            end_ = std::clamp(end_, start_, total);
            if (endpoint == TextPatternRangeEndpoint_Start) {
                start_ = position;
                end_ = std::max(end_, start_);
            } else {
                end_ = position;
                start_ = std::min(start_, end_);
            }
            return S_OK;
        });
    }
    HRESULT unavailable_operation() {
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            return valid() ? UIA_E_NOTSUPPORTED : UIA_E_ELEMENTNOTAVAILABLE;
        });
    }
    HRESULT select_locked(AccessibilitySelectionOperation operation = AccessibilitySelectionOperation::replace) {
        const auto current = positional_status();
        if (FAILED(current)) return current;
        if (!state_->active || state_->actions_suspended || !n().enabled) return UIA_E_ELEMENTNOTENABLED;
        if (!state_->foreground || n().offscreen || empty(n().bounds)) return UIA_E_INVALIDOPERATION;
        if (!contiguous_selection(n(), start_, end_, operation)) return UIA_E_INVALIDOPERATION;
        if (state_->actions.size() >= maximum_actions) return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_QUOTA);
        AccessibilityAction action;
        action.kind = AccessibilityActionKind::set_selection;
        action.view = id_;
        action.caret_offset = start_;
        action.selection_end = end_;
        action.selection_operation = operation;
        action.expected_text = anchor_->document->text;
        action.expected_buffer_revision = anchor_->document->buffer_revision;
        action.expected_text_revision = anchor_->document->text_revision;
        state_->actions.push_back({std::move(action), serial_});
        if (!PostMessageW(state_->window, state_->message, 0, 0)) {
            const auto error = GetLastError();
            state_->actions.pop_back();
            return HRESULT_FROM_WIN32(error ? error : ERROR_GEN_FAILURE);
        }
        return S_OK; // Accepted asynchronously; never waits for guest work.
    }
    HRESULT STDMETHODCALLTYPE Select() override {
        return guarded([&]() -> HRESULT { std::lock_guard lock(state_->mutex); return select_locked(); });
    }
    HRESULT single_selection_action(AccessibilitySelectionOperation operation) {
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            const auto status = positional_status();
            if (FAILED(status)) return status;
            return select_locked(operation); // The worker computes from its actual current selection.
        });
    }
    HRESULT STDMETHODCALLTYPE AddToSelection() override { return single_selection_action(AccessibilitySelectionOperation::add); }
    HRESULT STDMETHODCALLTYPE RemoveFromSelection() override { return single_selection_action(AccessibilitySelectionOperation::remove); }
    HRESULT STDMETHODCALLTYPE ScrollIntoView(BOOL align_to_top) override {
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            const auto status = positional_status();
            if (FAILED(status)) return status;
            if (!shaped_text(n())) return UIA_E_NOTSUPPORTED;
            if (!state_->active || state_->actions_suspended || !n().enabled) return UIA_E_ELEMENTNOTENABLED;
            const auto boxes = n().text_layout->rectangles(static_cast<std::uint32_t>(start_),
                                                           static_cast<std::uint32_t>(end_ - start_));
            if (boxes.empty()) return UIA_E_NOTSUPPORTED;
            double top = std::numeric_limits<double>::infinity(), bottom = -top;
            bool fully_visible = !n().offscreen && !empty(n().text_clip);
            const auto content_left = static_cast<double>(n().text_origin.x);
            const auto content_right = content_left + n().text_layout->width();
            for (const auto &box : boxes) {
                const auto left = static_cast<double>(n().text_origin.x) + box.left;
                const auto right = left + box.width;
                const auto first = static_cast<double>(n().text_origin.y) + box.top;
                const auto last = first + box.height;
                if (left < content_left || right > content_right || (box.width == 0 && left >= content_right)) return UIA_E_NOTSUPPORTED; // No horizontal scroller.
                top = std::min(top, first); bottom = std::max(bottom, last);
                fully_visible = fully_visible && left >= n().text_clip.left && right <= n().text_clip.right &&
                    (box.width != 0 || left < n().text_clip.right) && first >= n().text_clip.top && last <= n().text_clip.bottom;
            }
            if (!n().text_can_scroll) return fully_visible ? S_OK : UIA_E_NOTSUPPORTED;
            const auto relative_top = (top - n().view_origin.y) / n().text_scale;
            const auto relative_bottom = (bottom - n().view_origin.y) / n().text_scale;
            if (!std::isfinite(relative_top) || !std::isfinite(relative_bottom) || relative_top < 0 ||
                relative_bottom < relative_top || relative_bottom > 32768) return UIA_E_NOTSUPPORTED;
            if (state_->actions.size() >= maximum_actions) return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_QUOTA);
            AccessibilityAction action;
            action.kind = AccessibilityActionKind::reveal_text_range;
            action.view = id_;
            action.expected_text = anchor_->document->text;
            action.expected_view_revision = n().source_view_revision;
            action.range_top = static_cast<float>(relative_top);
            action.range_bottom = static_cast<float>(relative_bottom);
            action.align_top = align_to_top != FALSE;
            state_->actions.push_back({std::move(action), serial_});
            if (!PostMessageW(state_->window, state_->message, 0, 0)) {
                const auto error = GetLastError(); state_->actions.pop_back();
                return HRESULT_FROM_WIN32(error ? error : ERROR_GEN_FAILURE);
            }
            return S_OK; // Accepted once; worker independently revalidates current geometry/text.
        });
    }
    HRESULT STDMETHODCALLTYPE GetChildren(SAFEARRAY **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!valid()) return UIA_E_ELEMENTNOTAVAILABLE;
            *output = SafeArrayCreateVector(VT_UNKNOWN, 0, 0);
            return *output ? S_OK : E_OUTOFMEMORY;
        });
    }
};
class Provider final : public IRawElementProviderSimple,
                       public IRawElementProviderFragment,
                       public IRawElementProviderFragmentRoot,
                       public IInvokeProvider,
                       public IToggleProvider,
                       public IScrollProvider,
                       public IGridProvider,
                       public IGridItemProvider,
                       public IValueProvider,
                       public ITextEditProvider {
    std::atomic<ULONG> references_{1};
    std::shared_ptr<State> state_;
    const std::uint64_t id_, serial_;
    bool current() const noexcept {
        if (!state_->connected) return false;
        const auto found = state_->nodes.find(id_);
        return id_ == 0 || (found != state_->nodes.end() && found->second.serial == serial_ && !found->second.text_retired);
    }
    const AccessibilityNode &node() const { return state_->nodes.at(id_).current(); }
    const AccessibilityNode &grid_node() const { return state_->nodes.at(id_).node; }
    bool grid_item_current() const noexcept {
        if (!id_ || !current()) return false;
        const auto &entry = state_->nodes.at(id_);
        if (!entry.node.grid_item) return false;
        const auto &item = *entry.node.grid_item;
        const auto owner = state_->nodes.find(item.owner);
        return owner != state_->nodes.end() && available_grid(*state_, item.owner) &&
            entry.grid_owner == item.owner && entry.grid_owner_serial == owner->second.serial &&
            entry.node.parent == item.owner;
    }
    Provider *element(std::uint64_t id) const {
        if (!id) return new Provider(state_, 0, 0);
        return new Provider(state_, id, state_->nodes.at(id).serial);
    }
    HRESULT fragment(std::uint64_t id, IRawElementProviderFragment **result) const {
        *result = static_cast<IRawElementProviderFragment *>(element(id));
        return S_OK;
    }
    HRESULT queue_action(AccessibilityActionKind kind, std::int32_t amount = 0, double percent = 0, std::u16string value = {}) {
        // Caller holds the snapshot lock. PostMessage is asynchronous; keep the
        // target HWND and disconnect transition atomic with queue insertion.
        if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
        const bool scrolling = kind == AccessibilityActionKind::scroll || kind == AccessibilityActionKind::set_scroll_percent;
        if (!id_ || (kind == AccessibilityActionKind::invoke ? !node().invokable
                    : kind == AccessibilityActionKind::toggle ? !node().toggleable
                    : kind == AccessibilityActionKind::replace_text ? node().kind != AccessibilityKind::edit_text
                    : scrolling ? !node().scrollable : !node().focusable))
            return UIA_E_NOTSUPPORTED;
        if (!state_->active || state_->actions_suspended || !node().enabled) return UIA_E_ELEMENTNOTENABLED;
        if (node().offscreen || empty(node().bounds) ||
            (kind == AccessibilityActionKind::focus && !state_->foreground) ||
            (scrolling && (!node().scroll_range_y || !node().scroll_viewport_y)))
            return UIA_E_INVALIDOPERATION;
        if (state_->actions.size() >= maximum_actions) return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_QUOTA);
        if (value.size() > 4096) return E_INVALIDARG;
        AccessibilityAction action;
        action.kind = kind; action.view = id_; action.scroll_amount = amount;
        action.scroll_percent = percent; action.replacement_text = std::move(value);
        if (kind == AccessibilityActionKind::invoke)
            action.invocation = std::make_shared<AccessibilityInvocation>(state_,
                static_cast<IRawElementProviderSimple *>(this), id_, serial_);
        // Retain the exact requesting COM provider before the asynchronous wake.
        // disconnect() clears the bounded queue, breaking this transient cycle.
        state_->actions.push_back({std::move(action), serial_});
        if (!PostMessageW(state_->window, state_->message, 0, 0)) {
            const auto error = GetLastError();
            state_->actions.pop_back();
            return HRESULT_FROM_WIN32(error ? error : ERROR_GEN_FAILURE);
        }
        return S_OK; // Accepted asynchronously; no UIA call waits on a guest pipe.
    }
  public:
    Provider(std::shared_ptr<State> state, std::uint64_t id, std::uint64_t serial)
        : state_(std::move(state)), id_(id), serial_(serial) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (iid == __uuidof(IUnknown) || iid == __uuidof(IRawElementProviderSimple))
                *output = static_cast<IRawElementProviderSimple *>(this);
            else if (iid == __uuidof(IRawElementProviderFragment))
                *output = static_cast<IRawElementProviderFragment *>(this);
            else if (iid == __uuidof(IRawElementProviderFragmentRoot) && id_ == 0)
                *output = static_cast<IRawElementProviderFragmentRoot *>(this);
            // COM interface identity is fixed for this provider's lifetime.
            // Pattern availability and execution remain current-state checks.
            else if (iid == __uuidof(IInvokeProvider) && id_ != 0)
                *output = static_cast<IInvokeProvider *>(this);
            else if (iid == __uuidof(IToggleProvider) && id_ != 0)
                *output = static_cast<IToggleProvider *>(this);
            else if (iid == __uuidof(IScrollProvider) && id_ != 0)
                *output = static_cast<IScrollProvider *>(this);
            else if (iid == __uuidof(IGridProvider) && id_ != 0)
                *output = static_cast<IGridProvider *>(this);
            else if (iid == __uuidof(IGridItemProvider) && id_ != 0)
                *output = static_cast<IGridItemProvider *>(this);
            else if (iid == __uuidof(IValueProvider) && id_ != 0)
                *output = static_cast<IValueProvider *>(this);
            else if (iid == __uuidof(ITextProvider) && id_ != 0)
                *output = static_cast<ITextProvider *>(this);
            else if (iid == __uuidof(ITextEditProvider) && id_ != 0)
                *output = static_cast<ITextEditProvider *>(this);
            else return E_NOINTERFACE;
            AddRef();
            return S_OK;
        });
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return references_.fetch_add(1, std::memory_order_relaxed) + 1; }
    ULONG STDMETHODCALLTYPE Release() override {
        const auto remaining = references_.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (!remaining) delete this;
        return remaining;
    }
    HRESULT STDMETHODCALLTYPE get_ProviderOptions(ProviderOptions *result) override {
        if (!result) return E_POINTER;
        *result = ProviderOptions_ServerSideProvider;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetPatternProvider(PATTERNID pattern, IUnknown **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (pattern == UIA_InvokePatternId && id_ && node().invokable) {
                *output = static_cast<IInvokeProvider *>(this);
                AddRef();
            }
            if (pattern == UIA_TogglePatternId && id_ && node().toggleable) {
                *output = static_cast<IToggleProvider *>(this);
                AddRef();
            }
            if (pattern == UIA_ScrollPatternId && id_ && node().scrollable) {
                *output = static_cast<IScrollProvider *>(this);
                AddRef();
            }
            if (pattern == UIA_SelectionPatternId && id_ && available_selection(*state_, id_))
                *output = collection_selection_pattern(state_, id_, false);
            if (pattern == UIA_SelectionItemPatternId && id_ && available_selection_item(*state_, id_))
                *output = collection_selection_pattern(state_, id_, true);
            if (pattern == UIA_GridPatternId && id_ && available_grid(*state_, id_)) {
                *output = static_cast<IGridProvider *>(this);
                AddRef();
            }
            if (pattern == UIA_GridItemPatternId && grid_item_current()) {
                *output = static_cast<IGridItemProvider *>(this);
                AddRef();
            }
            if (pattern == UIA_TextPatternId && id_ && node().kind == AccessibilityKind::edit_text) {
                *output = static_cast<ITextProvider *>(this);
                AddRef();
            }
            if (pattern == UIA_TextEditPatternId && id_ && node().kind == AccessibilityKind::edit_text) {
                *output = static_cast<ITextEditProvider *>(this);
                AddRef();
            }
            if (pattern == UIA_ValuePatternId && id_ && node().kind == AccessibilityKind::edit_text) {
                *output = static_cast<IValueProvider *>(this);
                AddRef();
            }
            return S_OK; // No Selection or collection discovery beyond actual supported patterns.
        });
    }
    HRESULT STDMETHODCALLTYPE GetPropertyValue(PROPERTYID property, VARIANT *output) override {
        if (!output) return E_POINTER;
        VariantInit(output);
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            const auto *value = id_ ? &node() : nullptr;
            switch (property) {
            case UIA_NamePropertyId: return text_variant(output, value ? value->name : state_->name);
            case UIA_FrameworkIdPropertyId: return text_variant(output, u"Aether.Android");
            case UIA_ControlTypePropertyId:
                output->vt = VT_I4;
                output->lVal = !value ? UIA_WindowControlTypeId : value->kind == AccessibilityKind::checkbox
                    ? UIA_CheckBoxControlTypeId : value->kind == AccessibilityKind::edit_text
                    ? UIA_EditControlTypeId : value->kind == AccessibilityKind::button
                    ? UIA_ButtonControlTypeId : value->kind == AccessibilityKind::text
                    ? UIA_TextControlTypeId : UIA_GroupControlTypeId;
                break;
            case UIA_NativeWindowHandlePropertyId:
                if (!value) { output->vt = VT_I4; output->lVal = HandleToLong(state_->window); }
                break;
            case UIA_IsControlElementPropertyId:
            case UIA_IsContentElementPropertyId: boolean(output, true); break;
            case UIA_IsEnabledPropertyId: boolean(output, state_->active && (!value || value->enabled)); break;
            case UIA_HasKeyboardFocusPropertyId: boolean(output, state_->active && value && value->focused); break;
            case UIA_IsKeyboardFocusablePropertyId: boolean(output, value && value->focusable); break;
            case UIA_IsOffscreenPropertyId: boolean(output, !state_->active || (value && value->offscreen)); break;
            case UIA_IsInvokePatternAvailablePropertyId: boolean(output, value && value->invokable); break;
            case UIA_IsTogglePatternAvailablePropertyId: boolean(output, value && value->toggleable); break;
            case UIA_IsScrollPatternAvailablePropertyId: boolean(output, value && value->scrollable); break;
            case UIA_ItemStatusPropertyId:
                if (id_) {
                    const auto status = collection_item_status(state_->nodes, id_);
                    if (!status.empty()) return text_variant(output, status);
                }
                break;
            case UIA_IsSelectionPatternAvailablePropertyId: boolean(output, id_ && available_selection(*state_, id_)); break;
            case UIA_IsSelectionItemPatternAvailablePropertyId: boolean(output, id_ && available_selection_item(*state_, id_)); break;
            case UIA_SelectionSelectionPropertyId:
                if (id_ && available_selection(*state_, id_)) {
                    SAFEARRAY *array = nullptr;
                    const auto result = collection_selection_array(state_, id_, &array);
                    if (FAILED(result)) return result;
                    output->vt = static_cast<VARTYPE>(VT_ARRAY | VT_UNKNOWN); output->parray = array;
                }
                break;
            case UIA_SelectionCanSelectMultiplePropertyId:
                if (id_ && available_selection(*state_, id_))
                    boolean(output, grid_node().grid->selection_mode == 2);
                break;
            case UIA_SelectionIsSelectionRequiredPropertyId:
                // CollectionInfo has no required-selection field. CLEAR can
                // deselect one item while a real callback selects another.
                if (id_ && available_grid(*state_, id_) && grid_node().grid->selection_required.has_value()) {
                    boolean(output, *grid_node().grid->selection_required);
                    return S_OK;
                }
                output->vt = VT_UNKNOWN;
                return UiaGetReservedNotSupportedValue(&output->punkVal);
            case UIA_SelectionItemIsSelectedPropertyId:
                if (id_ && available_selection_item(*state_, id_)) boolean(output, grid_node().grid_item->selected);
                break;
            case UIA_SelectionItemSelectionContainerPropertyId:
                if (id_ && available_selection_item(*state_, id_)) {
                    output->vt = VT_UNKNOWN;
                    output->punkVal = static_cast<IRawElementProviderSimple *>(element(grid_node().grid_item->owner));
                }
                break;
            case UIA_IsGridPatternAvailablePropertyId: boolean(output, id_ && available_grid(*state_, id_)); break;
            case UIA_IsGridItemPatternAvailablePropertyId: boolean(output, grid_item_current()); break;
            case UIA_GridRowCountPropertyId:
            case UIA_GridColumnCountPropertyId:
                if (id_ && available_grid(*state_, id_)) {
                    output->vt = VT_I4;
                    output->lVal = property == UIA_GridRowCountPropertyId ? grid_node().grid->rows : grid_node().grid->columns;
                }
                break;
            case UIA_GridItemRowPropertyId:
            case UIA_GridItemColumnPropertyId:
            case UIA_GridItemRowSpanPropertyId:
            case UIA_GridItemColumnSpanPropertyId:
                if (grid_item_current()) {
                    const auto &item = *grid_node().grid_item;
                    output->vt = VT_I4;
                    output->lVal = property == UIA_GridItemRowPropertyId ? item.row
                        : property == UIA_GridItemColumnPropertyId ? item.column
                        : property == UIA_GridItemRowSpanPropertyId ? item.row_span : item.column_span;
                }
                break;
            case UIA_GridItemContainingGridPropertyId:
                if (grid_item_current()) {
                    output->vt = VT_UNKNOWN;
                    output->punkVal = static_cast<IRawElementProviderSimple *>(element(grid_node().grid_item->owner));
                }
                break;
            case UIA_IsTextPatternAvailablePropertyId: boolean(output, id_ && node().kind == AccessibilityKind::edit_text); break;
            case UIA_IsTextEditPatternAvailablePropertyId: boolean(output, id_ && node().kind == AccessibilityKind::edit_text); break;
            case UIA_IsValuePatternAvailablePropertyId: boolean(output, value && value->kind == AccessibilityKind::edit_text); break;
            case UIA_ValueValuePropertyId:
                if (value && value->kind == AccessibilityKind::edit_text) return text_variant(output, value->value);
                break;
            case UIA_ValueIsReadOnlyPropertyId:
                if (value && value->kind == AccessibilityKind::edit_text) boolean(output, false);
                break;
            case UIA_ScrollHorizontallyScrollablePropertyId:
                if (value && value->scrollable) boolean(output, false);
                break;
            case UIA_ScrollVerticallyScrollablePropertyId:
                if (value && value->scrollable) boolean(output, value->scroll_range_y > 0);
                break;
            case UIA_ScrollHorizontalScrollPercentPropertyId:
            case UIA_ScrollVerticalScrollPercentPropertyId:
            case UIA_ScrollHorizontalViewSizePropertyId:
            case UIA_ScrollVerticalViewSizePropertyId:
                if (value && value->scrollable) {
                    output->vt = VT_R8;
                    output->dblVal = property == UIA_ScrollHorizontalScrollPercentPropertyId ? UIA_ScrollPatternNoScroll
                        : property == UIA_ScrollVerticalScrollPercentPropertyId ? vertical_percent(*value)
                        : property == UIA_ScrollVerticalViewSizePropertyId ? vertical_view_size(*value) : 100.0;
                }
                break;
            case UIA_ToggleToggleStatePropertyId:
                if (value && value->toggleable) {
                    output->vt = VT_I4;
                    output->lVal = value->checked ? ToggleState_On : ToggleState_Off;
                }
                break;
            default: break; // VT_EMPTY delegates unsupported properties to UIA.
            }
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE get_HostRawElementProvider(IRawElementProviderSimple **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        HWND window = nullptr;
        const auto result = guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            // A retained detached provider keeps only its immutable connection
            // identity for completion events. Dynamic tree/actions still require
            // current(); this never reintroduces a removed node or newer serial.
            if (!state_->connected || !state_->window) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!id_) window = state_->window;
            return S_OK;
        });
        return SUCCEEDED(result) && window ? UiaHostProviderFromHwnd(window, output) : result;
    }
    HRESULT STDMETHODCALLTYPE Navigate(NavigateDirection direction, IRawElementProviderFragment **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (direction == NavigateDirection_Parent) return id_ ? fragment(node().parent, output) : S_OK;
            if (direction == NavigateDirection_FirstChild || direction == NavigateDirection_LastChild) {
                if (!id_) return state_->content ? fragment(state_->content, output) : S_OK;
                if (available_grid(*state_, id_)) {
                    const auto &children = state_->nodes.at(id_).grid_projection->children;
                    if (!children.empty()) *output = projected_fragment(state_, id_, direction == NavigateDirection_FirstChild
                                                                                     ? children.front() : children.back());
                    return S_OK;
                }
                const auto &children = node().children;
                return children.empty() ? S_OK : fragment(direction == NavigateDirection_FirstChild
                                                           ? children.front() : children.back(), output);
            }
            if (direction != NavigateDirection_NextSibling && direction != NavigateDirection_PreviousSibling)
                return E_INVALIDARG;
            if (!id_ || !node().parent) return S_OK;
            if (available_grid(*state_, node().parent)) {
                const auto &siblings = state_->nodes.at(node().parent).grid_projection->children;
                const auto found = std::find_if(siblings.begin(), siblings.end(), [&](const auto &cell) {
                    return cell.view == id_ && cell.serial == serial_;
                });
                if (found == siblings.end()) return UIA_E_ELEMENTNOTAVAILABLE;
                if (direction == NavigateDirection_NextSibling) {
                    if (std::next(found) != siblings.end()) *output = projected_fragment(state_, node().parent, *std::next(found));
                } else if (found != siblings.begin()) *output = projected_fragment(state_, node().parent, *std::prev(found));
                return S_OK;
            }
            const auto &siblings = state_->nodes.at(node().parent).node.children;
            const auto found = std::find(siblings.begin(), siblings.end(), id_);
            if (found == siblings.end()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (direction == NavigateDirection_NextSibling)
                return std::next(found) == siblings.end() ? S_OK : fragment(*std::next(found), output);
            return found == siblings.begin() ? S_OK : fragment(*std::prev(found), output);
        });
    }
    HRESULT STDMETHODCALLTYPE GetRuntimeId(SAFEARRAY **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            // A retained detached provider keeps only its immutable connection
            // identity for completion events. Dynamic tree/actions still require
            // current(); this never reintroduces a removed node or newer serial.
            if (!state_->connected || !state_->window) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!id_) return S_OK; // Host HWND supplies the fragment root identity.
            auto *array = SafeArrayCreateVector(VT_I4, 0, 3);
            if (!array) return E_OUTOFMEMORY;
            const std::array<int, 3> values{UiaAppendRuntimeId,
                static_cast<int>(serial_ & 0xffffffffu), static_cast<int>(serial_ >> 32)};
            for (LONG index = 0; index < static_cast<LONG>(values.size()); ++index) {
                auto value = values[static_cast<std::size_t>(index)];
                const auto result = SafeArrayPutElement(array, &index, &value);
                if (FAILED(result)) { SafeArrayDestroy(array); return result; }
            }
            *output = array;
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE get_BoundingRectangle(UiaRect *output) override {
        if (!output) return E_POINTER;
        *output = {};
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            const auto &bounds = id_ ? node().bounds : state_->bounds;
            *output = {static_cast<double>(bounds.left), static_cast<double>(bounds.top),
                       static_cast<double>(bounds.right - bounds.left), static_cast<double>(bounds.bottom - bounds.top)};
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE GetEmbeddedFragmentRoots(SAFEARRAY **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetFocus() override {
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            return queue_action(AccessibilityActionKind::focus);
        });
    }
    HRESULT STDMETHODCALLTYPE get_FragmentRoot(IRawElementProviderFragmentRoot **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            // A retained detached provider keeps only its immutable connection
            // identity for completion events. Dynamic tree/actions still require
            // current(); this never reintroduces a removed node or newer serial.
            if (!state_->connected || !state_->window) return UIA_E_ELEMENTNOTAVAILABLE;
            *output = static_cast<IRawElementProviderFragmentRoot *>(element(0));
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE ElementProviderFromPoint(double x, double y, IRawElementProviderFragment **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!state_->active || !inside(state_->bounds, x, y)) return S_OK;
            auto selected = state_->content;
            if (!selected) return fragment(0, output);
            const auto &content = state_->nodes.at(selected).node;
            if (content.offscreen || !inside(content.bounds, x, y))
                return fragment(0, output); // Letterbox margins belong to the host root.
            for (std::size_t depth = 0; depth < maximum_nodes; ++depth) {
                const auto &value = state_->nodes.at(selected).node;
                std::uint64_t next = 0;
                for (auto child = value.children.rbegin(); child != value.children.rend(); ++child)
                    if (!state_->nodes.at(*child).node.offscreen && inside(state_->nodes.at(*child).node.bounds, x, y)) {
                        next = *child;
                        break;
                    }
                if (!next) return fragment(selected, output);
                selected = next;
            }
            return UIA_E_ELEMENTNOTAVAILABLE;
        });
    }
    HRESULT STDMETHODCALLTYPE GetFocus(IRawElementProviderFragment **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (state_->active)
                for (const auto &[id, entry] : state_->nodes)
                    if (entry.node.focused) return fragment(id, output);
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE Invoke() override {
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            return queue_action(AccessibilityActionKind::invoke);
        });
    }
    HRESULT STDMETHODCALLTYPE Toggle() override {
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            return queue_action(AccessibilityActionKind::toggle);
        });
    }
    HRESULT STDMETHODCALLTYPE get_ToggleState(ToggleState *output) override {
        if (!output) return E_POINTER;
        *output = ToggleState_Off;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!id_ || !node().toggleable) return UIA_E_NOTSUPPORTED;
            *output = node().checked ? ToggleState_On : ToggleState_Off;
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE Scroll(ScrollAmount horizontal, ScrollAmount vertical) override {
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!id_ || !node().scrollable) return UIA_E_NOTSUPPORTED;
            const auto valid = [](ScrollAmount value) {
                return value == ScrollAmount_NoAmount || value == ScrollAmount_LargeDecrement ||
                       value == ScrollAmount_SmallDecrement || value == ScrollAmount_LargeIncrement ||
                       value == ScrollAmount_SmallIncrement;
            };
            if (!valid(horizontal) || !valid(vertical)) return E_INVALIDARG;
            if (horizontal != ScrollAmount_NoAmount) return UIA_E_INVALIDOPERATION;
            if (!state_->active || state_->actions_suspended || !node().enabled) return UIA_E_ELEMENTNOTENABLED;
            if (vertical == ScrollAmount_NoAmount) return S_OK;
            const std::int32_t amount = vertical == ScrollAmount_LargeDecrement ? -2
                : vertical == ScrollAmount_SmallDecrement ? -1 : vertical == ScrollAmount_LargeIncrement ? 2 : 1;
            return queue_action(AccessibilityActionKind::scroll, amount);
        });
    }
    HRESULT STDMETHODCALLTYPE SetScrollPercent(double horizontal, double vertical) override {
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!id_ || !node().scrollable) return UIA_E_NOTSUPPORTED;
            const auto valid = [](double value) {
                return std::isfinite(value) && (value == UIA_ScrollPatternNoScroll || (value >= 0 && value <= 100));
            };
            if (!valid(horizontal) || !valid(vertical)) return E_INVALIDARG;
            if (horizontal != UIA_ScrollPatternNoScroll) return UIA_E_INVALIDOPERATION;
            if (!state_->active || state_->actions_suspended || !node().enabled) return UIA_E_ELEMENTNOTENABLED;
            if (vertical == UIA_ScrollPatternNoScroll) return S_OK;
            return queue_action(AccessibilityActionKind::set_scroll_percent, 0, vertical);
        });
    }
    HRESULT scroll_double(double *output, bool vertical, bool size) {
        if (!output) return E_POINTER;
        *output = size ? 100.0 : UIA_ScrollPatternNoScroll;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!id_ || !node().scrollable) return UIA_E_NOTSUPPORTED;
            if (vertical) *output = size ? vertical_view_size(node()) : vertical_percent(node());
            return S_OK;
        });
    }
    HRESULT scroll_boolean(BOOL *output, bool vertical) {
        if (!output) return E_POINTER;
        *output = FALSE;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!id_ || !node().scrollable) return UIA_E_NOTSUPPORTED;
            *output = vertical && node().scroll_range_y > 0 ? TRUE : FALSE;
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE get_HorizontalScrollPercent(double *output) override { return scroll_double(output, false, false); }
    HRESULT STDMETHODCALLTYPE get_VerticalScrollPercent(double *output) override { return scroll_double(output, true, false); }
    HRESULT STDMETHODCALLTYPE get_HorizontalViewSize(double *output) override { return scroll_double(output, false, true); }
    HRESULT STDMETHODCALLTYPE get_VerticalViewSize(double *output) override { return scroll_double(output, true, true); }
    HRESULT STDMETHODCALLTYPE get_HorizontallyScrollable(BOOL *output) override { return scroll_boolean(output, false); }
    HRESULT STDMETHODCALLTYPE get_VerticallyScrollable(BOOL *output) override { return scroll_boolean(output, true); }
    HRESULT STDMETHODCALLTYPE GetItem(int row, int column, IRawElementProviderSimple **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!id_ || !available_grid(*state_, id_)) return UIA_E_NOTSUPPORTED;
            const auto &grid = *grid_node().grid;
            if (row < 0 || column < 0 || row >= grid.rows || column >= grid.columns) return E_INVALIDARG;
            const auto &projection = *state_->nodes.at(id_).grid_projection;
            *output = projected_element(state_, id_, projection.cells[static_cast<std::size_t>(row * grid.columns + column)]);
            return S_OK;
        });
    }
    HRESULT grid_integer(int *output, int field) {
        if (!output) return E_POINTER;
        *output = 0;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (field < 2) {
                if (!id_ || !available_grid(*state_, id_)) return UIA_E_NOTSUPPORTED;
                *output = field ? grid_node().grid->columns : grid_node().grid->rows;
            } else {
                if (!grid_item_current()) return UIA_E_NOTSUPPORTED;
                const auto &item = *grid_node().grid_item;
                *output = field == 2 ? item.row : field == 3 ? item.column : field == 4 ? item.row_span : item.column_span;
            }
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE get_RowCount(int *output) override { return grid_integer(output, 0); }
    HRESULT STDMETHODCALLTYPE get_ColumnCount(int *output) override { return grid_integer(output, 1); }
    HRESULT STDMETHODCALLTYPE get_Row(int *output) override { return grid_integer(output, 2); }
    HRESULT STDMETHODCALLTYPE get_Column(int *output) override { return grid_integer(output, 3); }
    HRESULT STDMETHODCALLTYPE get_RowSpan(int *output) override { return grid_integer(output, 4); }
    HRESULT STDMETHODCALLTYPE get_ColumnSpan(int *output) override { return grid_integer(output, 5); }
    HRESULT STDMETHODCALLTYPE get_ContainingGrid(IRawElementProviderSimple **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!grid_item_current()) return UIA_E_NOTSUPPORTED;
            *output = static_cast<IRawElementProviderSimple *>(element(grid_node().grid_item->owner));
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE SetValue(LPCWSTR input) override {
        if (!input) return E_INVALIDARG;
        return guarded([&]() -> HRESULT {
            std::size_t length = 0;
            while (length <= 4096 && input[length]) ++length;
            if (length > 4096) return E_INVALIDARG;
            std::u16string value(reinterpret_cast<const char16_t *>(input), length);
            std::lock_guard lock(state_->mutex);
            return queue_action(AccessibilityActionKind::replace_text, 0, 0, std::move(value));
        });
    }
    HRESULT STDMETHODCALLTYPE get_Value(BSTR *output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!id_ || node().kind != AccessibilityKind::edit_text) return UIA_E_NOTSUPPORTED;
            *output = SysAllocStringLen(reinterpret_cast<const OLECHAR *>(node().value.data()), static_cast<UINT>(node().value.size()));
            return *output ? S_OK : E_OUTOFMEMORY;
        });
    }
    HRESULT STDMETHODCALLTYPE get_IsReadOnly(BOOL *output) override {
        if (!output) return E_POINTER;
        *output = FALSE;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            return id_ && node().kind == AccessibilityKind::edit_text ? S_OK : UIA_E_NOTSUPPORTED;
        });
    }
    // ITextProvider methods (CR-UIA-003)
    HRESULT STDMETHODCALLTYPE GetSelection(SAFEARRAY **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!id_ || node().kind != AccessibilityKind::edit_text) return UIA_E_NOTSUPPORTED;
            const auto &text = node().value;
            if (node().selection_start < 0 || node().selection_end < 0) {
                return S_OK; // No selected text or insertion point: null per ITextProvider.
            }
            auto *range = new TextRange(state_, id_, serial_);
            const auto total = static_cast<std::int32_t>(text.size());
            range->start_ = std::clamp(std::min(node().selection_start, node().selection_end), 0, total);
            range->end_ = std::clamp(std::max(node().selection_start, node().selection_end), 0, total);
            *output = SafeArrayCreateVector(VT_UNKNOWN, 0, 1);
            if (!*output) { delete range; return E_OUTOFMEMORY; }
            LONG index = 0;
            IUnknown *unk = static_cast<IUnknown *>(range);
            const auto r = SafeArrayPutElement(*output, &index, unk);
            range->Release(); // SAFEARRAY retains its own reference on success.
            if (FAILED(r)) { SafeArrayDestroy(*output); *output = nullptr; return r; }
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE GetVisibleRanges(SAFEARRAY **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!id_ || !shaped_text(node())) return UIA_E_NOTSUPPORTED;
            std::vector<std::pair<std::uint32_t, std::uint32_t>> visible;
            if (!node().offscreen && !empty(node().text_clip)) {
                const auto clusters = node().text_layout->clusters();
                if (clusters.size() > node().value.size() + 1)
                    throw std::invalid_argument("Shaped cluster count exceeds text bound");
                for (const auto &cluster : clusters) {
                    if (cluster.start > node().value.size() || cluster.length > node().value.size() - cluster.start)
                        throw std::invalid_argument("Shaped cluster exceeds text bounds");
                    if (cluster.length && clipped_text_rectangle(node(), cluster.bounds, true))
                        visible.emplace_back(cluster.start, cluster.start + cluster.length);
                }
                // An empty visible editor still exposes its insertion position.
                if (node().value.empty())
                    for (const auto &rectangle : node().text_layout->rectangles(0, 0))
                        if (clipped_text_rectangle(node(), rectangle, true)) {
                            visible.emplace_back(0, 0);
                            break;
                        }
            }
            std::sort(visible.begin(), visible.end());
            std::vector<std::pair<std::uint32_t, std::uint32_t>> merged;
            for (const auto &range : visible) {
                if (!merged.empty() && range.first <= merged.back().second)
                    merged.back().second = std::max(merged.back().second, range.second);
                else merged.push_back(range);
            }
            SafeArrayOwner result(SafeArrayCreateVector(VT_UNKNOWN, 0, static_cast<ULONG>(merged.size())));
            if (!result.value) return E_OUTOFMEMORY;
            for (LONG index = 0; index < static_cast<LONG>(merged.size()); ++index) {
                ComPtr<ITextRangeProvider> range;
                auto *created = new TextRange(state_, id_, serial_);
                range.Attach(created);
                created->start_ = static_cast<std::int32_t>(merged[static_cast<std::size_t>(index)].first);
                created->end_ = static_cast<std::int32_t>(merged[static_cast<std::size_t>(index)].second);
                const auto status = SafeArrayPutElement(result.value, &index, static_cast<IUnknown *>(range.Get()));
                if (FAILED(status)) return status;
            }
            *output = result.release();
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE RangeFromChild(IRawElementProviderSimple *child, ITextRangeProvider **output) override {
        (void)child;
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            return E_INVALIDARG; // The editable value has no embedded child providers.
        });
    }
    HRESULT STDMETHODCALLTYPE RangeFromPoint(UiaPoint point, ITextRangeProvider **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (!std::isfinite(point.x) || !std::isfinite(point.y)) return E_INVALIDARG;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!id_ || !shaped_text(node())) return UIA_E_NOTSUPPORTED;
            const auto x = point.x - static_cast<double>(node().text_origin.x);
            const auto y = point.y - static_cast<double>(node().text_origin.y);
            if (std::abs(x) > std::numeric_limits<float>::max() ||
                std::abs(y) > std::numeric_limits<float>::max()) return E_INVALIDARG;
            // DirectWrite returns the closest insertion position even outside
            // the layout. Trailing shaping clusters are handled by TextLayout.
            const auto position = node().text_layout->hit_test(static_cast<float>(x), static_cast<float>(y));
            if (position > node().value.size()) throw std::invalid_argument("Text hit exceeds text bound");
            auto range = std::make_unique<TextRange>(state_, id_, serial_);
            range->start_ = range->end_ = static_cast<std::int32_t>(position);
            *output = range.release();
            return S_OK;
        });
    }
    // Current ranges are independent of the bounded historical event payloads.
    HRESULT composition_range(bool conversion, ITextRangeProvider **output) {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!id_ || node().kind != AccessibilityKind::edit_text) return UIA_E_NOTSUPPORTED;
            if (conversion && !node().conversion_available) return UIA_E_NOTSUPPORTED;
            const auto first = conversion ? node().conversion_start : node().composing_start;
            const auto last = conversion ? node().conversion_end : node().composing_end;
            if (first == -1 && last == -1) return S_OK;
            if (first < 0 || last <= first || static_cast<std::size_t>(last) > node().value.size())
                return UIA_E_INVALIDOPERATION;
            auto range = std::make_unique<TextRange>(state_, id_, serial_);
            range->start_ = first; range->end_ = last;
            *output = range.release();
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE GetActiveComposition(ITextRangeProvider **output) override {
        return composition_range(false, output); // Guest composition needs no native token.
    }
    HRESULT STDMETHODCALLTYPE GetConversionTarget(ITextRangeProvider **output) override {
        return composition_range(true, output);
    }
    HRESULT STDMETHODCALLTYPE get_DocumentRange(ITextRangeProvider **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!id_ || node().kind != AccessibilityKind::edit_text) return UIA_E_NOTSUPPORTED;
            auto *range = new TextRange(state_, id_, serial_);
            range->start_ = 0;
            range->end_ = static_cast<std::int32_t>(node().value.size());
            *output = range;
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE get_SupportedTextSelection(SupportedTextSelection *output) override {
        if (!output) return E_POINTER;
        *output = SupportedTextSelection_None;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!id_ || node().kind != AccessibilityKind::edit_text) return UIA_E_NOTSUPPORTED;
            *output = SupportedTextSelection_Single;
            return S_OK;
        });
    }
};
// Separate from Provider: ITextProvider::GetSelection has the same C++
// signature as ISelectionProvider::GetSelection but returns text ranges.
class CollectionSelectionPattern final : public ISelectionProvider, public ISelectionItemProvider {
    std::atomic<ULONG> references_{1};
    const std::shared_ptr<State> state_;
    const std::uint64_t view_, serial_, owner_, owner_serial_, shape_epoch_;
    const bool item_;
    bool current() const noexcept {
        const auto found = state_->nodes.find(view_);
        const auto owner = state_->nodes.find(owner_);
        return found != state_->nodes.end() && found->second.serial == serial_ && !found->second.text_retired &&
            owner != state_->nodes.end() && owner->second.serial == owner_serial_ && available_selection(*state_, owner_) &&
            owner->second.grid_projection->shape_epoch == shape_epoch_ &&
            (!item_ || (available_selection_item(*state_, view_) && found->second.node.grid_item->owner == owner_));
    }
    HRESULT queue(AccessibilityCollectionSelectionOperation operation) {
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!item_) return UIA_E_NOTSUPPORTED;
            const auto &entry = state_->nodes.at(view_);
            const auto &owner = state_->nodes.at(owner_);
            const auto &node = entry.node;
            if (!state_->active || state_->actions_suspended || !node.enabled || !owner.node.enabled) return UIA_E_ELEMENTNOTENABLED;
            if (!state_->foreground || node.offscreen || empty(node.bounds)) return UIA_E_INVALIDOPERATION;
            const auto selected = node.grid_item->selected;
            std::size_t count = 0;
            for (const auto child : owner.node.children) if (state_->nodes.at(child).node.grid_item->selected) ++count;
            if ((operation == AccessibilityCollectionSelectionOperation::add && selected) ||
                (operation == AccessibilityCollectionSelectionOperation::remove && !selected) ||
                (operation == AccessibilityCollectionSelectionOperation::replace && selected && count == 1)) return S_OK;
            if (operation == AccessibilityCollectionSelectionOperation::add && owner.node.grid->selection_mode == 1 && count)
                return UIA_E_INVALIDOPERATION;
            if (operation == AccessibilityCollectionSelectionOperation::remove && *owner.node.grid->selection_required && count == 1)
                return UIA_E_INVALIDOPERATION;
            if ((operation == AccessibilityCollectionSelectionOperation::add && !(node.grid_item->actions & 4u)) ||
                (operation == AccessibilityCollectionSelectionOperation::remove && !(node.grid_item->actions & 8u)))
                return UIA_E_NOTSUPPORTED;
            // Compound replace is checked at each real guest stage. Required
            // selection chooses the target first; a sole old item need not
            // advertise CLEAR when that first callback may deselect it itself.
            if (state_->actions.size() >= maximum_actions) return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_QUOTA);
            AccessibilityAction action;
            action.kind = AccessibilityActionKind::collection_selection;
            action.view = view_; action.collection_owner = owner_;
            action.collection_selection_operation = operation;
            action.expected_metadata_revision = owner.node.grid->metadata_revision;
            action.expected_view_revision = owner.node.source_view_revision;
            state_->actions.push_back({std::move(action), serial_, owner_serial_, shape_epoch_});
            if (!PostMessageW(state_->window, state_->message, 0, 0)) {
                const auto error = GetLastError(); state_->actions.pop_back();
                return HRESULT_FROM_WIN32(error ? error : ERROR_GEN_FAILURE);
            }
            return S_OK; // Accepted once, never a claim about desired guest state.
        });
    }
  public:
    CollectionSelectionPattern(std::shared_ptr<State> state, std::uint64_t view, bool item)
        : state_(std::move(state)), view_(view), serial_(state_->nodes.at(view).serial),
          owner_(item ? state_->nodes.at(view).node.grid_item->owner : view),
          owner_serial_(state_->nodes.at(owner_).serial), shape_epoch_(state_->nodes.at(owner_).grid_projection->shape_epoch), item_(item) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid == __uuidof(IUnknown)) *output = static_cast<IUnknown *>(static_cast<ISelectionProvider *>(this));
        else if (!item_ && iid == __uuidof(ISelectionProvider)) *output = static_cast<ISelectionProvider *>(this);
        else if (item_ && iid == __uuidof(ISelectionItemProvider)) *output = static_cast<ISelectionItemProvider *>(this);
        else return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return references_.fetch_add(1, std::memory_order_relaxed) + 1; }
    ULONG STDMETHODCALLTYPE Release() override {
        const auto remaining = references_.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (!remaining) delete this;
        return remaining;
    }
    HRESULT STDMETHODCALLTYPE GetSelection(SAFEARRAY **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            return item_ ? UIA_E_NOTSUPPORTED : collection_selection_array(state_, owner_, output);
        });
    }
    HRESULT STDMETHODCALLTYPE get_CanSelectMultiple(BOOL *output) override {
        if (!output) return E_POINTER;
        *output = FALSE;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (item_) return UIA_E_NOTSUPPORTED;
            *output = state_->nodes.at(owner_).node.grid->selection_mode == 2 ? TRUE : FALSE;
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE get_IsSelectionRequired(BOOL *output) override {
        if (!output) return E_POINTER;
        *output = FALSE;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            const auto required = state_->nodes.at(owner_).node.grid->selection_required;
            if (item_ || !required.has_value()) return UIA_E_NOTSUPPORTED;
            *output = *required ? TRUE : FALSE;
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE Select() override { return queue(AccessibilityCollectionSelectionOperation::replace); }
    HRESULT STDMETHODCALLTYPE AddToSelection() override { return queue(AccessibilityCollectionSelectionOperation::add); }
    HRESULT STDMETHODCALLTYPE RemoveFromSelection() override { return queue(AccessibilityCollectionSelectionOperation::remove); }
    HRESULT STDMETHODCALLTYPE get_IsSelected(BOOL *output) override {
        if (!output) return E_POINTER;
        *output = FALSE;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!item_) return UIA_E_NOTSUPPORTED;
            *output = state_->nodes.at(view_).node.grid_item->selected ? TRUE : FALSE;
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE get_SelectionContainer(IRawElementProviderSimple **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (!item_) return UIA_E_NOTSUPPORTED;
            *output = static_cast<IRawElementProviderSimple *>(new Provider(state_, owner_, owner_serial_));
            return S_OK;
        });
    }
};
IUnknown *collection_selection_pattern(const std::shared_ptr<State> &state, std::uint64_t view, bool item) {
    auto *pattern = new CollectionSelectionPattern(state, view, item);
    return item ? static_cast<IUnknown *>(static_cast<ISelectionItemProvider *>(pattern))
                : static_cast<IUnknown *>(static_cast<ISelectionProvider *>(pattern));
}
HRESULT collection_selection_array(const std::shared_ptr<State> &state, std::uint64_t owner, SAFEARRAY **output) {
    *output = nullptr;
    const auto &children = state->nodes.at(owner).node.children;
    ULONG count = 0;
    for (const auto child : children) if (state->nodes.at(child).node.grid_item->selected) ++count;
    struct Array {
        SAFEARRAY *value;
        ~Array() { if (value) SafeArrayDestroy(value); }
    } array{SafeArrayCreateVector(VT_UNKNOWN, 0, count)};
    if (!array.value) return E_OUTOFMEMORY;
    LONG index = 0;
    for (const auto child : children) {
        const auto &entry = state->nodes.at(child);
        if (!entry.node.grid_item->selected) continue;
        ComPtr<IRawElementProviderSimple> provider;
        provider.Attach(static_cast<IRawElementProviderSimple *>(new Provider(state, child, entry.serial)));
        const auto status = SafeArrayPutElement(array.value, &index, provider.Get());
        if (FAILED(status)) return status;
        ++index;
    }
    *output = std::exchange(array.value, nullptr);
    return S_OK;
}
// A logical empty cell is never a guest View. Its immutable identity belongs
// to one proven grid shape, and it has no visual, input, or action authority.
class EmptyCellProvider final : public IRawElementProviderSimple,
                                public IRawElementProviderFragment,
                                public IGridItemProvider {
    std::atomic<ULONG> references_{1};
    const std::shared_ptr<State> state_;
    const std::uint64_t owner_, owner_serial_, shape_epoch_;
    const int row_, column_;
    bool current() const noexcept {
        if (!available_grid(*state_, owner_)) return false;
        const auto &owner = state_->nodes.at(owner_);
        const auto &projection = *owner.grid_projection;
        if (owner.serial != owner_serial_ || projection.shape_epoch != shape_epoch_ ||
            row_ < 0 || column_ < 0 || row_ >= projection.metadata.rows || column_ >= projection.metadata.columns) return false;
        const auto &cell = projection.cells[static_cast<std::size_t>(row_ * projection.metadata.columns + column_)];
        return !cell.view && cell.row == row_ && cell.column == column_;
    }
    HRESULT integer(int *output, bool row, bool span) {
        if (!output) return E_POINTER;
        *output = 0;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            *output = span ? 1 : row ? row_ : column_;
            return S_OK;
        });
    }
  public:
    EmptyCellProvider(std::shared_ptr<State> state, std::uint64_t owner, std::uint64_t serial,
                      std::uint64_t shape, int row, int column)
        : state_(std::move(state)), owner_(owner), owner_serial_(serial), shape_epoch_(shape), row_(row), column_(column) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid == __uuidof(IUnknown) || iid == __uuidof(IRawElementProviderSimple))
            *output = static_cast<IRawElementProviderSimple *>(this);
        else if (iid == __uuidof(IRawElementProviderFragment))
            *output = static_cast<IRawElementProviderFragment *>(this);
        else if (iid == __uuidof(IGridItemProvider)) *output = static_cast<IGridItemProvider *>(this);
        else return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return references_.fetch_add(1, std::memory_order_relaxed) + 1; }
    ULONG STDMETHODCALLTYPE Release() override {
        const auto remaining = references_.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (!remaining) delete this;
        return remaining;
    }
    HRESULT STDMETHODCALLTYPE get_ProviderOptions(ProviderOptions *output) override {
        if (!output) return E_POINTER;
        *output = ProviderOptions_ServerSideProvider;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetPatternProvider(PATTERNID pattern, IUnknown **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (pattern == UIA_GridItemPatternId) { *output = static_cast<IGridItemProvider *>(this); AddRef(); }
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE GetPropertyValue(PROPERTYID property, VARIANT *output) override {
        if (!output) return E_POINTER;
        VariantInit(output);
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            switch (property) {
            case UIA_ControlTypePropertyId: output->vt = VT_I4; output->lVal = UIA_CustomControlTypeId; break;
            case UIA_FrameworkIdPropertyId: return text_variant(output, u"Aether.Android");
            case UIA_IsGridItemPatternAvailablePropertyId:
            case UIA_IsControlElementPropertyId:
            case UIA_IsContentElementPropertyId:
            case UIA_IsOffscreenPropertyId: boolean(output, true); break;
            case UIA_IsEnabledPropertyId: boolean(output, state_->nodes.at(owner_).node.enabled); break;
            case UIA_IsSelectionPatternAvailablePropertyId:
            case UIA_IsSelectionItemPatternAvailablePropertyId:
            case UIA_IsKeyboardFocusablePropertyId:
            case UIA_HasKeyboardFocusPropertyId:
            case UIA_IsInvokePatternAvailablePropertyId:
            case UIA_IsTogglePatternAvailablePropertyId:
            case UIA_IsGridPatternAvailablePropertyId:
            case UIA_IsValuePatternAvailablePropertyId:
            case UIA_IsTextPatternAvailablePropertyId:
            case UIA_IsTextEditPatternAvailablePropertyId:
            case UIA_IsScrollPatternAvailablePropertyId: boolean(output, false); break;
            case UIA_GridItemRowPropertyId:
            case UIA_GridItemColumnPropertyId:
            case UIA_GridItemRowSpanPropertyId:
            case UIA_GridItemColumnSpanPropertyId:
                output->vt = VT_I4;
                output->lVal = property == UIA_GridItemRowPropertyId ? row_ : property == UIA_GridItemColumnPropertyId ? column_ : 1;
                break;
            case UIA_GridItemContainingGridPropertyId:
                output->vt = VT_UNKNOWN;
                output->punkVal = static_cast<IRawElementProviderSimple *>(new Provider(state_, owner_, owner_serial_));
                break;
            default: break; // No name, value, selection, or guessed geometry.
            }
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE get_HostRawElementProvider(IRawElementProviderSimple **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT { std::lock_guard lock(state_->mutex); return current() ? S_OK : UIA_E_ELEMENTNOTAVAILABLE; });
    }
    HRESULT STDMETHODCALLTYPE Navigate(NavigateDirection direction, IRawElementProviderFragment **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (direction == NavigateDirection_Parent) {
                *output = static_cast<IRawElementProviderFragment *>(new Provider(state_, owner_, owner_serial_));
                return S_OK;
            }
            if (direction == NavigateDirection_FirstChild || direction == NavigateDirection_LastChild) return S_OK;
            if (direction != NavigateDirection_NextSibling && direction != NavigateDirection_PreviousSibling) return E_INVALIDARG;
            const auto &siblings = state_->nodes.at(owner_).grid_projection->children;
            const auto found = std::find_if(siblings.begin(), siblings.end(), [&](const auto &cell) {
                return !cell.view && cell.row == row_ && cell.column == column_;
            });
            if (found == siblings.end()) return UIA_E_ELEMENTNOTAVAILABLE;
            if (direction == NavigateDirection_NextSibling) {
                if (std::next(found) != siblings.end()) *output = projected_fragment(state_, owner_, *std::next(found));
            } else if (found != siblings.begin()) *output = projected_fragment(state_, owner_, *std::prev(found));
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE GetRuntimeId(SAFEARRAY **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            // Different length/tag from real View provider IDs, with no guest ID.
            const std::array<int, 8> values{UiaAppendRuntimeId, 1,
                static_cast<int>(owner_serial_ & 0xffffffffu), static_cast<int>(owner_serial_ >> 32),
                static_cast<int>(shape_epoch_ & 0xffffffffu), static_cast<int>(shape_epoch_ >> 32), row_, column_};
            auto *array = SafeArrayCreateVector(VT_I4, 0, static_cast<ULONG>(values.size()));
            if (!array) return E_OUTOFMEMORY;
            for (LONG index = 0; index < static_cast<LONG>(values.size()); ++index) {
                auto value = values[static_cast<std::size_t>(index)];
                const auto status = SafeArrayPutElement(array, &index, &value);
                if (FAILED(status)) { SafeArrayDestroy(array); return status; }
            }
            *output = array; return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE get_BoundingRectangle(UiaRect *output) override {
        if (!output) return E_POINTER;
        *output = {};
        return guarded([&]() -> HRESULT { std::lock_guard lock(state_->mutex); return current() ? S_OK : UIA_E_ELEMENTNOTAVAILABLE; });
    }
    HRESULT STDMETHODCALLTYPE GetEmbeddedFragmentRoots(SAFEARRAY **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT { std::lock_guard lock(state_->mutex); return current() ? S_OK : UIA_E_ELEMENTNOTAVAILABLE; });
    }
    HRESULT STDMETHODCALLTYPE SetFocus() override {
        return guarded([&]() -> HRESULT { std::lock_guard lock(state_->mutex); return current() ? UIA_E_NOTSUPPORTED : UIA_E_ELEMENTNOTAVAILABLE; });
    }
    HRESULT STDMETHODCALLTYPE get_FragmentRoot(IRawElementProviderFragmentRoot **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            *output = static_cast<IRawElementProviderFragmentRoot *>(new Provider(state_, 0, 0));
            return S_OK;
        });
    }
    HRESULT STDMETHODCALLTYPE get_Row(int *output) override { return integer(output, true, false); }
    HRESULT STDMETHODCALLTYPE get_Column(int *output) override { return integer(output, false, false); }
    HRESULT STDMETHODCALLTYPE get_RowSpan(int *output) override { return integer(output, true, true); }
    HRESULT STDMETHODCALLTYPE get_ColumnSpan(int *output) override { return integer(output, false, true); }
    HRESULT STDMETHODCALLTYPE get_ContainingGrid(IRawElementProviderSimple **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        return guarded([&]() -> HRESULT {
            std::lock_guard lock(state_->mutex);
            if (!current()) return UIA_E_ELEMENTNOTAVAILABLE;
            *output = static_cast<IRawElementProviderSimple *>(new Provider(state_, owner_, owner_serial_));
            return S_OK;
        });
    }
};
IRawElementProviderSimple *projected_element(const std::shared_ptr<State> &state, std::uint64_t owner, const GridCell &cell) {
    if (cell.view) return static_cast<IRawElementProviderSimple *>(new Provider(state, cell.view, cell.serial));
    const auto &entry = state->nodes.at(owner);
    return static_cast<IRawElementProviderSimple *>(new EmptyCellProvider(state, owner, entry.serial,
        entry.grid_projection->shape_epoch, cell.row, cell.column));
}
IRawElementProviderFragment *projected_fragment(const std::shared_ptr<State> &state, std::uint64_t owner, const GridCell &cell) {
    if (cell.view) return static_cast<IRawElementProviderFragment *>(new Provider(state, cell.view, cell.serial));
    const auto &entry = state->nodes.at(owner);
    return static_cast<IRawElementProviderFragment *>(new EmptyCellProvider(state, owner, entry.serial,
        entry.grid_projection->shape_epoch, cell.row, cell.column));
}
IRawElementProviderSimple *text_element(const std::shared_ptr<State> &state,
                                       std::uint64_t id, std::uint64_t serial) {
    return static_cast<IRawElementProviderSimple *>(new Provider(state, id, serial));
}
} // namespace

struct WindowAccessibility::Impl {
    struct TextEditDelivery {
        ComPtr<IRawElementProviderSimple> provider;
        std::uint64_t view = 0, serial = 0, buffer_revision = 0, revision = 0;
        AccessibilityTextEditKind kind = AccessibilityTextEditKind::composition;
        std::u16string text;
    };
    struct SelectionDelivery {
        ComPtr<IRawElementProviderSimple> provider;
        PROPERTYID property = 0;
        EVENTID event = 0;
        std::uint64_t owner = 0;
        bool before = false, after = false;
    };
    std::deque<SelectionDelivery> selection_delivery;
    bool delivering_selection = false;
    void drain_selection() {
        if (delivering_selection) return;
        delivering_selection = true;
        struct Reset { bool &flag; ~Reset() { flag = false; } } reset{delivering_selection};
        while (!selection_delivery.empty()) {
            auto event = std::move(selection_delivery.front());
            selection_delivery.pop_front(); // Consume before native callback/reentry.
            {
                std::lock_guard lock(state->mutex);
                if (!state->connected || state->terminal) { selection_delivery.clear(); break; }
                if ((event.event || event.property == UIA_SelectionItemIsSelectedPropertyId ||
                     event.property == UIA_SelectionCanSelectMultiplePropertyId ||
                     event.property == UIA_SelectionIsSelectionRequiredPropertyId) &&
                    !available_selection(*state, event.owner)) continue;
            }
            if (!UiaClientsAreListening()) continue;
            HRESULT status;
            if (event.property) {
                VARIANT before{}, after{};
                boolean(&before, event.before); boolean(&after, event.after);
                status = UiaRaiseAutomationPropertyChangedEvent(event.provider.Get(), event.property, before, after);
            } else status = UiaRaiseAutomationEvent(event.provider.Get(), event.event);
            if (FAILED(status)) OutputDebugStringW(L"AETHER_UIA_SELECTION_EVENT_UNAVAILABLE\n");
        }
    }
    std::shared_ptr<State> state;
    ComPtr<IRawElementProviderSimple> root;
    std::deque<TextEditDelivery> text_edit_delivery;
    std::size_t text_edit_units = 0;
    std::uint64_t last_text_edit_revision = 0;
    bool delivering_text_edits = false;
    Impl(HWND window, UINT message) : state(std::make_shared<State>(window, message)) {
        root.Attach(static_cast<IRawElementProviderSimple *>(new Provider(state, 0, 0)));
    }
    struct PreparedTextEdits {
        std::vector<TextEditDelivery> deliveries;
        std::map<std::uint64_t, std::uint64_t> cursors;
        std::uint64_t last_revision = 0;
    };
    struct PreparedTextEditQueue {
        std::deque<TextEditDelivery> deliveries;
        std::size_t units = 0;
    };
    static void validate_text_edits(const std::vector<AccessibilityTextEditEvent> &events,
                                   const std::vector<AccessibilityTextEditGap> &gaps) {
        if (events.size() > 256 || gaps.size() > maximum_nodes)
            throw std::invalid_argument("UI Automation text edit batch exceeds the bound");
        std::size_t units = 0;
        std::uint64_t previous_revision = 0;
        for (const auto &event : events) {
            if (!event.view || !event.buffer_revision || !event.revision || event.revision <= previous_revision ||
                event.text.size() > 4096 || event.text.size() > 65536 - units ||
                (event.kind != AccessibilityTextEditKind::composition &&
                 event.kind != AccessibilityTextEditKind::composition_finalized &&
                 event.kind != AccessibilityTextEditKind::conversion_target_changed) ||
                (event.kind == AccessibilityTextEditKind::conversion_target_changed && !event.text.empty()))
                throw std::invalid_argument("Invalid UI Automation text edit record");
            previous_revision = event.revision;
            units += event.text.size();
        }
        for (const auto &gap : gaps)
            if (!gap.view || !gap.buffer_revision || !gap.dropped_revision)
                throw std::invalid_argument("Invalid UI Automation text edit gap");
    }
    PreparedTextEdits prepare_text_edits(const std::map<std::uint64_t, Entry> &nodes,
        std::vector<AccessibilityTextEditEvent> &events, const std::vector<AccessibilityTextEditGap> &gaps,
        AccessibilityTextEditResult &result) {
        PreparedTextEdits prepared;
        prepared.last_revision = last_text_edit_revision;
        for (auto &event : events) {
            const auto found = nodes.find(event.view);
            if (found == nodes.end() || found->second.text_retired ||
                found->second.current().kind != AccessibilityKind::edit_text ||
                event.buffer_revision > found->second.current().text_buffer_revision) {
                ++result.retired;
                continue;
            }
            const auto &entry = found->second;
            auto &cursor = prepared.cursors.try_emplace(event.view, entry.text_edit_attempted_revision).first->second;
            if (event.revision <= cursor) continue; // Repeated records are consumed, not a new global order.
            if (event.revision > entry.current().text_edit_event_revision)
                throw std::invalid_argument("UI Automation text edit exceeds current revision");
            if (event.revision <= prepared.last_revision)
                throw std::invalid_argument("UI Automation TextEdit global order regressed");
            TextEditDelivery delivery;
            delivery.provider.Attach(static_cast<IRawElementProviderSimple *>(new Provider(state, event.view, entry.serial)));
            delivery.view = event.view; delivery.serial = entry.serial;
            delivery.buffer_revision = event.buffer_revision; delivery.revision = event.revision;
            delivery.kind = event.kind; delivery.text = std::move(event.text);
            prepared.deliveries.push_back(std::move(delivery));
            cursor = event.revision;
            prepared.last_revision = event.revision;
        }
        // Per-View journal gaps span backing buffers. Capture independently
        // known records first, then consume missing intervals before COM.
        for (const auto &gap : gaps) {
            const auto found = nodes.find(gap.view);
            if (found == nodes.end() || found->second.text_retired ||
                found->second.current().kind != AccessibilityKind::edit_text) continue;
            if (gap.dropped_revision > found->second.current().text_edit_event_revision)
                throw std::invalid_argument("UI Automation text edit gap exceeds current revision");
            auto &cursor = prepared.cursors.try_emplace(gap.view, found->second.text_edit_attempted_revision).first->second;
            cursor = std::max(cursor, gap.dropped_revision);
        }
        return prepared;
    }
    PreparedTextEditQueue prepare_text_edit_queue(PreparedTextEdits &prepared, AccessibilityTextEditResult &result) {
        PreparedTextEditQueue queued{text_edit_delivery, text_edit_units};
        for (auto &event : prepared.deliveries) {
            while (!queued.deliveries.empty() &&
                (queued.deliveries.size() >= 256 || event.text.size() > 65536 - queued.units)) {
                queued.units -= queued.deliveries.front().text.size();
                queued.deliveries.pop_front();
                ++result.retired; // The consumed cursor makes this bounded drop permanent.
            }
            queued.units += event.text.size();
            queued.deliveries.push_back(std::move(event));
        }
        return queued;
    }
    void commit_text_edits(std::map<std::uint64_t, Entry> &nodes, const PreparedTextEdits &prepared,
                          PreparedTextEditQueue &queued) noexcept {
        for (const auto &[id, cursor] : prepared.cursors) nodes.find(id)->second.text_edit_attempted_revision = cursor;
        text_edit_delivery.swap(queued.deliveries);
        text_edit_units = queued.units;
        last_text_edit_revision = prepared.last_revision;
    }
    void drain_text_edits(AccessibilityTextEditResult &result);
};
void WindowAccessibility::Impl::drain_text_edits(AccessibilityTextEditResult &result) {
    if (!delivering_text_edits) {
        delivering_text_edits = true;
        struct DeliveryGuard { bool &value; ~DeliveryGuard() { value = false; } } guard{delivering_text_edits};
        while (!text_edit_delivery.empty()) {
            auto event = std::move(text_edit_delivery.front());
            text_edit_delivery.pop_front();
            text_edit_units -= event.text.size();
            {
                std::lock_guard lock(state->mutex);
                const auto found = state->nodes.find(event.view);
                if (!state->connected || found == state->nodes.end() ||
                    found->second.serial != event.serial || found->second.text_retired || !event.buffer_revision ||
                    event.buffer_revision > found->second.current().text_buffer_revision) {
                    ++result.retired;
                    continue;
                }
            }
            // Removal precedes the first external call, including listener checks.
            if (!UiaClientsAreListening()) continue;
            ++result.attempted; // Actual delivery/preparation, including allocation failure.
            HRESULT status = S_OK;
            if (event.kind == AccessibilityTextEditKind::conversion_target_changed) {
                status = UiaRaiseAutomationEvent(event.provider.Get(), UIA_TextEdit_ConversionTargetChangedEventId);
            } else {
                SafeArrayOwner data(SafeArrayCreateVector(VT_BSTR, 0, 1));
                VARIANT text{};
                status = data.value ? text_variant(&text, event.text) : E_OUTOFMEMORY;
                if (SUCCEEDED(status)) {
                    LONG index = 0;
                    status = SafeArrayPutElement(data.value, &index, text.bstrVal);
                }
                VariantClear(&text);
                if (SUCCEEDED(status))
                    status = UiaRaiseTextEditTextChangedEvent(event.provider.Get(),
                        event.kind == AccessibilityTextEditKind::composition ? TextEditChangeType_Composition
                            : TextEditChangeType_CompositionFinalized, data.value);
            }
            if (FAILED(status)) ++result.failed; // An ambiguous failure is never replayed.
        }
    }
}
WindowAccessibility::WindowAccessibility(HWND window, UINT action_message)
    : impl_(std::make_unique<Impl>(window, action_message)) {}
WindowAccessibility::~WindowAccessibility() { disconnect(); }
bool WindowAccessibility::text_edit_delivery_idle() const noexcept {
    return !impl_->delivering_text_edits && impl_->text_edit_delivery.empty();
}
bool WindowAccessibility::text_edit_delivery_active() const noexcept {
    return impl_->delivering_text_edits;
}
void WindowAccessibility::advance_text_documents(std::vector<AccessibilityNode> current_editors,
    std::vector<AccessibilityTextMutationRecord> mutations,
    std::vector<AccessibilityTextMutationGap> gaps) {
    advance_text_documents_impl(std::move(current_editors), std::move(mutations), std::move(gaps), 0);
}
void WindowAccessibility::advance_text_document(AccessibilityNode editor, bool rooted) {
    validate_editor_document(editor);
    const auto id = editor.id;
    std::vector<AccessibilityNode> documents;
    if (rooted) documents.push_back(std::move(editor));
    advance_text_documents_impl(std::move(documents), {}, {}, id);
}
void WindowAccessibility::advance_text_documents_impl(std::vector<AccessibilityNode> current_editors,
    std::vector<AccessibilityTextMutationRecord> mutations,
    std::vector<AccessibilityTextMutationGap> gaps, std::uint64_t only_view) {
    if (current_editors.size() > maximum_nodes || mutations.size() > 256 || gaps.size() > maximum_nodes)
        throw std::invalid_argument("UI Automation text advance exceeds the bound");
    std::map<std::uint64_t, AccessibilityNode> documents;
    std::map<std::uint64_t, std::map<std::uint64_t, AccessibilityTextMutation>> histories;
    const auto retain = [&](std::uint64_t view, const AccessibilityTextMutation &mutation) {
        auto &history = histories[view];
        const auto [found, inserted] = history.emplace(mutation.revision, mutation);
        if (!inserted && (found->second.start != mutation.start || found->second.removed != mutation.removed ||
            found->second.inserted != mutation.inserted || found->second.before_length != mutation.before_length))
            throw std::invalid_argument("Conflicting UI Automation text mutation identity");
    };
    for (auto &editor : current_editors) {
        validate_editor_document(editor);
        histories.try_emplace(editor.id);
        for (const auto &mutation : editor.text_mutations) retain(editor.id, mutation);
        if (!documents.emplace(editor.id, std::move(editor)).second)
            throw std::invalid_argument("Duplicate UI Automation current editor");
    }
    for (const auto &record : mutations) {
        const auto &mutation = record.mutation;
        if (!record.view || !record.buffer_revision || !mutation.revision || mutation.before_length < 0 ||
            mutation.before_length > 4096 || mutation.start < 0 || mutation.start > mutation.before_length ||
            mutation.removed < 0 || mutation.removed > mutation.before_length - mutation.start ||
            mutation.inserted < 0 || mutation.inserted > 4096 - (mutation.before_length - mutation.removed) ||
            (!mutation.removed && !mutation.inserted))
            throw std::invalid_argument("Invalid UI Automation streamed text mutation");
        const auto found = documents.find(record.view);
        if (found == documents.end() || found->second.text_buffer_revision != record.buffer_revision) continue;
        if (mutation.revision > found->second.text_event_revision)
            throw std::invalid_argument("UI Automation mutation exceeds current document");
        retain(record.view, mutation);
    }
    for (const auto &gap : gaps) {
        if (!gap.view || !gap.buffer_revision || !gap.through_revision)
            throw std::invalid_argument("Invalid UI Automation streamed text mutation gap");
        const auto found = documents.find(gap.view);
        if (found != documents.end() && found->second.text_buffer_revision == gap.buffer_revision &&
            gap.through_revision > found->second.text_event_revision)
            throw std::invalid_argument("UI Automation mutation gap exceeds current document");
        // A watermark never suppresses independently captured deltas. The
        // complete consecutive chain below proves whether an anchor can move.
    }
    auto rebase_documents = documents;
    for (auto &[id, document] : rebase_documents) {
        const auto &history = histories.at(id);
        document.text_mutations.clear();
        for (const auto &[revision, mutation] : history) {
            (void)revision;
            document.text_mutations.push_back(mutation);
        }
        document.text_mutation_base_revision = history.empty() ? document.text_event_revision : history.begin()->first - 1;
    }
    std::lock_guard lock(impl_->state->mutex);
    auto &state = *impl_->state;
    if (!state.connected || state.terminal) return;
    struct ContentUpdate {
        Entry *entry = nullptr;
        std::shared_ptr<const AccessibilityNode> content;
        std::shared_ptr<const RangeDocument> document;
        bool retired = false;
    };
    std::vector<ContentUpdate> content_updates;
    content_updates.reserve(state.nodes.size());
    for (auto &[id, entry] : state.nodes) {
        if (only_view && id != only_view) continue;
        if (entry.node.kind != AccessibilityKind::edit_text || entry.text_retired) continue;
        ContentUpdate update;
        update.entry = &entry;
        const auto found = documents.find(id);
        update.retired = found == documents.end();
        if (!update.retired) {
            const auto &current = entry.current();
            const auto &next = found->second;
            if (next.text_buffer_revision < current.text_buffer_revision || next.text_event_revision < current.text_event_revision ||
                (next.text_buffer_revision == current.text_buffer_revision &&
                    (next.text_mutation_base_revision < current.text_mutation_base_revision ||
                     (next.text_event_revision == current.text_event_revision && next.value != current.value))))
                throw std::invalid_argument("UI Automation current document regressed");
            auto content = std::make_shared<AccessibilityNode>(entry.node);
            content->value = next.value;
            content->selection_start = next.selection_start; content->selection_end = next.selection_end;
            content->caret_pos = next.caret_pos;
            content->composing_start = next.composing_start; content->composing_end = next.composing_end;
            content->conversion_start = next.conversion_start; content->conversion_end = next.conversion_end;
            content->conversion_available = next.conversion_available;
            content->composition_event_revision = next.composition_event_revision; content->ime_token = next.ime_token;
            content->text_event_revision = next.text_event_revision; content->selection_event_revision = next.selection_event_revision;
            content->text_mutation_base_revision = next.text_mutation_base_revision; content->text_mutations = next.text_mutations;
            content->text_buffer_revision = next.text_buffer_revision; content->text_edit_event_revision = next.text_edit_event_revision;
            content->source_view_revision = next.source_view_revision;
            content->text_layout.reset(); // Same-value commits cannot reuse old geometry.
            SetRectEmpty(&content->text_clip);
            content->text_can_scroll = false;
            update.content = std::move(content);
            if (entry.document && entry.document->buffer_revision == next.text_buffer_revision &&
                entry.document->text_revision == next.text_event_revision) update.document = entry.document;
            else update.document = std::make_shared<const RangeDocument>(RangeDocument{
                next.text_buffer_revision, next.text_event_revision, next.value});
        }
        content_updates.push_back(std::move(update));
    }
    struct AnchorUpdate {
        std::shared_ptr<RangeAnchor> anchor;
        std::shared_ptr<const RangeDocument> document;
        std::int32_t start = 0, end = 0;
        bool retired = false;
    };
    std::vector<AnchorUpdate> anchor_updates;
    anchor_updates.reserve(state.range_anchors.size());
    for (const auto &registration : state.range_anchors) {
        auto anchor = registration.lock();
        if (!anchor || anchor->retired) continue;
        if (only_view && anchor->view != only_view) continue;
        AnchorUpdate update;
        update.anchor = std::move(anchor);
        update.start = update.anchor->start; update.end = update.anchor->end;
        const auto entry = state.nodes.find(update.anchor->view);
        const auto target = rebase_documents.find(update.anchor->view);
        update.retired = entry == state.nodes.end() || entry->second.text_retired ||
            entry->second.serial != update.anchor->serial || target == rebase_documents.end() ||
            !TextRange::rebase_anchor(*update.anchor, target->second, update.start, update.end);
        if (!update.retired) {
            const auto content = std::find_if(content_updates.begin(), content_updates.end(),
                [&](const auto &candidate) { return candidate.entry == &entry->second; });
            if (content == content_updates.end() || content->retired) update.retired = true;
            else update.document = content->document;
        }
        if (update.retired) { update.start = update.anchor->start; update.end = update.anchor->end; }
        anchor_updates.push_back(std::move(update));
    }
    // No allocation, COM callback, or guest work follows preparation under the
    // mutex. Preserve the full-publication baseline for coalesced UIA events.
    for (auto &update : content_updates) {
        update.entry->pending_content = std::move(update.content);
        update.entry->document = std::move(update.document);
        update.entry->text_retired = update.retired;
    }
    for (auto &update : anchor_updates) {
        update.anchor->start = update.start; update.anchor->end = update.end;
        update.anchor->retired = update.retired;
        update.anchor->document = std::move(update.document);
    }
    std::erase_if(state.range_anchors, [](const auto &anchor) { return anchor.expired(); });
    state.actions_suspended = true; // Preserve valid queued requests until real geometry is published.
}
AccessibilityTextEditResult WindowAccessibility::deliver_text_edits(std::vector<AccessibilityTextEditEvent> text_edits,
    std::vector<AccessibilityTextEditGap> text_edit_gaps) {
    Impl::validate_text_edits(text_edits, text_edit_gaps);
    AccessibilityTextEditResult result;
    {
        std::lock_guard lock(impl_->state->mutex);
        if (!impl_->state->connected || impl_->state->terminal) return result;
        auto prepared = impl_->prepare_text_edits(impl_->state->nodes, text_edits, text_edit_gaps, result);
        auto queued = impl_->prepare_text_edit_queue(prepared, result);
        // Prepared allocations cannot strand a consumed cursor without its
        // payload. Commit all cursors/explicit drops before any external call.
        impl_->commit_text_edits(impl_->state->nodes, prepared, queued);
    }
    impl_->drain_text_edits(result);
    return result;
}
AccessibilityTextEditResult WindowAccessibility::publish(AccessibilitySnapshot snapshot,
    std::vector<AccessibilityTextEditEvent> text_edits,
    std::vector<AccessibilityTextEditGap> text_edit_gaps) {
    AccessibilityTextEditResult result;
    if (snapshot.nodes.size() > maximum_nodes || snapshot.name.size() > 4096)
        throw std::invalid_argument("UI Automation snapshot exceeds the view bound");
    Impl::validate_text_edits(text_edits, text_edit_gaps);
    std::map<std::uint64_t, Entry> replacement;
    for (auto &node : snapshot.nodes) {
        if (node.selection_start < -1 || node.selection_end < -1 || node.caret_pos < -1 ||
            (node.selection_start >= 0 && static_cast<std::size_t>(node.selection_start) > node.value.size()) ||
            (node.selection_end >= 0 && static_cast<std::size_t>(node.selection_end) > node.value.size()) ||
            (node.caret_pos >= 0 && static_cast<std::size_t>(node.caret_pos) > node.value.size()) ||
            (node.kind != AccessibilityKind::edit_text &&
                (node.selection_start != -1 || node.selection_end != -1 || node.caret_pos != -1)))
            throw std::invalid_argument("Invalid UI Automation selection snapshot");
        if (node.value.size() > 4096 || (node.kind != AccessibilityKind::edit_text && !node.value.empty()))
            throw std::invalid_argument("Invalid UI Automation editable value");
        if ((node.kind == AccessibilityKind::edit_text && !node.text_buffer_revision) ||
            (node.kind != AccessibilityKind::edit_text && (node.text_buffer_revision || node.text_edit_event_revision)))
            throw std::invalid_argument("Invalid UI Automation text buffer identity");
        if (node.text_mutations.size() > 64 || node.text_mutation_base_revision > node.text_event_revision ||
            (node.kind != AccessibilityKind::edit_text &&
                (node.text_mutation_base_revision || !node.text_mutations.empty())))
            throw std::invalid_argument("Invalid UI Automation text mutation history");
        auto mutation_revision = node.text_mutation_base_revision;
        std::int32_t mutation_length = -1;
        for (const auto &mutation : node.text_mutations) {
            if (mutation_revision == UINT64_MAX || mutation.revision != mutation_revision + 1 ||
                mutation.before_length < 0 || mutation.before_length > 4096 ||
                (mutation_length >= 0 && mutation.before_length != mutation_length) ||
                mutation.start < 0 || mutation.start > mutation.before_length ||
                mutation.removed < 0 || mutation.removed > mutation.before_length - mutation.start ||
                mutation.inserted < 0 || mutation.inserted > 4096 - (mutation.before_length - mutation.removed) ||
                (!mutation.removed && !mutation.inserted))
                throw std::invalid_argument("Invalid UI Automation text mutation chain");
            mutation_revision = mutation.revision;
            mutation_length = mutation.before_length - mutation.removed + mutation.inserted;
        }
        if (mutation_revision != node.text_event_revision ||
            (mutation_length >= 0 && static_cast<std::size_t>(mutation_length) != node.value.size()))
            throw std::invalid_argument("Incomplete UI Automation text mutation chain");
        const auto marker_valid = [&](std::int32_t first, std::int32_t last) {
            return (first == -1 && last == -1) || (first >= 0 && last > first &&
                static_cast<std::size_t>(last) <= node.value.size());
        };
        if (!marker_valid(node.composing_start, node.composing_end) ||
            !marker_valid(node.conversion_start, node.conversion_end) ||
            (!node.conversion_available && node.conversion_start != -1) ||
            (node.conversion_start >= 0 && (node.composing_start < 0 ||
                node.conversion_start < node.composing_start || node.conversion_end > node.composing_end)) ||
            (node.kind != AccessibilityKind::edit_text && (node.composing_start != -1 || node.conversion_start != -1 ||
                node.composition_event_revision || node.ime_token)))
            throw std::invalid_argument("Invalid UI Automation composition snapshot");
        if (!std::isfinite(node.text_scale) || node.text_scale < 0.5f || node.text_scale > 10 ||
            (node.kind != AccessibilityKind::edit_text &&
             (node.text_event_revision || node.selection_event_revision || node.text_can_scroll)))
            throw std::invalid_argument("Invalid UI Automation text event/scale snapshot");
        if (node.text_layout) {
            if (!shaped_text(node) || node.text_clip.right < node.text_clip.left ||
                node.text_clip.bottom < node.text_clip.top ||
                (!empty(node.text_clip) &&
                    (node.text_clip.left < node.bounds.left || node.text_clip.top < node.bounds.top ||
                     node.text_clip.right > node.bounds.right || node.text_clip.bottom > node.bounds.bottom)))
                throw std::invalid_argument("Invalid UI Automation shaped text binding or clip");
        }
        if (node.scroll_y < 0 || node.scroll_range_y < node.scroll_y || node.scroll_range_y > 327680 ||
            node.scroll_viewport_y < 0 || node.scroll_viewport_y > 327680 ||
            (node.scroll_range_y && node.scroll_viewport_y > 327680 - node.scroll_range_y) ||
            (node.scroll_range_y && !node.scroll_viewport_y) ||
            node.scrollable != (node.kind == AccessibilityKind::scroll_view) ||
            (node.scrollable && (node.parent || node.children.size() > 1)) ||
            (!node.scrollable && (node.scroll_y || node.scroll_range_y || node.scroll_viewport_y)))
            throw std::invalid_argument("Invalid UI Automation scroll geometry");
        if (!node.id || node.name.size() > 65536 || node.children.size() > maximum_nodes ||
            !replacement.emplace(node.id, Entry{std::move(node), 0}).second)
            throw std::invalid_argument("Invalid UI Automation view identity or text bound");
    }
    if (snapshot.content && (!replacement.contains(snapshot.content) || replacement.at(snapshot.content).node.parent))
        throw std::invalid_argument("UI Automation content has no root");
    // Reachability and reciprocal edges reject orphaned/cyclic snapshot trees.
    std::vector<std::uint64_t> pending;
    if (snapshot.content) pending.push_back(snapshot.content);
    std::map<std::uint64_t, bool> visited;
    while (!pending.empty()) {
        const auto id = pending.back(); pending.pop_back();
        if (!replacement.contains(id) || !visited.emplace(id, true).second)
            throw std::invalid_argument("Invalid UI Automation tree");
        for (const auto child : replacement.at(id).node.children) {
            if (!replacement.contains(child) || replacement.at(child).node.parent != id)
                throw std::invalid_argument("Invalid UI Automation child relationship");
            pending.push_back(child);
        }
    }
    if (visited.size() != replacement.size()) throw std::invalid_argument("Unreachable UI Automation node");
    // Explicit direct-child grids only. Suppress unsupported metadata instead
    // of synthesizing roles, empty cells, or coordinates from visual geometry.
    for (auto &[id, entry] : replacement) {
        if (!entry.node.grid) continue;
        const auto grid = *entry.node.grid;
        const auto anchors = static_cast<int>(entry.node.children.size());
        bool valid = grid.nonvirtual_subtree && grid.rows >= 0 && grid.columns >= 0 && grid.rows <= 256 && grid.columns <= 256 &&
            (grid.columns == 0 || grid.rows <= 256 / grid.columns) && grid.item_count >= -1 &&
            grid.important_item_count >= -1 && (grid.item_count == -1 || grid.item_count == anchors) &&
            (grid.important_item_count == -1 || grid.important_item_count == anchors);
        std::array<bool, 256> covered{};
        if (valid) for (const auto child : entry.node.children) {
            const auto &metadata = replacement.at(child).node.grid_item;
            if (!metadata || metadata->owner != id) { valid = false; break; }
            const auto &item = *metadata;
            if (item.row < 0 || item.column < 0 || item.row_span <= 0 || item.column_span <= 0 ||
                item.row >= grid.rows || item.column >= grid.columns ||
                item.row_span > grid.rows - item.row || item.column_span > grid.columns - item.column) {
                valid = false; break;
            }
            for (int row = item.row; row < item.row + item.row_span; ++row)
                for (int column = item.column; column < item.column + item.column_span; ++column) {
                    auto &cell = covered[static_cast<std::size_t>(row * grid.columns + column)];
                    if (cell) valid = false;
                    cell = true;
                }
        }
        bool holes = false;
        if (valid) for (int cell = 0; cell < grid.rows * grid.columns; ++cell)
            if (!covered[static_cast<std::size_t>(cell)]) holes = true;
        // A complete nonvirtual subtree plus an exact declared anchor count is
        // positive proof that uncovered coordinates contain no hidden items.
        if (holes && grid.item_count != anchors) valid = false;
        if (!valid) entry.node.grid.reset();
    }
    for (auto &[id, entry] : replacement) {
        if (!entry.node.grid_item) continue;
        const auto owner = replacement.find(entry.node.grid_item->owner);
        if (owner == replacement.end() || !owner->second.node.grid || entry.node.parent != owner->first ||
            std::find(owner->second.node.children.begin(), owner->second.node.children.end(), id) == owner->second.node.children.end())
            entry.node.grid_item.reset();
    }
    bool changed = false;
    ComPtr<IRawElementProviderSimple> focus_event;
    struct ToggleEvent {
        ComPtr<IRawElementProviderSimple> provider;
        bool before = false, after = false;
    };
    std::vector<ToggleEvent> toggle_events;
    struct NameEvent {
        ComPtr<IRawElementProviderSimple> provider;
        std::u16string before, after;
        PROPERTYID property = UIA_NamePropertyId;
    };
    std::vector<NameEvent> name_events;
    struct TextEvent {
        ComPtr<IRawElementProviderSimple> provider;
        bool text = false, selection = false;
    };
    std::vector<TextEvent> text_events;
    struct ScrollEvent {
        ComPtr<IRawElementProviderSimple> provider;
        double before_percent = 0, after_percent = 0, before_size = 0, after_size = 0;
        bool before_scrollable = false, after_scrollable = false;
    };
    std::vector<ScrollEvent> scroll_events;
    struct GridEvent {
        ComPtr<IRawElementProviderSimple> provider, before_owner, after_owner;
        PROPERTYID property = 0;
        std::optional<int> before, after;
        bool boolean = false;
    };
    std::vector<GridEvent> grid_events;
    {
        std::lock_guard lock(impl_->state->mutex);
        auto &state = *impl_->state;
        if (!state.connected) return result;
        if (state.terminal && (snapshot.content || !snapshot.nodes.empty() || snapshot.active))
            return result;
        auto next_serial = state.next_serial;
        auto next_grid_shape = state.next_grid_shape;
        std::uint64_t previous_focus = 0;
        if (state.active)
            for (const auto &[id, entry] : state.nodes)
                if (entry.node.focused) { previous_focus = id; break; }
        changed = state.content != snapshot.content || state.nodes.size() != replacement.size() ||
                  state.active != snapshot.active || state.foreground != snapshot.foreground ||
                  state.name != snapshot.name || !same_rectangle(state.bounds, snapshot.bounds);
        if (state.name != snapshot.name)
            name_events.push_back({impl_->root, state.name, snapshot.name});
        // Assign identities in tree order, before creating event providers.
        // Owner binding history survives temporary unknown metadata, preventing
        // an old item provider from redirecting to a different grid incarnation.
        auto new_serial = [&] {
            if (next_serial == std::numeric_limits<std::uint64_t>::max())
                throw std::overflow_error("UI Automation element identity exhausted");
            return next_serial++;
        };
        pending.clear();
        if (snapshot.content) pending.push_back(snapshot.content);
        while (!pending.empty()) {
            const auto id = pending.back(); pending.pop_back();
            auto &entry = replacement.at(id);
            const auto old = state.nodes.find(id);
            if (old != state.nodes.end() && !old->second.text_retired) {
                entry.serial = old->second.serial;
                entry.grid_owner = old->second.grid_owner;
                entry.grid_owner_serial = old->second.grid_owner_serial;
            } else entry.serial = new_serial();
            if (entry.node.grid_item) {
                const auto owner = entry.node.grid_item->owner;
                const auto owner_serial = replacement.at(owner).serial;
                if (entry.grid_owner && (entry.grid_owner != owner || entry.grid_owner_serial != owner_serial)) {
                    entry.serial = new_serial();
                    changed = true;
                }
                entry.grid_owner = owner;
                entry.grid_owner_serial = owner_serial;
            }
            pending.insert(pending.end(), entry.node.children.begin(), entry.node.children.end());
        }
        for (auto &[id, entry] : replacement) {
            if (!entry.node.grid) continue;
            auto projection = std::make_shared<GridProjection>();
            projection->metadata = *entry.node.grid;
            projection->owner_serial = entry.serial;
            const auto rows = projection->metadata.rows, columns = projection->metadata.columns;
            projection->cells.resize(static_cast<std::size_t>(rows * columns));
            for (int row = 0; row < rows; ++row)
                for (int column = 0; column < columns; ++column)
                    projection->cells[static_cast<std::size_t>(row * columns + column)] = {0, 0, row, column};
            for (const auto child : entry.node.children) {
                const auto &cell = replacement.at(child);
                const auto &metadata = *cell.node.grid_item;
                const GridCell reference{child, cell.serial, metadata.row, metadata.column};
                for (int row = metadata.row; row < metadata.row + metadata.row_span; ++row)
                    for (int column = metadata.column; column < metadata.column + metadata.column_span; ++column)
                        projection->cells[static_cast<std::size_t>(row * columns + column)] = reference;
            }
            // The fragment tree contains each real spanning anchor once, plus
            // each independently proven logical empty coordinate in row order.
            for (std::size_t index = 0; index < projection->cells.size(); ++index) {
                const auto &cell = projection->cells[index];
                if (!cell.view || index == static_cast<std::size_t>(cell.row * columns + cell.column))
                    projection->children.push_back(cell);
            }
            const auto old = state.nodes.find(id);
            if (old != state.nodes.end() && old->second.grid_projection &&
                old->second.grid_projection->metadata.rows == projection->metadata.rows &&
                old->second.grid_projection->metadata.columns == projection->metadata.columns &&
                old->second.grid_projection->metadata.item_count == projection->metadata.item_count &&
                old->second.grid_projection->metadata.important_item_count == projection->metadata.important_item_count &&
                old->second.grid_projection->metadata.nonvirtual_subtree == projection->metadata.nonvirtual_subtree &&
                old->second.grid_projection->owner_serial == projection->owner_serial &&
                old->second.grid_projection->cells == projection->cells) {
                projection->shape_epoch = old->second.grid_projection->shape_epoch;
            } else {
                if (next_grid_shape == UINT64_MAX) throw std::overflow_error("UI Automation grid shape identity exhausted");
                projection->shape_epoch = next_grid_shape++;
                changed = true;
            }
            entry.grid_projection = std::move(projection);
        }
        for (auto &[id, entry] : replacement) {
            const auto found = state.nodes.find(id);
            if (found != state.nodes.end() && !found->second.text_retired) {
                entry.text_edit_attempted_revision = found->second.text_edit_attempted_revision;
                // Historical TextEdit payloads belong to this surviving View
                // lifetime. A backing-buffer swap alone does not consume them.
                const auto &old = found->second.node;
                const auto &current = found->second.current();
                if (entry.node.text_buffer_revision < current.text_buffer_revision ||
                    entry.node.text_event_revision < current.text_event_revision ||
                    (current.text_buffer_revision == entry.node.text_buffer_revision &&
                     entry.node.text_mutation_base_revision < current.text_mutation_base_revision))
                    throw std::invalid_argument("UI Automation text mutation history regressed");
                if (current.text_buffer_revision == entry.node.text_buffer_revision &&
                    current.text_event_revision == entry.node.text_event_revision && current.value != entry.node.value)
                    throw std::invalid_argument("UI Automation text changed without a commit revision");
                if (old.name != entry.node.name) {
                    NameEvent event;
                    event.provider.Attach(static_cast<IRawElementProviderSimple *>(new Provider(impl_->state, id, entry.serial)));
                    event.before = old.name;
                    event.after = entry.node.name;
                    name_events.push_back(std::move(event));
                }
                if (old.kind == AccessibilityKind::edit_text && entry.node.kind == AccessibilityKind::edit_text && old.value != entry.node.value) {
                    NameEvent event;
                    event.provider.Attach(static_cast<IRawElementProviderSimple *>(new Provider(impl_->state, id, entry.serial)));
                    event.before = old.value;
                    event.after = entry.node.value;
                    event.property = UIA_ValueValuePropertyId;
                    name_events.push_back(std::move(event));
                }
                if (shaped_text(old) && shaped_text(entry.node)) {
                    const bool text_changed = old.text_event_revision != entry.node.text_event_revision ||
                                              old.value != entry.node.value;
                    const bool selection_changed = old.selection_event_revision != entry.node.selection_event_revision ||
                        old.selection_start != entry.node.selection_start || old.selection_end != entry.node.selection_end;
                    if (text_changed || selection_changed) {
                        TextEvent event;
                        event.provider.Attach(static_cast<IRawElementProviderSimple *>(new Provider(impl_->state, id, entry.serial)));
                        event.text = text_changed; event.selection = selection_changed;
                        text_events.push_back(std::move(event));
                    }
                }
                if (old.toggleable && entry.node.toggleable && old.checked != entry.node.checked) {
                    ToggleEvent event;
                    event.provider.Attach(static_cast<IRawElementProviderSimple *>(new Provider(impl_->state, id, entry.serial)));
                    event.before = old.checked;
                    event.after = entry.node.checked;
                    toggle_events.push_back(std::move(event));
                }
                if (old.scrollable && entry.node.scrollable &&
                    (old.scroll_y != entry.node.scroll_y || old.scroll_range_y != entry.node.scroll_range_y ||
                     old.scroll_viewport_y != entry.node.scroll_viewport_y)) {
                    ScrollEvent event;
                    event.provider.Attach(static_cast<IRawElementProviderSimple *>(new Provider(impl_->state, id, entry.serial)));
                    event.before_percent = vertical_percent(old);
                    event.after_percent = vertical_percent(entry.node);
                    event.before_size = vertical_view_size(old);
                    event.after_size = vertical_view_size(entry.node);
                    event.before_scrollable = old.scroll_range_y > 0;
                    event.after_scrollable = entry.node.scroll_range_y > 0;
                    scroll_events.push_back(std::move(event));
                }
                changed = changed || old.parent != entry.node.parent || old.children != entry.node.children ||
                          old.name != entry.node.name || old.enabled != entry.node.enabled || old.focused != entry.node.focused ||
                          old.value != entry.node.value || old.text_layout != entry.node.text_layout ||
                          old.text_origin.x != entry.node.text_origin.x || old.text_origin.y != entry.node.text_origin.y ||
                          !same_rectangle(old.text_clip, entry.node.text_clip) ||
                          old.invokable != entry.node.invokable || old.focusable != entry.node.focusable || old.kind != entry.node.kind ||
                          old.toggleable != entry.node.toggleable || old.checked != entry.node.checked ||
                          old.scrollable != entry.node.scrollable || old.scroll_y != entry.node.scroll_y ||
                          old.scroll_range_y != entry.node.scroll_range_y || old.scroll_viewport_y != entry.node.scroll_viewport_y ||
                          old.offscreen != entry.node.offscreen || !same_rectangle(old.bounds, entry.node.bounds);
            } else {
                // Newly exposed providers start at their current history. Past
                // records never replay when a listener or fragment appears.
                entry.text_edit_attempted_revision = entry.node.text_edit_event_revision;
                changed = true;
            }
            if (entry.node.kind == AccessibilityKind::edit_text) {
                if (found != state.nodes.end() && found->second.document &&
                    found->second.document->buffer_revision == entry.node.text_buffer_revision &&
                    found->second.document->text_revision == entry.node.text_event_revision)
                    entry.document = found->second.document;
                else entry.document = std::make_shared<const RangeDocument>(RangeDocument{
                    entry.node.text_buffer_revision, entry.node.text_event_revision, entry.node.value});
            }
        }
        for (const auto &[id, entry] : replacement) {
            const auto found = state.nodes.find(id);
            if (found == state.nodes.end()) continue;
            const auto &old_entry = found->second;
            const auto &old = old_entry.node;
            const auto &now = entry.node;
            const auto property = [&](PROPERTYID property_id, std::optional<int> before,
                                      std::optional<int> after, bool boolean = false) {
                if (before == after) return;
                GridEvent event;
                event.provider.Attach(static_cast<IRawElementProviderSimple *>(new Provider(impl_->state, id, entry.serial)));
                event.property = property_id; event.before = before; event.after = after; event.boolean = boolean;
                grid_events.push_back(std::move(event));
                changed = true;
            };
            property(UIA_IsGridPatternAvailablePropertyId, old.grid.has_value(), now.grid.has_value(), true);
            property(UIA_IsGridItemPatternAvailablePropertyId, old.grid_item.has_value(), now.grid_item.has_value(), true);
            property(UIA_GridRowCountPropertyId, old.grid ? std::optional<int>(old.grid->rows) : std::nullopt,
                     now.grid ? std::optional<int>(now.grid->rows) : std::nullopt);
            property(UIA_GridColumnCountPropertyId, old.grid ? std::optional<int>(old.grid->columns) : std::nullopt,
                     now.grid ? std::optional<int>(now.grid->columns) : std::nullopt);
            const auto item_property = [&](PROPERTYID property_id, int AccessibilityGridItem::*member) {
                property(property_id, old.grid_item ? std::optional<int>((*old.grid_item).*member) : std::nullopt,
                         now.grid_item ? std::optional<int>((*now.grid_item).*member) : std::nullopt);
            };
            item_property(UIA_GridItemRowPropertyId, &AccessibilityGridItem::row);
            item_property(UIA_GridItemColumnPropertyId, &AccessibilityGridItem::column);
            item_property(UIA_GridItemRowSpanPropertyId, &AccessibilityGridItem::row_span);
            item_property(UIA_GridItemColumnSpanPropertyId, &AccessibilityGridItem::column_span);
            if (old.grid_item.has_value() != now.grid_item.has_value() ||
                (old.grid_item && now.grid_item && (old.grid_item->owner != now.grid_item->owner ||
                    old_entry.grid_owner_serial != entry.grid_owner_serial))) {
                GridEvent event;
                event.provider.Attach(static_cast<IRawElementProviderSimple *>(new Provider(impl_->state, id, entry.serial)));
                event.property = UIA_GridItemContainingGridPropertyId;
                if (old.grid_item) event.before_owner.Attach(static_cast<IRawElementProviderSimple *>(
                    new Provider(impl_->state, old.grid_item->owner, old_entry.grid_owner_serial)));
                if (now.grid_item) event.after_owner.Attach(static_cast<IRawElementProviderSimple *>(
                    new Provider(impl_->state, now.grid_item->owner, entry.grid_owner_serial)));
                grid_events.push_back(std::move(event));
                changed = true;
            }
        }
        // Prepare a bounded ordered queue before committing any state. A nested
        // publication appends after these facts; no COM callback holds the lock.
        auto prepared_selection_queue = impl_->selection_delivery;
        constexpr std::size_t maximum_selection_deliveries = 4096;
        const auto selection_event = [&](std::uint64_t id, std::uint64_t serial, PROPERTYID property_id,
                                         EVENTID event_id, bool before = false, bool after = false) {
            if (prepared_selection_queue.size() == maximum_selection_deliveries) throw RangeQuota{};
            Impl::SelectionDelivery event;
            event.provider.Attach(static_cast<IRawElementProviderSimple *>(new Provider(impl_->state, id, serial)));
            event.property = property_id; event.event = event_id; event.before = before; event.after = after;
            const auto current = replacement.find(id), previous = state.nodes.find(id);
            if (current != replacement.end() && current->second.node.grid_item)
                event.owner = current->second.node.grid_item->owner;
            else if (previous != state.nodes.end() && previous->second.node.grid_item)
                event.owner = previous->second.node.grid_item->owner;
            else event.owner = id;
            if (property_id == UIA_IsSelectionPatternAvailablePropertyId ||
                property_id == UIA_SelectionCanSelectMultiplePropertyId || property_id == UIA_SelectionIsSelectionRequiredPropertyId ||
                event_id == UIA_Selection_InvalidatedEventId)
                event.owner = id;
            prepared_selection_queue.push_back(std::move(event));
        };
        std::map<std::uint64_t, bool> selection_ids;
        for (const auto &[id, entry] : state.nodes) { (void)entry; selection_ids.emplace(id, true); }
        for (const auto &[id, entry] : replacement) { (void)entry; selection_ids.emplace(id, true); }
        using SelectedIdentity = std::pair<std::uint64_t, std::uint64_t>;
        const auto selected_items = [](const std::map<std::uint64_t, Entry> &nodes, std::uint64_t id) {
            std::vector<SelectedIdentity> selected;
            for (const auto child : nodes.at(id).node.children) {
                const auto &entry = nodes.at(child);
                if (entry.node.grid_item->selected) selected.emplace_back(child, entry.serial);
            }
            std::sort(selected.begin(), selected.end());
            return selected;
        };
        for (const auto &[id, unused] : selection_ids) {
            (void)unused;
            const auto old = state.nodes.find(id), now = replacement.find(id);
            const bool parent_before = available_selection_nodes(state.nodes, id);
            const bool parent_after = available_selection_nodes(replacement, id);
            const bool item_before = available_selection_item_nodes(state.nodes, id);
            const bool item_after = available_selection_item_nodes(replacement, id);
            const auto serial = now != replacement.end() ? now->second.serial : old->second.serial;
            const auto before_status = collection_item_status(state.nodes, id);
            const auto after_status = collection_item_status(replacement, id);
            if (before_status != after_status) {
                NameEvent event;
                event.provider.Attach(static_cast<IRawElementProviderSimple *>(new Provider(impl_->state, id, serial)));
                event.property = UIA_ItemStatusPropertyId; event.before = before_status; event.after = after_status;
                name_events.push_back(std::move(event));
            }
            if (parent_before != parent_after)
                selection_event(id, serial, UIA_IsSelectionPatternAvailablePropertyId, 0, parent_before, parent_after);
            if (item_before != item_after)
                selection_event(id, serial, UIA_IsSelectionItemPatternAvailablePropertyId, 0, item_before, item_after);
            if (item_before && item_after && old->second.serial == now->second.serial &&
                old->second.grid_owner == now->second.grid_owner && old->second.grid_owner_serial == now->second.grid_owner_serial &&
                old->second.node.grid_item->selected != now->second.node.grid_item->selected)
                selection_event(id, serial, UIA_SelectionItemIsSelectedPropertyId, 0,
                    old->second.node.grid_item->selected, now->second.node.grid_item->selected);
            if (!parent_after) continue; // No Selection events while the full pattern is unavailable.
            if (parent_before && old->second.node.grid->selection_required.has_value() &&
                now->second.node.grid->selection_required.has_value() &&
                old->second.node.grid->selection_required != now->second.node.grid->selection_required)
                selection_event(id, serial, UIA_SelectionIsSelectionRequiredPropertyId, 0,
                    *old->second.node.grid->selection_required, *now->second.node.grid->selection_required);
            if (parent_before && parent_after &&
                (old->second.node.grid->selection_mode == 2) != (now->second.node.grid->selection_mode == 2))
                selection_event(id, serial, UIA_SelectionCanSelectMultiplePropertyId, 0,
                    old->second.node.grid->selection_mode == 2, now->second.node.grid->selection_mode == 2);
            if (!parent_before || !parent_after || old->second.serial != now->second.serial ||
                old->second.grid_projection->shape_epoch != now->second.grid_projection->shape_epoch) {
                selection_event(id, serial, 0, UIA_Selection_InvalidatedEventId);
                continue; // Unknown/lifetime state never invents item-selected transitions.
            }
            const auto before = selected_items(state.nodes, id), after = selected_items(replacement, id);
            if (before == after) continue;
            if (after.size() == 1) {
                selection_event(after.front().first, after.front().second, 0, UIA_SelectionItem_ElementSelectedEventId);
            } else {
                for (const auto &selected : before)
                    if (!std::binary_search(after.begin(), after.end(), selected))
                        selection_event(selected.first, selected.second, 0, UIA_SelectionItem_ElementRemovedFromSelectionEventId);
                for (const auto &selected : after)
                    if (!std::binary_search(before.begin(), before.end(), selected))
                        selection_event(selected.first, selected.second, 0, UIA_SelectionItem_ElementAddedToSelectionEventId);
            }
        }
        auto prepared_text_edits = impl_->prepare_text_edits(replacement, text_edits, text_edit_gaps, result);
        struct AnchorUpdate {
            std::shared_ptr<RangeAnchor> anchor;
            std::shared_ptr<const RangeDocument> document;
            std::int32_t start = 0, end = 0;
            bool retired = false;
        };
        std::vector<AnchorUpdate> anchor_updates;
        anchor_updates.reserve(state.range_anchors.size());
        for (const auto &registration : state.range_anchors) {
            auto anchor = registration.lock();
            if (!anchor || anchor->retired) continue;
            AnchorUpdate update;
            update.anchor = std::move(anchor);
            update.start = update.anchor->start; update.end = update.anchor->end;
            const auto found = replacement.find(update.anchor->view);
            update.retired = found == replacement.end() || found->second.serial != update.anchor->serial ||
                found->second.node.kind != AccessibilityKind::edit_text ||
                !TextRange::rebase_anchor(*update.anchor, found->second.node, update.start, update.end);
            if (!update.retired) update.document = found->second.document;
            else { update.start = update.anchor->start; update.end = update.anchor->end; }
            anchor_updates.push_back(std::move(update));
        }
        if (snapshot.active)
            for (const auto &[id, entry] : replacement)
                if (entry.node.focused) {
                    if (id != previous_focus)
                        focus_event.Attach(static_cast<IRawElementProviderSimple *>(new Provider(impl_->state, id, entry.serial)));
                    break;
                }
        auto prepared_text_queue = impl_->prepare_text_edit_queue(prepared_text_edits, result);
        if (snapshot.active && !state.actions.empty()) post_action_wake(state);
        // All allocations and validation precede this snapshot/anchor commit.
        // No callbacks or destructor-side registry locks occur here.
        state.name = std::move(snapshot.name);
        state.bounds = snapshot.bounds;
        state.content = snapshot.content;
        state.active = snapshot.active;
        state.actions_suspended = state.terminal;
        state.foreground = snapshot.foreground;
        state.nodes = std::move(replacement);
        impl_->commit_text_edits(state.nodes, prepared_text_edits, prepared_text_queue);
        impl_->selection_delivery.swap(prepared_selection_queue);
        state.next_serial = next_serial;
        state.next_grid_shape = next_grid_shape;
        for (auto &update : anchor_updates) {
            update.anchor->start = update.start; update.anchor->end = update.end;
            update.anchor->retired = update.retired;
            update.anchor->document = std::move(update.document); // Retirement releases old private text.
        }
        std::erase_if(state.range_anchors, [](const auto &anchor) { return anchor.expired(); });
        if (!state.active) state.actions.clear();
    }
    // Worker journal revisions preserve composition-before-target ordering.
    // UIA can synchronously query a provider while receiving an event. Never
    // hold the snapshot lock across a call into UIAutomationCore.
    if (changed && UiaClientsAreListening())
        (void)UiaRaiseStructureChangedEvent(impl_->root.Get(), StructureChangeType_ChildrenInvalidated, nullptr, 0);
    if (focus_event && UiaClientsAreListening())
        (void)UiaRaiseAutomationEvent(focus_event.Get(), UIA_AutomationFocusChangedEventId);
    if (UiaClientsAreListening())
        for (const auto &event : name_events) {
            VARIANT before{}, after{};
            if (SUCCEEDED(text_variant(&before, event.before)) &&
                SUCCEEDED(text_variant(&after, event.after)))
                (void)UiaRaiseAutomationPropertyChangedEvent(event.provider.Get(), event.property, before, after);
            VariantClear(&before);
            VariantClear(&after);
        }
    if (UiaClientsAreListening())
        for (const auto &event : text_events) {
            // Coalesced publication events still observe equal-value edits via
            // per-View revisions. No COM client callback runs under state lock.
            if (event.text) (void)UiaRaiseAutomationEvent(event.provider.Get(), UIA_Text_TextChangedEventId);
            if (event.selection) (void)UiaRaiseAutomationEvent(event.provider.Get(), UIA_Text_TextSelectionChangedEventId);
        }
    if (UiaClientsAreListening())
        for (const auto &event : scroll_events) {
            const auto changed_double = [&](PROPERTYID property, double old_value, double new_value) {
                if (old_value == new_value) return;
                VARIANT before{}, after{};
                before.vt = after.vt = VT_R8;
                before.dblVal = old_value;
                after.dblVal = new_value;
                (void)UiaRaiseAutomationPropertyChangedEvent(event.provider.Get(), property, before, after);
            };
            changed_double(UIA_ScrollVerticalScrollPercentPropertyId, event.before_percent, event.after_percent);
            changed_double(UIA_ScrollVerticalViewSizePropertyId, event.before_size, event.after_size);
            if (event.before_scrollable != event.after_scrollable) {
                VARIANT before{}, after{};
                boolean(&before, event.before_scrollable);
                boolean(&after, event.after_scrollable);
                (void)UiaRaiseAutomationPropertyChangedEvent(event.provider.Get(), UIA_ScrollVerticallyScrollablePropertyId,
                                                            before, after);
            }
        }
    if (UiaClientsAreListening())
        for (const auto &event : toggle_events) {
            VARIANT before{}, after{};
            before.vt = after.vt = VT_I4;
            before.lVal = event.before ? ToggleState_On : ToggleState_Off;
            after.lVal = event.after ? ToggleState_On : ToggleState_Off;
            (void)UiaRaiseAutomationPropertyChangedEvent(event.provider.Get(), UIA_ToggleToggleStatePropertyId,
                                                        before, after);
        }
    if (UiaClientsAreListening())
        for (const auto &event : grid_events) {
            {
                std::lock_guard lock(impl_->state->mutex);
                if (!impl_->state->connected || impl_->state->terminal) break;
            }
            VARIANT before{}, after{};
            const auto value = [&](VARIANT &output, const std::optional<int> &number,
                                   const ComPtr<IRawElementProviderSimple> &owner) {
                if (event.property == UIA_GridItemContainingGridPropertyId) {
                    if (owner) { output.vt = VT_UNKNOWN; output.punkVal = owner.Get(); output.punkVal->AddRef(); }
                } else if (number) {
                    output.vt = static_cast<VARTYPE>(event.boolean ? VT_BOOL : VT_I4);
                    if (event.boolean) output.boolVal = *number ? VARIANT_TRUE : VARIANT_FALSE;
                    else output.lVal = *number;
                }
            };
            value(before, event.before, event.before_owner);
            value(after, event.after, event.after_owner);
            (void)UiaRaiseAutomationPropertyChangedEvent(event.provider.Get(), event.property, before, after);
            VariantClear(&before); VariantClear(&after);
        }
    impl_->drain_selection();
    impl_->drain_text_edits(result);
    return result;
}
LRESULT WindowAccessibility::object(WPARAM wp, LPARAM lp) {
    HWND window = nullptr;
    {
        std::lock_guard lock(impl_->state->mutex);
        if (!impl_->state->connected) return 0;
        window = impl_->state->window;
    }
    return UiaReturnRawElementProvider(window, wp, lp, impl_->root.Get());
}
std::optional<AccessibilityAction> WindowAccessibility::next_action() {
    std::lock_guard lock(impl_->state->mutex);
    auto &state = *impl_->state;
    const auto take_action = [&]() -> std::optional<AccessibilityAction> {
        // A wake consumed while suspended leaves the queue intact. Drain its
        // remaining requests with new asynchronous wakes, consuming each once.
        // A notification failure must not remove the still-unsubmitted action.
        if (state.actions.size() > 1) post_action_wake(state);
        auto action = std::move(state.actions.front().action);
        state.actions.pop_front();
        return action;
    };
    while (state.connected && state.active && !state.actions_suspended && !state.actions.empty()) {
        const auto &request = state.actions.front();
        const auto found = state.nodes.find(request.action.view);
        if (found == state.nodes.end() || found->second.serial != request.serial || found->second.text_retired ||
            !found->second.current().enabled) { state.actions.pop_front(); continue; }
        const auto &node = found->second.current();
        const auto &action = request.action;
        if (action.kind == AccessibilityActionKind::collection_selection) {
            if (available_selection_item(state, action.view) && found->second.node.grid_item &&
                found->second.node.grid_item->owner == action.collection_owner && state.foreground && !node.offscreen) {
                const auto &owner = state.nodes.at(action.collection_owner);
                if (owner.serial == request.collection_owner_serial && owner.grid_projection->shape_epoch == request.collection_shape &&
                    owner.node.grid->metadata_revision == action.expected_metadata_revision &&
                    owner.node.source_view_revision == action.expected_view_revision) return take_action();
            }
            state.actions.pop_front();
            continue;
        }
        if (action.kind == AccessibilityActionKind::reveal_text_range) {
            if (shaped_text(node) && node.text_can_scroll && node.value == action.expected_text &&
                node.source_view_revision == action.expected_view_revision && std::isfinite(action.range_top) &&
                std::isfinite(action.range_bottom) && action.range_top >= 0 && action.range_bottom >= action.range_top &&
                action.range_bottom <= 32768) return take_action();
            state.actions.pop_front();
            continue; // Revealing offscreen text is allowed; ordinary actions still require visibility.
        }
        if (node.offscreen) { state.actions.pop_front(); continue; }
        const bool allowed = action.kind == AccessibilityActionKind::invoke ? node.invokable
            : action.kind == AccessibilityActionKind::toggle ? node.toggleable
            : action.kind == AccessibilityActionKind::set_selection
                ? node.kind == AccessibilityKind::edit_text && state.foreground && node.value == action.expected_text &&
                  action.expected_buffer_revision && node.text_buffer_revision == action.expected_buffer_revision &&
                  node.text_event_revision == action.expected_text_revision &&
                  action.caret_offset >= 0 && action.selection_end >= action.caret_offset &&
                  static_cast<std::size_t>(action.selection_end) <= node.value.size() &&
                  contiguous_selection(node, action.caret_offset, action.selection_end, action.selection_operation)
            : action.kind == AccessibilityActionKind::replace_text ? node.kind == AccessibilityKind::edit_text
            : action.kind == AccessibilityActionKind::scroll || action.kind == AccessibilityActionKind::set_scroll_percent
                ? node.scrollable && node.scroll_range_y > 0 && node.scroll_viewport_y > 0
            : action.kind == AccessibilityActionKind::focus && node.focusable && state.foreground;
        if (allowed) return take_action();
        state.actions.pop_front();
    }
    return {};
}
void WindowAccessibility::retire_for_terminal() {
    const auto state = impl_->state;
    if (GetCurrentThreadId() != state->owner || impl_->delivering_text_edits)
        throw std::logic_error("Terminal projection requires an idle UI owner");
    AccessibilitySnapshot retired;
    {
        std::lock_guard lock(state->mutex);
        if (!state->connected || state->terminal) return;
        retired.name = state->name;
        retired.bounds = state->bounds;
        state->terminal = true;
        state->active = false;
        state->actions_suspended = true;
        state->actions.clear();
        impl_->text_edit_delivery.clear();
        impl_->selection_delivery.clear();
        impl_->text_edit_units = 0;
    }
    // No final guest values are guessed during unwind. A retained provider can
    // identify a historical activation, while dynamic queries are unavailable.
    (void)publish(std::move(retired));
}
std::shared_ptr<AccessibilityInvocation> WindowAccessibility::capture_invocation(std::uint64_t view) {
    const auto state = impl_->state;
    if (GetCurrentThreadId() != state->owner)
        throw std::logic_error("Activation capture requires the UI owner");
    std::lock_guard lock(state->mutex);
    const auto found = state->nodes.find(view);
    if (!state->connected || !state->window || !view || found == state->nodes.end() ||
        !found->second.node.invokable || found->second.node.toggleable) return {};
    ComPtr<IRawElementProviderSimple> provider;
    provider.Attach(static_cast<IRawElementProviderSimple *>(new Provider(state, view, found->second.serial)));
    return std::make_shared<AccessibilityInvocation>(state, provider.Get(), view, found->second.serial);
}
HRESULT WindowAccessibility::complete_invoke(const std::shared_ptr<AccessibilityInvocation> &invocation,
                                            bool handled) noexcept {
    if (!invocation) return S_FALSE;
    const auto state = impl_->state;
    if (GetCurrentThreadId() != state->owner) return RPC_E_WRONG_THREAD;
    Microsoft::WRL::ComPtr<IRawElementProviderSimple> provider;
    HWND window = nullptr;
    try {
        {
            std::lock_guard lock(state->mutex);
            if (invocation->connection.get() != state.get() || invocation->consumed) return S_FALSE;
            invocation->consumed = true; // Consume before native callbacks or reentrant publication.
            if (!handled || !state->connected || !state->window || !invocation->view || !invocation->serial)
                return S_FALSE;
            provider = invocation->provider;
            window = state->window;
        }
        // Never look up the View again here. A real successful activation may
        // remove, disable or replace it; the retained original provider/serial
        // must not be replaced by whichever node is published under that ID.
        if (!provider || !IsWindow(window)) return S_FALSE;
        // Keep all required state local across COM reentry, including window
        // disconnection/destruction. Neither the receipt nor event is retried.
        return UiaRaiseAutomationEvent(provider.Get(), UIA_Invoke_InvokedEventId);
    } catch (...) { return E_UNEXPECTED; }
}
void WindowAccessibility::disconnect() noexcept {
    if (!impl_) return;
    try {
        {
            std::lock_guard lock(impl_->state->mutex);
            if (!impl_->state->connected) return;
            impl_->state->connected = false;
            impl_->state->window = nullptr;
            for (const auto &registration : impl_->state->range_anchors)
                if (const auto anchor = registration.lock()) {
                    anchor->retired = true;
                    anchor->document.reset();
                }
            impl_->state->range_anchors.clear();
            impl_->state->nodes.clear();
            impl_->state->actions.clear();
            impl_->selection_delivery.clear();
        }
        (void)UiaDisconnectProvider(impl_->root.Get());
    } catch (...) { }
}
void WindowAccessibility::suspend() noexcept {
    try {
        std::lock_guard lock(impl_->state->mutex);
        impl_->state->actions_suspended = true;
        // Geometry acknowledgement alone does not cancel a user request.
        // Full publication rearms delivery and rechecks each retained identity;
        // genuine inactive publication and disconnect still clear the queue.
    } catch (...) { }
}
} // namespace aether::host
