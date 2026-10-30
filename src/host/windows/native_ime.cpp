#include "aether/host/windows/native_ime.hpp"
#include "aether/apk/inspect.hpp"
#include <imm.h>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace aether::host {
namespace {
constexpr LONG maximum_units = 4096;
constexpr LONG maximum_bytes = maximum_units * 2;
[[noreturn]] void fail(const char *code) { throw std::runtime_error(code); }
struct BorrowedContext {
    HWND window;
    HIMC value = nullptr;
    BorrowedContext(HWND owner, HIMC expected) : window(owner), value(ImmGetContext(owner)) {
        if (!value) fail("AETHER_IME_CONTEXT_UNAVAILABLE");
        if (value != expected) {
            (void)ImmReleaseContext(window, value);
            value = nullptr;
            fail("AETHER_IME_CONTEXT_OWNERSHIP_CHANGED");
        }
    }
    ~BorrowedContext() { if (value) (void)ImmReleaseContext(window, value); }
    BorrowedContext(const BorrowedContext &) = delete;
    BorrowedContext &operator=(const BorrowedContext &) = delete;
};
struct CallScope {
    bool &active;
    explicit CallScope(bool &value) : active(value) { active = true; }
    ~CallScope() { active = false; }
};
bool same_point(const POINT &a, const POINT &b) noexcept { return a.x == b.x && a.y == b.y; }
bool same_rectangle(const RECT &a, const RECT &b) noexcept {
    return a.left == b.left && a.top == b.top && a.right == b.right && a.bottom == b.bottom;
}
void read_error(LONG result) {
    if (result == IMM_ERROR_NODATA) fail("AETHER_IME_READ_NODATA");
    if (result < 0) fail("AETHER_IME_READ_FAILED");
}
std::u16string read_text(HIMC context, DWORD field) {
    static_assert(sizeof(char16_t) == sizeof(WCHAR));
    const auto bytes = ImmGetCompositionStringW(context, field, nullptr, 0);
    read_error(bytes);
    if (bytes > maximum_bytes || (bytes & 1)) fail("AETHER_IME_UTF16_LIMIT");
    std::u16string result(static_cast<std::size_t>(bytes / 2), u'\0');
    // A present empty field is still read a second time: a changed native size
    // must not turn an absent/racing composition into an invented empty value.
    const auto actual = ImmGetCompositionStringW(context, field,
        result.empty() ? nullptr : result.data(), static_cast<DWORD>(bytes));
    read_error(actual);
    if (actual != bytes) fail("AETHER_IME_READ_CHANGED");
    return result;
}
template <class Element> std::vector<Element> read_array(HIMC context, DWORD field, LONG limit) {
    const auto bytes = ImmGetCompositionStringW(context, field, nullptr, 0);
    read_error(bytes);
    if (bytes > limit || bytes % static_cast<LONG>(sizeof(Element))) fail("AETHER_IME_METADATA_LIMIT");
    std::vector<Element> result(static_cast<std::size_t>(bytes) / sizeof(Element));
    const auto actual = ImmGetCompositionStringW(context, field,
        result.empty() ? nullptr : result.data(), static_cast<DWORD>(bytes));
    read_error(actual);
    if (actual != bytes) fail("AETHER_IME_METADATA_CHANGED");
    return result;
}
bool text_boundary(std::u16string_view text, std::size_t position) noexcept {
    return position <= text.size() && (!position || position == text.size() ||
        !(text[position - 1] >= 0xd800 && text[position - 1] <= 0xdbff &&
          text[position] >= 0xdc00 && text[position] <= 0xdfff));
}
std::optional<LONG> read_delta_start(HIMC context) noexcept {
    // GCS_DELTASTART returns a scalar Unicode position, not a buffer size.
    // Optional missing/invalid evidence must not discard valid native text.
    const auto position = ImmGetCompositionStringW(context, GCS_DELTASTART, nullptr, 0);
    if (position <= 0 || position > maximum_units) return {};
    return position;
}
std::string composition_sha256(std::u16string_view text) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(text.size() * 2);
    for (const auto unit : text) {
        bytes.push_back(static_cast<std::uint8_t>(unit & 0xff));
        bytes.push_back(static_cast<std::uint8_t>(unit >> 8));
    }
    return apk::sha256(bytes);
}
NativeImeConversion read_conversion(HIMC context, const std::optional<std::u16string> &announced,
                                    bool clauses_announced) {
    NativeImeConversion result;
    result.composition = announced ? *announced : read_text(context, GCS_COMPSTR);
    // ImmGetCompositionStringW sizes are bytes. Attributes are one BYTE per
    // UTF-16 unit; Unicode clause DWORD values are already UTF-16 positions.
    const auto attributes = read_array<BYTE>(context, GCS_COMPATTR, maximum_units);
    if (attributes.size() != result.composition.size()) fail("AETHER_IME_ATTRIBUTE_LENGTH");
    bool target_ended = false;
    for (std::size_t index = 0; index < attributes.size(); ++index) {
        const auto attribute = attributes[index];
        if (attribute > ATTR_FIXEDCONVERTED) fail("AETHER_IME_ATTRIBUTE_UNSUPPORTED");
        if (!text_boundary(result.composition, index) && attribute != attributes[index - 1])
            fail("AETHER_IME_ATTRIBUTE_SURROGATE");
        const bool target = attribute == ATTR_TARGET_CONVERTED || attribute == ATTR_TARGET_NOTCONVERTED;
        if (target) {
            if (target_ended) fail("AETHER_IME_TARGET_DISJOINT");
            if (result.start < 0) result.start = static_cast<std::int32_t>(index);
            result.end = static_cast<std::int32_t>(index + 1);
        } else if (result.start >= 0) target_ended = true;
    }
    std::vector<DWORD> clauses;
    constexpr LONG clause_limit = (maximum_units + 1) * static_cast<LONG>(sizeof(DWORD));
    if (clauses_announced) {
        clauses = read_array<DWORD>(context, GCS_COMPCLAUSE, clause_limit);
        if (result.composition.empty()) {
            if (clauses.size() > 1 || (!clauses.empty() && clauses.front())) fail("AETHER_IME_CLAUSE_INVALID");
        } else {
            if (clauses.size() < 2 || clauses.front() || clauses.back() != result.composition.size())
                fail("AETHER_IME_CLAUSE_INVALID");
            for (std::size_t index = 1; index < clauses.size(); ++index) {
                const auto first = clauses[index - 1], last = clauses[index];
                if (first >= last || last > result.composition.size() ||
                    !text_boundary(result.composition, first) || !text_boundary(result.composition, last))
                    fail("AETHER_IME_CLAUSE_INVALID");
                for (auto position = first + 1; position < last; ++position)
                    if (attributes[position] != attributes[first]) fail("AETHER_IME_CLAUSE_ATTRIBUTE");
            }
        }
    }
    if ((result.start >= 0 && (!text_boundary(result.composition, static_cast<std::size_t>(result.start)) ||
                              !text_boundary(result.composition, static_cast<std::size_t>(result.end)))) ||
        read_text(context, GCS_COMPSTR) != result.composition ||
        read_array<BYTE>(context, GCS_COMPATTR, maximum_units) != attributes ||
        (clauses_announced && read_array<DWORD>(context, GCS_COMPCLAUSE, clause_limit) != clauses))
        fail("AETHER_IME_METADATA_CHANGED");
    // These bounded consistency reads detect changes; IMM provides no atomic
    // transaction spanning the string, attributes and clause queries.
    return result;
}
} // namespace

struct NativeIme::Impl {
    const HWND window;
    const DWORD thread;
    HIMC owned = nullptr, previous = nullptr;
    bool closing = false, positioning = false, cancelling = false;
    std::optional<std::u16string> previous_composition;
    std::uint64_t continuity_revision = 0;
    bool continuity_disabled = false;
    void advance_continuity() noexcept {
        if (continuity_revision == std::numeric_limits<std::uint64_t>::max()) {
            continuity_disabled = true;
            previous_composition.reset();
        } else ++continuity_revision;
    }
    void reset_continuity() noexcept {
        previous_composition.reset();
        advance_continuity();
    }
    struct Position {
        POINT caret;
        RECT line;
        unsigned mask;
    };
    std::optional<Position> attempted_position;
    explicit Impl(HWND value) : window(value), thread(GetCurrentThreadId()) {
        check_window();
        owned = ImmCreateContext();
        if (!owned) fail("AETHER_IME_CONTEXT_CREATE_FAILED");
        previous = ImmAssociateContext(window, owned);
        try {
            BorrowedContext verification(window, owned);
        } catch (...) {
            cleanup();
            throw;
        }
    }
    ~Impl() noexcept { cleanup(); }
    void check_window() const {
        DWORD process = 0;
        if (closing || !window || !IsWindow(window) || GetCurrentThreadId() != thread ||
            GetWindowThreadProcessId(window, &process) != thread || process != GetCurrentProcessId())
            fail("AETHER_IME_WINDOW_UNAVAILABLE");
    }
    void cleanup() noexcept {
        reset_continuity();
        closing = true;
        const auto retiring = std::exchange(owned, nullptr);
        if (!retiring) return;
        // Only restore our own still-current association. A foreign replacement
        // remains untouched, while the separately owned private context retires.
        const auto current = ImmGetContext(window);
        if (current) (void)ImmReleaseContext(window, current);
        if (current == retiring) (void)ImmAssociateContext(window, previous);
        (void)ImmDestroyContext(retiring);
        previous = nullptr;
    }
};

NativeIme::NativeIme(HWND window) : impl_(std::make_unique<Impl>(window)) {}
NativeIme::~NativeIme() noexcept = default;
void NativeIme::reset_composition_evidence() noexcept { impl_->reset_continuity(); }
NativeImePacket NativeIme::read(LPARAM message_flags) {
    auto &p = *impl_;
    // Nested native reads/cancels invalidate an outer capture without wrapping
    // the generation or refusing an otherwise valid text packet.
    p.advance_continuity();
    try {
        p.check_window();
        BorrowedContext context(p.window, p.owned);
        NativeImePacket result;
        if (!message_flags) {
            p.reset_continuity();
            result.cancel = true;
            return result;
        }
        const auto flags = static_cast<std::uintptr_t>(message_flags);
        if (flags & (CS_INSERTCHAR | CS_NOMOVECARET)) fail("AETHER_IME_INLINE_FLAGS_UNSUPPORTED");
        constexpr std::uintptr_t allowed = GCS_COMPREADSTR | GCS_COMPREADATTR | GCS_COMPREADCLAUSE |
            GCS_COMPSTR | GCS_COMPATTR | GCS_COMPCLAUSE | GCS_CURSORPOS | GCS_DELTASTART |
            GCS_RESULTREADSTR | GCS_RESULTREADCLAUSE | GCS_RESULTSTR | GCS_RESULTCLAUSE;
        if (flags & ~allowed) fail("AETHER_IME_PACKET_FLAGS_UNSUPPORTED");
        constexpr std::uintptr_t result_fields = GCS_RESULTREADSTR | GCS_RESULTREADCLAUSE |
            GCS_RESULTSTR | GCS_RESULTCLAUSE;
        const bool has_result = (flags & result_fields) != 0;
        if (has_result) p.reset_continuity();
        const auto revision = p.continuity_revision;
        auto previous_composition = std::move(p.previous_composition);
        p.previous_composition.reset();
        const bool delta_announced = !has_result && !p.cancelling && !p.continuity_disabled &&
            (flags & GCS_COMPSTR) && (flags & GCS_DELTASTART);
        const auto first_delta = delta_announced ? read_delta_start(context.value) : std::nullopt;
        // A native message may commit one composition and begin another. Preserve
        // result-before-composition capture order; the parent preserves FIFO writes.
        if (flags & GCS_RESULTSTR) result.result = read_text(context.value, GCS_RESULTSTR);
        if (flags & GCS_COMPSTR) result.composition = read_text(context.value, GCS_COMPSTR);
        if (flags & GCS_CURSORPOS) {
            const auto cursor = ImmGetCompositionStringW(context.value, GCS_CURSORPOS, nullptr, 0);
            read_error(cursor);
            if (cursor > maximum_units ||
                (result.composition && static_cast<std::size_t>(cursor) > result.composition->size()))
                fail("AETHER_IME_CURSOR_INVALID");
            result.cursor = static_cast<std::int32_t>(cursor);
        }
        if (flags & (GCS_COMPSTR | GCS_COMPATTR | GCS_COMPCLAUSE)) {
            try {
                result.conversion = read_conversion(context.value, result.composition, (flags & GCS_COMPCLAUSE) != 0);
            } catch (const std::exception &) {
                // Optional projection cannot discard an already captured result or
                // composing edit. Unknown is distinct from authoritative no target.
                p.reset_continuity();
                result.conversion.emplace();
                result.conversion->available = false;
            }
        }
        const auto last_delta = delta_announced ? read_delta_start(context.value) : std::nullopt;
        BorrowedContext verification(p.window, p.owned);
        if (!p.continuity_disabled && !p.cancelling && p.continuity_revision == revision) {
            if (delta_announced && first_delta && first_delta == last_delta && previous_composition &&
                result.composition && result.conversion && result.conversion->available) {
                const auto prefix = static_cast<std::size_t>(*first_delta);
                if (prefix <= previous_composition->size() && prefix <= result.composition->size() &&
                    text_boundary(*previous_composition, prefix) && text_boundary(*result.composition, prefix) &&
                    std::u16string_view(*previous_composition).substr(0, prefix) ==
                        std::u16string_view(*result.composition).substr(0, prefix)) {
                    try {
                        result.conversion->previous_composition_sha256 = composition_sha256(*previous_composition);
                        result.conversion->unchanged_prefix = static_cast<std::int32_t>(prefix);
                    } catch (const std::exception &) {
                        result.conversion->previous_composition_sha256.clear();
                        result.conversion->unchanged_prefix = -1;
                    }
                }
            }
            try {
                if (result.composition) p.previous_composition = *result.composition;
                else if (result.conversion && result.conversion->available)
                    p.previous_composition = result.conversion->composition;
                else p.previous_composition = std::move(previous_composition);
            } catch (const std::exception &) {
                // Retaining optional evidence cannot discard the actual edit.
                p.reset_continuity();
            }
        }
        return result;
    } catch (...) {
        p.reset_continuity();
        throw;
    }
}
void NativeIme::position(POINT client_caret, RECT client_line, unsigned candidate_mask, bool force) {
    auto &p = *impl_;
    if (p.positioning || p.closing) return; // IMN_SETCANDIDATEPOS can reenter this call.
    p.check_window();
    BorrowedContext context(p.window, p.owned);
    if (candidate_mask & ~0x0fu) fail("AETHER_IME_CANDIDATE_INDEX_UNSUPPORTED");
    RECT client{};
    if (!GetClientRect(p.window, &client)) fail("AETHER_IME_POSITION_UNAVAILABLE");
    if (client_line.left > client_line.right || client_line.top >= client_line.bottom ||
        client_line.left < client.left || client_line.right > client.right ||
        client_line.top < client.top || client_line.bottom > client.bottom ||
        client_caret.x < client.left || client_caret.x > client.right ||
        client_caret.y < client.top || client_caret.y > client.bottom)
        fail("AETHER_IME_POSITION_OUTSIDE_CLIENT");
    if (!force && p.attempted_position && p.attempted_position->mask == candidate_mask &&
        same_point(p.attempted_position->caret, client_caret) && same_rectangle(p.attempted_position->line, client_line))
        return;
    // Remember the attempted geometry before native calls. A failed write is
    // not replayed by polling, and synchronous IME notifications cannot recurse.
    p.attempted_position = Impl::Position{client_caret, client_line, candidate_mask};
    CallScope positioning(p.positioning);
    for (unsigned index = 0; index < 4; ++index) {
        if (!(candidate_mask & (1u << index))) continue;
        CANDIDATEFORM form{};
        form.dwIndex = index;
        form.dwStyle = CFS_EXCLUDE;
        form.ptCurrentPos = client_caret;
        form.rcArea = client_line;
        if (!ImmSetCandidateWindow(context.value, &form)) fail("AETHER_IME_CANDIDATE_POSITION_FAILED");
    }
}
void NativeIme::cancel() {
    auto &p = *impl_;
    p.reset_continuity(); // Also invalidate an outer read on a reentrant cancel.
    if (p.cancelling || p.closing) return;
    try {
        p.check_window();
        BorrowedContext context(p.window, p.owned);
        CallScope cancelling(p.cancelling);
        if (!ImmNotifyIME(context.value, NI_COMPOSITIONSTR, CPS_CANCEL, 0)) fail("AETHER_IME_CANCEL_FAILED");
    } catch (...) {
        p.reset_continuity();
        throw;
    }
    p.reset_continuity(); // Synchronous cancellation notifications cannot restore it.
}
} // namespace aether::host
