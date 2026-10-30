#include "aether/host/windows/clipboard_service.hpp"
#include <algorithm>
#include <limits>
#include <new>
#include <utility>

namespace aether::host {
namespace {
struct SharedLock {
    SRWLOCK &value;
    explicit SharedLock(SRWLOCK &lock) noexcept : value(lock) { AcquireSRWLockShared(&value); }
    ~SharedLock() { ReleaseSRWLockShared(&value); }
};
struct ExclusiveLock {
    SRWLOCK &value;
    explicit ExclusiveLock(SRWLOCK &lock) noexcept : value(lock) { AcquireSRWLockExclusive(&value); }
    ~ExclusiveLock() { ReleaseSRWLockExclusive(&value); }
};
struct OpenedClipboard {
    bool open;
    explicit OpenedClipboard(HWND window) noexcept : open(OpenClipboard(window) != FALSE) {}
    ~OpenedClipboard() { if (open) (void)CloseClipboard(); }
    bool close() noexcept {
        if (!std::exchange(open, false)) return false;
        return CloseClipboard() != FALSE; // One release attempt, never a mutation retry.
    }
};
struct GlobalMemory {
    HGLOBAL value = nullptr;
    explicit GlobalMemory(SIZE_T bytes) noexcept : value(GlobalAlloc(GMEM_MOVEABLE, bytes)) {}
    ~GlobalMemory() { if (value) (void)GlobalFree(value); }
};
template <class Function> ClipboardStatus guarded(Function &&function) noexcept {
    try { return function(); }
    catch (const std::bad_alloc &) { return ClipboardStatus::quota; }
    catch (...) { return ClipboardStatus::unavailable; }
}
} // namespace
struct ClipboardWindowContext::Impl {
    const DWORD owner = GetCurrentThreadId(), process = GetCurrentProcessId();
    mutable SRWLOCK mutex = SRWLOCK_INIT;
    HWND window = nullptr;
    std::uint64_t epoch = 1;
    bool exhausted = false, closed = false;
    void advance() noexcept {
        if (epoch == std::numeric_limits<std::uint64_t>::max()) exhausted = true;
        else ++epoch;
    }
    bool owned(HWND candidate) const noexcept {
        DWORD actual_process = 0;
        return candidate && IsWindow(candidate) &&
            GetWindowThreadProcessId(candidate, &actual_process) == owner && actual_process == process &&
            GetAncestor(candidate, GA_ROOT) == candidate;
    }
    bool foreground(HWND candidate) const noexcept {
        if (!owned(candidate) || GetForegroundWindow() != candidate || !IsWindowVisible(candidate) ||
            !IsWindowEnabled(candidate) || IsIconic(candidate)) return false;
        GUITHREADINFO info{sizeof(GUITHREADINFO)};
        return GetGUIThreadInfo(owner, &info) && info.hwndFocus == candidate &&
            !(info.flags & (GUI_INMENUMODE | GUI_POPUPMENUMODE | GUI_SYSTEMMENUMODE));
    }
};
ClipboardWindowContext::ClipboardWindowContext() : impl_(std::make_unique<Impl>()) {}
ClipboardWindowContext::~ClipboardWindowContext() = default;
void ClipboardWindowContext::bind(HWND window) noexcept {
    auto &state = *impl_;
    const bool owned = GetCurrentThreadId() == state.owner && state.owned(window);
    ExclusiveLock lock(state.mutex);
    if (state.closed) return;
    if (owned && !state.exhausted && state.window == window) return;
    state.advance();
    state.window = owned && !state.exhausted ? window : nullptr;
}
void ClipboardWindowContext::retire() noexcept {
    auto &state = *impl_;
    ExclusiveLock lock(state.mutex);
    if (state.closed) return;
    state.window = nullptr;
    state.advance();
}
void ClipboardWindowContext::close() noexcept {
    auto &state = *impl_;
    ExclusiveLock lock(state.mutex);
    if (state.closed) return;
    state.closed = true;
    state.window = nullptr;
    state.advance();
}
ClipboardStatus ClipboardWindowContext::snapshot(HWND &window, std::uint64_t &epoch) const noexcept {
    window = nullptr; epoch = 0;
    const auto &state = *impl_;
    HWND candidate = nullptr;
    std::uint64_t captured = 0;
    {
        SharedLock lock(state.mutex);
        if (state.closed || state.exhausted || !state.window) return ClipboardStatus::denied;
        candidate = state.window; captured = state.epoch;
    }
    // No context lock spans User32, a broker call, or a UI callback.
    if (!state.foreground(candidate)) return ClipboardStatus::denied;
    {
        SharedLock lock(state.mutex);
        if (state.closed || state.exhausted || state.window != candidate || state.epoch != captured) return ClipboardStatus::denied;
    }
    window = candidate; epoch = captured;
    return ClipboardStatus::ok;
}
ClipboardStatus ClipboardWindowContext::check_access(std::uint64_t &epoch) const noexcept {
    HWND window = nullptr;
    return snapshot(window, epoch);
}
HostClipboardService::HostClipboardService(std::shared_ptr<ClipboardWindowContext> context) : context_(std::move(context)) {}
ClipboardStatus HostClipboardService::check_access(std::uint64_t &epoch) noexcept {
    epoch = 0;
    if (GetCurrentThreadId() != owner_) return ClipboardStatus::denied;
    armed_window_ = nullptr; armed_epoch_ = 0;
    if (!context_) return ClipboardStatus::denied;
    const auto result = context_->snapshot(armed_window_, armed_epoch_);
    if (result == ClipboardStatus::ok) epoch = armed_epoch_;
    return result;
}
bool HostClipboardService::current(HWND window, std::uint64_t epoch) const noexcept {
    if (GetCurrentThreadId() != owner_ || !context_ || !window || !epoch) return false;
    HWND actual = nullptr;
    std::uint64_t current_epoch = 0;
    return context_->snapshot(actual, current_epoch) == ClipboardStatus::ok && actual == window && current_epoch == epoch;
}
ClipboardStatus HostClipboardService::consume(HWND &window, std::uint64_t &epoch) noexcept {
    window = nullptr; epoch = 0;
    if (GetCurrentThreadId() != owner_) return ClipboardStatus::denied;
    const auto captured_window = std::exchange(armed_window_, nullptr);
    const auto captured_epoch = std::exchange(armed_epoch_, 0);
    if (!current(captured_window, captured_epoch)) return ClipboardStatus::denied;
    window = captured_window; epoch = captured_epoch;
    return ClipboardStatus::ok;
}
ClipboardStatus HostClipboardService::has_text(bool &value) noexcept {
    value = false;
    HWND window = nullptr;
    std::uint64_t epoch = 0;
    const auto access = consume(window, epoch);
    if (access != ClipboardStatus::ok) return access;
    const bool available = IsClipboardFormatAvailable(CF_UNICODETEXT) != FALSE;
    if (!current(window, epoch)) return ClipboardStatus::denied;
    value = available;
    return ClipboardStatus::ok;
}
ClipboardStatus HostClipboardService::read_text(std::optional<std::u16string> &value) noexcept {
    value.reset();
    return guarded([&] {
        HWND window = nullptr;
        std::uint64_t epoch = 0;
        const auto access = consume(window, epoch);
        if (access != ClipboardStatus::ok) return access;
        OpenedClipboard opened(window);
        if (!opened.open) return ClipboardStatus::unavailable;
        std::optional<std::u16string> selected;
        const auto result = [&] {
            if (!current(window, epoch)) return ClipboardStatus::denied;
            if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) return ClipboardStatus::ok;
            if (!current(window, epoch)) return ClipboardStatus::denied;
            const auto handle = GetClipboardData(CF_UNICODETEXT);
            if (!handle) return ClipboardStatus::unavailable;
            if (!current(window, epoch)) return ClipboardStatus::denied;
            const auto bytes = GlobalSize(handle);
            if (bytes < sizeof(wchar_t)) return ClipboardStatus::invalid;
            if (bytes > 65536) return ClipboardStatus::quota;
            const auto memory = static_cast<const wchar_t *>(GlobalLock(handle));
            if (!memory) return ClipboardStatus::unavailable;
            struct Unlock { HGLOBAL value; ~Unlock() { GlobalUnlock(value); } } unlock{handle};
            const auto available = std::min<std::size_t>(bytes / sizeof(wchar_t), clipboard_text_limit + 1);
            std::size_t length = 0;
            while (length < available && memory[length]) ++length;
            if (length == available || length > clipboard_text_limit) return ClipboardStatus::quota;
            selected.emplace(memory, memory + length);
            if (!valid_drop_text(*selected)) { selected.reset(); return ClipboardStatus::invalid; }
            return ClipboardStatus::ok;
        }();
        const bool closed = opened.close();
        if (result != ClipboardStatus::ok) return result;
        if (!closed) return ClipboardStatus::unavailable;
        if (!current(window, epoch)) return ClipboardStatus::denied;
        value = std::move(selected); // Absent and an actual empty string differ.
        return ClipboardStatus::ok;
    });
}
ClipboardStatus HostClipboardService::write_text(std::u16string_view value) noexcept {
    return guarded([&] {
        HWND window = nullptr;
        std::uint64_t epoch = 0;
        const auto access = consume(window, epoch);
        if (access != ClipboardStatus::ok) return access;
        if (!valid_drop_text(value)) return value.size() > clipboard_text_limit ? ClipboardStatus::quota : ClipboardStatus::invalid;
        GlobalMemory prepared((value.size() + 1) * sizeof(wchar_t));
        if (!prepared.value) return ClipboardStatus::quota;
        const auto memory = static_cast<wchar_t *>(GlobalLock(prepared.value));
        if (!memory) return ClipboardStatus::unavailable;
        for (std::size_t index = 0; index < value.size(); ++index) memory[index] = static_cast<wchar_t>(value[index]);
        memory[value.size()] = L'\0';
        SetLastError(ERROR_SUCCESS);
        if (!GlobalUnlock(prepared.value) && GetLastError() != ERROR_SUCCESS) return ClipboardStatus::unavailable;
        if (!current(window, epoch)) return ClipboardStatus::denied;
        OpenedClipboard opened(window);
        if (!opened.open) return ClipboardStatus::unavailable;
        const auto result = [&] {
            if (!current(window, epoch)) return ClipboardStatus::denied;
            if (!EmptyClipboard()) return ClipboardStatus::unavailable;
            // EmptyClipboard is already a write. If ownership/focus changes or
            // the next write fails, no rollback or automatic retry is safe.
            if (!current(window, epoch)) return ClipboardStatus::unavailable;
            if (!SetClipboardData(CF_UNICODETEXT, prepared.value)) return ClipboardStatus::unavailable;
            prepared.value = nullptr; // Windows owns the unlocked allocation.
            return ClipboardStatus::ok;
        }();
        const bool closed = opened.close();
        if (result != ClipboardStatus::ok) return result;
        return closed && current(window, epoch) ? ClipboardStatus::ok : ClipboardStatus::unavailable;
    });
}
ClipboardStatus HostClipboardService::clear() noexcept {
    HWND window = nullptr;
    std::uint64_t epoch = 0;
    const auto access = consume(window, epoch);
    if (access != ClipboardStatus::ok) return access;
    OpenedClipboard opened(window);
    if (!opened.open) return ClipboardStatus::unavailable;
    const auto result = current(window, epoch) ?
        (EmptyClipboard() ? ClipboardStatus::ok : ClipboardStatus::unavailable) : ClipboardStatus::denied;
    const bool closed = opened.close();
    if (result != ClipboardStatus::ok) return result;
    return closed && current(window, epoch) ? ClipboardStatus::ok : ClipboardStatus::unavailable;
}
} // namespace aether::host
