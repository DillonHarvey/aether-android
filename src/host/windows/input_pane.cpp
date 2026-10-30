#include "aether/host/windows/input_pane.hpp"
#include <InputPaneInterop.h>
#include <atomic>
#include <cstdint>
#include <iterator>
#include <limits>
#include <roapi.h>
#include <shobjidl.h>
#include <utility>
#include <windows.ui.viewmanagement.h>
#include <winstring.h>
#include <wrl/client.h>

namespace aether::host {
namespace {
using Microsoft::WRL::ComPtr;
using ABI::Windows::UI::ViewManagement::IInputPane;
using ABI::Windows::UI::ViewManagement::IInputPane2;
struct Lock {
    SRWLOCK &mutex;
    explicit Lock(SRWLOCK &value) noexcept : mutex(value) { AcquireSRWLockExclusive(&mutex); }
    ~Lock() { ReleaseSRWLockExclusive(&mutex); }
};
std::optional<RECT> valid_rectangle(const RECT &value) noexcept {
    if (value.left > value.right || value.top > value.bottom) return {};
    if (value.left == value.right || value.top == value.bottom) return RECT{};
    return value;
}
bool same_rectangle(const std::optional<RECT> &left, const std::optional<RECT> &right) noexcept {
    return left.has_value() == right.has_value() && (!left ||
        (left->left == right->left && left->top == right->top &&
         left->right == right->right && left->bottom == right->bottom));
}
struct Observation {
    const HWND window;
    const DWORD owner = GetCurrentThreadId(), process = GetCurrentProcessId();
    const UINT message;
    SRWLOCK mutex = SRWLOCK_INIT;
    bool live = true, posted = false, exhausted = false;
    std::uint64_t revision = 0;
    std::optional<RECT> rectangle;
    Observation(HWND value, UINT changed) : window(value), message(changed) {}
    bool owned_window() const noexcept {
        DWORD actual_process = 0;
        return window && IsWindow(window) &&
            GetWindowThreadProcessId(window, &actual_process) == owner && actual_process == process &&
            AreDpiAwarenessContextsEqual(GetWindowDpiAwarenessContext(window),
                                         DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
    bool ui_owner() const noexcept {
        return GetCurrentThreadId() == owner && owned_window() &&
            AreDpiAwarenessContextsEqual(GetThreadDpiAwarenessContext(),
                                         DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
    bool foreground() const noexcept {
        return ui_owner() && GetForegroundWindow() == window && GetFocus() == window &&
            IsWindowVisible(window) && !IsIconic(window);
    }
    void publish(std::optional<RECT> value, std::optional<std::uint64_t> expected = {}) noexcept {
        Lock lock(mutex);
        if (!live || (expected && (exhausted || *expected != revision))) return;
        if (revision == std::numeric_limits<std::uint64_t>::max()) exhausted = true;
        else ++revision;
        const bool changed = !same_rectangle(rectangle, value);
        rectangle = value;
        // PostMessage does not call a window procedure synchronously. Keeping
        // retirement and this post serialized prevents a late callback post.
        // No COM or guest call runs under the observation lock.
        if (changed && !posted) posted = PostMessageW(window, message, 0, 0) != FALSE;
    }
    std::optional<std::uint64_t> read_revision() noexcept {
        Lock lock(mutex);
        if (!live || exhausted) return {};
        return revision;
    }
    std::optional<RECT> take() noexcept {
        Lock lock(mutex);
        posted = false;
        return live ? rectangle : std::nullopt;
    }
    void retire() noexcept {
        Lock lock(mutex);
        live = false;
        rectangle.reset();
    }
};
class Handler final : public IFrameworkInputPaneHandler {
    std::atomic<ULONG> references_{1};
    const std::weak_ptr<Observation> observation_;
  public:
    explicit Handler(const std::shared_ptr<Observation> &observation) : observation_(observation) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != __uuidof(IUnknown) && iid != __uuidof(IFrameworkInputPaneHandler)) return E_NOINTERFACE;
        *output = static_cast<IFrameworkInputPaneHandler *>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return references_.fetch_add(1, std::memory_order_relaxed) + 1; }
    ULONG STDMETHODCALLTYPE Release() override {
        const auto remaining = references_.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (!remaining) delete this;
        return remaining;
    }
    HRESULT STDMETHODCALLTYPE Showing(RECT *location, BOOL) override {
        if (const auto observation = observation_.lock()) {
            // The native contract supplies a screen-coordinate rectangle for
            // this HWND. PMv2 ownership makes these physical pixels.
            observation->publish(location && observation->ui_owner() ? valid_rectangle(*location) : std::nullopt);
        }
        return location ? S_OK : E_POINTER;
    }
    HRESULT STDMETHODCALLTYPE Hiding(BOOL) override {
        if (const auto observation = observation_.lock())
            observation->publish(observation->ui_owner() ? std::optional<RECT>{RECT{}} : std::nullopt);
        return S_OK;
    }
};
struct Writing {
    bool &active;
    explicit Writing(bool &value) noexcept : active(value) { active = true; }
    ~Writing() { active = false; }
};
} // namespace

struct InputPane::Impl {
    const std::shared_ptr<Observation> observation;
    ComPtr<IInputPane2> control;
    ComPtr<IFrameworkInputPane> observer;
    ComPtr<IFrameworkInputPaneHandler> handler;
    HRESULT initialized = E_FAIL;
    DWORD cookie = 0;
    bool advised = false, closing = false, writing = false, own_show = false;
    std::uint64_t tenure = 0;
    bool tenure_exhausted = false;
    void forget_ownership() noexcept {
        own_show = false;
        if (tenure == std::numeric_limits<std::uint64_t>::max()) tenure_exhausted = true;
        else ++tenure;
    }
    Impl(HWND window, UINT message) : observation(std::make_shared<Observation>(window, message)) {}
    ~Impl() noexcept {
        shutdown();
        if (SUCCEEDED(initialized)) RoUninitialize();
    }
    void initialize() noexcept {
        if (!observation->ui_owner() || observation->message < WM_APP || observation->message > 0xffff) return;
        initialized = RoInitialize(RO_INIT_SINGLETHREADED);
        if (FAILED(initialized)) return;
        try {
            constexpr wchar_t class_name[] = L"Windows.UI.ViewManagement.InputPane";
            HSTRING_HEADER header{};
            HSTRING name = nullptr;
            ComPtr<IInputPaneInterop> factory;
            if (SUCCEEDED(WindowsCreateStringReference(class_name,
                    static_cast<UINT32>(std::size(class_name) - 1), &header, &name)) &&
                SUCCEEDED(RoGetActivationFactory(name, IID_PPV_ARGS(&factory)))) {
                ComPtr<IInputPane> pane;
                if (SUCCEEDED(factory->GetForWindow(observation->window, IID_PPV_ARGS(&pane))))
                    (void)pane.As(&control);
            }
            if (!observation->ui_owner()) return;
            if (FAILED(CoCreateInstance(__uuidof(FrameworkInputPane), nullptr, CLSCTX_INPROC_SERVER,
                                         IID_PPV_ARGS(&observer)))) return;
            refresh(); // Initial passive observation, before a Showing callback can supersede it.
            if (!observation->ui_owner()) return;
            handler.Attach(new Handler(observation));
            advised = SUCCEEDED(observer->AdviseWithHWND(observation->window, handler.Get(), &cookie));
        } catch (...) {
            // Unsupported observation/control must not prevent the app window.
            // Any successfully acquired interfaces remain normally owned.
        }
    }
    void refresh() noexcept {
        if (closing || !observation->ui_owner()) return;
        if (!observation->foreground()) forget_ownership();
        const auto revision = observation->read_revision();
        if (!revision) return;
        const auto source = observer; // Pin across a reentrant native callback.
        if (!source) { observation->publish({}, revision); return; }
        RECT rectangle{};
        const auto result = source->Location(&rectangle);
        observation->publish(SUCCEEDED(result) ? valid_rectangle(rectangle) : std::nullopt, revision);
    }
    void shutdown() noexcept {
        if (closing) return;
        closing = true;
        forget_ownership();
        observation->retire();
        const auto source = std::move(observer);
        const bool remove = std::exchange(advised, false);
        if (source && remove) (void)source->Unadvise(cookie);
        handler.Reset();
        control.Reset();
        // RoUninitialize belongs to the final Impl destruction. An in-flight
        // request keeps Impl and its apartment reference alive through reentry.
    }
};
InputPane::InputPane(HWND window, UINT changed_message)
    : impl_(std::make_shared<Impl>(window, changed_message)) { impl_->initialize(); }
InputPane::~InputPane() noexcept { impl_->shutdown(); }
PaneAttempt InputPane::request_show() noexcept {
    const auto state = impl_;
    if (state->closing || !state->observation->ui_owner() || !state->control) return PaneAttempt::unsupported;
    if (!state->observation->foreground()) { state->forget_ownership(); return PaneAttempt::declined; }
    if (state->writing || state->tenure_exhausted) return PaneAttempt::declined;
    const auto tenure = state->tenure;
    const auto control = state->control;
    Writing writing(state->writing);
    boolean accepted = false;
    const auto result = control->TryShow(&accepted);
    if (FAILED(result)) return PaneAttempt::unsupported;
    if (!accepted) return PaneAttempt::declined;
    // COM may pump a full focus-loss/regain cycle. Current foreground alone
    // cannot restore ownership of an attempt made in the retired tenure.
    if (state->closing || state->tenure_exhausted || tenure != state->tenure ||
        !state->observation->foreground()) return PaneAttempt::declined;
    state->own_show = true;
    return PaneAttempt::accepted;
}
PaneAttempt InputPane::request_hide() noexcept {
    const auto state = impl_;
    if (state->closing || !state->observation->ui_owner() || !state->control) return PaneAttempt::unsupported;
    if (!state->observation->foreground()) { state->forget_ownership(); return PaneAttempt::declined; }
    if (!state->own_show || state->writing || state->tenure_exhausted) return PaneAttempt::declined;
    const auto tenure = state->tenure;
    const auto control = state->control;
    Writing writing(state->writing);
    boolean accepted = false;
    const auto result = control->TryHide(&accepted);
    if (FAILED(result)) return PaneAttempt::unsupported;
    if (!accepted) return PaneAttempt::declined;
    if (state->closing || state->tenure_exhausted || tenure != state->tenure ||
        !state->observation->foreground()) return PaneAttempt::declined;
    state->own_show = false;
    return PaneAttempt::accepted;
}
void InputPane::abandon() noexcept {
    const auto state = impl_;
    if (GetCurrentThreadId() == state->observation->owner) state->forget_ownership();
}
std::optional<RECT> InputPane::occlusion() const noexcept {
    const auto state = impl_;
    if (state->closing || !state->observation->ui_owner()) return {};
    return state->observation->take();
}
void InputPane::refresh() noexcept { const auto state = impl_; state->refresh(); }
} // namespace aether::host
