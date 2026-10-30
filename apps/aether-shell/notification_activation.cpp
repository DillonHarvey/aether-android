#include "notification_activation.hpp"
#include "aether/common/text.hpp"
#include "aether/install/notification_identity.hpp"
#include "aether/install/shell.hpp"
#include "aether/install/store.hpp"
#include <Windows.h>
#include <notificationactivationcallback.h>
#include <objbase.h>
#include <wrl/client.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <new>
#include <string_view>
#include <utility>

namespace aether::install {
namespace {
using Microsoft::WRL::ComPtr;
constexpr ULONGLONG startup_wait_ms = 30'000, idle_wait_ms = 5'000;
constexpr unsigned maximum_objects = 16, maximum_locks = 16;

void require(bool condition, const char *code, const char *message) {
    if (!condition) throw InstallError(code, message);
}
void checked(HRESULT result, const char *message) {
    require(SUCCEEDED(result), "AETHER_NOTIFICATION_SERVER", message);
}
struct Apartment {
    HRESULT result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    Apartment() { checked(result, "Cannot initialize notification activation apartment"); }
    ~Apartment() { if (SUCCEEDED(result)) CoUninitialize(); }
};
struct Registration {
    DWORD cookie = 0;
    ~Registration() { if (cookie) (void)CoRevokeClassObject(cookie); }
    void revoke() {
        checked(CoRevokeClassObject(cookie), "Cannot revoke notification activation class");
        cookie = 0;
    }
};
bool bounded_text(LPCWSTR value, std::size_t maximum, std::wstring_view &result) noexcept {
    if (!value) return false;
    for (std::size_t size = 0; size <= maximum; ++size) {
        if (!value[size]) {
            result = {value, size};
            return true;
        }
    }
    return false;
}
bool canonical_notification_id(std::wstring_view arguments, std::int32_t &id) {
    constexpr std::wstring_view prefix = L"aether-notification-v1:";
    if (!arguments.starts_with(prefix)) return false;
    const auto number = arguments.substr(prefix.size());
    if (number.empty() || number.size() > 11) return false;
    std::array<char, 11> decimal{};
    for (std::size_t index = 0; index < number.size(); ++index) {
        const auto unit = number[index];
        if ((unit < L'0' || unit > L'9') && !(index == 0 && unit == L'-')) return false;
        decimal[index] = static_cast<char>(unit);
    }
    const auto parsed = std::from_chars(decimal.data(), decimal.data() + number.size(), id);
    return parsed.ec == std::errc{} && parsed.ptr == decimal.data() + number.size() &&
           notification_arguments(id) == arguments;
}
struct ServerState {
    const DWORD owner = GetCurrentThreadId();
    const std::string id;
    const std::filesystem::path store;
    const std::wstring aumid;
    std::atomic<unsigned> objects{0}, locks{0};
    std::atomic<ULONGLONG> last_activity{GetTickCount64()};
    std::atomic<bool> used{false}, accepting{true};
    ServerState(std::string id, std::filesystem::path store)
        : id(std::move(id)), store(std::move(store)), aumid(L"Aether.App." + utf16(this->id)) {}
    void touch() noexcept {
        last_activity.store(GetTickCount64(), std::memory_order_relaxed);
        used.store(true, std::memory_order_relaxed);
    }
    void admit() const {
        // A short read snapshot excludes registry mutations while this selected
        // identity and its Windows projection are checked. Never prepare a launch.
        PackageStore snapshot(store, PackageStore::Access::read);
        const auto applications = snapshot.list();
        const auto selected = std::find_if(applications.begin(), applications.end(),
                                            [&](const auto &app) { return app.id == id; });
        require(selected != applications.end() && selected->state == State::installed &&
                    selected->shell == ShellState::ready && valid_shell_record(*selected),
                "AETHER_NOTIFICATION_ADMISSION", "Notification app is not a settled installed identity");
        const auto shell = hold_shell_registration(); // Existing store -> Shell lock order.
        require(selected->launcher == utf8(shell_launcher().wstring()) &&
                    inspect_notification_registration(*selected, snapshot.root()),
                "AETHER_NOTIFICATION_ADMISSION", "Notification activation registration is not owned and current");
    }
};
class Activation final : public INotificationActivationCallback {
    std::atomic<ULONG> references{1};
    std::shared_ptr<ServerState> state;
    ~Activation() {
        state->objects.fetch_sub(1, std::memory_order_relaxed);
        state->touch();
    }
  public:
    explicit Activation(std::shared_ptr<ServerState> state) : state(std::move(state)) {
        this->state->objects.fetch_add(1, std::memory_order_relaxed);
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != __uuidof(IUnknown) && iid != __uuidof(INotificationActivationCallback)) return E_NOINTERFACE;
        *output = static_cast<INotificationActivationCallback *>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return references.fetch_add(1, std::memory_order_relaxed) + 1; }
    ULONG STDMETHODCALLTYPE Release() override {
        const auto remaining = references.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (!remaining) delete this;
        return remaining;
    }
    HRESULT STDMETHODCALLTYPE Activate(LPCWSTR app_user_model_id, LPCWSTR invoked_arguments,
                                        const NOTIFICATION_USER_INPUT_DATA *, ULONG count) override {
        if (GetCurrentThreadId() != state->owner) return RPC_E_WRONG_THREAD;
        if (!state->accepting.load(std::memory_order_relaxed)) return CO_E_SERVER_STOPPING;
        state->touch();
        if (count != 0) return E_INVALIDARG;
        try {
            std::wstring_view app, arguments;
            std::int32_t id = 0;
            if (!bounded_text(app_user_model_id, state->aumid.size(), app) || app != state->aumid ||
                !bounded_text(invoked_arguments, 40, arguments) || !canonical_notification_id(arguments, id))
                return E_INVALIDARG;
            state->admit();
            // Current posts support only null contentIntent and no actions.
            // A valid activation has no Android operation to deliver. Acknowledge
            // that exact contract; never substitute a generic relaunch or APK run.
            return S_OK;
        } catch (const std::bad_alloc &) {
            return E_OUTOFMEMORY;
        } catch (...) {
            return E_ACCESSDENIED;
        }
    }
};
class Factory final : public IClassFactory {
    std::atomic<ULONG> references{1};
    std::shared_ptr<ServerState> state;
  public:
    explicit Factory(std::shared_ptr<ServerState> state) : state(std::move(state)) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (iid != __uuidof(IUnknown) && iid != __uuidof(IClassFactory)) return E_NOINTERFACE;
        *output = static_cast<IClassFactory *>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return references.fetch_add(1, std::memory_order_relaxed) + 1; }
    ULONG STDMETHODCALLTYPE Release() override {
        const auto remaining = references.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (!remaining) delete this;
        return remaining;
    }
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown *outer, REFIID iid, void **output) override {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (outer) return CLASS_E_NOAGGREGATION;
        if (GetCurrentThreadId() != state->owner) return RPC_E_WRONG_THREAD;
        if (!state->accepting.load(std::memory_order_relaxed)) return CO_E_SERVER_STOPPING;
        if (state->objects.load(std::memory_order_relaxed) >= maximum_objects)
            return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_QUOTA);
        state->touch();
        try {
            auto *object = new Activation(state);
            const auto result = object->QueryInterface(iid, output);
            object->Release();
            return result;
        } catch (const std::bad_alloc &) {
            return E_OUTOFMEMORY;
        } catch (...) {
            return E_UNEXPECTED;
        }
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
        if (GetCurrentThreadId() != state->owner) return RPC_E_WRONG_THREAD;
        if (!state->accepting.load(std::memory_order_relaxed)) return CO_E_SERVER_STOPPING;
        const auto count = state->locks.load(std::memory_order_relaxed);
        if (lock) {
            if (count >= maximum_locks) return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_QUOTA);
            state->locks.fetch_add(1, std::memory_order_relaxed);
        } else {
            if (!count) return E_UNEXPECTED;
            state->locks.fetch_sub(1, std::memory_order_relaxed);
        }
        state->touch();
        return S_OK;
    }
};
} // namespace

std::optional<int> run_notification_server(const std::vector<std::string> &arguments) {
    if (arguments.empty() || arguments[0] != "notification-server") return {};
    require((arguments.size() == 5 || (arguments.size() == 6 && arguments[5] == "-Embedding")) &&
                arguments[1] == "--app-id" && valid_app_id(arguments[2]) &&
                arguments[3] == "--store" && !arguments[4].empty(),
            "AETHER_CLI_USAGE", "Expected notification-server --app-id ID --store PATH with optional final -Embedding");
    auto state = std::make_shared<ServerState>(arguments[2], std::filesystem::path(utf16(arguments[4])));
    Apartment apartment;
    state->admit();
    CLSID clsid{};
    checked(CLSIDFromString(notification_clsid(state->id).c_str(), &clsid), "Cannot parse notification activation identity");
    require(!IsEqualCLSID(clsid, CLSID_NULL), "AETHER_NOTIFICATION_SERVER", "Notification activation identity is reserved");
    ComPtr<IClassFactory> factory;
    factory.Attach(new Factory(state));
    Registration registration;
    checked(CoRegisterClassObject(clsid, factory.Get(), CLSCTX_LOCAL_SERVER, REGCLS_MULTIPLEUSE,
                                  &registration.cookie), "Cannot register notification activation class");
    MSG message{};
    bool quit = false;
    for (;;) {
        // STA RPC calls are dispatched by this owner thread's message pump.
        for (unsigned dispatched = 0; dispatched < 64 && PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE);
             ++dispatched) {
            if (message.message == WM_QUIT) quit = true;
            else { TranslateMessage(&message); DispatchMessageW(&message); }
        }
        const auto elapsed = GetTickCount64() - state->last_activity.load(std::memory_order_relaxed);
        const auto timeout = state->used.load(std::memory_order_relaxed) ? idle_wait_ms : startup_wait_ms;
        if ((quit || elapsed >= timeout) && !state->objects.load(std::memory_order_relaxed) &&
            !state->locks.load(std::memory_order_relaxed)) {
            state->accepting.store(false, std::memory_order_relaxed);
            checked(CoSuspendClassObjects(), "Cannot suspend notification activation class");
            if (!state->objects.load(std::memory_order_relaxed) && !state->locks.load(std::memory_order_relaxed)) {
                registration.revoke();
                return 0;
            }
            state->accepting.store(true, std::memory_order_relaxed);
            checked(CoResumeClassObjects(), "Cannot resume notification activation class");
        }
        const auto wait = MsgWaitForMultipleObjectsEx(0, nullptr, 250, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        require(wait == WAIT_OBJECT_0 || wait == WAIT_TIMEOUT, "AETHER_NOTIFICATION_SERVER",
                "Notification activation message wait failed");
    }
}
} // namespace aether::install
