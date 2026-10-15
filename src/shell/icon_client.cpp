#include "icon_client.hpp"
#include "aether/security/worker_image.hpp"
#include "aether/shell/icon_cache.hpp"
#include "aether/shell/icon_service.hpp"
#include "aether/shell/icons.hpp"
#include <atomic>
#include <deque>
#include <mutex>
#include <sddl.h>
#include <set>

namespace aether::shell {
namespace {
struct Requests {
    std::mutex mutex;
    std::deque<std::wstring> paths;
    std::set<std::wstring> outstanding;
    std::atomic<bool> running = false;
    ULONGLONG last_start = 0;
    std::size_t path_bytes = 0;
} requests;
std::wstring registry_text(HKEY key, const wchar_t *name) {
    DWORD bytes = 0, type = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS || type != REG_SZ ||
        bytes < 2 || bytes > 65536 || bytes % 2)
        return {};
    std::wstring value(bytes / 2, L'\0');
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE *>(value.data()), &bytes) !=
            ERROR_SUCCESS ||
        type != REG_SZ || bytes != value.size() * 2 || value.back() || value.find(L'\0') != value.size() - 1)
        return {};
    value.pop_back();
    return value;
}
std::filesystem::path registered_broker(HMODULE module) {
    const auto key_path = L"Software\\Classes\\CLSID\\" + std::wstring(icon_handler_id) + L"\\InprocServer32";
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, key_path.c_str(), 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) !=
        ERROR_SUCCESS)
        return {};
    struct Close {
        HKEY key;
        ~Close() { RegCloseKey(key); }
    } close{key};
    auto configured = std::filesystem::path(registry_text(key, nullptr));
    // Bundle-relative paths use '/', while GetModuleFileNameW returns '\\'.
    // Compare the same Windows spelling before authenticating this loaded DLL.
    configured.make_preferred();
    std::wstring filename(32768, L'\0');
    const auto count = GetModuleFileNameW(module, filename.data(), static_cast<DWORD>(filename.size()));
    if (!count || count >= filename.size())
        return {};
    filename.resize(count);
    if (CompareStringOrdinal(filename.c_str(), -1, configured.c_str(), -1, TRUE) != CSTR_EQUAL)
        return {}; // Old Explorer-loaded DLLs cannot restart an unregistered/replaced service.
    const std::filesystem::path image(filename), broker(registry_text(key, L"AetherBroker"));
    const auto directory = image.parent_path();
    const bool beside = directory == broker.parent_path();
    const bool versioned = directory.parent_path().filename() == L"shell-icons" &&
                           directory.parent_path().parent_path() == broker.parent_path();
    return broker.is_absolute() && broker.filename() == L"aether.exe" && (beside || versioned)
               ? broker
               : std::filesystem::path{};
}
bool ensure_service(HMODULE module, const std::wstring &endpoint) {
    if (send_icon_message(endpoint, IconMessage::ping))
        return true;
    const auto tick = GetTickCount64();
    if (requests.last_start && tick - requests.last_start < 30000)
        return false;
    requests.last_start = tick;
    const auto broker = registered_broker(module);
    if (broker.empty())
        return false;
    PSECURITY_DESCRIPTOR raw = nullptr;
    auto policy = security::runtime_directory_sddl();
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(policy.c_str(), SDDL_REVISION_1, &raw, nullptr))
        return false;
    struct Release {
        PSECURITY_DESCRIPTOR p;
        ~Release() { LocalFree(p); }
    } release{raw};
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), raw, FALSE};
    const auto name = L"Local\\" + endpoint.substr(9) + L".Startup";
    host::UniqueHandle mutex(CreateMutexW(&attributes, FALSE, name.c_str()));
    if (!mutex)
        return false;
    const auto lock = WaitForSingleObject(mutex.get(), 2000);
    if (lock != WAIT_OBJECT_0 && lock != WAIT_ABANDONED)
        return false;
    struct Unlock {
        HANDLE mutex;
        ~Unlock() { ReleaseMutex(mutex); }
    } unlock{mutex.get()};
    if (registered_broker(module) != broker)
        return false; // Registration may have been removed while startup was serialized.
    if (send_icon_message(endpoint, IconMessage::ping))
        return true;
    if (!launch_icon_service(broker))
        return false;
    for (unsigned i = 0; i < 40; ++i) {
        if (send_icon_message(endpoint, IconMessage::ping))
            return true;
        Sleep(50); // Background callback only; never GetIconLocation or Extract.
    }
    return false;
}
void CALLBACK drain(PTP_CALLBACK_INSTANCE callback, void *context) {
    const auto module = static_cast<HMODULE>(context);
    FreeLibraryWhenCallbackReturns(callback, module);
    for (;;) {
        std::wstring path;
        {
            std::lock_guard lock(requests.mutex);
            if (requests.paths.empty()) {
                requests.running = false;
                return;
            }
            path = std::move(requests.paths.front());
            requests.paths.pop_front();
        }
        try {
            if (!registered_broker(module).empty()) {
                const auto endpoint = icon_endpoint();
                if (ensure_service(module, endpoint))
                    send_icon_message(endpoint, IconMessage::enqueue, path);
            }
        } catch (...) {
            // A missing, stopped or unhealthy service leaves the generic icon.
        }
        {
            std::lock_guard lock(requests.mutex);
            requests.outstanding.erase(path);
            requests.path_bytes -= path.size() * sizeof(wchar_t);
        }
    }
}
} // namespace
void queue_icon_read(HMODULE module, std::wstring_view path) noexcept {
    try {
        if (path.empty() || path.size() > 32760 || registered_broker(module).empty())
            return;
        std::lock_guard lock(requests.mutex);
        const std::wstring copy(path);
        if (requests.outstanding.contains(copy) || requests.outstanding.size() >= 1024 ||
            copy.size() * sizeof(wchar_t) > 4 * 1024 * 1024 - requests.path_bytes)
            return;
        requests.paths.push_back(copy);
        try {
            requests.outstanding.insert(copy);
        } catch (...) {
            requests.paths.pop_back();
            throw;
        }
        requests.path_bytes += copy.size() * sizeof(wchar_t);
        if (requests.running)
            return;
        HMODULE retained = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(&drain),
                                &retained)) {
            requests.paths.clear();
            requests.outstanding.clear();
            requests.path_bytes = 0;
            return;
        }
        requests.running = true;
        if (!TrySubmitThreadpoolCallback(drain, retained, nullptr)) {
            requests.running = false;
            requests.paths.clear();
            requests.outstanding.clear();
            requests.path_bytes = 0;
            FreeLibrary(retained);
        }
    } catch (...) {
        // Failure to queue must not escape a COM call or change the fallback.
    }
}
bool icon_reads_pending() noexcept { return requests.running.load(); }
} // namespace aether::shell
