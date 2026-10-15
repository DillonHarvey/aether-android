#include "aether/shell/icon_cache.hpp"
#include "aether/shell/icons.hpp"
#include "icon_client.hpp"
#include <ShlObj.h>
#include <atomic>
#include <cstring>
#include <new>
#include <string>

namespace {
HINSTANCE module = nullptr;
std::atomic<long> objects{0}, server_locks{0};
constexpr wchar_t package_token[] = L"aether:package", bundle_token[] = L"aether:bundle";
HRESULT exception_result() noexcept {
    try {
        throw;
    } catch (const std::bad_alloc &) {
        return E_OUTOFMEMORY;
    } catch (...) {
        return E_FAIL;
    }
}
class IconHandler final : public IPersistFile, public IExtractIconW {
  public:
    IconHandler() { ++objects; }
    ~IconHandler() { --objects; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void **out) override {
        if (!out)
            return E_POINTER;
        *out = nullptr;
        if (id == IID_IUnknown || id == IID_IPersist || id == IID_IPersistFile)
            *out = static_cast<IPersistFile *>(this);
        else if (id == IID_IExtractIconW)
            *out = static_cast<IExtractIconW *>(this);
        else
            return E_NOINTERFACE;
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override {
        const auto remaining = --references_;
        if (!remaining)
            delete this;
        return remaining;
    }
    HRESULT STDMETHODCALLTYPE GetClassID(CLSID *id) override {
        if (!id)
            return E_POINTER;
        *id = aether::shell::icon_handler_clsid;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE IsDirty() override { return S_FALSE; }
    HRESULT STDMETHODCALLTYPE Load(LPCOLESTR file, DWORD mode) override {
        path_.clear();
        cached_token_.clear();
        cached_path_.clear();
        if (!file)
            return E_POINTER;
        if ((mode & 3) != STGM_READ)
            return STG_E_ACCESSDENIED;
        try {
            const auto count = wcsnlen(file, 32761);
            path_ = aether::shell::icon_input_path({file, count});
            return path_.empty() ? STG_E_INVALIDNAME : S_OK;
        } catch (...) {
            return exception_result();
        }
    }
    HRESULT STDMETHODCALLTYPE Save(LPCOLESTR, BOOL) override { return STG_E_ACCESSDENIED; }
    HRESULT STDMETHODCALLTYPE SaveCompleted(LPCOLESTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetCurFile(LPOLESTR *file) override {
        if (!file)
            return E_POINTER;
        *file = nullptr;
        const auto bytes = (path_.size() + 1) * sizeof(wchar_t);
        auto copy = static_cast<wchar_t *>(CoTaskMemAlloc(bytes));
        if (!copy)
            return E_OUTOFMEMORY;
        std::memcpy(copy, path_.c_str(), bytes);
        *file = copy;
        return path_.empty() ? S_FALSE : S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetIconLocation(UINT requested, PWSTR location, UINT capacity, int *index,
                                              UINT *flags) override {
        if (location && capacity)
            location[0] = 0;
        if (index)
            *index = 0;
        if (flags)
            *flags = 0;
        if (!location || !capacity || !index || !flags)
            return E_POINTER;
        try {
            cached_token_.clear();
            cached_path_.clear();
            *flags = GIL_PERINSTANCE | GIL_FORCENOSHIELD;
            if (!(requested & GIL_DEFAULTICON) && !path_.empty()) {
                bool queue = true;
                try {
                    aether::shell::IconSource source(path_);
                    aether::shell::IconCache cache;
                    const auto hit = cache.lookup(source.identity());
                    queue = hit.state != aether::shell::CacheState::retry_later;
                    if (hit.state == aether::shell::CacheState::ready) {
                        cached_path_ = hit.path.native();
                        if (cached_path_.size() < capacity) {
                            std::memcpy(location, cached_path_.c_str(),
                                        (cached_path_.size() + 1) * sizeof(wchar_t));
                            aether::shell::queue_icon_read(module, path_); // Asynchronous LRU touch.
                            return S_OK;
                        }
                        const auto token = L"aether:" + aether::shell::icon_hex(hit.digest);
                        if (token.size() < capacity) {
                            cached_token_ = token;
                            std::memcpy(location, token.c_str(), (token.size() + 1) * sizeof(wchar_t));
                            *flags |= GIL_NOTFILENAME;
                            aether::shell::queue_icon_read(module, path_);
                            return S_OK;
                        }
                    }
                } catch (...) {
                    // Inaccessible/cache-corrupt paths always retain the real fallback.
                }
                if (queue)
                    aether::shell::queue_icon_read(module, path_);
            }
            const bool bundle = aether::shell::bundle_path(path_);
            std::wstring filename(32768, L'\0');
            const auto count =
                GetModuleFileNameW(module, filename.data(), static_cast<DWORD>(filename.size()));
            if (!count || count >= filename.size())
                return E_FAIL;
            filename.resize(count);
            *index = -(bundle ? aether::shell::bundle_icon_resource : aether::shell::package_icon_resource);
            if (filename.size() < capacity) {
                std::memcpy(location, filename.c_str(), (filename.size() + 1) * sizeof(wchar_t));
                return S_OK;
            }
            // Long installed paths still work with older Shell callers' MAX_PATH
            // buffers. A synthetic location is accompanied by actual HICON extraction.
            const auto token = bundle ? bundle_token : package_token;
            const auto length = wcslen(token);
            if (length >= capacity)
                return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
            std::memcpy(location, token, (length + 1) * sizeof(wchar_t));
            *flags |= GIL_NOTFILENAME;
            return S_OK;
        } catch (...) {
            return exception_result();
        }
    }
    HRESULT STDMETHODCALLTYPE Extract(PCWSTR file, UINT index, HICON *large, HICON *small_icon,
                                      UINT sizes) override {
        if (large)
            *large = nullptr;
        if (small_icon)
            *small_icon = nullptr;
        if (!file || (!large && !small_icon))
            return E_INVALIDARG;
        bool cached = false;
        if (!cached_token_.empty() && cached_token_ == file && index == 0) {
            try {
                aether::shell::IconSource source(path_);
                aether::shell::IconCache cache;
                const auto hit = cache.lookup(source.identity());
                cached = hit.state == aether::shell::CacheState::ready &&
                         cached_token_ == L"aether:" + aether::shell::icon_hex(hit.digest) &&
                         hit.path.native() == cached_path_;
            } catch (...) {
                cached = false;
            }
            if (!cached)
                return E_FAIL; // A changed/tampered artifact is never handed to Windows.
        }
        const bool bundle = wcscmp(file, bundle_token) == 0;
        if (!cached && !bundle && wcscmp(file, package_token) != 0)
            return S_FALSE; // The real filename/index from GetIconLocation is directly usable.
        const auto resource =
            bundle ? aether::shell::bundle_icon_resource : aether::shell::package_icon_resource;
        if (!cached && index != static_cast<UINT>(-resource))
            return E_INVALIDARG;
        const auto large_size = LOWORD(sizes), small_size = HIWORD(sizes);
        if ((large && (!large_size || large_size > 1024)) ||
            (small_icon && (!small_size || small_size > 1024)))
            return E_INVALIDARG;
        const auto load = [this, resource, cached](int size) {
            if (cached)
                return static_cast<HICON>(
                    LoadImageW(nullptr, cached_path_.c_str(), IMAGE_ICON, size, size, LR_LOADFROMFILE));
            return static_cast<HICON>(
                LoadImageW(module, MAKEINTRESOURCEW(resource), IMAGE_ICON, size, size, 0));
        };
        HICON big = large ? load(large_size) : nullptr;
        HICON little = small_icon ? load(small_size) : nullptr;
        if ((large && !big) || (small_icon && !little)) {
            if (big)
                DestroyIcon(big);
            if (little)
                DestroyIcon(little);
            return E_FAIL;
        }
        if (large)
            *large = big;
        if (small_icon)
            *small_icon = little;
        return S_OK;
    }

  private:
    std::atomic<ULONG> references_{1};
    std::wstring path_;
    std::wstring cached_path_, cached_token_;
};
class Factory final : public IClassFactory {
  public:
    Factory() { ++objects; }
    ~Factory() { --objects; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void **out) override {
        if (!out)
            return E_POINTER;
        *out = nullptr;
        if (id != IID_IUnknown && id != IID_IClassFactory)
            return E_NOINTERFACE;
        *out = static_cast<IClassFactory *>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override {
        const auto remaining = --references_;
        if (!remaining)
            delete this;
        return remaining;
    }
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown *outer, REFIID id, void **out) override {
        if (!out)
            return E_POINTER;
        *out = nullptr;
        if (outer)
            return CLASS_E_NOAGGREGATION;
        try {
            auto instance = new IconHandler;
            const auto result = instance->QueryInterface(id, out);
            instance->Release();
            return result;
        } catch (...) {
            return exception_result();
        }
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
        if (lock)
            ++server_locks;
        else {
            auto current = server_locks.load();
            do {
                if (!current)
                    return E_UNEXPECTED;
            } while (!server_locks.compare_exchange_weak(current, current - 1));
        }
        return S_OK;
    }

  private:
    std::atomic<ULONG> references_{1};
};
} // namespace
extern "C" HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void **out) {
    if (!out)
        return E_POINTER;
    *out = nullptr;
    if (clsid != aether::shell::icon_handler_clsid)
        return CLASS_E_CLASSNOTAVAILABLE;
    try {
        auto factory = new Factory;
        const auto result = factory->QueryInterface(iid, out);
        factory->Release();
        return result;
    } catch (...) {
        return exception_result();
    }
}
extern "C" HRESULT WINAPI DllCanUnloadNow() {
    return objects.load() || server_locks.load() || aether::shell::icon_reads_pending() ? S_FALSE : S_OK;
}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        module = instance;
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}
