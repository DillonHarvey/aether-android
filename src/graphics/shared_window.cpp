#include "shared_window.hpp"
#include "aether/a64/guest_memory.hpp"
#include <format>

namespace aether::graphics {
namespace {
void require(bool value, const char *message) {
    if (!value)
        throw a64::GuestError("AETHER_GRAPHICS_SHARED_WINDOW", message);
}
} // namespace
SharedWindow::SharedWindow(const SharedWindowGrant &value)
    : grant(value), handle_(reinterpret_cast<HANDLE>(value.handle)) {
    require(value.valid(), "Invalid trusted texture grant");
}
SharedWindow::~SharedWindow() { release_device(); }
EGLSurface SharedWindow::create_surface(EGLDisplay display, EGLConfig config) {
    if (!texture_) {
        EGLAttrib device = 0, native = 0;
        const auto egl_check = [](EGLBoolean success, const char *stage) {
            if (!success) {
                const auto error = eglGetError();
                throw a64::GuestError(
                    "AETHER_GRAPHICS_SHARED_WINDOW",
                    std::format("{} failed (EGL 0x{:04X})", stage, static_cast<std::uint32_t>(error)));
            }
        };
        egl_check(eglQueryDisplayAttribEXT(display, EGL_DEVICE_EXT, &device), "eglQueryDisplayAttribEXT");
        egl_check(
            eglQueryDeviceAttribEXT(reinterpret_cast<EGLDeviceEXT>(device), EGL_D3D11_DEVICE_ANGLE, &native),
            "eglQueryDeviceAttribEXT");
        require(native != 0, "Cannot identify the ANGLE hardware device");
        Microsoft::WRL::ComPtr<ID3D11Device1> d3d;
        Microsoft::WRL::ComPtr<IDXGIDevice> dxgi;
        Microsoft::WRL::ComPtr<IDXGIAdapter> adapter;
        Microsoft::WRL::ComPtr<IDXGIAdapter1> adapter1;
        DXGI_ADAPTER_DESC1 desc{};
        require(SUCCEEDED(reinterpret_cast<ID3D11Device *>(native)->QueryInterface(IID_PPV_ARGS(&d3d))) &&
                    SUCCEEDED(d3d.As(&dxgi)) && SUCCEEDED(dxgi->GetAdapter(&adapter)) &&
                    SUCCEEDED(adapter.As(&adapter1)) && SUCCEEDED(adapter1->GetDesc1(&desc)) &&
                    !(desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) &&
                    desc.AdapterLuid.LowPart == grant.luid_low &&
                    static_cast<std::uint32_t>(desc.AdapterLuid.HighPart) == grant.luid_high,
                "Texture grant belongs to a different hardware adapter");
        require(SUCCEEDED(d3d->OpenSharedResource1(handle_.get(), IID_PPV_ARGS(&texture_))) &&
                    SUCCEEDED(texture_.As(&mutex_)),
                "Cannot open the explicitly granted NT texture");
        D3D11_TEXTURE2D_DESC texture{};
        texture_->GetDesc(&texture);
        require(texture.Width == grant.width && texture.Height == grant.height &&
                    texture.Format == DXGI_FORMAT_R8G8B8A8_UNORM && texture.MipLevels == 1 &&
                    texture.ArraySize == 1 && texture.SampleDesc.Count == 1 && !texture.SampleDesc.Quality &&
                    texture.Usage == D3D11_USAGE_DEFAULT && !texture.CPUAccessFlags &&
                    texture.BindFlags == (D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE) &&
                    texture.MiscFlags ==
                        (D3D11_RESOURCE_MISC_SHARED_NTHANDLE | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX),
                "Granted resource has an invalid texture description");
    }
    acquire();
    return eglCreatePbufferFromClientBuffer(display, EGL_D3D_TEXTURE_ANGLE, texture_.Get(), config, nullptr);
}
void SharedWindow::acquire() {
    if (!owned_) {
        require(mutex_ && mutex_->AcquireSync(key_, 1000) == S_OK,
                "Shared texture ownership unavailable or abandoned");
        owned_ = true;
    }
}
void SharedWindow::publish() {
    require(owned_ && key_ < 200000, "Invalid shared frame ownership or frame quota");
    require(mutex_->ReleaseSync(key_ + 1) == S_OK, "Cannot publish the shared frame");
    owned_ = false;
    key_ += 2;
}
bool SharedWindow::release_device() noexcept {
    const bool ok = !owned_ || (mutex_ && mutex_->ReleaseSync(key_) == S_OK);
    owned_ = false;
    mutex_.Reset();
    texture_.Reset(); // Release all ANGLE-device references before eglTerminate can unload its driver.
    return ok;
}
} // namespace aether::graphics
