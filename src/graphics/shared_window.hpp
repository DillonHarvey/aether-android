#pragma once
#include "aether/graphics/shared_window.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <d3d11_1.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

namespace aether::graphics {
class SharedWindow final {
  public:
    explicit SharedWindow(const SharedWindowGrant &grant);
    ~SharedWindow();
    SharedWindowGrant grant;
    EGLSurface create_surface(EGLDisplay display, EGLConfig config);
    void acquire();
    void publish();
    bool release_device() noexcept;

  private:
    host::UniqueHandle handle_;
    Microsoft::WRL::ComPtr<ID3D11Texture2D> texture_;
    Microsoft::WRL::ComPtr<IDXGIKeyedMutex> mutex_;
    std::uint64_t key_ = 0;
    bool owned_ = false;
};
} // namespace aether::graphics
