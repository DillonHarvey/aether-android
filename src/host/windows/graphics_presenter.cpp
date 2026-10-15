#include "aether/host/graphics_presenter.hpp"
#include "aether/a64/guest_memory.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include <cstring>
#include <d3d11_1.h>
#include <dxgi1_3.h>
#include <format>
#include <thread>
#include <wrl/client.h>

// Only the separately linked, non-installed test executable substitutes native results.
#ifdef AETHER_GRAPHICS_FAULT_TESTING
#include "graphics_presenter_faults.hpp"
#define AETHER_PRESENT_CALL(point, expression)                                                               \
    testing::presentation_call(testing::PresentationPoint::point, [&]() -> HRESULT { return (expression); })
#else
#define AETHER_PRESENT_CALL(point, expression) (expression)
#endif

namespace aether::host {
namespace {
void require(bool value, const char *message) {
    if (!value)
        throw a64::GuestError("AETHER_GRAPHICS_PRESENTATION", message);
}
} // namespace
struct GraphicsPresenter::Impl {
    const std::thread::id owner = std::this_thread::get_id();
    SurfaceSnapshot surface;
    graphics::SharedWindowGrant binding;
    PresentationMetrics stats;
    bool capture, failed = false;
    Microsoft::WRL::ComPtr<ID3D11Device> device;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> context;
    Microsoft::WRL::ComPtr<IDXGISwapChain1> swap;
    Microsoft::WRL::ComPtr<ID3D11Texture2D> texture;
    Microsoft::WRL::ComPtr<IDXGIKeyedMutex> mutex;
    UniqueHandle shared, latency;
    std::uint64_t key = 1;
    std::vector<std::uint8_t> pixels;
    static constexpr UINT swap_flags = DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT;
    Impl(const SurfaceSnapshot &state, std::uint64_t token, bool retain) : surface(state), capture(retain) {
        check();
        require(GetCurrentThreadId() != surface.owner, "GPU presentation must not run on the HWND owner");
        stats.thread = GetCurrentThreadId();
        binding.token = token;
        binding.generation = 1;
        D3D_FEATURE_LEVEL level{};
        require(SUCCEEDED(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0,
                                            D3D11_SDK_VERSION, &device, &level, &context)),
                "Cannot create the hardware presentation device");
        Microsoft::WRL::ComPtr<IDXGIDevice> dxgi;
        Microsoft::WRL::ComPtr<IDXGIAdapter> adapter;
        Microsoft::WRL::ComPtr<IDXGIAdapter1> adapter1;
        Microsoft::WRL::ComPtr<IDXGIFactory2> factory;
        DXGI_ADAPTER_DESC1 description{};
        require(SUCCEEDED(device.As(&dxgi)) && SUCCEEDED(dxgi->GetAdapter(&adapter)) &&
                    SUCCEEDED(adapter.As(&adapter1)) && SUCCEEDED(adapter1->GetDesc1(&description)) &&
                    !(description.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) &&
                    SUCCEEDED(adapter->GetParent(IID_PPV_ARGS(&factory))),
                "Cannot select a hardware presentation adapter");
        binding.luid_low = description.AdapterLuid.LowPart;
        binding.luid_high = static_cast<std::uint32_t>(description.AdapterLuid.HighPart);
        DXGI_SWAP_CHAIN_DESC1 desc{};
        desc.Width = surface.width;
        desc.Height = surface.height;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        desc.BufferCount = 2;
        desc.Scaling = DXGI_SCALING_STRETCH;
        desc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
        desc.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
        desc.Flags = swap_flags;
        Microsoft::WRL::ComPtr<IDXGISwapChain2> swap2;
        require(SUCCEEDED(factory->CreateSwapChainForHwnd(device.Get(), surface.window, &desc, nullptr,
                                                          nullptr, &swap)) &&
                    SUCCEEDED(factory->MakeWindowAssociation(surface.window, DXGI_MWA_NO_ALT_ENTER)) &&
                    SUCCEEDED(swap.As(&swap2)) && SUCCEEDED(swap2->SetMaximumFrameLatency(1)),
                "Cannot create the native HWND presentation queue");
        latency.reset(swap2->GetFrameLatencyWaitableObject());
        require(static_cast<bool>(latency), "Missing presentation queue readiness event");
        create_texture();
    }
    void check() const {
        require(!failed, "Presentation is permanently closed after a native failure");
        require(owner == std::this_thread::get_id() && HostSurface::valid_snapshot(surface),
                "Stale window binding or wrong presentation owner");
    }
    void checked(HRESULT status, const char *operation, bool exact = false) {
        if (SUCCEEDED(status) && (!exact || status == S_OK))
            return;
        failed = true;
        const auto reason = device ? device->GetDeviceRemovedReason() : S_OK;
        throw a64::GuestError("AETHER_GRAPHICS_PRESENTATION",
                              std::format("{} failed (HRESULT 0x{:08X}; device reason 0x{:08X})", operation,
                                          static_cast<std::uint32_t>(status),
                                          static_cast<std::uint32_t>(reason)));
    }
    void create_texture() {
        D3D11_TEXTURE2D_DESC desc{};
        desc.Width = surface.width;
        desc.Height = surface.height;
        desc.MipLevels = desc.ArraySize = desc.SampleDesc.Count = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
        desc.MiscFlags = D3D11_RESOURCE_MISC_SHARED_NTHANDLE | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX;
        std::vector<std::uint8_t> zero(static_cast<std::size_t>(surface.width) * surface.height * 4);
        const D3D11_SUBRESOURCE_DATA initial{zero.data(), surface.width * 4, static_cast<UINT>(zero.size())};
        Microsoft::WRL::ComPtr<ID3D11Texture2D> next;
        Microsoft::WRL::ComPtr<IDXGIKeyedMutex> next_mutex;
        Microsoft::WRL::ComPtr<IDXGIResource1> resource;
        require(SUCCEEDED(device->CreateTexture2D(&desc, &initial, &next)) &&
                    SUCCEEDED(next.As(&next_mutex)) && SUCCEEDED(next.As(&resource)) &&
                    next_mutex->AcquireSync(0, 1000) == S_OK,
                "Cannot create the bounded shared texture");
        context->Flush(); // Publish initialization before the graphics service can write.
        require(next_mutex->ReleaseSync(0) == S_OK, "Cannot publish initialized texture ownership");
        HANDLE handle = nullptr;
        require(SUCCEEDED(resource->CreateSharedHandle(
                    nullptr, DXGI_SHARED_RESOURCE_READ | DXGI_SHARED_RESOURCE_WRITE, nullptr, &handle)),
                "Cannot create unnamed NT texture");
        texture = std::move(next);
        mutex = std::move(next_mutex);
        shared.reset(handle);
        binding.handle = reinterpret_cast<std::uint64_t>(handle);
        binding.width = surface.width;
        binding.height = surface.height;
        require(binding.valid(), "Invalid generated texture grant");
        key = 1;
        pixels.clear();
    }
    void readback(ID3D11Texture2D *backbuffer) {
        D3D11_TEXTURE2D_DESC desc{};
        backbuffer->GetDesc(&desc);
        require(desc.Width == surface.width && desc.Height == surface.height &&
                    desc.Format == DXGI_FORMAT_R8G8B8A8_UNORM,
                "Unexpected presentation back buffer");
        desc.Usage = D3D11_USAGE_STAGING;
        desc.BindFlags = desc.MiscFlags = 0;
        desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        Microsoft::WRL::ComPtr<ID3D11Texture2D> readback;
        require(SUCCEEDED(device->CreateTexture2D(&desc, nullptr, &readback)),
                "Cannot create proof readback");
        pixels.resize(static_cast<std::size_t>(surface.width) * surface.height * 4);
        context->CopyResource(readback.Get(), backbuffer);
        context->Flush();
        D3D11_MAPPED_SUBRESOURCE mapped{};
        checked(AETHER_PRESENT_CALL(map, context->Map(readback.Get(), 0, D3D11_MAP_READ, 0, &mapped)),
                "ID3D11DeviceContext::Map");
        for (unsigned y = 0; y < surface.height; ++y)
            std::memcpy(pixels.data() + static_cast<std::size_t>(y) * surface.width * 4,
                        static_cast<const std::uint8_t *>(mapped.pData) + y * mapped.RowPitch,
                        static_cast<std::size_t>(surface.width) * 4);
        context->Unmap(readback.Get(), 0);
        ++stats.captures;
    }
};
GraphicsPresenter::GraphicsPresenter(const SurfaceSnapshot &state, std::uint64_t token, bool capture)
    : impl_(std::make_unique<Impl>(state, token, capture)) {}
GraphicsPresenter::~GraphicsPresenter() = default;
bool GraphicsPresenter::resize(const SurfaceSnapshot &state) {
    auto &p = *impl_;
    p.check();
    require(HostSurface::valid_snapshot(state) && state.window == p.surface.window &&
                state.binding == p.surface.binding && state.owner == p.surface.owner,
            "Cannot replace the window lifetime during resize");
    if (state.width == p.surface.width && state.height == p.surface.height)
        return false;
    require(p.binding.generation < 65535, "Shared texture generation quota reached");
    p.checked(
        AETHER_PRESENT_CALL(resize, p.swap->ResizeBuffers(2, state.width, state.height,
                                                          DXGI_FORMAT_R8G8B8A8_UNORM, Impl::swap_flags)),
        "IDXGISwapChain::ResizeBuffers");
    p.surface = state;
    ++p.binding.generation;
    p.create_texture();
    ++p.stats.resizes;
    return true;
}
graphics::SharedWindowGrant GraphicsPresenter::grant() const {
    impl_->check();
    return impl_->binding;
}
void GraphicsPresenter::present() {
    auto &p = *impl_;
    p.check();
    p.checked(AETHER_PRESENT_CALL(acquire, p.mutex->AcquireSync(p.key, 1000)), "IDXGIKeyedMutex::AcquireSync",
              true);
    Microsoft::WRL::ComPtr<ID3D11Texture2D> backbuffer;
    p.checked(AETHER_PRESENT_CALL(buffer, p.swap->GetBuffer(0, IID_PPV_ARGS(&backbuffer))),
              "IDXGISwapChain::GetBuffer");
    for (unsigned y = 0; y < p.surface.height; ++y) {
        const D3D11_BOX row{0, y, 0, p.surface.width, y + 1, 1};
        p.context->CopySubresourceRegion(backbuffer.Get(), 0, 0, p.surface.height - 1 - y, 0, p.texture.Get(),
                                         0, &row);
    }
    p.context->Flush();
    p.checked(p.mutex->ReleaseSync(p.key + 1), "IDXGIKeyedMutex::ReleaseSync", true);
    p.key += 2;
    if (p.capture)
        p.readback(backbuffer.Get());
    require(WaitForSingleObject(p.latency.get(), 1000) == WAIT_OBJECT_0, "Presentation queue stalled");
    const auto status = AETHER_PRESENT_CALL(present, p.swap->Present(0, DXGI_PRESENT_DO_NOT_WAIT));
    if (status != DXGI_STATUS_OCCLUDED && status != DXGI_ERROR_WAS_STILL_DRAWING)
        p.checked(status, "IDXGISwapChain::Present", true);
    ++p.stats.frames;
    p.stats.occluded += status == DXGI_STATUS_OCCLUDED;
    p.stats.busy +=
        status == DXGI_ERROR_WAS_STILL_DRAWING; // Drop this submission; never replay a guest draw.
}
const PresentationMetrics &GraphicsPresenter::metrics() const noexcept { return impl_->stats; }
const std::vector<std::uint8_t> &GraphicsPresenter::pixels() const noexcept { return impl_->pixels; }
} // namespace aether::host
