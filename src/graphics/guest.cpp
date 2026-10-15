#include "aether/common/text.hpp"
#include "guest_internal.hpp"
#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <bit>
#include <d3d11.h>
#include <dxgi.h>
#include <format>
#include <limits>
#include <wrl/client.h>

namespace aether::graphics {
#ifdef AETHER_GRAPHICS_CONTEXT_TESTING
namespace testing {
void before_shared_rebind(std::uint64_t app_id, std::string_view stage, EGLDisplay display);
}
#endif
namespace {
constexpr std::array<ApiEntry, static_cast<std::size_t>(Operation::count)> entries{
    {ApiEntry{"libEGL.so", "eglGetDisplay"},
     {"libEGL.so", "eglInitialize"},
     {"libEGL.so", "eglChooseConfig"},
     {"libEGL.so", "eglBindAPI"},
     {"libEGL.so", "eglCreateContext"},
     {"libEGL.so", "eglCreatePbufferSurface"},
     {"libEGL.so", "eglCreateWindowSurface"},
     {"libEGL.so", "eglMakeCurrent"},
     {"libEGL.so", "eglDestroyContext"},
     {"libEGL.so", "eglDestroySurface"},
     {"libEGL.so", "eglTerminate"},
     {"libEGL.so", "eglQuerySurface"},
     {"libEGL.so", "eglSwapBuffers"},
     {"libEGL.so", "eglGetError"},
     {"libEGL.so", "eglGetProcAddress"},
     {"libEGL.so", "eglGetCurrentContext"},
     {"libEGL.so", "eglGetCurrentDisplay"},
     {"libEGL.so", "eglGetCurrentSurface"},
     {"libEGL.so", "eglQueryString"},
     {"libEGL.so", "eglReleaseThread"},
     {"libGLESv2.so", "glCreateShader"},
     {"libGLESv2.so", "glShaderSource"},
     {"libGLESv2.so", "glCompileShader"},
     {"libGLESv2.so", "glGetShaderiv"},
     {"libGLESv2.so", "glGetShaderInfoLog"},
     {"libGLESv2.so", "glDeleteShader"},
     {"libGLESv2.so", "glCreateProgram"},
     {"libGLESv2.so", "glAttachShader"},
     {"libGLESv2.so", "glBindAttribLocation"},
     {"libGLESv2.so", "glLinkProgram"},
     {"libGLESv2.so", "glGetProgramiv"},
     {"libGLESv2.so", "glGetProgramInfoLog"},
     {"libGLESv2.so", "glUseProgram"},
     {"libGLESv2.so", "glGetUniformLocation"},
     {"libGLESv2.so", "glUniform4f"},
     {"libGLESv2.so", "glDeleteProgram"},
     {"libGLESv2.so", "glGenBuffers"},
     {"libGLESv2.so", "glBindBuffer"},
     {"libGLESv2.so", "glBufferData"},
     {"libGLESv2.so", "glDeleteBuffers"},
     {"libGLESv2.so", "glVertexAttribPointer"},
     {"libGLESv2.so", "glEnableVertexAttribArray"},
     {"libGLESv2.so", "glDisableVertexAttribArray"},
     {"libGLESv2.so", "glViewport"},
     {"libGLESv2.so", "glClearColor"},
     {"libGLESv2.so", "glClear"},
     {"libGLESv2.so", "glEnable"},
     {"libGLESv2.so", "glDisable"},
     {"libGLESv2.so", "glPixelStorei"},
     {"libGLESv2.so", "glDrawArrays"},
     {"libGLESv2.so", "glReadPixels"},
     {"libGLESv2.so", "glGetError"},
     {"libGLESv2.so", "glFinish"},
     {"libGLESv2.so", "glGetString"}}};
static_assert(entries.size() == static_cast<std::size_t>(Operation::count));
std::atomic<std::uint64_t> next_identity{1};
std::uint64_t identity() {
    auto value = next_identity.load();
    do {
        if (value >= 0x7fffffff)
            unsupported("Graphics identity space exhausted");
    } while (!next_identity.compare_exchange_weak(value, value + 1));
    return value;
}
Token token() { return 0xa6e0000000000000ULL | identity(); }
EGLint integer(std::uint64_t value) { return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value)); }
} // namespace

std::span<const ApiEntry> api_registry() noexcept { return entries; }
GuestGraphicsServices::Impl::Impl(a64::GuestMemory &m, const a64::AppContext &a, GraphicsChannel *remote)
    : memory(m), channel(remote), app(a), display_key(static_cast<EGLint>(identity())) {}
GuestGraphicsServices::Impl::~Impl() { close(); }
void GuestGraphicsServices::Impl::readable(a64::Address address, std::size_t size) const {
    if (size && !memory.accessible(address, size, a64::Permission::read))
        throw Rejection{a64::Fault::read, "Graphics input is outside readable guest memory"};
}
void GuestGraphicsServices::Impl::writable(a64::Address address, std::size_t size) const {
    if (size && !memory.accessible(address, size, a64::Permission::write))
        throw Rejection{a64::Fault::write, "Graphics output is outside writable guest memory"};
}
std::uint64_t GuestGraphicsServices::Impl::read(a64::Address address, std::size_t size) const {
    std::array<std::uint8_t, 8> data{};
    if (size > data.size() || !memory.read(address, std::span{data}.first(size)))
        throw Rejection{a64::Fault::read, "Cannot read a graphics ABI value from guest memory"};
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < size; ++i)
        value |= std::uint64_t{data[i]} << (i * 8);
    return value;
}
void GuestGraphicsServices::Impl::write(a64::Address address, std::uint64_t value, std::size_t size) {
    std::array<std::uint8_t, 8> data{};
    if (size > data.size())
        throw Rejection{a64::Fault::write, "Graphics ABI output width is invalid"};
    for (std::size_t i = 0; i < size; ++i)
        data[i] = static_cast<std::uint8_t>(value >> (i * 8));
    copy_output(address, std::span{data}.first(size));
}
void GuestGraphicsServices::Impl::copy_output(a64::Address address, std::span<const std::uint8_t> bytes) {
    if (!memory.write(address, bytes))
        throw Rejection{a64::Fault::write, "Cannot copy graphics output to guest memory"};
    if (observed && !bytes.empty()) {
        if (observed->size() >= 1024)
            unsupported("Graphics output write count exceeds 1024");
        observed->push_back({address, {bytes.begin(), bytes.end()}});
    }
}
std::vector<std::uint8_t> GuestGraphicsServices::Impl::bytes(a64::Address address, std::size_t size) const {
    if (size > maximum_transfer)
        unsupported("Graphics memory transfer exceeds 4 MiB");
    readable(address, size);
    std::vector<std::uint8_t> data(size);
    if (size && !memory.read(address, data))
        throw Rejection{a64::Fault::read, "Graphics input changed during marshalling"};
    return data;
}
std::string GuestGraphicsServices::Impl::text(a64::Address address, std::size_t limit) const {
    if (address >= a64::GuestMemory::address_limit || limit > maximum_transfer)
        throw Rejection{a64::Fault::read, "Invalid graphics string address or length"};
    std::string value;
    for (std::size_t i = 0; i < limit; ++i) {
        const auto byte = static_cast<char>(read(address + i, 1));
        if (!byte)
            return value;
        value.push_back(byte);
    }
    unsupported("Graphics string is not terminated within its limit");
}
a64::Address GuestGraphicsServices::Impl::string_result(std::string value) {
    if (const auto found = strings.find(value); found != strings.end())
        return found->second;
    if (value.size() >= 4096 || string_pages.size() >= 16)
        unsupported("Graphics query strings exceed the 16-page quota");
    const auto address = 0x70000 + string_pages.size() * a64::GuestMemory::page_size;
    string_pages.reserve(string_pages.size() + 1);
    memory.map(address, 4096, a64::read_write);
    string_pages.push_back(address);
    std::vector<std::uint8_t> data(value.begin(), value.end());
    data.push_back(0);
    if (!memory.write(address, data))
        throw Rejection{a64::Fault::write, "Cannot initialize a graphics query string"};
    memory.protect(address, a64::Permission::read);
    strings.emplace(std::move(value), address);
    return address;
}
std::vector<EGLint> GuestGraphicsServices::Impl::attribute_list(a64::Address address,
                                                                std::span<const EGLint> allowed) const {
    std::vector<EGLint> result;
    if (address) {
        for (std::size_t i = 0; i <= 32; ++i) {
            if (address >= a64::GuestMemory::address_limit)
                throw Rejection{a64::Fault::read, "Invalid EGL attribute-list address"};
            const auto name = integer(read(address + i * 8, 4));
            if (name == EGL_NONE) {
                result.push_back(EGL_NONE);
                return result;
            }
            if (i == 32)
                unsupported("EGL attribute list exceeds 32 pairs or lacks EGL_NONE");
            if (std::find(allowed.begin(), allowed.end(), name) == allowed.end())
                throw EglFailure{EGL_BAD_ATTRIBUTE};
            result.push_back(name);
            result.push_back(integer(read(address + i * 8 + 4, 4)));
        }
        unsupported("EGL attribute list exceeds 32 pairs or lacks EGL_NONE");
    }
    result.push_back(EGL_NONE);
    return result;
}
void GuestGraphicsServices::Impl::require_display(Token value, bool ready) const {
    if (!display_token || value != display_token)
        throw EglFailure{EGL_BAD_DISPLAY};
    if (ready && !initialized)
        throw EglFailure{EGL_NOT_INITIALIZED};
}
EGLConfig GuestGraphicsServices::Impl::config(Token value) const {
    const auto found = configs.find(value);
    if (found == configs.end())
        throw EglFailure{EGL_BAD_CONFIG};
    return found->second;
}
GuestGraphicsServices::Impl::Surface &GuestGraphicsServices::Impl::surface(Token value, bool allow_deleted) {
    const auto found = surfaces.find(value);
    if (found == surfaces.end() || (found->second.deleted && !allow_deleted))
        throw EglFailure{EGL_BAD_SURFACE};
    return found->second;
}
host::HostSurface &GuestGraphicsServices::Impl::window(Token value) const {
    const auto found = windows.find(value);
    if (found == windows.end() || !found->second->alive())
        throw EglFailure{EGL_BAD_NATIVE_WINDOW};
    try {
        (void)found->second->extent();
    } catch (const a64::GuestError &) {
        throw EglFailure{EGL_BAD_NATIVE_WINDOW};
    }
    return *found->second;
}
void GuestGraphicsServices::Impl::validate_window_surface(const Surface &value) const {
    if (value.window && (!shared_window || value.window != shared_window->grant.token))
        (void)window(value.window);
}
bool GuestGraphicsServices::Impl::egl_result(EGLBoolean value) {
    if (value == EGL_FALSE)
        throw EglFailure{eglGetError()};
    return true;
}
void GuestGraphicsServices::Impl::egl_error(EGLint value) noexcept {
    egl_pending = value;
    ++stats.api_errors;
}
void GuestGraphicsServices::Impl::gl_error(GLenum value) noexcept {
    if (gl_pending == GL_NO_ERROR)
        gl_pending = value;
    ++stats.api_errors;
}
bool GuestGraphicsServices::Impl::gl_result() {
    const auto reset = glGetGraphicsResetStatusEXT();
    if (reset != GL_NO_ERROR)
        throw GlFailure{GL_CONTEXT_LOST_KHR, reset};
    bool clean = true;
    // Drain the finite native error set: an ordinary error must not hide context loss.
    for (unsigned i = 0; i < 16; ++i) {
        const auto value = glGetError();
        if (value == GL_CONTEXT_LOST_KHR)
            throw GlFailure{value};
        if (value == GL_NO_ERROR)
            return clean;
        gl_error(value);
        clean = false;
    }
    throw Rejection{a64::Fault::windows_service, "ANGLE error set exceeded its bounded drain"};
}
void GuestGraphicsServices::Impl::lose_context(const char *message) noexcept {
    if (context_failed)
        return;
    context_failed = true;
    error = message;
    ++stats.api_errors;
    ++stats.rejected;
    if (observed)
        observed->clear();
    close();
}
void GuestGraphicsServices::Impl::update_counts() noexcept {
    stats.contexts = context == EGL_NO_CONTEXT ? 0 : 1;
    stats.surfaces = surfaces.size();
    stats.shaders = shaders.size();
    stats.programs = programs.size();
    stats.buffers = buffers.size();
    stats.window_bindings = windows.size() + (shared_window ? 1 : 0);
    stats.window_surfaces = static_cast<std::size_t>(std::count_if(
        surfaces.begin(), surfaces.end(), [](const auto &entry) { return entry.second.window != 0; }));
}
void GuestGraphicsServices::Impl::reset_gl() noexcept {
    shaders.clear();
    programs.clear();
    buffers.clear();
    stats.buffer_bytes = 0;
    array_buffer = 0;
    pack_alignment = 4;
    attributes = {};
    gl_pending = GL_NO_ERROR;
    update_counts();
}
void GuestGraphicsServices::Impl::collect_deleted() {
    for (auto it = surfaces.begin(); it != surfaces.end();) {
        if (it->second.deleted && it->first != draw_surface && it->first != read_surface) {
            egl_result(eglDestroySurface(display, it->second.native));
            it = surfaces.erase(it);
        } else
            ++it;
    }
    if (context_deleted && !current) {
        egl_result(eglDestroyContext(display, context));
        context = EGL_NO_CONTEXT;
        context_token = 0;
        context_deleted = false;
        reset_gl();
    }
    if (!initialized && driver_initialized && !current) {
        if (shared_window && !shared_window->release_device())
            throw Rejection{a64::Fault::windows_service, "Cannot release shared device before termination"};
        egl_result(eglTerminate(display));
        driver_initialized = false;
    }
    update_counts();
}
void GuestGraphicsServices::Impl::collect_gl() {
    for (auto it = shaders.begin(); it != shaders.end();) {
        if (it->second && !glIsShader(it->first))
            it = shaders.erase(it);
        else
            ++it;
    }
    for (auto it = programs.begin(); it != programs.end();) {
        if (it->second && !glIsProgram(it->first))
            it = programs.erase(it);
        else
            ++it;
    }
    update_counts();
}
void GuestGraphicsServices::Impl::activate() {
    if (!current || context == EGL_NO_CONTEXT)
        unsupported("GLES call requires this app's current EGL context");
    try {
        validate_window_surface(surface(draw_surface, true));
        validate_window_surface(surface(read_surface, true));
    } catch (const EglFailure &) {
        throw Rejection{a64::Fault::windows_service, "GLES current surface has an invalid native window"};
    }
    if (shared_window && (surface(draw_surface, true).window == shared_window->grant.token ||
                          surface(read_surface, true).window == shared_window->grant.token))
        shared_window->acquire();
    if (eglGetCurrentContext() != context || eglGetCurrentDisplay() != display) {
        if (!eglMakeCurrent(display, surface(draw_surface, true).native, surface(read_surface, true).native,
                            context)) {
            const auto status = eglGetError();
            if (status == EGL_CONTEXT_LOST)
                throw EglFailure{status};
            throw Rejection{a64::Fault::windows_service, "Cannot activate this app's graphics context"};
        }
    }
}
void GuestGraphicsServices::Impl::inspect_device() {
    EGLAttrib device = 0, native = 0;
    egl_result(eglQueryDisplayAttribEXT(display, EGL_DEVICE_EXT, &device));
    egl_result(
        eglQueryDeviceAttribEXT(reinterpret_cast<EGLDeviceEXT>(device), EGL_D3D11_DEVICE_ANGLE, &native));
    if (!native)
        throw Rejection{a64::Fault::windows_service, "ANGLE did not return its D3D11 device"};
    auto *d3d = reinterpret_cast<ID3D11Device *>(native);
    Microsoft::WRL::ComPtr<IDXGIDevice> dxgi;
    Microsoft::WRL::ComPtr<IDXGIAdapter> adapter;
    Microsoft::WRL::ComPtr<IDXGIAdapter1> adapter1;
    DXGI_ADAPTER_DESC1 description{};
    if (FAILED(d3d->QueryInterface(IID_PPV_ARGS(&dxgi))) || FAILED(dxgi->GetAdapter(&adapter)) ||
        FAILED(adapter.As(&adapter1)) || FAILED(adapter1->GetDesc1(&description)))
        throw Rejection{a64::Fault::windows_service, "Cannot inspect the D3D11 hardware adapter"};
    info.hardware = (description.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) == 0;
    if (!info.hardware)
        throw Rejection{a64::Fault::windows_service, "Hardware graphics required; software adapter rejected"};
    info.adapter = utf8(description.Description);
    info.vendor_id = description.VendorId;
    info.device_id = description.DeviceId;
    info.feature_level = static_cast<std::uint32_t>(d3d->GetFeatureLevel());
}
void GuestGraphicsServices::Impl::inspect_context() {
    const auto query = [this](GLenum name) {
        const auto *value = glGetString(name);
        (void)gl_result();
        if (!value)
            throw Rejection{a64::Fault::windows_service, "Cannot read the ANGLE context identity"};
        return std::string(reinterpret_cast<const char *>(value));
    };
    info.renderer = query(GL_RENDERER);
    info.vendor = query(GL_VENDOR);
    info.version = query(GL_VERSION);
}
void GuestGraphicsServices::Impl::close() noexcept {
    if (closed)
        return;
    if (channel) {
        try {
            auto result = channel->close();
            stats = result.metrics;
            info = std::move(result.host);
        } catch (...) {
            ++stats.cleanup_failures;
        }
    } else {
        if (context != EGL_NO_CONTEXT && eglGetCurrentContext() == context)
            if (!eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT))
                ++stats.cleanup_failures;
        // A lost ANGLE display rejects per-object destruction. Once unbound, terminating
        // this app's exclusive display destroys its contexts and surfaces together.
        if (!context_failed) {
            for (const auto &[id, value] : surfaces) {
                (void)id;
                if (!eglDestroySurface(display, value.native))
                    ++stats.cleanup_failures;
            }
            if (context != EGL_NO_CONTEXT && !eglDestroyContext(display, context))
                ++stats.cleanup_failures;
        }
        surfaces.clear();
        if (shared_window && !shared_window->release_device())
            ++stats.cleanup_failures;
        shared_window.reset();
        if (driver_initialized && !eglTerminate(display))
            ++stats.cleanup_failures;
        if (display != EGL_NO_DISPLAY && eglGetCurrentContext() == EGL_NO_CONTEXT && !eglReleaseThread())
            ++stats.cleanup_failures;
        context = EGL_NO_CONTEXT;
        display = EGL_NO_DISPLAY;
        current = draw_surface = read_surface = context_token = display_token = 0;
        initialized = false;
        driver_initialized = false;
        configs.clear();
        windows.clear();
        reset_gl();
    }
    const auto unmap = [&](a64::Address address) {
        try {
            memory.unmap(address);
        } catch (...) {
            ++stats.cleanup_failures;
        }
    };
    for (const auto address : string_pages)
        unmap(address);
    string_pages.clear();
    strings.clear();
    if (trampoline_owned)
        unmap(GuestGraphicsServices::trampoline_base);
    trampoline_owned = false;
    closed = true;
}

std::uint64_t GuestGraphicsServices::Impl::dispatch_egl(Operation op, a64::ServiceState &state) {
    const auto &r = state.registers;
    switch (op) {
    case Operation::egl_error: {
        const auto value = egl_pending;
        egl_pending = EGL_SUCCESS;
        return static_cast<std::uint32_t>(value);
    }
    case Operation::proc_address: {
        const auto name = text(r[0], 256);
        for (std::size_t i = 0; i < entries.size(); ++i)
            if (entries[i].name == name)
                return GuestGraphicsServices::trampoline_base + i * 8;
        return 0;
    }
    case Operation::get_display:
        if (r[0])
            throw EglFailure{EGL_BAD_PARAMETER};
        if (display == EGL_NO_DISPLAY) {
            const auto id = token();
            if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32))
                throw Rejection{a64::Fault::windows_service,
                                "Cannot restrict graphics DLL loading to System32"};
            std::vector<EGLint> attrs{
                EGL_PLATFORM_ANGLE_TYPE_ANGLE,        EGL_PLATFORM_ANGLE_TYPE_D3D11_ANGLE,
                EGL_PLATFORM_ANGLE_DEVICE_TYPE_ANGLE, EGL_PLATFORM_ANGLE_DEVICE_TYPE_HARDWARE_ANGLE,
                EGL_PLATFORM_ANGLE_DISPLAY_KEY_ANGLE, display_key};
            if (shared_window) {
                attrs.insert(attrs.end(), {EGL_PLATFORM_ANGLE_D3D_LUID_LOW_ANGLE,
                                           std::bit_cast<EGLint>(shared_window->grant.luid_low),
                                           EGL_PLATFORM_ANGLE_D3D_LUID_HIGH_ANGLE,
                                           std::bit_cast<EGLint>(shared_window->grant.luid_high)});
            }
            attrs.push_back(EGL_NONE);
            display = eglGetPlatformDisplayEXT(EGL_PLATFORM_ANGLE_ANGLE, EGL_DEFAULT_DISPLAY, attrs.data());
            if (display == EGL_NO_DISPLAY)
                throw EglFailure{eglGetError()};
            display_token = id;
        }
        return display_token;
    case Operation::initialize: {
        require_display(r[0], false);
        if (r[1])
            writable(r[1], 4);
        if (r[2])
            writable(r[2], 4);
        EGLint major = 0, minor = 0;
        egl_result(eglInitialize(display, &major, &minor));
        initialized = true;
        driver_initialized = true;
        try {
            inspect_device();
        } catch (...) {
            eglTerminate(display);
            initialized = driver_initialized = false;
            throw;
        }
        if (r[1])
            write(r[1], static_cast<std::uint32_t>(major), 4);
        if (r[2])
            write(r[2], static_cast<std::uint32_t>(minor), 4);
        return EGL_TRUE;
    }
    case Operation::bind_api:
        if (r[0] != EGL_OPENGL_ES_API)
            throw EglFailure{EGL_BAD_PARAMETER};
        return egl_result(eglBindAPI(EGL_OPENGL_ES_API));
    case Operation::current_context:
        return current;
    case Operation::current_display:
        return current ? display_token : 0;
    case Operation::current_surface:
        if (r[0] != EGL_DRAW && r[0] != EGL_READ)
            throw EglFailure{EGL_BAD_PARAMETER};
        return r[0] == EGL_DRAW ? draw_surface : read_surface;
    case Operation::release_thread:
        if (context != EGL_NO_CONTEXT && eglGetCurrentContext() == context)
            egl_result(eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT));
        current = draw_surface = read_surface = 0;
        collect_deleted();
        egl_pending = EGL_SUCCESS;
        return EGL_TRUE;
    default:
        break;
    }
    require_display(r[0], op != Operation::terminate && op != Operation::make_current);
    switch (op) {
    case Operation::choose_config: {
        constexpr std::array allowed{EGL_RED_SIZE,       EGL_GREEN_SIZE,    EGL_BLUE_SIZE,
                                     EGL_ALPHA_SIZE,     EGL_DEPTH_SIZE,    EGL_STENCIL_SIZE,
                                     EGL_BUFFER_SIZE,    EGL_SURFACE_TYPE,  EGL_RENDERABLE_TYPE,
                                     EGL_CONFIG_ID,      EGL_CONFIG_CAVEAT, EGL_SAMPLES,
                                     EGL_SAMPLE_BUFFERS, EGL_CONFORMANT,    EGL_NATIVE_RENDERABLE};
        const auto attrs = attribute_list(r[1], allowed);
        const auto count = integer(r[3]);
        if (count < 0)
            throw EglFailure{EGL_BAD_PARAMETER};
        if (count > 32)
            unsupported("eglChooseConfig output exceeds 32 configurations");
        writable(r[4], 4);
        if (r[2])
            writable(r[2], static_cast<std::size_t>(count) * 8);
        std::array<EGLConfig, 32> result{};
        EGLint found = 0;
        egl_result(eglChooseConfig(display, attrs.data(), r[2] ? result.data() : nullptr, count, &found));
        if (r[2]) {
            for (EGLint i = 0; i < found; ++i) {
                auto it = std::find_if(configs.begin(), configs.end(),
                                       [&](const auto &entry) { return entry.second == result[i]; });
                if (it == configs.end()) {
                    if (configs.size() >= 128)
                        unsupported("EGL configuration handle quota exceeded");
                    it = configs.emplace(token(), result[i]).first;
                }
                write(r[2] + static_cast<std::size_t>(i) * 8, it->first, 8);
            }
        }
        write(r[4], static_cast<std::uint32_t>(found), 4);
        return EGL_TRUE;
    }
    case Operation::create_context: {
        const auto selected = config(r[1]);
        if (r[2]) {
            if (r[2] != context_token || context_deleted)
                throw EglFailure{EGL_BAD_CONTEXT};
            unsupported("Shared guest EGL contexts are not implemented");
        }
        constexpr std::array allowed{EGL_CONTEXT_CLIENT_VERSION};
        const auto attrs = attribute_list(r[3], allowed);
        EGLint version = 1;
        for (std::size_t i = 0; i + 1 < attrs.size(); i += 2)
            version = attrs[i + 1];
        if (version != 2)
            throw EglFailure{EGL_BAD_MATCH};
        if (context != EGL_NO_CONTEXT)
            throw EglFailure{EGL_BAD_ALLOC};
        const auto id = token();
        // Require ANGLE's compiler limits without changing GLES into a WebGL context.
        // Context creation fails if the pinned backend cannot provide this policy.
        const EGLint host_attrs[]{EGL_CONTEXT_CLIENT_VERSION,
                                  2,
                                  EGL_CONTEXT_OPENGL_BACKWARDS_COMPATIBLE_ANGLE,
                                  EGL_FALSE,
                                  EGL_CONTEXT_HARDENED_ANGLE,
                                  EGL_TRUE,
                                  EGL_ROBUST_RESOURCE_INITIALIZATION_ANGLE,
                                  EGL_TRUE,
                                  EGL_CONTEXT_OPENGL_RESET_NOTIFICATION_STRATEGY_EXT,
                                  EGL_LOSE_CONTEXT_ON_RESET_EXT,
                                  EGL_NONE};
        context = eglCreateContext(display, selected, EGL_NO_CONTEXT, host_attrs);
        if (context == EGL_NO_CONTEXT)
            throw EglFailure{eglGetError()};
        context_token = id;
        context_deleted = false;
        reset_gl();
        return id;
    }
    case Operation::create_pbuffer: {
        const auto selected = config(r[1]);
        constexpr std::array allowed{EGL_WIDTH, EGL_HEIGHT};
        const auto attrs = attribute_list(r[2], allowed);
        EGLint width = 0, height = 0;
        for (std::size_t i = 0; i + 1 < attrs.size(); i += 2)
            (attrs[i] == EGL_WIDTH ? width : height) = attrs[i + 1];
        if (width < 0 || height < 0)
            throw EglFailure{EGL_BAD_PARAMETER};
        if (!width || !height || width > 1024 || height > 1024 || surfaces.size() >= 4)
            throw EglFailure{EGL_BAD_ALLOC};
        const auto id = token();
        const auto native = eglCreatePbufferSurface(display, selected, attrs.data());
        if (native == EGL_NO_SURFACE)
            throw EglFailure{eglGetError()};
        try {
            surfaces.emplace(id, Surface{native, width, height});
        } catch (...) {
            eglDestroySurface(display, native);
            throw;
        }
        update_counts();
        return id;
    }
    case Operation::create_window: {
        const auto selected = config(r[1]);
        const bool shared = shared_window && shared_window->grant.token == r[2];
        const auto size =
            shared ? std::array<unsigned, 2>{shared_window->grant.width, shared_window->grant.height}
                   : window(r[2]).extent();
        const auto attrs = attribute_list(r[3], {}); // No optional window attributes in this subset.
        if (surfaces.size() >= 4 || std::any_of(surfaces.begin(), surfaces.end(), [&](const auto &entry) {
                return entry.second.window == r[2];
            }))
            throw EglFailure{EGL_BAD_ALLOC};
        if (!size[0] || !size[1])
            throw EglFailure{EGL_BAD_NATIVE_WINDOW};
        const auto id = token();
        const auto native =
            shared ? shared_window->create_surface(display, selected)
                   : eglCreateWindowSurface(display, selected, window(r[2]).native_window(), attrs.data());
        if (native == EGL_NO_SURFACE)
            throw EglFailure{eglGetError()};
        try {
            surfaces.emplace(id, Surface{native, static_cast<EGLint>(size[0]), static_cast<EGLint>(size[1]),
                                         false, r[2], selected});
        } catch (...) {
            eglDestroySurface(display, native);
            throw;
        }
        return id;
    }
    case Operation::make_current:
        if (!r[3]) {
            if (r[1] || r[2])
                throw EglFailure{EGL_BAD_MATCH};
            if (context != EGL_NO_CONTEXT && eglGetCurrentContext() == context)
                egl_result(eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT));
            current = draw_surface = read_surface = 0;
        } else {
            if (!initialized)
                throw EglFailure{EGL_NOT_INITIALIZED};
            if (r[3] != context_token || context_deleted)
                throw EglFailure{EGL_BAD_CONTEXT};
            const auto &draw_surface_value = surface(r[1]);
            const auto &read_surface_value = surface(r[2]);
            validate_window_surface(draw_surface_value);
            validate_window_surface(read_surface_value);
            if (shared_window && (draw_surface_value.window == shared_window->grant.token ||
                                  read_surface_value.window == shared_window->grant.token))
                shared_window->acquire();
            const auto draw = draw_surface_value.native;
            const auto read_buffer = read_surface_value.native;
            egl_result(eglMakeCurrent(display, draw, read_buffer, context));
            current = r[3];
            draw_surface = r[1];
            read_surface = r[2];
            inspect_context();
        }
        collect_deleted();
        return EGL_TRUE;
    case Operation::destroy_context:
        if (r[1] != context_token || !context_token || context_deleted)
            throw EglFailure{EGL_BAD_CONTEXT};
        context_deleted = true;
        collect_deleted();
        return EGL_TRUE;
    case Operation::destroy_surface:
        surface(r[1]).deleted = true;
        collect_deleted();
        return EGL_TRUE;
    case Operation::terminate:
        if (initialized) {
            // Keep logically current objects alive until this guest releases them, even when another
            // app is using the same Windows owner thread. Their guest handles immediately expire.
            for (auto &[id, value] : surfaces) {
                (void)id;
                value.deleted = true;
            }
            context_deleted = context != EGL_NO_CONTEXT;
            initialized = false;
            configs.clear();
            collect_deleted();
        }
        return EGL_TRUE;
    case Operation::query_surface: {
        auto &value = surface(r[1]);
        validate_window_surface(value);
        if (shared_window && value.window == shared_window->grant.token && r[2] != EGL_WIDTH &&
            r[2] != EGL_HEIGHT)
            unsupported("Shared window queries support EGL_WIDTH and EGL_HEIGHT only");
        writable(r[3], 4);
        EGLint result = 0;
        egl_result(eglQuerySurface(display, value.native, integer(r[2]), &result));
        write(r[3], static_cast<std::uint32_t>(result), 4);
        return EGL_TRUE;
    }
    case Operation::swap_buffers: {
        const auto &value = surface(r[1]);
        validate_window_surface(value);
        // ANGLE's swap uses the calling thread's GL context. Restore this logical guest first.
        if (!current)
            unsupported("eglSwapBuffers requires this guest's current context in the supported subset");
        activate();
        egl_result(eglSwapBuffers(display, value.native));
        glFinish(); // Check loss before acknowledging or publishing either surface type.
        if (!gl_result())
            throw Rejection{a64::Fault::windows_service, "Cannot finish the rendered frame"};
        if (shared_window && value.window == shared_window->grant.token) {
            egl_result(eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT));
            shared_window->publish();
        }
        ++stats.swaps;
        if (value.window)
            ++stats.window_swaps;
        return EGL_TRUE;
    }
    case Operation::query_string: {
        if (r[1] == EGL_EXTENSIONS)
            return string_result("");
        if (r[1] != EGL_VENDOR && r[1] != EGL_VERSION && r[1] != EGL_CLIENT_APIS)
            throw EglFailure{EGL_BAD_PARAMETER};
        const auto *value = eglQueryString(display, integer(r[1]));
        if (!value)
            throw EglFailure{eglGetError()};
        return string_result(value);
    }
    default:
        unsupported("Unregistered EGL operation");
    }
}

GuestGraphicsServices::GuestGraphicsServices(a64::GuestMemory &memory, const a64::AppContext &app,
                                             GraphicsChannel *channel)
    : impl_(std::make_unique<Impl>(memory, app, channel)) {
    memory.map(trampoline_base, 4096, a64::read_write);
    impl_->trampoline_owned = true;
    for (std::size_t i = 0; i < entries.size(); ++i) {
        impl_->write(trampoline_base + i * 8, 0xd4000001u | ((first_service + i) << 5), 4);
        impl_->write(trampoline_base + i * 8 + 4, 0xd65f03c0u, 4);
    }
    memory.protect(trampoline_base, a64::read_execute);
}
GuestGraphicsServices::~GuestGraphicsServices() = default;
bool GuestGraphicsServices::handles_service(std::uint32_t service) noexcept {
    return service >= first_service && service - first_service < entries.size();
}
bool GuestGraphicsServices::has_library(std::string_view library) const noexcept {
    return library == "libEGL.so" || library == "libGLESv2.so";
}
std::optional<elf::GuestSymbol> GuestGraphicsServices::resolve(std::string_view library,
                                                               std::string_view name,
                                                               std::string_view version) const {
    const auto expected_version = library == "libEGL.so" ? "LIBEGL" : "LIBGLESV2";
    if (impl_->closed || (!version.empty() && version != expected_version))
        return std::nullopt;
    for (std::size_t i = 0; i < entries.size(); ++i)
        if (entries[i].library == library && entries[i].name == name)
            return elf::GuestSymbol{
                std::string(name), std::string(library), std::string(version), trampoline_base + i * 8, 8, 2};
    return std::nullopt;
}
a64::Fault GuestGraphicsServices::invoke(std::uint32_t service, a64::Address instruction,
                                         std::array<std::uint64_t, 31> &registers) noexcept {
    a64::ServiceState state;
    state.registers = registers;
    const auto result = invoke_frame(service, instruction, state);
    registers = state.registers;
    return result;
}
a64::Fault GuestGraphicsServices::invoke_frame(std::uint32_t service, a64::Address instruction,
                                               a64::ServiceState &state) noexcept {
    auto &p = *impl_;
    if (p.context_failed) {
        state.registers[0] = 0;
        return a64::Fault::windows_service;
    }
    p.error = {};
    try {
        if (p.owner != std::this_thread::get_id())
            throw Rejection{a64::Fault::invalid_call, "Graphics service belongs to another owner thread"};
        if (p.closed || !handles_service(service) ||
            instruction != trampoline_base + (service - first_service) * 8)
            unsupported("Graphics service trap is not at its live registered call site");
        if (!p.app.instance_id || !p.app.graphics_allowed)
            throw Rejection{a64::Fault::capability_denied, "This app has no graphics capability"};
        const auto op = static_cast<Operation>(service - first_service);
        if (p.channel) {
            const auto command =
                copy_command(op, state, p.memory, static_cast<std::uint32_t>(p.pack_alignment));
            auto result = p.channel->exchange(command);
            apply_outputs(command, result, state, p.memory);
            p.stats = result.metrics;
            p.info = std::move(result.host);
            p.remote_error = std::move(result.error);
            p.error = p.remote_error;
            if (result.string_result)
                state.registers[0] = p.string_result(std::move(result.text));
            else if (op == Operation::proc_address && result.value)
                state.registers[0] = trampoline_base + (result.value - 1) * 8;
            else
                state.registers[0] = result.value;
            p.pack_alignment = static_cast<GLint>(result.pack_alignment);
            return result.fault;
        }
        ++p.stats.calls;
        if (op < Operation::create_shader) {
            ++p.stats.egl_calls;
            state.registers[0] = p.dispatch_egl(op, state);
        } else {
            ++p.stats.gl_calls;
            state.registers[0] = p.dispatch_gl(op, state);
        }
        p.update_counts();
        return a64::Fault::none;
    } catch (const EglFailure &e) {
        if (e.error == EGL_CONTEXT_LOST) {
            p.lose_context("AETHER_GRAPHICS_CONTEXT_LOST: EGL_CONTEXT_LOST (0x300E)");
            state.registers[0] = 0;
            return a64::Fault::windows_service;
        }
        p.egl_error(e.error);
        state.registers[0] = 0;
        return a64::Fault::none;
    } catch (const GlFailure &e) {
        if (e.error == GL_CONTEXT_LOST_KHR) {
            const char *message = "AETHER_GRAPHICS_CONTEXT_LOST: GL_CONTEXT_LOST (0x0507)";
            if (e.reset == GL_GUILTY_CONTEXT_RESET_EXT)
                message = "AETHER_GRAPHICS_CONTEXT_LOST: GL reset 0x8253 (GUILTY_CONTEXT_RESET_EXT)";
            else if (e.reset == GL_INNOCENT_CONTEXT_RESET_EXT)
                message = "AETHER_GRAPHICS_CONTEXT_LOST: GL reset 0x8254 (INNOCENT_CONTEXT_RESET_EXT)";
            else if (e.reset == GL_UNKNOWN_CONTEXT_RESET_EXT)
                message = "AETHER_GRAPHICS_CONTEXT_LOST: GL reset 0x8255 (UNKNOWN_CONTEXT_RESET_EXT)";
            p.lose_context(message);
            state.registers[0] = 0;
            return a64::Fault::windows_service;
        }
        p.gl_error(e.error);
        state.registers[0] = 0;
        return a64::Fault::none;
    } catch (const GraphicsCopyError &e) {
        p.remote_error = e.what();
        p.error = p.remote_error;
        ++p.stats.rejected;
        return e.fault;
    } catch (const Rejection &e) {
        p.error = e.message;
        ++p.stats.rejected;
        return e.fault;
    } catch (const a64::GuestError &e) {
        p.remote_error = e.code + ": " + e.what();
        p.error = p.remote_error;
        ++p.stats.rejected;
        if (p.shared_window)
            p.close();
        return a64::Fault::windows_service;
    } catch (...) {
        p.error = "Host failure while marshalling a graphics call";
        ++p.stats.rejected;
        return a64::Fault::windows_service;
    }
}
a64::Fault GuestGraphicsServices::invoke_observed(std::uint32_t service, a64::ServiceState &state,
                                                  std::vector<ObservedWrite> &writes) {
    if (impl_->observed || impl_->channel || impl_->owner != std::this_thread::get_id())
        throw a64::GuestError("AETHER_GRAPHICS_COPY", "Invalid observed graphics invocation");
    impl_->observed = &writes;
    const auto result = invoke_frame(service, trampoline_base + (service - first_service) * 8, state);
    impl_->observed = nullptr;
    return result;
}
std::uint32_t GuestGraphicsServices::pack_alignment() const noexcept {
    return static_cast<std::uint32_t>(impl_->pack_alignment);
}
const Metrics &GuestGraphicsServices::metrics() const noexcept { return impl_->stats; }
const HostInfo &GuestGraphicsServices::host_info() const noexcept { return impl_->info; }
std::string_view GuestGraphicsServices::last_error() const noexcept { return impl_->error; }
std::uint64_t GuestGraphicsServices::attach_window(std::unique_ptr<host::HostSurface> surface) {
    auto &p = *impl_;
    if (p.owner != std::this_thread::get_id() || p.closed || !p.app.instance_id || !p.app.graphics_allowed)
        throw a64::GuestError("AETHER_GRAPHICS_WINDOW_BINDING",
                              "Window binding requires a live, authorized graphics owner");
    if (p.channel || !surface || !surface->alive() || !p.windows.empty() || p.shared_window)
        throw a64::GuestError("AETHER_GRAPHICS_WINDOW_BINDING",
                              "Exactly one live host window may be bound per guest");
    const auto id = token();
    p.windows.emplace(id, std::move(surface));
    p.update_counts();
    return id;
}
void GuestGraphicsServices::bind_shared_window(const SharedWindowGrant &grant) {
    auto &p = *impl_;
    const auto check = [](bool value, const char *message) {
        if (!value)
            throw a64::GuestError("AETHER_GRAPHICS_SHARED_WINDOW", message);
    };
    check(p.owner == std::this_thread::get_id() && !p.closed && p.app.graphics_allowed && !p.channel &&
              p.windows.empty() && grant.valid(),
          "Invalid trusted shared-window binding");
    if (!p.shared_window) {
        check(grant.generation == 1 && p.display == EGL_NO_DISPLAY,
              "Initial shared-window grant must precede display creation");
    } else {
        const auto &old = p.shared_window->grant;
        check(grant.token == old.token && grant.generation == old.generation + 1 &&
                  grant.luid_low == old.luid_low && grant.luid_high == old.luid_high &&
                  grant.handle != old.handle,
              "Stale, foreign or nonsequential shared-window replacement");
    }
    p.error = {};
    auto replacement = std::make_unique<SharedWindow>(grant);
    const char *stage = "activate previous surface";
    const auto terminal = [&](std::string message) {
        // Drop replacement device references before terminating this exclusive display.
        // eglTerminate also owns any newly created surface not yet committed to our map.
        if (replacement && !replacement->release_device())
            ++p.stats.cleanup_failures;
        replacement.reset();
        p.remote_error = std::move(message);
        p.lose_context(p.remote_error.c_str());
    };
    try {
        for (auto &[id, value] : p.surfaces) {
            (void)id;
            if (value.window != grant.token)
                continue;
            check(!value.deleted && p.driver_initialized, "Cannot replace a retired window surface");
#ifdef AETHER_GRAPHICS_CONTEXT_TESTING
            testing::before_shared_rebind(p.app.instance_id, "activate", p.display);
#endif
            if (p.current && p.context != EGL_NO_CONTEXT) {
                // Swap unbinds ANGLE. Reactivate the logical context so latent loss is
                // detected even when the native context is no longer current.
                p.activate();
                stage = "glFinish before resize";
#ifdef AETHER_GRAPHICS_CONTEXT_TESTING
                testing::before_shared_rebind(p.app.instance_id, "finish", p.display);
#endif
                glFinish();
                (void)p.gl_result(); // Ordinary pending errors do not conceal reset/loss.
                stage = "eglMakeCurrent unbind before resize";
                p.egl_result(eglMakeCurrent(p.display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT));
            }
            stage = "create replacement shared pbuffer";
#ifdef AETHER_GRAPHICS_CONTEXT_TESTING
            testing::before_shared_rebind(p.app.instance_id, "create", p.display);
#endif
            const auto surface = replacement->create_surface(p.display, value.config);
            if (surface == EGL_NO_SURFACE)
                throw EglFailure{eglGetError()};
            stage = "eglDestroySurface previous shared pbuffer";
#ifdef AETHER_GRAPHICS_CONTEXT_TESTING
            testing::before_shared_rebind(p.app.instance_id, "retire", p.display);
#endif
            // Read the first error before any cleanup call can replace EGL's last error.
            p.egl_result(eglDestroySurface(p.display, value.native));
            value.native = surface;
            value.width = static_cast<EGLint>(grant.width);
            value.height = static_cast<EGLint>(grant.height);
        }
        if (p.shared_window)
            check(p.shared_window->release_device(), "Cannot retire the previous shared texture");
        p.shared_window = std::move(replacement);
        p.update_counts();
    } catch (const EglFailure &failure) {
        terminal(std::format("AETHER_GRAPHICS_SHARED_WINDOW: {} failed (EGL 0x{:04X})", stage,
                             static_cast<std::uint32_t>(failure.error)));
    } catch (const GlFailure &failure) {
        terminal(std::format("AETHER_GRAPHICS_SHARED_WINDOW: {} failed (GL 0x{:04X}; reset 0x{:04X})", stage,
                             failure.error, failure.reset));
    } catch (const a64::GuestError &failure) {
        terminal(failure.code + ": " + failure.what());
    } catch (const Rejection &failure) {
        terminal(std::string("AETHER_GRAPHICS_SHARED_WINDOW: ") + failure.message);
    }
}
void GuestGraphicsServices::detach_window(std::uint64_t id) {
    auto &p = *impl_;
    if (p.owner != std::this_thread::get_id() || !p.windows.contains(id))
        throw a64::GuestError("AETHER_GRAPHICS_WINDOW_BINDING",
                              "Window binding is stale or belongs to another owner");
    if (std::any_of(p.surfaces.begin(), p.surfaces.end(),
                    [&](const auto &entry) { return entry.second.window == id; }))
        throw a64::GuestError("AETHER_GRAPHICS_WINDOW_IN_USE",
                              "Release every EGL surface before detaching its window");
    p.windows.erase(id);
    p.update_counts();
}
void GuestGraphicsServices::shutdown() {
    if (impl_->owner != std::this_thread::get_id())
        throw a64::GuestError("AETHER_GRAPHICS_THREAD", "Graphics shutdown requires its owner thread");
    impl_->close();
}
} // namespace aether::graphics
