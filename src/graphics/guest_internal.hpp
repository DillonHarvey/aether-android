#pragma once
#include "aether/graphics/command.hpp"
#include "aether/host/graphics_surface.hpp"
#include "shared_window.hpp"
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <map>
#include <set>
#include <thread>

namespace aether::graphics {
struct Rejection {
    a64::Fault fault;
    const char *message;
};
struct EglFailure {
    EGLint error;
};
struct GlFailure {
    GLenum error;
    GLenum reset = GL_NO_ERROR;
};
[[noreturn]] inline void unsupported(const char *message) {
    throw Rejection{a64::Fault::unsupported_service, message};
}
using Token = std::uint64_t;
struct GuestGraphicsServices::Impl {
    a64::GuestMemory &memory;
    GraphicsChannel *channel;
    std::vector<ObservedWrite> *observed = nullptr;
    std::string remote_error;
    const a64::AppContext &app;
    const std::thread::id owner = std::this_thread::get_id();
    Metrics stats;
    HostInfo info;
    std::string_view error;
    bool trampoline_owned = false, closed = false, initialized = false, driver_initialized = false;
    EGLDisplay display = EGL_NO_DISPLAY;
    Token display_token = 0, context_token = 0, current = 0, draw_surface = 0, read_surface = 0;
    EGLContext context = EGL_NO_CONTEXT;
    EGLint display_key = 0, egl_pending = EGL_SUCCESS;
    GLenum gl_pending = GL_NO_ERROR;
    bool context_deleted = false;
    bool context_failed = false;
    struct Surface {
        EGLSurface native;
        EGLint width, height;
        bool deleted = false;
        Token window = 0;
        EGLConfig config = nullptr;
    };
    std::map<Token, EGLConfig> configs;
    std::map<Token, Surface> surfaces;
    std::map<Token, std::unique_ptr<host::HostSurface>> windows;
    std::unique_ptr<SharedWindow> shared_window;
    std::map<GLuint, bool> shaders, programs;
    std::map<GLuint, std::size_t> buffers;
    GLuint array_buffer = 0;
    GLint pack_alignment = 4;
    struct Attribute {
        bool enabled = false;
        GLuint buffer = 0;
        std::size_t offset = 0, stride = 0, element = 0;
    };
    std::array<Attribute, 16> attributes{};
    std::map<std::string, a64::Address, std::less<>> strings;
    std::vector<a64::Address> string_pages;
    static constexpr std::size_t maximum_transfer = 4 * 1024 * 1024;
    static constexpr std::size_t maximum_buffer_bytes = 16 * 1024 * 1024;
    Impl(a64::GuestMemory &m, const a64::AppContext &a, GraphicsChannel *remote);
    ~Impl();
    void close() noexcept;
    void lose_context(const char *message) noexcept;
    void reset_gl() noexcept;
    void collect_deleted();
    void collect_gl();
    void update_counts() noexcept;
    void readable(a64::Address address, std::size_t size) const;
    void writable(a64::Address address, std::size_t size) const;
    std::uint64_t read(a64::Address address, std::size_t size) const;
    void copy_output(a64::Address address, std::span<const std::uint8_t> bytes);
    void write(a64::Address address, std::uint64_t value, std::size_t size);
    std::vector<std::uint8_t> bytes(a64::Address address, std::size_t size) const;
    std::string text(a64::Address address, std::size_t limit) const;
    a64::Address string_result(std::string value);
    std::vector<EGLint> attribute_list(a64::Address address, std::span<const EGLint> allowed) const;
    void require_display(Token token, bool ready = true) const;
    EGLConfig config(Token token) const;
    Surface &surface(Token token, bool allow_deleted = false);
    host::HostSurface &window(Token token) const;
    void validate_window_surface(const Surface &value) const;
    void activate();
    void inspect_device();
    void inspect_context();
    bool egl_result(EGLBoolean value);
    bool gl_result();
    void egl_error(EGLint value) noexcept;
    void gl_error(GLenum value) noexcept;
    std::uint64_t dispatch_egl(Operation op, a64::ServiceState &state);
    std::uint64_t dispatch_gl(Operation op, a64::ServiceState &state);
};
} // namespace aether::graphics
