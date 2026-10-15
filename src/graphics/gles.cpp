#include "guest_internal.hpp"
#include <algorithm>
#include <bit>
#include <limits>

namespace aether::graphics {
std::uint64_t GuestGraphicsServices::Impl::dispatch_gl(Operation op, a64::ServiceState &state) {
    const auto &r = state.registers;
    const auto u = [&](std::size_t index) { return static_cast<std::uint32_t>(r[index]); };
    const auto i = [&](std::size_t index) { return std::bit_cast<std::int32_t>(u(index)); };
    const auto f = [&](std::size_t index) {
        return std::bit_cast<float>(static_cast<std::uint32_t>(state.vectors[index][0]));
    };
    if (op == Operation::gl_error) {
        if (current) {
            activate();
            (void)gl_result();
        }
        const auto result = gl_pending;
        gl_pending = GL_NO_ERROR;
        return result;
    }
    activate();
    (void)gl_result(); // Loss takes precedence over ordinary guest validation errors.
    const auto shader = [&](GLuint id) {
        if (!shaders.contains(id))
            throw GlFailure{GL_INVALID_VALUE};
    };
    const auto program = [&](GLuint id) {
        if (!programs.contains(id))
            throw GlFailure{GL_INVALID_VALUE};
    };
    switch (op) {
    case Operation::create_shader: {
        collect_gl();
        if (shaders.size() >= 32)
            unsupported("Guest shader quota (32) exceeded");
        const auto result = glCreateShader(u(0));
        if (!gl_result())
            return 0;
        try {
            shaders.emplace(result, false);
        } catch (...) {
            glDeleteShader(result);
            throw;
        }
        return result;
    }
    case Operation::shader_source: {
        shader(u(0));
        if (i(1) < 0)
            throw GlFailure{GL_INVALID_VALUE};
        if (i(1) > 16)
            unsupported("glShaderSource exceeds 16 strings");
        const auto count = static_cast<std::size_t>(u(1));
        readable(r[2], count * 8);
        if (r[3])
            readable(r[3], count * 4);
        std::vector<std::string> sources;
        std::vector<const char *> pointers;
        std::vector<GLint> lengths;
        sources.reserve(count);
        pointers.reserve(count);
        lengths.reserve(count);
        std::size_t total = 0;
        for (std::size_t n = 0; n < count; ++n) {
            const auto address = read(r[2] + n * 8, 8);
            const auto length =
                r[3] ? std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(read(r[3] + n * 4, 4))) : -1;
            if (length >= 0) {
                if (length > 262144)
                    unsupported("Shader source exceeds 256 KiB");
                auto data = bytes(address, static_cast<std::size_t>(length));
                sources.emplace_back(data.begin(), data.end());
            } else
                sources.push_back(text(address, 262144));
            total += sources.back().size();
            if (total > 262144)
                unsupported("Combined shader source exceeds 256 KiB");
            pointers.push_back(sources.back().c_str());
            lengths.push_back(static_cast<GLint>(sources.back().size()));
        }
        glShaderSource(u(0), i(1), pointers.data(), lengths.data());
        break;
    }
    case Operation::compile_shader:
        shader(u(0));
        glCompileShader(u(0));
        ++stats.shader_compiles;
        break;
    case Operation::shader_iv:
    case Operation::program_iv: {
        constexpr std::array shader_parameters{GL_SHADER_TYPE, GL_DELETE_STATUS, GL_COMPILE_STATUS,
                                               GL_INFO_LOG_LENGTH, GL_SHADER_SOURCE_LENGTH};
        constexpr std::array program_parameters{GL_DELETE_STATUS,
                                                GL_LINK_STATUS,
                                                GL_VALIDATE_STATUS,
                                                GL_INFO_LOG_LENGTH,
                                                GL_ATTACHED_SHADERS,
                                                GL_ACTIVE_ATTRIBUTES,
                                                GL_ACTIVE_ATTRIBUTE_MAX_LENGTH,
                                                GL_ACTIVE_UNIFORMS,
                                                GL_ACTIVE_UNIFORM_MAX_LENGTH};
        const std::span<const int> allowed = op == Operation::shader_iv
                                                 ? std::span<const int>{shader_parameters}
                                                 : std::span<const int>{program_parameters};
        if (std::find(allowed.begin(), allowed.end(), i(1)) == allowed.end())
            throw GlFailure{GL_INVALID_ENUM};
        if (op == Operation::shader_iv)
            shader(u(0));
        else
            program(u(0));
        writable(r[2], 4);
        GLint value = 0;
        if (op == Operation::shader_iv)
            glGetShaderiv(u(0), u(1), &value);
        else
            glGetProgramiv(u(0), u(1), &value);
        if (gl_result())
            write(r[2], static_cast<std::uint32_t>(value), 4);
        return 0;
    }
    case Operation::shader_log:
    case Operation::program_log: {
        if (op == Operation::shader_log)
            shader(u(0));
        else
            program(u(0));
        if (i(1) < 0)
            throw GlFailure{GL_INVALID_VALUE};
        if (u(1) > 65536)
            unsupported("Shader/program info log exceeds 64 KiB");
        writable(r[3], u(1));
        if (r[2])
            writable(r[2], 4);
        std::vector<char> data(std::max<std::size_t>(u(1), 1));
        GLsizei length = 0;
        if (op == Operation::shader_log)
            glGetShaderInfoLog(u(0), i(1), &length, data.data());
        else
            glGetProgramInfoLog(u(0), i(1), &length, data.data());
        if (gl_result()) {
            if (r[2])
                write(r[2], static_cast<std::uint32_t>(length), 4);
            const auto size = u(1) ? std::min<std::size_t>(static_cast<std::size_t>(length) + 1, u(1)) : 0;
            if (size)
                copy_output(r[3], {reinterpret_cast<const std::uint8_t *>(data.data()), size});
        }
        return 0;
    }
    case Operation::delete_shader:
        if (u(0))
            shader(u(0));
        glDeleteShader(u(0));
        if (gl_result() && u(0))
            shaders.at(u(0)) = true;
        collect_gl();
        return 0;
    case Operation::create_program: {
        collect_gl();
        if (programs.size() >= 16)
            unsupported("Guest program quota (16) exceeded");
        const auto result = glCreateProgram();
        if (!gl_result())
            return 0;
        try {
            programs.emplace(result, false);
        } catch (...) {
            glDeleteProgram(result);
            throw;
        }
        return result;
    }
    case Operation::attach_shader:
        program(u(0));
        shader(u(1));
        glAttachShader(u(0), u(1));
        break;
    case Operation::bind_attribute: {
        program(u(0));
        const auto name = text(r[2], 1024);
        glBindAttribLocation(u(0), u(1), name.c_str());
        break;
    }
    case Operation::link_program:
        program(u(0));
        glLinkProgram(u(0));
        break;
    case Operation::use_program:
        if (u(0))
            program(u(0));
        glUseProgram(u(0));
        gl_result();
        collect_gl();
        return 0;
    case Operation::uniform_location: {
        program(u(0));
        const auto name = text(r[1], 1024);
        const auto result = glGetUniformLocation(u(0), name.c_str());
        gl_result();
        return static_cast<std::uint32_t>(result);
    }
    case Operation::uniform4f:
        glUniform4f(i(0), f(0), f(1), f(2), f(3));
        break;
    case Operation::delete_program:
        if (u(0))
            program(u(0));
        glDeleteProgram(u(0));
        if (gl_result() && u(0))
            programs.at(u(0)) = true;
        collect_gl();
        return 0;
    case Operation::gen_buffers: {
        if (i(0) < 0)
            throw GlFailure{GL_INVALID_VALUE};
        if (u(0) > 32 || buffers.size() + u(0) > 32)
            unsupported("Guest buffer quota (32) exceeded");
        writable(r[1], static_cast<std::size_t>(u(0)) * 4);
        std::array<GLuint, 32> generated{};
        glGenBuffers(i(0), generated.data());
        if (!gl_result())
            return 0;
        try {
            for (std::size_t n = 0; n < u(0); ++n)
                buffers.emplace(generated[n], 0);
        } catch (...) {
            glDeleteBuffers(i(0), generated.data());
            for (std::size_t n = 0; n < u(0); ++n)
                buffers.erase(generated[n]);
            throw;
        }
        for (std::size_t n = 0; n < u(0); ++n)
            write(r[1] + n * 4, generated[n], 4);
        return 0;
    }
    case Operation::bind_buffer:
        if (u(0) != GL_ARRAY_BUFFER)
            unsupported("Only GL_ARRAY_BUFFER is implemented");
        if (u(1) && !buffers.contains(u(1)))
            unsupported("Buffer name was not generated by this context");
        glBindBuffer(GL_ARRAY_BUFFER, u(1));
        if (gl_result())
            array_buffer = u(1);
        return 0;
    case Operation::buffer_data: {
        if (u(0) != GL_ARRAY_BUFFER)
            unsupported("Only GL_ARRAY_BUFFER uploads are implemented");
        if (std::bit_cast<std::int64_t>(r[1]) < 0)
            throw GlFailure{GL_INVALID_VALUE};
        if (!array_buffer)
            throw GlFailure{GL_INVALID_OPERATION};
        if (r[1] > maximum_transfer)
            unsupported("Buffer upload exceeds 4 MiB");
        const auto size = static_cast<std::size_t>(r[1]);
        const auto previous = buffers.at(array_buffer);
        if (stats.buffer_bytes - previous + size > maximum_buffer_bytes)
            unsupported("Guest buffer allocation exceeds 16 MiB");
        const auto data = r[2] ? bytes(r[2], size) : std::vector<std::uint8_t>{};
        glBufferData(GL_ARRAY_BUFFER, static_cast<GLsizeiptr>(size), r[2] ? data.data() : nullptr, u(3));
        if (gl_result()) {
            buffers.at(array_buffer) = size;
            stats.buffer_bytes = stats.buffer_bytes - previous + size;
        }
        return 0;
    }
    case Operation::delete_buffers: {
        if (i(0) < 0)
            throw GlFailure{GL_INVALID_VALUE};
        if (u(0) > 32)
            unsupported("Buffer deletion exceeds 32 names");
        readable(r[1], static_cast<std::size_t>(u(0)) * 4);
        std::array<GLuint, 32> names{};
        for (std::size_t n = 0; n < u(0); ++n)
            names[n] = static_cast<GLuint>(read(r[1] + n * 4, 4));
        glDeleteBuffers(i(0), names.data());
        if (gl_result()) {
            for (std::size_t n = 0; n < u(0); ++n) {
                const auto found = buffers.find(names[n]);
                if (found == buffers.end())
                    continue;
                stats.buffer_bytes -= found->second;
                buffers.erase(found);
                if (array_buffer == names[n])
                    array_buffer = 0;
                for (auto &attribute : attributes)
                    if (attribute.buffer == names[n])
                        attribute.buffer = 0;
            }
        }
        return 0;
    }
    case Operation::attribute_pointer: {
        if (u(0) >= attributes.size() || i(1) < 1 || i(1) > 4 || i(4) < 0)
            throw GlFailure{GL_INVALID_VALUE};
        if (u(2) != GL_FLOAT)
            unsupported("Only GL_FLOAT vertex attributes are implemented");
        if (!array_buffer)
            unsupported("Guest client-memory vertex arrays are not implemented; use a VBO");
        if (u(4) > 4096 || r[5] > buffers.at(array_buffer))
            unsupported("Vertex offset/stride exceeds its buffer bound");
        const auto offset = static_cast<std::size_t>(r[5]);
        glVertexAttribPointer(u(0), i(1), GL_FLOAT, static_cast<GLboolean>(u(3)), i(4),
                              reinterpret_cast<const void *>(offset));
        if (gl_result()) {
            auto &attribute = attributes[u(0)];
            attribute.buffer = array_buffer;
            attribute.offset = offset;
            attribute.element = static_cast<std::size_t>(u(1)) * sizeof(float);
            attribute.stride = u(4) ? u(4) : attribute.element;
        }
        return 0;
    }
    case Operation::enable_attribute:
    case Operation::disable_attribute:
        if (u(0) >= attributes.size())
            throw GlFailure{GL_INVALID_VALUE};
        if (op == Operation::enable_attribute)
            glEnableVertexAttribArray(u(0));
        else
            glDisableVertexAttribArray(u(0));
        if (gl_result())
            attributes[u(0)].enabled = op == Operation::enable_attribute;
        return 0;
    case Operation::viewport:
        if (i(2) < 0 || i(3) < 0)
            throw GlFailure{GL_INVALID_VALUE};
        if (i(0) < -65536 || i(0) > 65536 || i(1) < -65536 || i(1) > 65536 || u(2) > 4096 || u(3) > 4096)
            unsupported("Viewport exceeds guest graphics limits");
        glViewport(i(0), i(1), i(2), i(3));
        break;
    case Operation::clear_color:
        glClearColor(f(0), f(1), f(2), f(3));
        break;
    case Operation::clear:
        glClear(u(0));
        break;
    case Operation::enable:
        glEnable(u(0));
        break;
    case Operation::disable:
        glDisable(u(0));
        break;
    case Operation::pixel_store:
        if (u(0) != GL_PACK_ALIGNMENT && u(0) != GL_UNPACK_ALIGNMENT)
            throw GlFailure{GL_INVALID_ENUM};
        glPixelStorei(u(0), i(1));
        if (gl_result() && u(0) == GL_PACK_ALIGNMENT)
            pack_alignment = i(1);
        return 0;
    case Operation::draw_arrays:
        if (i(1) < 0 || i(2) < 0)
            throw GlFailure{GL_INVALID_VALUE};
        if (u(1) > 65536 || u(2) > 65536)
            unsupported("Vertex draw range exceeds 65536");
        if (u(2)) {
            for (const auto &attribute : attributes)
                if (attribute.enabled) {
                    const auto found = buffers.find(attribute.buffer);
                    if (found == buffers.end())
                        unsupported("Enabled vertex attribute has no live VBO");
                    const auto end = attribute.offset + (std::size_t{u(1)} + u(2) - 1) * attribute.stride +
                                     attribute.element;
                    if (end > found->second)
                        unsupported("Vertex draw would read outside its VBO");
                }
        }
        glDrawArrays(u(0), i(1), i(2));
        if (gl_result())
            ++stats.draws;
        return 0;
    case Operation::read_pixels: {
        if (i(2) < 0 || i(3) < 0)
            throw GlFailure{GL_INVALID_VALUE};
        if (u(4) != GL_RGBA || u(5) != GL_UNSIGNED_BYTE)
            unsupported("Only RGBA8 guest pixel readback is implemented");
        if (u(2) > 1024 || u(3) > 1024 || i(0) < -65536 || i(0) > 65536 || i(1) < -65536 || i(1) > 65536)
            unsupported("Pixel readback exceeds bounded dimensions");
        const auto row = static_cast<std::size_t>(u(2)) * 4;
        const auto alignment = static_cast<std::size_t>(pack_alignment);
        const auto stride = (row + alignment - 1) & ~(alignment - 1);
        const auto height = static_cast<std::size_t>(u(3));
        const auto size = row && height ? (height - 1) * stride + row : 0;
        writable(r[6], size);
        std::vector<std::uint8_t> data(std::max<std::size_t>(stride * height, 1));
        glReadPixels(i(0), i(1), i(2), i(3), GL_RGBA, GL_UNSIGNED_BYTE, data.data());
        if (gl_result()) {
            for (std::size_t y = 0; row && y < height; ++y)
                copy_output(r[6] + y * stride, std::span{data}.subspan(y * stride, row));
            ++stats.readbacks;
            stats.readback_bytes += row * height;
        }
        return 0;
    }
    case Operation::finish:
        glFinish();
        break;
    case Operation::gl_string: {
        if (u(0) == GL_EXTENSIONS)
            return string_result("");
        if (u(0) != GL_VENDOR && u(0) != GL_RENDERER && u(0) != GL_VERSION &&
            u(0) != GL_SHADING_LANGUAGE_VERSION)
            throw GlFailure{GL_INVALID_ENUM};
        const auto *value = glGetString(u(0));
        if (!gl_result() || !value)
            return 0;
        return string_result(reinterpret_cast<const char *>(value));
    }
    default:
        unsupported("Unregistered GLES operation");
    }
    gl_result();
    return 0;
}
} // namespace aether::graphics
