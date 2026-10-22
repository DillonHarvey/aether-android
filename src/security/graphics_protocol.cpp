#include "aether/security/graphics_protocol.hpp"
#include <algorithm>
namespace aether::security {
namespace {
void require(bool value) {
    if (!value)
        throw ProtocolError("AETHER_GRAPHICS_WIRE: invalid bounded record");
}
struct Writer {
    std::vector<std::uint8_t> data;
    void n(std::uint64_t value) {
        require(data.size() <= graphics::graphics_packet_limit - 8);
        for (unsigned i = 0; i < 8; ++i)
            data.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
    }
    void bytes(std::span<const std::uint8_t> value) {
        n(value.size());
        require(value.size() <= graphics::graphics_packet_limit - data.size());
        data.insert(data.end(), value.begin(), value.end());
    }
    void text(std::string_view value, std::size_t limit) {
        require(value.size() <= limit && value.find('\0') == std::string::npos);
        bytes({reinterpret_cast<const std::uint8_t *>(value.data()), value.size()});
    }
};
struct Reader {
    std::span<const std::uint8_t> data;
    std::size_t offset = 0;
    explicit Reader(std::span<const std::uint8_t> value) : data(value) {
        require(data.size() <= graphics::graphics_packet_limit);
        require(n() == 1);
    }
    std::uint64_t n() {
        const auto value = read_u64(data, offset);
        offset += 8;
        return value;
    }
    std::uint32_t u() {
        const auto value = n();
        require(value <= UINT32_MAX);
        return static_cast<std::uint32_t>(value);
    }
    bool flag() {
        const auto value = n();
        require(value <= 1);
        return value != 0;
    }
    std::vector<std::uint8_t> bytes(std::size_t limit) {
        const auto size = n();
        require(size <= limit && size <= data.size() - offset);
        std::vector<std::uint8_t> value(data.begin() + offset,
                                        data.begin() + offset + static_cast<std::size_t>(size));
        offset += static_cast<std::size_t>(size);
        return value;
    }
    std::string text(std::size_t limit) {
        auto value = bytes(limit);
        require(std::find(value.begin(), value.end(), 0) == value.end());
        return {value.begin(), value.end()};
    }
    void end() const { require(offset == data.size()); }
};
} // namespace
std::vector<std::uint8_t> encode_graphics_command(const graphics::GraphicsCommand &c) {
    Writer w;
    w.n(1);
    w.n(static_cast<std::uint32_t>(c.operation));
    for (auto n : c.scalars)
        w.n(n);
    for (auto n : c.floats)
        w.n(n);
    for (const auto &a : c.memory) {
        w.n(a.present);
        w.n(a.output_capacity);
        w.bytes(a.input);
    }
    return w.data;
}
graphics::GraphicsCommand decode_graphics_command(std::span<const std::uint8_t> bytes) {
    Reader r(bytes);
    graphics::GraphicsCommand c;
    const auto op = r.n();
    require(op < static_cast<unsigned>(graphics::Operation::count));
    c.operation = static_cast<graphics::Operation>(op);
    for (auto &n : c.scalars)
        n = r.n();
    for (auto &n : c.floats)
        n = r.u();
    std::size_t total = 0;
    for (auto &a : c.memory) {
        a.present = r.flag();
        a.output_capacity = r.u();
        require(a.output_capacity <= graphics::graphics_transfer_limit);
        a.input = r.bytes(graphics::graphics_transfer_limit);
        total += a.input.size() + a.output_capacity;
        require(total <= graphics::graphics_packet_limit);
    }
    r.end();
    return c;
}
std::vector<std::uint8_t> encode_graphics_reply(const graphics::GraphicsReply &r) {
    Writer w;
    w.n(1);
    w.n(r.value);
    w.n(static_cast<unsigned>(r.fault));
    w.n(r.string_result);
    w.n(r.pack_alignment);
    w.text(r.text, 4095);
    w.text(r.error, 512);
    const auto &m = r.metrics;
    for (auto n : {m.calls,
                   m.egl_calls,
                   m.gl_calls,
                   m.rejected,
                   m.api_errors,
                   m.shader_compiles,
                   m.draws,
                   m.readbacks,
                   m.readback_bytes,
                   m.swaps,
                   m.window_swaps,
                   static_cast<std::uint64_t>(m.contexts),
                   static_cast<std::uint64_t>(m.surfaces),
                   static_cast<std::uint64_t>(m.shaders),
                   static_cast<std::uint64_t>(m.programs),
                   static_cast<std::uint64_t>(m.buffers),
                   static_cast<std::uint64_t>(m.buffer_bytes),
                   static_cast<std::uint64_t>(m.window_bindings),
                   static_cast<std::uint64_t>(m.window_surfaces),
                   m.cleanup_failures})
        w.n(n);
    for (const auto *s : {&r.host.renderer, &r.host.vendor, &r.host.version, &r.host.adapter})
        w.text(*s, 1024);
    w.n(r.host.vendor_id);
    w.n(r.host.device_id);
    w.n(r.host.feature_level);
    w.n(r.host.hardware);
    require(r.outputs.size() <= 1024);
    w.n(r.outputs.size());
    std::size_t total = 0;
    for (const auto &o : r.outputs) {
        require(o.argument < 7);
        total += o.bytes.size();
        require(total <= graphics::graphics_transfer_limit);
        w.n(o.argument);
        w.n(o.offset);
        w.bytes(o.bytes);
    }
    return w.data;
}
graphics::GraphicsReply decode_graphics_reply(std::span<const std::uint8_t> bytes) {
    Reader r(bytes);
    graphics::GraphicsReply reply;
    reply.value = r.n();
    const auto fault = r.n();
    require(fault <= static_cast<unsigned>(a64::Fault::thread_exit));
    reply.fault = static_cast<a64::Fault>(fault);
    reply.string_result = r.flag();
    reply.pack_alignment = r.u();
    require(reply.pack_alignment == 1 || reply.pack_alignment == 2 || reply.pack_alignment == 4 ||
            reply.pack_alignment == 8);
    reply.text = r.text(4095);
    reply.error = r.text(512);
    auto &m = reply.metrics;
    for (auto *n : {&m.calls, &m.egl_calls, &m.gl_calls, &m.rejected, &m.api_errors, &m.shader_compiles,
                    &m.draws, &m.readbacks, &m.readback_bytes, &m.swaps, &m.window_swaps})
        *n = r.n();
    for (auto *n : {&m.contexts, &m.surfaces, &m.shaders, &m.programs, &m.buffers, &m.buffer_bytes,
                    &m.window_bindings, &m.window_surfaces})
        *n = static_cast<std::size_t>(r.n());
    m.cleanup_failures = r.n();
    require(m.contexts <= 1 && m.surfaces <= 4 && m.shaders <= 32 && m.programs <= 16 && m.buffers <= 32 &&
            m.buffer_bytes <= 16 * 1024 * 1024 && m.window_bindings <= 1 && m.window_surfaces <= 1);
    for (auto *s : {&reply.host.renderer, &reply.host.vendor, &reply.host.version, &reply.host.adapter})
        *s = r.text(1024);
    reply.host.vendor_id = r.u();
    reply.host.device_id = r.u();
    reply.host.feature_level = r.u();
    reply.host.hardware = r.flag();
    const auto count = r.n();
    require(count <= 1024);
    std::size_t total = 0;
    for (std::size_t i = 0; i < count; ++i) {
        graphics::GraphicsOutput o;
        o.argument = r.u();
        o.offset = r.u();
        require(o.argument < 7 && o.offset <= graphics::graphics_transfer_limit);
        o.bytes = r.bytes(graphics::graphics_transfer_limit);
        total += o.bytes.size();
        require(total <= graphics::graphics_transfer_limit &&
                o.bytes.size() <= graphics::graphics_transfer_limit - o.offset);
        reply.outputs.push_back(std::move(o));
    }
    r.end();
    return reply;
}
} // namespace aether::security
