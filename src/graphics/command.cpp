#include "aether/graphics/command.hpp"
#include "aether/host/graphics_surface.hpp"
#include <algorithm>
#include <bit>
#include <thread>

namespace aether::graphics {
namespace {
struct Shape {
    unsigned scalars, wide, inputs, outputs;
    bool floats = false;
};
constexpr std::array<Shape, 54> shapes{
    {{1, 1, 0, 0},  {1, 1, 0, 6},   {9, 1, 2, 20},      {1, 0, 0, 0}, {7, 7, 8, 0},       {3, 3, 4, 0},
     {7, 7, 8, 0},  {15, 15, 0, 0}, {3, 3, 0, 0},       {3, 3, 0, 0}, {1, 1, 0, 0},       {7, 3, 0, 8},
     {3, 3, 0, 0},  {0, 0, 0, 0},   {0, 0, 1, 0},       {0, 0, 0, 0}, {0, 0, 0, 0},       {1, 0, 0, 0},
     {3, 1, 0, 0},  {0, 0, 0, 0},   {1, 0, 0, 0},       {3, 0, 4, 0}, {1, 0, 0, 0},       {3, 0, 0, 4},
     {3, 0, 0, 12}, {1, 0, 0, 0},   {0, 0, 0, 0},       {3, 0, 0, 0}, {3, 0, 4, 0},       {1, 0, 0, 0},
     {3, 0, 0, 4},  {3, 0, 0, 12},  {1, 0, 0, 0},       {1, 0, 2, 0}, {1, 0, 0, 0, true}, {1, 0, 0, 0},
     {1, 0, 0, 2},  {3, 0, 0, 0},   {11, 2, 4, 0},      {1, 0, 2, 0}, {63, 32, 0, 0},     {1, 0, 0, 0},
     {1, 0, 0, 0},  {15, 0, 0, 0},  {0, 0, 0, 0, true}, {1, 0, 0, 0}, {1, 0, 0, 0},       {1, 0, 0, 0},
     {3, 0, 0, 0},  {7, 0, 0, 0},   {63, 0, 0, 64},     {0, 0, 0, 0}, {0, 0, 0, 0},       {1, 0, 0, 0}}};
void require(bool condition, const char *message, a64::Fault fault = a64::Fault::unsupported_service) {
    if (!condition)
        throw GraphicsCopyError(fault, message);
}
Shape shape(Operation op) {
    require(static_cast<unsigned>(op) < shapes.size(), "Unregistered copied graphics operation");
    return shapes[static_cast<std::size_t>(op)];
}
std::size_t count(std::uint64_t value, std::size_t limit) {
    if (std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value)) < 0)
        return 0;
    require(value <= limit, "Copied graphics count exceeds its API bound");
    return static_cast<std::size_t>(value);
}
std::uint64_t integer(std::span<const std::uint8_t> data, std::size_t offset, std::size_t width) {
    require(offset <= data.size() && width <= data.size() - offset, "Truncated copied graphics integer");
    std::uint64_t n = 0;
    for (std::size_t i = 0; i < width; ++i)
        n |= std::uint64_t{data[offset + i]} << (8 * i);
    return n;
}
void append(std::vector<std::uint8_t> &data, std::uint64_t n, std::size_t width = 8) {
    require(data.size() <= graphics_packet_limit - width, "Copied graphics packet exceeds limit");
    for (std::size_t i = 0; i < width; ++i)
        data.push_back(static_cast<std::uint8_t>(n >> (i * 8)));
}
std::vector<std::uint8_t> read(const a64::GuestMemory &memory, a64::Address address, std::size_t size) {
    require(size <= graphics_transfer_limit, "Copied graphics input exceeds 4 MiB");
    std::vector<std::uint8_t> bytes(size);
    require(!size || memory.read(address, bytes), "Graphics input is outside readable guest memory",
            a64::Fault::read);
    return bytes;
}
std::vector<std::uint8_t> text(const a64::GuestMemory &memory, a64::Address address, std::size_t limit) {
    require(address < a64::GuestMemory::address_limit, "Invalid graphics text address", a64::Fault::read);
    std::vector<std::uint8_t> data;
    for (std::size_t i = 0; i < limit; ++i) {
        std::array<std::uint8_t, 1> one{};
        require(memory.read(address + i, one), "Invalid graphics text memory", a64::Fault::read);
        data.push_back(one[0]);
        if (!one[0])
            return data;
    }
    throw GraphicsCopyError(a64::Fault::unsupported_service, "Graphics text exceeds its termination bound");
}
bool attributes(Operation op) {
    return op == Operation::choose_config || op == Operation::create_context ||
           op == Operation::create_pbuffer || op == Operation::create_window;
}
std::size_t output_size(const GraphicsCommand &c, unsigned argument, std::uint32_t alignment) {
    const auto &r = c.scalars;
    switch (c.operation) {
    case Operation::initialize:
    case Operation::query_surface:
    case Operation::shader_iv:
    case Operation::program_iv:
        return 4;
    case Operation::choose_config:
        return argument == 4 ? 4 : count(r[3], 32) * 8;
    case Operation::shader_log:
    case Operation::program_log:
        return argument == 2 ? 4 : count(r[1], 65536);
    case Operation::gen_buffers:
        return count(r[0], 32) * 4;
    case Operation::read_pixels: {
        require(alignment == 1 || alignment == 2 || alignment == 4 || alignment == 8,
                "Invalid pixel pack alignment");
        const auto row = count(r[2], 1024) * 4, height = count(r[3], 1024);
        const auto stride = (row + alignment - 1) & ~std::size_t{alignment - 1};
        return row && height ? (height - 1) * stride + row : 0;
    }
    default:
        return 0;
    }
}
void validate_source(const GraphicsCommand &c) {
    const auto n = count(c.scalars[1], 16);
    const auto &bytes = c.memory[2].input;
    std::size_t offset = 0, total = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const auto size = integer(bytes, offset, 8);
        offset += 8;
        require(size <= 262144 && size <= bytes.size() - offset && total + size <= 262144,
                "Shader source exceeds 256 KiB");
        offset += static_cast<std::size_t>(size);
        total += static_cast<std::size_t>(size);
    }
    require(offset == bytes.size(), "Trailing shader source data");
}
} // namespace
void validate_command(const GraphicsCommand &c, std::uint32_t alignment) {
    const auto spec = shape(c.operation);
    std::size_t total = 0;
    for (unsigned i = 0; i < 7; ++i) {
        const auto bit = 1U << i;
        const auto &arg = c.memory[i];
        require((spec.scalars & bit) || c.scalars[i] == 0,
                "Pointer/unused register present as graphics scalar");
        require((spec.wide & bit) || c.scalars[i] <= UINT32_MAX, "Noncanonical 32-bit graphics scalar");
        require(((spec.inputs | spec.outputs) & bit) || !arg.present, "Unexpected copied graphics argument");
        require(arg.present || (arg.input.empty() && !arg.output_capacity),
                "Data for absent graphics argument");
        require((spec.inputs & bit) || arg.input.empty(), "Unexpected graphics input bytes");
        const auto expected = arg.present && (spec.outputs & bit) ? output_size(c, i, alignment) : 0;
        require(arg.output_capacity == expected && arg.input.size() <= graphics_transfer_limit,
                "Invalid graphics output capacity or input size");
        total += arg.input.size() + arg.output_capacity;
    }
    require(total <= graphics_packet_limit, "Combined graphics transfer exceeds bound");
    if (!spec.floats)
        for (auto n : c.floats)
            require(n == 0, "Unexpected graphics float argument");
    for (unsigned i = 0; i < 7; ++i) {
        const auto &a = c.memory[i];
        if (!(spec.inputs & (1U << i)) || !a.present)
            continue;
        if (attributes(c.operation)) {
            require(a.input.size() >= 4 && a.input.size() <= 260 && a.input.size() % 8 == 4,
                    "Invalid copied EGL attribute list");
            for (std::size_t offset = 0; offset < a.input.size(); offset += 8)
                require((integer(a.input, offset, 4) == 0x3038) == (offset + 4 == a.input.size()),
                        "Invalid EGL terminator");
        } else if (c.operation == Operation::shader_source)
            validate_source(c);
        else if (c.operation == Operation::delete_buffers)
            require(a.input.size() == count(c.scalars[0], 32) * 4, "Invalid buffer-name array");
        else if (c.operation == Operation::buffer_data) {
            const auto size = std::bit_cast<std::int64_t>(c.scalars[1]) < 0 ? 0 : c.scalars[1];
            require(size <= graphics_transfer_limit && a.input.size() == size, "Invalid copied VBO bytes");
        } else {
            const auto limit = c.operation == Operation::proc_address ? 256U : 1024U;
            require(!a.input.empty() && a.input.size() <= limit && a.input.back() == 0 &&
                        std::find(a.input.begin(), a.input.end() - 1, 0) == a.input.end() - 1,
                    "Invalid copied graphics string");
        }
    }
}
GraphicsCommand copy_command(Operation op, const a64::ServiceState &state, const a64::GuestMemory &memory,
                             std::uint32_t alignment) {
    GraphicsCommand c;
    c.operation = op;
    const auto spec = shape(op);
    const auto &r = state.registers;
    for (unsigned i = 0; i < 7; ++i) {
        const auto bit = 1U << i;
        if (spec.scalars & bit)
            c.scalars[i] = (spec.wide & bit) ? r[i] : static_cast<std::uint32_t>(r[i]);
        if ((spec.inputs | spec.outputs) & bit)
            c.memory[i].present = r[i] != 0;
    }
    if (spec.floats)
        for (unsigned i = 0; i < 4; ++i)
            c.floats[i] = static_cast<std::uint32_t>(state.vectors[i][0]);
    for (unsigned i = 0; i < 7; ++i) {
        auto &a = c.memory[i];
        if (!(spec.inputs & (1U << i)) || !a.present)
            continue;
        if (attributes(op)) {
            for (unsigned n = 0; n <= 32; ++n) {
                const auto key = read(memory, r[i] + n * 8, 4);
                a.input.insert(a.input.end(), key.begin(), key.end());
                if (integer(key, 0, 4) == 0x3038)
                    break;
                require(n < 32, "EGL attribute list exceeds 32 pairs");
                const auto value = read(memory, r[i] + n * 8 + 4, 4);
                a.input.insert(a.input.end(), value.begin(), value.end());
            }
        } else if (op == Operation::shader_source) {
            const auto n = count(c.scalars[1], 16);
            for (std::size_t k = 0; k < n; ++k) {
                const auto address = integer(read(memory, r[2] + k * 8, 8), 0, 8);
                const auto length = r[3] ? std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(
                                               integer(read(memory, r[3] + k * 4, 4), 0, 4)))
                                         : -1;
                require(length <= 262144, "Shader source exceeds 256 KiB");
                auto data = length < 0 ? text(memory, address, 262144)
                                       : read(memory, address, static_cast<std::size_t>(length));
                if (length < 0)
                    data.pop_back();
                require(a.input.size() + data.size() + 8 <= 262144 + 128,
                        "Combined shader source exceeds 256 KiB");
                append(a.input, data.size());
                a.input.insert(a.input.end(), data.begin(), data.end());
            }
        } else if (op == Operation::buffer_data) {
            const auto size = std::bit_cast<std::int64_t>(r[1]) < 0 ? 0 : r[1];
            require(size <= graphics_transfer_limit, "VBO input exceeds 4 MiB");
            a.input = read(memory, r[i], static_cast<std::size_t>(size));
        } else if (op == Operation::delete_buffers)
            a.input = read(memory, r[i], count(c.scalars[0], 32) * 4);
        else
            a.input = text(memory, r[i], op == Operation::proc_address ? 256 : 1024);
    }
    for (unsigned i = 0; i < 7; ++i)
        if ((spec.outputs & (1U << i)) && c.memory[i].present) {
            const auto size = output_size(c, i, alignment);
            require(!size || memory.accessible(r[i], size, a64::Permission::write),
                    "Graphics output is outside writable guest memory", a64::Fault::write);
            c.memory[i].output_capacity = static_cast<std::uint32_t>(size);
        }
    validate_command(c, alignment);
    return c;
}
void apply_outputs(const GraphicsCommand &c, const GraphicsReply &reply, const a64::ServiceState &state,
                   a64::GuestMemory &memory) {
    require(reply.pack_alignment == 1 || reply.pack_alignment == 2 || reply.pack_alignment == 4 ||
                reply.pack_alignment == 8,
            "Invalid graphics reply pack alignment");
    require(reply.string_result ? (reply.value == 0 && reply.fault == a64::Fault::none) : reply.text.empty(),
            "Noncanonical graphics string result");
    require(reply.outputs.size() <= 1024, "Graphics reply has too many output ranges");
    std::array<std::uint64_t, 7> ends{};
    std::size_t total = 0;
    for (const auto &output : reply.outputs) {
        require(output.argument < 7, "Invalid graphics output argument");
        const auto cap = c.memory[output.argument].output_capacity;
        require(!output.bytes.empty() && output.offset >= ends[output.argument] && output.offset <= cap &&
                    output.bytes.size() <= cap - output.offset,
                "Graphics output is overlapping or outside destination");
        ends[output.argument] = output.offset + output.bytes.size();
        total += output.bytes.size();
        require(memory.accessible(state.registers[output.argument] + output.offset, output.bytes.size(),
                                  a64::Permission::write),
                "Graphics reply destination changed", a64::Fault::write);
    }
    require(total <= graphics_transfer_limit, "Graphics reply exceeds output bound");
    require(reply.fault <= a64::Fault::nesting_limit && reply.text.size() < 4096 && reply.error.size() <= 512,
            "Invalid graphics reply metadata");
    require(!reply.string_result || c.operation == Operation::query_string ||
                c.operation == Operation::gl_string,
            "Unexpected graphics text result");
    require(c.operation != Operation::proc_address || reply.value <= shapes.size(),
            "Invalid graphics procedure index");
    for (const auto &output : reply.outputs)
        require(memory.write(state.registers[output.argument] + output.offset, output.bytes),
                "Cannot copy graphics reply", a64::Fault::write);
}
struct GraphicsExecutor::Impl {
    static constexpr a64::Address arena = 0x60000000, stride = graphics_transfer_limit + 4096;
    a64::GuestMemory memory;
    a64::AppContext app;
    GuestGraphicsServices graphics;
    bool closed = false;
    std::string terminal_error;
    const std::thread::id owner = std::this_thread::get_id();
    explicit Impl(std::uint64_t app_id) : app{app_id, false, true}, graphics(memory, app) {
        require(app_id != 0, "Graphics executor needs an app identity");
        memory.map(arena, static_cast<std::size_t>(stride) * 7, a64::read_write);
    }
    GraphicsReply snapshot() const {
        GraphicsReply r;
        r.pack_alignment = graphics.pack_alignment();
        r.metrics = graphics.metrics();
        r.host = graphics.host_info();
        if (!terminal_error.empty()) {
            r.fault = a64::Fault::windows_service;
            r.error = terminal_error;
        }
        return r;
    }
};
GraphicsExecutor::GraphicsExecutor(std::uint64_t app_id) : impl_(std::make_unique<Impl>(app_id)) {}
GraphicsExecutor::~GraphicsExecutor() = default;
GraphicsReply GraphicsExecutor::exchange(const GraphicsCommand &c) {
    auto &p = *impl_;
    require(p.owner == std::this_thread::get_id(), "Graphics executor belongs to another thread",
            a64::Fault::invalid_call);
    require(!p.closed, "Graphics executor is closed");
    validate_command(c, p.graphics.pack_alignment());
    a64::ServiceState state{};
    for (unsigned i = 0; i < 7; ++i) {
        state.registers[i] = c.scalars[i];
        const auto &a = c.memory[i];
        if (a.present) {
            state.registers[i] = Impl::arena + i * Impl::stride;
            require(a.input.empty() || p.memory.write(state.registers[i], a.input),
                    "Cannot initialize graphics argument arena");
        }
    }
    for (unsigned i = 0; i < 4; ++i)
        state.vectors[i][0] = c.floats[i];
    if (c.operation == Operation::shader_source && c.memory[2].present) {
        const auto n = count(c.scalars[1], 16);
        const auto base = state.registers[2];
        const auto &data = c.memory[2].input;
        std::size_t offset = 0, target = 256;
        std::vector<std::uint8_t> pointers, lengths;
        for (std::size_t i = 0; i < n; ++i) {
            const auto size = static_cast<std::size_t>(integer(data, offset, 8));
            offset += 8;
            append(pointers, base + target);
            append(lengths, size, 4);
            require(!size || p.memory.write(base + target, std::span(data).subspan(offset, size)),
                    "Cannot copy shader source arena");
            offset += size;
            target += size;
        }
        require(p.memory.write(base, pointers) && p.memory.write(base + 128, lengths),
                "Cannot initialize shader source descriptors");
        state.registers[3] = base + 128;
    }
    std::vector<ObservedWrite> writes;
    const auto fault = p.graphics.invoke_observed(
        GuestGraphicsServices::first_service + static_cast<std::uint32_t>(c.operation), state, writes);
    if (fault == a64::Fault::windows_service && p.terminal_error.empty())
        p.terminal_error = p.graphics.last_error();
    auto r = p.snapshot();
    r.value = state.registers[0];
    r.fault = fault;
    r.error = p.graphics.last_error();
    for (auto &write : writes) {
        require(write.address >= Impl::arena && write.address < Impl::arena + 7 * Impl::stride,
                "Graphics wrote outside its argument arena");
        const auto index = static_cast<std::uint32_t>((write.address - Impl::arena) / Impl::stride);
        const auto offset = static_cast<std::uint32_t>((write.address - Impl::arena) % Impl::stride);
        require(offset <= c.memory[index].output_capacity &&
                    write.bytes.size() <= c.memory[index].output_capacity - offset,
                "Graphics wrote outside its declared destination");
        if (!r.outputs.empty() && r.outputs.back().argument == index &&
            r.outputs.back().offset + r.outputs.back().bytes.size() == offset)
            r.outputs.back().bytes.insert(r.outputs.back().bytes.end(), write.bytes.begin(),
                                          write.bytes.end());
        else
            r.outputs.push_back({index, offset, std::move(write.bytes)});
    }
    if (r.value && fault == a64::Fault::none &&
        (c.operation == Operation::query_string || c.operation == Operation::gl_string)) {
        auto bytes = text(p.memory, r.value, 4096);
        bytes.pop_back();
        r.text.assign(bytes.begin(), bytes.end());
        r.string_result = true;
        r.value = 0;
    } else if (c.operation == Operation::proc_address && r.value) {
        require(r.value >= GuestGraphicsServices::trampoline_base &&
                    (r.value - GuestGraphicsServices::trampoline_base) % 8 == 0,
                "Invalid graphics trampoline result");
        r.value = 1 + (r.value - GuestGraphicsServices::trampoline_base) / 8;
    }
    return r;
}
GraphicsReply GraphicsExecutor::close() {
    auto &p = *impl_;
    require(p.owner == std::this_thread::get_id(), "Graphics close belongs to another thread",
            a64::Fault::invalid_call);
    if (!p.closed) {
        p.closed = true;
        p.graphics.shutdown();
        p.memory.unmap(Impl::arena);
    }
    return p.snapshot();
}
const Metrics &GraphicsExecutor::metrics() const noexcept { return impl_->graphics.metrics(); }
const HostInfo &GraphicsExecutor::host_info() const noexcept { return impl_->graphics.host_info(); }
std::uint64_t GraphicsExecutor::attach_window(std::unique_ptr<host::HostSurface> surface) {
    return impl_->graphics.attach_window(std::move(surface));
}
void GraphicsExecutor::detach_window(std::uint64_t token) { impl_->graphics.detach_window(token); }
GraphicsReply GraphicsExecutor::bind_shared_window(const SharedWindowGrant &grant) {
    auto &p = *impl_;
    require(!p.closed && p.terminal_error.empty(), "Graphics executor is closed after binding failure");
    p.graphics.bind_shared_window(grant);
    if (!p.graphics.last_error().empty())
        p.terminal_error = p.graphics.last_error();
    return p.snapshot();
}
} // namespace aether::graphics
