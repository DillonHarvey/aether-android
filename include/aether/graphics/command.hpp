#pragma once
#include "aether/graphics/guest.hpp"

namespace aether::graphics {
// Ordinals are a versioned typed API registry, not host function addresses.
enum class Operation : std::uint32_t {
    get_display,
    initialize,
    choose_config,
    bind_api,
    create_context,
    create_pbuffer,
    create_window,
    make_current,
    destroy_context,
    destroy_surface,
    terminate,
    query_surface,
    swap_buffers,
    egl_error,
    proc_address,
    current_context,
    current_display,
    current_surface,
    query_string,
    release_thread,
    create_shader,
    shader_source,
    compile_shader,
    shader_iv,
    shader_log,
    delete_shader,
    create_program,
    attach_shader,
    bind_attribute,
    link_program,
    program_iv,
    program_log,
    use_program,
    uniform_location,
    uniform4f,
    delete_program,
    gen_buffers,
    bind_buffer,
    buffer_data,
    delete_buffers,
    attribute_pointer,
    enable_attribute,
    disable_attribute,
    viewport,
    clear_color,
    clear,
    enable,
    disable,
    pixel_store,
    draw_arrays,
    read_pixels,
    gl_error,
    finish,
    gl_string,
    count
};
inline constexpr std::size_t graphics_transfer_limit = 4 * 1024 * 1024;
inline constexpr std::size_t graphics_packet_limit = graphics_transfer_limit + 65536;
class GraphicsCopyError final : public std::runtime_error {
  public:
    GraphicsCopyError(a64::Fault kind, const char *message) : std::runtime_error(message), fault(kind) {}
    const a64::Fault fault;
};
struct MemoryArgument {
    bool present = false;
    std::uint32_t output_capacity = 0;
    std::vector<std::uint8_t> input;
};
struct GraphicsCommand {
    Operation operation{};
    std::array<std::uint64_t, 7> scalars{};
    std::array<std::uint32_t, 4> floats{};
    std::array<MemoryArgument, 7> memory;
};
struct GraphicsOutput {
    std::uint32_t argument = 0, offset = 0;
    std::vector<std::uint8_t> bytes;
};
struct GraphicsReply {
    std::uint64_t value = 0;
    a64::Fault fault = a64::Fault::none;
    Metrics metrics;
    HostInfo host;
    bool string_result = false;
    std::uint32_t pack_alignment = 4;
    std::string text, error;
    std::vector<GraphicsOutput> outputs;
};
class GraphicsChannel {
  public:
    virtual ~GraphicsChannel() = default;
    virtual GraphicsReply exchange(const GraphicsCommand &command) = 0;
    virtual GraphicsReply close() = 0;
};
// Builds copied arguments and preflights all destinations before any remote resource operation.
GraphicsCommand copy_command(Operation operation, const a64::ServiceState &state,
                             const a64::GuestMemory &memory, std::uint32_t pack_alignment);
void validate_command(const GraphicsCommand &command, std::uint32_t pack_alignment);
void apply_outputs(const GraphicsCommand &command, const GraphicsReply &reply, const a64::ServiceState &state,
                   a64::GuestMemory &memory);
// Parent-owned original validation/ANGLE bridge over a bounded private argument arena. No guest CPU.
class GraphicsExecutor final : public GraphicsChannel {
  public:
    explicit GraphicsExecutor(std::uint64_t app_id);
    ~GraphicsExecutor() override;
    GraphicsReply exchange(const GraphicsCommand &command) override;
    GraphicsReply close() override;
    const Metrics &metrics() const noexcept;
    const HostInfo &host_info() const noexcept;
    std::uint64_t attach_window(std::unique_ptr<host::HostSurface> surface);
    void detach_window(std::uint64_t token);
    GraphicsReply bind_shared_window(const SharedWindowGrant &grant);

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::graphics
