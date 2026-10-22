#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace aether::security {
// Explicit little-endian wire format. Never serialize a native C++ struct or pointer.
inline constexpr std::size_t header_bytes = 32, maximum_payload = 4096;
inline constexpr std::size_t maximum_worker_error = 512;
inline constexpr std::uint32_t protocol_magic = 0x52544841;
inline constexpr std::uint16_t protocol_version = 1;
enum class Operation : std::uint16_t {
    boot = 1,
    monotonic_time = 2,
    storage = 3,
    network = 4,
    clipboard = 5,
    camera = 6,
    microphone = 7,
    audio = 8,
    finished = 9,
    observation = 10, // Fixed bring-up stage values; never a delegated host action.
    file_open = 11,
    file_read = 12,
    file_write = 13,
    file_close = 14,
    package_info = 15,
    package_read = 16,
    uptime = 17, // Sleep-excluding clock, gated by the existing time capability.
    file_root = 18, // Empty query of the broker-selected private root, never a path.
    wall_time = 19, // UTC Unix epoch query, gated separately from monotonic time.
    elapsed_realtime = 20, // Time since boot including suspend, monotonic capability.
    file_flush = 22, // Explicit durable flush of an existing private-file token.
    thread_cpu = 21, // CPU of trusted bound guest main thread, monotonic capability.
    file_data_observe = 23, // One app-data-root leaf; separate from files/, existing private grant.
    process_start_uptime = 24, // Frozen worker execution-start uptime; existing time grant.
    file_directory = 25, // Empty query for a bounded held-private-root snapshot.
    local_calendar = 26, // Signed Unix seconds -> local calendar, existing wall-time consent.
    file_lock = 27, // Existing private-file token + flock operation; never a path/handle.
    file_access = 28, // Typed app-private namespace, safe leaf and R/W/X mask; no host path.
    activity_command = 32,
    activity_state = 33,
    activity_read_unavailable = 34, // Empty negative acknowledgement, only for a state read.
    audio_open = 40,
    audio_control = 41,
    audio_observe = 42,
    audio_wait = 43,
    audio_write_begin = 44,
    audio_write_chunk = 45,
    audio_write_commit = 46,
    audio_close = 47,
    graphics_call = 50,
    graphics_begin = 51,
    graphics_chunk = 52,
    graphics_commit = 53,
    graphics_result = 54,
    graphics_close = 55,
    graphics_window_command = 56,
    graphics_window_state = 57,
    graphics_window_unavailable = 58,
    graphics_bind_surface = 59, // Trusted host-to-graphics-service control only; never guest delegated.
    icon_result = 60,           // Dedicated metadata process only; no runtime/admission authority.
    icon_pixels = 61,
    icon_permissions = 62, // Metadata text only, never a capability grant.
    guest_exited = 63 // Terminal app-owned process exit, never startup success or broker request.
};
enum class Status : std::uint32_t { ok, denied, unsupported, invalid, quota };
struct Header {
    Operation operation = Operation::boot;
    std::uint64_t sequence = 0, session = 0;
    std::uint32_t payload_size = 0;
    Status status = Status::ok;
};
struct Frame {
    Header header;
    std::vector<std::uint8_t> payload;
};
class ProtocolError final : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};
std::array<std::uint8_t, header_bytes> encode_header(const Header &header);
Header decode_header(std::span<const std::uint8_t> bytes);
std::vector<std::uint8_t> encode_frame(const Frame &frame);
Frame decode_frame(std::span<const std::uint8_t> bytes);
void append_u64(std::vector<std::uint8_t> &bytes, std::uint64_t value);
std::uint64_t read_u64(std::span<const std::uint8_t> bytes, std::size_t offset);
void append_text(std::vector<std::uint8_t> &bytes, std::string_view text);
std::string read_text(std::span<const std::uint8_t> bytes, std::size_t &offset, std::size_t limit);
// Preserve the error code/context and terminal cause within the existing wire
// bound. Valid UTF-8 sequences are never cut at an elision boundary.
std::string bounded_worker_error(std::string_view message);
// App-owned terminal record, independent of an in-flight presentation/RPC sequence.
Frame guest_exit_frame(std::uint64_t session, std::uint8_t status);
std::uint8_t guest_exit_status(const Frame &frame, std::uint64_t session);
} // namespace aether::security
