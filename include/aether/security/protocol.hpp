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
    icon_pixels = 61
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
} // namespace aether::security
