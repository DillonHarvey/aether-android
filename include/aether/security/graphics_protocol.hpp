#pragma once
#include "aether/graphics/command.hpp"
#include "aether/security/protocol.hpp"
namespace aether::security {
std::vector<std::uint8_t> encode_graphics_command(const graphics::GraphicsCommand &command);
graphics::GraphicsCommand decode_graphics_command(std::span<const std::uint8_t> bytes);
std::vector<std::uint8_t> encode_graphics_reply(const graphics::GraphicsReply &reply);
graphics::GraphicsReply decode_graphics_reply(std::span<const std::uint8_t> bytes);
} // namespace aether::security
