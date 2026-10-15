#pragma once
#include "aether/graphics/selftest.hpp"
#include "aether/security/graphics_channel.hpp"
namespace aether::security {
std::vector<std::uint8_t> encode_graphics_result(const graphics::SelftestReport &report);
graphics::SelftestReport decode_graphics_result(std::span<const std::uint8_t> bytes);
void run_graphics_worker(HANDLE reader, HANDLE writer, std::uint64_t session, std::uint64_t app_id);
} // namespace aether::security
