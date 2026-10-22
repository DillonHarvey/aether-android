#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
namespace aether::dex {
inline constexpr std::string_view time_unit_type="Ljava/util/concurrent/TimeUnit;";
inline constexpr std::array<std::string_view,7> time_unit_names{
    "NANOSECONDS","MICROSECONDS","MILLISECONDS","SECONDS","MINUTES","HOURS","DAYS"};
std::optional<std::size_t> time_unit_index(std::string_view name);
std::optional<std::size_t> time_unit_target(std::string_view method);
std::int64_t convert_time_unit(std::int64_t value,std::size_t source,std::size_t target);
} // namespace aether::dex
