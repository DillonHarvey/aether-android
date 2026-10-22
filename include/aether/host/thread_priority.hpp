#pragma once
#include <cstdint>
#include <functional>
#include <optional>
namespace aether::host {
struct PriorityResult {unsigned error=0;std::int32_t nice=0;};
using PriorityService=std::function<PriorityResult(std::optional<std::int32_t>)>;
bool priority_profile_supported(std::int32_t) noexcept;
std::optional<int> priority_profile_target(int baseline,std::int32_t nice) noexcept;
std::optional<int> current_thread_priority() noexcept;
bool apply_thread_priority(int baseline,std::int32_t nice) noexcept;
bool restore_thread_priority(int snapshot) noexcept;
}
