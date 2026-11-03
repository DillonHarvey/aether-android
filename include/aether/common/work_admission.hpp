#pragma once
#include <cstdint>
#include <string_view>

namespace aether {
// Trusted host policy, never an app callback or a permission grant. Actual work
// is cumulative for the retained main entry, including managed/native reentry.
enum class WorkStopReason : std::uint32_t {
    none, invalid_policy, deadline, cpu_limit, clock_failure, counter_error, cancelled
};
struct WorkGrant {
    std::uint64_t quantum = 0;
    WorkStopReason stop = WorkStopReason::none;
};
class WorkAdmission {
  public:
    virtual ~WorkAdmission() = default;
    // check never renews a quantum. Both methods fail closed and never throw,
    // allocate, enter guest code, or reset the original resource authority.
    virtual WorkStopReason check(std::uint64_t actual_work) noexcept = 0;
    virtual WorkGrant admit(std::uint64_t actual_work) noexcept = 0;
    virtual WorkStopReason stop_reason() const noexcept = 0;
};
constexpr std::string_view work_stop_name(WorkStopReason reason) noexcept {
    switch(reason) {
    case WorkStopReason::none:return "AETHER_WORK_ADMITTED";
    case WorkStopReason::invalid_policy:return "AETHER_WORK_POLICY_INVALID";
    case WorkStopReason::deadline:return "AETHER_WORK_DEADLINE";
    case WorkStopReason::cpu_limit:return "AETHER_WORK_CPU_LIMIT";
    case WorkStopReason::clock_failure:return "AETHER_WORK_HOST_CLOCK";
    case WorkStopReason::counter_error:return "AETHER_WORK_COUNTER";
    case WorkStopReason::cancelled:return "AETHER_WORK_CANCELLED";
    }
    return "AETHER_WORK_POLICY_INVALID";
}
} // namespace aether
