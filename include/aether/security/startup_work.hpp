#pragma once
#include "aether/common/work_admission.hpp"
#include <cstdint>

namespace aether::security {
struct StartupWorkPolicy {
    std::uint64_t version=1;
    std::uint64_t absolute_awake_deadline_100ns=0;
    std::uint64_t user_cpu_limit_100ns=0;
    std::uint64_t memory_limit_bytes=0;
};
bool valid_startup_work_policy(const StartupWorkPolicy &) noexcept;
// Internal metering is independent of guest clock grants. The parent job and
// watchdog retain hard authority; this object cannot extend either limit.
class StartupWorkController final:public WorkAdmission {
  public:
    explicit StartupWorkController(const StartupWorkPolicy &) noexcept;
    StartupWorkController(const StartupWorkController &)=delete;
    StartupWorkController &operator=(const StartupWorkController &)=delete;
    WorkStopReason check(std::uint64_t actual_work) noexcept override;
    WorkGrant admit(std::uint64_t actual_work) noexcept override;
    WorkStopReason stop_reason() const noexcept override {return stopped_;}
  private:
    const StartupWorkPolicy policy_;
    std::uint32_t owner_=0;
    WorkStopReason stopped_=WorkStopReason::none;
    std::uint64_t last_work_=0,last_awake_=0,last_cpu_=0;
    std::uint64_t admitted_work_=0,admitted_awake_=0;
    bool admitted_=false;
};
} // namespace aether::security
