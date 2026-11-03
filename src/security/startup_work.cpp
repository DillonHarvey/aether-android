#include "aether/security/startup_work.hpp"
#include <Windows.h>
#include <algorithm>
#include <cstddef>
#include <limits>

namespace aether::security {
bool valid_startup_work_policy(const StartupWorkPolicy &policy) noexcept {
    return policy.version==1 && policy.absolute_awake_deadline_100ns &&
        policy.absolute_awake_deadline_100ns<=INT64_MAX && policy.user_cpu_limit_100ns &&
        policy.user_cpu_limit_100ns<=INT64_MAX && policy.memory_limit_bytes &&
        policy.memory_limit_bytes<=std::numeric_limits<std::size_t>::max();
}
StartupWorkController::StartupWorkController(const StartupWorkPolicy &policy) noexcept
    :policy_(policy),owner_(GetCurrentThreadId()) {
    if(!valid_startup_work_policy(policy_))stopped_=WorkStopReason::invalid_policy;
}
WorkStopReason StartupWorkController::check(std::uint64_t actual_work) noexcept {
    if(stopped_!=WorkStopReason::none)return stopped_;
    if(GetCurrentThreadId()!=owner_ || actual_work<last_work_)
        return stopped_=WorkStopReason::counter_error;
    ULONGLONG awake=0;QueryUnbiasedInterruptTimePrecise(&awake);
    FILETIME created{},exited{},kernel{},user{};
    if(!awake || !GetProcessTimes(GetCurrentProcess(),&created,&exited,&kernel,&user))
        return stopped_=WorkStopReason::clock_failure;
    const auto cpu=(std::uint64_t{user.dwHighDateTime}<<32)|user.dwLowDateTime;
    if(awake<last_awake_ || cpu<last_cpu_)return stopped_=WorkStopReason::counter_error;
    last_work_=actual_work;last_awake_=awake;last_cpu_=cpu;
    if(awake>=policy_.absolute_awake_deadline_100ns)return stopped_=WorkStopReason::deadline;
    if(cpu>=policy_.user_cpu_limit_100ns)return stopped_=WorkStopReason::cpu_limit;
    return WorkStopReason::none;
}
WorkGrant StartupWorkController::admit(std::uint64_t actual_work) noexcept {
    const auto stop=check(actual_work);if(stop!=WorkStopReason::none)return {0,stop};
    std::uint64_t quantum=4096;
    if(admitted_){
        const auto elapsed=last_awake_-admitted_awake_,work=actual_work-admitted_work_;
        if(elapsed && work){
            // Adapt only soft latency. Neither observed work nor this estimate
            // mints CPU time or moves the immutable absolute deadline.
            const auto target=std::min({std::uint64_t{10000},
                policy_.absolute_awake_deadline_100ns-last_awake_,
                policy_.user_cpu_limit_100ns-last_cpu_});
            quantum=work>UINT64_MAX/target?65536:work*target/elapsed;
        }
        quantum=std::clamp(quantum,std::uint64_t{256},std::uint64_t{65536});
    }
    admitted_=true;admitted_work_=actual_work;admitted_awake_=last_awake_;
    return {quantum,WorkStopReason::none};
}
} // namespace aether::security
