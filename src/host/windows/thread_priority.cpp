#include "aether/host/thread_priority.hpp"
#include <algorithm>
#include <windows.h>
namespace aether::host {
bool priority_profile_supported(std::int32_t nice) noexcept {return nice==0 || nice==10;}
std::optional<int> priority_profile_target(int baseline,std::int32_t nice) noexcept {
    if(!priority_profile_supported(nice) || baseline==THREAD_PRIORITY_ERROR_RETURN)return {};
    return nice==10?std::min(baseline,int(THREAD_PRIORITY_BELOW_NORMAL)):baseline;
}
std::optional<int> current_thread_priority() noexcept {const auto value=GetThreadPriority(GetCurrentThread());if(value==THREAD_PRIORITY_ERROR_RETURN)return {};return value;}
bool apply_thread_priority(int baseline,std::int32_t nice) noexcept {const auto target=priority_profile_target(baseline,nice);return target && SetThreadPriority(GetCurrentThread(),*target);}
bool restore_thread_priority(int snapshot) noexcept {return snapshot!=THREAD_PRIORITY_ERROR_RETURN && SetThreadPriority(GetCurrentThread(),snapshot);}
}
