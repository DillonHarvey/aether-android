#include "aether/host/process_info.hpp"
#include <bit>
#include <windows.h>
namespace aether::host {
std::uint32_t current_process_id() noexcept {
    return static_cast<std::uint32_t>(GetCurrentProcessId());
}
std::uint32_t available_processors() noexcept {
    if (GetActiveProcessorGroupCount()!=1) return 0;
    ULONG count=0;
    if (!GetThreadSelectedCpuSets(GetCurrentThread(),nullptr,0,&count) || count) return 0;
    if (!GetProcessDefaultCpuSets(GetCurrentProcess(),nullptr,0,&count) || count) return 0;
    DWORD_PTR process_mask=0,system_mask=0;
    GROUP_AFFINITY thread{};
    if (!GetProcessAffinityMask(GetCurrentProcess(),&process_mask,&system_mask) ||
        !GetThreadGroupAffinity(GetCurrentThread(),&thread) || thread.Group!=0) return 0;
    return static_cast<std::uint32_t>(std::popcount(process_mask & system_mask & thread.Mask));
}
} // namespace aether::host
