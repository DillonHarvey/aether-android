#include "aether/host/process_info.hpp"
#include <bit>
#include <array>
#include <windows.h>
namespace aether::host {
std::uint32_t current_process_id() noexcept {
    return static_cast<std::uint32_t>(GetCurrentProcessId());
}
std::string current_process_image_basename() {
    std::array<wchar_t,32768> path{};
    const auto count=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
    if(!count || count>=path.size())return {};
    const std::wstring_view full(path.data(),count);
    const auto split=full.find_last_of(L"/\\");
    const auto name=split==std::wstring_view::npos?full:full.substr(split+1);
    if(name.empty() || name.size()>127 || name==L"." || name==L"..")return {};
    std::string result;
    for(const auto c:name){
        if(!((c>=L'a' && c<=L'z') || (c>=L'A' && c<=L'Z') || (c>=L'0' && c<=L'9') || c==L'_' || c==L'-' || c==L'.'))return {};
        result.push_back(static_cast<char>(c));
    }
    return result;
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
