#pragma once
#include "aether/host/time_service.hpp"
#include "aether/common/text.hpp"
#include <chrono>
namespace aether::host {
inline bool valid_local_time(const LocalTime &value) noexcept {
    try {
        const auto year=std::int64_t{value.year}+1900;
        if(year<1601 || year>9999 || value.month<0 || value.month>11 || value.day<1 || value.day>31 ||
           value.hour<0 || value.hour>23 || value.minute<0 || value.minute>59 || value.second<0 || value.second>59 ||
           value.is_dst<0 || value.is_dst>1 || value.utc_offset< -86400 || value.utc_offset>86400 ||
           value.zone.empty() || value.zone.size()>256 || value.zone.find('\0')!=std::string::npos)return false;
        (void)aether::utf16(value.zone);
        const std::chrono::year_month_day date{std::chrono::year{static_cast<int>(year)},std::chrono::month{static_cast<unsigned>(value.month+1)},std::chrono::day{static_cast<unsigned>(value.day)}};
        if(!date.ok())return false;
        const auto days=std::chrono::sys_days{date};
        const auto start=std::chrono::sys_days{std::chrono::year{static_cast<int>(year)}/1/1};
        return value.weekday==static_cast<std::int32_t>(std::chrono::weekday{days}.c_encoding()) && value.yearday==(days-start).count();
    }catch(...){return false;}
}
inline bool local_time_matches_epoch(const LocalTime &value,std::int64_t epoch) noexcept {
    if(!valid_local_time(value))return false;
    const std::chrono::year_month_day date{std::chrono::year{value.year+1900},std::chrono::month{static_cast<unsigned>(value.month+1)},std::chrono::day{static_cast<unsigned>(value.day)}};
    const auto seconds=static_cast<std::int64_t>(std::chrono::sys_days{date}.time_since_epoch().count())*86400 + value.hour*3600 + value.minute*60 + value.second;
    return seconds-value.utc_offset==epoch;
}
}
