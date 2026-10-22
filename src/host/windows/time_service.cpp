#include "aether/host/time_service.hpp"
#include <limits>
#include <stdexcept>
#include <windows.h>

namespace aether::host {
namespace {
constexpr std::int64_t unix_filetime_seconds = 11'644'473'600LL;
bool calendar_seconds(const SYSTEMTIME &calendar, std::int64_t &seconds) {
    FILETIME file{};
    if (!SystemTimeToFileTime(&calendar, &file)) return false;
    const auto ticks = (std::uint64_t{file.dwHighDateTime} << 32) | file.dwLowDateTime;
    seconds = static_cast<std::int64_t>(ticks / 10'000'000) - unix_filetime_seconds;
    return true;
}
// Windows transition rules use either an absolute date or the nth weekday of a month.
bool transition_seconds(const SYSTEMTIME &rule, WORD year, std::int64_t &seconds) {
    if (!rule.wMonth || rule.wMonth > 12) return false;
    SYSTEMTIME calendar = rule;
    if (rule.wYear) {
        if (rule.wYear != year) return false;
    } else {
        if (!rule.wDay || rule.wDay > 5 || rule.wDayOfWeek > 6) return false;
        calendar.wYear = year;
        calendar.wDay = 1;
        FILETIME first_file{};
        SYSTEMTIME first{};
        if (!SystemTimeToFileTime(&calendar, &first_file) || !FileTimeToSystemTime(&first_file, &first)) return false;
        const bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        constexpr unsigned days[]{31,28,31,30,31,30,31,31,30,31,30,31};
        const auto month_days = days[rule.wMonth - 1] + (rule.wMonth == 2 && leap ? 1U : 0U);
        auto day = 1U + (rule.wDayOfWeek + 7U - first.wDayOfWeek) % 7U + (rule.wDay - 1U) * 7U;
        if (day > month_days) day -= 7;
        calendar.wDay = static_cast<WORD>(day);
    }
    return calendar_seconds(calendar, seconds);
}
template<std::size_t N> bool zone_name(const WCHAR (&name)[N], std::string &output) {
    std::size_t length = 0;
    while (length < N && name[length]) ++length;
    if (!length || length == N) return false;
    const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name, static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (count <= 0 || count > 256) return false;
    std::string result(static_cast<std::size_t>(count), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name, static_cast<int>(length), result.data(), count, nullptr, nullptr) != count) return false;
    output = std::move(result);
    return true;
}
}
HostTimeService::HostTimeService() {
    LARGE_INTEGER frequency{};
    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0 ||
        frequency.QuadPart > std::numeric_limits<std::uint32_t>::max())
        throw std::runtime_error("Windows monotonic frequency unavailable");
    frequency_ = static_cast<std::uint64_t>(frequency.QuadPart);
}
bool HostTimeService::monotonic(MonotonicTime &value) const noexcept {
    LARGE_INTEGER counter{};
    if (!QueryPerformanceCounter(&counter) || counter.QuadPart < 0)
        return false;
    const auto ticks = static_cast<std::uint64_t>(counter.QuadPart);
    value.seconds = ticks / frequency_;
    // The constructor's frequency bound makes this multiplication fit uint64.
    value.nanoseconds = (ticks % frequency_) * 1'000'000'000 / frequency_;
    return true;
}
TimeStatus HostTimeService::read_uptime(MonotonicTime &value) const noexcept {
    ULONGLONG ticks = 0;
    // Windows 11's precise working-time clock excludes sleep/hibernation.
    // This API returns void and reports actual 100ns units; no alternate clock
    // or lower-resolution fallback is substituted.
    QueryUnbiasedInterruptTimePrecise(&ticks);
    value = {ticks / 10'000'000, (ticks % 10'000'000) * 100};
    return TimeStatus::ok;
}
TimeStatus HostTimeService::read_wall_time(EpochTime &value) const noexcept {
    FILETIME time{};
    GetSystemTimePreciseAsFileTime(&time);
    const auto ticks = static_cast<std::uint64_t>(time.dwHighDateTime) << 32 | time.dwLowDateTime;
    // Divide before subtracting: FILETIME is unsigned and may precede Unix epoch.
    // Even UINT64_MAX ticks gives seconds fitting int64_t, with no timezone conversion.
    value = {static_cast<std::int64_t>(ticks / 10'000'000) - 11'644'473'600LL,
             (ticks % 10'000'000) * 100};
    return TimeStatus::ok;
}
TimeStatus HostTimeService::convert_local_time(std::int64_t epoch, LocalTime &value) const noexcept {
    // Both the UTC input and resulting local calendar must fit Windows' supported range.
    if (epoch < -unix_filetime_seconds || epoch > 253'402'300'799LL) return TimeStatus::out_of_range;
    try {
        const auto ticks = static_cast<std::uint64_t>(epoch + unix_filetime_seconds) * 10'000'000;
        const FILETIME file{static_cast<DWORD>(ticks), static_cast<DWORD>(ticks >> 32)};
        SYSTEMTIME utc{}, local{};
        if (!FileTimeToSystemTime(&file, &utc)) return TimeStatus::out_of_range;
        DYNAMIC_TIME_ZONE_INFORMATION dynamic{};
        if (GetDynamicTimeZoneInformation(&dynamic) == TIME_ZONE_ID_INVALID) return TimeStatus::unavailable;
        if (!SystemTimeToTzSpecificLocalTimeEx(&dynamic, &utc, &local)) return TimeStatus::unavailable;
        if (local.wYear < 1601 || local.wYear > 9999) return TimeStatus::out_of_range;
        TIME_ZONE_INFORMATION annual{};
        // Annual rules take a LOCAL year, which can differ from the UTC year near January 1.
        if (dynamic.DynamicDaylightTimeDisabled) {
            // Disabling dynamic rules means fixed transition dates, not necessarily no DST.
            annual.Bias = dynamic.Bias; annual.StandardBias = dynamic.StandardBias; annual.DaylightBias = dynamic.DaylightBias;
            annual.StandardDate = dynamic.StandardDate; annual.DaylightDate = dynamic.DaylightDate;
            for (unsigned i = 0; i < 32; ++i) {
                annual.StandardName[i] = dynamic.StandardName[i]; annual.DaylightName[i] = dynamic.DaylightName[i];
            }
        } else if (!GetTimeZoneInformationForYear(local.wYear, &dynamic, &annual)) return TimeStatus::unavailable;
        std::int64_t wall_seconds = 0;
        if (!calendar_seconds(local, wall_seconds)) return TimeStatus::out_of_range;
        const auto offset = wall_seconds - epoch;
        const auto standard_offset = -(std::int64_t{annual.Bias} + (annual.StandardDate.wMonth ? annual.StandardBias : 0)) * 60;
        const auto daylight_offset = -(std::int64_t{annual.Bias} + annual.DaylightBias) * 60;
        bool daylight = false;
        if (annual.DaylightDate.wMonth && annual.StandardDate.wMonth) {
            if (standard_offset != daylight_offset) {
                if (offset == daylight_offset) daylight = true;
                else if (offset != standard_offset) return TimeStatus::unavailable;
            } else {
                // Equal seasonal offsets still have distinct named/DST intervals.
                std::int64_t begin = 0, end = 0;
                if (!transition_seconds(annual.DaylightDate, local.wYear, begin) ||
                    !transition_seconds(annual.StandardDate, local.wYear, end)) return TimeStatus::unavailable;
                begin -= standard_offset;
                end -= daylight_offset;
                if (begin == end || offset != standard_offset) return TimeStatus::unavailable;
                daylight = begin < end ? epoch >= begin && epoch < end : epoch >= begin || epoch < end;
            }
        } else if (offset != standard_offset) return TimeStatus::unavailable;
        constexpr unsigned preceding[]{0,31,59,90,120,151,181,212,243,273,304,334};
        if (!local.wMonth || local.wMonth > 12 || !local.wDay) return TimeStatus::unavailable;
        const auto year = local.wYear;
        const bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        LocalTime result;
        result.second = local.wSecond; result.minute = local.wMinute; result.hour = local.wHour;
        result.day = local.wDay; result.month = local.wMonth - 1; result.year = year - 1900;
        result.weekday = local.wDayOfWeek;
        result.yearday = static_cast<std::int32_t>(preceding[local.wMonth - 1] + local.wDay - 1 + (leap && local.wMonth > 2 ? 1U : 0U));
        result.is_dst = daylight ? 1 : 0; result.utc_offset = offset;
        if (!zone_name(daylight ? annual.DaylightName : annual.StandardName, result.zone)) return TimeStatus::unavailable;
        value = std::move(result);
        return TimeStatus::ok;
    } catch (...) { return TimeStatus::unavailable; }
}
TimeStatus HostTimeService::read_elapsed_realtime(MonotonicTime &value) const noexcept {
    ULONGLONG ticks = 0;
    QueryInterruptTimePrecise(&ticks);
    value = {ticks / 10'000'000, (ticks % 10'000'000) * 100};
    return TimeStatus::ok;
}
void HostTimeService::bind_thread(HANDLE thread, std::uint32_t expected_process, std::optional<MonotonicTime> process_start) {
    if ((process_start && process_start->nanoseconds >= 1'000'000'000) ||
        thread_ || !thread || thread == INVALID_HANDLE_VALUE || !expected_process ||
        GetProcessIdOfThread(thread) != expected_process)
        throw std::runtime_error("Invalid or repeated trusted clock thread binding");
    HANDLE duplicate = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), thread, GetCurrentProcess(), &duplicate,
                         THREAD_QUERY_LIMITED_INFORMATION, FALSE, 0))
        throw std::runtime_error("Cannot retain query-only clock thread");
    UniqueHandle owned(duplicate);
    if (GetProcessIdOfThread(owned.get()) != expected_process)
        throw std::runtime_error("Clock thread identity changed during binding");
    thread_ = std::move(owned);
    process_start_ = process_start;
}
TimeStatus HostTimeService::read_process_start_uptime(MonotonicTime &value) const noexcept {
    if(!thread_ || !process_start_)return TimeStatus::unavailable;
    value=*process_start_;return TimeStatus::ok;
}
TimeStatus HostTimeService::read_thread_cpu(MonotonicTime &value) const noexcept {
    if (!thread_)
        return TimeStatus::unavailable;
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetThreadTimes(thread_.get(), &created, &exited, &kernel, &user))
        return TimeStatus::unavailable;
    const auto ticks = [](FILETIME time) {
        return static_cast<std::uint64_t>(time.dwHighDateTime) << 32 | time.dwLowDateTime;
    };
    const auto kernel_ticks = ticks(kernel), user_ticks = ticks(user);
    if (kernel_ticks > UINT64_MAX - user_ticks)
        return TimeStatus::unavailable;
    const auto total = kernel_ticks + user_ticks;
    value = {total / 10'000'000, (total % 10'000'000) * 100};
    return TimeStatus::ok;
}
} // namespace aether::host
