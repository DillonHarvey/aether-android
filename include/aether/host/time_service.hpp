#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include "aether/host/windows/unique_handle.hpp"

namespace aether::host {
struct MonotonicTime {
    std::uint64_t seconds = 0, nanoseconds = 0;
};
// UTC Unix epoch, normalized to floor seconds and nonnegative fractional nanoseconds.
struct EpochTime {
    std::int64_t seconds = 0;
    std::uint64_t nanoseconds = 0;
};

struct LocalTime {
    std::int32_t second = 0, minute = 0, hour = 0, day = 0, month = 0, year = 0;
    std::int32_t weekday = 0, yearday = 0, is_dst = 0;
    std::int64_t utc_offset = 0;
    std::string zone;
};

enum class TimeStatus { ok, denied, unavailable, out_of_range };
class TimeService {
  public:
    virtual ~TimeService() = default;
    virtual TimeStatus read_monotonic(MonotonicTime &value) const noexcept = 0;
    // Absolute UTC time requires separate provider/capability support.
    virtual TimeStatus read_wall_time(EpochTime &) const noexcept { return TimeStatus::unavailable; }
    // Uses the provider's real local timezone; errors leave the output unchanged.
    virtual TimeStatus convert_local_time(std::int64_t, LocalTime &) const noexcept { return TimeStatus::unavailable; }
    // Time since host boot excluding sleep/hibernation. Providers must opt in;
    // an arbitrary monotonic clock does not have the required suspend semantics.
    virtual TimeStatus read_uptime(MonotonicTime &) const noexcept { return TimeStatus::unavailable; }
    virtual TimeStatus read_elapsed_realtime(MonotonicTime &) const noexcept { return TimeStatus::unavailable; }
    virtual TimeStatus read_thread_cpu(MonotonicTime &) const noexcept { return TimeStatus::unavailable; }
    virtual TimeStatus read_process_start_uptime(MonotonicTime &) const noexcept { return TimeStatus::unavailable; }
};
// Host service exposes values, never host pointers or guest ABI structures.
class HostTimeService final : public TimeService {
  public:
    HostTimeService();
    bool monotonic(MonotonicTime &value) const noexcept;
    TimeStatus read_monotonic(MonotonicTime &value) const noexcept override {
        return monotonic(value) ? TimeStatus::ok : TimeStatus::unavailable;
    }
    TimeStatus read_uptime(MonotonicTime &value) const noexcept override;
    TimeStatus read_wall_time(EpochTime &value) const noexcept override;
    TimeStatus convert_local_time(std::int64_t epoch, LocalTime &value) const noexcept override;
    TimeStatus read_elapsed_realtime(MonotonicTime &value) const noexcept override;
    TimeStatus read_thread_cpu(MonotonicTime &value) const noexcept override;
    TimeStatus read_process_start_uptime(MonotonicTime &value) const noexcept override;
    // Trusted host binding only: duplicate query-only, non-inherited ownership.
    void bind_thread(HANDLE thread, std::uint32_t expected_process,
                     std::optional<MonotonicTime> process_start = {});
    void unbind_thread() noexcept { thread_.reset(); process_start_.reset(); }
    std::uint64_t frequency() const noexcept { return frequency_; }

  private:
    std::uint64_t frequency_ = 0;
    UniqueHandle thread_;
    std::optional<MonotonicTime> process_start_;
};
} // namespace aether::host
