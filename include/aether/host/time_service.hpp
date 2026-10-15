#pragma once
#include <cstdint>

namespace aether::host {
struct MonotonicTime {
    std::uint64_t seconds = 0, nanoseconds = 0;
};
enum class TimeStatus { ok, denied, unavailable };
class TimeService {
  public:
    virtual ~TimeService() = default;
    virtual TimeStatus read_monotonic(MonotonicTime &value) const noexcept = 0;
};
// Host service exposes values, never host pointers or guest ABI structures.
class HostTimeService final : public TimeService {
  public:
    HostTimeService();
    bool monotonic(MonotonicTime &value) const noexcept;
    TimeStatus read_monotonic(MonotonicTime &value) const noexcept override {
        return monotonic(value) ? TimeStatus::ok : TimeStatus::unavailable;
    }
    std::uint64_t frequency() const noexcept { return frequency_; }

  private:
    std::uint64_t frequency_ = 0;
};
} // namespace aether::host
