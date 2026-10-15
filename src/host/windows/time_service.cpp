#include "aether/host/time_service.hpp"
#include <limits>
#include <stdexcept>
#include <windows.h>

namespace aether::host {
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
} // namespace aether::host
