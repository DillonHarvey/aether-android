#pragma once
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include "aether/common/process_exit.hpp"

namespace aether::dex {
// Cooperative host foundation only; not a Java scheduler or a guest acceptance
// boundary. Callbacks must reach checkpoints and must not suppress cancellation.
// The isolated process watchdog remains required for noncooperative computation.
class Scheduler final {
  public:
    using TaskId = std::uint64_t;
    enum class State { runnable, running, sleeping, parked, completed, cancelled, failed };
    struct Limits {
        std::size_t contexts = 16;
        std::size_t stack_reserve = 1024 * 1024;
        std::size_t stack_commit = 64 * 1024;
    };
    Scheduler();
    explicit Scheduler(int owner_priority_baseline);
    explicit Scheduler(Limits limits);
    // Trusted same-owner CPU sampler; ticks are kernel+user time in 100ns units.
    // The overload allows deterministic host tests, never guest registration.
    using CpuClock = std::function<std::optional<std::uint64_t>()>;
    Scheduler(Limits limits, CpuClock cpu_clock);
    // Adjust an authorized reading of this same OS owner's CPU clock. A running
    // task gets only its own slices; main excludes all completed task slices,
    // including released tasks. Failed accounting is explicit, never zero-filled.
    std::uint64_t logical_cpu_ticks(std::uint64_t authorized_raw_ticks) const;
    ~Scheduler();
    Scheduler(const Scheduler &) = delete;
    Scheduler &operator=(const Scheduler &) = delete;
    TaskId submit(std::function<void()> callback,std::optional<std::int32_t> inherited_priority={});
    // External owner main only. Resume at most one ready context; never wait.
    bool run_one();
    void yield();
    void sleep_for(std::chrono::milliseconds duration);
    // A coalesced permit is consumed before checking a timed park's deadline.
    // Wake/timeout can return without a permit; sleep_for never consumes one.
    void park();
    void park_until(std::chrono::steady_clock::time_point deadline);
    void unpark(TaskId task);
    void cancel(TaskId task);
    // Wake sleeping or parked contexts without creating a parking permit.
    void wake(TaskId task);
    std::optional<std::chrono::steady_clock::time_point> next_deadline() const;
    // Terminal contexts retain status/exception and occupy a slot until release.
    void release(TaskId task);
    void close();
    // Narrow Android priority bridge: 0 restores the owner's initial Win32
    // priority; 10 lowers it to at most BELOW_NORMAL. Applied per logical task
    // across fiber switches, never raises above the captured owner baseline.
    // Other Linux nice values are explicitly unsupported.
    void set_current_priority(std::int32_t nice);
    std::int32_t current_priority() const;
    int priority_baseline() const;
    void bind_process_state(std::shared_ptr<ProcessState> state);
    // Token tracks scheduler-owned switches only. Direct Win32 fiber switches are
    // unsupported; instance entry points verify the actual current fiber.
    static TaskId execution_token() noexcept;
    TaskId current() const;
    bool contains(TaskId task) const;
    State state(TaskId task) const;
    std::exception_ptr exception(TaskId task) const;
    std::size_t size() const;
  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::dex
