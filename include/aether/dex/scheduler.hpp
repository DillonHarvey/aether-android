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
    enum class State { runnable, running, sleeping, parked, completed, cancelled, failed, prepared };
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
    struct SwitchHooks {
        using Callback = void (*)(void *context, TaskId task) noexcept;
        void *context = nullptr;
        Callback enter = nullptr, leave = nullptr;
    };
    TaskId submit(std::function<void()> callback,std::optional<std::int32_t> inherited_priority={});
    // Trusted host admission only. Both callbacks are required together, and
    // context is borrowed and must outlive the retained task through release,
    // including close/cancellation. Callback captures are destroyed before the
    // terminal leave hook, so they cannot be its sole context owner.
    // Hooks must not allocate or enter checked Scheduler/runtime/CPU APIs: enter
    // runs immediately before the actual fiber switch, leave immediately after
    // root identity restoration. Fallible capsule preparation belongs outside
    // these allocation-free commit hooks, before each run_one/close admission.
    // Hooked execution requires a valid slice clock. close() may resume only a
    // cancelled task to unwind after clock failure; accounting stays explicitly
    // unavailable, and its checkpoint runs before any guest work resumes.
    // Empty hooks preserve ordinary tasks; hooks alone enable no native task.
    TaskId submit(std::function<void()> callback,std::optional<std::int32_t> inherited_priority,SwitchHooks hooks);
    // Reserve the same bounded task/fiber resources without making work runnable.
    // Captures and borrowed hooks follow the submit contract. No entry or hook
    // executes before publish; cancel/release/close may discard prepared work
    // without entering its fiber or calling either switch hook. Cancelling
    // prepared work clears its hooks, ending the borrowed-context obligation.
    TaskId prepare(std::function<void()> callback,std::optional<std::int32_t> inherited_priority={});
    TaskId prepare(std::function<void()> callback,std::optional<std::int32_t> inherited_priority,SwitchHooks hooks);
    // Allocation-free trusted same-owner commit, from root or its current task.
    // False leaves state unchanged for a foreign owner/fiber/token, closed
    // scheduler, unknown ID or non-prepared task. No process/provider/clock call
    // occurs here; the eventual task-entry checkpoint still enforces termination.
    bool publish(TaskId task) noexcept;
    // Pre-publication rollback from any current owned context. Removes only a
    // still-prepared task, before destroying captures; no hook or entry runs.
    // Invalid ownership/identity/state returns false without a mutation.
    bool discard_prepared(TaskId task) noexcept;
    // External owner main only. Resume at most one ready context; never wait.
    bool run_one();
    TaskId prepare_targeted(std::function<void()>,std::optional<std::int32_t>,SwitchHooks);
    // One retained logical-main stack, still included in the context bound.
    // Targeted only; its CPU time belongs to main rather than a background task.
    TaskId prepare_main(std::function<void()>,SwitchHooks);
    bool run_main(TaskId task);
    bool run_one(TaskId task,std::int32_t priority);
    void cancel_and_unwind(TaskId task);
    bool release_terminal(TaskId task) noexcept;
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
    // A prepared context can also be released directly; its stack never entered.
    // Started runnable/parked contexts must unwind cancellation before release.
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
    TaskId admit(std::function<void()>,std::optional<std::int32_t>,SwitchHooks,bool prepared,bool target_only=false,bool logical_main=false);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::dex
