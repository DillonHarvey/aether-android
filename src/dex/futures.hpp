#pragma once
#include "aether/dex/runtime.hpp"
#include <array>

namespace aether::dex {
inline constexpr std::string_view callable_type="Ljava/util/concurrent/Callable;";
inline constexpr std::string_view future_type="Ljava/util/concurrent/Future;";
inline constexpr std::string_view runnable_future_type="Ljava/util/concurrent/RunnableFuture;";
inline constexpr std::string_view future_task_type="Ljava/util/concurrent/FutureTask;";
inline constexpr std::string_view cancellation_type="Ljava/util/concurrent/CancellationException;";
inline constexpr std::string_view execution_exception_type="Ljava/util/concurrent/ExecutionException;";
inline constexpr std::string_view timeout_exception_type="Ljava/util/concurrent/TimeoutException;";
std::optional<HostClass> future_class(std::string_view descriptor);
// Original fixed storage. A terminal Future may still have an executing runner.
// Active action/result roots survive cancellation until that runner unwinds.
struct FutureState {
    enum class State { pending, normal, failed, cancelled, aborted };
    State state=State::pending;
    bool initialized=false,runnable=false,runner_active=false;
    // action, configured result, outcome, cause, runner, active action/result, transient outcome
    std::array<Value,8> roots{};
    std::array<Value,17> waiters{};
    std::array<Scheduler::TaskId,17> waiter_tasks{};
    std::exception_ptr host_failure;
};
} // namespace aether::dex
