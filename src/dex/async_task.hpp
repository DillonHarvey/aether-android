#pragma once
#include "aether/dex/runtime.hpp"
#include <array>
namespace aether::dex {
inline constexpr std::string_view async_task_type="Landroid/os/AsyncTask;";
inline constexpr std::string_view async_status_type="Landroid/os/AsyncTask$Status;";
inline constexpr std::string_view async_callable_type="Laether/internal/AsyncTaskCallable;";
inline constexpr std::string_view async_future_type="Laether/internal/AsyncTaskFuture;";
inline constexpr std::string_view async_serial_type="Laether/internal/AsyncSerialExecutor;";
inline constexpr std::string_view async_serial_wrapper_type="Laether/internal/AsyncSerialRunnable;";
inline constexpr std::string_view async_factory_type="Laether/internal/AsyncThreadFactory;";
inline constexpr std::string_view async_backup_policy_type="Laether/internal/AsyncBackupPolicy;";
inline constexpr std::string_view android_process_type="Landroid/os/Process;";
inline constexpr std::string_view android_binder_type="Landroid/os/Binder;";
std::optional<HostClass> async_task_class(std::string_view type);
bool async_internal_type(std::string_view type) noexcept;
struct AsyncTaskState {
    enum class Status : std::uint32_t {pending,running,finished};
    Status status=Status::pending;
    bool initialized=false,cancel_requested=false,invoked=false,result_posted=false;
    std::array<Value,3> roots{}; // authentic Future, original params, result while posting
};
struct AsyncSdkState {
    enum class Kind {callable,serial,serial_wrapper,factory,backup_policy};
    Kind kind;
    explicit AsyncSdkState(Kind kind):kind(kind){}
    // Serial: active then sixteen queued wrappers. Others: owning task/executor,
    // inner runnable. All storage and byte accounting remain fixed.
    std::array<Value,17> roots{};
    std::size_t head=0,count=0;
    std::uint64_t sequence=0;
    bool aborted=false;
};
} // namespace aether::dex
