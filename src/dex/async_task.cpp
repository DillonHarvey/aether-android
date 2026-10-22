#include "async_task.hpp"
#include "futures.hpp"
#include "execution_policy.hpp"
#include "thread_pool.hpp"
namespace aether::dex {
bool async_internal_type(std::string_view type) noexcept {
    return type==async_callable_type || type==async_future_type || type==async_serial_type ||
        type==async_serial_wrapper_type || type==async_factory_type || type==async_backup_policy_type;
}
std::optional<HostClass> async_task_class(std::string_view type) {
    static constexpr std::array<std::string_view,1> callable{callable_type},runnable{"Ljava/lang/Runnable;"},
        executor{"Ljava/util/concurrent/Executor;"},factory{thread_factory_type},handler{rejection_handler_type};
    if(type==async_task_type)return HostClass{"Ljava/lang/Object;",{},true};
    if(type==async_status_type)return HostClass{"Ljava/lang/Enum;"};
    if(type==async_callable_type)return HostClass{"Ljava/lang/Object;",callable};
    if(type==async_future_type)return HostClass{future_task_type};
    if(type==async_serial_type)return HostClass{"Ljava/lang/Object;",executor};
    if(type==async_serial_wrapper_type)return HostClass{"Ljava/lang/Object;",runnable};
    if(type==async_factory_type)return HostClass{"Ljava/lang/Object;",factory};
    if(type==async_backup_policy_type)return HostClass{"Ljava/lang/Object;",handler};
    if(type==android_process_type || type==android_binder_type)return HostClass{"Ljava/lang/Object;"};
    return {};
}
} // namespace aether::dex
