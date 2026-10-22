#include "futures.hpp"
namespace aether::dex {
std::optional<HostClass> future_class(std::string_view type) {
    static constexpr std::array<std::string_view,2> runnable_future{"Ljava/lang/Runnable;",future_type};
    static constexpr std::array<std::string_view,1> implementation{runnable_future_type};
    if(type==callable_type || type==future_type)return HostClass{"Ljava/lang/Object;",{},true,true};
    if(type==runnable_future_type)return HostClass{"Ljava/lang/Object;",runnable_future,true,true};
    if(type==future_task_type)return HostClass{"Ljava/lang/Object;",implementation};
    if(type==cancellation_type)return HostClass{"Ljava/lang/IllegalStateException;"};
    if(type==execution_exception_type || type==timeout_exception_type)return HostClass{"Ljava/lang/Exception;"};
    return {};
}
} // namespace aether::dex
