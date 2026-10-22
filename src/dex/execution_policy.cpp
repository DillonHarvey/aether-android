#include "execution_policy.hpp"
#include <array>
namespace aether::dex {
std::optional<HostClass> execution_policy_class(std::string_view type) {
    static constexpr std::array<std::string_view, 1> interfaces{rejection_handler_type};
    if (type == abort_policy_type)
        return HostClass{"Ljava/lang/Object;", interfaces};
    if (type == rejection_handler_type)
        return HostClass{"Ljava/lang/Object;", {}, true, true};
    if (type == rejected_execution_type)
        return HostClass{"Ljava/lang/RuntimeException;"};
    return {};
}
std::optional<Value> AbortPolicy::invoke(ManagedRuntime &runtime, std::string_view owner,
                                        std::string_view name, std::string_view signature) {
    if (owner == abort_policy_type && name == "<init>" && signature == "()V") {
        if (initialized_)
            throw DexError("AETHER_DEX_STATE", "AbortPolicy constructor invoked twice");
        initialized_ = true;
        return Value::nothing();
    }
    if ((owner == abort_policy_type || owner == rejection_handler_type) && name == "rejectedExecution" &&
        signature == "(Ljava/lang/Runnable;Ljava/util/concurrent/ThreadPoolExecutor;)V") {
        if (!initialized_)
            throw DexError("AETHER_DEX_STATE", "AbortPolicy must be initialized before use");
        runtime.raise(rejected_execution_type, u"Task rejected by AbortPolicy");
    }
    return {};
}
} // namespace aether::dex
