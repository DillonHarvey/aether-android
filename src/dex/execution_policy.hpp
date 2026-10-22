#pragma once
#include "aether/dex/runtime.hpp"
namespace aether::dex {
inline constexpr std::string_view abort_policy_type = "Ljava/util/concurrent/ThreadPoolExecutor$AbortPolicy;";
inline constexpr std::string_view rejection_handler_type = "Ljava/util/concurrent/RejectedExecutionHandler;";
inline constexpr std::string_view rejected_execution_type = "Ljava/util/concurrent/RejectedExecutionException;";
std::optional<HostClass> execution_policy_class(std::string_view type);
class AbortPolicy {
  public:
    std::optional<Value> invoke(ManagedRuntime &runtime, std::string_view owner, std::string_view name,
                               std::string_view signature);
  private:
    bool initialized_ = false;
};
} // namespace aether::dex
