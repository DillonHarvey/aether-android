#pragma once
#include "aether/dex/runtime.hpp"
#include <array>
namespace aether::dex {
inline constexpr std::string_view thread_pool_type="Ljava/util/concurrent/ThreadPoolExecutor;";
inline constexpr std::string_view pool_worker_type="Laether/internal/ThreadPoolWorker;";
inline constexpr std::string_view thread_factory_type="Ljava/util/concurrent/ThreadFactory;";
inline constexpr std::string_view default_thread_factory_type="Ljava/util/concurrent/Executors$DefaultThreadFactory;";
std::optional<HostClass> thread_pool_class(std::string_view type);
class ThreadPoolState {
  public:
    bool initialized() const noexcept{return initialized_;}
    std::span<const Value> references() const noexcept{return references_;}
    void initialize(std::uint32_t core,std::uint32_t maximum,std::int64_t nanos,ObjectId queue,ObjectId factory,ObjectId handler);
    ObjectId queue() const noexcept{return references_[0].bits;}
    ObjectId factory() const noexcept{return references_[1].bits;}
    ObjectId handler() const noexcept{return references_[2].bits;}
    std::span<Value> workers() noexcept{return std::span<Value>(references_).subspan(3);}
    std::span<const Value> workers() const noexcept{return std::span<const Value>(references_).subspan(3);}
    // Logical workers may exit before their factory Thread wrappers unwind.
    // Retained worker references independently reserve bounded GC/task resources.
    std::uint32_t count() const noexcept {return live_workers;}
    std::uint32_t core()const noexcept{return core_;}
    std::uint32_t maximum()const noexcept{return maximum_;}
    std::int64_t keep_alive()const noexcept{return keep_alive_;}
    bool timeout()const noexcept{return timeout_;}
    bool shutdown()const noexcept{return shutdown_;}
    void begin_shutdown(bool stop=false)noexcept{shutdown_=true;stop_=stop_||stop;}
    bool stopped()const noexcept{return stop_;}
    bool terminated=false,terminating=false;
    std::uint32_t live_workers=0,active=0,largest=0;
    std::uint64_t completed=0,configuration=0;
    bool maintenance=false;
    std::optional<Value> invoke(ManagedRuntime &runtime,std::string_view name,std::string_view signature,
                               std::span<const Value> args,std::optional<std::uint32_t> unit);
  private:
    std::array<Value,19> references_{};
    std::uint32_t core_=0,maximum_=0;
    std::int64_t keep_alive_=0;
    bool initialized_=false,timeout_=false,shutdown_=false,stop_=false;
};
} // namespace aether::dex
