#include "thread_pool.hpp"
#include "execution_policy.hpp"
#include "time_units.hpp"
#include <bit>
namespace aether::dex {
std::optional<HostClass> thread_pool_class(std::string_view type) {
    static constexpr std::array<std::string_view,1> executor{"Ljava/util/concurrent/Executor;"};
    static constexpr std::array<std::string_view,1> service{"Ljava/util/concurrent/ExecutorService;"};
    static constexpr std::array<std::string_view,1> factory{thread_factory_type};
    if(type=="Ljava/util/concurrent/Executor;")return HostClass{"Ljava/lang/Object;",{},true,true};
    if(type=="Ljava/util/concurrent/ExecutorService;")return HostClass{"Ljava/lang/Object;",executor,true,true};
    if(type=="Ljava/util/concurrent/AbstractExecutorService;")return HostClass{"Ljava/lang/Object;",service,true};
    if(type==thread_pool_type)return HostClass{"Ljava/util/concurrent/AbstractExecutorService;"};
    if(type==pool_worker_type) {static constexpr std::array<std::string_view,1> runnable{"Ljava/lang/Runnable;"};return HostClass{"Ljava/lang/Object;",runnable};}
    if(type==thread_factory_type)return HostClass{"Ljava/lang/Object;",{},true,true};
    if(type==default_thread_factory_type)return HostClass{"Ljava/lang/Object;",factory};
    return {};
}
void ThreadPoolState::initialize(std::uint32_t core,std::uint32_t maximum,std::int64_t nanos,ObjectId queue,ObjectId factory,ObjectId handler) {
    if(initialized_)throw DexError("AETHER_DEX_STATE","ThreadPoolExecutor constructor invoked twice");
    core_=core;maximum_=maximum;keep_alive_=nanos;
    references_[0]=Value::reference(queue);references_[1]=Value::reference(factory);references_[2]=Value::reference(handler);initialized_=true;
}
std::optional<Value> ThreadPoolState::invoke(ManagedRuntime &runtime,std::string_view name,std::string_view signature,
                                            std::span<const Value> args,std::optional<std::uint32_t> unit) {
    if(!initialized_)throw DexError("AETHER_DEX_STATE","ThreadPoolExecutor must be initialized before use");
    if(name=="getCorePoolSize"&&signature=="()I")return Value::word(core_);
    if(name=="getMaximumPoolSize"&&signature=="()I")return Value::word(maximum_);
    if(name=="getKeepAliveTime"&&signature=="(Ljava/util/concurrent/TimeUnit;)J")
        return Value::wide(static_cast<std::uint64_t>(convert_time_unit(keep_alive_,0,unit.value())));
    if(name=="getQueue"&&signature=="()Ljava/util/concurrent/BlockingQueue;")return references_[0];
    if(name=="getThreadFactory"&&signature=="()Ljava/util/concurrent/ThreadFactory;")return references_[1];
    if(name=="getRejectedExecutionHandler"&&signature=="()Ljava/util/concurrent/RejectedExecutionHandler;")return references_[2];
    if(name=="allowsCoreThreadTimeOut"&&signature=="()Z")return Value::word(timeout_);
    if(name=="allowCoreThreadTimeOut"&&signature=="(Z)V") {
        if(args[1].bits && !keep_alive_)runtime.raise("Ljava/lang/IllegalArgumentException;");
        timeout_=args[1].bits!=0;++configuration;return Value::nothing();
    }
    if((name=="setCorePoolSize"||name=="setMaximumPoolSize")&&signature=="(I)V") {
        const auto n=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[1].bits));
        if(n<0||(name=="setCorePoolSize"?static_cast<std::uint32_t>(n)>maximum_:
              n==0||static_cast<std::uint32_t>(n)<core_))runtime.raise("Ljava/lang/IllegalArgumentException;");
        if(name=="setCorePoolSize")core_=static_cast<std::uint32_t>(n);else maximum_=static_cast<std::uint32_t>(n);
        ++configuration;return Value::nothing();
    }
    if(name=="setKeepAliveTime"&&signature=="(JLjava/util/concurrent/TimeUnit;)V") {
        const auto value=std::bit_cast<std::int64_t>(args[1].bits);
        if(value<0||(value==0&&timeout_))runtime.raise("Ljava/lang/IllegalArgumentException;");
        keep_alive_=convert_time_unit(value,unit.value(),0);++configuration;return Value::nothing();
    }
    if((name=="setThreadFactory"&&signature=="(Ljava/util/concurrent/ThreadFactory;)V")||
       (name=="setRejectedExecutionHandler"&&signature=="(Ljava/util/concurrent/RejectedExecutionHandler;)V")) {
        if(!args[1].bits)runtime.raise("Ljava/lang/NullPointerException;");
        references_[name=="setThreadFactory"?1:2]=args[1];return Value::nothing();
    }
    if(name=="isShutdown"&&signature=="()Z")return Value::word(shutdown_);
    if(name=="isTerminated"&&signature=="()Z")return Value::word(terminated);
    if(name=="isTerminating"&&signature=="()Z")return Value::word(shutdown_&&!terminated);
    if(name=="getPoolSize"&&signature=="()I")return Value::word(count());
    if(name=="getActiveCount"&&signature=="()I")return Value::word(active);
    if(name=="getLargestPoolSize"&&signature=="()I")return Value::word(largest);
    if(name=="getCompletedTaskCount"&&signature=="()J")return Value::wide(completed);
    return {};
}
} // namespace aether::dex
