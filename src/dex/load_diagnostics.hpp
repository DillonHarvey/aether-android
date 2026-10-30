#pragma once
#include "aether/dex/source.hpp"
#include <atomic>
#include <new>

namespace aether::dex::detail {
// Stack-resident nodes preserve a loader's first phase even when another loader
// is entered before reentering the original one. Nothing owns labels or allocates.
struct ClassLoadAllocationScopeFrame {
    std::atomic<ClassLoadAllocationPhase> *target;
    ClassLoadAllocationScopeFrame *previous;
};
inline thread_local ClassLoadAllocationScopeFrame *active_class_load_allocation=nullptr;
class ScopedClassLoadAllocation {
  public:
    explicit ScopedClassLoadAllocation(std::atomic<ClassLoadAllocationPhase> &target) noexcept
        :frame_{&target,active_class_load_allocation} {
        bool active=false;
        for(auto *scope=frame_.previous;scope;scope=scope->previous)
            if(scope->target==&target){active=true;break;}
        if(!active)target.store(ClassLoadAllocationPhase::none,std::memory_order_relaxed);
        active_class_load_allocation=&frame_;
    }
    ~ScopedClassLoadAllocation(){active_class_load_allocation=frame_.previous;}
    ScopedClassLoadAllocation(const ScopedClassLoadAllocation &)=delete;
    ScopedClassLoadAllocation &operator=(const ScopedClassLoadAllocation &)=delete;
    ScopedClassLoadAllocation(ScopedClassLoadAllocation &&)=delete;
    ScopedClassLoadAllocation &operator=(ScopedClassLoadAllocation &&)=delete;
  private:
    ClassLoadAllocationScopeFrame frame_;
};
inline void note_class_load_allocation(ClassLoadAllocationPhase phase) noexcept {
    if(!active_class_load_allocation || phase==ClassLoadAllocationPhase::none)return;
    auto expected=ClassLoadAllocationPhase::none;
    active_class_load_allocation->target->compare_exchange_strong(expected,phase,std::memory_order_relaxed);
}
} // namespace aether::dex::detail
