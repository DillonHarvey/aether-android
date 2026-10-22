#include "thread_locals.hpp"
#include <algorithm>
namespace aether::dex {
std::optional<HostClass> thread_local_class(std::string_view type) {
    if(type==thread_local_type)return HostClass{"Ljava/lang/Object;"};
    if(type=="Ljava/util/function/Supplier;")return HostClass{"Ljava/lang/Object;",{},true,true};
    return {};
}
bool thread_local_method(std::string_view name,std::string_view signature) noexcept {
    return (name=="<init>" && signature=="()V") || ((name=="get" || name=="initialValue") && signature=="()Ljava/lang/Object;") ||
        (name=="set" && signature=="(Ljava/lang/Object;)V") || (name=="remove" && signature=="()V");
}
void ThreadLocalTable::expunge() noexcept {for(auto &slot:slots)if(slot.occupied && !slot.key)slot={};}
ThreadLocalSlot *ThreadLocalTable::find(ObjectId key) noexcept {for(auto &slot:slots)if(slot.occupied && slot.key==key)return &slot;return nullptr;}
void ThreadLocalTable::set(ManagedRuntime &runtime,ObjectId key,ObjectId value,CollectionBudget budget) {
    expunge();
    if(auto *slot=find(key)){slot->value=value;return;}
    for(auto &slot:slots)if(!slot.occupied){slot={key,value,true};return;}
    if(slots.size()>=budget.maximum_elements)throw DexError("AETHER_DEX_THREAD_LOCAL_LIMIT","Logical ThreadLocal table exceeds managed element bound");
    if(slots.size()==slots.capacity()) {
        const auto capacity=std::min(budget.maximum_elements,slots.capacity()?(slots.capacity()>budget.maximum_elements/2?budget.maximum_elements:slots.capacity()*2):std::size_t{16});
        if(capacity>budget.heap_limit/sizeof(ThreadLocalSlot))throw DexError("AETHER_DEX_HEAP_LIMIT","ThreadLocal table capacity exceeds managed heap quota");
        const auto before=bytes(),after=capacity*sizeof(ThreadLocalSlot);
        if(after-before>budget.heap_limit-budget.heap_bytes) {
            runtime.collect();expunge();
            for(auto &slot:slots)if(!slot.occupied){slot={key,value,true};return;}
        }
        if(after-before>budget.heap_limit-budget.heap_bytes)throw DexError("AETHER_DEX_HEAP_LIMIT","ThreadLocal table growth exceeds managed heap quota");
        std::vector<ThreadLocalSlot> next;next.reserve(capacity);next.insert(next.end(),slots.begin(),slots.end());
        const auto actual=next.capacity()*sizeof(ThreadLocalSlot);
        if(next.capacity()>budget.maximum_elements || actual-before>budget.heap_limit-budget.heap_bytes)
            throw DexError("AETHER_DEX_HEAP_LIMIT","ThreadLocal table allocation exceeds managed heap quota");
        slots.swap(next);budget.object_bytes+=actual-before;budget.heap_bytes+=actual-before;
    }
    slots.push_back({key,value,true});
}
}
