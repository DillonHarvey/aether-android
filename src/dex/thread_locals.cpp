#include "thread_locals.hpp"
#include <algorithm>
#include <cstring>
#include <exception>
#include <initializer_list>
#include <limits>
#include <type_traits>
#include <utility>
namespace aether::dex {
namespace {
using Slots=std::vector<ThreadLocalSlot>;
static_assert(std::is_trivially_copyable_v<ThreadLocalSlot>);
static_assert(std::is_nothrow_default_constructible_v<ThreadLocalSlot>);
static_assert(noexcept(std::declval<Slots &>().swap(std::declval<Slots &>())));
static_assert(sizeof(std::size_t)<=sizeof(std::uint64_t));
[[noreturn]] void fail(const char *code,const char *message) {throw DexError(code,message);}
std::size_t storage_bytes(std::size_t capacity) {
    if(capacity>std::numeric_limits<std::size_t>::max()/sizeof(ThreadLocalSlot))
        fail("AETHER_DEX_HEAP_LIMIT","ThreadLocal storage byte size overflows");
    return capacity*sizeof(ThreadLocalSlot);
}
std::uint64_t work_count(std::size_t construction,std::size_t zero_bytes,
                         std::size_t copies,std::size_t writes) {
    std::uint64_t result=0;
    for(const auto amount:{construction,zero_bytes,copies,writes}) {
        const auto value=static_cast<std::uint64_t>(amount);
        if(value>std::numeric_limits<std::uint64_t>::max()-result)
            fail("AETHER_DEX_THREAD_LOCAL_LIMIT","ThreadLocal work count overflows");
        result+=value;
    }
    return result;
}
void clear_slot(ThreadLocalSlot &slot) noexcept {
    // Live, trivially copyable integer/bool fields: all-zero is valid on the
    // admitted Windows target, including padding. No writes past vector size.
    std::memset(static_cast<void *>(&slot),0,sizeof(slot));
}
void write_slot(ThreadLocalSlot &slot,ObjectId key,ObjectId value) noexcept {
    // Fieldwise writes preserve the physically zeroed padding.
    slot.key=key;slot.value=value;slot.occupied=true;
}
void validate_budget(const Slots &slots,CollectionBudget budget) {
    const auto old_bytes=storage_bytes(slots.capacity());
    if(slots.size()>slots.capacity() || slots.capacity()>slots.max_size() ||
       old_bytes>budget.object_bytes || old_bytes>budget.heap_bytes ||
       budget.heap_bytes>budget.heap_limit)
        fail("AETHER_DEX_HEAP_LIMIT","ThreadLocal owner storage accounting is inconsistent");
    if(slots.capacity()>budget.maximum_elements)
        fail("AETHER_DEX_THREAD_LOCAL_LIMIT","ThreadLocal capacity exceeds its managed element bound");
}
struct Reservation {
    ManagedRuntime &runtime;
    std::size_t bytes;
    Reservation(ManagedRuntime &owner,std::size_t amount):runtime(owner),bytes(amount) {
        runtime.reserve_provider_storage(bytes);
    }
    ~Reservation() {runtime.release_provider_storage(bytes);}
    Reservation(const Reservation &)=delete;
    Reservation &operator=(const Reservation &)=delete;
};
} // namespace
std::optional<HostClass> thread_local_class(std::string_view type) {
    if(type==thread_local_type)return HostClass{"Ljava/lang/Object;"};
    if(type==supplied_thread_local_type)return HostClass{thread_local_type};
    if(type=="Ljava/util/function/Supplier;")return HostClass{"Ljava/lang/Object;",{},true,true};
    return {};
}
bool thread_local_method(std::string_view owner,std::string_view name,std::string_view signature) noexcept {
    if(owner!=thread_local_type && owner!=supplied_thread_local_type)return false;
    if(name=="<init>")return owner==thread_local_type ? signature=="()V" :
        signature=="(Ljava/util/function/Supplier;)V";
    return ((name=="get" || name=="initialValue") && signature=="()Ljava/lang/Object;") ||
        (name=="set" && signature=="(Ljava/lang/Object;)V") || (name=="remove" && signature=="()V");
}
bool thread_local_static_method(std::string_view owner,std::string_view name,std::string_view signature) noexcept {
    return owner==thread_local_type && name=="withInitial" &&
        signature=="(Ljava/util/function/Supplier;)Ljava/lang/ThreadLocal;";
}
void ThreadLocalTable::expunge(ManagedRuntime &runtime) {
    for(auto &slot:slots) {
        runtime.charge_provider_work(1);
        if(slot.occupied && !slot.key) {
            runtime.charge_provider_work(sizeof(ThreadLocalSlot));
            clear_slot(slot);
        }
    }
}
ThreadLocalSlot *ThreadLocalTable::find(ManagedRuntime &runtime,ObjectId key) {
    for(auto &slot:slots) {
        runtime.charge_provider_work(1);
        if(slot.occupied && slot.key && slot.key==key)return &slot;
    }
    return nullptr;
}
void ThreadLocalTable::erase(ManagedRuntime &runtime,ObjectId key) {
    expunge(runtime);
    if(auto *slot=find(runtime,key)) {
        runtime.charge_provider_work(sizeof(ThreadLocalSlot));
        clear_slot(*slot);
    }
}
void ThreadLocalTable::set(ManagedRuntime &runtime,ObjectId key,ObjectId value,
                          CollectionBudget budget,ThreadLocalStorageCommit commit) {
    if(!key || !commit.adopt)
        fail("AETHER_DEX_THREAD_LOCAL_STATE","ThreadLocal publication requires an authenticated key and storage owner");
    validate_budget(slots,budget);
    const auto maximum=std::min(budget.maximum_elements,
        std::min(slots.max_size(),std::numeric_limits<std::size_t>::max()/sizeof(ThreadLocalSlot)));
    const auto store_without_growth=[&] {
        expunge(runtime);
        if(auto *slot=find(runtime,key)) {
            runtime.charge_provider_work(1);
            slot->value=value;
            return true;
        }
        for(auto &slot:slots) {
            runtime.charge_provider_work(1);
            if(!slot.occupied) {
                runtime.charge_provider_work(1);
                write_slot(slot,key,value);
                return true;
            }
        }
        if(slots.size()<slots.capacity() && slots.size()<maximum) {
            // Construction, physical zero of the entire live slot, then binding.
            runtime.charge_provider_work(work_count(1,sizeof(ThreadLocalSlot),0,1));
            slots.resize(slots.size()+1);
            clear_slot(slots.back());
            write_slot(slots.back(),key,value);
            return true;
        }
        return false;
    };
    if(store_without_growth())return;
    if(slots.size()>=maximum)
        fail("AETHER_DEX_THREAD_LOCAL_LIMIT","Logical ThreadLocal table exceeds its managed element bound");
    const auto old_capacity=slots.capacity();
    const auto increment=std::max(old_capacity/2,std::size_t{1});
    const auto grown=increment>maximum-old_capacity ? maximum : old_capacity+increment;
    const auto capacity=std::max(slots.size()+1,grown);
    const auto new_bytes=storage_bytes(capacity);
    if(new_bytes>budget.heap_limit)
        fail("AETHER_DEX_HEAP_LIMIT","ThreadLocal replacement capacity exceeds the managed heap quota");
    if(new_bytes>budget.heap_limit-budget.heap_bytes) {
        // One bounded collection may clear weak keys. Reuse that actual space
        // before allocating; no slot pointer survives this admission boundary.
        runtime.collect();
        validate_budget(slots,budget);
        if(store_without_growth())return;
        if(new_bytes>budget.heap_limit-budget.heap_bytes)
            fail("AETHER_DEX_HEAP_LIMIT","ThreadLocal old and replacement capacities exceed the shared heap quota");
    }
    const auto old_bytes=storage_bytes(old_capacity);
    // Full fresh allocation stays charged alongside the old owner capacity.
    // Declare the guard first: failure destroys fresh BEFORE refunding its bytes.
    const auto collections_before=runtime.metrics().collections;
    Reservation reservation(runtime,new_bytes);
    if(runtime.metrics().collections!=collections_before) {
        validate_budget(slots,budget);
        if(store_without_growth())return;
    }
    const auto size=slots.size();
    {
        Slots fresh;
        fresh.reserve(capacity);
        // Current MSVC C++20 allocator reserve is exact; never repair a larger
        // allocation using a collecting admission after it already exists.
        if(fresh.capacity()!=capacity)
            fail("AETHER_DEX_THREAD_LOCAL_STORAGE_UNSUPPORTED","ThreadLocal allocation changed its admitted capacity");
        // Allocation succeeded. Admit every construction/zero/copy/write visit
        // before the nonthrowing population and publication that follow.
        runtime.charge_provider_work(work_count(capacity,new_bytes,size,1));
        fresh.resize(capacity);
        std::memset(static_cast<void *>(fresh.data()),0,new_bytes);
        for(std::size_t at=0;at<size;++at) {
            fresh[at].key=slots[at].key;
            fresh[at].value=slots[at].value;
            fresh[at].occupied=slots[at].occupied;
        }
        write_slot(fresh[size],key,value);
        fresh.resize(size+1);
        slots.swap(fresh);
    } // Old buffer is physically freed; all throwing work preceded publication.
    commit.adopt(commit.context,old_bytes,new_bytes,reservation.bytes);
    if(reservation.bytes!=0)std::terminate(); // Trusted no-throw adoption contract.
}
}
