#pragma once
#include "collections.hpp"
#include <vector>
namespace aether::dex {
inline constexpr std::string_view thread_local_type="Ljava/lang/ThreadLocal;";
struct ManagedThreadLocal {bool initialized=false;};
struct ThreadLocalSlot {ObjectId key=0,value=0;bool occupied=false;};
struct ThreadLocalTable {
    std::vector<ThreadLocalSlot> slots;
    std::size_t bytes() const noexcept{return slots.capacity()*sizeof(ThreadLocalSlot);}
    void expunge() noexcept;
    ThreadLocalSlot *find(ObjectId) noexcept;
    void set(ManagedRuntime &,ObjectId,ObjectId,CollectionBudget);
};
std::optional<HostClass> thread_local_class(std::string_view);
bool thread_local_method(std::string_view name,std::string_view signature) noexcept;
}
