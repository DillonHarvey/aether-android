#pragma once
#include "collections.hpp"
#include <vector>
namespace aether::dex {
inline constexpr std::string_view thread_local_type="Ljava/lang/ThreadLocal;";
inline constexpr std::string_view supplied_thread_local_type="Ljava/lang/ThreadLocal$SuppliedThreadLocal;";
// The Runtime owns construction/null-check ordering and invokes the supplier.
// supplier is a strong traced reference of the key, never a table weak key.
struct ManagedThreadLocal {bool initialized=false,supplied=false;ObjectId supplier=0;};
struct ThreadLocalSlot {ObjectId key=0,value=0;bool occupied=false;};
struct ThreadLocalStorageCommit {
    void *context=nullptr;
    // The caller validates/stabilizes its existing or staged owner BEFORE set.
    // Called once after publication AND actual old-buffer destruction, with no
    // throwing work afterward. Fresh bytes are already included in heap_bytes.
    // Adopt new-old into owner bytes, subtract old from heap and new from the
    // provider-reservation component, then consume fresh_reserved_bytes to zero.
    void (*adopt)(void *context,std::size_t old_capacity_bytes,std::size_t new_capacity_bytes,
                  std::size_t &fresh_reserved_bytes) noexcept=nullptr;
};
struct ThreadLocalTable {
    std::vector<ThreadLocalSlot> slots;
    std::size_t bytes() const noexcept{return slots.capacity()*sizeof(ThreadLocalSlot);}
    void expunge(ManagedRuntime &);
    // Do not retain a returned slot pointer across collection or managed calls.
    ThreadLocalSlot *find(ManagedRuntime &,ObjectId);
    void erase(ManagedRuntime &,ObjectId);
    // set/erase expunge internally. Caller roots the logical Thread/table owner,
    // key and binding across collection and keeps native table identity stable.
    // First-table header storage/adoption remains the Runtime caller's job.
    void set(ManagedRuntime &,ObjectId,ObjectId,CollectionBudget,ThreadLocalStorageCommit);
};
std::optional<HostClass> thread_local_class(std::string_view);
bool thread_local_method(std::string_view owner,std::string_view name,std::string_view signature) noexcept;
bool thread_local_static_method(std::string_view owner,std::string_view name,std::string_view signature) noexcept;
}
