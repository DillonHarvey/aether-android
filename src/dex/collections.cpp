#include "collections.hpp"
#include "deque.hpp"
#include "array_views.hpp"
#include "unmodifiable_lists.hpp"
#include "synchronized_lists.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <limits>

namespace aether::dex {
namespace {
constexpr std::string_view list_type = "Ljava/util/ArrayList;";
[[noreturn]] void limit(std::string message) {
    throw DexError("AETHER_DEX_COLLECTION_LIMIT", std::move(message));
}
} // namespace
std::optional<HostClass> collection_class(std::string_view type) {
    if(const auto wrapper=synchronized_list_metadata(type))return wrapper;
    if(const auto wrapper=unmodifiable_class(type))return wrapper;
    if(const auto deque=deque_class(type))return deque;
    static constexpr std::array<std::string_view, 2> empty_interfaces{"Ljava/util/RandomAccess;", "Ljava/io/Serializable;"};
    static constexpr std::array<std::string_view, 1> empty_iterator_interfaces{"Ljava/util/ListIterator;"};
    static constexpr std::array<std::string_view,1> live_interfaces{"Ljava/util/Iterator;"};
    if (type == live_iterator_type || type == queue_iterator_type)
        return HostClass{"Ljava/lang/Object;",live_interfaces};
    if (type == live_list_iterator_type)
        return HostClass{"Ljava/lang/Object;",empty_iterator_interfaces};
    if (type == empty_list_type || type == singleton_list_type)
        return HostClass{"Ljava/util/AbstractList;", empty_interfaces};
    if (type == empty_iterator_type)
        return HostClass{"Ljava/lang/Object;", empty_iterator_interfaces};
    static constexpr std::array<std::string_view, 2> queue_interfaces{"Ljava/util/Queue;", "Ljava/io/Serializable;"};
    static constexpr std::array<std::string_view, 1> queue_interface{"Ljava/util/Queue;"};
    static constexpr std::array<std::string_view, 2> blocking_interfaces{
        "Ljava/util/concurrent/BlockingQueue;", "Ljava/io/Serializable;"};
    if (type == blocking_queue_type || type == synchronous_queue_type)
        return HostClass{"Ljava/util/AbstractQueue;", blocking_interfaces};
    if (type == "Ljava/util/concurrent/BlockingQueue;")
        return HostClass{"Ljava/util/Queue;", {}, true, true};
    if (type == concurrent_queue_type)
        return HostClass{"Ljava/util/AbstractQueue;", queue_interfaces};
    if (type == "Ljava/util/AbstractQueue;")
        return HostClass{"Ljava/util/AbstractCollection;", queue_interface, true};
    if (type == "Ljava/util/Queue;")
        return HostClass{"Ljava/util/Collection;", {}, true, true};
    if (const auto view = array_view_class(type))
        return view;
    static constexpr std::array<std::string_view, 4> list_interfaces{
        "Ljava/util/List;", "Ljava/util/RandomAccess;", "Ljava/lang/Cloneable;", "Ljava/io/Serializable;"};
    static constexpr std::array<std::string_view, 1> abstract_list_interfaces{"Ljava/util/List;"};
    static constexpr std::array<std::string_view, 1> collection_interfaces{"Ljava/util/Collection;"};
    if (type == list_type)
        return HostClass{"Ljava/util/AbstractList;", list_interfaces};
    if (type == copy_list_type)
        return HostClass{"Ljava/lang/Object;", list_interfaces};
    static constexpr std::array<std::string_view, 1> iterator_interfaces{"Ljava/util/ListIterator;"};
    if (type == snapshot_iterator_type)
        return HostClass{"Ljava/lang/Object;", iterator_interfaces};
    if (type == "Ljava/util/ListIterator;")
        return HostClass{"Ljava/util/Iterator;", {}, true, true};
    if (type == "Ljava/util/Iterator;")
        return HostClass{"Ljava/lang/Object;", {}, true, true};
    if (type == "Ljava/util/AbstractList;")
        return HostClass{"Ljava/util/AbstractCollection;", abstract_list_interfaces, true};
    if (type == "Ljava/util/AbstractCollection;")
        return HostClass{"Ljava/lang/Object;", collection_interfaces, true};
    if (type == "Ljava/util/List;")
        return HostClass{"Ljava/util/Collection;", {}, true, true};
    if (type == "Ljava/util/Collection;")
        return HostClass{"Ljava/lang/Iterable;", {}, true, true};
    if (type == "Ljava/lang/Iterable;" || type == "Ljava/util/RandomAccess;" ||
        type == "Ljava/lang/Cloneable;" || type == "Ljava/io/Serializable;")
        return HostClass{"Ljava/lang/Object;", {}, true, true};
    return {};
}
std::optional<Value> invoke_empty_list(ManagedRuntime &runtime, std::string_view name,
                                      std::string_view signature, std::span<const Value> args) {
    if (name == "size" && signature == "()I") return Value::word(0);
    if (name == "isEmpty" && signature == "()Z") return Value::word(1);
    if ((name == "contains" || name == "remove") && signature == "(Ljava/lang/Object;)Z")
        return Value::word(0);
    if ((name == "indexOf" || name == "lastIndexOf") && signature == "(Ljava/lang/Object;)I")
        return Value::word(0xffffffff);
    if (name == "hashCode" && signature == "()I") return Value::word(1);
    if (name == "clear" && signature == "()V") return Value::nothing();
    if ((name == "get" || name == "remove") && signature == "(I)Ljava/lang/Object;")
        runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
    if ((name == "add" && (signature == "(Ljava/lang/Object;)Z" || signature == "(ILjava/lang/Object;)V")) ||
        (name == "set" && signature == "(ILjava/lang/Object;)Ljava/lang/Object;"))
        runtime.raise("Ljava/lang/UnsupportedOperationException;");
    if (name == "toArray" && signature == "()[Ljava/lang/Object;")
        return Value::reference(runtime.new_array("[Ljava/lang/Object;",0));
    if (name == "toArray" && signature == "([Ljava/lang/Object;)[Ljava/lang/Object;") {
        const auto array=args[1].bits;
        if (runtime.array_length(array)) runtime.array_set(array,0,Value::reference(0));
        return Value::reference(array);
    }
    return {};
}
std::optional<Value> invoke_empty_iterator(ManagedRuntime &runtime, std::string_view name,
                                          std::string_view signature) {
    if ((name == "hasNext" || name == "hasPrevious") && signature == "()Z") return Value::word(0);
    if (name == "nextIndex" && signature == "()I") return Value::word(0);
    if (name == "previousIndex" && signature == "()I") return Value::word(0xffffffff);
    if ((name == "next" || name == "previous") && signature == "()Ljava/lang/Object;")
        runtime.raise("Ljava/util/NoSuchElementException;");
    if ((name == "remove" && signature == "()V") || (name == "set" && signature == "(Ljava/lang/Object;)V"))
        runtime.raise("Ljava/lang/IllegalStateException;");
    if (name == "add" && signature == "(Ljava/lang/Object;)V")
        runtime.raise("Ljava/lang/UnsupportedOperationException;");
    return {};
}
std::uint64_t ManagedQueue::next_wait_ticket() {
    if(!initialized_ || !synchronous_)
        throw DexError("AETHER_DEX_STATE", "Wait tickets require an initialized SynchronousQueue");
    if(next_wait_ticket_==std::numeric_limits<std::uint64_t>::max())
        throw DexError("AETHER_DEX_COLLECTION_LIMIT", "SynchronousQueue wait identity exhausted");
    return next_wait_ticket_++;
}
void ManagedQueue::check_revision() const {
    if (revision_ == std::numeric_limits<std::uint64_t>::max())
        throw DexError("AETHER_DEX_COLLECTION_LIMIT", "Queue mutation identity exhausted");
}
void ManagedQueue::grow(CollectionBudget budget) {
    if (values_.size() == budget.maximum_elements)
        throw DexError("AETHER_DEX_COLLECTION_LIMIT", "Queue exceeds managed element bound");
    if (values_.size() < values_.capacity() && ids_.size() < ids_.capacity()) return;
    const auto requested = std::min(budget.maximum_elements,
        std::max({std::size_t(1),values_.size() * 2,values_.capacity(),ids_.capacity()}));
    const auto before = bytes();
    constexpr auto entry_bytes = sizeof(Value) + sizeof(std::uint64_t);
    if (requested > std::numeric_limits<std::size_t>::max() / entry_bytes ||
        requested * entry_bytes - before > budget.heap_limit - budget.heap_bytes)
        throw DexError("AETHER_DEX_HEAP_LIMIT", "Queue exceeds managed heap bound");
    std::vector<Value> replacement;
    std::vector<std::uint64_t> identities;
    replacement.reserve(requested); identities.reserve(requested);
    const auto after = replacement.capacity() * sizeof(Value) + identities.capacity() * sizeof(std::uint64_t);
    if (replacement.capacity() > budget.maximum_elements || identities.capacity() > budget.maximum_elements ||
        after - before > budget.heap_limit - budget.heap_bytes)
        throw DexError("AETHER_DEX_HEAP_LIMIT", "Queue allocation exceeds managed heap bound");
    replacement.insert(replacement.end(), values_.begin(), values_.end());
    identities.insert(identities.end(), ids_.begin(), ids_.end());
    values_.swap(replacement); ids_.swap(identities);
    budget.object_bytes += after - before; budget.heap_bytes += after - before;
}
void ManagedQueue::erase(std::size_t at) {
    check_revision();
    values_.erase(values_.begin() + at); ids_.erase(ids_.begin() + at); ++revision_;
}
std::optional<Value> ManagedQueue::iterate(ManagedRuntime &runtime, QueueIterator &iterator,
                                          std::string_view name, std::string_view signature) {
    if (!initialized_) throw DexError("AETHER_DEX_STATE", "Queue must be initialized before iteration");
    const auto prepare = [&] {
        if (iterator.ready || iterator.exhausted) return;
        const auto at = std::upper_bound(ids_.begin(), ids_.end(), iterator.cursor);
        if (at == ids_.end()) { iterator.exhausted = true; return; }
        const auto index = static_cast<std::size_t>(at - ids_.begin());
        iterator.pending = values_[index]; iterator.pending_id = *at; iterator.ready = true;
    };
    if (name == "hasNext" && signature == "()Z") { prepare(); return Value::word(iterator.ready); }
    if (name == "next" && signature == "()Ljava/lang/Object;") {
        prepare();
        if (!iterator.ready) runtime.raise("Ljava/util/NoSuchElementException;");
        const auto result = iterator.pending;
        iterator.cursor = iterator.last = iterator.pending_id; iterator.removable = true;
        iterator.pending = {}; iterator.pending_id = 0; iterator.ready = false;
        return result;
    }
    if (name == "remove" && signature == "()V") {
        if (!iterator.removable) runtime.raise("Ljava/lang/IllegalStateException;");
        const auto at = std::lower_bound(ids_.begin(), ids_.end(), iterator.last);
        if (at != ids_.end() && *at == iterator.last) erase(static_cast<std::size_t>(at - ids_.begin()));
        iterator.removable = false;
        return Value::nothing();
    }
    return {};
}
std::optional<Value> ManagedQueue::invoke(ManagedRuntime &runtime, std::string_view owner,
                                         std::string_view name, std::string_view signature,
                                         std::span<const Value> args, CollectionBudget budget,
                                         const std::function<bool(ObjectId,ObjectId)> &equal,
                                         const std::function<bool(ObjectId)> &handoff) {
    if (name == "<init>") {
        if (owner != (synchronous_ ? synchronous_queue_type : bounded_ ? blocking_queue_type : concurrent_queue_type) ||
            (signature != "()V" && !(synchronous_ ? signature=="(Z)V" : bounded_ && signature=="(I)V")))
            return {};
        if (initialized_)
            throw DexError("AETHER_DEX_STATE", "Queue constructor invoked twice");
        if(synchronous_) {capacity_=0;fair_=signature=="(Z)V" && args[1].bits!=0;}
        if (signature == "(I)V") {
            const auto capacity = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[1].bits));
            if (capacity <= 0)
                runtime.raise("Ljava/lang/IllegalArgumentException;");
            capacity_ = static_cast<std::size_t>(capacity);
        }
        initialized_ = true;
        return Value::nothing();
    }
    if (!initialized_)
        throw DexError("AETHER_DEX_STATE", "Queue must be initialized before use");
    if(synchronous_ && (name=="put" || name=="take" ||
       (name=="offer" && signature=="(Ljava/lang/Object;JLjava/util/concurrent/TimeUnit;)Z") ||
       (name=="poll" && signature=="(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;")))
        throw DexError("AETHER_DEX_THREAD_BLOCKING_UNSUPPORTED", "Guest synchronous blocking transfers require a separate audited wait gateway");
    if (bounded_ && name == "remainingCapacity" && signature == "()I")
        return Value::word(static_cast<std::uint32_t>(capacity_ - values_.size()));
    if (name == "size" && signature == "()I")
        return Value::word(static_cast<std::uint32_t>(values_.size()));
    if (name == "isEmpty" && signature == "()Z")
        return Value::word(values_.empty());
    if (name == "clear" && signature == "()V") {
        if (!values_.empty()) { check_revision(); values_.clear(); ids_.clear(); ++revision_; }
        return Value::nothing();
    }
    if ((name == "add" || name == "offer") && signature == "(Ljava/lang/Object;)Z") {
        if (!args[1].bits)
            runtime.raise("Ljava/lang/NullPointerException;");
        if(synchronous_) {
            const bool accepted=handoff && handoff(args[1].bits);
            if(!accepted && name=="add")runtime.raise("Ljava/lang/IllegalStateException;");
            return Value::word(accepted);
        }
        if (bounded_ && values_.size() == capacity_) {
            if (name == "add")
                runtime.raise("Ljava/lang/IllegalStateException;");
            return Value::word(0);
        }
        check_revision();
        if (next_id_ == std::numeric_limits<std::uint64_t>::max())
            throw DexError("AETHER_DEX_COLLECTION_LIMIT", "Queue occurrence identity exhausted");
        grow(budget);
        values_.push_back(Value::reference(args[1].bits));
        ids_.push_back(next_id_++); ++revision_;
        return Value::word(1);
    }
    if ((name == "poll" || name == "peek" || name == "remove" || name == "element") &&
        signature == "()Ljava/lang/Object;") {
        if (values_.empty()) {
            if (name == "remove" || name == "element")
                runtime.raise("Ljava/util/NoSuchElementException;");
            return Value::reference(0);
        }
        const auto value = values_.front();
        if (name == "poll" || name == "remove")
            erase(0);
        return value;
    }
    if ((name == "contains" || name == "remove") && signature == "(Ljava/lang/Object;)Z") {
        const auto query = args[1].bits;
        if (!query) return Value::word(0);
        const auto revision = revision_;
        for (std::size_t at = 0; at < values_.size(); ++at) {
            const auto candidate = values_[at].bits;
            runtime.retain(candidate);
            struct ReleaseCandidate {
                ManagedRuntime &runtime; ObjectId candidate;
                ~ReleaseCandidate() { runtime.release(candidate); }
            } release_candidate{runtime,candidate};
            if (query != candidate && !equal)
                throw DexError("AETHER_DEX_API_UNSUPPORTED", "Queue equality requires managed virtual dispatch");
            const bool match = query == candidate || equal(query,candidate);
            if (revision != revision_)
                throw DexError("AETHER_DEX_COLLECTION_REENTRANCY", "Equality callback changed queue");
            if (match) { if (name == "remove") erase(at); return Value::word(1); }
        }
        return Value::word(0);
    }
    if (name == "toArray" && (signature == "()[Ljava/lang/Object;" || signature == "([Ljava/lang/Object;)[Ljava/lang/Object;")) {
        const auto revision = revision_;
        const auto count = values_.size();
        const bool typed = signature[1] == '[';
        auto array = typed ? args[1].bits : 0;
        const auto length = typed ? runtime.array_length(array) : 0;
        if (!typed || length < count)
            array = runtime.new_array(typed ? std::string(runtime.object_type(array)) : "[Ljava/lang/Object;",
                                      static_cast<std::int32_t>(count));
        runtime.retain(array);
        struct ReleaseArray {
            ManagedRuntime &runtime; ObjectId array;
            ~ReleaseArray() { runtime.release(array); }
        } release_array{runtime,array};
        const auto stable = [&] {
            if (revision != revision_)
                throw DexError("AETHER_DEX_COLLECTION_REENTRANCY", "Type callback changed queue during array snapshot");
        };
        stable();
        for (std::size_t at = 0; at < count; ++at) {
            const auto value = values_[at];
            runtime.retain(value.bits);
            struct ReleaseElement {
                ManagedRuntime &runtime; ObjectId element;
                ~ReleaseElement() { runtime.release(element); }
            } release_element{runtime,value.bits};
            runtime.array_set(array,static_cast<std::int32_t>(at),value); stable();
        }
        if (typed && length > count) runtime.array_set(array,static_cast<std::int32_t>(count),Value::reference(0));
        return Value::reference(array);
    }
    return {};
}
void ManagedList::check_capacity(std::size_t count, CollectionBudget budget) const {
    if (count > budget.maximum_elements)
        limit("List capacity exceeds the managed element bound");
    const auto before = bytes();
    const auto after = count * sizeof(Value);
    if (after > before && after - before > budget.heap_limit - budget.heap_bytes)
        throw DexError("AETHER_DEX_HEAP_LIMIT", "List capacity exceeds the managed heap bound");
}
void ManagedList::commit(std::vector<Value> replacement, CollectionBudget budget) {
    if(copy_on_write_ && revision_==std::numeric_limits<std::uint64_t>::max())
        limit("Copy-on-write publication revision exhausted");
    check_capacity(replacement.capacity(), budget);
    const auto before = bytes(), actual = replacement.capacity() * sizeof(Value);
    values_.swap(replacement);
    budget.object_bytes = budget.object_bytes - before + actual;
    budget.heap_bytes = budget.heap_bytes - before + actual;
    if(copy_on_write_)++revision_;
}
void ManagedList::begin_collection_construction() {
    if(initialized_ || constructing_)
        throw DexError("AETHER_DEX_STATE","ArrayList constructor invoked twice or reentered");
    if(copy_on_write_)throw DexError("AETHER_DEX_STATE","ArrayList constructor requires ArrayList storage");
    constructing_=true;
}
void ManagedList::initialize_snapshot(ManagedRuntime &runtime,ObjectId array,CollectionBudget budget) {
    if(initialized_ || !constructing_)throw DexError("AETHER_DEX_STATE","Collection constructor has no active initialization");
    const auto count=runtime.array_length(array);check_capacity(count,budget);
    // The rooted, authenticated reference array has no guest callbacks while
    // copying. Publish the independent storage and initialized state together.
    std::vector<Value> replacement(count);
    for(std::size_t n=0;n<count;++n)replacement[n]=runtime.array_get(array,static_cast<std::int32_t>(n));
    commit(std::move(replacement),budget);initialized_=true;constructing_=false;
}
bool ManagedList::append_snapshot(ManagedRuntime &runtime, ObjectId array, CollectionBudget budget) {
    if (!initialized_) throw DexError("AETHER_DEX_STATE", "Bulk append requires an initialized list");
    // ArrayList invalidates iterators after toArray returns, even for an empty
    // or null snapshot and before a later growth failure. COW snapshot iterators
    // ignore revisions; commit advances its private publication revision.
    if (!copy_on_write_) {
        if (revision_==UINT64_MAX) limit("List structural revision exhausted");
        ++revision_;
    }
    const auto count=runtime.array_length(array);
    if (!count) return false;
    if (values_.size()>budget.maximum_elements || count>budget.maximum_elements-values_.size())
        limit("List bulk length exceeds the managed element bound");
    const auto total=values_.size()+count;
    if (!copy_on_write_ && total<=values_.capacity()) {
        // Capacity is already charged; no allocation, callback, or collection
        // occurs while appending the validated reference-array snapshot.
        for(std::size_t n=0;n<count;++n) values_.push_back(runtime.array_get(array,static_cast<std::int32_t>(n)));
        return true;
    }
    const auto requested=copy_on_write_ ? total : std::min(budget.maximum_elements,
        std::max(total,values_.capacity()+std::max<std::size_t>(values_.capacity()/2,1)));
    if (requested>SIZE_MAX/sizeof(Value) || requested*sizeof(Value)>budget.heap_limit-budget.heap_bytes)
        throw DexError("AETHER_DEX_HEAP_LIMIT", "Bulk replacement exceeds transient managed heap bound");
    // Keep old storage charged while constructing the replacement. There are no
    // guest callbacks or collection points between reservation and publication.
    const auto reserved=requested*sizeof(Value);
    budget.heap_bytes+=reserved;
    struct Reservation { std::size_t &heap; std::size_t bytes; ~Reservation(){heap-=bytes;} } reservation{budget.heap_bytes,reserved};
    std::vector<Value> replacement(requested);
    replacement.resize(total);
    if (replacement.capacity()*sizeof(Value)>reserved)
        throw DexError("AETHER_DEX_HEAP_LIMIT", "Unexpected bulk replacement capacity");
    std::copy(values_.begin(),values_.end(),replacement.begin());
    for(std::size_t n=0;n<count;++n) replacement[values_.size()+n]=runtime.array_get(array,static_cast<std::int32_t>(n));
    const auto before=bytes();
    values_.swap(replacement);
    budget.object_bytes=budget.object_bytes-before+reserved;
    // Transfer reservation to persistent storage; old storage dies before return.
    budget.heap_bytes-=before;
    reservation.bytes=0;
    return true;
}
void ManagedList::capacity(std::size_t requested, bool trim, CollectionBudget budget) {
    check_capacity(requested, budget);
    if (!trim && requested <= values_.capacity())
        return;
    // Build a bounded replacement in memory so failure preserves contents and
    // accounting. No guest allocation/collection occurs during this operation.
    std::vector<Value> replacement;
    replacement.reserve(requested);
    replacement.insert(replacement.end(), values_.begin(), values_.end());
    commit(std::move(replacement), budget);
    if (initialized_ && !copy_on_write_) ++revision_;
}
std::optional<Value> ManagedList::invoke(ManagedRuntime &runtime, std::string_view owner,
                                         std::string_view name, std::string_view signature,
                                         std::span<const Value> args, CollectionBudget budget) {
    const auto integer = [&](std::size_t at) {
        return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[at].bits));
    };
    if (name == "<init>" && owner == copy_list_type &&
        (signature == "()V" || signature == "([Ljava/lang/Object;)V")) {
        if (initialized_ || constructing_)
            throw DexError("AETHER_DEX_STATE", "CopyOnWriteArrayList constructor invoked twice");
        const auto count = signature == "()V" ? 0 : runtime.array_length(args[1].bits);
        check_capacity(count, budget);
        std::vector<Value> replacement(count);
        for (std::size_t n = 0; n < count; ++n)
            replacement[n] = runtime.array_get(args[1].bits, static_cast<std::int32_t>(n));
        commit(std::move(replacement), budget);
        initialized_ = true;
        return Value::nothing();
    }
    if (name == "<init>" && owner == list_type && (signature == "()V" || signature == "(I)V")) {
        if (initialized_ || constructing_)
            throw DexError("AETHER_DEX_STATE", "ArrayList constructor invoked twice or reentered");
        const auto initial = signature == "()V" ? std::min<std::size_t>(10, budget.maximum_elements)
                                                : static_cast<std::size_t>(std::max(0, integer(1)));
        if (signature == "(I)V" && integer(1) < 0)
            runtime.raise("Ljava/lang/IllegalArgumentException;");
        capacity(initial, false, budget);
        initialized_ = true;
        return Value::nothing();
    }
    const bool list_owner = owner == list_type || owner == copy_list_type ||
                            owner == "Ljava/util/AbstractList;" || owner == "Ljava/util/List;";
    const bool collection_owner =
        list_owner || owner == "Ljava/util/AbstractCollection;" || owner == "Ljava/util/Collection;";
    if (!collection_owner || name == "<init>")
        return {};
    if (!initialized_)
        throw DexError("AETHER_DEX_STATE", "ArrayList must be initialized before use");
    if (name == "size" && signature == "()I")
        return Value::word(static_cast<std::uint32_t>(values_.size()));
    if (name == "isEmpty" && signature == "()Z")
        return Value::word(values_.empty());
    if (name == "clear" && signature == "()V") {
        if (copy_on_write_)
            commit({}, budget);
        else {
            values_.clear();
            ++revision_;
        }
        return Value::nothing();
    }
    if (name == "ensureCapacity" && signature == "(I)V" && owner == list_type) {
        if (integer(1) > 0)
            capacity(static_cast<std::size_t>(integer(1)), false, budget);
        return Value::nothing();
    }
    if (name == "trimToSize" && signature == "()V" && owner == list_type) {
        capacity(values_.size(), true, budget);
        return Value::nothing();
    }
    const auto position = [&](bool insertion) {
        const auto index = integer(1);
        if (index < 0 || static_cast<std::size_t>(index) > values_.size() ||
            (!insertion && static_cast<std::size_t>(index) == values_.size()))
            runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
        return static_cast<std::size_t>(index);
    };
    if (list_owner && name == "get" && signature == "(I)Ljava/lang/Object;")
        return values_[position(false)];
    if (list_owner && name == "set" && signature == "(ILjava/lang/Object;)Ljava/lang/Object;") {
        const auto at = position(false);
        const auto before = values_[at];
        if (copy_on_write_) {
            auto replacement = values_;
            replacement[at] = args[2];
            commit(std::move(replacement), budget);
        } else
            values_[at] = args[2];
        return before;
    }
    if (list_owner && name == "remove" && signature == "(I)Ljava/lang/Object;") {
        const auto at = position(false);
        const auto before = values_[at];
        if (copy_on_write_) {
            std::vector<Value> replacement(values_.size() - 1);
            std::copy_n(values_.begin(), at, replacement.begin());
            std::copy(values_.begin() + at + 1, values_.end(), replacement.begin() + at);
            commit(std::move(replacement), budget);
        } else {
            values_.erase(values_.begin() + at);
            ++revision_;
        }
        return before;
    }
    if (name == "add" &&
        (signature == "(Ljava/lang/Object;)Z" || (list_owner && signature == "(ILjava/lang/Object;)V"))) {
        const bool indexed = signature[1] == 'I';
        const auto at = indexed ? position(true) : values_.size();
        if (values_.size() == budget.maximum_elements)
            limit("ArrayList length exceeds the managed element bound");
        if (copy_on_write_) {
            check_capacity(values_.size() + 1, budget);
            std::vector<Value> replacement(values_.size() + 1);
            std::copy_n(values_.begin(), at, replacement.begin());
            replacement[at] = args[indexed ? 2 : 1];
            std::copy(values_.begin() + at, values_.end(), replacement.begin() + at + 1);
            commit(std::move(replacement), budget);
        } else {
            if (values_.size() == values_.capacity()) {
                const auto grown = values_.capacity() + std::max<std::size_t>(values_.capacity() / 2, 1);
                capacity(std::min(budget.maximum_elements, std::max(values_.size() + 1, grown)), false,
                         budget);
            }
            values_.insert(values_.begin() + at, args[indexed ? 2 : 1]);
            ++revision_;
        }
        return indexed ? Value::nothing() : Value::word(1);
    }
    return {};
}
std::optional<Value> LiveListIterator::invoke(ManagedRuntime &runtime,ManagedList &list,std::string_view name,
                                             std::string_view signature,std::span<const Value> args,CollectionBudget budget) {
    const auto check=[&]{if(revision_!=list.revision())runtime.raise("Ljava/util/ConcurrentModificationException;");};
    if(name=="hasNext"&&signature=="()Z")return Value::word(cursor_!=list.references().size());
    if(bidirectional_&&name=="hasPrevious"&&signature=="()Z")return Value::word(cursor_!=0);
    if(bidirectional_&&name=="nextIndex"&&signature=="()I")return Value::word(static_cast<std::uint32_t>(cursor_));
    if(bidirectional_&&name=="previousIndex"&&signature=="()I")return Value::word(static_cast<std::uint32_t>(cursor_)-1);
    if(name=="next"&&signature=="()Ljava/lang/Object;") {
        check();if(cursor_>=list.references().size())runtime.raise("Ljava/util/NoSuchElementException;");
        last_=cursor_++;return list.references()[*last_];
    }
    if(bidirectional_&&name=="previous"&&signature=="()Ljava/lang/Object;") {
        check();if(!cursor_)runtime.raise("Ljava/util/NoSuchElementException;");
        last_=--cursor_;return list.references()[*last_];
    }
    if(name=="remove"&&signature=="()V") {
        if(!last_)runtime.raise("Ljava/lang/IllegalStateException;");
        check();const std::array call{Value::reference(backing_),Value::word(static_cast<std::uint32_t>(*last_))};
        (void)list.invoke(runtime,"Ljava/util/ArrayList;","remove","(I)Ljava/lang/Object;",call,budget);
        cursor_=*last_;last_.reset();revision_=list.revision();return Value::nothing();
    }
    if(bidirectional_&&name=="set"&&signature=="(Ljava/lang/Object;)V") {
        if(!last_)runtime.raise("Ljava/lang/IllegalStateException;");
        check();const std::array call{Value::reference(backing_),Value::word(static_cast<std::uint32_t>(*last_)),args[1]};
        (void)list.invoke(runtime,"Ljava/util/ArrayList;","set","(ILjava/lang/Object;)Ljava/lang/Object;",call,budget);
        return Value::nothing();
    }
    if(bidirectional_&&name=="add"&&signature=="(Ljava/lang/Object;)V") {
        check();const std::array call{Value::reference(backing_),Value::word(static_cast<std::uint32_t>(cursor_)),args[1]};
        (void)list.invoke(runtime,"Ljava/util/ArrayList;","add","(ILjava/lang/Object;)V",call,budget);
        ++cursor_;last_.reset();revision_=list.revision();return Value::nothing();
    }
    return {};
}
std::optional<Value> SnapshotIterator::invoke(ManagedRuntime &runtime, std::string_view owner,
                                              std::string_view name, std::string_view signature) {
    const bool list = owner == "Ljava/util/ListIterator;" || owner == snapshot_iterator_type;
    if (!list && owner != "Ljava/util/Iterator;")
        return {};
    if (name == "hasNext" && signature == "()Z")
        return Value::word(cursor_ < values_.size());
    if (list && name == "hasPrevious" && signature == "()Z")
        return Value::word(cursor_ > 0);
    if (list && name == "nextIndex" && signature == "()I")
        return Value::word(static_cast<std::uint32_t>(cursor_));
    if (list && name == "previousIndex" && signature == "()I")
        return Value::word(static_cast<std::uint32_t>(cursor_) - 1);
    if (name == "next" && signature == "()Ljava/lang/Object;") {
        if (cursor_ == values_.size())
            runtime.raise("Ljava/util/NoSuchElementException;");
        return values_[cursor_++];
    }
    if (list && name == "previous" && signature == "()Ljava/lang/Object;") {
        if (!cursor_)
            runtime.raise("Ljava/util/NoSuchElementException;");
        return values_[--cursor_];
    }
    if ((name == "remove" && signature == "()V") ||
        (list && (name == "set" || name == "add") && signature == "(Ljava/lang/Object;)V"))
        runtime.raise("Ljava/lang/UnsupportedOperationException;");
    return {};
}
} // namespace aether::dex
