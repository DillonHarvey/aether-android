#pragma once
#include "aether/dex/runtime.hpp"
#include <functional>

namespace aether::dex {
inline constexpr std::string_view concurrent_queue_type = "Ljava/util/concurrent/ConcurrentLinkedQueue;";
inline constexpr std::string_view blocking_queue_type = "Ljava/util/concurrent/LinkedBlockingQueue;";
inline constexpr std::string_view synchronous_queue_type = "Ljava/util/concurrent/SynchronousQueue;";
inline constexpr std::string_view singleton_list_type = "Ljava/util/Collections$SingletonList;";
inline constexpr std::string_view empty_list_type = "Ljava/util/Collections$EmptyList;";
inline constexpr std::string_view empty_iterator_type = "Laether/internal/EmptyListIterator;";
std::optional<Value> invoke_empty_list(ManagedRuntime &runtime, std::string_view name,
                                      std::string_view signature, std::span<const Value> args);
std::optional<Value> invoke_empty_iterator(ManagedRuntime &runtime, std::string_view name,
                                          std::string_view signature);
std::optional<HostClass> collection_class(std::string_view descriptor);
struct CollectionBudget {
    std::size_t &object_bytes, &heap_bytes;
    std::size_t heap_limit, maximum_elements;
};
// Original single-owner list storage. References participate in the runtime's
// ordinary tracing collector; no host object or guest pointer is exposed.
inline constexpr std::string_view copy_list_type = "Ljava/util/concurrent/CopyOnWriteArrayList;";
inline constexpr std::string_view snapshot_iterator_type = "Laether/internal/CopyOnWriteIterator;";
inline constexpr std::string_view queue_iterator_type = "Laether/internal/QueueIterator;";
struct QueueIterator {
    ObjectId backing = 0;
    std::uint64_t cursor = 0, last = 0;
    bool removable = false;
    Value pending;
    std::uint64_t pending_id = 0;
    bool ready = false, exhausted = false;
};
class ManagedQueue {
  public:
    explicit ManagedQueue(bool bounded = false, bool synchronous = false) : bounded_(bounded), synchronous_(synchronous) {}
    std::span<const Value> references() const noexcept { return values_; }
    std::size_t bytes() const noexcept { return values_.capacity() * sizeof(Value) + ids_.capacity() * sizeof(std::uint64_t); }
    bool initialized() const noexcept { return initialized_; }
    std::uint64_t revision() const noexcept { return revision_; }
    bool synchronous() const noexcept {return synchronous_;}
    bool fair() const noexcept {return fair_;}
    std::uint64_t next_wait_ticket();
    std::optional<Value> invoke(ManagedRuntime &runtime, std::string_view owner, std::string_view name,
                               std::string_view signature, std::span<const Value> args, CollectionBudget budget,
                               const std::function<bool(ObjectId,ObjectId)> &equal = {},
                               const std::function<bool(ObjectId)> &handoff = {});
    std::optional<Value> iterate(ManagedRuntime &, QueueIterator &, std::string_view name, std::string_view signature);
  private:
    std::vector<Value> values_;
    std::vector<std::uint64_t> ids_;
    std::uint64_t next_id_ = 1, revision_ = 0;
    const bool bounded_, synchronous_;
    bool fair_ = false;
    std::uint64_t next_wait_ticket_ = 1;
    std::size_t capacity_ = 0x7fffffff;
    bool initialized_ = false;
    void grow(CollectionBudget);
    void erase(std::size_t at);
    void check_revision() const;
};
inline constexpr std::string_view live_iterator_type="Laether/internal/LiveArrayListIterator;";
inline constexpr std::string_view live_list_iterator_type="Laether/internal/LiveArrayListListIterator;";
class ManagedList {
  public:
    explicit ManagedList(bool copy_on_write) : copy_on_write_(copy_on_write) {}
    bool snapshots() const noexcept { return copy_on_write_ && initialized_; }
    bool append_snapshot(ManagedRuntime &, ObjectId, CollectionBudget);
    void begin_collection_construction();
    void cancel_collection_construction() noexcept { constructing_ = false; }
    void initialize_snapshot(ManagedRuntime &, ObjectId, CollectionBudget);
    bool initialized() const noexcept { return initialized_; }
    std::uint64_t revision() const noexcept { return revision_; }
    std::span<const Value> references() const noexcept { return values_; }
    std::size_t bytes() const noexcept { return values_.capacity() * sizeof(Value); }
    std::optional<Value> invoke(ManagedRuntime &runtime, std::string_view owner, std::string_view name,
                                std::string_view signature, std::span<const Value> arguments,
                                CollectionBudget budget);

  private:
    std::vector<Value> values_;
    bool initialized_ = false;
    std::uint64_t revision_ = 0;
    bool constructing_ = false;
    const bool copy_on_write_;
    void check_capacity(std::size_t count, CollectionBudget budget) const;
    void commit(std::vector<Value> replacement, CollectionBudget budget);
    void capacity(std::size_t requested, bool trim, CollectionBudget budget);
};
class LiveListIterator {
  public:
    LiveListIterator(ObjectId backing,std::size_t cursor,std::uint64_t revision,bool bidirectional)
        : backing_(backing),cursor_(cursor),revision_(revision),bidirectional_(bidirectional) {}
    ObjectId backing() const noexcept {return backing_;}
    std::optional<Value> invoke(ManagedRuntime &runtime,ManagedList &list,std::string_view name,
                               std::string_view signature,std::span<const Value> args,CollectionBudget budget);
  private:
    ObjectId backing_;
    std::size_t cursor_;
    std::optional<std::size_t> last_;
    std::uint64_t revision_;
    const bool bidirectional_;
};
class SnapshotIterator {
  public:
    SnapshotIterator(std::span<const Value> values, std::size_t cursor)
        : values_(values.begin(), values.end()), cursor_(cursor) {}
    std::span<const Value> references() const noexcept { return values_; }
    std::size_t bytes() const noexcept { return values_.capacity() * sizeof(Value); }
    std::optional<Value> invoke(ManagedRuntime &runtime, std::string_view owner, std::string_view name,
                                std::string_view signature);

  private:
    const std::vector<Value> values_;
    std::size_t cursor_;
};
} // namespace aether::dex
