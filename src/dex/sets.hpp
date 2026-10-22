#pragma once
#include "collections.hpp"
#include <functional>
#include <mutex>

namespace aether::dex {
inline constexpr std::string_view copy_set_type = "Ljava/util/concurrent/CopyOnWriteArraySet;";
inline constexpr std::string_view linked_hash_set_type = "Ljava/util/LinkedHashSet;";
inline constexpr std::string_view hash_set_type = "Ljava/util/HashSet;";
inline constexpr std::string_view collections_utility_type = "Ljava/util/Collections;";
inline constexpr std::string_view map_backed_set_type = "Ljava/util/Collections$SetFromMap;";
bool map_backed_set_method(std::string_view name, std::string_view signature) noexcept;
inline constexpr std::string_view synchronized_set_type = "Ljava/util/Collections$SynchronizedSet;";
inline constexpr std::string_view synchronized_collection_type =
    "Ljava/util/Collections$SynchronizedCollection;";
struct SynchronizedSet {
    explicit SynchronizedSet(ObjectId backing) : backing(backing) {}
    const ObjectId backing;
    std::recursive_mutex mutex;
};
std::optional<HostClass> set_class(std::string_view descriptor);
using SetEquality = std::function<bool(ObjectId, ObjectId)>;
// Original, insertion-ordered set. Mutations publish bounded replacement storage;
// iterator snapshots are separately owned and traced by the managed runtime.
class ManagedSet {
  public:
    bool initialized() const noexcept { return initialized_; }
    std::span<const Value> references() const noexcept { return values_; }
    std::size_t bytes() const noexcept { return values_.capacity() * sizeof(Value); }
    std::optional<Value> invoke(ManagedRuntime &runtime, std::string_view owner, std::string_view name,
                                std::string_view signature, std::span<const Value> arguments,
                                CollectionBudget budget, const SetEquality &equal);

  private:
    std::vector<Value> values_;
    std::uint64_t revision_ = 0;
    bool initialized_ = false;
    void check_capacity(std::size_t count, CollectionBudget budget) const;
    void commit(std::vector<Value> replacement, CollectionBudget budget);
    std::optional<std::size_t> find(ManagedRuntime &runtime, ObjectId query, const SetEquality &equal) const;
};
} // namespace aether::dex
