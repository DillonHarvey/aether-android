#pragma once
#include "collections.hpp"
#include <functional>
#include <mutex>

namespace aether::dex {
inline constexpr std::string_view weak_map_type = "Ljava/util/WeakHashMap;";
inline constexpr std::string_view hash_map_type = "Ljava/util/HashMap;";
inline constexpr std::string_view linked_map_type = "Ljava/util/LinkedHashMap;";
inline constexpr std::string_view concurrent_map_type = "Ljava/util/concurrent/ConcurrentHashMap;";
inline constexpr std::string_view concurrent_map_interface = "Ljava/util/concurrent/ConcurrentMap;";
inline constexpr std::string_view map_keys_type = "Ljava/util/concurrent/ConcurrentHashMap$KeySetView;";
inline constexpr std::string_view map_key_iterator_type = "Laether/internal/ConcurrentKeyIterator;";
inline constexpr std::string_view hash_set_iterator_type = "Laether/internal/HashSetIterator;";
inline constexpr std::string_view map_values_type="Laether/internal/MapValues;";
inline constexpr std::string_view map_value_iterator_type="Laether/internal/MapValueIterator;";
inline constexpr std::string_view map_entries_type = "Laether/internal/MapEntries;";
inline constexpr std::string_view map_entry_iterator_type = "Laether/internal/MapEntryIterator;";
inline constexpr std::string_view map_entry_type = "Laether/internal/MapEntry;";
inline constexpr std::string_view map_entry_interface = "Ljava/util/Map$Entry;";
struct MapEntryReference {
    ObjectId map = 0;
    std::size_t index = 0;
    std::uint64_t expected_structure = 0;
};
inline constexpr std::string_view synchronized_map_type = "Ljava/util/Collections$SynchronizedMap;";
struct SynchronizedMap {
    explicit SynchronizedMap(ObjectId value) : backing(value) {}
    const ObjectId backing;
    std::recursive_mutex mutex;
};
struct MapValues {
    ObjectId map=0;
    std::size_t cursor=0;
    std::optional<std::size_t> last;
    std::uint64_t expected_structure=0;
    bool iterator=false, entry_set=false;
};
std::optional<HostClass> map_class(std::string_view descriptor);
std::optional<HostClass> map_view_class(std::string_view descriptor);
struct MapEntry {
    ObjectId key = 0, value = 0;
    std::uint32_t hash = 0;
};
struct MapCallbacks {
    std::function<std::uint32_t(ObjectId)> hash;
    std::function<bool(ObjectId, ObjectId)> equal;
};
struct MapKeys {
    ObjectId map = 0, mapped_value = 0;
    // Iteration observes a bounded point-in-time key set. Removal still acts
    // on the live backing map, as required by the weakly consistent contract.
    std::vector<Value> snapshot;
    std::size_t cursor = 0;
    bool iterator = false, can_remove = false;
    bool hash_set = false;
    std::uint64_t expected_revision = 0;
    std::size_t bytes() const noexcept { return snapshot.capacity() * sizeof(Value); }
};
class ManagedMap {
  public:
    explicit ManagedMap(bool weak, bool linked = false, bool concurrent = false)
        : weak_(weak), linked_(linked), concurrent_(concurrent) {}
    bool weak() const noexcept { return weak_; }
    bool concurrent() const noexcept { return concurrent_; }
    bool initialized() const noexcept { return initialized_; }
    std::uint64_t revision() const noexcept { return revision_; }
    std::uint64_t structure_revision() const noexcept { return structure_revision_; }
    std::span<const MapEntry> entries() const noexcept { return entries_; }
    std::size_t bytes() const noexcept { return entries_.capacity() * sizeof(MapEntry); }
    void prune(const std::function<bool(ObjectId)> &alive);
    void put_all(ManagedRuntime &runtime,ManagedMap &source,ObjectId target,
                 CollectionBudget budget,const MapCallbacks &callbacks);
    std::optional<Value> invoke(ManagedRuntime &runtime, std::string_view owner, std::string_view name,
                                std::string_view signature, std::span<const Value> args,
                                CollectionBudget budget, const MapCallbacks &callbacks);
    std::optional<Value> invoke_keys(ManagedRuntime &runtime, MapKeys &view, std::string_view name,
                                     std::string_view signature, std::span<const Value> args,
                                     CollectionBudget budget, const MapCallbacks &callbacks);

    std::optional<Value> invoke_values(ManagedRuntime &runtime,MapValues &view,std::string_view name,
                                       std::string_view signature,std::span<const Value> args,const MapCallbacks &callbacks);
    std::optional<Value> invoke_entry(ManagedRuntime &runtime, const MapEntryReference &entry,
                                      std::string_view name, std::string_view signature,
                                      std::span<const Value> args);
    // HashSet uses a private non-null presence value in the same strong map.
    std::optional<Value> invoke_hash_set(ManagedRuntime &runtime, std::string_view owner,
                                         std::string_view name, std::string_view signature,
                                         std::span<const Value> args, CollectionBudget budget,
                                         const MapCallbacks &callbacks);

  private:
    std::vector<MapEntry> entries_;
    bool initialized_ = false;
    const bool weak_;
    const bool linked_;
    const bool concurrent_;
    bool access_order_ = false;
    std::uint64_t revision_ = 0,structure_revision_=0;
    void capacity(std::size_t count, CollectionBudget budget);
    void unchanged(std::uint64_t revision) const;
    void record_access(std::size_t index);
    std::optional<std::size_t> find(ManagedRuntime &runtime, ObjectId key, std::uint32_t hash,
                                    const MapCallbacks &callbacks) const;
};
} // namespace aether::dex
