#include "maps.hpp"
#include "sets.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cmath>

namespace aether::dex {
std::optional<HostClass> map_class(std::string_view type) {
    static constexpr std::array<std::string_view, 1> maps{"Ljava/util/Map;"};
    static constexpr std::array<std::string_view, 3> hash_interfaces{
        "Ljava/util/Map;", "Ljava/lang/Cloneable;", "Ljava/io/Serializable;"};
    static constexpr std::array<std::string_view, 2> concurrent_interfaces{concurrent_map_interface,
                                                                           "Ljava/io/Serializable;"};
    if (type == synchronized_map_type) {
        static constexpr std::array<std::string_view,2> interfaces{"Ljava/util/Map;","Ljava/io/Serializable;"};
        return HostClass{"Ljava/lang/Object;",interfaces};
    }
    if (type == concurrent_map_type)
        return HostClass{"Ljava/util/AbstractMap;", concurrent_interfaces};
    if (type == concurrent_map_interface)
        return HostClass{"Ljava/util/Map;", {}, true, true};
    if (type == weak_map_type)
        return HostClass{"Ljava/util/AbstractMap;", maps};
    if (type == hash_map_type)
        return HostClass{"Ljava/util/AbstractMap;", hash_interfaces};
    if (type == linked_map_type)
        return HostClass{hash_map_type, maps};
    if (type == "Ljava/util/AbstractMap;")
        return HostClass{"Ljava/lang/Object;", maps, true};
    if (type == "Ljava/util/Map;")
        return HostClass{"Ljava/lang/Object;", {}, true, true};
    return {};
}
std::optional<HostClass> map_view_class(std::string_view type) {
    static constexpr std::array<std::string_view, 2> keys{"Ljava/util/Set;", "Ljava/io/Serializable;"};
    static constexpr std::array<std::string_view, 1> iterator{"Ljava/util/Iterator;"};
    static constexpr std::array<std::string_view, 1> entry_interface{map_entry_interface};
    if (type == map_entry_interface)
        return HostClass{"Ljava/lang/Object;", {}, true, true};
    if (type == map_entry_type)
        return HostClass{"Ljava/lang/Object;", entry_interface};
    if (type == map_entries_type)
        return HostClass{"Ljava/util/AbstractSet;"};
    if (type == map_entry_iterator_type)
        return HostClass{"Ljava/lang/Object;", iterator};
    if (type == map_values_type)
        return HostClass{"Ljava/util/AbstractCollection;"};
    if (type == map_value_iterator_type)
        return HostClass{"Ljava/lang/Object;", iterator};
    if (type == map_keys_type)
        return HostClass{"Ljava/lang/Object;", keys};
    if (type == map_key_iterator_type || type == hash_set_iterator_type)
        return HostClass{"Ljava/lang/Object;", iterator};
    return {};
}
void ManagedMap::capacity(std::size_t count, CollectionBudget budget) {
    if (count > budget.maximum_elements)
        throw DexError("AETHER_DEX_MAP_LIMIT", "Map capacity exceeds the managed element bound");
    if (count <= entries_.capacity())
        return;
    const auto before = bytes(), after = count * sizeof(MapEntry);
    if (after - before > budget.heap_limit - budget.heap_bytes)
        throw DexError("AETHER_DEX_HEAP_LIMIT", "Map capacity exceeds the managed heap bound");
    std::vector<MapEntry> replacement;
    replacement.reserve(count);
    replacement.insert(replacement.end(), entries_.begin(), entries_.end());
    const auto actual = replacement.capacity() * sizeof(MapEntry);
    if (replacement.capacity() > budget.maximum_elements ||
        actual - before > budget.heap_limit - budget.heap_bytes)
        throw DexError("AETHER_DEX_HEAP_LIMIT", "Map allocation exceeds the managed heap bound");
    entries_.swap(replacement);
    budget.object_bytes = budget.object_bytes - before + actual;
    budget.heap_bytes = budget.heap_bytes - before + actual;
}
void ManagedMap::unchanged(std::uint64_t revision) const {
    if (revision != revision_)
        throw DexError("AETHER_DEX_MAP_REENTRANCY", "A key/value callback changed the map during lookup");
}
void ManagedMap::record_access(std::size_t index) {
    if (access_order_ && index + 1 < entries_.size()) {
        std::rotate(entries_.begin() + index, entries_.begin() + index + 1, entries_.end());
        ++revision_;
        ++structure_revision_;
    }
}
std::optional<std::size_t> ManagedMap::find(ManagedRuntime &runtime, ObjectId key, std::uint32_t hash,
                                            const MapCallbacks &callbacks) const {
    const auto revision = revision_;
    for (std::size_t n = 0; n < entries_.size(); ++n) {
        const auto entry = entries_[n];
        if (entry.hash != hash)
            continue;
        bool equal = key == entry.key;
        if (!equal && key && entry.key) {
            runtime.retain(entry.key);
            struct Release {
                ManagedRuntime &runtime;
                ObjectId key;
                ~Release() { runtime.release(key); }
            } release{runtime, entry.key};
            equal = callbacks.equal(key, entry.key);
            unchanged(revision);
        }
        if (equal)
            return n;
    }
    return {};
}
void ManagedMap::prune(const std::function<bool(ObjectId)> &alive) {
    if (!weak_)
        return;
    const auto removed =
        std::erase_if(entries_, [&](const auto &entry) { return entry.key && !alive(entry.key); });
    if (removed) {
        ++revision_;
        ++structure_revision_;
    }
}
void ManagedMap::put_all(ManagedRuntime &runtime,ManagedMap &source,ObjectId target,
                         CollectionBudget budget,const MapCallbacks &callbacks) {
    if (!initialized_||!source.initialized_)
        throw DexError("AETHER_DEX_STATE","putAll requires initialized maps");
    const auto required=source.entries_.size()*sizeof(MapEntry);
    if (required>budget.heap_limit-budget.heap_bytes)
        throw DexError("AETHER_DEX_HEAP_LIMIT","putAll snapshot exceeds the managed heap bound");
    std::vector<MapEntry> snapshot(source.entries_.begin(),source.entries_.end());
    const auto scratch=snapshot.capacity()*sizeof(MapEntry);
    if (scratch>budget.heap_limit-budget.heap_bytes)
        throw DexError("AETHER_DEX_HEAP_LIMIT","putAll snapshot allocation exceeds the managed heap bound");
    budget.heap_bytes+=scratch;
    std::size_t rooted=0;
    struct Release {
        ManagedRuntime &runtime;const std::vector<MapEntry> &snapshot;std::size_t &rooted;
        std::size_t &heap_bytes;std::size_t scratch;
        ~Release(){while(rooted){--rooted;const auto &e=snapshot[rooted/2];runtime.release(rooted%2?e.value:e.key);}heap_bytes-=scratch;}
    } release{runtime,snapshot,rooted,budget.heap_bytes,scratch};
    for (const auto &entry:snapshot) {
        runtime.retain(entry.key);++rooted;runtime.retain(entry.value);++rooted;
    }
    const auto source_revision=source.revision_;
    const auto source_unchanged=[&]{if(&source!=this&&source.revision_!=source_revision)
        runtime.raise("Ljava/util/ConcurrentModificationException;");};
    const auto owner=concurrent_?concurrent_map_type:linked_?linked_map_type:weak_?weak_map_type:hash_map_type;
    for (const auto &entry:snapshot) {
        source_unchanged();
        const std::array args{Value::reference(target),Value::reference(entry.key),Value::reference(entry.value)};
        (void)invoke(runtime,owner,"put","(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",args,budget,callbacks);
        source_unchanged();
    }
}
std::optional<Value> ManagedMap::invoke(ManagedRuntime &runtime, std::string_view owner,
                                        std::string_view name, std::string_view signature,
                                        std::span<const Value> args, CollectionBudget budget,
                                        const MapCallbacks &callbacks) {
    if (name == "<init>") {
        const bool ordered = linked_ && signature == "(IFZ)V";
        const bool concurrency = concurrent_ && signature == "(IFI)V";
        const auto expected = concurrent_ ? concurrent_map_type
                              : linked_   ? linked_map_type
                              : weak_     ? weak_map_type
                                          : hash_map_type;
        if (owner != expected ||
            (signature != "()V" && signature != "(I)V" && signature != "(IF)V" && !ordered && !concurrency))
            return {};
        if (initialized_)
            throw DexError("AETHER_DEX_STATE", "Map constructor invoked twice");
        auto initial = signature == "()V"
                           ? static_cast<std::int32_t>(std::min<std::size_t>(16, budget.maximum_elements))
                           : std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[1].bits));
        const auto factor = signature == "(IF)V" || ordered || concurrency
                                ? std::bit_cast<float>(static_cast<std::uint32_t>(args[2].bits))
                                : 0.75f;
        if (initial < 0 || factor <= 0 || std::isnan(factor))
            runtime.raise("Ljava/lang/IllegalArgumentException;");
        if (concurrency) {
            const auto hint = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[3].bits));
            if (hint <= 0)
                runtime.raise("Ljava/lang/IllegalArgumentException;");
            initial = std::max(initial, hint);
        }
        capacity(static_cast<std::size_t>(initial), budget);
        access_order_ = ordered && args[3].bits != 0;
        initialized_ = true;
        return Value::nothing();
    }
    if (owner != weak_map_type && owner != hash_map_type && owner != linked_map_type &&
        owner != concurrent_map_type && owner != concurrent_map_interface && owner != "Ljava/util/Map;" &&
        owner != "Ljava/util/AbstractMap;")
        return {};
    if (!initialized_)
        throw DexError("AETHER_DEX_STATE", "Map must be initialized before use");
    if (name == "size" && signature == "()I")
        return Value::word(static_cast<std::uint32_t>(entries_.size()));
    if (concurrent_ && name == "mappingCount" && signature == "()J")
        return Value::wide(entries_.size());
    if (name == "isEmpty" && signature == "()Z")
        return Value::word(entries_.empty());
    if (name == "clear" && signature == "()V") {
        if (!entries_.empty()) {
            ++revision_;
            ++structure_revision_;
            entries_.clear();
        }
        return Value::nothing();
    }
    if ((name == "containsValue" || (concurrent_ && name == "contains")) &&
        signature == "(Ljava/lang/Object;)Z") {
        if (concurrent_ && !args[1].bits)
            runtime.raise("Ljava/lang/NullPointerException;");
        const auto revision = revision_;
        for (const auto &entry : entries_) {
            const auto value = entry.value;
            if (args[1].bits == value)
                return Value::word(1);
            if (args[1].bits && value) {
                const bool equal = callbacks.equal(args[1].bits, value);
                unchanged(revision);
                if (equal)
                    return Value::word(1);
            }
        }
        return Value::word(0);
    }
    const bool get = name == "get" && signature == "(Ljava/lang/Object;)Ljava/lang/Object;";
    const bool get_default =
        name == "getOrDefault" && signature == "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;";
    const bool contains = name == "containsKey" && signature == "(Ljava/lang/Object;)Z";
    const bool remove = name == "remove" && signature == "(Ljava/lang/Object;)Ljava/lang/Object;";
    const bool put = name == "put" && signature == "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;";
    const bool absent = concurrent_ && name == "putIfAbsent" &&
                        signature == "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;";
    const bool remove_if =
        concurrent_ && name == "remove" && signature == "(Ljava/lang/Object;Ljava/lang/Object;)Z";
    const bool replace = concurrent_ && name == "replace" &&
                         signature == "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;";
    const bool replace_if = concurrent_ && name == "replace" &&
                            signature == "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z";
    if (!get && !get_default && !contains && !remove && !put && !absent && !remove_if && !replace &&
        !replace_if)
        return {};
    const auto key = args[1].bits;
    if (concurrent_ && (!key || ((put || absent || replace || replace_if) && !args[2].bits) ||
                        (replace_if && !args[3].bits)))
        runtime.raise("Ljava/lang/NullPointerException;");
    if (remove_if && !args[2].bits)
        return Value::word(0);
    const auto revision = revision_;
    const auto hash = key ? callbacks.hash(key) : 0;
    unchanged(revision);
    const auto found = find(runtime, key, hash, callbacks);
    if (contains)
        return Value::word(found.has_value());
    const auto previous = found ? entries_[*found].value : 0;
    if (remove_if || replace_if) {
        if (!found)
            return Value::word(0);
        const bool matches = args[2].bits == previous || callbacks.equal(args[2].bits, previous);
        unchanged(revision);
        if (!matches)
            return Value::word(0);
        ++revision_;
        if (remove_if) {
            entries_.erase(entries_.begin() + *found);
            ++structure_revision_;
        }
        else
            entries_[*found].value = args[3].bits;
        return Value::word(1);
    }
    if (replace) {
        if (found) {
            ++revision_;
            entries_[*found].value = args[2].bits;
        }
        return Value::reference(previous);
    }
    if (remove && found) {
        ++revision_;
        ++structure_revision_;
        entries_.erase(entries_.begin() + *found);
    } else if (put || absent) {
        if (found) {
            if (!absent && previous != args[2].bits) {
                ++revision_;
                entries_[*found].value = args[2].bits;
            }
        } else {
            if (entries_.size() == budget.maximum_elements)
                throw DexError("AETHER_DEX_MAP_LIMIT", "Map length exceeds the managed element bound");
            if (entries_.size() == entries_.capacity())
                capacity(std::min(budget.maximum_elements,
                                  entries_.capacity() + std::max<std::size_t>(entries_.capacity() / 2, 1)),
                         budget);
            ++revision_;
            ++structure_revision_;
            entries_.push_back({key, args[2].bits, hash});
        }
    }
    if (found && (get || get_default || put))
        record_access(*found);
    return Value::reference(get_default && !found ? args[2].bits : previous);
}
std::optional<Value> ManagedMap::invoke_entry(ManagedRuntime &runtime, const MapEntryReference &entry,
                                                std::string_view name, std::string_view signature,
                                                std::span<const Value> args) {
    if (entry.expected_structure != structure_revision_ || entry.index >= entries_.size())
        runtime.raise("Ljava/util/ConcurrentModificationException;");
    auto &mapping = entries_[entry.index];
    if (name == "getKey" && signature == "()Ljava/lang/Object;")
        return Value::reference(mapping.key);
    if (name == "getValue" && signature == "()Ljava/lang/Object;")
        return Value::reference(mapping.value);
    if (name == "setValue" && signature == "(Ljava/lang/Object;)Ljava/lang/Object;") {
        const auto previous = mapping.value;
        if (previous != args[1].bits) {
            mapping.value = args[1].bits;
            ++revision_;
        }
        return Value::reference(previous);
    }
    return {};
}
std::optional<Value> ManagedMap::invoke_values(ManagedRuntime &runtime,MapValues &view,std::string_view name,
                                              std::string_view signature,std::span<const Value> args,const MapCallbacks &callbacks) {
    if (!initialized_||weak_||concurrent_)
        throw DexError("AETHER_DEX_STATE","Values view requires an initialized strong nonconcurrent map");
    const auto check=[&]{if(view.expected_structure!=structure_revision_)runtime.raise("Ljava/util/ConcurrentModificationException;");};
    const auto erase=[&](std::size_t at){entries_.erase(entries_.begin()+at);++revision_;++structure_revision_;};
    if (view.iterator) {
        if (name=="hasNext"&&signature=="()Z")return Value::word(view.cursor<entries_.size());
        if (name=="next"&&signature=="()Ljava/lang/Object;") {
            check();if(view.cursor>=entries_.size())runtime.raise("Ljava/util/NoSuchElementException;");
            view.last=view.cursor++;return Value::reference(entries_[*view.last].value);
        }
        if (name=="remove"&&signature=="()V") {
            if(!view.last)runtime.raise("Ljava/lang/IllegalStateException;");
            check();erase(*view.last);view.cursor=*view.last;view.last.reset();view.expected_structure=structure_revision_;
            return Value::nothing();
        }
        return {};
    }
    if (name=="size"&&signature=="()I")return Value::word(static_cast<std::uint32_t>(entries_.size()));
    if (name=="isEmpty"&&signature=="()Z")return Value::word(entries_.empty());
    if (name=="clear"&&signature=="()V") {
        if(!entries_.empty()){entries_.clear();++revision_;++structure_revision_;}
        return Value::nothing();
    }
    if (name=="add"&&signature=="(Ljava/lang/Object;)Z")runtime.raise("Ljava/lang/UnsupportedOperationException;");
    // Entry membership needs key/value pair equality; never use value-only lookup.
    if (view.entry_set)
        return {};
    if ((name=="contains"||name=="remove")&&signature=="(Ljava/lang/Object;)Z") {
        const auto query=args[1].bits,revision=revision_;
        for(std::size_t n=0;n<entries_.size();++n) {
            const auto candidate=entries_[n].value;
            const auto match=query==candidate||(query&&callbacks.equal(query,candidate));
            unchanged(revision);
            if(match){if(name=="remove")erase(n);return Value::word(1);}
        }
        return Value::word(0);
    }
    if (name=="toArray"&&(signature=="()[Ljava/lang/Object;"||signature=="([Ljava/lang/Object;)[Ljava/lang/Object;")) {
        const bool typed=signature[1]=='[';
        auto array=typed?args[1].bits:0;
        const auto length=typed?runtime.array_length(array):0;
        if(!typed||length<entries_.size())array=runtime.new_array(typed?std::string(runtime.object_type(array)):"[Ljava/lang/Object;",static_cast<std::int32_t>(entries_.size()));
        for(std::size_t n=0;n<entries_.size();++n)runtime.array_set(array,static_cast<std::int32_t>(n),Value::reference(entries_[n].value));
        if(typed&&length>entries_.size())runtime.array_set(array,static_cast<std::int32_t>(entries_.size()),Value::reference(0));
        return Value::reference(array);
    }
    return {};
}
std::optional<Value> ManagedMap::invoke_keys(ManagedRuntime &runtime, MapKeys &view, std::string_view name,
                                             std::string_view signature, std::span<const Value> args,
                                             CollectionBudget budget, const MapCallbacks &callbacks) {
    if ((!concurrent_ && !view.hash_set) || !initialized_)
        throw DexError("AETHER_DEX_STATE", "Key view requires an initialized backing map");
    const auto delegate = [&](std::string_view method, std::string_view descriptor,
                              std::span<const Value> values) {
        const auto result = invoke(runtime, concurrent_ ? concurrent_map_type : linked_ ? linked_map_type : hash_map_type, method,
                                   descriptor, values, budget, callbacks);
        if (!result)
            throw DexError("AETHER_DEX_STATE", "Invalid concurrent key-view delegation");
        return *result;
    };
    if (view.iterator) {
        if (name == "hasNext" && signature == "()Z")
            return Value::word(view.cursor < view.snapshot.size());
        if (name == "next" && signature == "()Ljava/lang/Object;") {
            if (view.hash_set && view.expected_revision != revision_)
                runtime.raise("Ljava/util/ConcurrentModificationException;");
            if (view.cursor == view.snapshot.size())
                runtime.raise("Ljava/util/NoSuchElementException;");
            view.can_remove = true;
            return view.snapshot[view.cursor++];
        }
        if (name == "remove" && signature == "()V") {
            if (!view.can_remove)
                runtime.raise("Ljava/lang/IllegalStateException;");
            if (view.hash_set && view.expected_revision != revision_)
                runtime.raise("Ljava/util/ConcurrentModificationException;");
            const std::array values{Value::reference(view.map), view.snapshot[view.cursor - 1]};
            (void)delegate("remove", "(Ljava/lang/Object;)Ljava/lang/Object;", values);
            view.can_remove = false;
            view.expected_revision = revision_;
            return Value::nothing();
        }
        return {};
    }
    if (!view.hash_set && name == "getMap" && signature == "()Ljava/util/concurrent/ConcurrentHashMap;")
        return Value::reference(view.map);
    if (!view.hash_set && name == "getMappedValue" && signature == "()Ljava/lang/Object;")
        return Value::reference(view.mapped_value);
    if ((name == "size" && signature == "()I") || (name == "isEmpty" && signature == "()Z") ||
        (name == "clear" && signature == "()V"))
        return delegate(name, signature, args);
    if ((name == "contains" || name == "remove" || name == "add") && signature == "(Ljava/lang/Object;)Z") {
        if (name == "contains")
            return delegate("containsKey", signature, args);
        if (name == "remove")
            return Value::word(delegate("remove", "(Ljava/lang/Object;)Ljava/lang/Object;", args).bits != 0);
        if (!view.mapped_value)
            runtime.raise("Ljava/lang/UnsupportedOperationException;");
        const std::array values{Value::reference(view.map), args[1], Value::reference(view.mapped_value)};
        return Value::word(delegate(view.hash_set ? "put" : "putIfAbsent",
                                    "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", values)
                               .bits == 0);
    }
    if (name == "toArray" &&
        (signature == "()[Ljava/lang/Object;" || signature == "([Ljava/lang/Object;)[Ljava/lang/Object;")) {
        const auto revision=revision_;
        const auto count=entries_.size();
        const bool typed = signature[1] == '[';
        auto array = typed ? args[1].bits : 0;
        const auto length = typed ? runtime.array_length(array) : 0;
        if (!typed || length < count)
            array = runtime.new_array(typed ? std::string(runtime.object_type(array))
                                            : std::string("[Ljava/lang/Object;"),
                                      static_cast<std::int32_t>(count));
        runtime.retain(array);
        struct ArrayRoot {ManagedRuntime &runtime;ObjectId id;~ArrayRoot(){runtime.release(id);}} destination{runtime,array};
        unchanged(revision);
        for (std::size_t n = 0; n < count; ++n) {
            const auto key=entries_[n].key;
            runtime.retain(key);
            ArrayRoot element{runtime,key};
            runtime.array_set(array, static_cast<std::int32_t>(n), Value::reference(key));
            unchanged(revision);
        }
        if (typed && length > count) {
            runtime.array_set(array, static_cast<std::int32_t>(count), Value::reference(0));
            unchanged(revision);
        }
        return Value::reference(array);
    }
    return {};
}
std::optional<Value> ManagedMap::invoke_hash_set(ManagedRuntime &runtime, std::string_view owner,
                                                 std::string_view name, std::string_view signature,
                                                 std::span<const Value> args, CollectionBudget budget,
                                                 const MapCallbacks &callbacks) {
    if (name == "<init>") {
        if (owner != hash_set_type && owner != linked_hash_set_type)
            return {};
        return invoke(runtime, linked_ ? linked_map_type : hash_map_type, name, signature, args, budget, callbacks);
    }
    MapKeys view;
    view.map = args[0].bits;
    view.mapped_value = view.map;
    view.hash_set = true;
    return invoke_keys(runtime, view, name, signature, args, budget, callbacks);
}
} // namespace aether::dex
