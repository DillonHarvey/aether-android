#include "sets.hpp"
#include <algorithm>
#include <array>

namespace aether::dex {
bool map_backed_set_method(std::string_view name,std::string_view signature) noexcept {
    return ((name=="size" || name=="hashCode") && signature=="()I") ||
        (name=="isEmpty" && signature=="()Z") || (name=="clear" && signature=="()V") ||
        ((name=="add" || name=="remove" || name=="contains" || name=="equals") && signature=="(Ljava/lang/Object;)Z") ||
        ((name=="addAll" || name=="removeAll" || name=="retainAll" || name=="containsAll") && signature=="(Ljava/util/Collection;)Z") ||
        (name=="iterator" && signature=="()Ljava/util/Iterator;") ||
        (name=="toArray" && (signature=="()[Ljava/lang/Object;" || signature=="([Ljava/lang/Object;)[Ljava/lang/Object;")) ||
        (name=="toString" && signature=="()Ljava/lang/String;");
}
std::optional<HostClass> set_class(std::string_view type) {
    static constexpr std::array<std::string_view, 1> sets{"Ljava/util/Set;"};
    static constexpr std::array<std::string_view, 1> serializable{"Ljava/io/Serializable;"};
    static constexpr std::array<std::string_view, 2> synchronized_interfaces{"Ljava/util/Collection;",
                                                                             "Ljava/io/Serializable;"};
    if (type == map_backed_set_type)
        return HostClass{"Ljava/util/AbstractSet;", serializable};
    if (type == synchronized_collection_type)
        return HostClass{"Ljava/lang/Object;", synchronized_interfaces};
    if (type == synchronized_set_type)
        return HostClass{synchronized_collection_type, sets};
    static constexpr std::array<std::string_view, 2> hash_interfaces{"Ljava/lang/Cloneable;",
                                                                     "Ljava/io/Serializable;"};
    if (type == linked_hash_set_type)
        return HostClass{hash_set_type, hash_interfaces};
    if (type == hash_set_type)
        return HostClass{"Ljava/util/AbstractSet;", hash_interfaces};
    if (type == copy_set_type)
        return HostClass{"Ljava/util/AbstractSet;", serializable};
    if (type == "Ljava/util/AbstractSet;")
        return HostClass{"Ljava/util/AbstractCollection;", sets, true};
    if (type == "Ljava/util/Set;")
        return HostClass{"Ljava/util/Collection;", {}, true, true};
    return {};
}
void ManagedSet::check_capacity(std::size_t count, CollectionBudget budget) const {
    if (count > budget.maximum_elements)
        throw DexError("AETHER_DEX_SET_LIMIT", "Set capacity exceeds the managed element bound");
    const auto after = count * sizeof(Value), before = bytes();
    if (after > before && after - before > budget.heap_limit - budget.heap_bytes)
        throw DexError("AETHER_DEX_HEAP_LIMIT", "Set capacity exceeds the managed heap bound");
}
void ManagedSet::commit(std::vector<Value> replacement, CollectionBudget budget) {
    check_capacity(replacement.capacity(), budget);
    const auto before = bytes(), after = replacement.capacity() * sizeof(Value);
    values_.swap(replacement);
    budget.object_bytes = budget.object_bytes - before + after;
    budget.heap_bytes = budget.heap_bytes - before + after;
    ++revision_;
}
std::optional<std::size_t> ManagedSet::find(ManagedRuntime &runtime, ObjectId query,
                                            const SetEquality &equal) const {
    const auto revision = revision_;
    for (std::size_t n = 0; n < values_.size(); ++n) {
        const auto candidate = values_[n].bits;
        if (query == candidate)
            return n;
        if (!query)
            continue;
        if (candidate)
            runtime.retain(candidate);
        struct Release {
            ManagedRuntime &runtime;
            ObjectId id;
            ~Release() {
                if (id)
                    runtime.release(id);
            }
        } release{runtime, candidate};
        // A managed callback may clear this set and run GC. Pin the candidate,
        // keep no iterator into mutable storage, and refuse the outer mutation.
        const auto match = equal(query, candidate);
        if (revision != revision_)
            throw DexError("AETHER_DEX_SET_REENTRANCY", "An equality callback changed the set during lookup");
        if (match)
            return n;
    }
    return {};
}
std::optional<Value> ManagedSet::invoke(ManagedRuntime &runtime, std::string_view owner,
                                        std::string_view name, std::string_view signature,
                                        std::span<const Value> args, CollectionBudget budget,
                                        const SetEquality &equal) {
    if (name == "<init>") {
        if (owner != copy_set_type || signature != "()V")
            return {};
        if (initialized_)
            throw DexError("AETHER_DEX_STATE", "CopyOnWriteArraySet constructor invoked twice");
        initialized_ = true;
        return Value::nothing();
    }
    if (!set_class(owner) && owner != "Ljava/util/AbstractCollection;" && owner != "Ljava/util/Collection;")
        return {};
    if (!initialized_)
        throw DexError("AETHER_DEX_STATE", "CopyOnWriteArraySet must be initialized before use");
    if (name == "size" && signature == "()I")
        return Value::word(static_cast<std::uint32_t>(values_.size()));
    if (name == "isEmpty" && signature == "()Z")
        return Value::word(values_.empty());
    if (name == "clear" && signature == "()V") {
        commit({}, budget);
        return Value::nothing();
    }
    if ((name == "add" || name == "remove" || name == "contains") && signature == "(Ljava/lang/Object;)Z") {
        const auto found = find(runtime, args[1].bits, equal);
        if (name == "contains")
            return Value::word(found.has_value());
        if (name == "add") {
            if (found)
                return Value::word(0);
            check_capacity(values_.size() + 1, budget);
            std::vector<Value> replacement(values_.size() + 1);
            std::copy(values_.begin(), values_.end(), replacement.begin());
            replacement.back() = Value::reference(args[1].bits);
            commit(std::move(replacement), budget);
            return Value::word(1);
        }
        if (!found)
            return Value::word(0);
        std::vector<Value> replacement(values_.size() - 1);
        std::copy_n(values_.begin(), *found, replacement.begin());
        std::copy(values_.begin() + *found + 1, values_.end(), replacement.begin() + *found);
        commit(std::move(replacement), budget);
        return Value::word(1);
    }
    if (name == "toArray" &&
        (signature == "()[Ljava/lang/Object;" || signature == "([Ljava/lang/Object;)[Ljava/lang/Object;")) {
        const bool typed = signature[1] == '[';
        auto array = typed ? args[1].bits : 0;
        const auto length = typed ? runtime.array_length(array) : 0;
        if (!typed || length < values_.size())
            array = runtime.new_array(typed ? std::string(runtime.object_type(array))
                                            : std::string("[Ljava/lang/Object;"),
                                      static_cast<std::int32_t>(values_.size()));
        for (std::size_t n = 0; n < values_.size(); ++n)
            runtime.array_set(array, static_cast<std::int32_t>(n), values_[n]);
        if (typed && length > values_.size())
            runtime.array_set(array, static_cast<std::int32_t>(values_.size()), Value::reference(0));
        return Value::reference(array);
    }
    return {};
}
} // namespace aether::dex
