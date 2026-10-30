#include "intent_categories.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <optional>
#include <vector>

namespace aether::android {
namespace {
using dex::ManagedRuntime;
using dex::ObjectId;
using dex::Value;

// Original state and algorithms, reviewed against Android15 ArraySet and
// MapCollections at framework revision4e43ad12e1b211f15152e9c5b16b0fe88e6b93f3.
// Capacity-backed tails matter to that version's non-fail-fast ArrayIterator.
class Categories final : public dex::HostObjectState {
  public:
    std::vector<std::int32_t> hashes;
    std::vector<Value> entries;
    std::size_t size = 0;
    std::span<const Value> values() const noexcept override { return entries; }
    std::size_t bytes() const noexcept override {
        return sizeof(*this) + hashes.capacity() * sizeof(std::int32_t) + entries.capacity() * sizeof(Value);
    }
    void capacity(std::size_t count) {
        hashes.resize(count);
        entries.resize(count, Value::reference(0));
    }
};
class Iterator final : public dex::HostObjectState {
  public:
    std::array<Value, 1> owner;
    std::size_t size = 0, index = 0;
    bool can_remove = false;
    explicit Iterator(ObjectId set) : owner{Value::reference(set)} {}
    std::span<const Value> values() const noexcept override { return owner; }
    std::size_t bytes() const noexcept override { return sizeof(*this); }
};
[[noreturn]] void fail(std::string_view code, std::string message) {
    throw dex::DexError("AETHER_ANDROID_" + std::string(code), std::move(message));
}
ObjectId reference(Value value) {
    if (value.kind != dex::ValueKind::reference) fail("CATEGORY_ARGUMENT", "ArraySet requires reference arguments");
    return value.bits;
}
std::int32_t integer(Value value) {
    if (value.kind != dex::ValueKind::word) fail("CATEGORY_ARGUMENT", "ArraySet index/capacity requires int");
    return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value.bits));
}
class Root {
    ManagedRuntime &runtime;
    ObjectId id;
  public:
    Root(ManagedRuntime &runtime, ObjectId id) : runtime(runtime), id(id) { runtime.retain(id); }
    ~Root() { runtime.release(id); }
    Root(const Root &) = delete;
    Root &operator=(const Root &) = delete;
};
class Roots {
    ManagedRuntime &runtime;
    std::vector<ObjectId> ids;
  public:
    explicit Roots(ManagedRuntime &runtime) : runtime(runtime) {}
    ~Roots() { for (const auto id : ids) runtime.release(id); }
    void add(ObjectId id) {
        runtime.retain(id);
        try { ids.push_back(id); } catch (...) { runtime.release(id); throw; }
    }
};
const Categories &state(ManagedRuntime &runtime, ObjectId receiver) {
    if (!receiver) runtime.raise("Ljava/lang/NullPointerException;");
    if (runtime.object_type(receiver) != intent_categories_type)
        fail("CATEGORY_STATE", "ArraySet requires its actual final-class receiver");
    const auto *current = dynamic_cast<const Categories *>(runtime.host_state(receiver));
    if (!current) fail("CATEGORY_STATE", "ArraySet constructor has not completed");
    return *current;
}
void check_key(ManagedRuntime &runtime, ObjectId key) {
    if (key && runtime.object_type(key) != "Ljava/lang/String;")
        fail("API_UNSUPPORTED", "This ArraySet profile supports only actual String and null keys");
}
std::int32_t key_hash(ManagedRuntime &runtime, ObjectId key) {
    check_key(runtime, key);
    std::uint32_t result = 0;
    if (key) for (const auto unit : runtime.string(key)) result = result * 31u + static_cast<std::uint16_t>(unit);
    return std::bit_cast<std::int32_t>(result);
}
bool equal_key(ManagedRuntime &runtime, ObjectId key, Value candidate) {
    const auto other = reference(candidate);
    return key == other || (key && other && runtime.string(key) == runtime.string(other));
}
std::int32_t find(ManagedRuntime &runtime, const Categories &set, ObjectId key, std::int32_t hash) {
    std::int32_t low = 0, high = static_cast<std::int32_t>(set.size) - 1;
    while (low <= high) {
        const auto middle = (low + high) / 2;
        const auto current = set.hashes[static_cast<std::size_t>(middle)];
        if (current < hash) low = middle + 1;
        else if (current > hash) high = middle - 1;
        else {
            if (equal_key(runtime, key, set.entries[static_cast<std::size_t>(middle)])) return middle;
            auto end = middle + 1;
            while (end < static_cast<std::int32_t>(set.size) && set.hashes[static_cast<std::size_t>(end)] == hash) {
                if (equal_key(runtime, key, set.entries[static_cast<std::size_t>(end)])) return end;
                ++end;
            }
            for (auto at = middle - 1; at >= 0 && set.hashes[static_cast<std::size_t>(at)] == hash; --at)
                if (equal_key(runtime, key, set.entries[static_cast<std::size_t>(at)])) return at;
            return ~end; // Append to the end of this signed-hash collision chain.
        }
    }
    return ~low;
}
void bounded_capacity(std::size_t count) {
    if (count > intent_category_limit) fail("CATEGORY_LIMIT", "ArraySet capacity exceeds 65536 entries");
}
bool add(ManagedRuntime &runtime, ObjectId receiver, ObjectId key) {
    const auto hash = key_hash(runtime, key);
    const auto &current = state(runtime, receiver);
    const auto index = find(runtime, current, key, hash);
    if (index >= 0) return false;
    if (current.size == intent_category_limit) fail("CATEGORY_LIMIT", "ArraySet exceeds 65536 entries");
    auto next = std::make_unique<Categories>(current);
    if (next->size == next->entries.size()) {
        const auto capacity = next->size >= 8 ? next->size + next->size / 2 : next->size >= 4 ? 8u : 4u;
        // A full logical capacity never bypasses the runtime's lower array or
        // heap limits: set_host_state admits the actual traced backing storage.
        next->capacity(std::min(capacity, intent_category_limit));
    }
    const auto at = static_cast<std::size_t>(~index);
    std::move_backward(next->entries.begin() + static_cast<std::ptrdiff_t>(at),
                       next->entries.begin() + static_cast<std::ptrdiff_t>(next->size),
                       next->entries.begin() + static_cast<std::ptrdiff_t>(next->size + 1));
    std::move_backward(next->hashes.begin() + static_cast<std::ptrdiff_t>(at),
                       next->hashes.begin() + static_cast<std::ptrdiff_t>(next->size),
                       next->hashes.begin() + static_cast<std::ptrdiff_t>(next->size + 1));
    next->entries[at] = Value::reference(key);
    next->hashes[at] = hash;
    ++next->size;
    runtime.set_host_state(receiver, std::move(next));
    return true;
}
Value remove_at(ManagedRuntime &runtime, ObjectId receiver, std::int32_t index) {
    const auto &current = state(runtime, receiver);
    if (index < 0 || static_cast<std::size_t>(index) >= current.size)
        runtime.raise("Ljava/lang/ArrayIndexOutOfBoundsException;");
    const auto at = static_cast<std::size_t>(index);
    const auto removed = current.entries[at];
    Root removed_root(runtime, reference(removed));
    auto next = std::make_unique<Categories>();
    if (current.size > 1) {
        const auto capacity = current.entries.size() > 8 && current.size < current.entries.size() / 3 ?
            (current.size > 8 ? current.size + current.size / 2 : 8u) : current.entries.size();
        next->capacity(capacity);
        next->size = current.size - 1;
        for (std::size_t n = 0; n < next->size; ++n) {
            const auto source = n < at ? n : n + 1;
            next->hashes[n] = current.hashes[source];
            next->entries[n] = current.entries[source];
        }
    }
    runtime.set_host_state(receiver, std::move(next));
    return removed;
}
std::unique_ptr<Categories> copied(ManagedRuntime &runtime, ObjectId source) {
    auto result = std::make_unique<Categories>();
    if (source) {
        const auto &current = state(runtime, source);
        result->capacity(current.size);
        result->size = current.size;
        std::copy_n(current.hashes.begin(), current.size, result->hashes.begin());
        std::copy_n(current.entries.begin(), current.size, result->entries.begin());
    }
    return result;
}
ObjectId allocate(ManagedRuntime &runtime, std::unique_ptr<Categories> next) {
    Roots roots(runtime);
    for (const auto value : next->entries) roots.add(reference(value));
    const auto result = runtime.new_object(intent_categories_type);
    Root result_root(runtime, result);
    runtime.set_host_state(result, std::move(next));
    return result;
}
Value array(ManagedRuntime &runtime, ObjectId receiver, ObjectId supplied, bool typed) {
    const auto captured = state(runtime, receiver);
    Roots captured_roots(runtime);
    for (std::size_t n = 0; n < captured.size; ++n) captured_roots.add(reference(captured.entries[n]));
    ObjectId result = supplied;
    if (!typed) result = runtime.new_array("[Ljava/lang/Object;", static_cast<std::int32_t>(captured.size));
    else {
        if (!supplied) runtime.raise("Ljava/lang/NullPointerException;");
        const auto descriptor = std::string(runtime.object_type(supplied));
        if (!descriptor.starts_with("[L") && !descriptor.starts_with("[["))
            fail("CATEGORY_ARGUMENT", "Typed toArray requires a reference array");
        if (runtime.array_length(supplied) < captured.size)
            result = runtime.new_array(descriptor, static_cast<std::int32_t>(captured.size));
    }
    Root result_root(runtime, result);
    for (std::size_t n = 0; n < captured.size; ++n)
        runtime.array_set(result, static_cast<std::int32_t>(n), captured.entries[n]);
    if (typed && runtime.array_length(result) > captured.size)
        runtime.array_set(result, static_cast<std::int32_t>(captured.size), Value::reference(0));
    return Value::reference(result);
}
std::size_t argument_count(std::string_view name, std::string_view signature, bool iterator) {
    if (iterator) {
        if (name == "hasNext" && signature == "()Z") return 0;
        if (name == "next" && signature == "()Ljava/lang/Object;") return 0;
        if (name == "remove" && signature == "()V") return 0;
    } else {
        if (name == "<init>" && signature == "()V") return 0;
        if (name == "<init>" && (signature == "(I)V" || signature == "(Landroid/util/ArraySet;)V")) return 1;
        if ((name == "size" || name == "hashCode") && signature == "()I") return 0;
        if (name == "isEmpty" && signature == "()Z") return 0;
        if (name == "clear" && signature == "()V") return 0;
        if ((name == "add" || name == "contains" || name == "remove" || name == "equals") &&
            signature == "(Ljava/lang/Object;)Z") return 1;
        if (name == "indexOf" && signature == "(Ljava/lang/Object;)I") return 1;
        if ((name == "valueAt" || name == "removeAt") && signature == "(I)Ljava/lang/Object;") return 1;
        if (name == "ensureCapacity" && signature == "(I)V") return 1;
        if (name == "iterator" && signature == "()Ljava/util/Iterator;") return 0;
        if (name == "toArray" && signature == "()[Ljava/lang/Object;") return 0;
        if (name == "toArray" && signature == "([Ljava/lang/Object;)[Ljava/lang/Object;") return 1;
        if (name == "toString" && signature == "()Ljava/lang/String;") return 0;
    }
    fail("API_UNSUPPORTED", "ArraySet/iterator method is outside the supported category profile");
}
} // namespace

ObjectId new_intent_categories(ManagedRuntime &runtime) { return allocate(runtime, std::make_unique<Categories>()); }
ObjectId copy_intent_categories(ManagedRuntime &runtime, ObjectId source) {
    Root source_root(runtime, source);
    return allocate(runtime, copied(runtime, source));
}
Value invoke_intent_categories(ManagedRuntime &runtime, std::string_view owner, std::string_view name,
                               std::string_view signature, std::span<const Value> args) {
    if (args.empty()) fail("CATEGORY_ARGUMENT", "ArraySet method requires a receiver");
    const auto receiver = reference(args[0]);
    Root receiver_root(runtime, receiver);
    if (!receiver) runtime.raise("Ljava/lang/NullPointerException;");
    const bool iterator = runtime.object_type(receiver) == intent_categories_iterator_type;
    const auto count = argument_count(name, signature, iterator);
    if (args.size() != count + 1) fail("CATEGORY_ARGUMENT", "ArraySet argument count disagrees with its descriptor");
    std::optional<Root> argument_root;
    if (count && args[1].kind == dex::ValueKind::reference) argument_root.emplace(runtime, args[1].bits);
    if (iterator) {
        const auto *current = dynamic_cast<const Iterator *>(runtime.host_state(receiver));
        if (!current) fail("CATEGORY_STATE", "Iterator has no authenticated state");
        const auto set = reference(current->owner[0]);
        Root set_root(runtime, set);
        if (name == "hasNext") return Value::word(current->index < current->size);
        auto next = std::make_unique<Iterator>(*current);
        if (name == "next") {
            if (current->index >= current->size) runtime.raise("Ljava/util/NoSuchElementException;");
            const auto &set_state = state(runtime, set);
            if (current->index >= set_state.entries.size()) runtime.raise("Ljava/lang/ArrayIndexOutOfBoundsException;");
            const auto result = set_state.entries[current->index];
            Root result_root(runtime, reference(result));
            ++next->index;
            next->can_remove = true;
            runtime.set_host_state(receiver, std::move(next));
            return result;
        }
        if (!next->can_remove) runtime.raise("Ljava/lang/IllegalStateException;");
        --next->index;
        --next->size;
        next->can_remove = false;
        const auto index = next->index;
        runtime.set_host_state(receiver, std::move(next));
        (void)remove_at(runtime, set, static_cast<std::int32_t>(index));
        return Value::nothing();
    }
    if (name == "<init>") {
        if (owner != intent_categories_type || runtime.object_type(receiver) != intent_categories_type || runtime.host_state(receiver))
            fail("CATEGORY_STATE", "ArraySet constructor has invalid ownership or was repeated");
        auto next = std::make_unique<Categories>();
        if (signature == "(I)V") {
            const auto capacity = integer(args[1]);
            if (capacity < 0) runtime.raise("Ljava/lang/NegativeArraySizeException;");
            bounded_capacity(static_cast<std::size_t>(capacity));
            next->capacity(static_cast<std::size_t>(capacity));
        } else if (count) next = copied(runtime, reference(args[1]));
        runtime.set_host_state(receiver, std::move(next));
        return Value::nothing();
    }
    const auto &current = state(runtime, receiver);
    if (name == "size") return Value::word(static_cast<std::uint32_t>(current.size));
    if (name == "isEmpty") return Value::word(current.size == 0);
    if (name == "clear") {
        if (current.size) runtime.set_host_state(receiver, std::make_unique<Categories>());
        return Value::nothing();
    }
    if (name == "add") return Value::word(add(runtime, receiver, reference(args[1])));
    if (name == "contains" || name == "indexOf" || name == "remove") {
        const auto key = reference(args[1]);
        const auto index = find(runtime, current, key, key_hash(runtime, key));
        if (name == "indexOf") return Value::word(std::bit_cast<std::uint32_t>(index));
        if (name == "remove" && index >= 0) (void)remove_at(runtime, receiver, index);
        return Value::word(index >= 0);
    }
    if (name == "valueAt" || name == "removeAt") {
        const auto index = integer(args[1]);
        if (name == "removeAt") return remove_at(runtime, receiver, index);
        if (index < 0 || static_cast<std::size_t>(index) >= current.size)
            runtime.raise("Ljava/lang/ArrayIndexOutOfBoundsException;");
        return current.entries[static_cast<std::size_t>(index)];
    }
    if (name == "ensureCapacity") {
        const auto minimum = integer(args[1]);
        if (minimum >= 0 && static_cast<std::size_t>(minimum) > current.entries.size()) {
            bounded_capacity(static_cast<std::size_t>(minimum));
            auto next = std::make_unique<Categories>(current);
            next->capacity(static_cast<std::size_t>(minimum));
            runtime.set_host_state(receiver, std::move(next));
        }
        return Value::nothing();
    }
    if (name == "toArray") return array(runtime, receiver, count ? reference(args[1]) : 0, count != 0);
    if (name == "iterator") {
        auto next = std::make_unique<Iterator>(receiver);
        next->size = current.size;
        const auto result = runtime.new_object(intent_categories_iterator_type);
        Root result_root(runtime, result);
        runtime.set_host_state(result, std::move(next));
        return Value::reference(result);
    }
    if (name == "hashCode") {
        std::uint32_t hash = 0;
        for (std::size_t n = 0; n < current.size; ++n) hash += std::bit_cast<std::uint32_t>(current.hashes[n]);
        return Value::word(hash);
    }
    if (name == "equals") {
        const auto other = reference(args[1]);
        if (other == receiver) return Value::word(1);
        if (!other || !runtime.assignable(other, "Ljava/util/Set;")) return Value::word(0);
        const auto size = state(runtime, receiver).size;
        if (integer(runtime.invoke_virtual_named(other, "size", "()I")) != static_cast<std::int32_t>(size))
            return Value::word(0);
        try {
            // Pinned ArraySet equality reads its live size/value on each turn.
            // An actual other-Set callback may mutate this set; never keep a
            // borrowed provider-state reference across that callback.
            for (std::size_t n = 0; n < state(runtime, receiver).size; ++n) {
                const auto key = state(runtime, receiver).entries[n];
                Root key_root(runtime, reference(key));
                const std::array call{key};
                if (!integer(runtime.invoke_virtual_named(other, "contains", "(Ljava/lang/Object;)Z", call)))
                    return Value::word(0);
            }
            return Value::word(1);
        } catch (const dex::JavaException &error) {
            if (runtime.assignable(error.object, "Ljava/lang/NullPointerException;") ||
                runtime.assignable(error.object, "Ljava/lang/ClassCastException;")) return Value::word(0);
            throw;
        }
    }
    if (name == "toString") {
        std::u16string result = u"{";
        for (std::size_t n = 0; n < current.size; ++n) {
            const auto key = reference(current.entries[n]);
            const auto text = key ? runtime.string(key) : std::u16string_view(u"null");
            const auto separator = n ? 2u : 0u;
            // Refuse oversized output before building a native string that
            // would exceed this profile's 65536-unit representation bound.
            if (result.size() > intent_category_limit - separator - 1 ||
                text.size() > intent_category_limit - result.size() - separator - 1)
                fail("CATEGORY_LIMIT", "ArraySet text exceeds 65536 UTF-16 units");
            if (n) result += u", ";
            result += text;
        }
        result += u'}';
        return Value::reference(runtime.new_string(result));
    }
    fail("API_UNSUPPORTED", "ArraySet method is outside the supported category profile");
}
} // namespace aether::android
