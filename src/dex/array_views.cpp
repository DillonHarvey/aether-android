#include "array_views.hpp"
#include <array>
#include <bit>

namespace aether::dex {
std::optional<HostClass> array_view_class(std::string_view type) {
    static constexpr std::array<std::string_view, 2> interfaces{"Ljava/util/RandomAccess;",
                                                                "Ljava/io/Serializable;"};
    static constexpr std::array<std::string_view, 1> iterator{"Ljava/util/ListIterator;"};
    if (type == arrays_type)
        return HostClass{"Ljava/lang/Object;", {}};
    if (type == array_list_type)
        return HostClass{"Ljava/util/AbstractList;", interfaces};
    if (type == array_iterator_type)
        return HostClass{"Ljava/lang/Object;", iterator};
    return {};
}
std::optional<Value> invoke_array_view(ManagedRuntime &runtime, ObjectId array, std::string_view name,
                                       std::string_view signature, std::span<const Value> args,
                                       const std::function<bool(ObjectId, ObjectId)> &equal) {
    const auto count = runtime.array_length(array);
    const auto position = [&](bool insertion = false) {
        const auto index = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[1].bits));
        if (index < 0 || static_cast<std::size_t>(index) > count ||
            (!insertion && static_cast<std::size_t>(index) == count))
            runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
        return index;
    };
    if (name == "size" && signature == "()I")
        return Value::word(static_cast<std::uint32_t>(count));
    if (name == "isEmpty" && signature == "()Z")
        return Value::word(count == 0);
    if (name == "get" && signature == "(I)Ljava/lang/Object;")
        return runtime.array_get(array, position());
    if (name == "set" && signature == "(ILjava/lang/Object;)Ljava/lang/Object;") {
        const auto index = position();
        const auto previous = runtime.array_get(array, index);
        runtime.array_set(array, index, args[2]);
        return previous;
    }
    if (((name == "contains" || name == "remove") && signature == "(Ljava/lang/Object;)Z") ||
        ((name == "indexOf" || name == "lastIndexOf") && signature == "(Ljava/lang/Object;)I")) {
        for (std::size_t n = 0; n < count; ++n) {
            const auto index = static_cast<std::int32_t>(name == "lastIndexOf" ? count - n - 1 : n);
            const auto candidate = runtime.array_get(array, index).bits;
            if (args[1].bits == candidate || (args[1].bits && equal(args[1].bits, candidate))) {
                if (name == "remove")
                    runtime.raise("Ljava/lang/UnsupportedOperationException;");
                return Value::word(name == "contains" ? 1 : index);
            }
        }
        return Value::word(name == "contains" || name == "remove" ? 0 : UINT32_MAX);
    }
    if (name == "toArray" &&
        (signature == "()[Ljava/lang/Object;" || signature == "([Ljava/lang/Object;)[Ljava/lang/Object;")) {
        const bool typed = signature[1] == '[';
        auto target = typed ? args[1].bits : 0;
        const auto capacity = typed ? runtime.array_length(target) : 0;
        if (!typed || capacity < count)
            target = runtime.new_array(typed ? std::string(runtime.object_type(target))
                                             : std::string("[Ljava/lang/Object;"),
                                       static_cast<std::int32_t>(count));
        for (std::size_t n = 0; n < count; ++n)
            runtime.array_set(target, static_cast<std::int32_t>(n),
                              runtime.array_get(array, static_cast<std::int32_t>(n)));
        if (typed && capacity > count)
            runtime.array_set(target, static_cast<std::int32_t>(count), Value::reference(0));
        return Value::reference(target);
    }
    if (name == "clear" && signature == "()V") {
        if (count)
            runtime.raise("Ljava/lang/UnsupportedOperationException;");
        return Value::nothing();
    }
    if (name == "add" && signature == "(ILjava/lang/Object;)V") {
        (void)position(true);
        runtime.raise("Ljava/lang/UnsupportedOperationException;");
    }
    if ((name == "add" && signature == "(Ljava/lang/Object;)Z") ||
        (name == "remove" && signature == "(I)Ljava/lang/Object;"))
        runtime.raise("Ljava/lang/UnsupportedOperationException;");
    return {};
}
std::optional<Value> invoke_array_iterator(ManagedRuntime &runtime, std::span<Value> state,
                                           std::string_view name, std::string_view signature,
                                           std::span<const Value> args) {
    if (state.size() != 3 || state[0].kind != ValueKind::reference || state[1].kind != ValueKind::word ||
        state[2].kind != ValueKind::word)
        throw DexError("AETHER_DEX_STATE", "Invalid array-list iterator state");
    const auto array = state[0].bits, count = runtime.array_length(array);
    auto cursor = static_cast<std::uint32_t>(state[1].bits);
    if (cursor > count)
        throw DexError("AETHER_DEX_STATE", "Array-list iterator cursor exceeds its backing array");
    if (name == "hasNext" && signature == "()Z")
        return Value::word(cursor < count);
    if (name == "hasPrevious" && signature == "()Z")
        return Value::word(cursor > 0);
    if (name == "nextIndex" && signature == "()I")
        return Value::word(cursor);
    if (name == "previousIndex" && signature == "()I")
        return Value::word(cursor - 1);
    if ((name == "next" || name == "previous") && signature == "()Ljava/lang/Object;") {
        const bool next = name == "next";
        if (next ? cursor == count : cursor == 0)
            runtime.raise("Ljava/util/NoSuchElementException;");
        const auto index = next ? cursor : cursor - 1;
        const auto result = runtime.array_get(array, static_cast<std::int32_t>(index));
        state[1] = Value::word(next ? cursor + 1 : cursor - 1);
        state[2] = Value::word(index);
        return result;
    }
    if ((name == "set" && signature == "(Ljava/lang/Object;)V") || (name == "remove" && signature == "()V")) {
        if (state[2].bits == UINT32_MAX)
            runtime.raise("Ljava/lang/IllegalStateException;");
        if (name == "remove")
            runtime.raise("Ljava/lang/UnsupportedOperationException;");
        runtime.array_set(array, static_cast<std::int32_t>(state[2].bits), args[1]);
        return Value::nothing();
    }
    if (name == "add" && signature == "(Ljava/lang/Object;)V")
        runtime.raise("Ljava/lang/UnsupportedOperationException;");
    return {};
}
} // namespace aether::dex
