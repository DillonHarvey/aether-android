#include "atomics.hpp"
#include <array>
#include <bit>
#include "integral_values.hpp"

namespace aether::dex {
std::optional<HostClass> atomic_class(std::string_view descriptor) {
    static constexpr std::array<std::string_view, 1> interfaces{"Ljava/io/Serializable;"};
    if (descriptor == atomic_boolean_type)
        return HostClass{"Ljava/lang/Object;", interfaces};
    if (descriptor == atomic_reference_type)
        return HostClass{"Ljava/lang/Object;", interfaces};
    if (descriptor == atomic_integer_type)
        return HostClass{number_type, interfaces};
    if (descriptor == atomic_long_type)
        return HostClass{number_type, interfaces, false, false, true, true};
    if (descriptor == number_type)
        return HostClass{"Ljava/lang/Object;", interfaces, true};
    if (descriptor == atomic_field_updater_type)
        return HostClass{"Ljava/lang/Object;", {}, true};
    if (descriptor == field_updater_implementation_type)
        return HostClass{atomic_field_updater_type, {}};
    return {};
}
bool atomic_long_method(std::string_view name, std::string_view signature) noexcept {
    return (name == "<init>" && (signature == "()V" || signature == "(J)V")) ||
        ((name == "get" || name == "longValue" || name == "getAndIncrement" || name == "incrementAndGet" ||
          name == "getAndDecrement" || name == "decrementAndGet") && signature == "()J") ||
        ((name == "set" || name == "lazySet") && signature == "(J)V") ||
        ((name == "getAndSet" || name == "getAndAdd" || name == "addAndGet") && signature == "(J)J") ||
        ((name == "compareAndSet" || name == "weakCompareAndSet") && signature == "(JJ)Z") ||
        (name == "intValue" && signature == "()I") || (name == "byteValue" && signature == "()B") ||
        (name == "shortValue" && signature == "()S") || (name == "floatValue" && signature == "()F") ||
        (name == "doubleValue" && signature == "()D") || (name == "toString" && signature == "()Ljava/lang/String;");
}
std::optional<Value> AtomicLong::invoke(ManagedRuntime &runtime, std::string_view name,
                                     std::string_view signature, std::span<const Value> args) {
    if (!atomic_long_method(name, signature)) return {};
    if (name == "<init>") {
        if (initialized_) throw DexError("AETHER_DEX_STATE", "AtomicLong constructor invoked twice");
        value_.store(signature == "()V" ? 0 : args[1].bits);
        initialized_ = true;
        return Value::nothing();
    }
    if (!initialized_) throw DexError("AETHER_DEX_STATE", "AtomicLong must be initialized before use");
    if (name == "get" || name == "longValue") return Value::wide(value_.load());
    if (name == "set" || name == "lazySet") {
        value_.store(args[1].bits, name == "lazySet" ? std::memory_order_release : std::memory_order_seq_cst);
        return Value::nothing();
    }
    if (name == "getAndSet") return Value::wide(value_.exchange(args[1].bits));
    if (name == "compareAndSet" || name == "weakCompareAndSet") {
        auto expected = args[1].bits;
        return Value::word(value_.compare_exchange_strong(expected, args[2].bits));
    }
    if (name == "getAndAdd" || name == "addAndGet" || name == "getAndIncrement" ||
        name == "incrementAndGet" || name == "getAndDecrement" || name == "decrementAndGet") {
        const auto delta = (name == "getAndAdd" || name == "addAndGet") ? args[1].bits :
            ((name == "getAndIncrement" || name == "incrementAndGet") ? std::uint64_t{1} : UINT64_MAX);
        const auto previous = value_.fetch_add(delta); // Java modulo-2^64 arithmetic.
        return Value::wide(name.starts_with("getAnd") ? previous : previous + delta);
    }
    // Reuse integer-based Java narrowing/widening and decimal conversion,
    // without boxing or dependence on the host floating-point rounding mode.
    ManagedIntegral snapshot(true);
    snapshot.initialize(value_.load());
    return snapshot.invoke(runtime, name, signature, args, nullptr);
}
bool field_updater_method(std::string_view name, std::string_view signature) {
    return (name == "get" && signature == "(Ljava/lang/Object;)Ljava/lang/Object;") ||
           ((name == "set" || name == "lazySet") && signature == "(Ljava/lang/Object;Ljava/lang/Object;)V") ||
           (name == "getAndSet" && signature == "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;") ||
           ((name == "compareAndSet" || name == "weakCompareAndSet") &&
            signature == "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z");
}
Value ReferenceFieldUpdater::invoke(ManagedRuntime &runtime, Value &slot, std::string_view field_type,
                                    std::string_view name, std::span<const Value> args) const {
    if (slot.kind != ValueKind::reference)
        throw DexError("AETHER_DEX_FIELD", "Atomic reference updater requires a reference field slot");
    const bool compare = name == "compareAndSet" || name == "weakCompareAndSet";
    const auto update = name == "get" ? ObjectId{0} : args[compare ? 3 : 2].bits;
    if (name != "get" && update && !runtime.assignable(update, field_type))
        runtime.raise("Ljava/lang/ClassCastException;");
    // The owner-thread guard prevents ordinary field reads/writes from racing
    // this atomic view. No atomic_ref survives this operation or a collection.
    static_assert(alignof(Value) >= std::atomic_ref<ObjectId>::required_alignment);
    static_assert(offsetof(Value, bits) % std::atomic_ref<ObjectId>::required_alignment == 0);
    std::atomic_ref<ObjectId> value(slot.bits);
    if (name == "get")
        return Value::reference(value.load());
    if (name == "set" || name == "lazySet") {
        value.store(update, name == "lazySet" ? std::memory_order_release : std::memory_order_seq_cst);
        return Value::nothing();
    }
    if (name == "getAndSet")
        return Value::reference(value.exchange(update));
    auto expected = args[2].bits;
    return Value::word(value.compare_exchange_strong(expected, update));
}
std::optional<Value> AtomicReference::invoke(std::string_view name, std::string_view signature,
                                             std::span<const Value> args) {
    if (name == "<init>") {
        if (signature != "()V" && signature != "(Ljava/lang/Object;)V")
            return {};
        if (initialized_)
            throw DexError("AETHER_DEX_STATE", "AtomicReference constructor invoked twice");
        value_.store(signature == "()V" ? 0 : args[1].bits);
        initialized_ = true;
        return Value::nothing();
    }
    if (!initialized_)
        throw DexError("AETHER_DEX_STATE", "AtomicReference must be initialized before use");
    if (name == "get" && signature == "()Ljava/lang/Object;")
        return reference();
    if ((name == "set" || name == "lazySet") && signature == "(Ljava/lang/Object;)V") {
        value_.store(args[1].bits, name == "lazySet" ? std::memory_order_release : std::memory_order_seq_cst);
        return Value::nothing();
    }
    if (name == "getAndSet" && signature == "(Ljava/lang/Object;)Ljava/lang/Object;")
        return Value::reference(value_.exchange(args[1].bits));
    if ((name == "compareAndSet" || name == "weakCompareAndSet") &&
        signature == "(Ljava/lang/Object;Ljava/lang/Object;)Z") {
        auto expected = args[1].bits;
        // The weak API permits a strong attempt. Managed entry and collection
        // retain their existing owner-thread policy; no guest scheduling is added.
        return Value::word(value_.compare_exchange_strong(expected, args[2].bits));
    }
    return {};
}
std::optional<Value> AtomicInteger::invoke_boolean(ManagedRuntime &runtime, std::string_view name,
                                                std::string_view signature, std::span<const Value> args) {
    const auto boolean=[](Value value) { return static_cast<std::uint32_t>(value.bits!=0); };
    if(name=="<init>") {
        if(signature!="()V" && signature!="(Z)V") return {};
        if(initialized_) throw DexError("AETHER_DEX_STATE", "AtomicBoolean constructor invoked twice");
        value_.store(signature=="()V" ? 0u : boolean(args[1]));initialized_=true;
        return Value::nothing();
    }
    if(!initialized_) throw DexError("AETHER_DEX_STATE", "AtomicBoolean must be initialized before use");
    if(name=="get" && signature=="()Z") return Value::word(value_.load());
    if((name=="set" || name=="lazySet") && signature=="(Z)V") {
        value_.store(boolean(args[1]),name=="lazySet"?std::memory_order_release:std::memory_order_seq_cst);
        return Value::nothing();
    }
    if(name=="getAndSet" && signature=="(Z)Z") return Value::word(value_.exchange(boolean(args[1])));
    if((name=="compareAndSet" || name=="weakCompareAndSet") && signature=="(ZZ)Z") {
        auto expected=boolean(args[1]);
        // A strong attempt is permitted by the weak API and retains honest results.
        return Value::word(value_.compare_exchange_strong(expected,boolean(args[2])));
    }
    if(name=="toString" && signature=="()Ljava/lang/String;")
        return Value::reference(runtime.new_string(value_.load()?u"true":u"false"));
    return {};
}
std::optional<Value> AtomicInteger::invoke(ManagedRuntime &runtime, std::string_view name,
                                           std::string_view signature, std::span<const Value> args) {
    if (boolean_) return invoke_boolean(runtime,name,signature,args);
    if (name == "<init>") {
        if (signature != "()V" && signature != "(I)V")
            return {};
        if (initialized_)
            throw DexError("AETHER_DEX_STATE", "AtomicInteger constructor invoked twice");
        value_.store(signature == "()V" ? 0 : static_cast<std::uint32_t>(args[1].bits));
        initialized_ = true;
        return Value::nothing();
    }
    if (!initialized_)
        throw DexError("AETHER_DEX_STATE", "AtomicInteger must be initialized before use");
    if ((name == "get" || name == "intValue") && signature == "()I")
        return Value::word(value_.load());
    if ((name == "set" || name == "lazySet") && signature == "(I)V") {
        value_.store(static_cast<std::uint32_t>(args[1].bits),
                     name == "lazySet" ? std::memory_order_release : std::memory_order_seq_cst);
        return Value::nothing();
    }
    if (name == "getAndSet" && signature == "(I)I")
        return Value::word(value_.exchange(static_cast<std::uint32_t>(args[1].bits)));
    if ((name == "compareAndSet" || name == "weakCompareAndSet") && signature == "(II)Z") {
        auto expected = static_cast<std::uint32_t>(args[1].bits);
        return Value::word(
            value_.compare_exchange_strong(expected, static_cast<std::uint32_t>(args[2].bits)));
    }
    const bool increment = name == "getAndIncrement" || name == "incrementAndGet";
    const bool decrement = name == "getAndDecrement" || name == "decrementAndGet";
    const bool add = name == "getAndAdd" || name == "addAndGet";
    if (((increment || decrement) && signature == "()I") || (add && signature == "(I)I")) {
        const auto delta = add ? static_cast<std::uint32_t>(args[1].bits) : (increment ? 1u : 0xffffffffu);
        // Unsigned arithmetic preserves Java's modulo-2^32 overflow behavior.
        const auto previous = value_.fetch_add(delta);
        return Value::word(name.starts_with("getAnd") ? previous : previous + delta);
    }
    if ((name == "longValue" && signature == "()J") || (name == "floatValue" && signature == "()F") ||
        (name == "doubleValue" && signature == "()D") ||
        (name == "toString" && signature == "()Ljava/lang/String;")) {
        const auto value = std::bit_cast<std::int32_t>(value_.load());
        if (name == "longValue")
            return Value::wide(static_cast<std::uint64_t>(static_cast<std::int64_t>(value)));
        if (name == "floatValue")
            return Value::word(std::bit_cast<std::uint32_t>(static_cast<float>(value)));
        if (name == "doubleValue")
            return Value::wide(std::bit_cast<std::uint64_t>(static_cast<double>(value)));
        const auto decimal = std::to_string(value);
        return Value::reference(runtime.new_string(std::u16string(decimal.begin(), decimal.end())));
    }
    return {};
}
} // namespace aether::dex
