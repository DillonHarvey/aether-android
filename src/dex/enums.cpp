#include "enums.hpp"
#include "time_units.hpp"
#include <array>

namespace aether::dex {
std::optional<HostClass> enum_class(std::string_view descriptor) {
    static constexpr std::array<std::string_view, 2> interfaces{"Ljava/lang/Comparable;",
                                                                "Ljava/io/Serializable;"};
    if (descriptor == time_unit_type)
        return HostClass{enum_type, {}, true};
    if (descriptor == enum_type)
        return HostClass{"Ljava/lang/Object;", interfaces, true};
    if (descriptor == "Ljava/lang/Comparable;")
        return HostClass{"Ljava/lang/Object;", {}, true, true};
    return {};
}
bool enum_instance_method(std::string_view name, std::string_view signature) {
    return ((name == "name" || name == "toString") && signature == "()Ljava/lang/String;") ||
           ((name == "ordinal" || name == "hashCode") && signature == "()I") ||
           (name == "equals" && signature == "(Ljava/lang/Object;)Z") ||
           (name == "compareTo" &&
            (signature == "(Ljava/lang/Enum;)I" || signature == "(Ljava/lang/Object;)I")) ||
           (name == "getDeclaringClass" && signature == "()Ljava/lang/Class;") ||
           (name == "clone" && signature == "()Ljava/lang/Object;");
}
std::uint32_t ManagedEnum::ordinal() const {
    if (!initialized_)
        throw DexError("AETHER_DEX_STATE", "Enum must be initialized before use");
    return ordinal_;
}
std::optional<Value> ManagedEnum::invoke(ManagedRuntime &runtime, std::string_view name,
                                         std::string_view signature, std::span<const Value> args) {
    if (name == "<init>") {
        if (signature != "(Ljava/lang/String;I)V")
            return {};
        if (initialized_)
            throw DexError("AETHER_DEX_STATE", "Enum constructor invoked twice");
        name_ = args[1].bits;
        ordinal_ = static_cast<std::uint32_t>(args[2].bits);
        initialized_ = true;
        return Value::nothing();
    }
    if (!enum_instance_method(name, signature))
        return {};
    (void)ordinal();
    if ((name == "name" || name == "toString") && signature == "()Ljava/lang/String;")
        return reference();
    if (name == "ordinal" && signature == "()I")
        return Value::word(ordinal_);
    if (name == "equals" && signature == "(Ljava/lang/Object;)Z")
        return Value::word(args[0].bits == args[1].bits);
    if (name == "hashCode" && signature == "()I")
        return Value::word(static_cast<std::uint32_t>(args[0].bits ^ (args[0].bits >> 32)));
    if (name == "clone" && signature == "()Ljava/lang/Object;")
        runtime.raise("Ljava/lang/CloneNotSupportedException;");
    return {};
}
} // namespace aether::dex
