#include "characters.hpp"
#include <array>

namespace aether::dex {
std::optional<HostClass> character_class(std::string_view type) {
    static constexpr std::array<std::string_view, 3> interfaces{
        "Ljava/io/Serializable;", "Ljava/lang/Comparable;", "Ljava/lang/constant/Constable;"};
    if (type == character_type) return HostClass{"Ljava/lang/Object;", interfaces};
    return {};
}
bool character_method(std::string_view name, std::string_view signature) noexcept {
    return (name == "<init>" && signature == "(C)V") ||
           (name == "charValue" && signature == "()C") ||
           (name == "hashCode" && signature == "()I") ||
           (name == "toString" && signature == "()Ljava/lang/String;") ||
           (name == "equals" && signature == "(Ljava/lang/Object;)Z") ||
           (name == "compareTo" && (signature == "(Ljava/lang/Character;)I" || signature == "(Ljava/lang/Object;)I"));
}
bool character_static(std::string_view name, std::string_view signature) noexcept {
    return (name == "valueOf" && signature == "(C)Ljava/lang/Character;") ||
           (name == "hashCode" && signature == "(C)I") ||
           (name == "compare" && signature == "(CC)I") ||
           (name == "toString" && signature == "(C)Ljava/lang/String;");
}
void ManagedCharacter::initialize(std::uint32_t bits) {
    if (initialized_) throw DexError("AETHER_DEX_STATE", "Character constructor invoked twice");
    value_ = static_cast<std::uint16_t>(bits);
    initialized_ = true;
}
std::uint16_t ManagedCharacter::value() const {
    if (!initialized_) throw DexError("AETHER_DEX_STATE", "Character must be initialized before use");
    return value_;
}
std::optional<Value> ManagedCharacter::invoke(ManagedRuntime &runtime, std::string_view name,
    std::string_view signature, std::span<const Value> args, const ManagedCharacter *other) {
    if (!character_method(name, signature)) return {};
    if (name == "<init>") { initialize(static_cast<std::uint32_t>(args[1].bits)); return Value::nothing(); }
    const auto current = value();
    if (name == "charValue" || name == "hashCode") return Value::word(current);
    if (name == "equals") return Value::word(other && current == other->value());
    if (name == "compareTo") {
        if (!args[1].bits) runtime.raise("Ljava/lang/NullPointerException;");
        if (!other) runtime.raise("Ljava/lang/ClassCastException;");
        return Value::word(static_cast<std::uint32_t>(static_cast<std::int32_t>(current) - other->value()));
    }
    // A Java char is one UTF-16 code unit, including NUL and isolated surrogates.
    return Value::reference(runtime.new_string(std::u16string(1, static_cast<char16_t>(current))));
}
}
