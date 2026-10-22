#include "booleans.hpp"
#include <array>

namespace aether::dex {
std::optional<HostClass> boolean_class(std::string_view descriptor) {
    static constexpr std::array<std::string_view,2> interfaces{"Ljava/lang/Comparable;","Ljava/io/Serializable;"};
    if(descriptor==boolean_type)return HostClass{"Ljava/lang/Object;",interfaces};
    return {};
}
void ManagedBoolean::initialize(bool value) {
    if(initialized_)throw DexError("AETHER_DEX_STATE","Boolean constructor invoked twice");
    value_=value;initialized_=true;
}
bool ManagedBoolean::value() const {
    if(!initialized_)throw DexError("AETHER_DEX_STATE","Boolean must be initialized before use");
    return value_;
}
std::optional<Value> ManagedBoolean::invoke(ManagedRuntime &runtime,std::string_view name,
    std::string_view signature,std::span<const Value> args,const ManagedBoolean *other) {
    if(name=="<init>") {
        if(signature!="(Z)V")return {};
        initialize(args[1].bits!=0);return Value::nothing();
    }
    const auto current=value();
    if(name=="booleanValue" && signature=="()Z")return Value::word(current);
    if(name=="hashCode" && signature=="()I")return Value::word(current?1231:1237);
    if(name=="toString" && signature=="()Ljava/lang/String;")
        return Value::reference(runtime.new_string(current?u"true":u"false"));
    if(name=="equals" && signature=="(Ljava/lang/Object;)Z")return Value::word(other && current==other->value());
    if(name=="compareTo" && (signature=="(Ljava/lang/Boolean;)I" || signature=="(Ljava/lang/Object;)I")) {
        if(!args[1].bits)runtime.raise("Ljava/lang/NullPointerException;");
        if(!other)runtime.raise("Ljava/lang/ClassCastException;");
        const auto right=other->value();
        return Value::word(static_cast<std::uint32_t>(static_cast<int>(current)-static_cast<int>(right)));
    }
    return {};
}
} // namespace aether::dex
