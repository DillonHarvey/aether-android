#include "bytes.hpp"
#include <array>
#include <bit>
namespace aether::dex {
std::optional<HostClass> byte_class(std::string_view type) {
    static constexpr std::array<std::string_view,2> interfaces{"Ljava/lang/Comparable;","Ljava/io/Serializable;"};
    if(type==byte_type)return HostClass{"Ljava/lang/Number;",interfaces};
    return {};
}
bool byte_method(std::string_view name,std::string_view signature) noexcept {
    return (name=="<init>" && signature=="(B)V") ||
        ((name=="intValue" || name=="hashCode") && signature=="()I") ||
        (name=="byteValue" && signature=="()B") || (name=="shortValue" && signature=="()S") ||
        (name=="longValue" && signature=="()J") || (name=="floatValue" && signature=="()F") ||
        (name=="doubleValue" && signature=="()D") || (name=="toString" && signature=="()Ljava/lang/String;") ||
        (name=="equals" && signature=="(Ljava/lang/Object;)Z") ||
        (name=="compareTo" && (signature=="(Ljava/lang/Byte;)I" || signature=="(Ljava/lang/Object;)I"));
}
void ManagedByte::initialize(std::uint32_t bits) {
    if(initialized_)throw DexError("AETHER_DEX_STATE","Byte constructor invoked twice");
    value_=std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(bits));initialized_=true;
}
std::int32_t ManagedByte::value() const {
    if(!initialized_)throw DexError("AETHER_DEX_STATE","Byte must be initialized before use");
    return value_;
}
std::optional<Value> ManagedByte::invoke(ManagedRuntime &runtime,std::string_view name,std::string_view signature,
    std::span<const Value> args,const ManagedByte *other) {
    if(name=="<init>" && signature=="(B)V"){initialize(static_cast<std::uint32_t>(args[1].bits));return Value::nothing();}
    if(!byte_method(name,signature))return {};
    const auto number=value();
    if((name=="intValue" || name=="hashCode" || name=="byteValue" || name=="shortValue"))return Value::word(static_cast<std::uint32_t>(number));
    if(name=="longValue")return Value::wide(static_cast<std::uint64_t>(static_cast<std::int64_t>(number)));
    if(name=="floatValue")return Value::word(std::bit_cast<std::uint32_t>(static_cast<float>(number)));
    if(name=="doubleValue")return Value::wide(std::bit_cast<std::uint64_t>(static_cast<double>(number)));
    if(name=="equals")return Value::word(other && number==other->value());
    if(name=="compareTo") {
        if(!args[1].bits)runtime.raise("Ljava/lang/NullPointerException;");
        if(!other)runtime.raise("Ljava/lang/ClassCastException;");
        return Value::word(static_cast<std::uint32_t>(number-other->value()));
    }
    const auto text=std::to_string(number);
    return Value::reference(runtime.new_string(std::u16string(text.begin(),text.end())));
}
}
