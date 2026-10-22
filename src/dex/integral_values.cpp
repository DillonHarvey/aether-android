#include "integral_values.hpp"
#include <array>
#include <bit>
namespace aether::dex {
namespace {
// Assemble nearest-even IEEE bits using integer arithmetic, without touching fenv.
std::uint64_t binary(std::uint64_t bits,unsigned precision,unsigned exponent_bits,unsigned bias) {
    const bool negative=(bits>>63)!=0;
    const auto magnitude=negative?std::uint64_t{0}-bits:bits;
    if(!magnitude)return 0;
    auto exponent=static_cast<unsigned>(std::bit_width(magnitude)-1);
    std::uint64_t significand;
    if(exponent<precision)significand=magnitude<<(precision-1-exponent);
    else {
        const auto shift=exponent-(precision-1);
        significand=magnitude>>shift;
        const auto remainder=magnitude&((std::uint64_t{1}<<shift)-1);
        const auto half=std::uint64_t{1}<<(shift-1);
        if(remainder>half || (remainder==half && (significand&1)))++significand;
        if(significand==(std::uint64_t{1}<<precision)){significand>>=1;++exponent;}
    }
    return (std::uint64_t{negative}<<(precision-1+exponent_bits)) |
        (std::uint64_t{exponent+bias}<<(precision-1)) |
        (significand&((std::uint64_t{1}<<(precision-1))-1));
}
}
std::optional<HostClass> integral_class(std::string_view type) {
    static constexpr std::array<std::string_view,2> interfaces{"Ljava/lang/Comparable;","Ljava/io/Serializable;"};
    if(type==long_type || type==short_type)return HostClass{"Ljava/lang/Number;",interfaces};
    return {};
}
bool integral_method(std::string_view type,std::string_view name,std::string_view signature) noexcept {
    const bool large=type==long_type;
    if(type!=long_type && type!=short_type)return false;
    return (name=="<init>" && signature==(large?"(J)V":"(S)V")) ||
        ((name=="intValue" || name=="hashCode") && signature=="()I") ||
        (name=="byteValue" && signature=="()B") || (name=="shortValue" && signature=="()S") ||
        (name=="longValue" && signature=="()J") || (name=="floatValue" && signature=="()F") ||
        (name=="doubleValue" && signature=="()D") || (name=="toString" && signature=="()Ljava/lang/String;") ||
        (name=="equals" && signature=="(Ljava/lang/Object;)Z") ||
        (name=="compareTo" && (signature=="(Ljava/lang/Object;)I" ||
                             signature==(large?"(Ljava/lang/Long;)I":"(Ljava/lang/Short;)I")));
}
void ManagedIntegral::initialize(std::uint64_t bits) {
    if(initialized_)throw DexError("AETHER_DEX_STATE","Integral wrapper constructor invoked twice");
    bits_=long_?bits:static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(bits))));
    initialized_=true;
}
std::uint64_t ManagedIntegral::bits() const {
    if(!initialized_)throw DexError("AETHER_DEX_STATE","Integral wrapper must be initialized before use");
    return bits_;
}
std::optional<Value> ManagedIntegral::invoke(ManagedRuntime &runtime,std::string_view name,std::string_view signature,
    std::span<const Value> args,const ManagedIntegral *other) {
    if(!integral_method(long_?long_type:short_type,name,signature))return {};
    if(name=="<init>"){initialize(args[1].bits);return Value::nothing();}
    const auto value=bits();
    if(name=="longValue")return Value::wide(value);
    if(name=="intValue")return Value::word(static_cast<std::uint32_t>(value));
    if(name=="byteValue")return Value::word(static_cast<std::uint32_t>(static_cast<std::int32_t>(std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(value)))));
    if(name=="shortValue")return Value::word(static_cast<std::uint32_t>(static_cast<std::int32_t>(std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(value)))));
    if(name=="floatValue")return Value::word(static_cast<std::uint32_t>(binary(value,24,8,127)));
    if(name=="doubleValue")return Value::wide(binary(value,53,11,1023));
    if(name=="hashCode")return Value::word(static_cast<std::uint32_t>(long_?value^(value>>32):value));
    if(name=="equals")return Value::word(other && long_==other->long_ && value==other->bits());
    if(name=="compareTo") {
        if(!args[1].bits)runtime.raise("Ljava/lang/NullPointerException;");
        if(!other || long_!=other->long_)runtime.raise("Ljava/lang/ClassCastException;");
        const auto left=std::bit_cast<std::int64_t>(value),right=std::bit_cast<std::int64_t>(other->bits());
        return Value::word(static_cast<std::uint32_t>(long_?(left>right)-(left<right):left-right));
    }
    const auto text=std::to_string(std::bit_cast<std::int64_t>(value));
    return Value::reference(runtime.new_string(std::u16string(text.begin(),text.end())));
}
}
