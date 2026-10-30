#include "floating_values.hpp"
#include <array>
#include <bit>
#include <limits>
namespace aether::dex {
namespace {
bool nan(std::uint64_t bits,bool wide) {
    return wide?(bits&0x7fffffffffffffffULL)>0x7ff0000000000000ULL:
        (bits&0x7fffffffULL)>0x7f800000ULL;
}
std::uint64_t canonical_bits(std::uint64_t bits,bool wide) {
    return nan(bits,wide)?(wide?0x7ff8000000000000ULL:0x7fc00000ULL):bits;
}
std::uint64_t widen(std::uint32_t bits) {
    const auto sign=static_cast<std::uint64_t>(bits>>31)<<63;
    auto exponent=(bits>>23)&255U;auto fraction=static_cast<std::uint64_t>(bits&0x7fffffU);
    if(exponent==255)return fraction?0x7ff8000000000000ULL:sign|0x7ff0000000000000ULL;
    if(!exponent) {
        if(!fraction)return sign;
        const auto shift=std::countl_zero(fraction)-40;
        fraction<<=shift;
        return sign|(static_cast<std::uint64_t>(897-shift)<<52)|((fraction&0x7fffffULL)<<29);
    }
    return sign|(static_cast<std::uint64_t>(exponent+896)<<52)|(fraction<<29);
}
std::uint64_t round_shift(std::uint64_t value,unsigned shift) {
    if(!shift)return value;
    if(shift>64)return 0;
    if(shift==64)return value>0x8000000000000000ULL?1:0;
    const auto result=value>>shift,mask=(std::uint64_t{1}<<shift)-1,rest=value&mask,half=std::uint64_t{1}<<(shift-1);
    return result+(rest>half || (rest==half && (result&1)));
}
std::uint32_t narrow(std::uint64_t bits) {
    const auto sign=static_cast<std::uint32_t>(bits>>63)<<31;
    const auto encoded=static_cast<unsigned>((bits>>52)&2047);
    auto fraction=bits&0xfffffffffffffULL;
    if(encoded==2047)return fraction?0x7fc00000U:sign|0x7f800000U;
    if(!encoded && !fraction)return sign;
    int exponent=static_cast<int>(encoded)-1023;
    if(encoded)fraction|=std::uint64_t{1}<<52;
    else {const auto shift=std::countl_zero(fraction)-11;fraction<<=shift;exponent=-1022-shift;}
    if(exponent>127)return sign|0x7f800000U;
    if(exponent< -126) {
        const auto shift=static_cast<unsigned>(-126-exponent+29);
        return sign|static_cast<std::uint32_t>(round_shift(fraction,shift));
    }
    auto rounded=round_shift(fraction,29);
    if(rounded==(std::uint64_t{1}<<24)){rounded>>=1;++exponent;}
    if(exponent>127)return sign|0x7f800000U;
    return sign|(static_cast<std::uint32_t>(exponent+127)<<23)|(static_cast<std::uint32_t>(rounded)&0x7fffffU);
}
std::uint64_t integer_bits(std::uint64_t bits,bool wide,unsigned width) {
    if(nan(bits,wide))return 0;
    const unsigned fraction_bits=wide?52U:23U;
    const auto sign=(bits>>(wide?63:31))!=0;
    const auto encoded=(bits>>fraction_bits)&(wide?2047ULL:255ULL);
    const int exponent=static_cast<int>(encoded)-(wide?1023:127);
    const auto minimum=std::uint64_t{1}<<(width-1),maximum=minimum-1;
    if(exponent>=static_cast<int>(width-1))return sign?minimum:maximum;
    if(exponent<0)return 0;
    const auto fraction=(bits&((std::uint64_t{1}<<fraction_bits)-1))|(std::uint64_t{1}<<fraction_bits);
    const auto magnitude=exponent>=static_cast<int>(fraction_bits)?fraction<<(static_cast<unsigned>(exponent)-fraction_bits):
        fraction>>(fraction_bits-static_cast<unsigned>(exponent));
    return sign?std::uint64_t{0}-magnitude:magnitude;
}
std::int32_t compare_bits(std::uint64_t left,std::uint64_t right,bool wide) {
    left=canonical_bits(left,wide);right=canonical_bits(right,wide);
    const auto sign=wide?0x8000000000000000ULL:0x80000000ULL;
    const auto mask=wide?~std::uint64_t{0}:0xffffffffULL;
    const auto a=(left&sign)?(~left&mask):(left|sign),b=(right&sign)?(~right&mask):(right|sign);
    return (a>b)-(a<b);
}
}
std::uint64_t widen_float_bits(std::uint32_t bits) noexcept { return widen(bits); }
std::optional<HostClass> floating_class(std::string_view type) {
    static constexpr std::array<std::string_view,2> interfaces{"Ljava/lang/Comparable;","Ljava/io/Serializable;"};
    if(type==float_type || type==double_type)return HostClass{"Ljava/lang/Number;",interfaces};
    return {};
}
bool floating_method(std::string_view type,std::string_view name,std::string_view signature) noexcept {
    const bool wide=type==double_type;
    return (name=="<init>" && (signature==(wide?"(D)V":"(F)V") || (!wide && signature=="(D)V"))) ||
        ((name=="intValue" || name=="hashCode") && signature=="()I") || (name=="longValue" && signature=="()J") ||
        (name=="shortValue" && signature=="()S") || (name=="byteValue" && signature=="()B") ||
        (name=="floatValue" && signature=="()F") || (name=="doubleValue" && signature=="()D") ||
        ((name=="isNaN" || name=="isInfinite") && signature=="()Z") ||
        (name=="equals" && signature=="(Ljava/lang/Object;)Z") ||
        (name=="compareTo" && (signature==(wide?"(Ljava/lang/Double;)I":"(Ljava/lang/Float;)I") || signature=="(Ljava/lang/Object;)I"));
}
bool floating_static(std::string_view name,std::string_view signature) noexcept {
    return name=="valueOf" || name=="parseFloat" || name=="parseDouble" || name=="compare" || name=="sum" || name=="max" || name=="min" ||
        name=="floatToIntBits" || name=="floatToRawIntBits" || name=="intBitsToFloat" ||
        name=="doubleToLongBits" || name=="doubleToRawLongBits" || name=="longBitsToDouble" ||
        ((name=="isNaN" || name=="isInfinite" || name=="isFinite" || name=="hashCode" || name=="toString" || name=="toHexString") &&
         signature.size()>2 && signature[1]!=')');
}
std::optional<Value> floating_static_call(std::string_view type,std::string_view name,std::string_view signature,std::span<const Value> args) {
    const bool wide=type==double_type;
    const auto unary=wide?"(D)Z":"(F)Z";
    if((name=="isNaN" || name=="isInfinite" || name=="isFinite") && signature==unary) {
        const auto bits=args[0].bits,absolute=bits&(wide?0x7fffffffffffffffULL:0x7fffffffULL),infinity=wide?0x7ff0000000000000ULL:0x7f800000ULL;
        return Value::word(name=="isNaN"?nan(bits,wide):name=="isInfinite"?absolute==infinity:absolute<infinity);
    }
    if(name=="compare" && signature==(wide?"(DD)I":"(FF)I"))return Value::word(static_cast<std::uint32_t>(compare_bits(args[0].bits,args[1].bits,wide)));
    if(name=="hashCode" && signature==(wide?"(D)I":"(F)I")) {
        const auto bits=canonical_bits(args[0].bits,wide);return Value::word(static_cast<std::uint32_t>(wide?bits^(bits>>32):bits));
    }
    if(!wide && (name=="floatToIntBits" || name=="floatToRawIntBits") && signature=="(F)I")return Value::word(static_cast<std::uint32_t>(name=="floatToIntBits"?canonical_bits(args[0].bits,false):args[0].bits));
    if(!wide && name=="intBitsToFloat" && signature=="(I)F")return Value::word(static_cast<std::uint32_t>(args[0].bits));
    if(wide && (name=="doubleToLongBits" || name=="doubleToRawLongBits") && signature=="(D)J")return Value::wide(name=="doubleToLongBits"?canonical_bits(args[0].bits,true):args[0].bits);
    if(wide && name=="longBitsToDouble" && signature=="(J)D")return Value::wide(args[0].bits);
    return {};
}
std::optional<Value> floating_constant(std::string_view type,std::string_view name,std::string_view descriptor) {
    const bool wide=type==double_type;
    if(descriptor=="I") {
        if(name=="SIZE")return Value::word(wide?64:32);
        if(name=="BYTES")return Value::word(wide?8:4);
        if(name=="MAX_EXPONENT")return Value::word(wide?1023:127);
        if(name=="MIN_EXPONENT")return Value::word(static_cast<std::uint32_t>(wide?-1022:-126));
    }
    if(descriptor!=(wide?"D":"F"))return {};
    std::uint64_t bits;
    if(name=="NaN")bits=wide?0x7ff8000000000000ULL:0x7fc00000ULL;
    else if(name=="POSITIVE_INFINITY")bits=wide?0x7ff0000000000000ULL:0x7f800000ULL;
    else if(name=="NEGATIVE_INFINITY")bits=wide?0xfff0000000000000ULL:0xff800000ULL;
    else if(name=="MAX_VALUE")bits=wide?0x7fefffffffffffffULL:0x7f7fffffULL;
    else if(name=="MIN_NORMAL")bits=wide?0x0010000000000000ULL:0x00800000ULL;
    else if(name=="MIN_VALUE")bits=1;
    else return {};
    return wide?Value::wide(bits):Value::word(static_cast<std::uint32_t>(bits));
}
void ManagedFloating::initialize(std::uint64_t bits) {
    if(initialized_)throw DexError("AETHER_DEX_STATE","Floating wrapper constructor invoked twice");
    bits_=wide_?bits:static_cast<std::uint32_t>(bits);initialized_=true;
}
std::uint64_t ManagedFloating::bits() const {
    if(!initialized_)throw DexError("AETHER_DEX_STATE","Floating wrapper must be initialized before use");
    return bits_;
}
std::uint64_t ManagedFloating::canonical() const{return canonical_bits(bits(),wide_);}
std::uint32_t ManagedFloating::hash() const {const auto value=canonical();return static_cast<std::uint32_t>(wide_?value^(value>>32):value);}
bool ManagedFloating::equals(const ManagedFloating *other) const {const auto own=canonical();return other && wide_==other->wide_ && own==other->canonical();}
std::optional<Value> ManagedFloating::invoke(ManagedRuntime &runtime,std::string_view name,std::string_view signature,std::span<const Value> args,const ManagedFloating *other) {
    if(name=="<init>") {initialize(!wide_ && signature=="(D)V"?narrow(args[1].bits):args[1].bits);return Value::nothing();}
    const auto raw=bits();
    if(name=="equals")return Value::word(equals(other));
    if(name=="hashCode")return Value::word(hash());
    if(name=="compareTo") {
        if(!args[1].bits)runtime.raise("Ljava/lang/NullPointerException;");
        if(!other || wide_!=other->wide_)runtime.raise("Ljava/lang/ClassCastException;");
        return Value::word(static_cast<std::uint32_t>(compare_bits(raw,other->bits(),wide_)));
    }
    if(name=="isNaN")return Value::word(nan(raw,wide_));
    if(name=="isInfinite")return Value::word((raw&(wide_?0x7fffffffffffffffULL:0x7fffffffULL))==(wide_?0x7ff0000000000000ULL:0x7f800000ULL));
    if(name=="floatValue")return Value::word(wide_?narrow(raw):static_cast<std::uint32_t>(raw));
    if(name=="doubleValue")return Value::wide(wide_?raw:widen(static_cast<std::uint32_t>(raw)));
    if(name=="longValue")return Value::wide(integer_bits(raw,wide_,64));
    const auto integer=static_cast<std::uint32_t>(integer_bits(raw,wide_,32));
    if(name=="intValue")return Value::word(integer);
    if(name=="byteValue")return Value::word(static_cast<std::uint32_t>(static_cast<std::int32_t>(std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(integer)))));
    if(name=="shortValue")return Value::word(static_cast<std::uint32_t>(static_cast<std::int32_t>(std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(integer)))));
    return {};
}
}
