#include "uuids.hpp"
#include <bit>
namespace aether::dex {
std::optional<HostClass> uuid_class(std::string_view type) {
    static constexpr std::array<std::string_view,2> interfaces{"Ljava/lang/Comparable;","Ljava/io/Serializable;"};
    if(type==uuid_type)return HostClass{"Ljava/lang/Object;",interfaces};
    return {};
}
std::array<std::uint64_t,2> uuid_v4_bits(std::span<const std::uint8_t,16> bytes) noexcept {
    std::array<std::uint64_t,2> result{};
    for(std::size_t n=0;n<16;++n)result[n/8]=(result[n/8]<<8)|bytes[n];
    result[0]=(result[0]&~std::uint64_t{0xf000})|0x4000;
    result[1]=(result[1]&0x3fffffffffffffffULL)|0x8000000000000000ULL;
    return result;
}
void ManagedUuid::initialize(std::uint64_t most,std::uint64_t least) {
    if(initialized_)throw DexError("AETHER_DEX_STATE","UUID constructor invoked twice");
    most_=most;least_=least;initialized_=true;
}
std::uint64_t ManagedUuid::most() const {
    if(!initialized_)throw DexError("AETHER_DEX_STATE","UUID must be initialized before use");
    return most_;
}
std::uint64_t ManagedUuid::least() const {(void)most();return least_;}
std::uint32_t ManagedUuid::hash() const {
    const auto bits=most()^least();return static_cast<std::uint32_t>(bits^(bits>>32));
}
bool ManagedUuid::equals(const ManagedUuid *other) const {
    const auto high=most(),low=least();return other && high==other->most() && low==other->least();
}
std::optional<Value> ManagedUuid::invoke(ManagedRuntime &runtime,std::string_view name,std::string_view signature,
    std::span<const Value> args,const ManagedUuid *other) {
    if(name=="<init>") {
        if(signature!="(JJ)V")return {};
        initialize(args[1].bits,args[2].bits);return Value::nothing();
    }
    const auto high=most(),low=least();
    if(name=="getMostSignificantBits" && signature=="()J")return Value::wide(high);
    if(name=="getLeastSignificantBits" && signature=="()J")return Value::wide(low);
    if(name=="version" && signature=="()I")return Value::word(static_cast<std::uint32_t>((high>>12)&15));
    if(name=="variant" && signature=="()I") {
        const auto value=!(low>>63)?0U:((low>>62)==2?2U:((low>>61)==6?6U:7U));
        return Value::word(value);
    }
    if(name=="hashCode" && signature=="()I")return Value::word(hash());
    if(name=="equals" && signature=="(Ljava/lang/Object;)Z")return Value::word(equals(other));
    if(name=="compareTo" && (signature=="(Ljava/util/UUID;)I" || signature=="(Ljava/lang/Object;)I")) {
        if(!args[1].bits)runtime.raise("Ljava/lang/NullPointerException;");
        if(!other)runtime.raise("Ljava/lang/ClassCastException;");
        const auto left_high=std::bit_cast<std::int64_t>(high),right_high=std::bit_cast<std::int64_t>(other->most());
        const auto left_low=std::bit_cast<std::int64_t>(low),right_low=std::bit_cast<std::int64_t>(other->least());
        const auto comparison=left_high!=right_high?((left_high>right_high)-(left_high<right_high)):
            ((left_low>right_low)-(left_low<right_low));
        return Value::word(static_cast<std::uint32_t>(comparison));
    }
    if(name=="toString" && signature=="()Ljava/lang/String;") {
        constexpr std::u16string_view digits=u"0123456789abcdef";
        std::array<char16_t,36> text{};std::size_t at=0;
        for(unsigned n=0;n<32;++n) {
            if(n==8 || n==12 || n==16 || n==20)text[at++]=u'-';
            const auto bits=n<16?high:low;
            text[at++]=digits[(bits>>((15-(n%16))*4))&15];
        }
        return Value::reference(runtime.new_string(std::u16string_view(text.data(),text.size())));
    }
    return {};
}
} // namespace aether::dex
