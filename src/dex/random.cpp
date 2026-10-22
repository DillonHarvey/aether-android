#include "random.hpp"
#include <bit>
#include <array>
namespace aether::dex {
namespace {constexpr std::uint64_t multiplier=0x5deece66dULL,mask=(1ULL<<48)-1;}
std::optional<HostClass> random_class(std::string_view type) {
    static constexpr std::array<std::string_view,1> interfaces{"Ljava/io/Serializable;"};
    if(type==random_type)return HostClass{"Ljava/lang/Object;",interfaces};return {};
}
bool random_method(std::string_view name,std::string_view signature) noexcept {
    return (name=="<init>" && (signature=="()V" || signature=="(J)V")) ||
        (name=="setSeed" && signature=="(J)V") || (name=="next" && signature=="(I)I") ||
        (name=="nextInt" && (signature=="()I" || signature=="(I)I")) ||
        (name=="nextLong" && signature=="()J") || (name=="nextBoolean" && signature=="()Z") ||
        (name=="nextFloat" && signature=="()F") || (name=="nextDouble" && signature=="()D") ||
        (name=="nextBytes" && signature=="([B)V");
}
void ManagedRandom::check() const {if(!initialized_)throw DexError("AETHER_DEX_STATE","Random must be initialized before use");}
void ManagedRandom::initialize(std::uint64_t seed,bool subclass) {
    if(initialized_)throw DexError("AETHER_DEX_STATE","Random constructor invoked twice");
    initialized_=true;state_=subclass?0:(seed^multiplier)&mask;
}
void ManagedRandom::set_seed(std::uint64_t seed){check();state_=(seed^multiplier)&mask;}
std::uint32_t ManagedRandom::next(std::uint32_t bits) {
    check();state_=(state_*multiplier+11)&mask;
    return static_cast<std::uint32_t>(state_>>((48U-bits)&63U));
}
std::optional<Value> ManagedRandom::invoke(ManagedRuntime &runtime,std::string_view name,std::string_view signature,
    std::span<const Value> args,const std::function<std::uint32_t(unsigned)> &next_bits) {
    check();
    if(name=="setSeed" && signature=="(J)V"){set_seed(args[1].bits);return Value::nothing();}
    if(name=="next" && signature=="(I)I")return Value::word(next(static_cast<std::uint32_t>(args[1].bits)));
    if(name=="nextInt" && signature=="()I")return Value::word(next_bits(32));
    if(name=="nextInt" && signature=="(I)I") {
        const auto bound=static_cast<std::uint32_t>(args[1].bits);
        if(!bound || bound>0x7fffffffU)runtime.raise("Ljava/lang/IllegalArgumentException;",u"bound must be positive");
        if(!(bound&(bound-1)))return Value::word(static_cast<std::uint32_t>((static_cast<std::uint64_t>(bound)*next_bits(31))>>31));
        for(;;){const auto bits=next_bits(31),value=bits%bound;if(bits-value+bound-1<=0x7fffffffU)return Value::word(value);}
    }
    if(name=="nextLong" && signature=="()J") {
        const auto high=next_bits(32),low=next_bits(32);
        return Value::wide((static_cast<std::uint64_t>(high)<<32)+static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int32_t>(low))));
    }
    if(name=="nextBoolean" && signature=="()Z")return Value::word(next_bits(1)!=0);
    if(name=="nextFloat" && signature=="()F")return Value::word(std::bit_cast<std::uint32_t>(static_cast<float>(next_bits(24))*0x1p-24f));
    if(name=="nextDouble" && signature=="()D") {
        const auto high=next_bits(26),low=next_bits(27);
        return Value::wide(std::bit_cast<std::uint64_t>(static_cast<double>((static_cast<std::uint64_t>(high)<<27)+low)*0x1p-53));
    }
    return {};
}
}
