#include "integers.hpp"
#include <array>
#include <bit>

namespace aether::dex {
std::uint32_t parse_integer(ManagedRuntime &runtime,ObjectId text,std::int32_t radix) {
    if(!text)runtime.raise("Ljava/lang/NumberFormatException;",u"s == null");
    const auto value=runtime.string(text);
    if(radix<2 || radix>36 || value.empty())
        runtime.raise("Ljava/lang/NumberFormatException;",u"Invalid integer or radix");
    const bool negative=value.front()==u'-';
    const auto first=negative || value.front()==u'+'?std::size_t{1}:std::size_t{0};
    if(first==value.size())runtime.raise("Ljava/lang/NumberFormatException;",u"Integer sign has no digits");
    const auto base=static_cast<std::uint32_t>(radix);
    const std::uint32_t maximum=negative?0x80000000u:0x7fffffffu;
    std::uint32_t magnitude=0;
    for(auto at=first;at<value.size();++at) {
        const auto c=value[at];
        if(c>0x7f)
            throw DexError("AETHER_DEX_INTEGER_PARSE_UNSUPPORTED",
                "Integer.parseInt Unicode Character.digit is not implemented; ASCII digits only");
        const auto digit=c>=u'0' && c<=u'9'?static_cast<std::uint32_t>(c-u'0'):
            c>=u'a' && c<=u'z'?static_cast<std::uint32_t>(c-u'a'+10):
            c>=u'A' && c<=u'Z'?static_cast<std::uint32_t>(c-u'A'+10):0xffffffffu;
        if(digit>=base || magnitude>(maximum-digit)/base)
            runtime.raise("Ljava/lang/NumberFormatException;",u"Invalid or overflowing integer");
        magnitude=magnitude*base+digit;
    }
    return negative?std::uint32_t{0}-magnitude:magnitude;
}
std::optional<HostClass> integer_class(std::string_view descriptor) {
    static constexpr std::array<std::string_view, 2> interfaces{"Ljava/lang/Comparable;",
                                                                "Ljava/io/Serializable;"};
    if (descriptor == integer_type)
        return HostClass{"Ljava/lang/Number;", interfaces};
    return {};
}
void ManagedInteger::initialize(std::uint32_t bits) {
    if (initialized_)
        throw DexError("AETHER_DEX_STATE", "Integer constructor invoked twice");
    bits_ = bits;
    initialized_ = true;
}
std::uint32_t ManagedInteger::value() const {
    if (!initialized_)
        throw DexError("AETHER_DEX_STATE", "Integer must be initialized before use");
    return bits_;
}
std::optional<Value> ManagedInteger::invoke(ManagedRuntime &runtime, std::string_view name,
                                            std::string_view signature, std::span<const Value> args,
                                            const ManagedInteger *other) {
    if (name == "<init>") {
        if (signature != "(I)V")
            return {};
        initialize(static_cast<std::uint32_t>(args[1].bits));
        return Value::nothing();
    }
    const auto bits = value();
    const auto signed_value = std::bit_cast<std::int32_t>(bits);
    if ((name == "intValue" || name == "hashCode") && signature == "()I")
        return Value::word(bits);
    if (name == "longValue" && signature == "()J")
        return Value::wide(static_cast<std::uint64_t>(static_cast<std::int64_t>(signed_value)));
    if (name == "floatValue" && signature == "()F")
        return Value::word(std::bit_cast<std::uint32_t>(static_cast<float>(signed_value)));
    if (name == "doubleValue" && signature == "()D")
        return Value::wide(std::bit_cast<std::uint64_t>(static_cast<double>(signed_value)));
    if (name == "byteValue" && signature == "()B")
        return Value::word(static_cast<std::uint32_t>(
            static_cast<std::int32_t>(std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(bits)))));
    if (name == "shortValue" && signature == "()S")
        return Value::word(static_cast<std::uint32_t>(
            static_cast<std::int32_t>(std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(bits)))));
    if (name == "equals" && signature == "(Ljava/lang/Object;)Z")
        return Value::word(other && bits == other->value());
    if (name == "compareTo" &&
        (signature == "(Ljava/lang/Integer;)I" || signature == "(Ljava/lang/Object;)I")) {
        if (!args[1].bits)
            runtime.raise("Ljava/lang/NullPointerException;");
        if (!other)
            runtime.raise("Ljava/lang/ClassCastException;");
        const auto right = std::bit_cast<std::int32_t>(other->value());
        return Value::word(static_cast<std::uint32_t>((signed_value > right) - (signed_value < right)));
    }
    if (name == "toString" && signature == "()Ljava/lang/String;") {
        const auto decimal = std::to_string(signed_value);
        return Value::reference(runtime.new_string(std::u16string(decimal.begin(), decimal.end())));
    }
    return {};
}
} // namespace aether::dex
