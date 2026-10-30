#include "integers.hpp"
#include <array>
#include <bit>
#include "../../third_party/unicode/ucd16.hpp"

namespace aether::dex {
namespace {
// Reuse licensed data already shipped with Aether. The decimal flag is bit3
// in that data's classification contract. All BMP ranges are ten digits and
// match the Java-profile Unicode15.1 data (ADR0347); ASCII is stored separately.
constexpr std::uint16_t decimal_flag = 1U << 3;
static_assert([] {
    std::size_t count = 0;
    for (const auto &range : bionic::unicode16::properties)
        if (range.first <= 0xffff && (range.flags & decimal_flag)) {
            if (range.last > 0xffff || range.last - range.first != 9) return false;
            ++count;
        }
    return count == 36;
}());
std::uint32_t java_digit(char16_t c) noexcept {
    if (c >= u'0' && c <= u'9') return static_cast<std::uint32_t>(c - u'0');
    if (c >= u'a' && c <= u'z') return static_cast<std::uint32_t>(c - u'a' + 10);
    if (c >= u'A' && c <= u'Z') return static_cast<std::uint32_t>(c - u'A' + 10);
    if (c >= 0xff21 && c <= 0xff3a) return static_cast<std::uint32_t>(c - 0xff21 + 10);
    if (c >= 0xff41 && c <= 0xff5a) return static_cast<std::uint32_t>(c - 0xff41 + 10);
    std::size_t low = 0, high = bionic::unicode16::properties.size();
    while (low < high) {
        const auto middle = low + (high - low) / 2;
        const auto &range = bionic::unicode16::properties[middle];
        if (c < range.first) high = middle;
        else if (c > range.last) low = middle + 1;
        else return (range.flags & decimal_flag) ? static_cast<std::uint32_t>(c - range.first) : 0xffffffffu;
    }
    return 0xffffffffu;
}
std::uint64_t parse_signed(ManagedRuntime &runtime,ObjectId text,std::int32_t radix,unsigned width) {
    if(!text)runtime.raise("Ljava/lang/NumberFormatException;",u"s == null");
    const auto value=runtime.string(text);
    if(radix<2 || radix>36 || value.empty())
        runtime.raise("Ljava/lang/NumberFormatException;",u"Invalid integer or radix");
    const bool negative=value.front()==u'-';
    const auto first=negative || value.front()==u'+'?std::size_t{1}:std::size_t{0};
    if(first==value.size())runtime.raise("Ljava/lang/NumberFormatException;",u"Integer sign has no digits");
    const auto base=static_cast<std::uint64_t>(radix);
    const auto sign_bit = std::uint64_t{1} << (width - 1);
    const auto maximum = negative ? sign_bit : sign_bit - 1;
    std::uint64_t magnitude=0;
    for(auto at=first;at<value.size();++at) {
        const auto digit=java_digit(value[at]);
        if(digit>=base || magnitude>(maximum-digit)/base)
            runtime.raise("Ljava/lang/NumberFormatException;",u"Invalid or overflowing integer");
        magnitude=magnitude*base+digit;
    }
    return negative?std::uint64_t{0}-magnitude:magnitude;
}
}
std::uint32_t parse_integer(ManagedRuntime &runtime,ObjectId text,std::int32_t radix) {
    return static_cast<std::uint32_t>(parse_signed(runtime,text,radix,32));
}
std::uint64_t parse_long(ManagedRuntime &runtime,ObjectId text,std::int32_t radix) {
    return parse_signed(runtime,text,radix,64);
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
