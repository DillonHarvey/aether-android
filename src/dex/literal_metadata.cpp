#include "literal_metadata.hpp"
#include <array>

namespace aether::dex {
std::optional<HostClass> literal_metadata_class(std::string_view type) {
    // Declarations checked against AOSP libcore android15-release, ojluni/src/
    // main/java. Only nominal relationships are implemented; source links and
    // the original class-literal evidence are retained in the local report.
    static constexpr std::array<std::string_view,1> serial{"Ljava/io/Serializable;"};
    static constexpr std::array<std::string_view,1> comparable{"Ljava/lang/Comparable;"};
    static constexpr std::array<std::string_view,2> comparable_serial{
        "Ljava/lang/Comparable;","Ljava/io/Serializable;"};
    static constexpr std::array<std::string_view,2> cloneable_serial{
        "Ljava/lang/Cloneable;","Ljava/io/Serializable;"};
    static constexpr std::array<std::string_view,3> character{
        "Ljava/io/Serializable;","Ljava/lang/Comparable;","Ljava/lang/constant/Constable;"};
    static constexpr std::array<std::string_view,3> string_buffer{
        "Ljava/io/Serializable;","Ljava/lang/Comparable;","Ljava/lang/CharSequence;"};
    static constexpr std::array<std::string_view,2> abstract_builder{
        "Ljava/lang/Appendable;","Ljava/lang/CharSequence;"};
    static constexpr std::array<std::string_view,3> calendar{
        "Ljava/io/Serializable;","Ljava/lang/Cloneable;","Ljava/lang/Comparable;"};
    if(type=="Ljava/util/concurrent/atomic/AtomicIntegerArray;" ||
       type=="Ljava/util/concurrent/atomic/AtomicLongArray;" || type=="Ljava/net/URL;" ||
       type=="Ljava/net/InetAddress;" || type=="Ljava/util/Currency;")
        return HostClass{"Ljava/lang/Object;",serial,false,false,false,true};
    if(type=="Ljava/math/BigDecimal;" || type=="Ljava/math/BigInteger;")
        return HostClass{"Ljava/lang/Number;",comparable,false,false,false,true};
    if(type=="Ljava/lang/Character;")
        return HostClass{"Ljava/lang/Object;",character,false,false,false,true};
    if(type=="Ljava/lang/StringBuffer;")
        return HostClass{"Ljava/lang/AbstractStringBuilder;",string_buffer,false,false,false,true};
    if(type=="Ljava/lang/AbstractStringBuilder;")
        return HostClass{"Ljava/lang/Object;",abstract_builder,true,false,false,true};
    if(type=="Ljava/net/URI;")
        return HostClass{"Ljava/lang/Object;",comparable_serial,false,false,false,true};
    if(type=="Ljava/util/Calendar;")
        return HostClass{"Ljava/lang/Object;",calendar,true,false,false,true};
    if(type=="Ljava/util/GregorianCalendar;")
        return HostClass{"Ljava/util/Calendar;",{},false,false,false,true};
    if(type=="Ljava/util/Locale;")
        return HostClass{"Ljava/lang/Object;",cloneable_serial,false,false,false,true};
    if(type=="Ljava/lang/Appendable;" || type=="Ljava/lang/constant/Constable;")
        return HostClass{"Ljava/lang/Object;",{},true,true,false,true};
    return {};
}
}
