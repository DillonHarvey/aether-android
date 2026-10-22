#include "regex.hpp"
#include <array>
namespace aether::dex {
std::optional<HostClass> regex_class(std::string_view type) {
    static constexpr std::array<std::string_view,1> serial{"Ljava/io/Serializable;"},result{"Ljava/util/regex/MatchResult;"};
    if(type==pattern_type)return HostClass{"Ljava/lang/Object;",serial};
    if(type==matcher_type)return HostClass{"Ljava/lang/Object;",result};
    if(type=="Ljava/util/regex/MatchResult;")return HostClass{"Ljava/lang/Object;",{},true,true};
    if(type==pattern_syntax_type)return HostClass{"Ljava/lang/IllegalArgumentException;"};
    return {};
}
bool regex_method(std::string_view type,std::string_view name,std::string_view signature) noexcept {
    if(type==pattern_type)return (name=="pattern" && signature=="()Ljava/lang/String;") ||
        (name=="toString" && signature=="()Ljava/lang/String;") || (name=="flags" && signature=="()I") ||
        (name=="matcher" && signature=="(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;");
    const bool match_result=((name=="start" || name=="end") && (signature=="()I" || signature=="(I)I")) ||
        (name=="group" && (signature=="()Ljava/lang/String;" || signature=="(I)Ljava/lang/String;")) ||
        (name=="groupCount" && signature=="()I");
    if(type=="Ljava/util/regex/MatchResult;")return match_result;
    if(type==matcher_type)return match_result || ((name=="matches" || name=="find") && signature=="()Z") ||
        (name=="find" && signature=="(I)Z") || (name=="pattern" && signature=="()Ljava/util/regex/Pattern;") ||
        (name=="reset" && (signature=="()Ljava/util/regex/Matcher;" || signature=="(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;"));
    if(type==pattern_syntax_type)return ((name=="getPattern" || name=="getDescription") && signature=="()Ljava/lang/String;") || (name=="getIndex" && signature=="()I");
    return false;
}
std::u16string regex_quote(std::u16string_view text) {
    std::u16string result=u"\\Q";
    for(std::size_t n=0;n<text.size();++n) {
        if(text[n]==u'\\' && n+1<text.size() && text[n+1]==u'E'){result+=u"\\E\\\\E\\Q";++n;}
        else result.push_back(text[n]);
    }
    result+=u"\\E";return result;
}
std::uint32_t regex_flags(ManagedRuntime &runtime,std::uint32_t flags) {
    if(flags&~0x7fU)runtime.raise("Ljava/lang/IllegalArgumentException;");
    return flags&0x2fU;
}
}
