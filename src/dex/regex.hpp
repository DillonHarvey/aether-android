#pragma once
#include "aether/dex/runtime.hpp"
#include "aether/host/regex.hpp"
namespace aether::dex {
inline constexpr std::string_view pattern_type="Ljava/util/regex/Pattern;",matcher_type="Ljava/util/regex/Matcher;";
inline constexpr std::string_view pattern_syntax_type="Ljava/util/regex/PatternSyntaxException;";
inline constexpr std::size_t regex_pattern_reservation=256*1024,regex_matcher_reservation=512*1024;
struct ManagedPattern {ObjectId source=0;std::uint32_t flags=0;std::unique_ptr<host::RegexPattern> native;};
struct ManagedMatcher {ObjectId pattern=0,original=0,snapshot=0;bool busy=false,matched=false;std::unique_ptr<host::RegexMatcher> native;};
struct PatternSyntax {ObjectId source=0,description=0;std::int32_t index=-1;};
std::optional<HostClass> regex_class(std::string_view);
bool regex_method(std::string_view type,std::string_view name,std::string_view signature) noexcept;
std::u16string regex_quote(std::u16string_view);
std::uint32_t regex_flags(ManagedRuntime &,std::uint32_t flags);
}
