// Compiled first-party DEX only: no caller-selected regex, input, APK or paths.
#include "probes.hpp"
#include "aether/dex/runtime.hpp"
#include "aether/host/regex.hpp"
#include <array>
#include <string>
namespace aether::security {
namespace {
using namespace dex;
void checked(bool value,const char *message){if(!value)throw ProtocolError(message);}
enum Method:Index{Compile,Matcher,Matches,Find,Start,End,Group,Count,Reset,Run};
DexImage regex_image() {
    DexImage image;
    image.types={"Ljava/util/regex/Pattern;","Ljava/lang/String;","Ljava/util/regex/Matcher;",
        "Ljava/lang/CharSequence;","Z","I","Lowned/RegexProof;","Ljava/lang/Object;"};
    image.prototypes={{0,{1},"(Ljava/lang/String;)Ljava/util/regex/Pattern;",1},
        {2,{3},"(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;",1},
        {4,{},"()Z",0},{5,{},"()I",0},{1,{5},"(I)Ljava/lang/String;",1},
        {4,{1,1},"(Ljava/lang/String;Ljava/lang/String;)Z",2}};
    image.methods={{0,0,"compile"},{0,1,"matcher"},{2,2,"matches"},{2,2,"find"},
        {2,3,"start"},{2,3,"end"},{2,4,"group"},{2,3,"groupCount"},{2,1,"reset"},
        {6,5,"run",9,true,true,Code{}}};
    auto &code=*image.methods[Run].code;code.registers=4;code.incoming=2;code.outgoing=2;
    code.units={0x1071,Compile,2,0x000c,0x206e,Matcher,0x0030,0x000c,
        0x106e,Matches,0,0x000a,0x000f};
    Class owner;owner.type=6;owner.superclass=7;owner.flags=1;owner.direct_methods={Run};
    image.classes.push_back(owner);return image;
}
}
void run_regex_probe(HANDLE writer,std::uint64_t session) {
    ManagedRuntime runtime(regex_image());
    std::u16string expression=u"(\\p{L}+)";expression.push_back(0);expression+=u"(\\d+)";
    std::u16string text=u"\u03a9\u00e9";text.push_back(0);text+=u"42";
    const auto source=runtime.new_string(expression);runtime.retain(source);
    const auto input=runtime.new_string(text);runtime.retain(input);
    const auto extra=runtime.new_string(text+u"!");runtime.retain(extra);
    checked(runtime.invoke(Run,std::array{Value::reference(source),Value::reference(input)})==Value::word(1),
        "Compiled DEX regex full match failed");
    checked(runtime.invoke(Run,std::array{Value::reference(source),Value::reference(extra)})==Value::word(0),
        "Compiled DEX regex full match ignored trailing text");
    const auto pattern=runtime.invoke(Compile,std::array{Value::reference(source)}).bits;runtime.retain(pattern);
    const auto matcher=runtime.invoke_virtual(Matcher,std::array{Value::reference(pattern),Value::reference(extra)}).bits;
    runtime.retain(matcher);runtime.collect();
    const std::array receiver{Value::reference(matcher)};
    checked(runtime.invoke_virtual(Find,receiver)==Value::word(1),"Regex find failed");
    const auto start=runtime.invoke_virtual(Start,receiver).bits,end=runtime.invoke_virtual(End,receiver).bits;
    const auto count=runtime.invoke_virtual(Count,receiver).bits;
    checked(start==0 && end==5 && count==2,"Regex UTF16 capture positions differ");
    const auto first=runtime.invoke_virtual(Group,std::array{Value::reference(matcher),Value::word(1)}).bits;
    checked(runtime.string(first)==u"\u03a9\u00e9","Unicode regex capture differs");
    const auto second=runtime.invoke_virtual(Group,std::array{Value::reference(matcher),Value::word(2)}).bits;
    checked(runtime.string(second)==u"42","Embedded NUL regex capture differs");
    checked(runtime.invoke_virtual(Reset,std::array{Value::reference(matcher),Value::reference(input)})==Value::reference(matcher),
        "Regex reset identity differs");
    checked(runtime.invoke_virtual(Matches,receiver)==Value::word(1),"Regex reset full match failed");
    for(const auto id:{matcher,pattern,extra,input,source})runtime.release(id);
    runtime.collect();
    const auto backend=host::regex_backend_info();
    checked(runtime.metrics().pinned_references==0 && backend.live_patterns==0 && backend.live_matchers==0,
        "Regex probe retained native handles or managed pins");
    std::array<std::uint64_t,15> proof{1,1,GetCurrentProcessId(),runtime.metrics().pinned_references,
        runtime.metrics().instructions,count,start,end,1,backend.live_patterns,backend.live_matchers,
        backend.version[0],backend.version[1],backend.version[2],backend.version[3]};
    Frame result{{Operation::finished,1,session,0,Status::ok},{}};
    for(const auto value:proof)append_u64(result.payload,value);
    result.header.payload_size=static_cast<std::uint32_t>(result.payload.size());write_pipe_frame(writer,result);
}
}
