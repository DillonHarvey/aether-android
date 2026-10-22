// Compiled first-party DEX and session metadata only; no caller code or paths.
#include "probes.hpp"
#include "aether/android/framework.hpp"
#include <array>
#include <string>

namespace aether::security {
namespace {
using namespace dex;
void checked(bool value,const char *message) { if(!value)throw ProtocolError(message); }
enum Method : Index { FileInit,DecodeInit,BufferInit,Read,Close,Pid,ReadManaged,
    AppInit,StartupAppInit,FactoryInit,StartupFactoryInit,Instantiate,StartupInstantiate,StartupRead };
DexImage stream_image() {
    DexImage i;
    i.types={"Ljava/io/FileInputStream;","Ljava/io/InputStreamReader;","Ljava/io/BufferedReader;",
        "Ljava/io/InputStream;","Ljava/io/Reader;","Ljava/lang/String;","V","I",
        "Landroid/os/Process;","Lowned/StreamProof;","Ljava/lang/Object;",
        "Landroid/app/Application;","Landroid/app/AppComponentFactory;","Ljava/lang/ClassLoader;",
        "Lowned/StartupApplication;","Lowned/StartupFactory;"};
    i.prototypes={{6,{5},"(Ljava/lang/String;)V",1},{6,{3,5},"(Ljava/io/InputStream;Ljava/lang/String;)V",2},
        {6,{4},"(Ljava/io/Reader;)V",1},{7,{},"()I",0},{6,{},"()V",0},{7,{4},"(Ljava/io/Reader;)I",1},
        {11,{13,5},"(Ljava/lang/ClassLoader;Ljava/lang/String;)Landroid/app/Application;",2}};
    i.methods={{0,0,"<init>"},{1,1,"<init>"},{2,2,"<init>"},{4,3,"read"},{4,4,"close"},
        {8,3,"myPid"},{9,5,"read",9,true,true,Code{}},
        {11,4,"<init>"},{14,4,"<init>",1,true,true,Code{}},{12,4,"<init>"},
        {15,4,"<init>",1,true,true,Code{}},{12,6,"instantiateApplication"},
        {15,6,"instantiateApplication",1,true,false,Code{}},{9,3,"startupRead",9,true,true,Code{}}};
    auto &c=*i.methods[ReadManaged].code;c.registers=2;c.incoming=1;c.outgoing=1;
    c.units={0x106e,Read,1,0x000a,0x000f};
    const auto digits=std::to_string(GetCurrentProcessId());
    i.strings={u"/proc/"+std::u16string(digits.begin(),digits.end())+u"/cmdline",u"iso-8859-1"};
    i.fields={{9,7,"startupCharacter",9,true}};
    auto &app=*i.methods[StartupAppInit].code;app.registers=2;app.incoming=app.outgoing=1;
    app.units={0x1070,AppInit,1,0x0071,StartupRead,0,0x000a,0x0067,0,0x000e};
    auto &factory=*i.methods[StartupFactoryInit].code;factory.registers=factory.incoming=factory.outgoing=1;
    factory.units={0x1070,FactoryInit,0,0x000e};
    auto &instantiate=*i.methods[StartupInstantiate].code;instantiate.registers=instantiate.incoming=instantiate.outgoing=3;
    instantiate.units={0x306f,Instantiate,0x0210,0x000c,0x0011};
    auto &startup=*i.methods[StartupRead].code;startup.registers=4;startup.outgoing=3;
    startup.units={0x0022,0,0x011a,0,0x2070,FileInit,0x0010,
        0x0122,1,0x021a,1,0x3070,DecodeInit,0x0201,
        0x0222,2,0x2070,BufferInit,0x0012,0x106e,Read,2,0x030a,
        0x106e,Close,2,0x030f};
    Class owner;owner.type=9;owner.superclass=10;owner.flags=1;owner.direct_methods={ReadManaged,StartupRead};owner.static_fields={0};i.classes.push_back(owner);
    Class application;application.type=14;application.superclass=11;application.flags=1;application.direct_methods={StartupAppInit};i.classes.push_back(application);
    Class component_factory;component_factory.type=15;component_factory.superclass=12;component_factory.flags=1;
    component_factory.direct_methods={StartupFactoryInit};component_factory.virtual_methods={StartupInstantiate};i.classes.push_back(component_factory);
    return i;
}
}
void run_stream_probe(HANDLE writer,std::uint64_t session) {
    constexpr char package[]="com.aether.streamproof";
    std::array<std::uint64_t,11> proof{};std::string observed;
    ManagedRuntime runtime(stream_image());
    {
        android::ActivitySession framework(runtime,package,{});
        framework.initialize_application("Lowned/StartupApplication;","Lowned/StartupFactory;");
        checked(framework.application()!=0 && runtime.get_static(0)==Value::word('c'),
            "Actual factory-provider Application constructor did not read self metadata");
        const auto pid=runtime.invoke(Pid,{});
        checked(pid==Value::word(GetCurrentProcessId()),"Stream probe process identity mismatch");
        const auto digits=std::to_string(pid.bits);
        const auto path=runtime.new_string(u"/proc/"+std::u16string(digits.begin(),digits.end())+u"/cmdline");
        runtime.retain(path);
        const auto input=runtime.new_object("Ljava/io/FileInputStream;");runtime.retain(input);
        runtime.invoke(FileInit,std::array{Value::reference(input),Value::reference(path)});
        const auto encoding=runtime.new_string(u"iso-8859-1");runtime.retain(encoding);
        const auto decoded=runtime.new_object("Ljava/io/InputStreamReader;");runtime.retain(decoded);
        runtime.invoke(DecodeInit,std::array{Value::reference(decoded),Value::reference(input),Value::reference(encoding)});
        const auto buffered=runtime.new_object("Ljava/io/BufferedReader;");runtime.retain(buffered);
        runtime.invoke(BufferInit,std::array{Value::reference(buffered),Value::reference(decoded)});
        bool eof=false;
        for(unsigned n=0;n<128;++n) {
            const auto value=runtime.invoke(ReadManaged,std::array{Value::reference(buffered)});
            checked(value.kind==ValueKind::word,"Reader did not return a word");
            if(value.bits==0xffffffffu){eof=true;break;}
            checked(value.bits<=255,"Unexpected metadata character");observed.push_back(static_cast<char>(value.bits));
        }
        checked(eof && observed==std::string(package,sizeof(package)),"Self metadata reader returned unexpected bytes");
        runtime.invoke_virtual(Close,std::array{Value::reference(buffered)});
        bool closed=false;
        try{(void)runtime.invoke(ReadManaged,std::array{Value::reference(buffered)});}
        catch(const JavaException &e){closed=runtime.assignable(e.object,"Ljava/io/IOException;");}
        checked(closed,"Reader did not refuse a read after close");
        runtime.invoke_virtual(Close,std::array{Value::reference(buffered)});
        const auto denied=runtime.new_object("Ljava/io/FileInputStream;");runtime.retain(denied);
        const auto other_path=runtime.new_string(u"/proc/0/cmdline");runtime.retain(other_path);
        bool other_refused=false;
        try{runtime.invoke(FileInit,std::array{Value::reference(denied),Value::reference(other_path)});}
        catch(const JavaException &e){other_refused=runtime.assignable(e.object,"Ljava/io/FileNotFoundException;");}
        checked(other_refused,"Nonself process metadata was not refused");
        for(const auto object:{path,input,encoding,decoded,buffered,denied,other_path})runtime.release(object);
        proof={2,1,pid.bits,observed.size(),1,1,1,0,0,1,runtime.get_static(0).bits};
    }
    runtime.close_main_callbacks();runtime.close_tasks();runtime.collect();
    checked(runtime.metrics().pinned_references==0,"Stream probe leaked managed pins");
    proof[7]=runtime.metrics().pinned_references;proof[8]=runtime.metrics().instructions;
    Frame result{{Operation::finished,1,session,0,Status::ok},{}};
    for(const auto value:proof)append_u64(result.payload,value);
    result.payload.insert(result.payload.end(),observed.begin(),observed.end());
    result.header.payload_size=static_cast<std::uint32_t>(result.payload.size());write_pipe_frame(writer,result);
}
} // namespace aether::security
