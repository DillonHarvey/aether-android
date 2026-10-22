// Compiled first-party DEX only. No caller-selected code, entropy or paths.
#include "probes.hpp"
#include "aether/dex/runtime.hpp"
#include <array>
#include <string>

namespace aether::security {
namespace {
using namespace dex;
void checked(bool value,const char *message){if(!value)throw ProtocolError(message);}
enum Method : Index {Random,Text,Most,Least,Make};
DexImage uuid_image() {
    DexImage image;
    image.types={"Ljava/util/UUID;","Ljava/lang/String;","J","Lowned/UuidProof;","Ljava/lang/Object;"};
    image.prototypes={{0,{},"()Ljava/util/UUID;",0},{1,{},"()Ljava/lang/String;",0},{2,{},"()J",0}};
    image.methods={{0,0,"randomUUID"},{0,1,"toString"},{0,2,"getMostSignificantBits"},
        {0,2,"getLeastSignificantBits"},{3,0,"make",9,true,true,Code{}}};
    auto &code=*image.methods[Make].code;code.registers=1;code.outgoing=1;
    code.units={0x0071,Random,0,0x000c,0x106e,Text,0,0x0011};
    Class owner;owner.type=3;owner.superclass=4;owner.flags=1;owner.direct_methods={Make};
    image.classes.push_back(owner);return image;
}
}
void run_uuid_probe(HANDLE writer,std::uint64_t session) {
    ManagedRuntime runtime(uuid_image());
    std::array<ObjectId,2> objects{};
    for(auto &object:objects){object=runtime.invoke(Make,{}).bits;runtime.retain(object);}
    runtime.collect();
    std::array<std::uint64_t,9> proof{1,1,GetCurrentProcessId(),0,0};
    std::string observed;
    for(std::size_t n=0;n<objects.size();++n) {
        const std::array args{Value::reference(objects[n])};
        proof[5+2*n]=runtime.invoke(Most,args).bits;proof[6+2*n]=runtime.invoke(Least,args).bits;
        const auto text=runtime.invoke(Text,args).bits;
        const auto units=runtime.string(text);checked(units.size()==36,"UUID text length differs");
        for(const auto unit:units){checked(unit<128,"UUID text is not ASCII");observed.push_back(static_cast<char>(unit));}
    }
    for(const auto object:objects)runtime.release(object);
    runtime.collect();checked(runtime.metrics().pinned_references==0,"UUID proof leaked managed pins");
    proof[3]=runtime.metrics().pinned_references;proof[4]=runtime.metrics().instructions;
    Frame result{{Operation::finished,1,session,0,Status::ok},{}};
    for(const auto value:proof)append_u64(result.payload,value);
    result.payload.insert(result.payload.end(),observed.begin(),observed.end());
    result.header.payload_size=static_cast<std::uint32_t>(result.payload.size());write_pipe_frame(writer,result);
}
} // namespace aether::security
