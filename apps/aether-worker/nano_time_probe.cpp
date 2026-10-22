// Compiled original DEX only; no caller-supplied code, clock or path.
#include "probes.hpp"
#include "aether/android/framework.hpp"
#include "aether/security/client.hpp"
namespace aether::security {
void run_nano_time_probe(HANDLE reader,HANDLE writer,std::uint64_t session,bool allowed) {
    dex::DexImage image;image.types={"Ljava/lang/System;","J","Lowned/NanoTimeProof;","Ljava/lang/Object;"};
    image.prototypes={{1,{},"()J",0}};
    image.methods={{0,0,"nanoTime"},{2,0,"read",9,true,true,dex::Code{}}};
    auto &code=*image.methods[1].code;code.registers=2;code.units={0x0071,0,0,0x000b,0x0010};
    dex::Class owner;owner.type=2;owner.superclass=3;owner.flags=1;owner.direct_methods={1};image.classes.push_back(owner);
    BrokerClient client(reader,writer,session);dex::ManagedRuntime runtime(std::move(image));
    android::ActivitySession activity(runtime,"owned.nano",{},&client);
    std::array<std::uint64_t,8> proof{1,GetCurrentProcessId(),allowed?1u:0u,0,0,0,0,0};
    if(allowed) {
        proof[3]=runtime.invoke(1,{}).bits;proof[4]=runtime.invoke(1,{}).bits;
        if(proof[4]<proof[3])throw ProtocolError("nanoTime probe regressed");
        proof[5]=activity.metrics().api_calls;
    } else {
        try {(void)runtime.invoke(1,{});throw ProtocolError("Denied nanoTime returned a timestamp");}
        catch(const dex::JavaException &error) {
            if(runtime.object_type(error.object)!="Ljava/lang/SecurityException;")throw;
            proof[5]=activity.metrics().api_calls;proof[6]=activity.metrics().denied_permissions;
        }
    }
    activity.close();runtime.collect();proof[7]=runtime.metrics().pinned_references;
    Frame result{{Operation::finished,client.next_sequence(),session,64,Status::ok},{}};
    for(const auto value:proof)append_u64(result.payload,value);
    write_pipe_frame(writer,result);
}
}
