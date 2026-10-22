// Compiled original DEX only. No caller-selected code, file name or path.
#include "probes.hpp"
#include "aether/android/framework.hpp"
#include "aether/security/client.hpp"
namespace aether::security {
namespace {
using namespace dex;
enum Method:Index {Open,GetLong,Edit,PutLong,Apply,Commit,GetBoolean,PutBoolean,Read};
DexImage image() {
    DexImage out;out.types={"Landroid/content/Context;","Ljava/lang/String;","I","Landroid/content/SharedPreferences;",
        "J","Landroid/content/SharedPreferences$Editor;","V","Z","Lowned/PreferencesProof;","Ljava/lang/Object;"};
    out.prototypes={{3,{1,2},"(Ljava/lang/String;I)Landroid/content/SharedPreferences;",2},
        {4,{1,4},"(Ljava/lang/String;J)J",3},{5,{},"()Landroid/content/SharedPreferences$Editor;",0},
        {5,{1,4},"(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;",3},{6,{},"()V",0},{7,{},"()Z",0},
        {7,{1,7},"(Ljava/lang/String;Z)Z",2},{5,{1,7},"(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;",2},
        {4,{3,1,4},"(Landroid/content/SharedPreferences;Ljava/lang/String;J)J",4}};
    out.methods={{0,0,"getSharedPreferences"},{3,1,"getLong"},{3,2,"edit"},{5,3,"putLong"},{5,4,"apply"},
        {5,5,"commit"},{3,6,"getBoolean"},{5,7,"putBoolean"},{8,8,"read",9,true,true,Code{}}};
    auto &body=*out.methods[Read].code;body.registers=body.incoming=body.outgoing=4;
    body.units={0x4072,GetLong,0x3210,0x000b,0x0010};Class owner;owner.type=8;owner.superclass=9;owner.flags=1;owner.direct_methods={Read};out.classes.push_back(owner);return out;
}
void checked(bool okay,const char *message){if(!okay)throw ProtocolError(message);}
}
void run_preferences_probe(HANDLE reader,HANDLE writer,std::uint64_t session,std::uint64_t action,std::uint64_t marker) {
    BrokerClient client(reader,writer,session);ManagedRuntime runtime(image());
    android::ActivitySession activity(runtime,"owned.preferences",{},nullptr,&client);activity.initialize_application();
    std::array<ObjectId,12> retained{};std::size_t count=0;
    auto keep=[&](ObjectId id){checked(count<retained.size(),"Preference proof root bound");runtime.retain(id);retained[count++]=id;return id;};
    std::array<std::uint64_t,8> proof{1,GetCurrentProcessId(),action,0,0,0,0,0};
    try {
        const auto name=keep(runtime.new_string(u"proof"));
        const auto store=keep(runtime.invoke(Open,std::array{Value::reference(activity.application()),Value::reference(name),Value::word(0)}).bits);
        checked(action!=2,"Denied preferences unexpectedly opened");
        const auto key=keep(runtime.new_string(u"marker")),flag=keep(runtime.new_string(u"flag"));
        if(action==0) {
            const auto first=keep(runtime.invoke(Edit,std::array{Value::reference(store)}).bits);
            (void)runtime.invoke(PutLong,std::array{Value::reference(first),Value::reference(key),Value::wide(marker)});
            (void)runtime.invoke(Apply,std::array{Value::reference(first)});
            const auto second=keep(runtime.invoke(Edit,std::array{Value::reference(store)}).bits);
            (void)runtime.invoke(PutBoolean,std::array{Value::reference(second),Value::reference(flag),Value::word(1)});
            checked(runtime.invoke(Commit,std::array{Value::reference(second)})==Value::word(1),"Preference commit did not confirm durability");
        }
        proof[3]=runtime.invoke(Read,std::array{Value::reference(store),Value::reference(key),Value::wide(UINT64_MAX)}).bits;
        proof[4]=runtime.invoke(GetBoolean,std::array{Value::reference(store),Value::reference(flag),Value::word(0)}).bits;
        checked(proof[3]!=UINT64_MAX && proof[4]==1,"Preference replay/default differs");proof[5]=1;
    } catch(const JavaException &error) {
        if(action!=2 || runtime.object_type(error.object)!="Ljava/lang/SecurityException;")throw;
        proof[5]=1;proof[6]=activity.metrics().denied_permissions;
    }
    activity.close();for(std::size_t n=0;n<count;++n)runtime.release(retained[n]);runtime.collect();proof[7]=runtime.metrics().pinned_references;
    Frame result{{Operation::finished,client.next_sequence(),session,64,Status::ok},{}};for(const auto value:proof)append_u64(result.payload,value);write_pipe_frame(writer,result);
}
}
