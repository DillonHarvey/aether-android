// Compiled first-party DEX only. No external guest input or service grants.
#include "probes.hpp"
#include "aether/dex/runtime.hpp"
#include <algorithm>
#include <array>
#include <stdexcept>
#include <vector>
#include <utility>

namespace aether::security {
namespace {
using namespace dex;
void require(bool value,const char *text){if(!value)throw ProtocolError(text);}
enum Method : Index {Init,Execute,Get,TaskStatus,Cancel,TaskInit,Pre,Background,Post,Cancelled,Observe,BoxBoolean,UnboxBoolean};
DexImage image() {
    DexImage i;
    i.types={"Landroid/os/AsyncTask;","Lowned/LpacAsync;","Lowned/LpacObservation;","V","I",
        "Ljava/lang/Object;","[Ljava/lang/Object;","Ljava/util/concurrent/Executor;","Z","Landroid/os/AsyncTask$Status;","Ljava/lang/Boolean;"};
    i.prototypes={{3,{},"()V",0},{0,{7,6},"(Ljava/util/concurrent/Executor;[Ljava/lang/Object;)Landroid/os/AsyncTask;",2},
        {5,{},"()Ljava/lang/Object;",0},{9,{},"()Landroid/os/AsyncTask$Status;",0},{8,{8},"(Z)Z",1},
        {5,{6},"([Ljava/lang/Object;)Ljava/lang/Object;",1},{3,{5},"(Ljava/lang/Object;)V",1},{3,{4},"(I)V",1},{10,{8},"(Z)Ljava/lang/Boolean;",1},{8,{},"()Z",0}};
    i.methods={{0,0,"<init>"},{0,1,"executeOnExecutor"},{0,2,"get"},{0,3,"getStatus"},{0,4,"cancel"},
        {1,0,"<init>",1,true,true,Code{}},{1,0,"onPreExecute",4,true,false,Code{}},
        {1,5,"doInBackground",4,true,false,Code{}},{1,6,"onPostExecute",4,true,false,Code{}},
        {1,6,"onCancelled",4,true,false,Code{}},{2,7,"observe"},{10,8,"valueOf"},{10,9,"booleanValue"}};
    i.fields={{0,7,"THREAD_POOL_EXECUTOR"},{9,9,"RUNNING"},{9,9,"FINISHED"},{1,8,"boxedBoolean",9,true}};
    auto &ctor=*i.methods[TaskInit].code;ctor.registers=ctor.incoming=ctor.outgoing=1;ctor.units={0x1070,Init,0,0x000e};
    for(const auto [method,stage]:{std::pair{Pre,1},std::pair{Background,2},std::pair{Post,3},std::pair{Cancelled,4}}){
        auto &c=*i.methods[method].code;c.incoming=(method==Pre?1:2);c.registers=c.incoming+1;c.outgoing=1;
        c.units={static_cast<std::uint16_t>(0x0012|(stage<<12)),0x1071,Observe,0};
        if(method==Background)c.units.insert(c.units.end(),{0x1012,0x1071,BoxBoolean,0,0x000c,0x106e,UnboxBoolean,0,0x000a,0x006a,3,0x0012,0x0011});else c.units.push_back(0x000e);
    }
    Class task;task.type=1;task.superclass=0;task.flags=1;task.direct_methods={TaskInit};task.virtual_methods={Pre,Background,Post,Cancelled};task.static_fields={3};i.classes.push_back(task);
    return i;
}
struct Observations final : HostInterface {
    std::array<unsigned,4> calls{};
    std::array<ObjectId,4> threads{};
    std::array<int,4> priorities{};
    std::optional<HostClass> class_info(std::string_view type) const override {
        if(type=="Lowned/LpacObservation;")return HostClass{"Ljava/lang/Object;"};return {};
    }
    bool method_is_static(const DexImage &,Index method) const override {
        require(method==Observe,"Unexpected LPAC observation method");return true;
    }
    Value invoke(ManagedRuntime &r,Index method,std::span<const Value> args) override {
        require(method==Observe && args.size()==1 && args[0].kind==ValueKind::word && args[0].bits>=1 && args[0].bits<=4,
            "Invalid LPAC observation invocation");
        const auto at=static_cast<std::size_t>(args[0].bits-1);++calls[at];threads[at]=r.current_thread();
        priorities[at]=GetThreadPriority(GetCurrentThread());require(priorities[at]!=THREAD_PRIORITY_ERROR_RETURN,"Cannot observe LPAC thread priority");
        return Value::nothing();
    }
};
Value call(ManagedRuntime &r,ObjectId task,Method method,std::initializer_list<Value> tail={}){
    std::vector args{Value::reference(task)};args.insert(args.end(),tail);return r.invoke_virtual(method,args);
}
}
void run_async_task_probe(HANDLE writer,std::uint64_t session) {
    const auto original=GetThreadPriority(GetCurrentThread());require(original!=THREAD_PRIORITY_ERROR_RETURN,"Cannot query LPAC owner priority");
    std::array<std::uint64_t,16> proof{};
    {
        Observations observations;ManagedRuntime runtime(image());runtime.set_host_interface(&observations);
        const auto main=runtime.current_thread();const auto task=runtime.new_object("Lowned/LpacAsync;");runtime.retain(task);
        runtime.invoke(TaskInit,std::array{Value::reference(task)});
        const auto pool=runtime.get_static(0);
        require(call(runtime,task,Execute,{pool,Value::reference(0)})==Value::reference(task),"AsyncTask did not return its original receiver");
        require(observations.calls[0]==1 && observations.calls[1]==0,"AsyncTask background executed inline");
        require(call(runtime,task,Get)==Value::reference(0),"Unexpected AsyncTask result");
        require(observations.calls[1]==1 && observations.calls[2]==0 && call(runtime,task,TaskStatus)==runtime.get_static(1),"Future completion bypassed idle main finish");
        require(GetThreadPriority(GetCurrentThread())==original,"Background priority leaked to LPAC owner");
        require(runtime.get_static(3)==Value::word(1),"LPAC background Boolean boxing/unboxing failed");
        require(runtime.run_main_callback() && observations.calls[2]==1 && call(runtime,task,TaskStatus)==runtime.get_static(2),"Idle main finish absent");
        require(!runtime.run_main_callback(),"Duplicate successful AsyncTask completion");
        const auto cancelled=runtime.new_object("Lowned/LpacAsync;");runtime.retain(cancelled);runtime.invoke(TaskInit,std::array{Value::reference(cancelled)});
        require(call(runtime,cancelled,Cancel,{Value::word(0)})==Value::word(1),"Initial cancellation failed");
        require(call(runtime,cancelled,Cancel,{Value::word(0)})==Value::word(0),"Repeated cancellation won twice");
        require(runtime.run_main_callback() && observations.calls[3]==1 && call(runtime,cancelled,TaskStatus)==runtime.get_static(2),"Cancelled finish absent");
        require(!runtime.run_main_callback() && observations.calls[1]==1 && observations.calls[2]==1,"Cancellation duplicated background/post callback");
        require(observations.threads[0]==main && observations.threads[2]==main && observations.threads[3]==main && observations.threads[1]!=main,"AsyncTask logical Thread mismatch");
        require(observations.priorities[0]==original && observations.priorities[2]==original && observations.priorities[3]==original &&
            observations.priorities[1]==std::min(original,int(THREAD_PRIORITY_BELOW_NORMAL)),"AsyncTask real Win32 priority mismatch");
        runtime.close_main_callbacks();runtime.close_tasks();runtime.release(task);runtime.release(cancelled);runtime.collect();
        require(!runtime.has_main_callbacks() && !runtime.run_task() && runtime.metrics().pinned_references==0,"LPAC AsyncTask cleanup leaked owned work");
        proof={1,1,main,observations.threads[1],observations.calls[0],observations.calls[1],observations.calls[2],observations.calls[3],
            static_cast<std::uint64_t>(static_cast<std::int64_t>(original)),static_cast<std::uint64_t>(static_cast<std::int64_t>(observations.priorities[1])),
            1,1,1,runtime.metrics().pinned_references,runtime.metrics().instructions,runtime.get_static(3).bits};
        runtime.set_host_interface(nullptr);
    }
    require(GetThreadPriority(GetCurrentThread())==original,"LPAC owner priority not restored after teardown");
    Frame result{{Operation::finished,1,session,0,Status::ok},{}};
    for(const auto value:proof)append_u64(result.payload,value);
    result.header.payload_size=static_cast<std::uint32_t>(result.payload.size());write_pipe_frame(writer,result);
}
} // namespace aether::security
