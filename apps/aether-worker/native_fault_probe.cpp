// Compiled original fault fixture only. No caller-selected code or input path.
#include "probes.hpp"
#include "aether/security/worker_progress.hpp"
namespace aether::security {
namespace {
using namespace dex;
using Burn = void (*)(volatile std::uint64_t *);
__declspec(noinline) void burn_stack(volatile std::uint64_t *);
Burn volatile recurse = &burn_stack;
__declspec(noinline) void burn_stack(volatile std::uint64_t *sink) {
    volatile std::uint8_t frame[4096];
    frame[0]=static_cast<std::uint8_t>(*sink);frame[4095]=1;
    *sink=*sink+1;
    const auto next=recurse;next(sink);
    *sink=*sink+frame[0]+frame[4095]; // Prevent tail-call elimination.
}
struct FaultNative final:NativeInterface {
    void load_library(ManagedRuntime &,std::u16string_view) override {throw ProtocolError("No probe library");}
    Value invoke(ManagedRuntime &,Index,std::span<const Value>) override {
        volatile std::uint64_t count=0;burn_stack(&count);return Value::nothing();
    }
};
struct FaultWorker final:ManagedWorkerEntry {
    void run(ManagedRuntime &)override {volatile std::uint64_t count=0;burn_stack(&count);}
    std::span<const Value> values()const noexcept override{return {};}
    std::size_t bytes()const noexcept override{return sizeof(*this);}
};
DexImage image() {
    DexImage out;out.types={"V","Lowned/NativeFaultProof;","Ljava/lang/Object;"};
    out.prototypes={{0,{},"()V",0}};
    out.methods={{1,0,"overflow",0x109,true,true,{}},{1,0,"enter",9,true,true,Code{}}};
    auto &code=*out.methods[1].code;code.units={0x0071,0,0,0x000e};
    Class owner;owner.type=1;owner.superclass=2;owner.flags=1;owner.direct_methods={0,1};out.classes.push_back(owner);return out;
}
}
void run_native_fault_probe(HANDLE owned_mapping,std::uint64_t action) {
    WorkerProgressWriter progress(owned_mapping);ScopedWorkerFaultCapture faults(progress);
    progress.stage(130,action?"native_fault_fiber":"native_fault_main");
    ManagedRuntime runtime(image());runtime.set_progress_sink(&progress);
    FaultNative native;runtime.set_native_interface(&native);
    if(!action)(void)runtime.invoke(1,{});
    else {
        (void)runtime.schedule_worker(std::make_unique<FaultWorker>());
        if(!runtime.run_task())throw ProtocolError("Native fault task did not run");
    }
    throw ProtocolError("Native overflow fixture unexpectedly returned");
}
}
