// Compiled first-party DEX only; no caller-selected code or path.
#include "probes.hpp"
#include "aether/security/worker_progress.hpp"
namespace aether::security {
void run_progress_probe(HANDLE owned_mapping) {
    WorkerProgressWriter progress(owned_mapping);
    progress.stage(120,"compiled_probe_start");
    dex::DexImage image;
    image.types={"V","Lowned/StartupProgressProof;","Ljava/lang/Object;"};
    image.prototypes={{0,{},"()V",0}};
    image.methods={{1,0,"countdown",9,true,true,dex::Code{}}};
    auto &code=*image.methods[0].code;code.registers=2;
    code.units={0x0013,0x0800,0x1112,0x10b1,0x003c,0xffff,0x000e};
    dex::Class owner;owner.type=1;owner.superclass=2;owner.flags=1;owner.direct_methods={0};
    image.classes.push_back(owner);
    dex::ManagedRuntime runtime(std::move(image));runtime.set_progress_sink(&progress);
    (void)runtime.invoke(0,{});
    if(runtime.metrics().instructions<4096)throw ProtocolError("Progress probe did not execute real DEX");
    progress.stage(121,"compiled_probe_wait");
    Sleep(INFINITE); // Parent's unchanged hard deadline must terminate this fixture.
}
}
