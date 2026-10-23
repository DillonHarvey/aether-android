#pragma once
#include "aether/a64/guest_cpu.hpp"
namespace aether::bionic {
class NativeDescriptors;
class NativeThreads;
class NativeSignals;
class NativePolling {
  public:
    NativePolling(a64::GuestMemory &memory,NativeDescriptors &files,NativeThreads &threads,NativeSignals &signals):memory_(memory),files_(files),threads_(threads),signals_(signals){}
    a64::Fault invoke(a64::Address error,std::array<std::uint64_t,31> &,bool full_frame,a64::ServiceState *frame=nullptr);
  private:
    a64::GuestMemory &memory_;NativeDescriptors &files_;NativeThreads &threads_;NativeSignals &signals_;
};
}
