#pragma once
#include "aether/a64/guest_cpu.hpp"
namespace aether::bionic {
class NativeThreads;
class NativeSignals;
class NativeJumps {
  public:
    NativeJumps(a64::GuestMemory &m,NativeThreads &t,NativeSignals &s):memory_(m),threads_(t),signals_(s){}
    // sigsetjmp, setjmp, _setjmp, siglongjmp/longjmp/_longjmp.
    a64::Fault invoke(unsigned operation,a64::ServiceState &state,bool full_frame);
  private:
    a64::GuestMemory &memory_;
    NativeThreads &threads_;
    NativeSignals &signals_;
};
}
