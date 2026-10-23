#pragma once
#include "aether/a64/guest_cpu.hpp"
namespace aether::bionic {
struct NativeThreadOptions {
    static constexpr std::uint64_t minimum_stack_size=16384;
    std::uint64_t stack_size=0xf8000,guard_size=4096;
    bool detached=false;
};
enum class ThreadAttributeOperation {initialize,destroy,set_detach,get_detach,set_stack_size,get_stack_size,set_guard,get_guard,get_stack,get_current,detach};
class NativeThreads;
class NativeThreadAttributes {
  public:
    NativeThreadAttributes(a64::GuestMemory &memory,NativeThreads &threads):memory_(memory),threads_(threads){}
    unsigned read(a64::Address,NativeThreadOptions &) const noexcept;
    a64::Fault invoke(ThreadAttributeOperation,std::array<std::uint64_t,31> &,const a64::ServiceState *frame=nullptr) noexcept;
  private:
    a64::GuestMemory &memory_;NativeThreads &threads_;
};
}
