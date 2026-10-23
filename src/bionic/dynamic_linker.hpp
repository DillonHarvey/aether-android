#pragma once
#include "aether/bionic/dynamic_linker.hpp"
#include <array>

namespace aether::bionic {
class NativeThreads;
class NativeDynamicLinker {
  public:
    NativeDynamicLinker(a64::GuestMemory &memory,NativeThreads &threads,const a64::AppContext &app)
        :memory_(memory),threads_(threads),app_(app){}
    ~NativeDynamicLinker();
    NativeDynamicLinker(const NativeDynamicLinker&)=delete;
    NativeDynamicLinker &operator=(const NativeDynamicLinker&)=delete;
    void callbacks(DynamicLinkCallbacks value);
    // dlopen, dlsym, dlclose, dlerror respectively. Modules stay pinned after close.
    a64::Fault invoke(unsigned operation,std::array<std::uint64_t,31> &) noexcept;
    std::string_view rejection() const noexcept {return rejection_;}
  private:
    enum class Phase {free,loading,ready};
    struct Module {std::array<char,128> name{};std::uint32_t length=0,references=0;std::uint64_t handle=0;Phase phase=Phase::free;};
    struct Error {a64::Address tls=0;std::uint32_t tid=0;std::array<char,256> text{};bool pending=false;};
    static constexpr a64::Address errors_base=0x3f000000;
    static constexpr std::size_t errors_bytes=12288;
    a64::GuestMemory &memory_;NativeThreads &threads_;const a64::AppContext &app_;
    DynamicLinkCallbacks callbacks_;
    std::array<Module,32> modules_{};
    // Main, sixteen native slots, and sixteen managed TLS owners.
    std::array<Error,33> errors_{};
    bool errors_owned_=false;
    std::string_view rejection_;
    std::size_t error_slot();
    Module *module(std::uint64_t) noexcept;
    void discard_loading(std::uint64_t) noexcept;
};
}
