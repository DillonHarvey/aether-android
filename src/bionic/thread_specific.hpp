#pragma once
#include "aether/bionic/guest_posix.hpp"
#include <array>
#include <functional>

namespace aether::bionic {
class NativeThreadSpecific {
  public:
    explicit NativeThreadSpecific(a64::GuestMemory &memory):memory_(memory){}
    // pthread_key_create, pthread_key_delete, pthread_getspecific, pthread_setspecific.
    a64::Fault invoke(unsigned operation,std::uint32_t tid,a64::Address tls,
                      std::array<std::uint64_t,31> &) noexcept;
    void discard(std::uint32_t tid,a64::Address tls) noexcept;
    using Runner=std::function<GuestPosixServices::ThreadExecution(a64::Address,a64::Address,std::uint64_t)>;
    GuestPosixServices::ThreadExecution finalize(std::uint32_t tid,a64::Address tls,
                                                const Runner &,std::uint64_t budget);
    std::string_view rejection()const noexcept{return rejection_;}
  private:
    static constexpr std::size_t key_count=128,owner_count=33;
    struct Key {std::uint64_t generation=0; a64::Address destructor=0;bool live=false;};
    struct Value {std::uint64_t generation=0; a64::Address data=0;};
    enum class Phase {live,finalizing,terminal};
    struct Owner {
        std::uint32_t tid=0; a64::Address tls=0;bool occupied=false;Phase phase=Phase::live;
        std::array<Value,key_count> values{};
        a64::ExecutionResult terminal;
    };
    a64::GuestMemory &memory_;
    std::array<Key,key_count> keys_{};
    // Main, sixteen native slots, and sixteen managed owners. Reuse is explicit.
    std::array<Owner,owner_count> owners_{};
    std::string_view rejection_;
    std::size_t owner(std::uint32_t,a64::Address) noexcept;
    static std::size_t key(std::uint64_t) noexcept;
};
}
