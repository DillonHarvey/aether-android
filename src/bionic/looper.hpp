#pragma once
#include "aether/bionic/guest_posix.hpp"

namespace aether::bionic {
class NativeThreads;
class NativeDescriptors;
class NativeSignals;
// App-owned native event loop. Host execution remains single-owner; its TLS
// associations use trusted logical-thread incarnations, never TPIDR bit values.
class NativeLooper final {
  public:
    NativeLooper(a64::GuestMemory &, NativeThreads &, NativeDescriptors &, NativeSignals &,
                 const a64::AppContext &);
    ~NativeLooper();
    NativeLooper(const NativeLooper &) = delete;
    NativeLooper &operator=(const NativeLooper &) = delete;
    void runner(GuestPosixServices::PhdrRunner);
    a64::Fault invoke(std::string_view, a64::ServiceState &, bool full_frame, bool allow_deferred=false) noexcept;
    std::string_view rejection() const noexcept;
    bool switch_safe() const noexcept;
    // Host-only ownership of one exact source registration. The Looper must
    // outlive this move-only token; queue teardown precedes Looper destruction.
    class Attachment final {
      public:
        Attachment() noexcept = default;
        ~Attachment();
        Attachment(Attachment &&) noexcept;
        Attachment &operator=(Attachment &&) noexcept;
        Attachment(const Attachment &) = delete;
        Attachment &operator=(const Attachment &) = delete;
      private:
        friend class NativeLooper;
        struct State;
        std::shared_ptr<State> state_;
    };
    Attachment attach_source(std::uint64_t looper, int fd, std::int32_t ident,
                             a64::Address callback, a64::Address data);
    void detach_source(Attachment &) noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::bionic
