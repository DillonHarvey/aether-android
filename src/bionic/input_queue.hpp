#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "aether/android/native_activity.hpp"

namespace aether::android { struct NativeActivityPointerInput; }
namespace aether::bionic {
class NativeDescriptors;
class NativeLooper;
// One app-owned native Activity queue. The Looper and descriptor registry
// outlive this adapter; shutdown follows retained task-stack unwinding.
class NativeInputQueues final {
  public:
    NativeInputQueues(a64::GuestMemory &, NativeDescriptors &, NativeLooper &, const a64::AppContext &);
    ~NativeInputQueues();
    NativeInputQueues(const NativeInputQueues &) = delete;
    NativeInputQueues &operator=(const NativeInputQueues &) = delete;
    std::uint64_t create();
    std::uint64_t current() const noexcept;
    void retire(std::uint64_t);
    void shutdown() noexcept;
    bool enqueue(std::uint64_t, const android::NativeActivityPointerInput &);
    bool enqueue_key(std::uint64_t, const android::NativeActivityKeyInput &);
    // Finished outcomes stay in ingress order, including handled=true. Peeking
    // does not retire storage; commit follows successful idle-main handoff.
    std::optional<android::NativeActivityInputCompletion> peek_input_completion() const;
    bool commit_input_completion(std::uint64_t queue, std::uint64_t event) noexcept;
    a64::Fault invoke(std::string_view, a64::ServiceState &, bool full_frame) noexcept;
    std::string_view rejection() const noexcept;
  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::bionic
