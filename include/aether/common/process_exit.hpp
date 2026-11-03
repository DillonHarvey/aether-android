#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
namespace aether {
// Captured guest architecture only, never host pointers or a fabricated ESR.
// Fixed storage permits terminal recording without allocation or guest work.
struct GuestSignalFault {
    std::uint32_t kind=0,subtype=0,access_bytes=0,signal_code=0;
    std::uint64_t pc=0,sp=0,address=0;
    std::array<std::uint64_t,31> registers{};
    bool has_memory_failure=false;
    std::uint32_t memory_kind=0,permission=0;
    std::uint64_t memory_address=0;
};
struct GuestInitializerContext {
    std::array<char,49> module{};
    std::uint64_t entry=0;
    bool finalizer=false;
};
// An actual full-frame abort service entry, not a synchronous CPU fault or a
// reconstructed call instruction. The register subset is x0, x1, x8 and x19.
struct GuestAbortContext {
    std::uint64_t pc=0,sp=0,lr=0;
    std::array<std::uint64_t,4> registers{};
    std::uint32_t logical_errno=0;
    bool has_errno=false;
};
// Latest actual owned-heap failure observation, not proof of an abort's cause.
struct GuestHeapFailure {
    enum class Reason : std::uint32_t { request_limit=1,object_limit,alignment,commit_limit,placement,
        host_metadata,mapping_rejected,host_mapping,mapping_other };
    enum class Stage : std::uint32_t { request=1,pool_record,backing,backing_record,allocation_record,mapping,resize };
    Reason reason=Reason::request_limit;
    Stage stage=Stage::request;
    std::uint64_t requested=0,alignment=0,new_backing=0,live_objects=0,live_backings=0;
    std::uint64_t live_requested=0,live_capacity=0,committed=0,guest_mapped=0;
};
// Trusted host control flow, deliberately not a Java or std::exception failure.
struct ProcessExit final {
    std::uint8_t status;
    std::uint8_t signal=0;
    std::shared_ptr<const std::string> abort_message{};
    std::optional<GuestSignalFault> fault{};
    std::optional<GuestInitializerContext> initializer{};
    std::optional<GuestAbortContext> abort_context{};
    std::optional<GuestHeapFailure> heap_failure{};
};
class ProcessState final {
  public:
    void request_exit(std::uint32_t value) noexcept {if(!exit_)exit_=static_cast<std::uint8_t>(value);}
    // Internal status is 128+signal; the cause remains distinct from an ordinary exit.
    void request_signal(std::uint8_t signal) noexcept {if(!exit_){exit_=static_cast<std::uint8_t>(128U+signal);signal_=signal;}}
    void request_signal(std::uint8_t signal,const GuestSignalFault &fault) noexcept {
        if(!exit_){fault_=fault;exit_=static_cast<std::uint8_t>(128U+signal);signal_=signal;}
    }
    // Diagnostic ownership only: preserve the innermost actual initializer
    // across adapters that reconstruct ProcessExit from terminal state.
    void retain_initializer_context(const GuestInitializerContext &context) noexcept {
        if(exit_ && !initializer_)initializer_=context;
    }
    // Publish after abort delivery/unwind. An inner actual abort wins over its
    // outer caller, and a different first terminal cause is never relabeled.
    void retain_abort_context(const GuestAbortContext &context) noexcept {
        if(exit_ && signal_ && *signal_==6 && !abort_context_)abort_context_=context;
    }
    void record_heap_failure(const GuestHeapFailure &failure) noexcept {heap_failure_=failure;}
    std::optional<std::uint8_t> exit_status() const noexcept {return exit_;}
    std::optional<std::uint8_t> termination_signal() const noexcept {return signal_;}
    std::shared_ptr<const std::string> abort_message() const noexcept {return abort_message_;}
    // Same single-owner discipline as the terminal cause. An engaged empty
    // string is a claimed message; construct completely before publishing it.
    void set_abort_message(std::string value) {
        if(abort_message_)return;
        auto message=std::make_shared<const std::string>(std::move(value));
        abort_message_=std::move(message);
    }
    // Copy immutable ownership through unwind without allocating on this path.
    void checkpoint() const {if(exit_)throw ProcessExit{*exit_,signal_.value_or(0),abort_message_,fault_,initializer_,abort_context_,heap_failure_};}
  private:
    std::optional<std::uint8_t> exit_,signal_;
    std::optional<GuestSignalFault> fault_;
    std::optional<GuestInitializerContext> initializer_;
    std::optional<GuestAbortContext> abort_context_;
    std::optional<GuestHeapFailure> heap_failure_;
    std::shared_ptr<const std::string> abort_message_;
};
}
