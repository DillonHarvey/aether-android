#pragma once
#include "aether/dex/image.hpp"
#include "aether/dex/scheduler.hpp"
#include "aether/host/file_service.hpp"
#include "aether/host/thread_priority.hpp"
#include "aether/common/process_exit.hpp"
#include "aether/common/thread_exit.hpp"
#include <memory>
#include <functional>

namespace aether::dex {
class ClassSource;
using ObjectId = std::uint64_t;
enum class ValueKind { empty, word, wide, reference, void_value, wide_tail };
struct Value {
    ValueKind kind = ValueKind::empty;
    std::uint64_t bits = 0;
    static Value word(std::uint32_t bits) noexcept { return {ValueKind::word, bits}; }
    static Value wide(std::uint64_t bits) noexcept { return {ValueKind::wide, bits}; }
    static Value reference(ObjectId id) noexcept { return {ValueKind::reference, id}; }
    static Value nothing() noexcept { return {ValueKind::void_value, 0}; }
    bool operator==(const Value &) const = default;
};
// Immutable provider-owned data attached to a managed object. The interpreter
// accounts its storage and traces its Values without knowing Android types.
class HostObjectState {
  public:
    virtual ~HostObjectState() = default;
    virtual std::span<const Value> values() const noexcept = 0;
    virtual std::size_t bytes() const noexcept = 0;
};
class JavaException final : public std::exception {
  public:
    explicit JavaException(ObjectId object) : object(object) {}
    const char *what() const noexcept override { return "Pending managed exception"; }
    const ObjectId object;
};
enum class RuntimeProgressStage {managed_enter,managed_sample,class_load_begin,class_load_end,core_enter,core_exit,native_enter,native_exit};
struct RuntimeProgress {
    RuntimeProgressStage stage;
    Index method=no_index;
    std::uint32_t pc=0;
    std::uint64_t instructions=0;
    std::string_view owner,name;
};
// Trusted non-owning observer. Labels are borrowed only for this synchronous
// report. Implementations must not allocate, reenter, invoke providers/guest
// APIs, retain label pointers, or alter execution budgets and deadlines.
class RuntimeProgressSink {
  public:
    virtual ~RuntimeProgressSink()=default;
    virtual void report(const RuntimeProgress &) noexcept=0;
    // Optional diagnostic setup on the actual executing native stack, before
    // guest work. False aborts setup; it never changes execution limits.
    virtual bool prepare_native_stack() noexcept { return true; }
};
class ManagedRuntime;
// Trusted descriptor adapter with fixed, nonreentrant byte accounting. Methods
// never call managed code; the runtime owns exactly-once close, including GC.
class HostInputStream {
  public:
    virtual ~HostInputStream() = default;
    virtual host::FileResult read(std::span<std::uint8_t>) noexcept = 0;
    virtual host::FileResult close() noexcept = 0;
    virtual std::size_t bytes() const noexcept = 0;
};
// Trusted host worker code, never an arbitrary APK callback. run must reach
// audited checkpoints/parks and must not suppress host cancellation. Metadata
// hooks/destruction are nonreentrant: fixed bytes and stable root span/storage
// until release;
// the Values themselves may change on the single owned execution thread.
// Host-local managed references crossing park/checkpoint boundaries must appear
// in values() or retained pins; ignored nested invocation results are discarded.
class ManagedWorkerEntry {
  public:
    virtual ~ManagedWorkerEntry() = default;
    virtual void run(ManagedRuntime &) = 0;
    virtual std::span<const Value> values() const noexcept = 0;
    virtual std::size_t bytes() const noexcept = 0;
};
// Trusted SDK/host main callback, never an APK-supplied native callable.
// Metadata/destruction are nonreentrant; root storage/count and byte charge stay
// fixed until destruction. Root Values may change on the one owned thread.
class ManagedMainEntry {
  public:
    virtual ~ManagedMainEntry() = default;
    virtual void run(ManagedRuntime &) = 0;
    virtual std::span<const Value> values() const noexcept = 0;
    virtual std::size_t bytes() const noexcept = 0;
};
struct HostClass {
    std::string_view superclass;
    std::span<const std::string_view> interfaces;
    bool is_abstract = false, is_interface = false;
    // Opt in only when this provider class inherits Object equality/hash unchanged.
    bool identity_object_methods = false;
    // Explicit provenance for Class.getClassLoader; class_info alone is partial.
    bool bootstrap_class = false;
};
struct HostField {
    std::string owner, name, type;
    std::uint32_t flags = 0;
    bool declaring_class_public = false;
};
struct HostMethod {
    std::string owner, name, return_type;
    std::vector<std::string> parameters;
    std::uint32_t flags = 1;
};
// Metadata is owned by the provider and stays valid until it is detached.
// An attached provider implements a bounded API surface, not arbitrary host calls.
class HostInterface {
  public:
    virtual ~HostInterface() = default;
    // Synchronous retained diagnostic output. No managed calls/reentry; false
    // reports an output failure to PrintStream.checkError, never silent success.
    virtual bool write_standard_output(ManagedRuntime &, bool, std::u16string_view) { return false; }
    virtual std::unique_ptr<HostInputStream> open_input_stream(ManagedRuntime &,std::u16string_view) {
        throw DexError("AETHER_DEX_INPUT_STREAM_UNSUPPORTED","No input stream provider is attached for this path");
    }
    virtual std::optional<HostClass> class_info(std::string_view descriptor) const = 0;
    virtual bool method_is_static(const DexImage &, Index method) const = 0;
    // nullopt is unknown/partial metadata, never proof that a method is absent.
    virtual std::optional<HostMethod> public_method(std::string_view, std::string_view,
                                                   std::span<const std::string>) const { return {}; }
    virtual Value invoke_reflected(ManagedRuntime &, const HostMethod &, std::span<const Value>) {
        throw DexError("AETHER_DEX_API_UNSUPPORTED", "Reflected provider invocation is not implemented");
    }

    // Exact declarations only; nullopt is partial/unknown metadata, not absence.
    virtual std::optional<HostField> declared_field(std::string_view, std::string_view) const { return {}; }
    virtual std::optional<HostField> public_field(std::string_view owner, std::string_view name) const {
        return declared_field(owner, name);
    }
    virtual Value read_reflected_field(ManagedRuntime &, const HostField &, ObjectId) {
        throw DexError("AETHER_DEX_FIELD_UNSUPPORTED", "Reflected provider field read is not implemented");
    }
    // Exact provider-owned, read-only static fields. Unknown fields stay unsupported.
    virtual std::optional<Value> static_field(ManagedRuntime &, Index) { return {}; }
    virtual Value invoke(ManagedRuntime &, Index method, std::span<const Value> arguments) = 0;
};
class NativeInterface {
  public:
    virtual ~NativeInterface() = default;
    virtual bool supports_background() const noexcept {return false;}
    virtual std::uint64_t capture_signal_mask(ManagedRuntime &) {return 0;}
    // Fallible, same-context orderly termination; never called by a destructor.
    virtual void finish_logical_thread(ManagedRuntime &) {}
    // Nonexecuting retirement, including cancellation and failed contexts.
    virtual void discard_logical_thread(ObjectId) noexcept {}
    virtual void load_library(ManagedRuntime &, std::u16string_view name) = 0;
    virtual Value invoke(ManagedRuntime &, Index method, std::span<const Value> arguments) = 0;
};
struct RuntimeLimits {
    std::uint64_t instructions = 1'000'000;
    std::size_t frames = 64, objects = 8192, heap_bytes = 16 * 1024 * 1024, array_length = 65536;
};
struct RuntimeMetrics {
    std::uint64_t instructions = 0, managed_calls = 0, native_calls = 0, core_calls = 0;
    std::uint64_t allocations = 0, collections = 0, reclaimed = 0, exceptions = 0;
    std::size_t maximum_frames = 0, live_objects = 0, heap_bytes = 0, pinned_references = 0;
};
// Original bounded interpreter with one Windows owner and a shared managed heap.
// Loading does not authorize code execution.
// Caller-owned object references must be retained across allocations/collection.
class ManagedRuntime {
  public:
    explicit ManagedRuntime(DexImage image, RuntimeLimits limits = {});
    explicit ManagedRuntime(std::shared_ptr<ClassSource> source, RuntimeLimits limits = {});
    ~ManagedRuntime();
    ManagedRuntime(const ManagedRuntime &) = delete;
    ManagedRuntime &operator=(const ManagedRuntime &) = delete;
    void set_progress_sink(RuntimeProgressSink *sink);
    void set_native_interface(NativeInterface *interface);
    void set_host_interface(HostInterface *interface);
    const DexImage &image() const noexcept;
    // Resolve definitions through the demand loader. image() is a passive view
    // of already linked data; IDs and element references survive later loads.
    const Class *class_definition(std::string_view descriptor) const;
    Index resolve_method(std::string_view owner, std::string_view name, std::string_view signature) const;
    const RuntimeMetrics &metrics() const noexcept;
    Value invoke(Index method, std::span<const Value> arguments = {});
    Value invoke_virtual(Index method, std::span<const Value> arguments);
    // Trusted host routing to genuine managed virtual declarations/defaults.
    // Arguments exclude the receiver. Does not invent SDK method IDs or relax
    // provider/native/initialization/monitor barriers.
    Value invoke_virtual_named(ObjectId receiver, std::string_view name, std::string_view signature,
                               std::span<const Value> arguments = {});
    Value invoke_static(std::string_view owner, std::string_view name, std::string_view signature,
                        std::span<const Value> arguments = {});
    Index lookup(std::string_view owner, std::string_view name, std::string_view signature,
                 bool is_static) const;
    void initialize(std::string_view descriptor);
    ObjectId new_object(std::string_view descriptor);
    ObjectId new_string(std::u16string_view value);
    // Trusted host construction of an ordinary initialized HashSet of strings.
    ObjectId new_string_set(std::span<const std::optional<std::u16string>> values);
    ObjectId class_object(std::string_view descriptor);
    // Canonical identity of this runtime's held, closed managed class space.
    ObjectId class_loader();
    // Stable identity of the current logical thread, including the original
    // guest Thread receiver after start(), on one Windows owner.
    // Synchronous owned native-worker boundary. Independent logical state and
    // GC roots share heap/frame/instruction quotas; scheduler suspension is barred.
    void run_native_thread(const std::function<void()> &entry,const host::PriorityService &priority={});
    // Trusted once-only cleanup on the current background/native context. Keeps
    // its first exit value and remaining budget; callbacks cannot reset either.
    void run_thread_finalizers(const std::function<void()> &entry);
    // Trusted nonexecuting accounting also works after an owned exit latch.
    // Exact debit to zero succeeds; overrun fails without modifying allowances.
    std::uint64_t thread_instruction_budget() const;
    void charge_thread_instructions(std::uint64_t instructions);
    // One owned background/native logical thread; root main exit is unsupported.
    [[noreturn]] void exit_current_thread(std::uint64_t value);
    host::PriorityResult thread_priority(std::optional<std::int32_t> nice={});
    int thread_priority_baseline();
    void bind_process_state(std::shared_ptr<ProcessState> state);
    std::shared_ptr<ProcessState> process_state() const;
    bool detach_native_thread();
    // Trusted runtime introspection. Hidden-API enforcement is Disabled;
    // exemption snapshots never grant Java access or supply missing APIs.
    bool hidden_api_access_allowed(std::u16string_view member) const;
    bool hidden_api_exempt(std::u16string_view member) const;
    bool thread_alive(ObjectId thread) const;
    std::uint64_t thread_initial_signal_mask(ObjectId thread) const;
    ObjectId current_thread();
    ObjectId main_thread();
    bool is_main_thread() const;
    bool has_background_execution() const;
    std::uint64_t logical_thread_cpu_millis(std::uint64_t authorized_seconds, std::uint64_t authorized_nanos) const;
    // Host-managed task boundary; Android/Java executor submission is not enabled.
    // All tasks share heap/statics. Arguments/results/exceptions stay GC roots
    // until release_task. Pumping is nonblocking and main-context-only.
    using TaskId = Scheduler::TaskId;
    TaskId schedule(Index method, std::span<const Value> arguments = {}, bool virtual_dispatch = false);
    // Audited host admission from any owned logical context, including a running
    // task/provider. Never executes inline. Retained IDs still require explicit
    // external-main observation/release; this does not enable Java executors.
    TaskId schedule_owned(Index method, std::span<const Value> arguments = {}, bool virtual_dispatch = false);
    // Retained persistent host entry in the same bounded task/context budget.
    // Only its empty managed stack may park/checkpoint; no provider barrier is relaxed.
    // Each park attempt/checkpoint consumes one shared batch unit, even an
    // immediately satisfied park. Checkpoint yields; park preserves permit semantics.
    TaskId schedule_worker(std::unique_ptr<ManagedWorkerEntry> entry);
    void park_worker(std::optional<std::chrono::steady_clock::time_point> deadline = {});
    void unpark_worker(TaskId task);
    void worker_checkpoint();
    bool run_task();
    std::optional<std::chrono::steady_clock::time_point> next_task_deadline() const;
    Scheduler::State task_state(TaskId task) const;
    Value task_result(TaskId task) const;
    std::exception_ptr task_exception(TaskId task) const;
    void cancel_task(TaskId task);
    void release_task(TaskId task);
    void close_tasks();
    // FIFO: at most 16 queued entries, 256 argument Values each, plus one in flight.
    // Posting never invokes guest code. Delivery requires idle external main,
    // never a safepoint. A queued/reposted batch shares the instruction allowance,
    // including one unit per dispatch. Close drops queued roots and forbids posts.
    void post_main(Index method, std::span<const Value> arguments = {}, bool virtual_dispatch = false);
    // Shares the same bounded queue, roots, quota and idle-main delivery rules.
    void post_main(std::unique_ptr<ManagedMainEntry> entry);
    bool run_main_callback();
    bool has_main_callbacks() const;
    void close_main_callbacks();
    ObjectId new_array(std::string_view descriptor, std::int32_t length);
    std::string_view object_type(ObjectId object) const;
    std::string_view represented_class(ObjectId object) const;
    std::u16string_view string(ObjectId object) const;
    std::u16string_view char_sequence(ObjectId object) const;
    std::u16string_view exception_message(ObjectId object) const;
    std::size_t array_length(ObjectId object) const;
    Value array_get(ObjectId object, std::int32_t index) const;
    void array_set(ObjectId object, std::int32_t index, Value value);
    const HostObjectState *host_state(ObjectId object) const;
    // Replacement is atomic with respect to allocation failure. The receiver
    // and proposed references remain rooted during any required collection.
    void set_host_state(ObjectId object, std::unique_ptr<HostObjectState> state);
    bool assignable(ObjectId object, std::string_view type) const;
    Value get_static(Index field);
    void set_static(Index field, Value value);
    void retain(ObjectId object);
    void release(ObjectId object);
    void collect();
    [[noreturn]] void raise(std::string_view type, std::u16string_view message = {});

  private:
    Value invoke_resolved(Index method, std::span<const Value> arguments, bool virtual_dispatch);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::dex
