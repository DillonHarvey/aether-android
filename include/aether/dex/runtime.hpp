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
    // Optional immutable hosted CharSequence storage. A borrowed view is valid
    // only until this object's state is replaced; it never invokes guest code.
    virtual std::optional<std::u16string_view> char_sequence_view() const noexcept { return {}; }
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
enum class RuntimeAllocationPhase : std::uint32_t {
    invoke_setup=1,verification=2,registers=3,execute=4,exception_handler=5,
    error_diagnostic=6,provider=7,class_load=8,core=9,native=10,return_validation=11,
    class_lookup=12,class_source=13,class_archive_read=14,class_archive_hash=15,
    dex_header=16,dex_map=17,dex_strings=18,dex_types=19,dex_prototypes=20,
    dex_fields=21,dex_methods=22,dex_code=23,dex_classes=24,dex_annotations=25,
    link_account=26,link_merge=27,link_validate=28,class_definition_index=29,class_complete=30,
    dex_code_units=31,dex_code_handler_list=32,dex_code_handler_types=33,
    dex_code_handler_index=34,dex_code_try_regions=35,dex_code_try_publish=36,
    dex_code_storage_publish=37
};
struct RuntimeAllocationFailure {
    RuntimeAllocationPhase phase;
    Index method=no_index;
    std::uint32_t pc=no_index,opcode=256;
    std::uint64_t instructions=0;
    std::uint32_t code_units=0;
    std::string_view owner,name;
};
// Trusted non-owning observer. Labels are borrowed only for this synchronous
// report. Implementations must not allocate, reenter, invoke providers/guest
// APIs, retain label pointers, or alter execution budgets and deadlines.
class RuntimeProgressSink {
  public:
    virtual ~RuntimeProgressSink()=default;
    virtual void report(const RuntimeProgress &) noexcept=0;
    // First bad_alloc witness per attachment; labels are synchronous views only.
    virtual void allocation_failure(const RuntimeAllocationFailure &) noexcept {}
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
    // Trusted exact View activation admission/observation. No allocation,
    // guest/provider reentry or native callbacks are permitted in these hooks.
    virtual std::uint64_t begin_view_activation(ObjectId) const noexcept { return 0; }
    virtual void view_activated(ObjectId, std::uint64_t) noexcept {}
    // Conservative source invalidation before an actual managed policy setter
    // body. The host validates the recognized receiver contract without guest
    // reentry; this is a dirty witness, never a successful-write/event claim.
    virtual void collection_selection_policy_write(ManagedRuntime &, ObjectId) {}
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
    virtual void write_reflected_field(ManagedRuntime &, const HostField &, ObjectId, Value) {
        throw DexError("AETHER_DEX_FIELD_UNSUPPORTED", "Provider field write is not implemented");
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
struct ViewActivationState;
class ViewActivationScope final {
  public:
    ViewActivationScope(ManagedRuntime &runtime, ObjectId receiver, bool delegation = false);
    ~ViewActivationScope() noexcept;
    ViewActivationScope(const ViewActivationScope &) = delete;
    ViewActivationScope &operator=(const ViewActivationScope &) = delete;
    void complete(bool activated) noexcept;
  private:
    std::unique_ptr<ViewActivationState> state_;
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
    // JNI lookup initializes the supplied class and returns its real declared
    // DEX method, including visibility-aware superclass and owned-interface
    // inheritance. Abstract IDs are valid; constructors remain target-local.
    // Incomplete providers and defaults needing copied conflict IDs refuse.
    Index lookup_jni_method(std::string_view owner, std::string_view name,
                            std::string_view signature, bool is_static);
    // Metadata-only validation for an owned canonical JNI method ID. Reuse
    // lookup resolution for the supplied class, without executing/initializing
    // any class. Overrides/hiding must resolve to that same declaration index.
    bool jni_method_compatible(Index method, std::string_view supplied_class);
    // Descriptor metadata queries do not initialize a class. A missing parent
    // is meaningful only for Object, interfaces and primitive class mirrors.
    std::optional<std::string> superclass(std::string_view descriptor) const;
    bool class_assignable(std::string_view from, std::string_view to) const;
    void initialize(std::string_view descriptor);
    ObjectId new_object(std::string_view descriptor);
    // Trusted provider source adoption into a genuine FileInputStream value.
    // Charges its fixed storage, binds the current provider generation and
    // closes the source exactly once on failure/close/GC. No native FD is
    // fabricated. Retain the result before another managed allocation.
    ObjectId new_host_input_stream(std::unique_ptr<HostInputStream> source);
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
    // JNI instance lookup initializes the supplied class, then resolves exact
    // owned instance declarations along its superclass chain. Access shares
    // the receiver's existing traced field slots; it never initializes again.
    Index lookup_instance_field(std::string_view owner, std::string_view name, std::string_view descriptor);
    Value get_instance_field(ObjectId receiver, Index field);
    void set_instance_field(ObjectId receiver, Index field, Value value);
    // JNI reflection conversion of authenticated owned DEX declarations. These
    // use real charged Field metadata, never guest constructors/class initializers
    // or provider/symbolic field IDs. Retain a new result before any allocation.
    Index reflected_field_index(ObjectId object);
    ObjectId new_reflected_field(Index field);
    // Real owned Method/Constructor storage, with canonical DEX declaration
    // identity. Providers and special core adapters do not become synthetic IDs.
    Index reflected_method_index(ObjectId object);
    ObjectId new_reflected_method(Index method);
    // Trusted JNI adapter storage: one ordinary charged WeakReference wrapper,
    // initialized without invoking guest code or joining a Java ReferenceQueue.
    // The returned wrapper must be retained before any managed allocation. Its
    // referent is weak after this call; reading it does not allocate or collect.
    ObjectId new_native_weak(ObjectId referent);
    // Trusted provider enum constants use real traced Enum storage, without a
    // guest constructor/initializer. Retain the result before another allocation.
    ObjectId new_host_enum(std::string_view descriptor, std::u16string_view name, std::int32_t ordinal);
    ObjectId native_weak_referent(ObjectId wrapper) const;
    // Reserve one charged, runtime-owned stackless OOME before native guest
    // execution. The collector retains it independently of the pin quota.
    // Preparation may fail normally; the returned root is borrowed, not a pin
    // for callers to release. Repeated preparation returns the same object.
    ObjectId prepare_native_allocation_error();
    // Trusted JNI backing: exactly 4096 stable, initially zero cells. Their
    // full capacity shares the existing 65536 retained-root budget. Registration
    // must precede native entry; cells/storage stay owned until unregister.
    // Updates and unregister allocate nothing, invoke no guest/provider code,
    // and remain valid during owned teardown after loader failure. Only this
    // API may mutate registered cells. Tokens are never reused in this runtime.
    std::uint64_t register_native_roots(std::span<ObjectId> cells);
    void set_native_root(std::uint64_t token, std::size_t index, ObjectId object);
    void unregister_native_roots(std::uint64_t token);
    Value get_static(Index field);
    void set_static(Index field, Value value);
    // JNI initializes the supplied lookup class, then resolves the canonical
    // declared static field through its interfaces and superclass hierarchy.
    Index lookup_static_field(std::string_view owner, std::string_view name, std::string_view descriptor);
    bool static_field_compatible(Index field, std::string_view supplied_class) const;
    // Native access uses prepared/default storage without initializing a
    // different declaring owner (notably an inherited interface).
    Value get_static_uninitialized(Index field);
    void set_static_uninitialized(Index field, Value value);
    void retain(ObjectId object);
    void release(ObjectId object);
    void collect();
    [[noreturn]] void raise(std::string_view type, std::u16string_view message = {});

  private:
    Index lookup_jni_method_impl(std::string_view owner, std::string_view name,
                                 std::string_view signature, bool is_static, bool initialize_class);
    Value invoke_resolved(Index method, std::span<const Value> arguments, bool virtual_dispatch,
                          bool activation_delegation = false);
    friend class ViewActivationScope;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::dex
