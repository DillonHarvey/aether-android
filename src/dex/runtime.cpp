#include "aether/dex/runtime.hpp"
#include "aether/dex/bytecode.hpp"
#include "aether/dex/source.hpp"
#include "aether/dex/scheduler.hpp"
#include "aether/host/process_info.hpp"
#include "aether/host/entropy.hpp"
#include "array_views.hpp"
#include "async_task.hpp"
#include "atomics.hpp"
#include "bytes.hpp"
#include "class_names.hpp"
#include "collections.hpp"
#include "unmodifiable_lists.hpp"
#include "synchronized_lists.hpp"
#include "deque.hpp"
#include "enums.hpp"
#include "execution_policy.hpp"
#include "futures.hpp"
#include "floating_values.hpp"
#include "integral_values.hpp"
#include "integers.hpp"
#include "literal_metadata.hpp"
#include "booleans.hpp"
#include "uuids.hpp"
#include "random.hpp"
#include "streams.hpp"
#include "maps.hpp"
#include "empty_maps.hpp"
#include "references.hpp"
#include "sets.hpp"
#include "regex.hpp"
#include "time_units.hpp"
#include "thread_pool.hpp"
#include "thread_locals.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cmath>
#include <limits>
#include <map>
#include <set>
#include <thread>
#include <type_traits>
#include <utility>

namespace aether::dex {
namespace {
[[noreturn]] void fail(std::string_view kind, const std::string &message) {
    throw DexError("AETHER_DEX_" + std::string(kind), message);
}
std::uint32_t word(Value v) {
    if (v.kind != ValueKind::word)
        fail("VALUE_TYPE", "Expected a 32-bit register value");
    return static_cast<std::uint32_t>(v.bits);
}
std::uint64_t wide(Value v) {
    if (v.kind != ValueKind::wide)
        fail("VALUE_TYPE", "Expected a 64-bit register pair");
    return v.bits;
}
ObjectId reference(Value v) {
    if (v.kind == ValueKind::word && !v.bits)
        return 0; // DEX const/4 zero is also null.
    if (v.kind != ValueKind::reference)
        fail("VALUE_TYPE", "Expected an object reference");
    return v.bits;
}
Value default_value(std::string_view type) {
    if (reference_type(type))
        return Value::reference(0);
    if (type == "V")
        return Value::nothing();
    return type_words(type) == 2 ? Value::wide(0) : Value::word(0);
}
// Integer normalization makes Java nearest-even rounding independent of the
// host thread's floating-point control state, without changing that state.
std::uint32_t int_float_bits(std::uint32_t bits) noexcept {
    const auto sign=bits & 0x80000000u;
    const auto magnitude=sign ? std::uint32_t{0}-bits : bits;
    if (!magnitude) return 0;
    auto exponent=std::bit_width(magnitude)-1u;
    std::uint32_t significand;
    if (exponent<=23) significand=magnitude << (23-exponent);
    else {
        const auto shift=exponent-23;
        significand=magnitude >> shift;
        const auto remainder=magnitude & ((1u << shift)-1u);
        const auto half=1u << (shift-1u);
        if (remainder>half || (remainder==half && (significand & 1u))) ++significand;
        if (significand==0x01000000u) {significand >>= 1;++exponent;}
    }
    return sign | ((exponent+127u) << 23) | (significand & 0x007fffffu);
}
std::uint32_t float_int_bits(std::uint32_t bits) noexcept {
    if ((bits & 0x7fffffffu)>0x7f800000u) return 0; // Every NaN converts to zero.
    const auto value=std::bit_cast<float>(bits);
    if (value>=0x1p31f) return 0x7fffffffu;
    if (value<=-0x1p31f) return 0x80000000u;
    // Only finite, in-range values reach this truncating C++ conversion.
    return static_cast<std::uint32_t>(static_cast<std::int32_t>(value));
}
std::uint32_t string_hash(std::u16string_view text) noexcept {
    std::uint32_t hash = 0;
    for (const auto character : text)
        hash = 31 * hash + character;
    return hash;
}
std::string_view core_super(std::string_view type) {
    if(const auto stream=stream_class(type))return stream->superclass;
    if(type=="Landroid/text/TextUtils;")return "Ljava/lang/Object;";
    if (const auto info=async_task_class(type))return info->superclass;
    if (const auto info = future_class(type))return info->superclass;
    if (const auto pool = thread_pool_class(type))
        return pool->superclass;
    if (const auto policy = execution_policy_class(type))
        return policy->superclass;
    if (const auto set = set_class(type))
        return set->superclass;
    if (const auto info = reference_class(type))
        return info->superclass;
    if (const auto enumeration = enum_class(type))
        return enumeration->superclass;
    if (const auto map = map_class(type))
        return map->superclass;
    if (const auto view = map_view_class(type))
        return view->superclass;
    if (const auto atomic = atomic_class(type))
        return atomic->superclass;
    if(const auto empty=empty_map_class(type))return empty->superclass;
    if(const auto local=thread_local_class(type))return local->superclass;
    if(const auto regex=regex_class(type))return regex->superclass;
    if(const auto integral=integral_class(type))return integral->superclass;
    if(const auto floating=floating_class(type))return floating->superclass;
    if(const auto byte=byte_class(type))return byte->superclass;
    if(const auto uuid=uuid_class(type))return uuid->superclass;
    if(const auto random=random_class(type))return random->superclass;
    if(const auto boolean=boolean_class(type))return boolean->superclass;
    if(type=="Ljava/lang/Void;")return "Ljava/lang/Object;";
    if(type=="Ljava/util/BitSet;")return "Ljava/lang/Object;"; // Nominal metadata only.
    if(const auto literal=literal_metadata_class(type))return literal->superclass;
    if (const auto integer = integer_class(type))
        return integer->superclass;
    if (const auto collection = collection_class(type))
        return collection->superclass;
    if (type == "Ljava/lang/Object;")
        return {};
    if (type == "Ljava/lang/String;" || type == "Ljava/lang/StringBuilder;" ||
        type == "Ljava/lang/CharSequence;" || type == "Ljava/lang/Class;" || type == "Ljava/lang/System;" ||
        type == "Ljava/lang/ThreadGroup;" || type == "Ljava/lang/Thread$UncaughtExceptionHandler;" ||
        type == "Ljava/lang/reflect/Type;" ||
        type == "Ljava/lang/Math;" || type == "Ldalvik/system/VMRuntime;" || type == "Ljava/lang/Runtime;" || type == "Ljava/lang/Throwable;" || type == "Ljava/lang/Runnable;" || type == "Ljava/lang/Thread;" || type == collections_utility_type)
        return "Ljava/lang/Object;";
    if (type == "Ljava/util/concurrent/CountDownLatch;") return "Ljava/lang/Object;";
    if (type == "Laether/dex/RuntimeClassLoader;") return "Ljava/lang/ClassLoader;";
    if (type == "Ljava/lang/ClassLoader;") return "Ljava/lang/Object;";
    if (type == "Ljava/lang/reflect/Method;") return "Ljava/lang/reflect/Executable;";
    if (type == "Ljava/lang/reflect/Field;") return "Ljava/lang/reflect/AccessibleObject;";
    if (type == "Ljava/lang/reflect/Executable;") return "Ljava/lang/reflect/AccessibleObject;";
    if (type == "Ljava/lang/reflect/AccessibleObject;") return "Ljava/lang/Object;";
    if (type == "Ljava/lang/InterruptedException;") return "Ljava/lang/Exception;";
    if (type == "Ljava/lang/Exception;" || type == "Ljava/lang/Error;")
        return "Ljava/lang/Throwable;";
    if (type == "Ljava/lang/NumberFormatException;")
        return "Ljava/lang/IllegalArgumentException;";
    if (type == "Ljava/lang/RuntimeException;")
        return "Ljava/lang/Exception;";
    if (type == "Ljava/lang/ReflectiveOperationException;")
        return "Ljava/lang/Exception;";
    if (type == "Ljava/lang/ClassNotFoundException;" || type == "Ljava/lang/NoSuchFieldException;" ||
        type == "Ljava/lang/IllegalAccessException;" || type == "Ljava/lang/NoSuchMethodException;" ||
        type == "Ljava/lang/reflect/InvocationTargetException;")
        return "Ljava/lang/ReflectiveOperationException;";
    if (type == "Ljava/lang/CloneNotSupportedException;")
        return "Ljava/lang/Exception;";
    if (type == "Ljava/lang/NullPointerException;" || type == "Ljava/lang/ArithmeticException;" ||
        type == "Ljava/lang/IndexOutOfBoundsException;" || type == "Ljava/lang/NegativeArraySizeException;" ||
        type == "Ljava/lang/ArrayStoreException;" || type == "Ljava/lang/ClassCastException;" ||
        type == "Ljava/lang/IllegalStateException;" || type == "Ljava/lang/IllegalArgumentException;" ||
        type == "Ljava/lang/IllegalThreadStateException;" ||
        type == "Ljava/lang/IllegalMonitorStateException;" ||
        type == "Ljava/lang/SecurityException;" || type == "Ljava/lang/UnsupportedOperationException;" ||
        type == "Ljava/util/NoSuchElementException;" || type == "Ljava/util/ConcurrentModificationException;")
        return "Ljava/lang/RuntimeException;";
    if (type == "Ljava/lang/ArrayIndexOutOfBoundsException;" ||
        type == "Ljava/lang/StringIndexOutOfBoundsException;")
        return "Ljava/lang/IndexOutOfBoundsException;";
    if (type == "Ljava/lang/ExceptionInInitializerError;" || type == "Ljava/lang/NoClassDefFoundError;" ||
        type == "Ljava/lang/NoSuchMethodError;")
        return "Ljava/lang/Error;";
    return {};
}
bool core_type(std::string_view type) { return type == "Ljava/lang/Object;" || !core_super(type).empty(); }
std::atomic<std::uint64_t> next_identity{1};
struct ReflectedMethod {
    HostMethod metadata;
    Index managed = no_index;
    bool provider = false;
    unsigned vm_runtime_operation = 0;
    std::size_t bytes() const {
        std::size_t n = sizeof(ReflectedMethod) + metadata.owner.capacity() + metadata.name.capacity() + metadata.return_type.capacity();
        n += metadata.parameters.capacity() * sizeof(std::string);
        for (const auto &p : metadata.parameters) n += p.capacity();
        return n;
    }
};
struct ReflectedField {
    HostField metadata;
    Index managed = no_index;
    bool provider = false;
    std::size_t bytes() const {
        return sizeof(ReflectedField) + metadata.owner.capacity() + metadata.name.capacity() + metadata.type.capacity();
    }
};
class CountDownLatchState final : public HostObjectState {
  public:
    CountDownLatchState(std::int32_t value = 0, bool ready = false) : count(value), initialized(ready) {}
    const std::int32_t count;
    const bool initialized;
    std::span<const Value> values() const noexcept override { return {}; }
    std::size_t bytes() const noexcept override { return sizeof(CountDownLatchState); }
};
struct ThreadState {
    enum class Lifecycle { fresh, started, terminated };
    ObjectId name = 0, target = 0, group = 0, pool_worker = 0, uncaught_handler = 0;
    Lifecycle lifecycle = Lifecycle::fresh;
    std::uint64_t inherited_signal_mask = 0;
    bool initialized = false, daemon = false, synthetic = false;
};
struct PoolWorker {
    std::array<Value,5> roots{}; // pool, actual factory Thread, first job, current job, throwable
    bool entered=false,exited=false,active=false,idle=false,abrupt=false,counted=false;
    ObjectId waiting_queue=0;
    std::uint64_t wait_ticket=0;
    std::optional<std::chrono::steady_clock::time_point> wait_deadline;
    ObjectId pool()const noexcept{return roots[0].bits;}
    ObjectId thread()const noexcept{return roots[1].bits;}
};
struct DefaultFactory {ObjectId group=0;std::uint64_t sequence=0;};
struct Object {
    std::string type, represented;
    std::u16string text;
    std::map<Index, Value> fields;
    std::vector<Value> elements;
    std::unique_ptr<ThreadPoolState> pool;
    std::unique_ptr<FutureState> future;
    std::unique_ptr<AsyncTaskState> async_task;
    std::unique_ptr<AsyncSdkState> async_sdk;
    ObjectId async_future_owner=0;
    std::unique_ptr<PoolWorker> pool_worker;
    std::unique_ptr<DefaultFactory> factory;
    std::unique_ptr<QueueIterator> queue_iterator;
    std::unique_ptr<ThreadState> thread;
    std::unique_ptr<AbortPolicy> abort_policy;
    std::unique_ptr<ManagedList> list;
    std::unique_ptr<ManagedQueue> fifo;
    std::unique_ptr<ManagedDeque> deque;
    std::unique_ptr<DequeIterator> deque_iterator;
    std::unique_ptr<SnapshotIterator> iterator;
    std::unique_ptr<LiveListIterator> live_iterator;
    std::unique_ptr<AtomicReference> atomic;
    std::unique_ptr<AtomicInteger> atomic_integer;
    std::unique_ptr<AtomicLong> atomic_long;
    std::unique_ptr<ManagedThreadLocal> thread_local_key;
    std::unique_ptr<ThreadLocalTable> thread_locals;
    std::unique_ptr<ManagedPattern> regex_pattern;
    std::unique_ptr<ManagedMatcher> regex_matcher;
    std::unique_ptr<PatternSyntax> regex_syntax;
    std::unique_ptr<ManagedIntegral> integral;
    std::unique_ptr<ManagedFloating> floating;
    std::unique_ptr<ManagedByte> byte;
    std::unique_ptr<ManagedInteger> integer;
    std::unique_ptr<ManagedBoolean> boolean;
    std::unique_ptr<ManagedUuid> uuid;
    std::unique_ptr<ManagedRandom> random;
    std::unique_ptr<ManagedStream> stream;
    std::unique_ptr<const ReflectedMethod> reflected_method;
    std::unique_ptr<const ReflectedField> reflected_field;
    bool reflective_access_override = false;
    std::unique_ptr<HostObjectState> host_state;
    std::size_t host_bytes = 0;
    std::unique_ptr<ManagedMap> map;
    std::unique_ptr<MapKeys> map_keys;
    std::unique_ptr<MapValues> map_values;
    std::unique_ptr<MapEntryReference> map_entry;
    std::unique_ptr<SynchronizedMap> synchronized_map;
    std::unique_ptr<ManagedSet> set;
    std::unique_ptr<SynchronizedSet> synchronized_set;
    std::unique_ptr<ManagedEnum> enumeration;
    std::unique_ptr<WeakReference> weak;
    std::unique_ptr<ReferenceQueue> queue;
    std::unique_ptr<ReferenceFieldUpdater> updater;
    ObjectId cause = 0;
    std::size_t bytes = 0;
    bool marked = false;
};
struct Frame {
    Index method = 0;
    std::uint32_t pc = 0;
    std::vector<Value> arguments, registers;
    Value result;
    ObjectId caught = 0;
    std::array<ObjectId, 32> monitors{};
    std::size_t monitor_count = 0;
    Value get(std::uint32_t r) const {
        if (r >= registers.size())
            fail("REGISTER", "Register outside frame");
        const auto v = registers[r];
        if (v.kind == ValueKind::empty || v.kind == ValueKind::wide_tail)
            fail("VALUE_TYPE", "Read from uninitialized register or high half");
        if (v.kind == ValueKind::wide &&
            (r + 1 >= registers.size() || registers[r + 1].kind != ValueKind::wide_tail))
            fail("VALUE_TYPE", "Broken wide register pair");
        return v;
    }
    void put(std::uint32_t r, Value v) {
        const auto width = v.kind == ValueKind::wide ? 2u : 1u;
        if (r >= registers.size() || width > registers.size() - r)
            fail("REGISTER", "Register write outside frame");
        const auto invalidate = [&](std::uint32_t at) {
            if (registers[at].kind == ValueKind::wide && at + 1 < registers.size())
                registers[at + 1] = {};
            if (registers[at].kind == ValueKind::wide_tail && at)
                registers[at - 1] = {};
            registers[at] = {};
        };
        invalidate(r);
        if (width == 2)
            invalidate(r + 1);
        registers[r] = v;
        if (width == 2)
            registers[r + 1] = {ValueKind::wide_tail, 0};
    }
};
// Per-logical-thread interpreter state. Main and host-managed task contexts share
// the runtime heap/statics/loader and aggregate quotas. Every registered context,
// including suspended and terminal retained contexts, participates in GC.
struct ExecutionContext {
    const host::PriorityService *native_priority=nullptr;
    std::optional<std::uint64_t> thread_exit, native_finalizing_exit;
    bool native_finalizing=false, native_finalization_started=false;
    std::exception_ptr native_finalization_failure;
    bool native_discarded=false, cancellation_requested=false;
    std::vector<Frame *> frames;
    Value last_result;
    ObjectId last_exception = 0;
    ObjectId thread_object = 0;
    std::uint64_t remaining = 0;
    std::size_t invocations = 0;
    std::size_t barriers = 0;
    unsigned quantum = 128;
    bool interrupted = false;
    template<class Visitor> void visit_roots(Visitor &&value) const {
        value(last_result);
        value(Value::reference(last_exception));
        value(Value::reference(thread_object));
        for (const auto *frame : frames) {
            for (auto v : frame->arguments) value(v);
            for (auto v : frame->registers) value(v);
            value(frame->result);
            value(Value::reference(frame->caught));
            for (std::size_t n = 0; n < frame->monitor_count; ++n)
                value(Value::reference(frame->monitors[n]));
        }
    }
};
struct NonYielding {
    ExecutionContext &context;
    explicit NonYielding(ExecutionContext &value) : context(value) { ++context.barriers; }
    ~NonYielding() { --context.barriers; }
};
// Only audited Thread.sleep/yield may relax their own core-call barrier.
// Restoration is tied to the suspended context, including cancellation unwind.
struct SuspendCoreBarrier {
    ExecutionContext &context;
    explicit SuspendCoreBarrier(ExecutionContext &value) : context(value) { --context.barriers; }
    ~SuspendCoreBarrier() { ++context.barriers; }
};
struct MainCallback {
    Index method = 0;
    bool virtual_dispatch = false;
    std::vector<Value> arguments;
    std::unique_ptr<ManagedMainEntry> entry;
    std::span<const Value> entry_roots;
    std::size_t entry_bytes=0, charged = 0;
    bool published=false;
    std::span<const Value> checked_roots() const {
        if(!entry)return {};
        // Admission traces the captured metadata without a partially published
        // virtual call; accepted entries must keep their storage/charge stable.
        if(published) {
            const auto roots=entry->values();
            if(entry->bytes()!=entry_bytes || roots.size()!=entry_roots.size() ||
                (!roots.empty() && roots.data()!=entry_roots.data()))
                fail("MAIN_CALLBACK_ENTRY", "Trusted main entry metadata changed after admission");
        }
        return entry_roots;
    }
};
struct TaskContext {
    Scheduler::TaskId id = 0;
    ExecutionContext context;
    std::vector<Value> arguments;
    std::unique_ptr<ManagedWorkerEntry> worker;
    std::span<const Value> worker_roots;
    std::size_t worker_bytes = 0;
    std::size_t charged = 0;
    bool java_owned = false;
    ObjectId maintenance_pool = 0;
    bool maintenance_abrupt = false, missing_worker = false;
    std::span<const Value> checked_worker_roots() const {
        if (!worker) return {};
        // During admission (id==0), captured metadata is already validated and
        // no entry hook is called while its roots are being published for GC.
        if (id) {
            const auto roots = worker->values();
            if (worker->bytes() != worker_bytes || roots.size() != worker_roots.size() ||
                (!roots.empty() && roots.data() != worker_roots.data()))
                fail("WORKER_ENTRY", "Persistent worker metadata changed after admission");
        }
        return worker_roots;
    }
};
} // namespace
struct ManagedRuntime::Impl {
    ManagedRuntime &runtime;
    DexImage image;
    std::unique_ptr<ClassLoader> loader;
    RuntimeLimits limits;
    RuntimeMetrics metrics;
    NativeInterface *native = nullptr;
    std::shared_ptr<ProcessState> process=std::make_shared<ProcessState>();
    bool process_bound=false;
    HostInterface *host = nullptr;
    std::uint64_t host_generation=1;
    std::thread::id owner = std::this_thread::get_id();
    const std::uint64_t execution_owner = Scheduler::execution_token();
    std::map<ObjectId, Object> heap;
    std::map<ObjectId, std::size_t> pins;
    std::map<std::string, ObjectId, std::less<>> class_objects;
    std::map<Index, ObjectId> strings;
    std::array<ObjectId,256> long_cache{},short_cache{};
    std::array<ObjectId,256> byte_cache{};
    std::array<ObjectId, 256> integer_cache{};
    std::array<ObjectId,2> boolean_cache{};
    std::array<ObjectId, 7> time_units{};
    // SDK35 public pool, serial executor, lazy backup, shared factory and policy.
    std::array<ObjectId,2> standard_streams{}; // out, err; runtime-owned GC roots.
    std::array<bool,2> standard_closed{},standard_error{};
    std::array<ObjectId,5> async_globals{};
    std::array<ObjectId,3> async_statuses{};
    bool async_initialized=false,async_initializing=false;
    std::map<std::string, unsigned, std::less<>> class_state;
    std::map<std::string,ExecutionContext*,std::less<>> class_initializers;
    std::map<Index, Value> statics;
    std::map<Index, VerifiedCode> verified;
    RuntimeProgressSink *progress_sink=nullptr;
    mutable ExecutionContext main_context;
    std::array<ExecutionContext*,16> native_contexts{};
    std::array<std::uint64_t,16> native_context_tokens{};
    std::size_t native_context_depth=0;
    bool native_cpu_unattributed=false;
    const std::optional<int> owner_priority_baseline=host::current_thread_priority();
    ObjectId thread_group_object = 0;
    ObjectId default_uncaught_handler = 0;
    ObjectId java_version_property = 0;
    ObjectId empty_list = 0;
    std::array<ObjectId,3> empty_map_objects{};
    ObjectId runtime_object = 0, vm_runtime_object = 0;
    std::vector<std::u16string> hidden_api_exemptions;
    std::size_t hidden_api_bytes=0;
    ObjectId loader_object = 0;
    // Held metadata is immutable and demand linking only appends classes. Never
    // reuse validation for a new range until that entire range has passed.
    mutable std::size_t sealed_loader_checked_classes = 0;
    std::unique_ptr<Scheduler> scheduler;
    std::array<std::unique_ptr<TaskContext>, 16> tasks;
    std::uint64_t task_work_remaining = 0;
    std::array<std::unique_ptr<MainCallback>, 16> main_callbacks;
    std::unique_ptr<MainCallback> main_callback_inflight;
    MainCallback *main_callback_posting = nullptr; // Temporary roots before quota collection/publication.
    std::size_t main_callback_head = 0, main_callback_count = 0;
    std::uint64_t main_callback_work_remaining = 0;
    bool main_callback_capacity_charged = false, main_callbacks_closed = false;
    bool background_executed = false, tasks_closing = false, pool_maintenance_active = false;
    void report_progress(RuntimeProgressStage stage,Index method=no_index,std::uint32_t pc=0) const noexcept {
        if(!progress_sink)return;
        RuntimeProgress event{stage,method,pc,metrics.instructions,{},{}};
        if(method<image.methods.size()) {
            const auto &declaration=image.methods[method];
            if(declaration.owner<image.types.size())event.owner=image.types[declaration.owner];
            event.name=declaration.name;
        }
        progress_sink->report(event);
    }
    struct ProgressEnd {
        const Impl &impl;RuntimeProgressStage stage;Index method;std::uint32_t pc;
        ~ProgressEnd(){impl.report_progress(stage,method,pc);}
    };
    struct LoadingProgress {
        const Impl &impl;Index method=no_index;std::uint32_t pc=0;
        LoadingProgress(const Impl &impl,std::string_view descriptor):impl(impl) {
            if(!impl.progress_sink)return;
            const auto &context=impl.current_context();
            if(!context.frames.empty()){method=context.frames.back()->method;pc=context.frames.back()->pc;}
            impl.progress_sink->report({RuntimeProgressStage::class_load_begin,method,pc,impl.metrics.instructions,descriptor,{}});
        }
        ~LoadingProgress() {
            // The descriptor may have pointed into the loader's growable image.
            // Do not reuse that borrowed view after linking or exception unwind.
            if(impl.progress_sink)impl.progress_sink->report({RuntimeProgressStage::class_load_end,method,pc,impl.metrics.instructions,{},{}});
        }
    };
    void ensure_class(std::string_view descriptor) const {
        LoadingProgress progress(*this,descriptor);loader->ensure(descriptor);
    }
    ExecutionContext &current_context() const {
        if(native_context_depth){
            if(Scheduler::execution_token()!=native_context_tokens[native_context_depth-1])fail("EXECUTION_CONTEXT","Native worker belongs to another scheduler context");
            return *native_contexts[native_context_depth-1];
        }
        const auto token = Scheduler::execution_token();
        if (token == execution_owner) return main_context;
        if (scheduler && scheduler->current() == token)
            for (const auto &task : tasks)
                if (task && task->id == token) return task->context;
        fail("EXECUTION_CONTEXT", "Managed runtime belongs to another logical execution context");
    }
    void execution_checkpoint() const {
        process->checkpoint();
        const auto &context=current_context();
        if(context.native_finalization_failure)std::rethrow_exception(context.native_finalization_failure);
        if(context.thread_exit && !(context.native_finalizing && context.native_finalizing_exit==context.thread_exit))
            throw ThreadExit{*context.thread_exit};
    }
    void failure_checkpoint() const {
        process->checkpoint();
        // Private scheduler cancellation must unwind unchanged. In particular,
        // an older caught pthread exit cannot turn cancellation into completion.
        if(!current_context().cancellation_requested)execution_checkpoint();
    }
    template<class F> decltype(auto) provider_call(F &&call) const {
        execution_checkpoint();
        NonYielding barrier(current_context());
        try {
            if constexpr(std::is_void_v<std::invoke_result_t<F&>>) {
                call();execution_checkpoint();
            } else {
                decltype(auto) result=call();execution_checkpoint();return result;
            }
        } catch(...) {failure_checkpoint();throw;}
    }
    bool scheduled_task() const {return Scheduler::execution_token()!=execution_owner;}
    bool background() const { return native_context_depth || Scheduler::execution_token() != execution_owner; }
    bool owned_thread(ObjectId id) const {
        const auto found = heap.find(id);
        return found != heap.end() && bool(found->second.thread);
    }
    ThreadState &thread_state(ObjectId id, bool initialized = true) {
        auto &receiver = object(id);
        if (!receiver.thread) fail("THREAD_STATE", "Thread is not an authenticated runtime object");
        if (initialized && !receiver.thread->initialized)
            fail("THREAD_STATE", "Thread constructor has not completed");
        return *receiver.thread;
    }
    ObjectId thread_group() {
        if (!thread_group_object) {
            Object group; group.type = "Ljava/lang/ThreadGroup;"; group.text = u"main";
            thread_group_object = allocate(std::move(group));
        }
        return thread_group_object;
    }
    ObjectId synthetic_thread(ExecutionContext &context, std::u16string_view name) {
        if (context.thread_object) return context.thread_object;
        Object value; value.type = "Ljava/lang/Thread;";
        value.text = name; // Immutable, accounted fallback; materialize a String only on getName.
        value.thread = std::make_unique<ThreadState>();
        value.thread->synthetic = value.thread->initialized = true;
        value.thread->lifecycle = ThreadState::Lifecycle::started;
        const auto id = allocate(std::move(value));
        if (id > static_cast<ObjectId>(std::numeric_limits<std::int64_t>::max()))
            fail("IDENTITY_LIMIT", "Managed Thread ID exceeds positive long range");
        context.thread_object = id;
        return id;
    }
    bool active_thread(ObjectId id) const {
        if (id && main_context.thread_object == id) return true;
        for(std::size_t n=0;n<native_context_depth;++n)if(id && native_contexts[n]->thread_object==id)return true;
        for (const auto &task : tasks) if (task && task->context.thread_object == id) {
            const auto state = scheduler->state(task->id);
            return state == Scheduler::State::running || state == Scheduler::State::runnable ||
                state == Scheduler::State::sleeping || state == Scheduler::State::parked;
        }
        return false;
    }
    ExecutionContext *live_thread_context(ObjectId id) const {
        if (id && main_context.thread_object == id) return &main_context;
        for(std::size_t n=0;n<native_context_depth;++n)if(id && native_contexts[n]->thread_object==id)return native_contexts[n];
        for (const auto &task : tasks)
            if (task && id && task->context.thread_object == id && active_thread(id)) return &task->context;
        return nullptr;
    }
    void require_suspendable() const {
        const auto &context = current_context();
        if (context.barriers != 1 || execution_owner != 0)
            fail("THREAD_BLOCKING_UNSUPPORTED", "Thread suspension crosses a provider/native/loading/initialization boundary");
        for (const auto *frame : context.frames)
            if (frame->monitor_count)
                fail("THREAD_BLOCKING_UNSUPPORTED", "Thread suspension while holding a monitor requires logical monitor parking");
    }
    void discard_native_context(ExecutionContext &context) noexcept {
        if(context.native_discarded)return;
        context.native_discarded=true;
        if(native && context.thread_object)native->discard_logical_thread(context.thread_object);
    }
    void finish_task_context(ExecutionContext &context) noexcept {
        if(context.thread_object)finish_java_thread(context.thread_object);
        discard_native_context(context);
    }
    void end_native_thread(ExecutionContext &context) noexcept {
        if(context.thread_object) {
            clear_thread_locals(context.thread_object);
            const auto found=heap.find(context.thread_object);
            if(found!=heap.end() && found->second.thread)found->second.thread->lifecycle=ThreadState::Lifecycle::terminated;
            context.thread_object=0;
        }
    }
    void check_interruption(ExecutionContext &context) {
        if (context.interrupted) {
            context.interrupted = false;
            runtime.raise("Ljava/lang/InterruptedException;");
        }
    }
    void thread_yield() {
        require_suspendable();
        auto &context = current_context();
        SuspendCoreBarrier allow(context);
        if (background()) scheduler->yield();
        else if (scheduler) (void)pump_task();
        else std::this_thread::yield();
    }
    void thread_sleep(std::int64_t milliseconds, std::int32_t nanoseconds) {
        if (milliseconds < 0 || nanoseconds < 0 || nanoseconds > 999999)
            runtime.raise("Ljava/lang/IllegalArgumentException;");
        require_suspendable(); // Unsupported suspension must not consume an interrupt.
        auto &context = current_context();
        check_interruption(context);
        SuspendCoreBarrier allow(context);
        if (!milliseconds && !nanoseconds) {
            if (background()) scheduler->yield();
            else if (scheduler) (void)pump_task();
            else std::this_thread::yield();
            check_interruption(context);
            return;
        }
        // Timer granularity rounds fractional milliseconds upward. Unsigned
        // remaining time handles Long.MAX_VALUE plus one without signed overflow.
        auto remaining = static_cast<std::uint64_t>(milliseconds) + (nanoseconds ? 1u : 0u);
        using Clock = std::chrono::steady_clock;
        constexpr std::uint64_t chunk_limit = 24 * 60 * 60 * 1000;
        while (remaining) {
            const auto chunk = std::min(remaining, chunk_limit);
            const auto duration = std::chrono::milliseconds(chunk);
            const auto now = Clock::now();
            if (duration > std::chrono::duration_cast<std::chrono::milliseconds>(Clock::time_point::max() - now))
                fail("THREAD_TIME_UNSUPPORTED", "Monotonic timer range cannot represent the next bounded sleep chunk");
            const auto deadline = now + duration;
            for (;;) {
                check_interruption(context);
                auto current = Clock::now();
                if (current >= deadline) break;
                if (background()) {
                    // Recompute after every wake: a scheduler wake without an
                    // interrupt must not shorten the requested Java sleep.
                    const auto delay = std::chrono::ceil<std::chrono::milliseconds>(deadline - current);
                    scheduler->sleep_for(delay);
                    check_interruption(context);
                    continue;
                }
                if (scheduler && pump_task()) continue;
                check_interruption(context);
                current = Clock::now();
                if (current >= deadline) break;
                auto wake = std::min(deadline, current + std::chrono::milliseconds(10));
                if (scheduler)
                    if (const auto task_deadline = scheduler->next_deadline(); task_deadline && *task_deadline > current)
                        wake = std::min(wake, *task_deadline);
                std::this_thread::sleep_for(wake - current);
            }
            remaining -= chunk;
        }
        check_interruption(context);
    }
    TaskContext &task(Scheduler::TaskId id) const {
        for (const auto &entry : tasks) if (entry && entry->id == id) return *entry;
        fail("TASK", "Managed task is absent, released or belongs to another runtime");
    }
    Scheduler::TaskId submit_task(Index method, std::span<const Value> arguments, bool virtual_dispatch,
                                  std::unique_ptr<ManagedWorkerEntry> worker = {}, ObjectId java_thread = 0) {
        check_thread();
        execution_checkpoint();
        if (execution_owner != 0)
            fail("TASK_STATE", "Managed task admission requires a runtime owned by the external main context");
        if (scheduler) (void)scheduler->current();
        if (!worker) {
            if (method >= image.methods.size()) fail("METHOD_NOT_FOUND", "Scheduled method is outside the held DEX table");
            if (image.methods[method].flags & 0x100)
                fail("TASK_NATIVE_UNSUPPORTED", "Native task entry requires per-context JNI/CPU state");
        }
        if (arguments.size() > 256) fail("TASK_LIMIT", "Managed task arguments exceed 256 values");
        std::unique_ptr<TaskContext> *slot = nullptr;
        bool new_batch = true;
        for (auto &entry : tasks) {
            if (entry) new_batch = false;
            else if (!slot) slot = &entry;
        }
        if (!slot) fail("TASK_LIMIT", "Managed task context bound of 16 is exhausted");
        auto entry = std::make_unique<TaskContext>();
        if (java_thread) {
            (void)thread_state(java_thread);
            entry->java_owned = true;
            entry->context.thread_object = java_thread;
        }
        entry->arguments.assign(arguments.begin(), arguments.end());
        entry->context.frames.reserve(limits.frames);
        for (const auto argument : entry->arguments)
            if (argument.kind == ValueKind::reference && argument.bits) (void)object(argument.bits);
        if (worker) {
            const auto roots = worker->values();
            const auto bytes = worker->bytes();
            if (bytes < sizeof(ManagedWorkerEntry) || (!roots.empty() && !roots.data()))
                fail("WORKER_ENTRY", "Persistent worker has invalid fixed metadata");
            if (roots.size() > 256) fail("TASK_LIMIT", "Persistent worker roots exceed 256 values");
            for (const auto root : roots)
                if (root.kind == ValueKind::reference && root.bits) (void)object(root.bits);
            entry->worker_roots = roots;
            entry->worker_bytes = bytes;
            entry->worker = std::move(worker);
        }
        const auto base_charge = sizeof(TaskContext) + entry->arguments.capacity() * sizeof(Value) +
            entry->context.frames.capacity() * sizeof(Frame *);
        if (base_charge > limits.heap_bytes || entry->worker_bytes > limits.heap_bytes - base_charge)
            fail("HEAP_LIMIT", "Managed task entry exceeds the shared heap quota");
        entry->charged = base_charge + entry->worker_bytes;
        std::optional<std::int32_t> inherited_priority;
        if(native_context_depth){const auto inherited=priority({});if(inherited.error)fail("SCHEDULER_PRIORITY_UNSUPPORTED","Cannot inherit native worker priority");inherited_priority=inherited.nice;}
        ensure_scheduler();
        // Publish entry arguments as roots before collection. No managed allocation
        // or callback can occur between copying arguments and this publication.
        *slot = std::move(entry);
        auto *task = slot->get();
        try {
            if (task->charged > limits.heap_bytes - metrics.heap_bytes) collect();
            if (task->charged > limits.heap_bytes - metrics.heap_bytes)
                fail("HEAP_LIMIT", "Managed task context exceeds shared heap quota");
        } catch (...) { slot->reset(); throw; }
        metrics.heap_bytes += task->charged;
        try {
            task->id = scheduler->submit([this, task, method, virtual_dispatch] {
                background_executed = true;
                if (progress_sink && !progress_sink->prepare_native_stack())
                    fail("PROGRESS_STACK", "Cannot prepare bounded native fault diagnostics on task stack");
                struct LocalEnd {Impl &impl;ExecutionContext &context;~LocalEnd(){impl.finish_task_context(context);}} local_end{*this,task->context};
                try {
                    try {
                        if (task->worker) {
                            task->context.remaining = limits.instructions;
                            (void)task->checked_worker_roots();
                            struct WorkerEnd {
                                ExecutionContext &context;
                                ~WorkerEnd() { context.last_result = Value::nothing(); }
                            } end{task->context};
                            try {
                                task->worker->run(runtime);
                            } catch (const JavaException &error) {
                                (void)object(error.object);
                                task->context.last_exception = error.object;
                                throw;
                            }
                        } else if (virtual_dispatch) (void)runtime.invoke_virtual(method, task->arguments);
                        else (void)runtime.invoke(method, task->arguments);
                        execution_checkpoint();
                    } catch(...) {failure_checkpoint();throw;}
                } catch(const ThreadExit &exit) {
                    process->checkpoint();
                    if(task->context.cancellation_requested)throw;
                    // A nested native child's exit must be consumed by its native
                    // runner; an unlatched foreign exit cannot terminate this task.
                    if(!task->context.thread_exit || *task->context.thread_exit!=exit.value)throw;
                    task->context.last_exception=0;task->context.last_result=Value::nothing();
                }
                // Only orderly completion or this context's recognized exit can
                // reach fallible cleanup. Failure/cancellation only retire state.
                if(native)runtime.run_thread_finalizers([&]{native->finish_logical_thread(runtime);});
            },inherited_priority);
        } catch (...) {
            metrics.heap_bytes -= task->charged;
            slot->reset();
            throw;
        }
        if (new_batch && !pool_maintenance_active) task_work_remaining = limits.instructions;
        return task->id;
    }
    // Named virtual routing uses only genuine linked declarations. In particular,
    // a base Thread need not have an unrelated Thread.run method reference in DEX.
    ThreadPoolState &pool_state(ObjectId id) {
        auto &value = object(id);
        if (!value.pool || !value.pool->initialized()) fail("STATE", "Executor is not initialized");
        return *value.pool;
    }
    Object &validate_pool_queue(ObjectId queue) {
        auto &value=object(queue);
        if(!subtype(value.type,"Ljava/util/concurrent/BlockingQueue;"))
            fail("EXECUTOR_QUEUE_UNSUPPORTED","Executor requires a BlockingQueue");
        if(value.fifo && !value.fifo->initialized())fail("STATE","Executor queue is not initialized");
        return value;
    }
    Object &pool_queue(ObjectId id) {return validate_pool_queue(pool_state(id).queue());}
    bool native_pool_queue(ObjectId id) {
        const auto &queue=pool_queue(id);
        return queue.fifo && (queue.type==blocking_queue_type || queue.type==synchronous_queue_type);
    }
    bool pool_queue_empty(ObjectId id) {return word(queue_call(id,"isEmpty","()Z"))!=0;}
    std::size_t pool_queue_size(ObjectId id) {
        const auto size=std::bit_cast<std::int32_t>(word(queue_call(id,"size","()I")));
        if(size<0)fail("EXECUTOR_QUEUE_RESULT","BlockingQueue.size returned a negative count");
        return static_cast<std::size_t>(size);
    }
    bool synchronous_handoff(ObjectId queue,ObjectId job) {
        auto &backing=object(queue);
        if(!backing.fifo || !backing.fifo->initialized() || !backing.fifo->synchronous())
            fail("STATE", "Handoff requires an authenticated initialized SynchronousQueue");
        (void)object(job);
        if(!scheduler)return false;
        PoolWorker *selected=nullptr;
        Scheduler::TaskId selected_task=0;
        const auto now=std::chrono::steady_clock::now();
        for(const auto &entry:tasks)if(entry && entry->java_owned && !entry->context.interrupted &&
            scheduler->state(entry->id)==Scheduler::State::parked) {
            const auto thread=heap.find(entry->context.thread_object);
            if(thread==heap.end() || !thread->second.thread || !thread->second.thread->pool_worker)continue;
            const auto worker=heap.find(thread->second.thread->pool_worker);
            if(worker==heap.end() || !worker->second.pool_worker)continue;
            auto &candidate=*worker->second.pool_worker;
            if(candidate.thread()!=entry->context.thread_object || candidate.exited || !candidate.entered ||
               !candidate.counted || !candidate.idle || candidate.waiting_queue!=queue || !candidate.wait_ticket ||
               candidate.roots[2].bits || (candidate.wait_deadline && now>=*candidate.wait_deadline))continue;
            const auto owner_pool=heap.find(candidate.pool());
            if(owner_pool==heap.end() || !owner_pool->second.pool || owner_pool->second.pool->shutdown())continue;
            if(!selected || (backing.fifo->fair()?candidate.wait_ticket<selected->wait_ticket:candidate.wait_ticket>selected->wait_ticket)) {
                selected=&candidate;selected_task=entry->id;
            }
        }
        if(!selected)return false;
        // This is the transfer's commit point: the owned consumer roots the job
        // before it becomes runnable. No queue element or producer buffer exists.
        selected->roots[2]=Value::reference(job);
        scheduler->unpark(selected_task);
        return true;
    }
    Value queue_call(ObjectId pool, std::string_view name, std::string_view signature, ObjectId argument=0) {
        auto &value = pool_queue(pool);
        if(!native_pool_queue(pool)) {
            const auto queue=pool_state(pool).queue();
            const std::array<Value,1> tail{Value::reference(argument)};
            PoolCallbackBoundary boundary(*this);
            return call_virtual_named(queue,name,signature,
                (name=="offer" || name=="remove")?std::span<const Value>(tail):std::span<const Value>{});
        }
        const std::array<Value,2> args{Value::reference(pool_state(pool).queue()),Value::reference(argument)};
        const auto revision=value.fifo->revision();
        try {
            const auto result = value.fifo->invoke(runtime,value.type,name,signature,
                std::span<const Value>(args).first(argument || name=="offer" || name=="remove" ? 2 : 1),
                {value.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length},
                [&](ObjectId left,ObjectId right){return key_equal(left,right);},
                [&](ObjectId job){return synchronous_handoff(args[0].bits,job);});
            if (!result) fail("EXECUTOR_QUEUE_UNSUPPORTED", "Executor backing queue operation is unsupported");
            if(revision!=value.fifo->revision())wake_queue_pools(args[0].bits);
            return *result;
        } catch(...) {
            const auto error=std::current_exception();
            if(revision!=value.fifo->revision())try{wake_queue_pools(args[0].bits);}catch(...){}
            std::rethrow_exception(error);
        }
    }
    std::optional<Value> native_queue_call(ObjectId receiver,std::string_view queue_owner,std::string_view name,
        std::string_view signature,std::span<const Value> args) {
        auto &value=object(receiver);
        if(!value.fifo)fail("STATE","Queue has no native storage");
        if((name=="take" && signature=="()Ljava/lang/Object;") ||
           (name=="poll" && signature=="(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;")) {
            if(queue_owner!="Ljava/util/concurrent/BlockingQueue;" && queue_owner!=blocking_queue_type && queue_owner!=synchronous_queue_type)return {};
            std::optional<std::int64_t> nanos;
            if(name=="poll") {
                const auto &unit=object(reference(args[2]));
                if(unit.type!=time_unit_type || !unit.enumeration)fail("ENUM_STATE","Invalid queue timeout TimeUnit");
                nanos=convert_time_unit(std::bit_cast<std::int64_t>(wide(args[1])),unit.enumeration->ordinal(),0);
            }
            return delegated_queue_read(receiver,nanos);
        }
        const auto revision=value.fifo->revision();
        try {
            const auto result=value.fifo->invoke(runtime,queue_owner,name,signature,args,
                {value.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length},
                [&](ObjectId a,ObjectId b){return key_equal(a,b);},
                [&](ObjectId job){return synchronous_handoff(receiver,job);});
            if(revision!=value.fifo->revision())wake_queue_pools(receiver);
            return result;
        } catch(...) {
            const auto failure=std::current_exception();
            if(revision!=value.fifo->revision())try{wake_queue_pools(receiver);}catch(...){}
            std::rethrow_exception(failure);
        }
    }
    void wake_pool(ObjectId id, bool interrupt=false) {
        auto &pool = pool_state(id);
        for (const auto root : pool.workers()) if (root.bits) {
            auto &value = object(root.bits);
            if (!value.pool_worker) fail("EXECUTOR_STATE", "Executor worker has no authenticated state");
            if(value.pool_worker->exited)continue;
            const auto thread = value.pool_worker->thread();
            for (const auto &task : tasks) if (task && thread && task->context.thread_object==thread) {
                if (interrupt) { task->context.interrupted=true;scheduler->wake(task->id); }
                else scheduler->unpark(task->id);
                break;
            }
        }
    }
    void wake_queue_pools(ObjectId queue) {
        for (auto &[id,value] : heap)
            if(value.pool && value.pool->initialized()) {
                bool waiting=value.pool->queue()==queue;
                for(const auto root:value.pool->workers())if(root.bits) {
                    const auto &worker=object(root.bits);
                    if(worker.pool_worker && worker.pool_worker->waiting_queue==queue)waiting=true;
                }
                if(waiting)wake_pool(id);
            }
    }
    struct PoolCallbackBoundary {
        std::optional<SuspendCoreBarrier> allow;
        explicit PoolCallbackBoundary(Impl &owner) {
            auto &context=owner.current_context();
            if(context.barriers) {
                if(context.barriers!=1 || owner.execution_owner)owner.require_suspendable();
                bool monitor_held=false;
                for(const auto *frame:context.frames)monitor_held=monitor_held || frame->monitor_count!=0;
                // Keep the core barrier while a caller holds a monitor. Genuine
                // callbacks may compute/admit work, but cannot switch contexts.
                if(!monitor_held)allow.emplace(context);
            } else {
                if(owner.execution_owner)fail("THREAD_BLOCKING_UNSUPPORTED", "Executor callbacks require the owned runtime");
                for(const auto *frame:context.frames)if(frame->monitor_count)
                    fail("THREAD_BLOCKING_UNSUPPORTED", "Executor callback while holding a monitor is unsupported");
            }
        }
    };
    void pool_hook(ObjectId pool,std::string_view name,std::string_view signature,std::span<const Value> args={}) {
        if (object_override(pool,name,signature)) {
            PoolCallbackBoundary boundary(*this);
            (void)runtime.invoke_virtual_named(pool,name,signature,args);
        }
    }
    ObjectId default_factory_thread(ObjectId factory,ObjectId target) {
        auto &value=object(factory);
        if(!value.factory) fail("THREAD_FACTORY_UNSUPPORTED", "Default factory lacks authenticated state");
        Object thread;thread.type="Ljava/lang/Thread;";thread.thread=std::make_unique<ThreadState>();
        thread.thread->target=target;thread.thread->group=value.factory->group;
        thread.thread->initialized=true;thread.thread->daemon=false;
        const auto id=allocate(std::move(thread));
        runtime.retain(id);
        struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} release{runtime,id};
        std::u16string name=u"pool-";
        for(auto c:std::to_string(factory))name.push_back(c);
        name+=u"-thread-";
        for(auto c:std::to_string(++value.factory->sequence))name.push_back(c);
        thread_state(id).name=runtime.new_string(name);
        return id;
    }
    bool pool_worker_admissible(ObjectId id,ObjectId first) {
        auto &pool=pool_state(id);
        if(tasks_closing || pool.stopped())return false;
        const bool empty=pool.shutdown() && !first?pool_queue_empty(id):false;
        return !tasks_closing && !pool.stopped() && !(pool.shutdown() && (first || empty));
    }
    bool add_pool_worker(ObjectId id,ObjectId first,bool core) {
        auto &pool=pool_state(id);
        if(!pool_worker_admissible(id,first))return false;
        if(pool.count()>=(core?pool.core():pool.maximum()))return false;
        Value *slot=nullptr;for(auto &root:pool.workers())if(!root.bits){slot=&root;break;}
        if(!slot)fail("TASK_LIMIT", "Executor worker bound of 16 is exhausted");
        PoolCallbackBoundary boundary(*this);
        Object value;value.type=pool_worker_type;value.pool_worker=std::make_unique<PoolWorker>();
        value.pool_worker->roots[0]=Value::reference(id);value.pool_worker->roots[2]=Value::reference(first);
        const auto worker=allocate(std::move(value));
        runtime.retain(worker); // start overrides may yield until this very Worker is reaped.
        struct ReleaseWorker {ManagedRuntime &runtime;ObjectId worker;~ReleaseWorker(){runtime.release(worker);}} release_worker{runtime,worker};
        *slot=Value::reference(worker); // Reserve/root only after fallible pin acquisition.
        object(worker).pool_worker->counted=true;++pool.live_workers;
        try {
            const std::array<Value,1> argument{Value::reference(worker)};
            const auto thread=reference(runtime.invoke_virtual_named(pool.factory(),"newThread",
                "(Ljava/lang/Runnable;)Ljava/lang/Thread;",argument));
            if(!thread){pool_worker_exit(worker);if(slot->bits==worker)*slot={};try_terminate_pool(id);return false;}
            runtime.retain(thread);
            struct ReleaseThread {ManagedRuntime &runtime;ObjectId id;~ReleaseThread(){runtime.release(id);}} thread_root{runtime,thread};
            if(!pool_worker_admissible(id,first) || pool.count()>pool.maximum()) {
                pool_worker_exit(worker);if(slot->bits==worker)*slot={};try_terminate_pool(id);return false;
            }
            auto &state=thread_state(thread);
            if(state.lifecycle!=ThreadState::Lifecycle::fresh || state.pool_worker)
                runtime.raise("Ljava/lang/IllegalThreadStateException;");
            object(worker).pool_worker->roots[1]=Value::reference(thread);
            state.pool_worker=worker;
            pool.largest=std::max(pool.largest,pool.count());
            try {
                (void)runtime.invoke_virtual_named(thread,"start","()V");
                if(state.lifecycle==ThreadState::Lifecycle::fresh)
                    fail("THREAD_FACTORY_UNSUPPORTED", "Factory Thread.start returned without starting the original Thread");
            } catch (...) {if(state.lifecycle==ThreadState::Lifecycle::fresh)state.pool_worker=0;throw;}
            return true;
        } catch (...) {
            const auto thread=object(worker).pool_worker->thread();
            // A real overriding start may already have started before throwing.
            // Its running worker remains registered; NEW admission rolls back.
            if(!thread || thread_state(thread).lifecycle==ThreadState::Lifecycle::fresh) {
                pool_worker_exit(worker);if(slot->bits==worker)*slot={};try_terminate_pool(id);
            }
            throw;
        }
    }
    void try_terminate_pool(ObjectId id) {
        auto &pool=pool_state(id);
        if(tasks_closing)return;
        const bool empty=pool.shutdown()?pool_queue_empty(id):false;
        if(pool.shutdown() && !pool.count() && empty && !pool.terminated && !pool.terminating) {
            pool.terminating=true;
            struct End {ThreadPoolState &pool;~End(){pool.terminated=true;pool.terminating=false;}} end{pool};
            pool_hook(id,"terminated","()V");
        }
    }
    void pool_maintenance(ObjectId id, bool abrupt=false) {
        auto &pool=pool_state(id);
        if(tasks_closing)return;
        const bool previous=pool_maintenance_active;pool_maintenance_active=true;
        struct EndMaintenance {bool &flag;bool previous;~EndMaintenance(){flag=previous;}} end_maintenance{pool_maintenance_active,previous};
        pool.maintenance=false;
        // Terminal slots may be reclaimed on main, but termination hooks belong
        // to process-worker-exit (or an explicit caller shutdown), never here.
        if(!pool.shutdown() && abrupt && pool.count()<pool.core())
            (void)add_pool_worker(id,0,true);
        else if(!pool.stopped()) {
            const bool empty=pool_queue_empty(id);
            if(!empty && !pool.stopped() && !pool.count())(void)add_pool_worker(id,0,false);
        }
    }
    void pool_worker_exit(ObjectId worker) noexcept {
        const auto found=heap.find(worker);
        if(found==heap.end() || !found->second.pool_worker)std::terminate();
        auto &state=*found->second.pool_worker;
        if(state.exited)return;
        const auto pool_owner=heap.find(state.pool());
        if(pool_owner==heap.end() || !pool_owner->second.pool)std::terminate();
        auto &pool=*pool_owner->second.pool;
        if(state.counted){if(!pool.live_workers)std::terminate();--pool.live_workers;state.counted=false;}
        if(state.active){--pool.active;state.active=false;}
        state.exited=true;state.idle=false;state.waiting_queue=0;state.wait_ticket=0;state.wait_deadline.reset();
        state.roots[2]={};state.roots[3]={};state.roots[4]={};
        pool.maintenance=true;
    }
    void pool_wait(ObjectId worker,std::optional<std::chrono::steady_clock::time_point> deadline,bool yield=false,ObjectId delegated_queue=0) {
        auto &context=current_context();
        auto &state=*object(worker).pool_worker;
        if(!background() || execution_owner || !scheduler || context.barriers ||
           context.thread_object!=state.thread() || thread_state(state.thread()).pool_worker!=worker)
            fail("THREAD_BLOCKING_UNSUPPORTED", "Executor wait requires its actual owned factory Thread without extra barriers");
        for(const auto *frame:context.frames)if(frame->monitor_count)
            fail("THREAD_BLOCKING_UNSUPPORTED", "Executor wait while holding a monitor is unsupported");
        (void)scheduler->current();
        context.last_result=Value::nothing();
        if(!task_work_remaining)fail("BUDGET", "Executor worker batch budget exhausted");
        --task_work_remaining;
        if(context.interrupted && !yield){context.interrupted=false;return;}
        if(!yield && deadline && std::chrono::steady_clock::now()>=*deadline)return;
        state.idle=true;
        struct End {PoolWorker &worker;~End(){worker.idle=false;worker.waiting_queue=0;worker.wait_ticket=0;worker.wait_deadline.reset();}} end{state};
        if(!yield) {
            const auto queue=delegated_queue?delegated_queue:pool_state(state.pool()).queue();
            auto &backing=object(queue);
            state.waiting_queue=queue;state.wait_deadline=deadline;
            if(backing.fifo && backing.fifo->synchronous()) {
                state.wait_ticket=backing.fifo->next_wait_ticket();
                state.waiting_queue=queue;state.wait_deadline=deadline;
            }
        }
        if(yield)scheduler->yield();else if(deadline)scheduler->park_until(*deadline);else scheduler->park();
        // STOP after a committed handoff must interrupt that assigned job rather
        // than consume its interrupt as an unsuccessful idle wait.
        if(!delegated_queue && (!state.roots[2].bits || !pool_state(state.pool()).stopped()))context.interrupted=false;
    }
    Value delegated_queue_read(ObjectId queue,std::optional<std::int64_t> nanos) {
        require_suspendable();
        auto &context=current_context();
        if(!background() || !context.thread_object)fail("THREAD_BLOCKING_UNSUPPORTED","Queue read requires an owned executor worker");
        const auto worker=thread_state(context.thread_object).pool_worker;
        if(!worker || native_pool_queue(object(worker).pool_worker->pool()))
            fail("THREAD_BLOCKING_UNSUPPORTED","Blocking queue gateway requires a managed executor queue delegation");
        auto &state=*object(worker).pool_worker;
        auto &backing=object(queue);
        if(backing.type!=blocking_queue_type || !backing.fifo || !backing.fifo->initialized())
            fail("THREAD_BLOCKING_UNSUPPORTED","Delegated blocking read requires an initialized LinkedBlockingQueue");
        check_interruption(context);
        const auto configuration=pool_state(state.pool()).configuration;
        using Clock=std::chrono::steady_clock;
        auto previous=Clock::now();auto remaining=nanos;
        SuspendCoreBarrier allow(context);
        for(;;) {
            check_interruption(context);
            auto &pool=pool_state(state.pool());
            if(pool.stopped() || configuration!=pool.configuration || (pool.shutdown() && backing.fifo->references().empty()))
                runtime.raise("Ljava/lang/InterruptedException;");
            const std::array<Value,1> args{Value::reference(queue)};
            const auto value=backing.fifo->invoke(runtime,backing.type,"poll","()Ljava/lang/Object;",args,
                {backing.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length});
            if(!value)fail("STATE","LinkedBlockingQueue poll is unavailable");
            if(reference(*value)) {wake_queue_pools(queue);return *value;}
            std::optional<Clock::time_point> deadline;
            if(remaining) {
                const auto now=Clock::now();const auto elapsed=now-previous;previous=now;
                if(*remaining<=0 || elapsed>=std::chrono::nanoseconds(*remaining))return Value::reference(0);
                *remaining-=std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count();
                const auto chunk=std::min(std::chrono::nanoseconds(*remaining),
                    std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::hours(24)));
                if(chunk>Clock::time_point::max()-now)fail("THREAD_TIME_UNSUPPORTED","Queue timer cannot represent the next wait chunk");
                deadline=now+std::chrono::ceil<Clock::duration>(chunk);
            }
            pool_wait(worker,deadline,false,queue);
        }
    }
    void run_pool_worker(ObjectId worker) {
        auto &state=*object(worker).pool_worker;
        auto &pool=pool_state(state.pool());
        auto &context=current_context();
        if(!background() || context.barriers || context.thread_object!=state.thread() ||
           thread_state(state.thread()).pool_worker!=worker || state.entered)
            fail("EXECUTOR_WORKER_STATE", "Worker.run must enter once through its real factory Thread and wrappers");
        for(const auto *frame:context.frames)if(frame->monitor_count)
            fail("THREAD_BLOCKING_UNSUPPORTED", "Worker.run while holding a monitor is unsupported");
        state.entered=true;state.abrupt=true;
        struct Exit {Impl &owner;ObjectId worker;~Exit(){owner.pool_worker_exit(worker);}} exit{*this,worker};
        std::optional<std::chrono::steady_clock::time_point> deadline;
        std::uint64_t configuration=pool.configuration;
        try {
        for(;;) {
            ObjectId job=state.roots[2].bits;
            state.roots[2]={};
            if(!job) {
                if(pool.stopped() || (pool.shutdown() && pool_queue_empty(state.pool())))break;
                if(pool.count()>pool.maximum())break;
                if(native_pool_queue(state.pool()))job=reference(queue_call(state.pool(),"poll","()Ljava/lang/Object;"));
                else {
                    const bool timed=pool.timeout() || pool.count()>pool.core();
                    const auto queue=pool.queue();
                    const auto nanos=pool.keep_alive();
                    const auto fetch_configuration=pool.configuration;
                    try {
                        PoolCallbackBoundary boundary(*this);
                        if(timed) {
                            const std::array<Value,2> arguments{Value::wide(static_cast<std::uint64_t>(nanos)),Value::reference(time_unit(0))};
                            job=reference(call_virtual_named(queue,"poll","(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;",arguments));
                        } else job=reference(call_virtual_named(queue,"take","()Ljava/lang/Object;"));
                    } catch(const JavaException &error) {
                        if(!subtype(object(error.object).type,"Ljava/lang/InterruptedException;"))throw;
                        continue;
                    }
                    if(!job) {
                        if(timed) {
                            const bool empty=pool.count()>1?false:pool_queue_empty(state.pool());
                            if(fetch_configuration==pool.configuration && (pool.timeout() || pool.count()>pool.core()) &&
                                (pool.count()>1 || empty))break;
                        }
                        pool_wait(worker,{},true);continue;
                    }
                }
            }
            if(job) {
                state.roots[3]=Value::reference(job);state.active=true;++pool.active;
                if(!pool.stopped())context.interrupted=false;
                {
                    struct JobEnd {ThreadPoolState &pool;PoolWorker &worker;~JobEnd(){--pool.active;worker.active=false;++pool.completed;worker.roots[3]={};worker.roots[4]={};}} job_end{pool,state};
                    const std::array<Value,2> before{Value::reference(state.thread()),Value::reference(job)};
                    pool_hook(state.pool(),"beforeExecute","(Ljava/lang/Thread;Ljava/lang/Runnable;)V",before);
                    try {run_runnable(job,true);}
                    catch(const JavaException &error) {
                        state.roots[4]=Value::reference(error.object);
                        const std::array<Value,2> after{Value::reference(job),Value::reference(error.object)};
                        pool_hook(state.pool(),"afterExecute","(Ljava/lang/Runnable;Ljava/lang/Throwable;)V",after);
                        throw;
                    }
                    const std::array<Value,2> after{Value::reference(job),Value::reference(0)};
                    pool_hook(state.pool(),"afterExecute","(Ljava/lang/Runnable;Ljava/lang/Throwable;)V",after);
                }
                deadline.reset();pool_wait(worker,{},true);continue;
            }
            const bool timed=pool.timeout() || pool.count()>pool.core();
            const auto now=std::chrono::steady_clock::now();
            if(configuration!=pool.configuration){configuration=pool.configuration;deadline.reset();}
            if(timed) {
                if(!deadline) {
                    const auto remaining=std::chrono::steady_clock::time_point::max()-now;
                    const auto ns=std::chrono::nanoseconds(pool.keep_alive());
                    deadline=ns>=remaining?std::chrono::steady_clock::time_point::max():now+ns;
                }
                if(now>=*deadline && (pool.count()>1 || pool_queue_empty(state.pool())))break;
            } else deadline.reset();
            pool_wait(worker,deadline);
        }
        state.abrupt=false;
        } catch(const std::exception &) {
            // Java/Dex/ordinary host failures exit the logical worker before
            // propagating through genuine Thread wrappers. Cancellation is a
            // private non-std signal: only the noexcept RAII path handles it.
            pool_worker_exit(worker);
            try_terminate_pool(state.pool());
            throw;
        }
        pool_worker_exit(worker);
        try_terminate_pool(state.pool());
    }
    void reject_pool_task(ObjectId id,ObjectId job) {
        PoolCallbackBoundary boundary(*this);
        const std::array<Value,2> args{Value::reference(job),Value::reference(id)};
        (void)runtime.invoke_virtual_named(pool_state(id).handler(),"rejectedExecution",
            "(Ljava/lang/Runnable;Ljava/util/concurrent/ThreadPoolExecutor;)V",args);
    }
    std::optional<Value> invoke_pool(ObjectId id,std::string_view name,std::string_view signature,
                                    std::span<const Value> args,std::optional<std::uint32_t> unit) {
        auto &pool=pool_state(id);
        if(name=="execute" && signature=="(Ljava/lang/Runnable;)V") {
            const auto job=reference(args[1]);if(!job)runtime.raise("Ljava/lang/NullPointerException;");
            if(!pool.shutdown() && pool.count()<pool.core() && add_pool_worker(id,job,true))return Value::nothing();
            if(!pool.shutdown() && word(queue_call(id,"offer","(Ljava/lang/Object;)Z",job))) {
                if(pool.shutdown() && word(queue_call(id,"remove","(Ljava/lang/Object;)Z",job)))reject_pool_task(id,job);
                else if(!pool.count())(void)add_pool_worker(id,0,false);
                if(!native_pool_queue(id) || !pool_queue(id).fifo->synchronous())wake_pool(id);
                return Value::nothing();
            }
            if(!add_pool_worker(id,job,false))reject_pool_task(id,job);
            return Value::nothing();
        }
        if((name=="beforeExecute" && signature=="(Ljava/lang/Thread;Ljava/lang/Runnable;)V") ||
           (name=="afterExecute" && signature=="(Ljava/lang/Runnable;Ljava/lang/Throwable;)V") ||
           (name=="terminated" && signature=="()V"))return Value::nothing();
        if(name=="prestartCoreThread" && signature=="()Z")return Value::word(add_pool_worker(id,0,true));
        if(name=="prestartAllCoreThreads" && signature=="()I") {
            std::uint32_t started=0;while(add_pool_worker(id,0,true))++started;return Value::word(started);
        }
        if(name=="shutdown" && signature=="()V") {
            pool.begin_shutdown();wake_pool(id);try_terminate_pool(id);return Value::nothing();
        }
        if(name=="shutdownNow" && signature=="()Ljava/util/List;") {
            if(!native_pool_queue(id))fail("EXECUTOR_QUEUE_UNSUPPORTED","Managed queue shutdownNow requires virtual drainTo/residual removal support");
            pool.begin_shutdown(true);wake_pool(id,true);
            Object result;result.type="Ljava/util/ArrayList;";result.list=std::make_unique<ManagedList>(false);
            const auto list=allocate(std::move(result));runtime.retain(list);
            struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} release{runtime,list};
            auto &value=object(list);
            const auto count=pool_queue_size(id);
            const std::array<Value,2> init{Value::reference(list),Value::word(static_cast<std::uint32_t>(count))};
            (void)value.list->invoke(runtime,value.type,"<init>","(I)V",init,
                {value.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length});
            while(!pool_queue_empty(id)) {
                const auto job=queue_call(id,"poll","()Ljava/lang/Object;");
                const std::array<Value,2> add{Value::reference(list),job};
                (void)value.list->invoke(runtime,value.type,"add","(Ljava/lang/Object;)Z",add,
                    {value.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length});
            }
            try_terminate_pool(id);return Value::reference(list);
        }
        if(name=="remove" && signature=="(Ljava/lang/Runnable;)Z") {
            const auto result=queue_call(id,"remove","(Ljava/lang/Object;)Z",reference(args[1]));
            wake_pool(id);try_terminate_pool(id);return result;
        }
        if(name=="getTaskCount" && signature=="()J") {
            const auto queued=pool_queue_size(id);
            std::uint64_t pending=0;for(auto root:pool.workers())if(root.bits && object(root.bits).pool_worker->roots[2].bits)++pending;
            return Value::wide(pool.completed+pool.active+pending+queued);
        }
        const auto previous_core=pool.core();
        const auto configuration=pool.configuration;
        const auto result=pool.invoke(runtime,name,signature,args,unit);
        if(result && configuration!=pool.configuration) {
            wake_pool(id);
            if(pool.core()>previous_core && !pool.shutdown()) {
                auto remaining=std::min<std::size_t>(pool.core()-previous_core,pool_queue_size(id));
                while(remaining-- && add_pool_worker(id,0,true)){}
            }
        }
        return result;
    }
    FutureState &future_state(ObjectId id,bool initialized=true) {
        auto &value=object(id);
        if(!value.future)fail("FUTURE_STATE", "FutureTask lacks authenticated runtime state");
        auto &state=*value.future;
        if(initialized && !state.initialized)fail("FUTURE_STATE", "FutureTask constructor has not completed");
        if(state.state==FutureState::State::aborted) {
            if(state.host_failure)std::rethrow_exception(state.host_failure);
            fail("FUTURE_ABORTED", "Future runner was aborted outside Java completion semantics");
        }
        return state;
    }
    void wake_future(FutureState &state) noexcept {
        if(!scheduler)return;
        try {
            for(const auto id:state.waiter_tasks)if(id && scheduler->contains(id))scheduler->unpark(id);
        } catch(...) {std::terminate();}
    }
    bool complete_future(ObjectId receiver,FutureState::State terminal,Value outcome,bool interrupt=false) {
        auto &state=future_state(receiver);
        if(state.state!=FutureState::State::pending)return false;
        const bool has_done=object(receiver).async_future_owner || bool(object_override(receiver,"done","()V"));
        std::optional<SuspendCoreBarrier> allow;
        if(has_done) {require_suspendable();allow.emplace(current_context());}
        // Publish the winning outcome before notification/done. Cancellation is
        // terminal even when the original runner is still executing managed code.
        state.state=terminal;
        if(terminal==FutureState::State::normal)state.roots[2]=outcome;
        else if(terminal==FutureState::State::failed)state.roots[3]=outcome;
        if(interrupt && state.runner_active) {
            if(auto *context=live_thread_context(state.roots[4].bits)) {
                context->interrupted=true;
                for(const auto &task:tasks)if(task && &task->context==context){scheduler->wake(task->id);break;}
            }
        }
        wake_future(state);
        struct ClearAction {FutureState &state;~ClearAction(){state.roots[0]={};state.roots[1]={};}} clear{state};
        if(object(receiver).async_future_owner)async_future_done(receiver);
        else if(has_done)(void)runtime.invoke_virtual_named(receiver,"done","()V");
        return true;
    }
    bool run_future(ObjectId receiver,bool reset) {
        auto &state=future_state(receiver);
        if(state.state!=FutureState::State::pending || state.runner_active)return false;
        require_suspendable();
        SuspendCoreBarrier allow(current_context());
        const auto thread=runtime.current_thread();
        state.runner_active=true;state.roots[4]=Value::reference(thread);
        state.roots[5]=state.roots[0];state.roots[6]=state.roots[1];
        struct RunnerEnd {
            Impl &owner;FutureState &state;bool aborted=true;
            ~RunnerEnd() {
                state.runner_active=false;state.roots[4]={};state.roots[5]={};state.roots[6]={};state.roots[7]={};
                if(aborted && state.state==FutureState::State::pending) {
                    state.state=FutureState::State::aborted;state.roots[0]={};state.roots[1]={};owner.wake_future(state);
                }
            }
        } end{*this,state};
        try {
            bool failed=false;
            try {
                if(state.runnable){run_runnable(state.roots[5].bits,true);state.roots[7]=state.roots[6];}
                else state.roots[7]=runtime.invoke_virtual_named(state.roots[5].bits,"call","()Ljava/lang/Object;");
            } catch(const JavaException &error) {failed=true;state.roots[7]=Value::reference(error.object);}
            if(failed) {
                const std::array<Value,1> args{state.roots[7]};
                (void)runtime.invoke_virtual_named(receiver,"setException","(Ljava/lang/Throwable;)V",args);
            } else if(!reset) {
                const std::array<Value,1> args{state.roots[7]};
                (void)runtime.invoke_virtual_named(receiver,"set","(Ljava/lang/Object;)V",args);
            }
            end.aborted=false;
            return reset && !failed && state.state==FutureState::State::pending;
        } catch(const JavaException &) {
            // A real protected set/setException/done override may throw; do not
            // reinterpret its Java exception as a second callable completion.
            end.aborted=false;throw;
        } catch(const std::exception &) {
            if(state.state==FutureState::State::pending)state.host_failure=std::current_exception();
            throw;
        }
    }
    Value report_future(FutureState &state) {
        if(state.state==FutureState::State::normal)return state.roots[2];
        if(state.state==FutureState::State::cancelled)runtime.raise(cancellation_type);
        if(state.state==FutureState::State::failed) {
            Object error;error.type=execution_exception_type;error.cause=state.roots[3].bits;
            const auto id=allocate(std::move(error));++metrics.exceptions;current_context().last_exception=id;
            throw JavaException(id);
        }
        if(state.state==FutureState::State::aborted) {
            if(state.host_failure)std::rethrow_exception(state.host_failure);
            fail("FUTURE_ABORTED", "Future runner was aborted outside Java completion semantics");
        }
        fail("FUTURE_STATE", "Future result is not terminal");
    }
    void charge_future_wait() {
        auto &context=current_context();
        if(!context.remaining)fail("BUDGET", "Future wait instruction allowance exhausted");
        --context.remaining;
        if(scheduled_task()) {
            if(!task_work_remaining)fail("BUDGET", "Future wait batch allowance exhausted");
            --task_work_remaining;
        } else if(main_callback_inflight) {
            if(!main_callback_work_remaining)fail("BUDGET", "Future main-callback wait allowance exhausted");
            --main_callback_work_remaining;
        }
    }
    Value get_future(ObjectId receiver,std::optional<std::int64_t> nanos) {
        auto &state=future_state(receiver);
        if(state.state!=FutureState::State::pending)return report_future(state);
        require_suspendable(); // A refusal must not consume the caller's interrupt.
        auto &context=current_context();
        check_interruption(context);
        if(nanos && *nanos<=0)runtime.raise(timeout_exception_type);
        SuspendCoreBarrier allow(context);
        using Clock=std::chrono::steady_clock;
        auto previous=Clock::now();
        auto remaining=nanos;
        const auto thread=runtime.current_thread();
        const auto task_id=background()?scheduler->current():0;
        std::size_t slot=state.waiters.size();
        for(std::size_t at=0;at<state.waiters.size();++at)if(!state.waiters[at].bits){slot=at;break;}
        if(slot==state.waiters.size())fail("FUTURE_LIMIT", "Future waiter bound of 17 is exhausted");
        state.waiters[slot]=Value::reference(thread);state.waiter_tasks[slot]=task_id;
        struct Remove {FutureState &state;std::size_t slot;~Remove(){state.waiters[slot]={};state.waiter_tasks[slot]=0;}} remove{state,slot};
        for(;;) {
            if(state.state!=FutureState::State::pending)return report_future(state);
            check_interruption(context);
            std::optional<Clock::time_point> deadline;
            if(remaining) {
                const auto now=Clock::now();const auto elapsed=now-previous;previous=now;
                if(elapsed>=std::chrono::nanoseconds(*remaining))runtime.raise(timeout_exception_type);
                *remaining-=std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count();
                // Keep the original remaining duration across all wakeups. Chunk
                // very large waits instead of overflowing/clamping the deadline.
                const auto chunk=std::min(std::chrono::nanoseconds(*remaining),
                    std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::hours(24)));
                if(chunk>Clock::time_point::max()-now)fail("THREAD_TIME_UNSUPPORTED", "Future timer range cannot represent the next bounded wait chunk");
                deadline=now+std::chrono::ceil<Clock::duration>(chunk);
            }
            charge_future_wait();
            if(background()) {
                if(deadline)scheduler->park_until(*deadline);else scheduler->park();
            } else {
                if(scheduler && pump_task())continue;
                auto wake=Clock::now()+std::chrono::milliseconds(10);
                if(deadline)wake=std::min(wake,*deadline);
                if(scheduler)if(const auto next=scheduler->next_deadline();next && *next>Clock::now())wake=std::min(wake,*next);
                const auto now=Clock::now();if(wake>now)std::this_thread::sleep_for(wake-now);
            }
        }
    }
    std::optional<Value> invoke_future(ObjectId receiver,std::string_view name,std::string_view signature,std::span<const Value> args) {
        if(name=="<init>" && (signature=="(Ljava/util/concurrent/Callable;)V" ||
            signature=="(Ljava/lang/Runnable;Ljava/lang/Object;)V")) {
            auto &state=future_state(receiver,false);
            if(state.initialized)fail("STATE", "FutureTask constructor invoked more than once");
            const auto action=reference(args[1]);(void)object(action);
            state.runnable=signature=="(Ljava/lang/Runnable;Ljava/lang/Object;)V";
            state.roots[0]=Value::reference(action);state.roots[1]=state.runnable?args[2]:Value::reference(0);
            state.initialized=true;return Value::nothing();
        }
        auto &state=future_state(receiver);
        if(name=="run" && signature=="()V"){(void)run_future(receiver,false);return Value::nothing();}
        if(name=="runAndReset" && signature=="()Z")return Value::word(run_future(receiver,true));
        if(name=="done" && signature=="()V")return Value::nothing();
        if(name=="isDone" && signature=="()Z")return Value::word(state.state!=FutureState::State::pending);
        if(name=="isCancelled" && signature=="()Z")return Value::word(state.state==FutureState::State::cancelled);
        if(name=="cancel" && signature=="(Z)Z")return Value::word(complete_future(receiver,FutureState::State::cancelled,Value::reference(0),word(args[1])!=0));
        if(name=="set" && signature=="(Ljava/lang/Object;)V") {
            (void)complete_future(receiver,FutureState::State::normal,args[1]);return Value::nothing();
        }
        if(name=="setException" && signature=="(Ljava/lang/Throwable;)V") {
            (void)complete_future(receiver,FutureState::State::failed,args[1]);return Value::nothing();
        }
        if(name=="get" && signature=="()Ljava/lang/Object;")return get_future(receiver,{});
        if(name=="get" && signature=="(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;") {
            const auto &unit=object(reference(args[2]));
            if(unit.type!=time_unit_type || !unit.enumeration)fail("ENUM_STATE", "Invalid Future timeout TimeUnit");
            return get_future(receiver,convert_time_unit(std::bit_cast<std::int64_t>(wide(args[1])),unit.enumeration->ordinal(),0));
        }
        return {};
    }
    AsyncTaskState &async_state(ObjectId id,bool initialized=true) {
        auto &value=object(id);
        if(!value.async_task)fail("ASYNC_STATE", "AsyncTask lacks authenticated state");
        if(initialized && !value.async_task->initialized)fail("ASYNC_STATE", "AsyncTask constructor has not completed");
        return *value.async_task;
    }
    void async_main_owner() {
        if(execution_owner || background())fail("ASYNC_THREAD_STATE", "AsyncTask lifecycle entry requires the owned main context");
        if(scheduler)(void)scheduler->current();
    }
    ObjectId async_sdk_object(std::string_view type,AsyncSdkState::Kind kind) {
        Object value;value.type=type;value.async_sdk=std::make_unique<AsyncSdkState>(kind);
        return allocate(std::move(value));
    }
    ObjectId async_pool(bool backup) {
        const auto position=backup?2U:0U;
        if(async_globals[position])return async_globals[position];
        Object queue;queue.type=backup?blocking_queue_type:synchronous_queue_type;
        queue.fifo=std::make_unique<ManagedQueue>(true,!backup);
        const std::array<Value,1> args{Value::reference(0)};
        (void)queue.fifo->invoke(runtime,queue.type,"<init>","()V",args,
            {queue.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length});
        const auto queue_id=allocate(std::move(queue));runtime.retain(queue_id);
        struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} release{runtime,queue_id};
        Object pool;pool.type=thread_pool_type;pool.pool=std::make_unique<ThreadPoolState>();
        ObjectId handler=async_globals[4];
        if(backup) {
            Object policy;policy.type=abort_policy_type;policy.abort_policy=std::make_unique<AbortPolicy>();
            (void)policy.abort_policy->invoke(runtime,abort_policy_type,"<init>","()V");handler=allocate(std::move(policy));
        }
        runtime.retain(handler);
        struct ReleaseHandler {ManagedRuntime &runtime;ObjectId id;~ReleaseHandler(){runtime.release(id);}} release_handler{runtime,handler};
        pool.pool->initialize(backup?5U:1U,backup?5U:20U,3000000000LL,queue_id,async_globals[3],handler);
        if(backup) {
            const std::array<Value,2> timeout{Value::reference(0),Value::word(1)};
            (void)pool.pool->invoke(runtime,"allowCoreThreadTimeOut","(Z)V",timeout,{});
        }
        async_globals[position]=allocate(std::move(pool));
        return async_globals[position];
    }
    void ensure_async_runtime() {
        if(async_initialized)return;
        if(async_initializing)fail("ASYNC_STATE", "Recursive AsyncTask static initialization");
        async_initializing=true;
        try {
            async_globals[3]=async_sdk_object(async_factory_type,AsyncSdkState::Kind::factory);
            async_globals[4]=async_sdk_object(async_backup_policy_type,AsyncSdkState::Kind::backup_policy);
            async_globals[1]=async_sdk_object(async_serial_type,AsyncSdkState::Kind::serial);
            (void)async_pool(false);async_initialized=true;async_initializing=false;
        } catch(...) {async_globals={};async_initializing=false;throw;}
    }
    ObjectId async_status(std::size_t ordinal) {
        static constexpr std::array<std::string_view,3> names{"PENDING","RUNNING","FINISHED"};
        if(ordinal>=names.size())fail("ENUM_STATE", "Invalid AsyncTask status ordinal");
        if(!async_statuses[ordinal]) {
            const auto ascii=names[ordinal];const auto name=runtime.new_string(std::u16string(ascii.begin(),ascii.end()));
            runtime.retain(name);
            struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} release{runtime,name};
            Object value;value.type=async_status_type;value.enumeration=std::make_unique<ManagedEnum>();
            const std::array args{Value::reference(0),Value::reference(name),Value::word(static_cast<std::uint32_t>(ordinal))};
            (void)value.enumeration->invoke(runtime,"<init>","(Ljava/lang/String;I)V",args);
            async_statuses[ordinal]=allocate(std::move(value));
        }
        return async_statuses[ordinal];
    }
    int priority_baseline() const {if(!owner_priority_baseline)fail("SCHEDULER_PRIORITY","Cannot capture owner priority baseline");return *owner_priority_baseline;}
    void ensure_scheduler() {
        if(!scheduler){scheduler=std::make_unique<Scheduler>(priority_baseline());scheduler->bind_process_state(process);}
    }
    host::PriorityResult priority(std::optional<std::int32_t> nice) {
        if(nice && !host::priority_profile_supported(*nice))return {95};
        if(native_context_depth){const auto service=current_context().native_priority;if(!service || !*service)return {95};return (*service)(nice);}
        if(!scheduler && !nice)return {};
        try {ensure_scheduler();if(nice)scheduler->set_current_priority(*nice);return {0,scheduler->current_priority()};}catch(...){return {5};}
    }
    void process_priority(std::int32_t nice) {
        const auto result=priority(nice);if(result.error)throw DexError(result.error==95?"AETHER_SCHEDULER_PRIORITY_UNSUPPORTED":"AETHER_SCHEDULER_PRIORITY","Cannot apply the requested owned thread priority profile");
    }
    void binder_flush() noexcept {
        // Aether exposes no Binder transport, transaction buffer, pending-command
        // queue, or native Binder ioctl. Under that enforced invariant the exact
        // flush has no pending bytes to submit; other Binder APIs stay unsupported.
    }
    void deliver_async(ObjectId task,Value value,bool progress) {
        auto &state=async_state(task);
        const std::array<Value,1> args{value};
        if(progress) {
            (void)runtime.invoke_virtual_named(task,"onProgressUpdate","([Ljava/lang/Object;)V",args);
        } else {
            (void)runtime.invoke_virtual_named(task,state.cancel_requested?"onCancelled":"onPostExecute","(Ljava/lang/Object;)V",args);
            state.status=AsyncTaskState::Status::finished;
        }
    }
    struct AsyncMainEntry final:ManagedMainEntry {
        Impl &impl;std::array<Value,2> roots;bool progress;
        AsyncMainEntry(Impl &impl,ObjectId task,Value value,bool progress):impl(impl),roots{Value::reference(task),value},progress(progress){}
        void run(ManagedRuntime &)override {impl.deliver_async(roots[0].bits,roots[1],progress);}
        std::span<const Value> values()const noexcept override{return roots;}
        std::size_t bytes()const noexcept override{return sizeof(*this);}
    };
    void post_async_result(ObjectId task,Value value) {
        auto &state=async_state(task);
        if(state.result_posted)return;
        state.roots[2]=value;
        runtime.post_main(std::make_unique<AsyncMainEntry>(*this,task,value,false));
        state.result_posted=true;state.roots[2]={};
    }
    void async_future_done(ObjectId future) {
        const auto task=object(future).async_future_owner;
        auto &state=future_state(future);
        if(state.state==FutureState::State::failed) {
            Object error;error.type="Ljava/lang/RuntimeException;";error.cause=state.roots[3].bits;
            error.text=u"An error occurred while executing doInBackground()";
            const auto id=allocate(std::move(error));++metrics.exceptions;current_context().last_exception=id;throw JavaException(id);
        }
        if(!async_state(task).invoked)
            post_async_result(task,state.state==FutureState::State::normal?state.roots[2]:Value::reference(0));
    }
    Value async_call(ObjectId receiver) {
        require_suspendable();SuspendCoreBarrier allow(current_context());
        const auto task=object(receiver).async_sdk->roots[0].bits;
        auto &state=async_state(task);state.invoked=true;state.roots[2]=Value::reference(0);
        try {
            process_priority(10);
            const std::array<Value,1> params{state.roots[1]};
            state.roots[2]=runtime.invoke_virtual_named(task,"doInBackground","([Ljava/lang/Object;)Ljava/lang/Object;",params);
            binder_flush();
        } catch(const JavaException &) {
            state.cancel_requested=true;post_async_result(task,state.roots[2]);throw;
        }
        const auto result=state.roots[2];post_async_result(task,result);return result;
    }
    void serial_next(ObjectId serial) {
        auto &state=*object(serial).async_sdk;
        state.roots[0]={};
        if(!state.count)return;
        const auto position=1+state.head;
        state.roots[0]=state.roots[position];state.roots[position]={};state.head=(state.head+1)%16;--state.count;
        const std::array<Value,1> args{state.roots[0]};
        (void)runtime.invoke_virtual_named(async_globals[0],"execute","(Ljava/lang/Runnable;)V",args);
    }
    std::optional<Value> invoke_async_sdk(ObjectId receiver,std::string_view name,std::string_view signature,std::span<const Value> args) {
        auto &value=object(receiver);
        if(!value.async_sdk)return {};
        auto &state=*value.async_sdk;
        if(state.kind==AsyncSdkState::Kind::callable && name=="call" && signature=="()Ljava/lang/Object;")return async_call(receiver);
        if(state.kind==AsyncSdkState::Kind::factory && name=="newThread" && signature=="(Ljava/lang/Runnable;)Ljava/lang/Thread;") {
            if(state.sequence==UINT64_MAX)fail("ASYNC_LIMIT", "AsyncTask thread-name counter exhausted");
            const auto creator=runtime.current_thread();
            Object thread;thread.type="Ljava/lang/Thread;";thread.thread=std::make_unique<ThreadState>();
            thread.thread->initialized=true;thread.thread->target=reference(args[1]);
            thread.thread->daemon=thread_state(creator).daemon;
            thread.thread->group=thread_state(creator).group?thread_state(creator).group:thread_group();
            const auto id=allocate(std::move(thread));runtime.retain(id);
            struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} release{runtime,id};
            std::u16string text=u"AsyncTask #";for(const auto c:std::to_string(++state.sequence))text.push_back(c);
            thread_state(id).name=runtime.new_string(text);return Value::reference(id);
        }
        if(state.kind==AsyncSdkState::Kind::backup_policy && name=="rejectedExecution" && signature=="(Ljava/lang/Runnable;Ljava/util/concurrent/ThreadPoolExecutor;)V") {
            require_suspendable();SuspendCoreBarrier allow(current_context());
            const auto pool=async_pool(true);const std::array<Value,1> job{args[1]};
            (void)runtime.invoke_virtual_named(pool,"execute","(Ljava/lang/Runnable;)V",job);return Value::nothing();
        }
        if(state.kind==AsyncSdkState::Kind::serial && name=="execute" && signature=="(Ljava/lang/Runnable;)V") {
            require_suspendable();SuspendCoreBarrier allow(current_context());
            const auto job=reference(args[1]);(void)object(job);
            if(state.aborted)fail("ASYNC_SERIAL_ABORTED", "Serial executor was aborted by a non-Java failure");
            if(state.count==16)fail("ASYNC_QUEUE_LIMIT", "Serial executor queue bound of 16 is exhausted");
            const auto wrapper=async_sdk_object(async_serial_wrapper_type,AsyncSdkState::Kind::serial_wrapper);
            auto &wrapper_state=*object(wrapper).async_sdk;wrapper_state.roots[0]=Value::reference(receiver);wrapper_state.roots[1]=Value::reference(job);
            state.roots[1+(state.head+state.count)%16]=Value::reference(wrapper);++state.count;
            if(!state.roots[0].bits)serial_next(receiver);
            return Value::nothing();
        }
        if(state.kind==AsyncSdkState::Kind::serial_wrapper && name=="run" && signature=="()V") {
            require_suspendable();SuspendCoreBarrier allow(current_context());
            const auto serial=state.roots[0].bits;
            try {run_runnable(state.roots[1].bits,true);}
            catch(const JavaException &error) {
                state.roots[2]=Value::reference(error.object);
                struct Clear {AsyncSdkState &state;~Clear(){state.roots[2]={};}} clear{state};
                serial_next(serial);throw;
            }
            catch(...) {object(serial).async_sdk->aborted=true;throw;}
            serial_next(serial);return Value::nothing();
        }
        return {};
    }
    std::optional<Value> invoke_async(ObjectId receiver,std::string_view name,std::string_view signature,std::span<const Value> args) {
        auto &state=async_state(receiver,name!="<init>");
        if(name=="<init>" && signature=="()V") {
            async_main_owner();if(state.initialized)fail("STATE", "AsyncTask constructor invoked more than once");
            ensure_async_runtime();
            const auto action=async_sdk_object(async_callable_type,AsyncSdkState::Kind::callable);
            object(action).async_sdk->roots[0]=Value::reference(receiver);runtime.retain(action);
            struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} release{runtime,action};
            Object future;future.type=async_future_type;future.future=std::make_unique<FutureState>();
            future.future->initialized=true;future.future->roots[0]=Value::reference(action);future.async_future_owner=receiver;
            state.roots[0]=Value::reference(allocate(std::move(future)));state.initialized=true;return Value::nothing();
        }
        if(name=="getStatus" && signature=="()Landroid/os/AsyncTask$Status;")return Value::reference(async_status(static_cast<std::size_t>(state.status)));
        if(name=="isCancelled" && signature=="()Z")return Value::word(state.cancel_requested);
        if(name=="cancel" && signature=="(Z)Z") {
            require_suspendable();SuspendCoreBarrier allow(current_context());state.cancel_requested=true;
            const std::array<Value,1> interrupt{args[1]};return runtime.invoke_virtual_named(state.roots[0].bits,"cancel","(Z)Z",interrupt);
        }
        if(name=="get" && (signature=="()Ljava/lang/Object;" || signature=="(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;")) {
            // The internal Future has no guest overrides. Reuse this exact core
            // barrier so terminal nonblocking get preserves provider/IRQ semantics,
            // while a pending wait still validates and drops only its own barrier.
            std::array<Value,3> future_args{state.roots[0],{}, {}};
            for(std::size_t n=1;n<args.size();++n)future_args[n]=args[n];
            return invoke_future(state.roots[0].bits,name,signature,std::span<const Value>(future_args).first(args.size()));
        }
        if(name=="publishProgress" && signature=="([Ljava/lang/Object;)V") {
            if(!state.cancel_requested)runtime.post_main(std::make_unique<AsyncMainEntry>(*this,receiver,args[1],true));
            return Value::nothing();
        }
        if((name=="execute" && signature=="([Ljava/lang/Object;)Landroid/os/AsyncTask;") ||
            (name=="executeOnExecutor" && signature=="(Ljava/util/concurrent/Executor;[Ljava/lang/Object;)Landroid/os/AsyncTask;")) {
            async_main_owner();require_suspendable();SuspendCoreBarrier allow(current_context());
            if(state.status!=AsyncTaskState::Status::pending)runtime.raise("Ljava/lang/IllegalStateException;");
            state.status=AsyncTaskState::Status::running;
            (void)runtime.invoke_virtual_named(receiver,"onPreExecute","()V");
            state.roots[1]=args[name=="execute"?1:2];
            const auto executor=name=="execute"?async_globals[1]:reference(args[1]);
            const std::array<Value,1> job{state.roots[0]};
            (void)runtime.invoke_virtual_named(executor,"execute","(Ljava/lang/Runnable;)V",job);
            return Value::reference(receiver);
        }
        if(name=="onCancelled" && signature=="(Ljava/lang/Object;)V") {
            require_suspendable();SuspendCoreBarrier allow(current_context());
            (void)runtime.invoke_virtual_named(receiver,"onCancelled","()V");return Value::nothing();
        }
        if((name=="onPreExecute" || name=="onCancelled") && signature=="()V")return Value::nothing();
        if(name=="onPostExecute" && signature=="(Ljava/lang/Object;)V")return Value::nothing();
        if(name=="onProgressUpdate" && signature=="([Ljava/lang/Object;)V")return Value::nothing();
        return {};
    }
    ManagedStream &stream_state(ObjectId id,bool initialized=true) {
        auto &value=object(id);
        if(!value.stream)fail("STREAM_STATE","Stream lacks authenticated runtime state");
        auto &state=*value.stream;
        if(initialized && !state.initialized)fail("STATE","Stream constructor has not completed");
        if(state.source && state.source->bytes()!=state.source_bytes)
            fail("STREAM_STATE","Input adapter byte accounting changed");
        return state;
    }
    void stream_error(host::FileResult result) {
        if(result.error==host::FileError::denied)runtime.raise("Ljava/lang/SecurityException;",u"Input stream access is denied");
        if(result.error!=host::FileError::none)runtime.raise("Ljava/io/IOException;",u"Input stream operation failed");
    }
    void stream_work() {
        // Native reader loops participate in the same persistent work budgets.
        auto &context=current_context();
        if(!context.remaining)fail("BUDGET","Stream operation instruction allowance exhausted");
        --context.remaining;
        if(scheduled_task()) {
            if(!task_work_remaining)fail("BUDGET","Stream task batch allowance exhausted");
            --task_work_remaining;
        } else if(main_callback_inflight) {
            if(!main_callback_work_remaining)fail("BUDGET","Stream main callback allowance exhausted");
            --main_callback_work_remaining;
        }
    }
    struct StreamGateway {
        Impl &impl;ManagedStream &state;std::optional<SuspendCoreBarrier> allow;
        StreamGateway(Impl &impl,ManagedStream &state):impl(impl),state(state) {
            // Synchronous SDK delegation drops only this reader core's barrier.
            // Keep every outer provider/native/loading/monitor constraint: real
            // suspension inside the callback still passes its unchanged guards.
            if(!impl.current_context().barriers)fail("STREAM_STATE","Reader delegate requires its own core barrier");
            if(state.busy)fail("STREAM_REENTRANT","Reentrant reader operation is unsupported");
            state.busy=true;allow.emplace(impl.current_context());
        }
        ~StreamGateway(){state.busy=false;}
    };
    void stream_open(ManagedStream &state) {
        if(state.closed)runtime.raise("Ljava/io/IOException;",u"Stream is closed");
    }
    std::pair<std::size_t,std::size_t> stream_range(ObjectId array,Value offset,Value length,std::string_view type) {
        const auto &value=object(array);
        if(value.type!=type)fail("VALUE_TYPE","Stream read requires the matching primitive array");
        const auto start=std::bit_cast<std::int32_t>(word(offset)),count=std::bit_cast<std::int32_t>(word(length));
        if(start<0 || count<0 || static_cast<std::size_t>(start)>value.elements.size() ||
            static_cast<std::size_t>(count)>value.elements.size()-static_cast<std::size_t>(start))
            runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
        return {static_cast<std::size_t>(start),static_cast<std::size_t>(count)};
    }
    std::int32_t delegated_input(ObjectId delegate) {
        const auto bits=word(runtime.invoke_virtual_named(delegate,"read","()I"));
        const auto value=std::bit_cast<std::int32_t>(bits);
        if(value < -1 || value>255)fail("STREAM_RESULT","InputStream.read returned an invalid byte/EOF");
        return value;
    }
    std::int32_t stream_input_one(ObjectId receiver,ManagedStream &state,ManagedStream::Kind kind) {
        if(kind==ManagedStream::Kind::bytes) {
            if(state.position>=state.end)return -1;
            return static_cast<std::int32_t>(word(object(state.roots[0].bits).elements[state.position++]) & 255u);
        }
        if(kind==ManagedStream::Kind::input)fail("ABSTRACT_METHOD","InputStream.read has no managed implementation");
        stream_open(state);
        if(kind==ManagedStream::Kind::file) {
            if(!state.source)fail("STREAM_STATE","FileInputStream has no descriptor adapter");
            if(state.provider_generation!=host_generation)fail("STREAM_PROVIDER","Input stream issuing provider binding is no longer current");
            std::array<std::uint8_t,1> byte{};
            const auto result=provider_call([&]{return state.source->read(byte);});stream_error(result);
            if(result.value<0 || result.value>1)fail("STREAM_RESULT","Input adapter returned an invalid read count");
            return result.value?byte[0]:-1;
        }
        (void)receiver;fail("ABSTRACT_METHOD","InputStream.read has no managed implementation");
    }
    std::int32_t stream_reader_one(ObjectId receiver,ManagedStream &state,ManagedStream::Kind kind) {
        stream_open(state);
        if(kind==ManagedStream::Kind::string) {
            const auto text=runtime.string(state.roots[0].bits);
            if(state.position>=text.size())return -1;
            return text[state.position++];
        }
        if(kind==ManagedStream::Kind::decoder) {
            StreamGateway gateway(*this,state);return delegated_input(state.roots[0].bits);
        }
        if(kind==ManagedStream::Kind::buffered) {
            StreamGateway gateway(*this,state);
            for(;;) {
                if(state.position>=state.end) {
                    const auto size=object(state.roots[1].bits).elements.size();
                    const std::array<Value,3> args{state.roots[1],Value::word(0),Value::word(static_cast<std::uint32_t>(size))};
                    stream_work();
                    const auto result=std::bit_cast<std::int32_t>(word(runtime.invoke_virtual_named(state.roots[0].bits,"read","([CII)I",args)));
                    if(result < -1 || (result>=0 && static_cast<std::size_t>(result)>size))fail("STREAM_RESULT","Reader.read returned an invalid character count");
                    if(result==-1)return -1;
                    if(!result)fail("STREAM_RESULT","Reader.read made no progress for a positive request");
                    state.position=0;state.end=static_cast<std::size_t>(result);
                }
                const auto value=word(object(state.roots[1].bits).elements[state.position++]);
                if(state.skip_lf){state.skip_lf=false;if(value==10)continue;}
                return static_cast<std::int32_t>(value);
            }
        }
        // java.io.Reader's default read() delegates to the actual virtual bulk
        // method. It has no mutable native buffer to guard while forwarding;
        // the selected concrete implementation owns its own callback guard.
        // Existing active callbacks must still refuse reentry before forwarding.
        // This synchronous forwarding owns one core barrier, not permission to
        // remove outer barriers or suspend through a held monitor.
        if(!current_context().barriers)fail("STREAM_STATE","Reader forwarding requires its own core barrier");
        if(state.busy)fail("STREAM_REENTRANT","Reentrant reader operation is unsupported");
        SuspendCoreBarrier allow(current_context());
        const auto array=runtime.new_array("[C",1);runtime.retain(array);
        struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} release{runtime,array};
        const std::array<Value,3> args{Value::reference(array),Value::word(0),Value::word(1)};
        const auto count=std::bit_cast<std::int32_t>(word(runtime.invoke_virtual_named(receiver,"read","([CII)I",args)));
        if(count==-1)return -1;
        if(count!=1)fail("STREAM_RESULT","Reader.read made no valid one-character progress");
        return static_cast<std::int32_t>(word(object(array).elements[0]));
    }
    std::optional<Value> invoke_stream(ObjectId receiver,std::string_view owner_type,std::string_view name,
        std::string_view signature,std::span<const Value> args,bool virtual_dispatch=false) {
        auto &state=stream_state(receiver,name!="<init>");
        using Kind=ManagedStream::Kind;
        const auto implementation=[&] {
            if(virtual_dispatch || name=="<init>")return state.kind;
            if(owner_type==input_stream_type)return Kind::input;
            if(owner_type==file_input_stream_type)return Kind::file;
            if(owner_type==byte_input_stream_type)return Kind::bytes;
            if(owner_type==reader_type)return Kind::reader;
            if(owner_type==string_reader_type)return Kind::string;
            if(owner_type==input_reader_type)return Kind::decoder;
            if(owner_type==buffered_reader_type)return Kind::buffered;
            fail("INVOKE_KIND","Nonvirtual stream interface invocation has no selected implementation");
        };
        const auto kind=implementation();
        if(name=="<init>") {
            if((owner_type==input_stream_type || owner_type==reader_type) && signature=="()V") {
                // A managed subclass still executes its real constructor body.
                if(state.kind==Kind::input || state.kind==Kind::reader) {
                    if(state.initialized)fail("STATE","Stream base constructor invoked twice");
                    state.initialized=true;
                }
                return Value::nothing();
            }
            const bool file=owner_type==file_input_stream_type && signature=="(Ljava/lang/String;)V";
            const bool bytes=owner_type==byte_input_stream_type && (signature=="([B)V" || signature=="([BII)V");
            const bool text=owner_type==string_reader_type && signature=="(Ljava/lang/String;)V";
            const bool decoder=owner_type==input_reader_type && signature=="(Ljava/io/InputStream;Ljava/lang/String;)V";
            const bool buffered=owner_type==buffered_reader_type && (signature=="(Ljava/io/Reader;)V" || signature=="(Ljava/io/Reader;I)V");
            if(!file && !bytes && !text && !decoder && !buffered)return {};
            if(state.initialized || state.initializing)fail("STATE","Stream constructor invoked more than once");
            state.initializing=true;
            struct InitEnd {ManagedStream &state;bool committed=false;~InitEnd(){state.initializing=false;if(!committed){state.roots={};state.position=state.end=0;(void)state.close_source();state.source.reset();state.source_bytes=0;state.source_closed=false;}}} end{state};
            const auto delegate=reference(args[1]);(void)object(delegate);
            if(file) {
                if(!host)fail("INPUT_STREAM_UNSUPPORTED","FileInputStream requires an input-stream provider");
                auto *const issuing_provider=host;
                const auto issuing_generation=host_generation;
                state.source=provider_call([&]{return issuing_provider->open_input_stream(runtime,runtime.string(delegate));});
                if(!state.source)fail("INPUT_STREAM_UNAVAILABLE","Input-stream provider returned no adapter");
                if(host!=issuing_provider || host_generation!=issuing_generation)
                    fail("STREAM_PROVIDER","Input stream provider binding changed during open");
                state.provider_generation=issuing_generation;
                const auto bytes_charge=state.source->bytes();
                if(bytes_charge<sizeof(HostInputStream) || bytes_charge>limits.heap_bytes)
                    fail("HEAP_LIMIT","Input adapter has invalid or excessive fixed storage");
                state.source_bytes=bytes_charge;
                if(bytes_charge>limits.heap_bytes-metrics.heap_bytes)collect();
                if(bytes_charge>limits.heap_bytes-metrics.heap_bytes)fail("HEAP_LIMIT","Input adapter exceeds shared heap quota");
                if(state.source->bytes()!=bytes_charge)fail("STREAM_STATE","Input adapter byte accounting changed during admission");
                object(receiver).bytes+=bytes_charge;metrics.heap_bytes+=bytes_charge;
            } else if(bytes) {
                if(object(delegate).type!="[B")fail("VALUE_TYPE","ByteArrayInputStream requires byte[]");
                const auto size=object(delegate).elements.size();
                std::size_t start=0,count=size;
                if(args.size()==4) {
                    const auto offset=std::bit_cast<std::int32_t>(word(args[2])),length=std::bit_cast<std::int32_t>(word(args[3]));
                    if(offset<0 || length<0 || static_cast<std::size_t>(offset)>size)runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
                    start=static_cast<std::size_t>(offset);count=std::min(static_cast<std::size_t>(length),size-start);
                }
                state.roots[0]=args[1];state.position=start;state.end=start+count;
            } else if(text) { (void)runtime.string(delegate);state.roots[0]=args[1]; }
            else if(decoder) {
                const auto charset=runtime.string(reference(args[2]));
                const auto matches=[&](std::u16string_view expected) {
                    if(charset.size()!=expected.size())return false;
                    for(std::size_t n=0;n<charset.size();++n) {
                        auto c=charset[n];if(c>=u'A' && c<=u'Z')c=static_cast<char16_t>(c+(u'a'-u'A'));
                        if(c!=expected[n])return false;
                    }
                    return true;
                };
                if(!matches(u"iso-8859-1") && !matches(u"iso8859_1") && !matches(u"iso8859-1") && !matches(u"latin1"))
                    runtime.raise("Ljava/io/UnsupportedEncodingException;",u"Only ISO-8859-1 is implemented");
                state.roots[0]=args[1];
            } else {
                const auto size=args.size()==3?std::bit_cast<std::int32_t>(word(args[2])):8192;
                if(size<=0)runtime.raise("Ljava/lang/IllegalArgumentException;");
                state.roots[0]=args[1];state.roots[1]=Value::reference(runtime.new_array("[C",size));
            }
            state.initialized=true;end.committed=true;return Value::nothing();
        }
        const bool input=kind==Kind::input || kind==Kind::file || kind==Kind::bytes;
        if(name=="close" && signature=="()V") {
            if(kind==Kind::bytes || kind==Kind::input)return Value::nothing();
            if(kind==Kind::reader)fail("ABSTRACT_METHOD","Reader.close has no managed implementation");
            if(state.closed)return Value::nothing();
            if(kind==Kind::file) {
                state.closed=true;stream_error(provider_call([&]{return state.close_source();}));
            } else if(kind==Kind::decoder || kind==Kind::buffered) {
                StreamGateway gateway(*this,state);
                struct Close {ManagedStream &state;~Close(){state.closed=true;state.roots={};}} close{state};
                (void)runtime.invoke_virtual_named(state.roots[0].bits,"close","()V");
            } else {state.closed=true;state.roots={};}
            return Value::nothing();
        }
        if(name=="available" && signature=="()I" && kind==Kind::bytes)
            return Value::word(static_cast<std::uint32_t>(state.end-state.position));
        if(name=="read" && signature=="()I")
            return Value::word(static_cast<std::uint32_t>(input?stream_input_one(receiver,state,kind):stream_reader_one(receiver,state,kind)));
        if(name=="read" && signature==(input?"([BII)I":"([CII)I")) {
            if(kind!=Kind::bytes && kind!=Kind::input)stream_open(state);
            const auto array=reference(args[1]);const auto [start,count]=stream_range(array,args[2],args[3],input?"[B":"[C");
            // Concrete ByteArrayInputStream checks EOF before a zero-length
            // request, after validating the supplied array slice.
            if(kind==Kind::bytes && state.position>=state.end)return Value::word(UINT32_MAX);
            if(!count)return Value::word(0);
            if(kind==Kind::file) {
                if(state.provider_generation!=host_generation)fail("STREAM_PROVIDER","Input stream issuing provider binding is no longer current");
                std::array<std::uint8_t,4080> buffer{};
                const auto requested=std::min(count,buffer.size());
                const auto result=provider_call([&]{return state.source->read(std::span<std::uint8_t>(buffer).first(requested));});
                stream_error(result);
                if(result.value<0 || static_cast<std::uint64_t>(result.value)>requested)fail("STREAM_RESULT","Input adapter returned an invalid bulk count");
                for(std::size_t n=0;n<static_cast<std::size_t>(result.value);++n)
                    object(array).elements[start+n]=Value::word(static_cast<std::uint32_t>(static_cast<std::int32_t>(std::bit_cast<std::int8_t>(buffer[n]))));
                return Value::word(result.value?static_cast<std::uint32_t>(result.value):UINT32_MAX);
            }
            if(kind==Kind::reader)fail("ABSTRACT_METHOD","Reader.read has no managed bulk implementation");
            std::size_t copied=0;
            // Reads may return a finite partial result; a source descriptor read
            // uses one bounded host byte, never an unaccounted host buffer.
            const auto maximum=kind==Kind::file?std::min(count,std::size_t{1}):count;
            if(kind==Kind::input) {
                StreamGateway gateway(*this,state);
                for(;copied<maximum;++copied) {
                    stream_work();std::int32_t value;
                    try {value=delegated_input(receiver);}
                    catch(const JavaException &error) {
                        // Type resolution may call a provider that reenters and
                        // collects. A C++ pending exception is not itself a GC root.
                        runtime.retain(error.object);
                        struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} release{runtime,error.object};
                        if(copied && subtype(object(error.object).type,"Ljava/io/IOException;"))break;
                        throw;
                    }
                    if(value<0)break;
                    object(array).elements[start+copied]=Value::word(static_cast<std::uint32_t>(static_cast<std::int32_t>(
                        std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(value)))));
                }
            } else for(;copied<maximum;++copied) {
                stream_work();const auto value=input?stream_input_one(receiver,state,kind):stream_reader_one(receiver,state,kind);if(value<0)break;
                object(array).elements[start+copied]=Value::word(input?static_cast<std::uint32_t>(static_cast<std::int32_t>(std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(value)))):static_cast<std::uint32_t>(value));
            }
            return Value::word(copied?static_cast<std::uint32_t>(copied):UINT32_MAX);
        }
        if(name=="readLine" && signature=="()Ljava/lang/String;" && kind==Kind::buffered) {
            stream_open(state);
            // The growing line is a normal managed StringBuilder-shaped string;
            // retain it across delegate callbacks/GC and enforce normal quotas.
            const auto line=runtime.new_string(u"");runtime.retain(line);
            struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} release{runtime,line};
            bool any=false;
            for(;;) {
                stream_work();const auto value=stream_reader_one(receiver,state,kind);
                if(value<0)return Value::reference(any?line:0);
                if(value==10)return Value::reference(line);
                if(value==13){state.skip_lf=true;return Value::reference(line);}
                any=true;
                auto text=std::u16string(object(line).text);text.push_back(static_cast<char16_t>(value));replace_text(line,std::move(text));
            }
        }
        return {};
    }
    ObjectId canonical_empty(std::string_view type) {
        if(type!=empty_map_type && type!=empty_set_type && type!=empty_map_iterator_type)
            fail("API_UNSUPPORTED","Unknown immutable empty collection singleton");
        const auto slot=type==empty_map_type?0U:type==empty_set_type?1U:2U;
        auto &id=empty_map_objects[slot];
        if(!id){Object value;value.type=type;id=allocate(std::move(value));}
        return id;
    }
    Value list_array(ObjectId receiver) {
        auto &source=object(receiver);
        if(!source.list || !source.list->initialized())fail("STATE","List must be initialized before snapshot");
        const auto count=source.list->references().size();
        const auto charge=sizeof(Object)+std::string_view("[Ljava/lang/Object;").size()+count*sizeof(Value);
        if(charge>limits.heap_bytes-metrics.heap_bytes)fail("HEAP_LIMIT","List snapshot exceeds managed heap bound");
        Object snapshot;snapshot.type="[Ljava/lang/Object;";
        snapshot.elements.assign(source.list->references().begin(),source.list->references().end());
        return Value::reference(allocate(std::move(snapshot)));
    }
    Value copy_list_add_if_absent(ObjectId receiver,ObjectId query) {
        if(!current_context().barriers)fail("STATE","addIfAbsent lacks its core boundary");
        const auto &initial=object(receiver);
        if(!initial.list || !initial.list->snapshots())fail("STATE","addIfAbsent requires initialized copy-on-write list storage");
        const auto revision=initial.list->revision(),count=initial.list->references().size();
        for(std::size_t at=0;at<count;++at) {
            const auto element=object(receiver).list->references()[at].bits;
            runtime.retain(element);
            struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} root{runtime,element};
            bool match=!query && !element;
            if(query) {
                SuspendCoreBarrier allow(current_context());
                if(const auto method=object_override(query,"equals","(Ljava/lang/Object;)Z"))
                    match=word(runtime.invoke_virtual(*method,std::array{Value::reference(query),Value::reference(element)}))!=0;
                else match=key_equal(query,element);
            }
            if(object(receiver).list->revision()!=revision)
                fail("API_UNSUPPORTED","addIfAbsent with list mutation during equality is not implemented");
            if(match)return Value::word(0);
        }
        auto &latest=object(receiver);
        const std::array<Value,2> args{Value::reference(receiver),Value::reference(query)};
        const auto result=latest.list->invoke(runtime,copy_list_type,"add","(Ljava/lang/Object;)Z",args,
            {latest.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length});
        if(!result)fail("STATE","Copy-on-write list append is unavailable");
        return *result;
    }
    Value inherited_set_add_all(ObjectId receiver,ObjectId source) {
        const auto &set=object(receiver);
        if(!set.map || !set.map->initialized())fail("STATE","Set must be initialized before bulk addition");
        auto &context=current_context();
        if(!context.barriers)fail("STATE","Inherited set bulk addition lacks its core boundary");
        SuspendCoreBarrier allow(context);
        const auto iterator=reference(call_virtual_named(source,"iterator","()Ljava/util/Iterator;"));
        runtime.retain(iterator);
        struct IteratorRoot {ManagedRuntime &runtime;ObjectId id;~IteratorRoot(){runtime.release(id);}} root{runtime,iterator};
        bool modified=false;
        while(word(call_virtual_named(iterator,"hasNext","()Z"))) {
            if(!context.remaining)fail("BUDGET","Collection traversal instruction allowance exhausted");
            --context.remaining;
            if(scheduled_task()) {
                if(!task_work_remaining)fail("BUDGET","Collection traversal batch allowance exhausted");
                --task_work_remaining;
            } else if(main_callback_inflight) {
                if(!main_callback_work_remaining)fail("BUDGET","Collection traversal main-callback allowance exhausted");
                --main_callback_work_remaining;
            }
            const auto value=call_virtual_named(iterator,"next","()Ljava/lang/Object;");
            const auto element=reference(value);runtime.retain(element);
            struct ElementRoot {ManagedRuntime &runtime;ObjectId id;~ElementRoot(){runtime.release(id);}} item{runtime,element};
            if(word(call_virtual_named(receiver,"add","(Ljava/lang/Object;)Z",std::array{value})))modified=true;
        }
        return Value::word(modified);
    }
    Value inherited_set_remove_all(ObjectId receiver,ObjectId source) {
        const auto &set=object(receiver);
        if(!set.map || !set.map->initialized())fail("STATE","Set must be initialized before bulk removal");
        if(!source)runtime.raise("Ljava/lang/NullPointerException;");
        auto &context=current_context();
        if(!context.barriers)fail("STATE","Inherited set bulk removal lacks its core boundary");
        SuspendCoreBarrier allow(context);
        const auto count=std::bit_cast<std::int32_t>(word(call_virtual_named(receiver,"size","()I")));
        const auto other_count=std::bit_cast<std::int32_t>(word(call_virtual_named(source,"size","()I")));
        const bool source_iteration=count>other_count;
        const auto iterator=reference(call_virtual_named(source_iteration?source:receiver,"iterator","()Ljava/util/Iterator;"));
        runtime.retain(iterator);
        struct Root {ManagedRuntime &runtime;ObjectId id;~Root(){runtime.release(id);}} held{runtime,iterator};
        bool modified=false;
        while(word(call_virtual_named(iterator,"hasNext","()Z"))) {
            if(!context.remaining)fail("BUDGET","Collection traversal instruction allowance exhausted");
            --context.remaining;
            if(scheduled_task()) {
                if(!task_work_remaining)fail("BUDGET","Collection traversal batch allowance exhausted");
                --task_work_remaining;
            } else if(main_callback_inflight) {
                if(!main_callback_work_remaining)fail("BUDGET","Collection traversal main-callback allowance exhausted");
                --main_callback_work_remaining;
            }
            const auto value=call_virtual_named(iterator,"next","()Ljava/lang/Object;");
            const auto element=reference(value);runtime.retain(element);Root item{runtime,element};
            if(source_iteration) {
                if(word(call_virtual_named(receiver,"remove","(Ljava/lang/Object;)Z",std::array{value})))modified=true;
            } else if(word(call_virtual_named(source,"contains","(Ljava/lang/Object;)Z",std::array{value}))) {
                (void)call_virtual_named(iterator,"remove","()V");modified=true;
            }
        }
        return Value::word(modified);
    }
    Value array_list_contains(ObjectId receiver,ObjectId query) {
        auto &initial=object(receiver);
        if(!initial.list || !initial.list->initialized())fail("STATE","List must be initialized before membership query");
        if(initial.list->snapshots())fail("API_UNSUPPORTED","CopyOnWriteArrayList membership requires snapshot search");
        if(initial.type!="Ljava/util/ArrayList;")fail("API_UNSUPPORTED","Inherited ArrayList membership requires subclass indexOf dispatch");
        const auto revision=initial.list->revision();
        const auto count=initial.list->references().size();
        for(std::size_t at=0;at<count;++at) {
            const auto element=object(receiver).list->references()[at].bits;
            runtime.retain(element);
            struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} root{runtime,element};
            bool match=!query && !element;
            if(query) {
                if(!current_context().barriers)fail("STATE","List equality lacks its core boundary");
                SuspendCoreBarrier allow(current_context());
                // ArrayList calls query.equals even for an identical reference.
                if(const auto method=object_override(query,"equals","(Ljava/lang/Object;)Z"))
                    match=word(runtime.invoke_virtual(*method,std::array{Value::reference(query),Value::reference(element)}))!=0;
                else match=key_equal(query,element);
            }
            // Guest equality may collect, replace elements, or structurally mutate
            // this list. Never retain a vector/span across that callback.
            if(object(receiver).list->revision()!=revision)
                fail("API_UNSUPPORTED","ArrayList membership with structural mutation during equality is unsupported");
            if(match)return Value::word(1);
        }
        return Value::word(0);
    }
    Value array_list_construct_collection(ObjectId receiver,ObjectId source) {
        auto *const state=object(receiver).list.get();
        if(!state)fail("STATE","ArrayList constructor has no authenticated list storage");
        state->begin_collection_construction();
        struct End {ManagedList &state;~End(){state.cancel_collection_construction();}} end{*state};
        (void)object(source); // Null source fails before any guest callback.
        if(!current_context().barriers)fail("STATE","Collection constructor lacks its core boundary");
        Value snapshot;
        {SuspendCoreBarrier allow(current_context());snapshot=call_virtual_named(source,"toArray","()[Ljava/lang/Object;");}
        const auto array=reference(snapshot);runtime.retain(array);
        struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} root{runtime,array};
        (void)typed(snapshot,"[Ljava/lang/Object;");
        auto &destination=object(receiver);
        destination.list->initialize_snapshot(runtime,array,
            {destination.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length});
        return Value::nothing();
    }
    Value list_add_all(ObjectId receiver,ObjectId source) {
        if(!object(receiver).list || !object(receiver).list->initialized())fail("STATE","Bulk append requires an initialized list");
        const bool copy_on_write=object(receiver).list->snapshots();
        object(source); // Null source throws before invoking guest code.
        Value snapshot;
        if(copy_on_write && object(source).type==copy_list_type) snapshot=list_array(source);
        else {
            // This is synchronous Java dispatch: remove only this exact SDK
            // barrier. Outer provider/native/monitor/class-init guards remain.
            if(!current_context().barriers)fail("STATE","Bulk callback lacks its core barrier");
            SuspendCoreBarrier allow(current_context());
            snapshot=call_virtual_named(source,"toArray","()[Ljava/lang/Object;",{});
        }
        const auto array=reference(snapshot);
        runtime.retain(array);
        struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} release{runtime,array};
        typed(snapshot,"[Ljava/lang/Object;");
        // Source callbacks may have changed the destination. Reacquire both its
        // storage and accounting only after the source snapshot is complete.
        auto &destination=object(receiver);
        return Value::word(destination.list->append_snapshot(runtime,array,
            {destination.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length}));
    }
    ObjectId unmodifiable_backing(ObjectId receiver) {
        const auto &value=object(receiver);
        if(!unmodifiable_class(value.type) || value.elements.size()!=1 || value.elements[0].kind!=ValueKind::reference)
            fail("STATE","Unmodifiable view lacks its authenticated backing reference");
        return value.elements[0].bits;
    }
    ObjectId wrap_unmodifiable_list(ObjectId backing,std::optional<bool> random_access={}) {
        (void)object(backing);
        runtime.retain(backing);
        struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} root{runtime,backing};
        (void)typed(Value::reference(backing),"Ljava/util/List;");
        if(!random_access && unmodifiable_list_class(object(backing).type))return backing;
        const bool random=random_access?*random_access:subtype(object(backing).type,"Ljava/util/RandomAccess;");
        Object result;result.type=random?unmodifiable_random_list_type:unmodifiable_list_type;
        result.elements={Value::reference(backing)};return allocate(std::move(result));
    }
    ObjectId wrap_synchronized_list(ObjectId backing,ObjectId mutex=0,std::optional<bool> random_access={}) {
        (void)object(backing);runtime.retain(backing);
        struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} root{runtime,backing};
        (void)typed(Value::reference(backing),"Ljava/util/List;");
        const bool random=random_access?*random_access:subtype(object(backing).type,"Ljava/util/RandomAccess;");
        if(mutex)(void)object(mutex);
        Object result;result.type=random?synchronized_random_list_type:synchronized_list_type;
        // A zero internal mutex slot means this factory-created wrapper itself.
        // Subviews retain the original wrapper explicitly as their shared mutex.
        result.elements={Value::reference(backing),Value::reference(mutex)};
        return allocate(std::move(result));
    }
    ObjectId wrap_map_backed_set(ObjectId backing) {
        (void)typed(Value::reference(backing),"Ljava/util/Map;");
        (void)object(backing);
        // The factory frame roots the supplied map. Call its actual overrides.
        Value keys;
        {
            SuspendCoreBarrier allow(current_context());
            if(word(call_virtual_named(backing,"isEmpty","()Z"))==0)
                runtime.raise("Ljava/lang/IllegalArgumentException;",u"Map is non-empty");
            keys=call_virtual_named(backing,"keySet","()Ljava/util/Set;");
        }
        const auto view=reference(keys);runtime.retain(view);
        struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} root{runtime,view};
        (void)typed(keys,"Ljava/util/Set;");
        Object result;result.type=map_backed_set_type;
        result.elements={Value::reference(backing),keys};return allocate(std::move(result));
    }
    Value invoke_map_backed_set(ObjectId receiver,std::string_view name,std::string_view signature,std::span<const Value> args) {
        const auto &value=object(receiver);
        if(value.type!=map_backed_set_type || value.elements.size()!=2)
            fail("STATE","Map-backed set lacks its factory state");
        const auto map=reference(value.elements[0]),keys=reference(value.elements[1]);
        if(name=="addAll")fail("API_UNSUPPORTED","Map-backed set addAll requires per-element wrapper additions");
        if(name=="equals" && reference(args[1])==receiver)return Value::word(1);
        if(name=="add") {
            const auto present=box_boolean(true);
            const std::array<Value,2> put{args[1],Value::reference(present)};
            SuspendCoreBarrier allow(current_context());
            return Value::word(reference(call_virtual_named(map,"put","(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",put))==0);
        }
        const bool map_query=name=="size" || name=="isEmpty" || name=="clear" || name=="contains" || name=="remove";
        const auto target=map_query?map:keys;
        const auto delegated_name=name=="contains"?std::string_view("containsKey"):name;
        const auto delegated_signature=name=="remove"?std::string_view("(Ljava/lang/Object;)Ljava/lang/Object;"):signature;
        SuspendCoreBarrier allow(current_context());
        const auto result=call_virtual_named(target,delegated_name,delegated_signature,args.subspan(1));
        return name=="remove"?Value::word(reference(result)!=0):result;
    }
    Value invoke_synchronized_list(ObjectId receiver,std::string_view name,std::string_view signature,std::span<const Value> args) {
        const auto &value=object(receiver);
        if(!synchronized_list_class(value.type) || value.elements.size()!=2 ||
           value.elements[0].kind!=ValueKind::reference || value.elements[1].kind!=ValueKind::reference)
            fail("STATE","Synchronized list lacks authenticated backing/mutex state");
        const auto backing=value.elements[0].bits,mutex=value.elements[1].bits?value.elements[1].bits:receiver;
        const bool random=value.type==synchronized_random_list_type,subview=name=="subList";
        if(name=="equals" && reference(args[1])==receiver)return Value::word(1);
        auto &context=current_context();
        if(!context.barriers || context.frames.empty())fail("STATE","Synchronized forwarding lacks its core invocation boundary");
        // Java exposes the backing iterators directly. Callers own any external
        // synchronization for traversal; iterator creation itself adds no lock.
        const bool iterator=name=="iterator" || name=="listIterator";
        auto &frame=*context.frames.back();const auto count=frame.monitor_count;
        if(!iterator) {
            (void)object(mutex);
            if(count==frame.monitors.size())fail("MONITOR_LIMIT","Monitor nesting exceeds 32 acquisitions per invocation");
            check_monitor_available(mutex);frame.monitors[frame.monitor_count++]=mutex;
        }
        struct Unlock {
            Frame &frame;std::size_t count;bool locked;
            Unlock(Frame &f,std::size_t n,bool held):frame(f),count(n),locked(held){}
            Unlock(const Unlock &)=delete;
            Unlock &operator=(const Unlock &)=delete;
            ~Unlock() noexcept {if(locked){frame.monitors[count]=0;frame.monitor_count=count;}}
        } unlock{frame,count,!iterator};
        Value result;
        {SuspendCoreBarrier allow(context);result=call_virtual_named(backing,name,signature,args.subspan(1));}
        if(subview)return Value::reference(wrap_synchronized_list(reference(result),mutex,random));
        return result;
    }
    Value invoke_unmodifiable(ObjectId receiver,std::string_view name,std::string_view signature,std::span<const Value> args) {
        const auto actual_type=std::string_view(object(receiver).type);
        const bool list=unmodifiable_list_class(actual_type);
        const bool random_parent=actual_type==unmodifiable_random_list_type;
        const bool bidirectional=actual_type==unmodifiable_list_iterator_type;
        if(list?unmodifiable_mutator(name,signature):
            ((name=="remove" && signature=="()V") || (bidirectional &&
             (name=="set" || name=="add") && signature=="(Ljava/lang/Object;)V")))
            runtime.raise("Ljava/lang/UnsupportedOperationException;");
        const auto backing=unmodifiable_backing(receiver);
        if(list && name=="equals" && reference(args[1])==receiver)return Value::word(1);
        if(!current_context().barriers)fail("STATE","Unmodifiable forwarding lacks its exact core boundary");
        Value result;
        {
            SuspendCoreBarrier allow(current_context());
            if(list && name=="listIterator" && signature=="()Ljava/util/ListIterator;") {
                const std::array<Value,1> zero{Value::word(0)};
                result=call_virtual_named(backing,name,"(I)Ljava/util/ListIterator;",zero);
            } else result=call_virtual_named(backing,name,signature,args.subspan(1));
        }
        if(list && name=="subList")return Value::reference(wrap_unmodifiable_list(reference(result),random_parent));
        if(list && (name=="iterator" || name=="listIterator")) {
            const bool indexed=name=="listIterator";
            const auto iterator=reference(result);
            runtime.retain(iterator);
            struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} root{runtime,iterator};
            (void)typed(result,indexed?"Ljava/util/ListIterator;":"Ljava/util/Iterator;");
            Object wrapped;wrapped.type=indexed?unmodifiable_list_iterator_type:unmodifiable_iterator_type;
            wrapped.elements={Value::reference(iterator)};return Value::reference(allocate(std::move(wrapped)));
        }
        return result;
    }
    std::optional<Value> singleton_list_call(ObjectId receiver,std::string_view name,std::string_view signature,std::span<const Value> args) {
        auto &value=object(receiver);

        if(value.elements.size()!=1)fail("STATE","Singleton list has invalid state");
        const auto element=value.elements[0];
        if(name=="size"&&signature=="()I")return Value::word(1);
        if(name=="isEmpty"&&signature=="()Z")return Value::word(0);
        if(name=="get"&&signature=="(I)Ljava/lang/Object;") {
            if(word(args[1]))runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
            return element;
        }
        if((name=="contains"||name=="indexOf"||name=="lastIndexOf"||name=="remove")&&
            (signature=="(Ljava/lang/Object;)Z"||signature=="(Ljava/lang/Object;)I")) {
            const auto query=reference(args[1]);const bool match=query==element.bits||(query&&key_equal(query,element.bits));
            if(name=="remove"&&match)runtime.raise("Ljava/lang/UnsupportedOperationException;");
            return Value::word(name=="indexOf"||name=="lastIndexOf"?(match?0:0xffffffffu):match);
        }
        if(name=="hashCode"&&signature=="()I")return Value::word(31u+(element.bits?key_hash(element.bits):0u));
        if((name=="clear"&&signature=="()V")||
            (name=="add"&&(signature=="(Ljava/lang/Object;)Z"||signature=="(ILjava/lang/Object;)V"))||
            (name=="set"&&signature=="(ILjava/lang/Object;)Ljava/lang/Object;")||
            (name=="remove"&&signature=="(I)Ljava/lang/Object;"))
            runtime.raise("Ljava/lang/UnsupportedOperationException;");
        if(name=="iterator"&&signature=="()Ljava/util/Iterator;") {
            Object result;result.type=snapshot_iterator_type;
            result.iterator=std::make_unique<SnapshotIterator>(value.elements,0);
            return Value::reference(allocate(std::move(result)));
        }
        if(name=="toArray"&&(signature=="()[Ljava/lang/Object;"||signature=="([Ljava/lang/Object;)[Ljava/lang/Object;")) {
            const bool typed=signature[1]=='[';auto array=typed?reference(args[1]):0;
            const auto length=typed?runtime.array_length(array):0;
            if(!typed||!length)array=runtime.new_array(typed?std::string(runtime.object_type(array)):"[Ljava/lang/Object;",1);
            runtime.array_set(array,0,element);if(typed&&length>1)runtime.array_set(array,1,Value::reference(0));
            return Value::reference(array);
        }
                    return {};
    }
    std::optional<Value> native_list_read(ObjectId receiver,std::string_view type,std::string_view name,
        std::string_view signature,std::span<const Value> args) {
        auto &value=object(receiver);
        if(value.type==singleton_list_type)return singleton_list_call(receiver,name,signature,args);
        if(value.type==empty_list_type) {
            if((name=="iterator" && signature=="()Ljava/util/Iterator;") ||
               (name=="listIterator" && (signature=="()Ljava/util/ListIterator;" || signature=="(I)Ljava/util/ListIterator;"))) {
                if(args.size()==2 && word(args[1]))runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
                Object result;result.type=empty_iterator_type;return Value::reference(allocate(std::move(result)));
            }
            return invoke_empty_list(runtime,name,signature,args);
        }
        if(value.type==array_list_type) {
            if(value.elements.size()!=1 || value.elements[0].kind!=ValueKind::reference)fail("STATE","Array-list view has no backing array");
            const auto array=value.elements[0].bits;
            if(name=="iterator" || name=="listIterator") {
                const auto position=args.size()==2?std::bit_cast<std::int32_t>(word(args[1])):0;
                if(position<0 || static_cast<std::size_t>(position)>runtime.array_length(array))runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
                Object result;result.type=array_iterator_type;
                result.elements={Value::reference(array),Value::word(static_cast<std::uint32_t>(position)),Value::word(UINT32_MAX)};
                return Value::reference(allocate(std::move(result)));
            }
            return invoke_array_view(runtime,array,name,signature,args,[&](ObjectId a,ObjectId b){return key_equal(a,b);});
        }
        if(value.list) {
            if(!value.list->initialized())fail("STATE","List must be initialized before query");
            if(!value.list->snapshots() && name=="contains" && signature=="(Ljava/lang/Object;)Z")
                return array_list_contains(receiver,reference(args[1]));
            if(name=="addAll" && signature=="(Ljava/util/Collection;)Z")return list_add_all(receiver,reference(args[1]));
            if(name=="toArray" && signature=="()[Ljava/lang/Object;")return list_array(receiver);
            if(name=="iterator" || name=="listIterator") {
                const bool indexed=name=="listIterator";
                const auto position=signature[1]=='I'?std::bit_cast<std::int32_t>(word(args[1])):0;
                if(position<0 || static_cast<std::size_t>(position)>value.list->references().size())runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
                Object result;
                if(value.list->snapshots()) {
                    result.type=snapshot_iterator_type;
                    result.iterator=std::make_unique<SnapshotIterator>(value.list->references(),static_cast<std::size_t>(position));
                } else {
                    if(value.type!="Ljava/util/ArrayList;")fail("API_UNSUPPORTED","ArrayList subclass iterators require virtual mutation support");
                    result.type=indexed?live_list_iterator_type:live_iterator_type;
                    result.live_iterator=std::make_unique<LiveListIterator>(receiver,static_cast<std::size_t>(position),value.list->revision(),indexed);
                }
                return Value::reference(allocate(std::move(result)));
            }
            return value.list->invoke(runtime,type,name,signature,args,{value.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length});
        }
        if(value.live_iterator) {
            auto &backing=object(value.live_iterator->backing());
            if(!backing.list)fail("STATE","Live iterator has no backing list");
            return value.live_iterator->invoke(runtime,*backing.list,name,signature,args,
                {backing.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length});
        }
        if(value.iterator)return value.iterator->invoke(runtime,type,name,signature);
        if(value.type==array_iterator_type)return invoke_array_iterator(runtime,value.elements,name,signature,args);
        if(value.type==empty_iterator_type)return invoke_empty_iterator(runtime,name,signature);
        return {};
    }
    void authenticate_named(Frame &frame,std::string_view signature,std::span<const Value> arguments) {
        std::size_t count=0,at=1;
        while(signature[at]!=')') {
            const auto first=at;while(signature[at]=='[')++at;
            if(signature[at]=='L')at=signature.find(';',at)+1;else ++at;
            if(count>=arguments.size())fail("SIGNATURE","Wrong named collection argument count");
            frame.arguments[count+1]=typed(arguments[count],signature.substr(first,at-first));++count;
        }
        if(count!=arguments.size())fail("SIGNATURE","Wrong named collection argument count");
    }
    std::optional<Value> named_map_support(ObjectId receiver,std::string_view type,std::string_view name,
        std::string_view signature,std::span<const Value> args) {
        auto &value=object(receiver);
        if(value.type==empty_list_type && type==empty_list_type && name=="toArray" && signature=="()[Ljava/lang/Object;")
            return invoke_empty_list(runtime,name,signature,args);
        if(value.list && collection_class(type) && name=="toArray" && signature=="()[Ljava/lang/Object;")
            return list_array(receiver);
        if(value.list && value.list->snapshots() && collection_class(type) && name=="addAll" && signature=="(Ljava/util/Collection;)Z")
            return list_add_all(receiver,reference(args[1]));
        if(value.type==array_iterator_type && array_view_class(type))
            return invoke_array_iterator(runtime,value.elements,name,signature,args);
        if(value.type==array_list_type && array_view_class(type)) {
            if(value.elements.size()!=1 || value.elements[0].kind!=ValueKind::reference)fail("STATE","Array-list view has no backing array");
            const auto array=value.elements[0].bits;
            if(name=="iterator" && signature=="()Ljava/util/Iterator;") {
                Object iterator;iterator.type=array_iterator_type;
                iterator.elements={Value::reference(array),Value::word(0),Value::word(UINT32_MAX)};
                return Value::reference(allocate(std::move(iterator)));
            }
            return invoke_array_view(runtime,array,name,signature,args,[&](ObjectId a,ObjectId b){return key_equal(a,b);});
        }
        if(value.map_keys && map_view_class(type)) {
            auto &view=*value.map_keys;auto &backing=object(view.map);
            if(!backing.map)fail("STATE","Set iterator has no backing map");
            const MapCallbacks callbacks{[&](ObjectId key){return key_hash(key);},[&](ObjectId a,ObjectId b){return key_equal(a,b);}};
            if(!view.iterator && name=="iterator" && signature=="()Ljava/util/Iterator;") {
                Object iterator;iterator.type=map_key_iterator_type;iterator.map_keys=std::make_unique<MapKeys>();
                iterator.map_keys->map=view.map;iterator.map_keys->iterator=true;
                for(const auto &entry:backing.map->entries())iterator.map_keys->snapshot.push_back(Value::reference(entry.key));
                return Value::reference(allocate(std::move(iterator)));
            }
            if(!view.iterator && ((name=="equals" && signature=="(Ljava/lang/Object;)Z") ||
                (name=="hashCode" && signature=="()I") || (name=="toString" && signature=="()Ljava/lang/String;")))
                fail("API_UNSUPPORTED","Native concurrent key-view object methods are not implemented");
            return backing.map->invoke_keys(runtime,view,name,signature,args,
                {backing.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length},callbacks);
        }
        if(value.live_iterator && collection_class(type)) {
            auto &backing=object(value.live_iterator->backing());
            if(!backing.list)fail("STATE","List iterator has no backing list");
            return value.live_iterator->invoke(runtime,*backing.list,name,signature,args,
                {backing.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length});
        }
        if(value.iterator && collection_class(type))return value.iterator->invoke(runtime,type,name,signature);
        if(name=="iterator" && signature=="()Ljava/util/Iterator;") {
            if(value.list && collection_class(type)) {
                if(!value.list->initialized())fail("STATE","List must be initialized before iteration");
                Object iterator;
                if(value.list->snapshots()) {
                    iterator.type=snapshot_iterator_type;
                    iterator.iterator=std::make_unique<SnapshotIterator>(value.list->references(),0);
                } else {
                    if(value.type!="Ljava/util/ArrayList;")fail("API_UNSUPPORTED","ArrayList subclass iterators require virtual mutation support");
                    iterator.type=live_iterator_type;
                    iterator.live_iterator=std::make_unique<LiveListIterator>(receiver,0,value.list->revision(),false);
                }
                return Value::reference(allocate(std::move(iterator)));
            }
            if(value.map && (type==hash_set_type || type==linked_hash_set_type)) {
                if(!value.map->initialized())fail("STATE","Set must be initialized before iteration");
                Object iterator;iterator.type=hash_set_iterator_type;iterator.map_keys=std::make_unique<MapKeys>();
                auto &view=*iterator.map_keys;view.map=receiver;view.iterator=true;view.hash_set=true;
                view.expected_revision=value.map->revision();
                view.snapshot.reserve(value.map->entries().size());
                for(const auto &entry:value.map->entries())view.snapshot.push_back(Value::reference(entry.key));
                return Value::reference(allocate(std::move(iterator)));
            }
            if(value.set && set_class(type)) {
                if(!value.set->initialized())fail("STATE","Set must be initialized before iteration");
                Object iterator;iterator.type=snapshot_iterator_type;
                iterator.iterator=std::make_unique<SnapshotIterator>(value.set->references(),0);
                return Value::reference(allocate(std::move(iterator)));
            }
        }
        if(value.map && (map_class(type))) {
            if(name=="keySet" && signature=="()Ljava/util/Set;") {
                if(!value.map->initialized())fail("STATE","Map must be initialized before keySet");
                if(!value.map->concurrent())fail("API_UNSUPPORTED","Native ordinary/weak map key views are not implemented");
                Object view;view.type=map_keys_type;view.map_keys=std::make_unique<MapKeys>();
                view.map_keys->map=receiver;return Value::reference(allocate(std::move(view)));
            }
            if((name=="size" && signature=="()I") || (name=="isEmpty" && signature=="()Z") ||
                (name=="put" && signature=="(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;") ||
                ((name=="get" || name=="remove") && signature=="(Ljava/lang/Object;)Ljava/lang/Object;") ||
                (name=="containsKey" && signature=="(Ljava/lang/Object;)Z") || (name=="clear" && signature=="()V")) {
                const MapCallbacks callbacks{[&](ObjectId key){return key_hash(key);},[&](ObjectId a,ObjectId b){return key_equal(a,b);}};
                return value.map->invoke(runtime,type,name,signature,args,{value.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length},callbacks);
            }
            if(name=="entrySet" && signature=="()Ljava/util/Set;") {
                if(!value.map->initialized())fail("STATE","Map must be initialized before traversal");
                if(value.type!=hash_map_type && value.type!=linked_map_type)fail("API_UNSUPPORTED","Named entry traversal requires native strong map");
                Object view;view.type=map_entries_type;view.map_values=std::make_unique<MapValues>();
                view.map_values->map=receiver;view.map_values->entry_set=true;return Value::reference(allocate(std::move(view)));
            }
        }
        if(value.map_values && map_view_class(type)) {
            auto &view=*value.map_values;auto &backing=object(view.map);
            if(!backing.map || !backing.map->initialized())fail("STATE","Map view has no initialized backing");
            if(!view.iterator && name=="iterator" && signature=="()Ljava/util/Iterator;") {
                Object iterator;iterator.type=view.entry_set?map_entry_iterator_type:map_value_iterator_type;
                iterator.map_values=std::make_unique<MapValues>(view);iterator.map_values->iterator=true;
                iterator.map_values->expected_structure=backing.map->structure_revision();return Value::reference(allocate(std::move(iterator)));
            }
            if(view.iterator && name=="next" && signature=="()Ljava/lang/Object;" && view.entry_set) {
                if(view.expected_structure!=backing.map->structure_revision())runtime.raise("Ljava/util/ConcurrentModificationException;");
                if(view.cursor>=backing.map->entries().size())runtime.raise("Ljava/util/NoSuchElementException;");
                Object entry;entry.type=map_entry_type;entry.map_entry=std::make_unique<MapEntryReference>();
                *entry.map_entry={view.map,view.cursor,view.expected_structure};
                const auto id=allocate(std::move(entry));view.last=view.cursor++;return Value::reference(id);
            }
            const MapCallbacks callbacks{[&](ObjectId key){return key_hash(key);},[&](ObjectId a,ObjectId b){return key_equal(a,b);}};
            return backing.map->invoke_values(runtime,view,name,signature,args,callbacks);
        }
        if(value.map_entry && map_view_class(type)) {
            const auto entry=*value.map_entry;auto &backing=object(entry.map);
            if(!backing.map)fail("STATE","Entry has no backing map");
            return backing.map->invoke_entry(runtime,entry,name,signature,args);
        }
        if((name=="size" && signature=="()I") || (name=="isEmpty" && signature=="()Z")) {
            std::optional<std::size_t> size;
            if(value.list && collection_class(type)) {
                if(!value.list->initialized())fail("STATE","List must be initialized before query");size=value.list->references().size();
            } else if(value.set && set_class(type)) {
                if(!value.set->initialized())fail("STATE","Set must be initialized before query");size=value.set->references().size();
            } else if(value.map && (type==hash_set_type || type==linked_hash_set_type)) {
                if(!value.map->initialized())fail("STATE","Set must be initialized before query");size=value.map->entries().size();
            } else if(value.type==empty_list_type && type==empty_list_type)size=0;
            if(size)return Value::word(name=="isEmpty"?*size==0:static_cast<std::uint32_t>(*size));
        }
        return {};
    }
    void random_work() {
        auto &context=current_context();if(!context.remaining)fail("BUDGET","Random instruction allowance exhausted");--context.remaining;
        if(scheduled_task()){if(!task_work_remaining)fail("BUDGET","Random batch allowance exhausted");--task_work_remaining;}
        else if(main_callback_inflight){if(!main_callback_work_remaining)fail("BUDGET","Random main-callback allowance exhausted");--main_callback_work_remaining;}
    }
    Value invoke_random(ObjectId receiver,std::string_view name,std::string_view signature,std::span<const Value> args) {
        if(!object(receiver).random)fail("STATE","Random receiver has no native state");
        if(name=="<init>") {
            std::uint64_t seed=0;
            if(signature=="(J)V")seed=wide(args[1]);
            else {std::array<std::uint8_t,16> bytes{};if(!host::secure_random_128(bytes))fail("RANDOM_ENTROPY_UNAVAILABLE","Windows entropy is unavailable");for(unsigned n=0;n<8;++n)seed=(seed<<8)|bytes[n];}
            const bool subclass=object(receiver).type!=random_type;object(receiver).random->initialize(seed,subclass);
            if(subclass){SuspendCoreBarrier allow(current_context());(void)call_virtual_named(receiver,"setSeed","(J)V",std::array{Value::wide(seed)});}
            return Value::nothing();
        }
        object(receiver).random->check();
        if(name=="next"){random_work();return Value::word(object(receiver).random->next(word(args[1])));}
        if(name=="setSeed"){object(receiver).random->set_seed(wide(args[1]));return Value::nothing();}
        SuspendCoreBarrier allow(current_context());
        if(name=="nextBytes") {
            const auto array=reference(args[1]);if(!array)runtime.raise("Ljava/lang/NullPointerException;");
            const auto length=runtime.array_length(array);
            for(std::size_t at=0;at<length;) {
                random_work();auto bits=word(call_virtual_named(receiver,"nextInt","()I"));
                for(unsigned n=0;n<4 && at<length;++n,++at,bits>>=8)runtime.array_set(array,static_cast<std::int32_t>(at),Value::word(bits&255));
            }
            return Value::nothing();
        }
        const auto next=[&](unsigned bits){random_work();return word(call_virtual_named(receiver,"next","(I)I",std::array{Value::word(bits)}));};
        const auto result=object(receiver).random->invoke(runtime,name,signature,args,next);
        if(result)return *result;fail("API_UNSUPPORTED","Random method is not implemented");
    }
    std::optional<Value> invoke_uuid(ObjectId receiver,std::string_view name,std::string_view signature,std::span<const Value> args) {
        auto &value=object(receiver);
        if(value.type!=uuid_type || !value.uuid)fail("UUID_STATE","UUID lacks authenticated final-class state");
        const ManagedUuid *other=nullptr;
        if((name=="equals" && signature=="(Ljava/lang/Object;)Z") ||
            (name=="compareTo" && (signature=="(Ljava/util/UUID;)I" || signature=="(Ljava/lang/Object;)I"))) {
            const auto id=reference(args[1]);if(id)other=object(id).uuid.get();
        }
        return value.uuid->invoke(runtime,name,signature,args,other);
    }
    void clear_thread_locals(ObjectId thread) noexcept {
        const auto found=heap.find(thread);
        if(found==heap.end() || !found->second.thread_locals)return;
        auto &value=found->second;
        const auto bytes=sizeof(ThreadLocalTable)+value.thread_locals->bytes();
        value.thread_locals.reset();value.bytes-=bytes;metrics.heap_bytes-=bytes;
    }
    void set_thread_local(ObjectId thread,ObjectId key,ObjectId binding) {
        auto &value=object(thread);
        if(!value.thread)fail("THREAD_STATE","ThreadLocal storage requires authenticated Thread identity");
        if(!value.thread_locals) {
            const auto charge=sizeof(ThreadLocalTable);
            if(charge>limits.heap_bytes-metrics.heap_bytes)collect();
            if(charge>limits.heap_bytes-metrics.heap_bytes)fail("HEAP_LIMIT","ThreadLocal table exceeds managed heap quota");
            auto table=std::make_unique<ThreadLocalTable>();
            std::size_t staged_bytes=0;metrics.heap_bytes+=charge;
            try {table->set(runtime,key,binding,{staged_bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length});}
            catch(...) {metrics.heap_bytes-=charge+staged_bytes;throw;}
            value.thread_locals=std::move(table);value.bytes+=charge+staged_bytes;return;
        }
        value.thread_locals->set(runtime,key,binding,{value.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length});
    }
    std::optional<Value> invoke_thread_local(ObjectId receiver,std::string_view name,std::string_view signature,std::span<const Value> args) {
        auto &key=object(receiver);
        if(!key.thread_local_key)fail("STATE","ThreadLocal lacks authenticated state");
        if(name=="<init>") {
            if(key.thread_local_key->initialized)fail("STATE","ThreadLocal constructor invoked twice");
            key.thread_local_key->initialized=true;return Value::nothing();
        }
        if(!key.thread_local_key->initialized)fail("STATE","ThreadLocal must be initialized before use");
        if(name=="initialValue")return Value::reference(0);
        const auto thread=runtime.current_thread();
        auto &thread_value=object(thread);
        if(thread_value.thread_locals)thread_value.thread_locals->expunge();
        if(name=="set") {set_thread_local(thread,receiver,reference(args[1]));return Value::nothing();}
        if(name=="remove") {
            if(thread_value.thread_locals)if(auto *slot=thread_value.thread_locals->find(receiver))*slot={};
            return Value::nothing();
        }
        if(name=="get") {
            if(thread_value.thread_locals)if(const auto *slot=thread_value.thread_locals->find(receiver))return Value::reference(slot->value);
            if(!current_context().barriers)fail("THREAD_LOCAL_STATE","ThreadLocal initializer requires its exact core boundary");
            Value result;
            {SuspendCoreBarrier allow(current_context());result=runtime.invoke_virtual_named(receiver,"initialValue","()Ljava/lang/Object;");}
            const auto binding=reference(result);runtime.retain(binding);
            struct BindingRoot {ManagedRuntime &runtime;ObjectId id;~BindingRoot(){runtime.release(id);}} root{runtime,binding};
            // Internal publication deliberately bypasses virtual set overrides.
            set_thread_local(thread,receiver,binding);return Value::reference(binding);
        }
        (void)signature;return {};
    }
    struct RegexCharge {
        std::size_t &heap;std::size_t bytes;
        RegexCharge(std::size_t &heap,std::size_t bytes):heap(heap),bytes(bytes){heap+=bytes;}
        ~RegexCharge(){heap-=bytes;}
    };
    void regex_preflight(std::size_t bytes,bool allocation) {
        if(bytes>limits.heap_bytes || bytes>limits.heap_bytes-metrics.heap_bytes || (allocation && heap.size()>=limits.objects))collect();
        if(bytes>limits.heap_bytes || bytes>limits.heap_bytes-metrics.heap_bytes || (allocation && heap.size()>=limits.objects))
            fail("HEAP_LIMIT","Regex native reservation exceeds the managed heap quota");
    }
    [[noreturn]] void regex_error(const host::RegexError &error,ObjectId source=0) {
        if(error.kind==host::RegexError::Kind::limit)fail("REGEX_LIMIT",error.what());
        if(error.kind!=host::RegexError::Kind::syntax || !source)fail("REGEX_BACKEND",error.what());
        const std::string description=error.what();
        const auto desc=runtime.new_string(std::u16string(description.begin(),description.end()));runtime.retain(desc);
        struct Root {ManagedRuntime &runtime;ObjectId id;~Root(){runtime.release(id);}} root{runtime,desc};
        Object value;value.type=pattern_syntax_type;value.regex_syntax=std::make_unique<PatternSyntax>();
        *value.regex_syntax={source,desc,error.index};value.text=runtime.string(desc);
        if(error.index>=0) {
            const auto number=std::to_string(error.index);value.text+=u" near index ";value.text.append(number.begin(),number.end());
        }
        value.text+=u"\n";value.text+=runtime.string(source);
        if(error.index>=0 && static_cast<std::size_t>(error.index)<=4096){value.text+=u"\n";value.text.append(static_cast<std::size_t>(error.index),u' ');value.text+=u"^";}
        const auto id=allocate(std::move(value));++metrics.exceptions;current_context().last_exception=id;throw JavaException(id);
    }
    ObjectId compile_regex(ObjectId source,std::uint32_t flags) {
        const auto text=runtime.string(source);
        if(text.size()>4096)fail("REGEX_LIMIT","Pattern exceeds 4096 UTF16 units");
        const auto native_flags=regex_flags(runtime,flags);
        const auto charge=sizeof(Object)+pattern_type.size()+sizeof(ManagedPattern)+regex_pattern_reservation;
        regex_preflight(charge,true);
        std::unique_ptr<host::RegexPattern> regex_backend;
        try {
            RegexCharge reservation(metrics.heap_bytes,charge);
            regex_backend=host::RegexPattern::compile(text,native_flags,(flags&16U)!=0);
        } catch(const host::RegexError &error){regex_error(error,source);}
        Object value;value.type=pattern_type;value.regex_pattern=std::make_unique<ManagedPattern>();
        value.regex_pattern->source=source;value.regex_pattern->flags=flags;value.regex_pattern->native=std::move(regex_backend);
        return allocate(std::move(value));
    }
    ObjectId regex_snapshot(ObjectId input) {
        (void)object(input);
        if(!current_context().barriers)fail("REGEX_STATE","Regex snapshot requires its exact core boundary");
        // Synchronous guest callbacks drop only this SDK operation's own barrier.
        // Existing provider/native/class-initializer/monitor boundaries remain.
        SuspendCoreBarrier allow(current_context());
        const auto length=std::bit_cast<std::int32_t>(word(runtime.invoke_virtual_named(input,"length","()I")));
        if(length<0 || length>65536)fail("REGEX_LIMIT","Regex input length exceeds 65536 UTF16 units");
        // Android retains originalInput, but binds native matching to input.toString().
        // Call the real managed implementation, never CharSequence's host-only view.
        const auto snapshot=reference(runtime.invoke_virtual_named(input,"toString","()Ljava/lang/String;"));
        const auto text=runtime.string(snapshot);
        if(text.size()>65536)fail("REGEX_LIMIT","Regex input snapshot exceeds 65536 UTF16 units");
        if(text.size()!=static_cast<std::size_t>(length))fail("REGEX_INPUT","CharSequence length and String snapshot disagree");
        return snapshot;
    }
    struct RegexRoot {ManagedRuntime &runtime;ObjectId id;RegexRoot(ManagedRuntime &runtime,ObjectId id):runtime(runtime),id(id){runtime.retain(id);}~RegexRoot(){runtime.release(id);}};
    ObjectId create_regex_matcher(ObjectId pattern,ObjectId input) {
        auto &owner_pattern=object(pattern);
        if(!owner_pattern.regex_pattern || !owner_pattern.regex_pattern->native)fail("REGEX_STATE","Pattern lacks authenticated state");
        const auto snapshot=regex_snapshot(input);RegexRoot root(runtime,snapshot);
        const auto text=runtime.string(snapshot);
        const auto charge=sizeof(Object)+matcher_type.size()+sizeof(ManagedMatcher)+regex_matcher_reservation+(text.size()+1)*2;
        regex_preflight(charge,true);
        std::unique_ptr<host::RegexMatcher> regex_backend;
        try {RegexCharge reservation(metrics.heap_bytes,charge);regex_backend=owner_pattern.regex_pattern->native->matcher(text);}
        catch(const host::RegexError &error){regex_error(error);}
        Object value;value.type=matcher_type;value.regex_matcher=std::make_unique<ManagedMatcher>();
        auto &state=*value.regex_matcher;state.pattern=pattern;state.original=input;state.snapshot=snapshot;state.native=std::move(regex_backend);
        return allocate(std::move(value));
    }
    std::optional<Value> invoke_regex(ObjectId receiver,std::string_view name,std::string_view signature,std::span<const Value> args) {
        auto &value=object(receiver);
        if(value.regex_pattern) {
            auto &state=*value.regex_pattern;
            if(name=="pattern" || name=="toString")return Value::reference(state.source);
            if(name=="flags")return Value::word(state.flags);
            if(name=="matcher")return Value::reference(create_regex_matcher(receiver,reference(args[1])));
        }
        if(value.regex_syntax) {
            if(name=="getIndex")return Value::word(static_cast<std::uint32_t>(value.regex_syntax->index));
            if(name=="getPattern")return Value::reference(value.regex_syntax->source);
            if(name=="getDescription")return Value::reference(value.regex_syntax->description);
        }
        if(!value.regex_matcher || !value.regex_matcher->native)fail("REGEX_STATE","Matcher lacks authenticated state");
        auto &state=*value.regex_matcher;
        if(state.busy)fail("REGEX_REENTRANT","Matcher callback reentered its active operation");
        state.busy=true;struct Busy {bool &value;~Busy(){value=false;}} busy{state.busy};
        try {
            if(name=="pattern")return Value::reference(state.pattern);
            if(name=="groupCount")return Value::word(static_cast<std::uint32_t>(state.native->groups()));
            if(name=="reset") {
                const auto input=args.size()==1?state.original:reference(args[1]);
                const auto snapshot=regex_snapshot(input);RegexRoot root(runtime,snapshot);
                const auto text=runtime.string(snapshot);const auto before=state.native->storage_bytes();
                const auto charge=regex_matcher_reservation+(text.size()+1)*2;
                regex_preflight(charge,false);
                {RegexCharge reservation(metrics.heap_bytes,charge);state.native->reset(text);}
                const auto after=state.native->storage_bytes();
                value.bytes=value.bytes-before+after;metrics.heap_bytes=metrics.heap_bytes-before+after;
                state.original=input;state.snapshot=snapshot;state.matched=false;return Value::reference(receiver);
            }
            if(name=="matches"){state.matched=false;state.matched=state.native->matches();return Value::word(state.matched);}
            if(name=="find") {
                const auto start=args.size()==1?-1:std::bit_cast<std::int32_t>(word(args[1]));
                if(args.size()!=1 && (start<0 || static_cast<std::size_t>(start)>state.native->input().size()))runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
                state.matched=false;state.matched=state.native->find(start);return Value::word(state.matched);
            }
            if(!state.matched)runtime.raise("Ljava/lang/IllegalStateException;");
            const auto group=args.size()==1?0:std::bit_cast<std::int32_t>(word(args[1]));
            if(group<0 || group>state.native->groups())runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
            if(name=="start")return Value::word(static_cast<std::uint32_t>(state.native->start(group)));
            if(name=="end")return Value::word(static_cast<std::uint32_t>(state.native->end(group)));
            if(name=="group") {
                const auto first=state.native->start(group),last=state.native->end(group);
                if(first<0)return Value::reference(0);
                const auto input=state.native->input();
                if(last<first || static_cast<std::size_t>(last)>input.size())fail("REGEX_BACKEND","ICU returned invalid group offsets");
                return Value::reference(runtime.new_string(input.substr(static_cast<std::size_t>(first),static_cast<std::size_t>(last-first))));
            }
        } catch(const host::RegexError &error){regex_error(error);}
        (void)signature;return {};
    }
    ObjectId box_integral(std::string_view type,std::uint64_t bits) {
        const bool large=type==long_type;
        const auto normalized=large?bits:static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(bits))));
        const auto number=std::bit_cast<std::int64_t>(normalized);
        const bool cached=number>=-128 && number<=127;
        const auto slot=cached?static_cast<std::size_t>(number+128):0;
        auto &cache=large?long_cache:short_cache;
        if(cached && cache[slot])return cache[slot];
        Object value;value.type=type;value.integral=std::make_unique<ManagedIntegral>(large);value.integral->initialize(normalized);
        const auto id=allocate(std::move(value));if(cached)cache[slot]=id;return id;
    }
    std::optional<Value> invoke_integral(ObjectId receiver,std::string_view name,std::string_view signature,std::span<const Value> args) {
        auto &value=object(receiver);
        if((value.type!=long_type && value.type!=short_type) || !value.integral)fail("STATE","Integral wrapper lacks authenticated final-class state");
        const ManagedIntegral *other=nullptr;
        if((name=="equals" && signature=="(Ljava/lang/Object;)Z") || name=="compareTo") {
            const auto id=reference(args[1]);if(id)other=object(id).integral.get();
        }
        return value.integral->invoke(runtime,name,signature,args,other);
    }
    ObjectId box_floating(std::string_view type,std::uint64_t bits) {
        Object value;value.type=type;value.floating=std::make_unique<ManagedFloating>(type==double_type);
        value.floating->initialize(bits);return allocate(std::move(value));
    }
    std::optional<Value> invoke_floating(ObjectId receiver,std::string_view name,std::string_view signature,std::span<const Value> args) {
        auto &value=object(receiver);
        if((value.type!=float_type && value.type!=double_type) || !value.floating)fail("STATE","Floating wrapper lacks authenticated final-class state");
        const ManagedFloating *other=nullptr;
        if((name=="equals" && signature=="(Ljava/lang/Object;)Z") || name=="compareTo") {
            const auto id=reference(args[1]);if(id)other=object(id).floating.get();
        }
        return value.floating->invoke(runtime,name,signature,args,other);
    }
    ObjectId box_byte(std::uint32_t bits) {
        const auto slot=static_cast<std::uint8_t>(bits);
        auto &cached=byte_cache[slot];
        if(!cached) {
            Object value;value.type=byte_type;value.byte=std::make_unique<ManagedByte>();value.byte->initialize(bits);
            cached=allocate(std::move(value));
        }
        return cached;
    }
    std::optional<Value> invoke_byte(ObjectId receiver,std::string_view name,std::string_view signature,std::span<const Value> args) {
        auto &value=object(receiver);
        if(value.type!=byte_type || !value.byte)fail("STATE","Byte lacks authenticated final-class state");
        const ManagedByte *other=nullptr;
        if((name=="equals" && signature=="(Ljava/lang/Object;)Z") || name=="compareTo") {
            const auto id=reference(args[1]);if(id)other=object(id).byte.get();
        }
        return value.byte->invoke(runtime,name,signature,args,other);
    }
    ObjectId box_boolean(bool value) {
        auto &cached=boolean_cache[value?1:0];
        if(!cached) {
            Object boxed;boxed.type=boolean_type;boxed.boolean=std::make_unique<ManagedBoolean>();
            boxed.boolean->initialize(value);cached=allocate(std::move(boxed));
        }
        return cached;
    }
    std::optional<Value> invoke_boolean(ObjectId receiver,std::string_view name,std::string_view signature,std::span<const Value> args) {
        auto &value=object(receiver);
        if(value.type!=boolean_type || !value.boolean)fail("BOOLEAN_STATE","Boolean lacks authenticated final-class state");
        const ManagedBoolean *other=nullptr;
        if((name=="equals" && signature=="(Ljava/lang/Object;)Z") ||
            (name=="compareTo" && (signature=="(Ljava/lang/Boolean;)I" || signature=="(Ljava/lang/Object;)I"))) {
            const auto id=reference(args[1]);if(id)other=object(id).boolean.get();
        }
        return value.boolean->invoke(runtime,name,signature,args,other);
    }
    Value call_virtual_named(ObjectId receiver, std::string_view name, std::string_view signature,
                             std::span<const Value> arguments = {}, bool allow_thread_base = false) {
        execution_checkpoint();
        (void)object(receiver);
        if (arguments.size() > 255) fail("SIGNATURE", "Named virtual arguments exceed 255 values");
        if (frame_count() >= limits.frames) fail("CALL_DEPTH", "Shared managed frame limit exceeded");
        Frame frame;
        frame.method = no_index;
        frame.arguments.push_back(Value::reference(receiver));
        frame.arguments.insert(frame.arguments.end(), arguments.begin(), arguments.end());
        for (const auto argument : frame.arguments)
            if (argument.kind == ValueKind::reference && argument.bits) (void)object(argument.bits);
        auto &context = current_context();
        context.frames.push_back(&frame);
        struct Pop { ExecutionContext &context; ~Pop() { context.frames.pop_back(); } } pop{context};
        metrics.maximum_frames = std::max(metrics.maximum_frames, frame_count());
        if(scheduled_task()) {
            if (!task_work_remaining) fail("BUDGET", "Managed task batch instruction budget exhausted");
            --task_work_remaining;
        }
        auto type = std::string_view(object(receiver).type);
        std::vector<std::string_view> interfaces;
        unsigned depth = 0;
        for (; depth < 256; ++depth) {
            if((type==blocking_queue_type || type==synchronous_queue_type) &&
                (((name=="offer" || name=="remove") && signature=="(Ljava/lang/Object;)Z") ||
                 (name=="poll" && signature=="()Ljava/lang/Object;") || (name=="take" && signature=="()Ljava/lang/Object;") ||
                 (name=="poll" && signature=="(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;") ||
                 (name=="size" && signature=="()I") || (name=="isEmpty" && signature=="()Z"))) {
                authenticate_named(frame,signature,arguments);
                NonYielding barrier(current_context());
                if(const auto result=native_queue_call(receiver,type,name,signature,frame.arguments))return *result;
                fail("API_UNSUPPORTED","Native blocking queue operation is unavailable");
            }
            if(type=="Ljava/lang/String;" && name=="isEmpty" && signature=="()Z") {
                authenticate_named(frame,signature,arguments);
                NonYielding barrier(current_context());
                return Value::word(runtime.string(receiver).empty());
            }
            if(type==copy_list_type && name=="addIfAbsent" && signature=="(Ljava/lang/Object;)Z") {
                authenticate_named(frame,signature,arguments);
                NonYielding barrier(current_context());
                return copy_list_add_if_absent(receiver,reference(frame.arguments[1]));
            }
            if(type==map_backed_set_type && map_backed_set_method(name,signature)) {
                authenticate_named(frame,signature,arguments);
                NonYielding barrier(current_context());
                return invoke_map_backed_set(receiver,name,signature,frame.arguments);
            }
            const bool native_map=(type==hash_map_type || type==linked_map_type || type==weak_map_type || type==concurrent_map_type) && object(receiver).map;
            const bool map_method=((name=="put" && signature=="(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;") ||
                ((name=="get" || name=="remove") && signature=="(Ljava/lang/Object;)Ljava/lang/Object;") ||
                (name=="containsKey" && signature=="(Ljava/lang/Object;)Z") || (name=="clear" && signature=="()V") ||
                (name=="keySet" && signature=="()Ljava/util/Set;"));
            const bool key_method=type==map_keys_type && (map_backed_set_method(name,signature));
            const bool key_iterator=(type==map_key_iterator_type || type==hash_set_iterator_type) && unmodifiable_iterator_method(name,signature,false);
            if((native_map && map_method) || key_method || key_iterator) {
                authenticate_named(frame,signature,arguments);
                NonYielding barrier(current_context());
                if(const auto result=named_map_support(receiver,type,name,signature,frame.arguments))return *result;
                fail("API_UNSUPPORTED","Native map/view "+std::string(name)+std::string(signature)+" is not implemented");
            }
            if(synchronized_list_class(type) && unmodifiable_list_method(name,signature)) {
                authenticate_named(frame,signature,arguments);
                NonYielding barrier(current_context());
                return invoke_synchronized_list(receiver,name,signature,frame.arguments);
            }
            if((unmodifiable_list_class(type) && unmodifiable_list_method(name,signature)) ||
               (unmodifiable_iterator_class(type) && unmodifiable_iterator_method(name,signature,type==unmodifiable_list_iterator_type))) {
                authenticate_named(frame,signature,arguments);
                NonYielding barrier(current_context());
                return invoke_unmodifiable(receiver,name,signature,frame.arguments);
            }
            const bool native_list=(((type=="Ljava/util/ArrayList;" || type==copy_list_type) && object(receiver).list) ||
                type==empty_list_type || type==singleton_list_type || type==array_list_type) &&
                unmodifiable_list_method(name,signature);
            const bool native_iterator=(type==live_iterator_type || type==live_list_iterator_type || type==snapshot_iterator_type ||
                type==array_iterator_type || type==empty_iterator_type) && unmodifiable_iterator_method(name,signature,type!=live_iterator_type);
            if(native_list || native_iterator) {
                authenticate_named(frame,signature,arguments);
                NonYielding barrier(current_context());
                if(const auto result=native_list_read(receiver,type,name,signature,frame.arguments))return *result;
                if(native_list)fail("API_UNSUPPORTED","Native list "+std::string(name)+std::string(signature)+" is not implemented");
            }
            if(type==print_stream_type && print_stream_method(name,signature)) {
                authenticate_named(frame,signature,arguments);
                NonYielding barrier(current_context());
                return invoke_print_stream(receiver,name,frame.arguments);
            }
            if(type==print_stream_type && (name=="print" || name=="println" || name=="flush" || name=="close" || name=="checkError"))
                fail("API_UNSUPPORTED","PrintStream overload is outside the standard diagnostic output profile");
            if(type==input_stream_type || type==file_input_stream_type || type==byte_input_stream_type ||
                type==reader_type || type==string_reader_type || type==input_reader_type || type==buffered_reader_type) {
                const bool input=type==input_stream_type || type==file_input_stream_type || type==byte_input_stream_type;
                std::array<std::string_view,3> parameters{};std::size_t count=0;bool known=false;
                if((name=="read" && signature=="()I") || (name=="close" && signature=="()V"))known=true;
                else if(name=="available" && signature=="()I" && type==byte_input_stream_type)known=true;
                else if(name=="readLine" && signature=="()Ljava/lang/String;" && type==buffered_reader_type)known=true;
                else if(name=="read" && signature==(input?"([BII)I":"([CII)I")) {
                    known=true;count=3;parameters={input?"[B":"[C","I","I"};
                }
                if(known) {
                    if(arguments.size()!=count)fail("SIGNATURE","Wrong named stream argument count");
                    for(std::size_t n=0;n<count;++n)frame.arguments[n+1]=typed(arguments[n],parameters[n]);
                    NonYielding barrier(current_context());
                    if(const auto result=invoke_stream(receiver,type,name,signature,frame.arguments))return *result;
                }
            }
            if(type=="Ljava/lang/String;" && name=="concat" && signature=="(Ljava/lang/String;)Ljava/lang/String;") {
                if(arguments.size()!=1)fail("SIGNATURE","Named String.concat requires one String");
                frame.arguments[1]=typed(arguments[0],"Ljava/lang/String;");
                NonYielding barrier(current_context());
                return string_concat(receiver,reference(frame.arguments[1]));
            }
            if(type=="Ljava/lang/String;" && name=="contains" && signature=="(Ljava/lang/CharSequence;)Z") {
                if(arguments.size()!=1)fail("SIGNATURE","Named String.contains requires one CharSequence");
                frame.arguments[1]=typed(arguments[0],"Ljava/lang/CharSequence;");
                NonYielding barrier(current_context());
                return string_contains(receiver,reference(frame.arguments[1]));
            }
            if(type=="Ljava/lang/String;" && name=="split" &&
               (signature=="(Ljava/lang/String;)[Ljava/lang/String;" ||
                signature=="(Ljava/lang/String;I)[Ljava/lang/String;")) {
                const bool limited=signature=="(Ljava/lang/String;I)[Ljava/lang/String;";
                if(arguments.size()!=(limited?2U:1U))fail("SIGNATURE","Wrong named String.split argument count");
                frame.arguments[1]=typed(arguments[0],"Ljava/lang/String;");
                if(limited)frame.arguments[2]=typed(arguments[1],"I");
                NonYielding barrier(current_context());
                return string_split(receiver,reference(frame.arguments[1]),
                    limited?std::bit_cast<std::int32_t>(word(frame.arguments[2])):0);
            }
            if(type=="Ljava/lang/Class;" && name=="isArray" && signature=="()Z") {
                if(!arguments.empty())fail("SIGNATURE","Named Class.isArray requires no arguments");
                NonYielding barrier(current_context());
                return Value::word(runtime.represented_class(receiver).starts_with('['));
            }
            if((type=="Ljava/lang/String;" || type=="Ljava/lang/StringBuilder;") && name=="length" && signature=="()I") {
                if(!arguments.empty())fail("SIGNATURE","Named CharSequence.length requires no arguments");
                NonYielding barrier(current_context());
                return Value::word(static_cast<std::uint32_t>(runtime.char_sequence(receiver).size()));
            }
            if(empty_map_method(type,name,signature)) {
                std::array<std::string_view,3> parameters{};std::size_t count=0,at=1;
                while(signature[at]!=')') {
                    const auto start=at;while(signature[at]=='[')++at;
                    if(signature[at]=='L')at=signature.find(';',at)+1;else ++at;
                    parameters[count++]=signature.substr(start,at-start);
                }
                if(arguments.size()!=count)fail("SIGNATURE","Wrong named immutable collection argument count");
                for(std::size_t n=0;n<count;++n)frame.arguments[n+1]=typed(arguments[n],parameters[n]);
                NonYielding barrier(current_context());
                if(const auto result=invoke_empty_map(runtime,type,name,signature,frame.arguments,
                    [&](std::string_view kind){return canonical_empty(kind);}))return *result;
            }
            if((type==hash_set_type || type==linked_hash_set_type) &&
                (((name=="add" || name=="remove" || name=="contains") && signature=="(Ljava/lang/Object;)Z") ||
                 ((name=="addAll" || name=="removeAll") && signature=="(Ljava/util/Collection;)Z"))) {
                authenticate_named(frame,signature,arguments);
                NonYielding barrier(current_context());
                if(name=="addAll")return inherited_set_add_all(receiver,reference(frame.arguments[1]));
                if(name=="removeAll")return inherited_set_remove_all(receiver,reference(frame.arguments[1]));
                auto &set=object(receiver);
                if(!set.map)fail("STATE","Native set has no map storage");
                const MapCallbacks callbacks{[&](ObjectId key){return key_hash(key);},[&](ObjectId a,ObjectId b){return key_equal(a,b);}};
                if(const auto result=set.map->invoke_hash_set(runtime,type,name,signature,frame.arguments,
                    {set.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length},callbacks))return *result;
                fail("API_UNSUPPORTED","Native set addition is not implemented");
            }
            if((type==copy_list_type || type=="Ljava/util/ArrayList;") && name=="addAll" && signature=="(Ljava/util/Collection;)Z") {
                if(arguments.size()!=1)fail("SIGNATURE","Named bulk append requires one Collection");
                frame.arguments[1]=typed(arguments[0],"Ljava/util/Collection;");
                NonYielding barrier(current_context());
                return list_add_all(receiver,reference(frame.arguments[1]));
            }
            const bool native_query=(name=="toArray" && signature=="()[Ljava/lang/Object;") || (name=="size" && signature=="()I") || (name=="isEmpty" && signature=="()Z") ||
                (name=="entrySet" && signature=="()Ljava/util/Set;") || (name=="iterator" && signature=="()Ljava/util/Iterator;") ||
                (name=="hasNext" && signature=="()Z") ||
                ((name=="next" || name=="getKey" || name=="getValue") && signature=="()Ljava/lang/Object;");
            if(native_query && (map_class(type) || map_view_class(type) || collection_class(type) || set_class(type) || array_view_class(type))) {
                if(!arguments.empty())fail("SIGNATURE","Named native collection query requires no arguments");
                NonYielding barrier(current_context());
                if(const auto result=named_map_support(receiver,type,name,signature,frame.arguments))return *result;
            }
            if(type==atomic_long_type && name!="<init>" && atomic_long_method(name,signature)) {
                authenticate_named(frame,signature,arguments);
                NonYielding barrier(current_context());
                auto &state=object(receiver).atomic_long;
                if(!state)fail("STATE","AtomicLong lacks authenticated storage");
                if(const auto result=state->invoke(runtime,name,signature,frame.arguments))return *result;
            }
            if(type==atomic_long_type && (name=="getAndUpdate" || name=="updateAndGet" ||
                name=="getAndAccumulate" || name=="accumulateAndGet"))
                fail("API_UNSUPPORTED","AtomicLong functional update callbacks are not implemented");
            if(type==random_type && name!="<init>" && random_method(name,signature)) {
                authenticate_named(frame,signature,arguments);NonYielding barrier(current_context());
                return invoke_random(receiver,name,signature,frame.arguments);
            }
            if(type==uuid_type) {
                bool known=false;std::size_t count=0;std::string_view parameter;
                if(((name=="getMostSignificantBits" || name=="getLeastSignificantBits") && signature=="()J") ||
                    ((name=="version" || name=="variant" || name=="hashCode") && signature=="()I") ||
                    (name=="toString" && signature=="()Ljava/lang/String;"))known=true;
                else if(name=="equals" && signature=="(Ljava/lang/Object;)Z") {known=true;count=1;parameter="Ljava/lang/Object;";}
                else if(name=="compareTo" && (signature=="(Ljava/util/UUID;)I" || signature=="(Ljava/lang/Object;)I")) {
                    known=true;count=1;parameter=signature=="(Ljava/util/UUID;)I"?uuid_type:"Ljava/lang/Object;";
                }
                if(known) {
                    if(arguments.size()!=count)fail("SIGNATURE","Wrong named UUID argument count");
                    if(count)frame.arguments[1]=typed(arguments[0],parameter);
                    NonYielding barrier(current_context());
                    if(const auto result=invoke_uuid(receiver,name,signature,frame.arguments))return *result;
                }
            }
            if(type==thread_local_type && name!="<init>" && thread_local_method(name,signature)) {
                const bool one=name=="set";
                if(arguments.size()!=(one?1U:0U))fail("SIGNATURE","Wrong named ThreadLocal argument count");
                if(one)frame.arguments[1]=typed(arguments[0],"Ljava/lang/Object;");
                NonYielding barrier(current_context());
                if(const auto result=invoke_thread_local(receiver,name,signature,frame.arguments))return *result;
            }
            if(regex_method(type,name,signature)) {
                const bool one=signature[1]!=')';
                if(arguments.size()!=(one?1U:0U))fail("SIGNATURE","Wrong named regex argument count");
                if(one)frame.arguments[1]=typed(arguments[0],signature[1]=='I'?"I":"Ljava/lang/CharSequence;");
                NonYielding barrier(current_context());
                if(const auto result=invoke_regex(receiver,name,signature,frame.arguments))return *result;
            }
            if(type=="Ljava/lang/StringBuilder;" && name=="append" && signature=="(Z)Ljava/lang/StringBuilder;") {
                authenticate_named(frame,signature,arguments);
                NonYielding barrier(current_context());
                return append_boolean(receiver,word(frame.arguments[1])!=0);
            }
            if(type=="Ljava/lang/StringBuilder;" && name=="append" && signature=="(Ljava/lang/Object;)Ljava/lang/StringBuilder;") {
                authenticate_named(frame,signature,arguments);
                NonYielding barrier(current_context());
                return append_object(receiver,reference(frame.arguments[1]));
            }
            if((type=="Ljava/lang/String;" || type=="Ljava/lang/StringBuilder;") && name=="toString" && signature=="()Ljava/lang/String;") {
                if(!arguments.empty())fail("SIGNATURE","Named CharSequence.toString requires no arguments");
                NonYielding barrier(current_context());
                return Value::reference(type=="Ljava/lang/String;"?receiver:runtime.new_string(runtime.char_sequence(receiver)));
            }
            if((type==long_type || type==short_type) && name!="<init>" && integral_method(type,name,signature)) {
                const bool one=name=="equals" || name=="compareTo";
                if(arguments.size()!=(one?1U:0U))fail("SIGNATURE","Wrong named integral wrapper argument count");
                if(one)frame.arguments[1]=typed(arguments[0],signature=="(Ljava/lang/Long;)I"?long_type:
                    signature=="(Ljava/lang/Short;)I"?short_type:"Ljava/lang/Object;");
                NonYielding barrier(current_context());
                if(const auto result=invoke_integral(receiver,name,signature,frame.arguments))return *result;
            }
            if((type==float_type || type==double_type) && name=="toString" && signature=="()Ljava/lang/String;") {
                if(!arguments.empty())fail("SIGNATURE","Named floating toString requires no arguments");
                fail("API_UNSUPPORTED","Java floating decimal formatting is not implemented");
            }
            if((type==float_type || type==double_type) && name!="<init>" && floating_method(type,name,signature)) {
                const bool one=name=="equals" || name=="compareTo";
                if(arguments.size()!=(one?1U:0U))fail("SIGNATURE","Wrong named floating wrapper argument count");
                if(one)frame.arguments[1]=typed(arguments[0],signature=="(Ljava/lang/Double;)I"?double_type:
                    signature=="(Ljava/lang/Float;)I"?float_type:"Ljava/lang/Object;");
                NonYielding barrier(current_context());
                if(const auto result=invoke_floating(receiver,name,signature,frame.arguments))return *result;
            }
            if(type==byte_type && name!="<init>" && byte_method(name,signature)) {
                const bool one=name=="equals" || name=="compareTo";
                if(arguments.size()!=(one?1U:0U))fail("SIGNATURE","Wrong named Byte argument count");
                if(one)frame.arguments[1]=typed(arguments[0],signature=="(Ljava/lang/Byte;)I"?byte_type:"Ljava/lang/Object;");
                NonYielding barrier(current_context());
                if(const auto result=invoke_byte(receiver,name,signature,frame.arguments))return *result;
            }
            if(type==boolean_type) {
                NonYielding barrier(current_context());
                bool known=false;std::size_t count=0;std::string_view parameter;
                if((name=="booleanValue" && signature=="()Z") || (name=="hashCode" && signature=="()I") ||
                    (name=="toString" && signature=="()Ljava/lang/String;"))known=true;
                else if(name=="equals" && signature=="(Ljava/lang/Object;)Z") {
                    known=true;count=1;parameter="Ljava/lang/Object;";
                } else if(name=="compareTo" && (signature=="(Ljava/lang/Boolean;)I" || signature=="(Ljava/lang/Object;)I")) {
                    known=true;count=1;parameter=signature=="(Ljava/lang/Boolean;)I"?boolean_type:"Ljava/lang/Object;";
                }
                if(known) {
                    if(arguments.size()!=count)fail("SIGNATURE","Wrong named Boolean argument count");
                    if(count)frame.arguments[1]=typed(arguments[0],parameter);
                    if(const auto result=invoke_boolean(receiver,name,signature,frame.arguments))return *result;
                }
            }
            if(type==async_future_type) {type=future_task_type;}
            if(type==async_task_type || async_internal_type(type)) {
                NonYielding barrier(current_context());
                // Named routes have no verified DEX prototype. Validate the exact
                // builtin tail before indexing it or publishing lifecycle effects.
                std::array<std::string_view,2> parameters{};
                std::size_t count=0;bool known=false;
                if(type==async_task_type) {
                    if((name=="onPreExecute" || name=="onCancelled") && signature=="()V")known=true;
                    else if(name=="getStatus" && signature=="()Landroid/os/AsyncTask$Status;")known=true;
                    else if(name=="isCancelled" && signature=="()Z")known=true;
                    else if(name=="get" && signature=="()Ljava/lang/Object;")known=true;
                    else if(name=="get" && signature=="(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;") {
                        known=true;parameters={"J",time_unit_type};count=2;
                    } else if(name=="cancel" && signature=="(Z)Z") {
                        known=true;parameters[0]="Z";count=1;
                    } else if((name=="onCancelled" || name=="onPostExecute") && signature=="(Ljava/lang/Object;)V") {
                        known=true;parameters[0]="Ljava/lang/Object;";count=1;
                    } else if((name=="onProgressUpdate" || name=="publishProgress") && signature=="([Ljava/lang/Object;)V") {
                        known=true;parameters[0]="[Ljava/lang/Object;";count=1;
                    } else if(name=="execute" && signature=="([Ljava/lang/Object;)Landroid/os/AsyncTask;") {
                        known=true;parameters[0]="[Ljava/lang/Object;";count=1;
                    } else if(name=="executeOnExecutor" && signature=="(Ljava/util/concurrent/Executor;[Ljava/lang/Object;)Landroid/os/AsyncTask;") {
                        known=true;parameters={"Ljava/util/concurrent/Executor;","[Ljava/lang/Object;"};count=2;
                    }
                } else if(type==async_callable_type && name=="call" && signature=="()Ljava/lang/Object;")known=true;
                else if(type==async_serial_wrapper_type && name=="run" && signature=="()V")known=true;
                else if(type==async_serial_type && name=="execute" && signature=="(Ljava/lang/Runnable;)V") {
                    known=true;parameters[0]="Ljava/lang/Runnable;";count=1;
                } else if(type==async_factory_type && name=="newThread" && signature=="(Ljava/lang/Runnable;)Ljava/lang/Thread;") {
                    known=true;parameters[0]="Ljava/lang/Runnable;";count=1;
                } else if(type==async_backup_policy_type && name=="rejectedExecution" && signature=="(Ljava/lang/Runnable;Ljava/util/concurrent/ThreadPoolExecutor;)V") {
                    known=true;parameters={"Ljava/lang/Runnable;",thread_pool_type};count=2;
                }
                if(known) {
                    if(arguments.size()!=count)fail("SIGNATURE", "Wrong named AsyncTask SDK argument count");
                    for(std::size_t n=0;n<count;++n)
                        frame.arguments[n+1]=parameters[n]=="Z"?Value::word(word(arguments[n])!=0):typed(arguments[n],parameters[n]);
                    if(type==async_task_type) {
                        if(const auto result=invoke_async(receiver,name,signature,frame.arguments))return *result;
                    } else if(const auto result=invoke_async_sdk(receiver,name,signature,frame.arguments))return *result;
                }
                // Unrelated names may resolve to a managed interface default;
                // preserve the ordinary maximally-specific search below.
            }
            if(type==future_task_type) {
                // A named host/SDK route has no ordinary core() frame. Own a
                // core barrier here, so existing provider/native barriers can
                // never be mistaken for the suspension gateway's own barrier.
                NonYielding barrier(current_context());
                bool known=false;
                if((name=="run" || name=="done") && signature=="()V")known=arguments.empty();
                else if((name=="isDone" || name=="isCancelled" || name=="runAndReset") && signature=="()Z")known=arguments.empty();
                else if(name=="get" && signature=="()Ljava/lang/Object;")known=arguments.empty();
                else if(name=="cancel" && signature=="(Z)Z" && arguments.size()==1){frame.arguments[1]=Value::word(word(arguments[0])!=0);known=true;}
                else if(name=="set" && signature=="(Ljava/lang/Object;)V" && arguments.size()==1){frame.arguments[1]=typed(arguments[0],"Ljava/lang/Object;");known=true;}
                else if(name=="setException" && signature=="(Ljava/lang/Throwable;)V" && arguments.size()==1){frame.arguments[1]=typed(arguments[0],"Ljava/lang/Throwable;");known=true;}
                else if(name=="get" && signature=="(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;" && arguments.size()==2) {
                    frame.arguments[1]=Value::wide(wide(arguments[0]));frame.arguments[2]=typed(arguments[1],time_unit_type);known=true;
                }
                if(known)if(const auto result=invoke_future(receiver,name,signature,frame.arguments))return *result;
            }
            if(type==thread_pool_type && name=="execute" && signature=="(Ljava/lang/Runnable;)V" && arguments.size()==1) {
                frame.arguments[1]=typed(arguments[0],"Ljava/lang/Runnable;");
                NonYielding barrier(current_context());
                return *invoke_pool(receiver,name,signature,frame.arguments,{});
            }
            if (type == pool_worker_type && name=="run" && signature=="()V" && arguments.empty()) {
                if(!object(receiver).pool_worker)fail("EXECUTOR_WORKER_STATE", "Worker lacks authenticated state");
                run_pool_worker(receiver);return Value::nothing();
            }
            if ((type=="Ljava/lang/Thread;" &&
                 ((name=="getUncaughtExceptionHandler" && signature=="()Ljava/lang/Thread$UncaughtExceptionHandler;") ||
                  (name=="setUncaughtExceptionHandler" && signature=="(Ljava/lang/Thread$UncaughtExceptionHandler;)V"))) ||
                (type=="Ljava/lang/ThreadGroup;" && name=="uncaughtException" && signature=="(Ljava/lang/Thread;Ljava/lang/Throwable;)V")) {
                const auto count=name=="getUncaughtExceptionHandler"?0u:name=="setUncaughtExceptionHandler"?1u:2u;
                if(arguments.size()!=count)fail("SIGNATURE","Wrong named thread-handler argument count");
                if(count==1)frame.arguments[1]=typed(arguments[0],"Ljava/lang/Thread$UncaughtExceptionHandler;");
                if(count==2) {
                    frame.arguments[1]=typed(arguments[0],"Ljava/lang/Thread;");
                    frame.arguments[2]=typed(arguments[1],"Ljava/lang/Throwable;");
                }
                NonYielding barrier(current_context());
                return *thread_handler_call(receiver,type,name,signature,frame.arguments);
            }
            if (type == "Ljava/lang/Thread;" && name=="start" && signature=="()V" && arguments.empty()) {
                start_java_thread(receiver);return Value::nothing();
            }
            if (type == default_thread_factory_type && name=="newThread" &&
                signature=="(Ljava/lang/Runnable;)Ljava/lang/Thread;" && arguments.size()==1) {
                const auto target=reference(typed(arguments[0],"Ljava/lang/Runnable;"));
                return Value::reference(default_factory_thread(receiver,target));
            }
            if (type == thread_pool_type &&
                ((name=="beforeExecute" && signature=="(Ljava/lang/Thread;Ljava/lang/Runnable;)V") ||
                 (name=="afterExecute" && signature=="(Ljava/lang/Runnable;Ljava/lang/Throwable;)V") ||
                 (name=="terminated" && signature=="()V")))return Value::nothing();
            if(type==abort_policy_type && name=="rejectedExecution" &&
                signature=="(Ljava/lang/Runnable;Ljava/util/concurrent/ThreadPoolExecutor;)V") {
                auto &policy=object(receiver).abort_policy;
                if(!policy)fail("STATE", "AbortPolicy lacks authenticated state");
                return *policy->invoke(runtime,abort_policy_type,name,signature);
            }
            if (type == "Ljava/lang/Thread;" && allow_thread_base) {
                const auto target = thread_state(receiver).target;
                if (target) run_runnable(target, true);
                return Value::nothing();
            }
            const auto *definition = resolve_class(type);
            if (!definition) {
                // Exact public provider toString at the actual hierarchy boundary.
                // Managed overrides were searched first; no synthetic DEX ID or
                // Object fallback may replace a provider's real representation.
                if(host && name=="toString" && signature=="()Ljava/lang/String;" &&
                   !core_type(type) && provider_call([&]{return host->class_info(type);})) {
                    if(!arguments.empty())fail("SIGNATURE","Named provider toString requires no arguments");
                    const auto method=provider_call([&]{return host->public_method(type,name,{});});
                    if(method && method->name==name && method->parameters.empty() &&
                       method->return_type=="Ljava/lang/String;" && (method->flags&1) && !(method->flags&(8|0x400)) &&
                       subtype(object(receiver).type,method->owner)) {
                        NonYielding barrier(current_context());
                        return typed(provider_call([&]{return host->invoke_reflected(runtime,*method,frame.arguments);}),"Ljava/lang/String;");
                    }
                }
                break;
            }
            for (const auto interface : definition->interfaces) interfaces.push_back(image.types.at(interface));
            for (const auto candidate : definition->virtual_methods) {
                const auto &method = image.methods.at(candidate);
                if (method.name == name && image.prototypes.at(method.prototype).descriptor == signature) {
                    if ((method.flags & 8) || method.direct)
                        fail("INVOKE_KIND", "Named virtual target is static or direct");
                    return runtime.invoke_virtual(candidate, std::span<const Value>(frame.arguments));
                }
            }
            if (definition->superclass == no_index) break;
            type = image.types.at(definition->superclass);
        }
        if (depth == 256) fail("CLASS_LIMIT", "Named virtual class hierarchy exceeds limit");
        // A managed implementation may inherit a genuine interface default.
        // Seed the existing default-resolution algorithm with a real declaration;
        // never fabricate a method ID in the append-only demand-linked image.
        std::set<std::string_view> seen;
        std::size_t work = 0;
        bool matching_abstract_default=false;
        while (!interfaces.empty()) {
            if (++work > 262144) fail("CLASS_LIMIT", "Named virtual interface search exceeds its work budget");
            const auto interface = interfaces.back(); interfaces.pop_back();
            if (!seen.insert(interface).second) continue;
            if (seen.size() > 65536) fail("CLASS_LIMIT", "Named virtual interface search exceeds its class budget");
            const auto *definition = resolve_class(interface);
            if (!definition) continue;
            for (const auto parent : definition->interfaces) interfaces.push_back(image.types.at(parent));
            for (const auto candidate : definition->virtual_methods) {
                if (++work > 262144) fail("CLASS_LIMIT", "Named virtual interface search exceeds its work budget");
                const auto &method = image.methods.at(candidate);
                if (method.name == name && image.prototypes.at(method.prototype).descriptor == signature) {
                    if(method.flags & 0x400)matching_abstract_default=true;
                    if (const auto target = default_target(candidate, {object(receiver).type})) {
                        return runtime.invoke_virtual(*target, std::span<const Value>(frame.arguments));
                    }
                }
            }
        }
        // SDK29 lifecycle pre/post callbacks have genuine empty default bodies.
        // This fallback is deliberately after managed class/interface resolution:
        // a real override/default or abstract redeclaration must win first.
        {
            static constexpr std::array<std::string_view,14> defaults{
                "onActivityPreCreated","onActivityPostCreated","onActivityPreStarted","onActivityPostStarted",
                "onActivityPreResumed","onActivityPostResumed","onActivityPrePaused","onActivityPostPaused",
                "onActivityPreStopped","onActivityPostStopped","onActivityPreSaveInstanceState","onActivityPostSaveInstanceState",
                "onActivityPreDestroyed","onActivityPostDestroyed"};
            if(std::find(defaults.begin(),defaults.end(),name)!=defaults.end()) {
                const bool bundle=name.ends_with("Created") || name.ends_with("SaveInstanceState");
                const auto expected=bundle?"(Landroid/app/Activity;Landroid/os/Bundle;)V":"(Landroid/app/Activity;)V";
                if(signature==expected && !matching_abstract_default && subtype(object(receiver).type,"Landroid/app/Application$ActivityLifecycleCallbacks;")) {
                    if(arguments.size()!=(bundle?2U:1U))fail("SIGNATURE","Wrong named lifecycle default argument count");
                    frame.arguments[1]=typed(arguments[0],"Landroid/app/Activity;");
                    if(bundle)frame.arguments[2]=typed(arguments[1],"Landroid/os/Bundle;");
                    return Value::nothing();
                }
            }
        }
        fail("ABSTRACT_METHOD", "Receiver has no executable managed virtual " + std::string(name) + std::string(signature));
    }
    void run_runnable(ObjectId receiver, bool allow_thread_base) {
        (void)call_virtual_named(receiver, "run", "()V", {}, allow_thread_base);
    }
    std::optional<Value> thread_handler_call(ObjectId receiver, std::string_view type,
                                            std::string_view name, std::string_view signature,
                                            std::span<const Value> args) {
        constexpr std::string_view handler_type="Ljava/lang/Thread$UncaughtExceptionHandler;";
        if(type=="Ljava/lang/Thread;") {
            if(name=="getUncaughtExceptionHandler" && signature=="()Ljava/lang/Thread$UncaughtExceptionHandler;") {
                const auto &state=thread_state(receiver);
                if(state.uncaught_handler)return Value::reference(state.uncaught_handler);
                if(state.lifecycle==ThreadState::Lifecycle::terminated)return Value::reference(0);
                if(!state.group) {
                    const auto group=thread_group();
                    thread_state(receiver).group=group;
                }
                return Value::reference(thread_state(receiver).group);
            }
            if(name=="setUncaughtExceptionHandler" && signature=="(Ljava/lang/Thread$UncaughtExceptionHandler;)V") {
                (void)thread_state(receiver);
                const auto handler=reference(args[1]);
                if(handler && !subtype(object(handler).type,handler_type))fail("VALUE_TYPE","Thread handler does not implement UncaughtExceptionHandler");
                thread_state(receiver).uncaught_handler=handler;
                return Value::nothing();
            }
        }
        if((type=="Ljava/lang/ThreadGroup;" || type==handler_type) && name=="uncaughtException" &&
           signature=="(Ljava/lang/Thread;Ljava/lang/Throwable;)V") {
            if(!thread_group_object || receiver!=thread_group_object)
                fail("THREAD_STATE","ThreadGroup is not this runtime's owner group");
            const auto handler=default_uncaught_handler;
            if(!handler) {
                const auto error=reference(args[2]);
                if(!error)runtime.raise("Ljava/lang/NullPointerException;");
                fail("THREAD_UNCAUGHT_EXCEPTION","Uncaught "+object(error).type+"; default ThreadGroup logging is unsupported");
            }
            if(!current_context().barriers)fail("STATE","ThreadGroup handler lacks its core boundary");
            SuspendCoreBarrier allow(current_context());
            (void)call_virtual_named(handler,"uncaughtException",signature,args.subspan(1));
            return Value::nothing();
        }
        return {};
    }
    void finish_java_thread(ObjectId receiver) noexcept {
        const auto found = heap.find(receiver);
        if (found == heap.end() || !found->second.thread) std::terminate();
        auto &state = *found->second.thread;
        if(state.pool_worker) {
            const auto worker=heap.find(state.pool_worker);
            if(worker==heap.end() || !worker->second.pool_worker)std::terminate();
            auto &worker_state=*worker->second.pool_worker;
            const auto pool=heap.find(worker_state.pool());
            if(pool==heap.end() || !pool->second.pool)std::terminate();
            if(!worker_state.exited)pool_worker_exit(state.pool_worker);
            for(auto &root:pool->second.pool->workers())if(root.bits==state.pool_worker){root={};break;}
            for(auto &task:tasks)if(task && task->context.thread_object==receiver) {
                task->maintenance_pool=worker_state.pool();task->maintenance_abrupt=worker_state.abrupt;
                task->missing_worker=!worker_state.entered;break;
            }
            state.pool_worker=0;
        }
        clear_thread_locals(receiver);
        state.lifecycle = ThreadState::Lifecycle::terminated;
        state.target = state.group = state.uncaught_handler = 0;
    }
    struct JavaThreadEntry final : ManagedWorkerEntry {
        Impl &owner;
        std::array<Value, 1> roots;
        JavaThreadEntry(Impl &owner, ObjectId receiver) : owner(owner), roots{Value::reference(receiver)} {}
        void run(ManagedRuntime &) override {
            try {owner.run_runnable(roots[0].bits, true);}
            catch(const JavaException &error) {
                // Delivery is on the dying Java logical thread, before exit clears
                // its group, handler and ThreadLocals. Ordinary invoke/run calls
                // keep propagating exceptions to their actual caller.
                owner.runtime.retain(error.object);
                struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} root{owner.runtime,error.object};
                try {
                    const auto handler=reference(owner.call_virtual_named(roots[0].bits,"getUncaughtExceptionHandler",
                        "()Ljava/lang/Thread$UncaughtExceptionHandler;"));
                    const std::array arguments{roots[0],Value::reference(error.object)};
                    (void)owner.call_virtual_named(handler,"uncaughtException",
                        "(Ljava/lang/Thread;Ljava/lang/Throwable;)V",arguments);
                } catch(const JavaException &) {
                    // The Java contract ignores Java throwables from the handler,
                    // including a null/throwing overridden getter. Runtime/native
                    // failures and private scheduler cancellation must escape.
                }
                owner.current_context().last_exception=0;
            }
        }
        std::span<const Value> values() const noexcept override { return roots; }
        std::size_t bytes() const noexcept override { return sizeof(JavaThreadEntry); }
    };
    void start_java_thread(ObjectId receiver) {
        auto &state = thread_state(receiver);
        if (state.lifecycle != ThreadState::Lifecycle::fresh)
            runtime.raise("Ljava/lang/IllegalThreadStateException;");
        const auto inherited_signal_mask = native ? native->capture_signal_mask(runtime) : 0;
        // Admission roots/binds the original Thread before scheduler publication.
        // No child can execute inline, so failed admission leaves it NEW.
        (void)submit_task(no_index, {}, false, std::make_unique<JavaThreadEntry>(*this, receiver), receiver);
        state.inherited_signal_mask = inherited_signal_mask;
        state.lifecycle = ThreadState::Lifecycle::started;
    }
    void reap_java_threads(bool report_failure = true) {
        if(process->exit_status())report_failure=false;
        for (auto &entry : tasks) if (entry && entry->java_owned) {
            const auto state = scheduler->state(entry->id);
            if (state != Scheduler::State::completed && state != Scheduler::State::cancelled &&
                state != Scheduler::State::failed) continue;
            if(process->exit_status()) {
                // No pool maintenance, exception formatting or new pins while
                // terminal stacks are being reclaimed.
                finish_task_context(entry->context);
                scheduler->release(entry->id);metrics.heap_bytes-=entry->charged;entry.reset();
                continue;
            }
            const auto exception = scheduler->exception(entry->id);
            std::string diagnostic;
            if (report_failure && exception) {
                try { std::rethrow_exception(exception); }
                catch (const JavaException &error) {
                    const auto found = heap.find(error.object);
                    diagnostic = "Uncaught " + (found == heap.end() ? std::string("managed exception") : found->second.type);
                } catch (const DexError &error) { diagnostic = error.code + ": " + error.what(); }
                catch (const std::exception &error) { diagnostic = error.what(); }
                catch (...) { diagnostic = "Unknown host failure"; }
            }
            finish_task_context(entry->context); // Also handles cancellation before first run.
            const auto pool=entry->maintenance_pool;
            const bool abrupt=entry->maintenance_abrupt;
            const bool missing=entry->missing_worker;
            // Keep maintenance roots after releasing the terminated worker slot,
            // including through real factory/hook callbacks and their collections.
            if(pool)++pins[pool];
            struct Unpin {Impl &owner;ObjectId id;~Unpin(){if(id){auto found=owner.pins.find(id);if(found==owner.pins.end())std::terminate();if(!--found->second)owner.pins.erase(found);}}} unpin{*this,pool};
            scheduler->release(entry->id);
            metrics.heap_bytes -= entry->charged;
            entry.reset();
            if(report_failure && pool && !tasks_closing) {
                try {pool_maintenance(pool,abrupt);}
                catch(const DexError &error) {if(exception)diagnostic+="; replacement: "+error.code+": "+error.what();else throw;}
                catch(...) {if(exception)diagnostic+="; replacement callback failed";else throw;}
            }
            if(report_failure && missing && !tasks_closing && !exception)
                fail("THREAD_FACTORY_UNSUPPORTED", "Factory Thread terminated without invoking its supplied Worker Runnable");
            if (report_failure && exception) {
                if (diagnostic.empty()) diagnostic = "Unhandled host failure with no diagnostic text";
                fail("THREAD_UNCAUGHT_EXCEPTION", diagnostic);
            }
        }
    }
    bool pump_task() {
        execution_checkpoint();
        // Every caller is the owned main fiber, including managed safepoints and
        // audited main sleep/yield. Host-owned retained task IDs are untouched.
        reap_java_threads();
        const bool ran = scheduler && scheduler->run_one();
        execution_checkpoint();
        reap_java_threads();
        return ran;
    }
    TaskContext &persistent_worker() {
        check_thread();
        if (execution_owner != 0 || !background() || !scheduler)
            fail("TASK_STATE", "Persistent worker operation requires its owned background context");
        const auto id = scheduler->current();
        auto &entry = task(id);
        if (!entry.worker || !entry.context.frames.empty() || entry.context.invocations || entry.context.barriers)
            fail("TASK_STATE", "Persistent worker operation requires an empty managed stack without barriers");
        for (const auto root : entry.checked_worker_roots())
            if (root.kind == ValueKind::reference && root.bits) (void)object(root.bits);
        return entry;
    }
    void task_owner(bool require_idle = false) const {
        check_thread();
        if (background() || execution_owner != 0)
            fail("TASK_STATE", "Managed task control requires the external main context");
        if (scheduler) (void)scheduler->current();
        if (require_idle && (!main_context.frames.empty() || main_context.barriers))
            fail("TASK_STATE", "Managed task pumping requires an idle main context");
    }
    void main_post_owner() const {
        check_thread();
        execution_checkpoint();
        if(scheduler)(void)scheduler->current();
        if(execution_owner || main_callbacks_closed || main_callback_posting)
            fail("MAIN_CALLBACK_STATE", "Main callback queue is closed, borrowed or already accepting an entry");
    }
    void accept_main_callback(std::unique_ptr<MainCallback> callback) {
        const auto base_charge=sizeof(MainCallback)+callback->arguments.capacity()*sizeof(Value);
        if(base_charge>limits.heap_bytes || callback->entry_bytes>limits.heap_bytes-base_charge)
            fail("HEAP_LIMIT", "Main callback entry exceeds the managed heap quota");
        callback->charged=base_charge+callback->entry_bytes;
        const auto capacity_charge=main_callback_capacity_charged?0:sizeof(main_callbacks);
        if(capacity_charge>limits.heap_bytes-callback->charged)
            fail("HEAP_LIMIT", "Main callback queue capacity exceeds the managed heap quota");
        const auto total_charge=callback->charged+capacity_charge;
        main_callback_posting=callback.get();
        struct PostingEnd {Impl &owner;~PostingEnd(){owner.main_callback_posting=nullptr;}} posting_end{*this};
        if(total_charge>limits.heap_bytes-metrics.heap_bytes)collect();
        if(total_charge>limits.heap_bytes-metrics.heap_bytes)
            fail("HEAP_LIMIT", "Main callback queue exceeds the managed heap quota");
        const bool new_batch=!main_callback_count && !main_callback_inflight;
        metrics.heap_bytes+=total_charge;main_callback_capacity_charged=true;
        const auto slot=(main_callback_head+main_callback_count)%main_callbacks.size();
        callback->published=true;
        main_callbacks[slot]=std::move(callback);++main_callback_count;
        if(new_batch)main_callback_work_remaining=limits.instructions;
    }
    void main_callback_owner(bool teardown = false) const {
        check_thread(teardown);
        if(!teardown)execution_checkpoint();
        if (scheduler) (void)scheduler->current();
        if (background() || execution_owner != 0 || !main_context.frames.empty() ||
            main_context.barriers || main_context.invocations || main_callback_inflight)
            fail("MAIN_CALLBACK_STATE", "Main callback delivery requires the idle external main context");
    }
    bool active_tasks() const {
        if (!scheduler) return false;
        for (const auto &entry : tasks) if (entry) {
            const auto state = scheduler->state(entry->id);
            if (state != Scheduler::State::completed && state != Scheduler::State::cancelled &&
                state != Scheduler::State::failed) return true;
        }
        return false;
    }
    Index caller_frame_method() const {
        const auto &frames = current_context().frames;
        // Internal Thread routing frames carry roots/depth, never image IDs.
        if (frames.size() < 2) return no_index;
        for (auto at = frames.size() - 1; at; ) {
            const auto method = frames[--at]->method;
            if (method != no_index) return method;
        }
        return no_index;
    }
    void check_monitor_available(ObjectId id) const {
        const auto &active=current_context();
        const auto check=[&](const ExecutionContext &context){
            if(&context==&active)return;
            for(const auto *frame:context.frames)for(std::size_t n=0;n<frame->monitor_count;++n)
                if(frame->monitors[n]==id)fail("THREAD_BLOCKING_UNSUPPORTED","Monitor is owned by another logical thread");
        };
        check(main_context);for(const auto &task:tasks)if(task)check(task->context);
        for(std::size_t n=0;n<native_context_depth;++n)check(*native_contexts[n]);
    }
    std::size_t frame_count() const {
        auto count = main_context.frames.size();
        for(std::size_t n=0;n<native_context_depth;++n)count+=native_contexts[n]->frames.size();
        for (const auto &task : tasks) if (task) count += task->context.frames.size();
        return count;
    }
    void safepoint() {
        execution_checkpoint();
        auto &context = current_context();
        if (context.quantum) { --context.quantum; return; }
        context.quantum = 127;
        if (!scheduler || context.barriers) return;
        for (const auto *frame : context.frames) if (frame->monitor_count) return;
        if (background()) scheduler->yield();
        else (void)pump_task();
    }
    ~Impl() {
        // Contexts and their traced roots remain alive while cancellation unwinds
        // suspended interpreter stacks. Never delete live callback stacks.
        if (scheduler) {
            try {
                tasks_closing=true;
                for(auto &task:tasks)if(task)task->context.cancellation_requested=true;
                scheduler->close();
                for(auto &task:tasks)if(task)finish_task_context(task->context);
                reap_java_threads(false);
            } catch (...) { std::terminate(); }
        }
    }
    Impl(ManagedRuntime &runtime, DexImage input, RuntimeLimits limits,
         std::shared_ptr<ClassSource> source = {})
        : runtime(runtime), image(std::move(input)), limits(limits) {
        if (!limits.instructions || limits.instructions > 10'000'000 || !limits.frames ||
            limits.frames > 128 || !limits.objects || limits.objects > 65536 || limits.heap_bytes < 1024 ||
            limits.heap_bytes > 64 * 1024 * 1024 || !limits.array_length || limits.array_length > 1'048'576)
            fail("LIMIT", "Invalid managed runtime limits");
        if (source)
            loader = std::make_unique<ClassLoader>(image, std::move(source));
        for (const auto &p : image.prototypes) {
            if (p.return_type >= image.types.size())
                fail("INDEX", "Invalid return type");
            for (auto t : p.parameters)
                if (t >= image.types.size())
                    fail("INDEX", "Invalid parameter type");
        }
        for (const auto &m : image.methods)
            if (m.owner >= image.types.size() || m.prototype >= image.prototypes.size())
                fail("INDEX", "Invalid method metadata");
        for (const auto &f : image.fields)
            if (f.owner >= image.types.size() || f.type >= image.types.size())
                fail("INDEX", "Invalid field metadata");
    }
    void check_thread(bool teardown = false) const {
        if (owner != std::this_thread::get_id())
            fail("THREAD", "Managed runtime belongs to another thread");
        (void)current_context();
        // Failed loading blocks execution, but root release and interface
        // detachment must still work while framework/JNI owners unwind.
        if (loader && !teardown)
            loader->check();
        if (!teardown && loader_object) {
            const auto count = image.classes.size();
            if (sealed_loader_checked_classes > count)
                fail("CLASS_LOADER_UNSUPPORTED", "Held class space no longer has append-only metadata");
            for (auto index = sealed_loader_checked_classes; index < count; ++index) {
                const auto &descriptor = image.types.at(image.classes[index].type);
                if (descriptor == "Ljava/lang/ClassLoader;" || descriptor == "Laether/dex/RuntimeClassLoader;")
                    fail("CLASS_LOADER_UNSUPPORTED", "Held class collides with the sealed runtime ClassLoader space");
            }
            sealed_loader_checked_classes = count;
        }
    }
    const Class *resolve_class(std::string_view descriptor) const {
        check_thread();
        if (loader) {
            NonYielding barrier(current_context());
            LoadingProgress progress(*this,descriptor);
            const auto *definition=loader->definition(descriptor);
            check_thread(); // A newly linked file may contain a reserved loader definition.
            return definition;
        }
        return image.definition(descriptor);
    }
    const Object &object(ObjectId id) const {
        check_thread();
        if (!id)
            const_cast<ManagedRuntime &>(runtime).raise("Ljava/lang/NullPointerException;");
        const auto it = heap.find(id);
        if (it == heap.end())
            fail("REFERENCE", "Invalid, collected, or foreign managed reference");
        return it->second;
    }
    Object &object(ObjectId id) { return const_cast<Object &>(std::as_const(*this).object(id)); }
    void known(std::string_view type) const {
        std::size_t dimensions = 0;
        while (!type.empty() && type.front() == '[') {
            ++dimensions;
            type.remove_prefix(1);
        }
        if (dimensions > 255 || type.empty() || (dimensions && type == "V"))
            fail("CLASS_NOT_FOUND", "Invalid or excessively deep class/array descriptor");
        if (type.size() == 1 && std::string_view("VZBSCIJFD").find(type[0]) != std::string_view::npos)
            return;
        if (!core_type(type) && !resolve_class(type) && !(host && provider_call([&] { return host->class_info(type); })))
            fail("CLASS_UNSUPPORTED", "Class not implemented: " + std::string(type));
    }
    bool subtype(std::string_view from, std::string_view to) const {
        if (from == to)
            return true;
        if (from.empty() || to.empty())
            return false;
        if (from.front() == '[') {
            if (to == "Ljava/lang/Object;" || to == "Ljava/lang/Cloneable;" || to == "Ljava/io/Serializable;")
                return true;
            return to.front() == '[' && reference_type(from.substr(1)) && reference_type(to.substr(1)) &&
                   subtype(from.substr(1), to.substr(1));
        }
        std::vector<std::string_view> todo{from};
        std::set<std::string_view> seen;
        while (!todo.empty()) {
            const auto current = todo.back();
            todo.pop_back();
            if (current == to)
                return true;
            if (current.empty() || !seen.insert(current).second)
                continue;
            if (seen.size() > 65536)
                fail("CLASS_LIMIT", "Class hierarchy exceeds limit");
            if (const auto *definition = resolve_class(current)) {
                if (definition->superclass != no_index)
                    todo.push_back(image.types.at(definition->superclass));
                for (const auto type : definition->interfaces)
                    todo.push_back(image.types.at(type));
            } else if (host && provider_call([&] { return host->class_info(current); })) {
                const auto info = *provider_call([&] { return host->class_info(current); });
                todo.push_back(info.superclass);
                todo.insert(todo.end(), info.interfaces.begin(), info.interfaces.end());
            } else {
                todo.push_back(core_super(current));
                if (current == "Ljava/lang/Thread;")
                    todo.push_back("Ljava/lang/Runnable;");
                if (current == "Ljava/lang/ThreadGroup;")
                    todo.push_back("Ljava/lang/Thread$UncaughtExceptionHandler;");
                if (current == "Ljava/lang/Class;")
                    todo.push_back("Ljava/lang/reflect/Type;");
                if (current == "Ljava/util/BitSet;") {
                    todo.push_back("Ljava/lang/Cloneable;");
                    todo.push_back("Ljava/io/Serializable;");
                }
                if(const auto literal=literal_metadata_class(current))
                    todo.insert(todo.end(),literal->interfaces.begin(),literal->interfaces.end());
                if(const auto info=stream_class(current))todo.insert(todo.end(),info->interfaces.begin(),info->interfaces.end());
                if(const auto info=async_task_class(current))todo.insert(todo.end(),info->interfaces.begin(),info->interfaces.end());
                if (const auto info = future_class(current))
                    todo.insert(todo.end(),info->interfaces.begin(),info->interfaces.end());
                if (const auto pool = thread_pool_class(current))
                    todo.insert(todo.end(), pool->interfaces.begin(), pool->interfaces.end());
                if (const auto policy = execution_policy_class(current))
                    todo.insert(todo.end(), policy->interfaces.begin(), policy->interfaces.end());
                if (const auto collection = collection_class(current))
                    todo.insert(todo.end(), collection->interfaces.begin(), collection->interfaces.end());
                if (const auto atomic = atomic_class(current))
                    todo.insert(todo.end(), atomic->interfaces.begin(), atomic->interfaces.end());
                if(const auto empty=empty_map_class(current))todo.insert(todo.end(),empty->interfaces.begin(),empty->interfaces.end());
                if(const auto local=thread_local_class(current))todo.insert(todo.end(),local->interfaces.begin(),local->interfaces.end());
                if(const auto regex=regex_class(current))todo.insert(todo.end(),regex->interfaces.begin(),regex->interfaces.end());
                if(const auto integral=integral_class(current))todo.insert(todo.end(),integral->interfaces.begin(),integral->interfaces.end());
                if(const auto floating=floating_class(current))todo.insert(todo.end(),floating->interfaces.begin(),floating->interfaces.end());
                if(const auto byte=byte_class(current))todo.insert(todo.end(),byte->interfaces.begin(),byte->interfaces.end());
                if(const auto uuid=uuid_class(current))todo.insert(todo.end(),uuid->interfaces.begin(),uuid->interfaces.end());
                if(const auto random=random_class(current))todo.insert(todo.end(),random->interfaces.begin(),random->interfaces.end());
                if(const auto boolean=boolean_class(current))
                    todo.insert(todo.end(),boolean->interfaces.begin(),boolean->interfaces.end());
                if (const auto integer = integer_class(current))
                    todo.insert(todo.end(), integer->interfaces.begin(), integer->interfaces.end());
                if (const auto map = map_class(current))
                    todo.insert(todo.end(), map->interfaces.begin(), map->interfaces.end());
                if (const auto view = map_view_class(current))
                    todo.insert(todo.end(), view->interfaces.begin(), view->interfaces.end());
                if (const auto set = set_class(current))
                    todo.insert(todo.end(), set->interfaces.begin(), set->interfaces.end());
                if (const auto enumeration = enum_class(current))
                    todo.insert(todo.end(), enumeration->interfaces.begin(), enumeration->interfaces.end());
                if (current == "Ljava/lang/String;" || current == "Ljava/lang/StringBuilder;")
                    todo.push_back("Ljava/lang/CharSequence;");
                if (current == "Ljava/lang/String;" || current == "Ljava/lang/StringBuilder;")
                    todo.push_back("Ljava/io/Serializable;");
            }
        }
        return false;
    }
    Value typed(Value v, std::string_view type) const {
        if (reference_type(type)) {
            const auto id = reference(v);
            if (id && !subtype(object(id).type, type))
                fail("VALUE_TYPE", "Object is incompatible with " + std::string(type));
            return Value::reference(id);
        }
        if (type == "V") {
            if (v.kind != ValueKind::void_value)
                fail("VALUE_TYPE", "Expected void result");
            return v;
        }
        if (type_words(type) == 2)
            return Value::wide(wide(v));
        auto bits = word(v);
        if (type == "Z")
            bits &= 1;
        else if (type == "B")
            bits = static_cast<std::uint32_t>(
                static_cast<std::int32_t>(std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(bits))));
        else if (type == "S")
            bits = static_cast<std::uint32_t>(
                static_cast<std::int32_t>(std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(bits))));
        else if (type == "C")
            bits &= 0xffff;
        return Value::word(bits);
    }
    void mark(ObjectId id, std::vector<ObjectId> &todo) {
        if (!id)
            return;
        const auto it = heap.find(id);
        if (it == heap.end())
            fail("REFERENCE", "A root refers to a collected object");
        if (!it->second.marked) {
            it->second.marked = true;
            todo.push_back(id);
        }
    }
    void collect() {
        check_thread();
        ++metrics.collections;
        for (auto &[id, value] : heap) {
            (void)id;
            value.marked = false;
        }
        std::vector<ObjectId> todo;
        const auto value = [&](Value v) {
            if (v.kind == ValueKind::reference)
                mark(v.bits, todo);
        };
        for (const auto &[id, count] : pins) {
            (void)count;
            mark(id, todo);
        }
        mark(loader_object, todo);
        for (const auto &[name, id] : class_objects) {
            (void)name;
            mark(id, todo);
        }
        for (const auto &[index, id] : strings) {
            (void)index;
            mark(id, todo);
        }
        for(const auto id:boolean_cache)mark(id,todo);
        for(const auto id:long_cache)mark(id,todo);
        for(const auto id:short_cache)mark(id,todo);
        for(const auto id:byte_cache)mark(id,todo);
        for (const auto id : integer_cache)
            mark(id, todo);
        for (const auto id : time_units)mark(id,todo);
        for(const auto id:standard_streams)mark(id,todo);
        for(const auto id:async_globals)mark(id,todo);
        for(const auto id:async_statuses)mark(id,todo);
        for (const auto &[index, v] : statics) {
            (void)index;
            value(v);
        }
        main_context.visit_roots(value);
        for(std::size_t n=0;n<native_context_depth;++n)native_contexts[n]->visit_roots(value);
        const auto callback_roots=[&](const MainCallback &callback) {
            for(const auto argument:callback.arguments)value(argument);
            for(const auto root:callback.checked_roots())value(root);
        };
        for(const auto &callback:main_callbacks)if(callback)callback_roots(*callback);
        if(main_callback_inflight)callback_roots(*main_callback_inflight);
        if(main_callback_posting)callback_roots(*main_callback_posting);
        for (const auto &task : tasks) if (task) {
            task->context.visit_roots(value);
            value(Value::reference(task->maintenance_pool));
            for (const auto argument : task->arguments) value(argument);
            for (const auto root : task->checked_worker_roots()) value(root);
        }
        mark(thread_group_object, todo);
        mark(default_uncaught_handler, todo);
        mark(java_version_property, todo);
        mark(empty_list, todo);
        for(const auto id:empty_map_objects)mark(id,todo);
        mark(runtime_object, todo);
        mark(vm_runtime_object, todo);
        while (!todo.empty()) {
            const auto id = todo.back();
            todo.pop_back();
            const auto &o = heap.at(id);
            mark(o.cause, todo);
            if(o.stream)for(const auto root:o.stream->roots)value(root);
            if (o.thread) {
                mark(o.thread->name, todo);
                mark(o.thread->target, todo);
                mark(o.thread->group, todo);
                mark(o.thread->pool_worker, todo);
                mark(o.thread->uncaught_handler, todo);
            }
            for (const auto &[field, v] : o.fields) {
                (void)field;
                value(v);
            }
            for (auto v : o.elements)
                value(v);
            if (o.pool_worker) {for(auto v:o.pool_worker->roots)value(v);mark(o.pool_worker->waiting_queue,todo);}
            if (o.factory) mark(o.factory->group,todo);
            if (o.queue_iterator) {mark(o.queue_iterator->backing,todo);value(o.queue_iterator->pending);}
            if(o.deque)for(auto v:o.deque->references())value(v);
            if(o.deque_iterator)mark(o.deque_iterator->backing,todo);
            if (o.fifo)
                for (auto v : o.fifo->references())
                    value(v);
            if(o.future){for(auto v:o.future->roots)value(v);for(auto v:o.future->waiters)value(v);}
            mark(o.async_future_owner,todo);
            if(o.async_task)for(auto v:o.async_task->roots)value(v);
            if(o.async_sdk)for(auto v:o.async_sdk->roots)value(v);
            if (o.pool)
                for (auto v : o.pool->references())
                    value(v);
            if (o.list)
                for (auto v : o.list->references())
                    value(v);
            if (o.live_iterator)
                mark(o.live_iterator->backing(), todo);
            if (o.iterator)
                for (auto v : o.iterator->references())
                    value(v);
            if (o.set)
                for (auto v : o.set->references())
                    value(v);
            if (o.synchronized_set)
                mark(o.synchronized_set->backing, todo);
            if (o.atomic)
                value(o.atomic->reference());
            if (o.host_state)
                for (auto v : o.host_state->values())
                    value(v);
            if (o.enumeration)
                value(o.enumeration->reference());
            if (o.weak) {
                mark(o.weak->queue, todo);
                mark(o.weak->next, todo);
            }
            if (o.queue)
                mark(o.queue->head, todo);
            if (o.map)
                for (const auto &entry : o.map->entries()) {
                    mark(entry.value, todo);
                    if (!o.map->weak())
                        mark(entry.key, todo);
                }
            if (o.synchronized_map)
                mark(o.synchronized_map->backing, todo);
            if (o.map_entry)
                mark(o.map_entry->map, todo);
            if (o.map_values)
                mark(o.map_values->map, todo);
            if(o.thread_locals)for(const auto &slot:o.thread_locals->slots)if(slot.occupied)mark(slot.value,todo);
            if(o.regex_pattern)mark(o.regex_pattern->source,todo);
            if(o.regex_matcher){mark(o.regex_matcher->pattern,todo);mark(o.regex_matcher->original,todo);mark(o.regex_matcher->snapshot,todo);}
            if(o.regex_syntax){mark(o.regex_syntax->source,todo);mark(o.regex_syntax->description,todo);}
            if (o.map_keys) {
                mark(o.map_keys->map, todo);
                mark(o.map_keys->mapped_value, todo);
                for (const auto key : o.map_keys->snapshot)
                    value(key);
            }
        }
        // Values remain strong, including values that lead back to a weak key.
        // Prune after the complete trace and before releasing any heap object.
        for (auto &[id, o] : heap) {
            if (o.marked && o.map)
                o.map->prune([&](ObjectId key) {
                    const auto found = heap.find(key);
                    return found != heap.end() && found->second.marked;
                });
            if (o.marked && o.weak && o.weak->referent) {
                const auto found = heap.find(o.weak->referent);
                if (found == heap.end() || !found->second.marked) {
                    o.weak->referent = 0;
                    (void)enqueue_reference(id);
                }
            }
        }
        // Java ThreadLocalMap values remain strong even when a weak key clears.
        // Expunge stale values on the next table operation, never conditionally
        // trace them like WeakHashMap (a value may itself keep its key alive).
        for(auto &[id,entry]:heap) {
            (void)id;
            if(entry.marked && entry.thread_locals)for(auto &slot:entry.thread_locals->slots)if(slot.occupied && slot.key) {
                const auto key=heap.find(slot.key);
                if(key==heap.end() || !key->second.marked)slot.key=0;
            }
        }
        for (auto it = heap.begin(); it != heap.end();) {
            if(it->second.stream && it->second.stream->source && it->second.stream->source->bytes()!=it->second.stream->source_bytes)
                fail("STREAM_STATE","Input adapter byte accounting changed during collection");
            if (!it->second.marked) {
                if(it->second.stream)(void)provider_call([&]{return it->second.stream->close_source();});
                metrics.heap_bytes -= it->second.bytes;
                ++metrics.reclaimed;
                it = heap.erase(it);
            } else
                ++it;
        }
        metrics.live_objects = heap.size();
    }
    ObjectId allocate(Object value) {
        check_thread();
        value.bytes = sizeof(Object) + value.type.size() + value.represented.size() + value.text.size() * 2 +
                      value.elements.size() * sizeof(Value) + value.fields.size() * (sizeof(Value) + 64);
        if (value.host_state) {
            value.host_bytes=value.host_state->bytes();
            value.bytes+=value.host_bytes;
        }
        if (value.reflected_field) value.bytes += value.reflected_field->bytes();
        if (value.reflected_method) value.bytes += value.reflected_method->bytes();
        if(value.deque)value.bytes+=sizeof(ManagedDeque)+value.deque->bytes();
        if(value.deque_iterator)value.bytes+=sizeof(DequeIterator);
        if (value.fifo)
            value.bytes += sizeof(ManagedQueue) + value.fifo->bytes();
        if (value.future)value.bytes+=sizeof(FutureState);
        if(value.async_task)value.bytes+=sizeof(AsyncTaskState);
        if(value.async_sdk)value.bytes+=sizeof(AsyncSdkState);
        if (value.pool)
            value.bytes += sizeof(ThreadPoolState);
        if (value.thread) value.bytes += sizeof(ThreadState);
        if (value.pool_worker) value.bytes += sizeof(PoolWorker);
        if (value.factory) value.bytes += sizeof(DefaultFactory);
        if (value.queue_iterator) value.bytes += sizeof(QueueIterator);
        if (value.abort_policy)
            value.bytes += sizeof(AbortPolicy);
        if (value.list)
            value.bytes += sizeof(ManagedList) + value.list->bytes();
        if (value.live_iterator)
            value.bytes += sizeof(LiveListIterator);
        if (value.iterator)
            value.bytes += sizeof(SnapshotIterator) + value.iterator->bytes();
        if (value.atomic)
            value.bytes += sizeof(AtomicReference);
        if (value.atomic_integer)
            value.bytes += sizeof(AtomicInteger);
        if (value.atomic_long)
            value.bytes += sizeof(AtomicLong);
        if (value.integer)
            value.bytes += sizeof(ManagedInteger);
        if(value.thread_local_key)value.bytes+=sizeof(ManagedThreadLocal);
        if(value.thread_locals)value.bytes+=sizeof(ThreadLocalTable)+value.thread_locals->bytes();
        if(value.regex_pattern)value.bytes+=sizeof(ManagedPattern)+regex_pattern_reservation;
        if(value.regex_matcher)value.bytes+=sizeof(ManagedMatcher)+regex_matcher_reservation+value.regex_matcher->native->storage_bytes();
        if(value.regex_syntax)value.bytes+=sizeof(PatternSyntax);
        if(value.integral)value.bytes+=sizeof(ManagedIntegral);
        if(value.floating)value.bytes+=sizeof(ManagedFloating);
        if(value.byte)value.bytes+=sizeof(ManagedByte);
        if(value.boolean)value.bytes+=sizeof(ManagedBoolean);
        if(value.uuid)value.bytes+=sizeof(ManagedUuid);
        if(value.random)value.bytes+=sizeof(ManagedRandom);
        if(value.stream)value.bytes+=sizeof(ManagedStream)+value.stream->source_bytes;
        if (value.map)
            value.bytes += sizeof(ManagedMap) + value.map->bytes();
        if (value.synchronized_map)
            value.bytes += sizeof(SynchronizedMap);
        if (value.map_entry)
            value.bytes += sizeof(MapEntryReference);
        if (value.map_values)
            value.bytes += sizeof(MapValues);
        if (value.map_keys)
            value.bytes += sizeof(MapKeys) + value.map_keys->bytes();
        if (value.set)
            value.bytes += sizeof(ManagedSet) + value.set->bytes();
        if (value.synchronized_set)
            value.bytes += sizeof(SynchronizedSet);
        if (value.enumeration)
            value.bytes += sizeof(ManagedEnum);
        if (value.weak)
            value.bytes += sizeof(WeakReference);
        if (value.queue)
            value.bytes += sizeof(ReferenceQueue);
        if (value.updater)
            value.bytes += sizeof(ReferenceFieldUpdater);
        if (heap.size() >= limits.objects || value.bytes > limits.heap_bytes - metrics.heap_bytes)
            collect();
        if (heap.size() >= limits.objects || value.bytes > limits.heap_bytes - metrics.heap_bytes)
            fail("HEAP_LIMIT", "Managed heap quota exhausted");
        const auto id = next_identity.fetch_add(1, std::memory_order_relaxed);
        if (!id || id == std::numeric_limits<ObjectId>::max())
            fail("IDENTITY_LIMIT", "Managed identity space exhausted");
        const auto bytes = value.bytes;
        heap.emplace(id, std::move(value));
        metrics.heap_bytes += bytes;
        ++metrics.allocations;
        metrics.live_objects = heap.size();
        return id;
    }
    ObjectId intern(Index index) {
        if (index >= image.strings.size())
            fail("INDEX", "Invalid string index");
        if (const auto it = strings.find(index); it != strings.end())
            return it->second;
        const auto id = runtime.new_string(image.strings[index]);
        strings.emplace(index, id);
        return id;
    }
    void initialize(std::string_view type) {
        execution_checkpoint();
        check_thread();
        NonYielding barrier(current_context());
        known(type);
        const auto *definition = resolve_class(type);
        if (!definition)
            return;
        auto &state = class_state[std::string(type)];
        if(state==1) {
            if(class_initializers.at(std::string(type))!=&current_context())fail("CLASS_INITIALIZATION_WAIT_UNSUPPORTED","Class initialization is owned by another logical thread");
            return;
        }
        if(state==2)return;
        if (state == 3)
            runtime.raise("Ljava/lang/NoClassDefFoundError;");
        const auto initializer_key=std::string(type);class_initializers.emplace(initializer_key,&current_context());
        struct InitializerEnd {Impl &p;const std::string &key;~InitializerEnd(){p.class_initializers.erase(key);}} initializer_end{*this,initializer_key};
        state = 1;
        try {
            for (const auto index : definition->static_fields)
                statics[index] = default_value(image.types.at(image.fields.at(index).type));
            for (std::size_t i = 0; i < definition->static_values.size(); ++i) {
                const auto index = definition->static_fields.at(i);
                const auto &entry = definition->static_values[i];
                const auto &field_type = image.types[image.fields[index].type];
                const auto exact_kind = [&](unsigned kind) {
                    if (entry.type != kind)
                        fail("STATIC_VALUE", "Encoded static value disagrees with declared field type");
                };
                Value v;
                if (reference_type(field_type)) {
                    if (entry.type == 0x1e)
                        v = Value::reference(0);
                    else if (entry.type == 0x17 && field_type == "Ljava/lang/String;")
                        v = Value::reference(intern(static_cast<Index>(entry.bits)));
                    else if (entry.type == 0x18 && field_type == "Ljava/lang/Class;")
                        v = Value::reference(
                            runtime.class_object(image.types.at(static_cast<Index>(entry.bits))));
                    else
                        fail("STATIC_VALUE", "Unsupported encoded reference initializer");
                } else {
                    const std::map<std::string_view, unsigned> kinds{{"B", 0},    {"S", 2},   {"C", 3},
                                                                     {"I", 4},    {"J", 6},   {"F", 0x10},
                                                                     {"D", 0x11}, {"Z", 0x1f}};
                    exact_kind(kinds.at(field_type));
                    v = type_words(field_type) == 2 ? Value::wide(entry.bits)
                                                    : Value::word(static_cast<std::uint32_t>(entry.bits));
                }
                statics[index] = typed(v, field_type);
            }
            if (!(definition->flags & 0x200)) {
                if (definition->superclass != no_index)
                    initialize(image.types.at(definition->superclass));
                // Class initialization visits superinterfaces in declaration
                // order, parents first, initializing only default declarers.
                // Initializing an interface itself does not initialize parents.
                std::set<Index> seen;
                std::vector<std::pair<Index, bool>> pending;
                const auto parents = [&](const Class &c) {
                    for (auto it = c.interfaces.rbegin(); it != c.interfaces.rend(); ++it)
                        pending.emplace_back(*it, false);
                };
                parents(*definition);
                std::size_t work = 0;
                while (!pending.empty()) {
                    if (++work > 262144)
                        fail("CLASS_LIMIT", "Default interface initialization exceeds its work budget");
                    const auto [index, visited] = pending.back();
                    pending.pop_back();
                    const auto *parent = resolve_class(image.types.at(index));
                    if (!parent)
                        continue;
                    if (!visited) {
                        if (!seen.insert(index).second)
                            continue;
                        pending.emplace_back(index, true);
                        parents(*parent);
                    } else {
                        for (const auto method : parent->virtual_methods) {
                            if (++work > 262144)
                                fail("CLASS_LIMIT",
                                     "Default interface initialization exceeds its work budget");
                            const auto &m = image.methods.at(method);
                            if (!(m.flags & (0x400 | 8)) && !m.direct && m.code) {
                                initialize(image.types.at(index));
                                break;
                            }
                        }
                    }
                }
            }
            for (const auto index : definition->direct_methods)
                if (image.methods.at(index).name == "<clinit>")
                    (void)runtime.invoke(index);
            state = 2;
        } catch (const JavaException &error) {
            state = 3;
            if (subtype(object(error.object).type, "Ljava/lang/Error;"))
                throw;
            runtime.raise("Ljava/lang/ExceptionInInitializerError;");
        } catch (...) {
            state = 3;
            throw;
        }
    }
    Value invoke_print_stream(ObjectId receiver,std::string_view name,std::span<const Value> args) {
        (void)object(receiver); // Ordinary null/stale receiver validation.
        const auto found=std::find(standard_streams.begin(),standard_streams.end(),receiver);
        if(found==standard_streams.end())fail("OUTPUT_STREAM_UNSUPPORTED","Only canonical standard PrintStreams have a diagnostic sink");
        const auto slot=static_cast<std::size_t>(found-standard_streams.begin());
        if(name=="checkError")return Value::word(standard_error[slot]);
        if(name=="close") {standard_closed[slot]=true;return Value::nothing();}
        if(standard_closed[slot]) {standard_error[slot]=true;return name=="printf"?Value::reference(receiver):Value::nothing();}
        if(name=="flush")return Value::nothing(); // Each accepted segment is retained synchronously.
        const auto emit=[&](std::u16string_view text) {
            if(!host || !provider_call([&]{return host->write_standard_output(runtime,slot==1,text);}))
                standard_error[slot]=true;
        };
        if(name=="printf") {
            // Literal formatting ignores surplus/null varargs, without invoking
            // their toString methods. Directive formatting remains explicit.
            const auto format=runtime.string(reference(args[1]));
            if(format.find(u'%')!=std::u16string_view::npos)
                fail("API_UNSUPPORTED","PrintStream printf directives are not implemented");
            if(!format.empty())emit(format);
            return Value::reference(receiver);
        }
        if(args.size()==2) {
            const auto text=reference(args[1]);
            emit(text?runtime.string(text):std::u16string_view(u"null"));
        }
        if(name=="println")emit(u"\n");
        return Value::nothing();
    }
    bool method_is_static(Index index) const {
        if (loader) {
            provider_call([&] { ensure_class(image.types.at(image.methods.at(index).owner)); });
            check_thread(); // Refuse reserved loader definitions linked by method resolution.
        }
        const auto &method = image.methods.at(index);
        if (method.declared)
            return bool(method.flags & 8);
        const auto &owner_type = image.types.at(method.owner);
        if (owner_type == "Ljava/lang/Runnable;") {
            if (method.name == "run" && image.prototypes.at(method.prototype).descriptor == "()V")
                return false;
            fail("API_UNSUPPORTED", owner_type + "." + method.name +
                                        image.prototypes.at(method.prototype).descriptor +
                                        " is not implemented");
        }
        if(owner_type==android_process_type || owner_type==android_binder_type)return method.name!="<init>";
        if(owner_type==async_status_type)return method.name=="values" || method.name=="valueOf";
        if(owner_type==async_task_type)return method.name=="execute" && image.prototypes.at(method.prototype).descriptor=="(Ljava/lang/Runnable;)V";
        if(owner_type=="Landroid/text/TextUtils;") {
            if(method.name=="isEmpty" && image.prototypes.at(method.prototype).descriptor=="(Ljava/lang/CharSequence;)Z")return true;
            // Existing framework-owned TextUtils APIs retain registry validation
            // and provider dispatch; this exact core addition does not claim them.
            if(host)return provider_call([&]{return host->method_is_static(image,index);});
            fail("API_UNSUPPORTED",owner_type+"."+method.name+image.prototypes.at(method.prototype).descriptor+" is not implemented");
        }
        if(owner_type==uuid_type)return method.name=="randomUUID" || method.name=="fromString" || method.name=="nameUUIDFromBytes";
        if(owner_type==random_type)return false;
        if(owner_type==thread_local_type)return method.name=="withInitial";
        if(owner_type==pattern_type)return method.name=="compile" || method.name=="quote" || method.name=="matches";
        if(owner_type==long_type || owner_type==short_type) {
            const auto &signature=image.prototypes.at(method.prototype).descriptor;
            const bool large=owner_type==long_type;
            const bool long_static=large && (method.name=="bitCount" || method.name=="compareUnsigned" ||
                method.name=="divideUnsigned" || method.name=="getLong" || method.name=="highestOneBit" ||
                method.name=="lowestOneBit" || method.name=="max" || method.name=="min" ||
                method.name=="numberOfLeadingZeros" || method.name=="numberOfTrailingZeros" ||
                method.name=="parseUnsignedLong" || method.name=="remainderUnsigned" || method.name=="reverse" ||
                method.name=="reverseBytes" || method.name=="rotateLeft" || method.name=="rotateRight" ||
                method.name=="signum" || method.name=="sum" || method.name=="toBinaryString" ||
                method.name=="toHexString" || method.name=="toOctalString" || method.name=="toUnsignedString");
            const bool short_static=!large && (method.name=="compareUnsigned" || method.name=="reverseBytes" ||
                method.name=="toUnsignedInt" || method.name=="toUnsignedLong");
            return long_static || short_static || method.name=="valueOf" || method.name=="decode" || method.name=="parseLong" || method.name=="parseShort" ||
                (method.name=="compare" && signature==(large?"(JJ)I":"(SS)I")) ||
                (method.name=="hashCode" && signature==(large?"(J)I":"(S)I")) ||
                (method.name=="toString" && signature==(large?"(J)Ljava/lang/String;":"(S)Ljava/lang/String;"));
        }
        if(owner_type==float_type || owner_type==double_type)return floating_static(method.name,image.prototypes.at(method.prototype).descriptor);
        if(owner_type==byte_type) {
            const auto &signature=image.prototypes.at(method.prototype).descriptor;
            return method.name=="valueOf" || method.name=="parseByte" || method.name=="decode" ||
                (method.name=="compare" && signature=="(BB)I") || (method.name=="hashCode" && signature=="(B)I") ||
                (method.name=="toString" && signature=="(B)Ljava/lang/String;") ||
                (method.name=="toUnsignedInt" && signature=="(B)I") || (method.name=="toUnsignedLong" && signature=="(B)J");
        }
        if(owner_type==boolean_type) {
            const auto &signature=image.prototypes.at(method.prototype).descriptor;
            return method.name=="valueOf" || method.name=="parseBoolean" || method.name=="getBoolean" ||
                (method.name=="compare" && signature=="(ZZ)I") ||
                (method.name=="hashCode" && signature=="(Z)I") ||
                (method.name=="toString" && signature=="(Z)Ljava/lang/String;");
        }
        if (core_type(owner_type))
            return owner_type == "Ljava/lang/System;" || owner_type == "Ljava/lang/Math;" || owner_type == arrays_type ||
                   owner_type == collections_utility_type ||
                   (owner_type == "Ljava/lang/String;" && method.name == "valueOf") ||
                   (owner_type == "Ljava/lang/Class;" && method.name == "forName") ||
                   ((owner_type == "Ljava/lang/Runtime;" || owner_type == "Ldalvik/system/VMRuntime;") && method.name == "getRuntime") ||
                   (owner_type == "Ljava/lang/Thread;" &&
                    (method.name == "currentThread" || method.name == "holdsLock" || method.name == "sleep" ||
                     method.name == "yield" || method.name == "interrupted" ||
                     (method.name=="getDefaultUncaughtExceptionHandler" && image.prototypes.at(method.prototype).descriptor=="()Ljava/lang/Thread$UncaughtExceptionHandler;") ||
                     (method.name=="setDefaultUncaughtExceptionHandler" && image.prototypes.at(method.prototype).descriptor=="(Ljava/lang/Thread$UncaughtExceptionHandler;)V"))) ||
                   (owner_type == enum_type && method.name == "valueOf") ||
                   (owner_type == time_unit_type && (method.name == "valueOf" || method.name == "values")) ||
                   (owner_type == integer_type && (method.name == "valueOf" ||
                    (method.name == "parseInt" &&
                     (image.prototypes.at(method.prototype).descriptor == "(Ljava/lang/String;)I" ||
                      image.prototypes.at(method.prototype).descriptor == "(Ljava/lang/String;I)I")))) ||
                   (owner_type == atomic_field_updater_type && method.name == "newUpdater") ||
                   ((owner_type == reference_type_name || owner_type == weak_reference_type) &&
                    method.name == "reachabilityFence");
        if (enum_instance_method(method.name, image.prototypes.at(method.prototype).descriptor) &&
            subtype(owner_type, enum_type))
            return false;
        if (reference_instance_method(method.name, image.prototypes.at(method.prototype).descriptor) &&
            subtype(owner_type, weak_reference_type))
            return false;
        if (owner_type.starts_with('[')) {
            if (method.name == "clone" &&
                image.prototypes.at(method.prototype).descriptor == "()Ljava/lang/Object;")
                return false;
            fail("API_UNSUPPORTED", owner_type + "." + method.name +
                                        image.prototypes.at(method.prototype).descriptor +
                                        " is not implemented");
        }
        if (host)
            return provider_call([&] { return host->method_is_static(image, index); });
        fail("API_UNSUPPORTED", owner_type + "." + method.name +
                                    image.prototypes.at(method.prototype).descriptor + " is not implemented");
    }
    bool is_interface(std::string_view type) const {
        if (const auto *definition = resolve_class(type))
            return bool(definition->flags & 0x200);
        if (host)
            if (const auto info = provider_call([&] { return host->class_info(type); }))
                return info->is_interface;
        if(const auto info=thread_local_class(type))return info->is_interface;
        if(const auto literal=literal_metadata_class(type))return literal->is_interface;
        if(const auto info=regex_class(type))return info->is_interface;
        if(const auto info=stream_class(type))return info->is_interface;
        if(const auto info=async_task_class(type))return info->is_interface;
        if (const auto info=future_class(type))return info->is_interface;
        if (const auto pool = thread_pool_class(type))
            return pool->is_interface;
        if (const auto policy = execution_policy_class(type))
            return policy->is_interface;
        if (const auto collection = collection_class(type))
            return collection->is_interface;
        if(const auto empty=empty_map_class(type))return empty->is_interface;
        if(const auto uuid=uuid_class(type))return uuid->is_interface;
        if(const auto random=random_class(type))return random->is_interface;
        if(const auto boolean=boolean_class(type))return boolean->is_interface;
        if (const auto map = map_class(type))
            return map->is_interface;
        if (const auto view = map_view_class(type))
            return view->is_interface;
        if (const auto set = set_class(type))
            return set->is_interface;
        if (const auto enumeration = enum_class(type))
            return enumeration->is_interface;
        return type == "Ljava/lang/CharSequence;" || type == "Ljava/lang/Runnable;" ||
               type == "Ljava/lang/Thread$UncaughtExceptionHandler;" || type == "Ljava/lang/reflect/Type;";
    }
    void replace_text(ObjectId id, std::u16string text) {
        if (text.size() > limits.array_length)
            fail("STRING_LIMIT", "Managed character sequence exceeds length limit");
        auto &value = object(id);
        const auto before = value.text.size() * 2, after = text.size() * 2;
        if (after > before && after - before > limits.heap_bytes - metrics.heap_bytes)
            fail("HEAP_LIMIT", "Managed character sequence exceeds heap limit");
        value.text = std::move(text);
        value.bytes = value.bytes - before + after;
        metrics.heap_bytes = metrics.heap_bytes - before + after;
    }
    std::optional<Index> object_override(ObjectId id, std::string_view name, std::string_view signature) {
        auto type = std::string_view(object(id).type);
        for (unsigned depth = 0; depth < 256; ++depth) {
            if (const auto *definition = resolve_class(type)) {
                for (const auto index : definition->virtual_methods) {
                    const auto &method = image.methods.at(index);
                    if (method.name == name && image.prototypes.at(method.prototype).descriptor == signature)
                        return index;
                }
                if (definition->superclass == no_index)
                    return {};
                type = image.types.at(definition->superclass);
            } else {
                if (object(id).list || object(id).map || object(id).set || object(id).map_keys || object(id).map_values || object(id).map_entry || object(id).synchronized_map ||
                    object(id).synchronized_set || type == array_list_type || type == empty_list_type || type == singleton_list_type)
                    fail("API_UNSUPPORTED", "Collection " + std::string(name) + " is not implemented");
                // Provider identity semantics must be explicit. Unknown overrides
                // cannot safely be replaced with Object's default behavior.
                const auto provider = host ? provider_call([&] { return host->class_info(type); }) : std::nullopt;
                if (!core_type(type) && !type.starts_with('[') &&
                    !(provider && provider->identity_object_methods))
                    fail("API_UNSUPPORTED", "Provider " + std::string(type) + "." + std::string(name) +
                                                " is not implemented for map keys/values");
                return {};
            }
        }
        fail("CLASS_LIMIT", "Object method hierarchy exceeds limit");
    }
    std::uint32_t key_hash(ObjectId id) {
        if(object(id).type==map_backed_set_type || unmodifiable_list_class(object(id).type) || synchronized_list_class(object(id).type))return word(call_virtual_named(id,"hashCode","()I"));
        if(object(id).type==empty_map_type || object(id).type==empty_set_type)return 0;
        if (const auto method = object_override(id, "hashCode", "()I")) {
            const std::array<Value, 1> args{Value::reference(id)};
            return word(runtime.invoke_virtual(*method, args));
        }
        if (object(id).type == "Ljava/lang/String;")
            return string_hash(object(id).text);
        if(object(id).integral) {
            const auto value=object(id).integral->bits();
            return static_cast<std::uint32_t>(object(id).integral->is_long()?value^(value>>32):value);
        }
        if(object(id).floating)return object(id).floating->hash();
        if(object(id).byte)return static_cast<std::uint32_t>(object(id).byte->value());
        if(object(id).uuid)return object(id).uuid->hash();
        if(object(id).boolean)return object(id).boolean->value()?1231U:1237U;
        if (object(id).integer)
            return object(id).integer->value();
        return static_cast<std::uint32_t>(id ^ (id >> 32));
    }
    bool key_equal(ObjectId left, ObjectId right) {
        if(left) {
            if(object(left).integral)(void)object(left).integral->bits();
            if(object(left).floating)(void)object(left).floating->bits();
        }
        if (left == right)
            return true;
        if (!left)
            return false;
        if(object(left).type==map_backed_set_type || unmodifiable_list_class(object(left).type) || synchronized_list_class(object(left).type))
            return word(call_virtual_named(left,"equals","(Ljava/lang/Object;)Z",std::array{Value::reference(right)}))!=0;
        if(object(left).type==empty_map_type || object(left).type==empty_set_type) {
            const std::array<Value,2> args{Value::reference(left),Value::reference(right)};
            return word(*invoke_empty_map(runtime,object(left).type,"equals","(Ljava/lang/Object;)Z",args,
                [&](std::string_view type){return canonical_empty(type);}))!=0;
        }
        if (const auto method = object_override(left, "equals", "(Ljava/lang/Object;)Z")) {
            const std::array<Value, 2> args{Value::reference(left), Value::reference(right)};
            return word(runtime.invoke_virtual(*method, args)) != 0;
        }
        if(object(left).integral) {
            const auto own=object(left).integral->bits();
            return right && object(right).integral && object(left).integral->is_long()==object(right).integral->is_long() &&
                own==object(right).integral->bits();
        }
        if(object(left).floating)return object(left).floating->equals(right?object(right).floating.get():nullptr);
        if(object(left).byte)return right && object(right).byte && object(left).byte->value()==object(right).byte->value();
        if(object(left).uuid)return object(left).uuid->equals(right?object(right).uuid.get():nullptr);
        if(object(left).boolean)
            return right && object(right).boolean && object(left).boolean->value()==object(right).boolean->value();
        if (object(left).integer)
            return right && object(right).integer &&
                   object(left).integer->value() == object(right).integer->value();
        return right && object(left).type == "Ljava/lang/String;" &&
               object(right).type == "Ljava/lang/String;" && object(left).text == object(right).text;
    }
    ReflectedMethod reflected_declaration(Index index) const {
        const auto &m = image.methods.at(index);
        const auto &p = image.prototypes.at(m.prototype);
        ReflectedMethod result;
        result.managed = index;
        result.metadata = {image.types.at(m.owner), m.name, image.types.at(p.return_type), {}, m.flags};
        for (const auto parameter : p.parameters) result.metadata.parameters.push_back(image.types.at(parameter));
        return result;
    }
    std::optional<ReflectedMethod> object_public_method(std::string_view name,
                                                       const std::vector<std::string> &parameters) const {
        // Complete public Object declaration inventory, not an implementation claim.
        const std::array<HostMethod, 9> declarations{{
            {"Ljava/lang/Object;", "getClass", "Ljava/lang/Class;", {}, 0x111},
            {"Ljava/lang/Object;", "equals", "Z", {"Ljava/lang/Object;"}, 1},
            {"Ljava/lang/Object;", "hashCode", "I", {}, 0x101},
            {"Ljava/lang/Object;", "toString", "Ljava/lang/String;", {}, 1},
            {"Ljava/lang/Object;", "notify", "V", {}, 0x111},
            {"Ljava/lang/Object;", "notifyAll", "V", {}, 0x111},
            {"Ljava/lang/Object;", "wait", "V", {}, 0x11},
            {"Ljava/lang/Object;", "wait", "V", {"J"}, 0x111},
            {"Ljava/lang/Object;", "wait", "V", {"J", "I"}, 0x11}}};
        for (const auto &m : declarations) if (m.name == name && m.parameters == parameters) {
            ReflectedMethod result; result.metadata = m;
            // A DEX reference is usable for dispatch only after matching authoritative metadata.
            for (Index i = 0; i < image.methods.size(); ++i) {
                if (i >= 262144) fail("METHOD_LIMIT", "Object reflection dispatch search exceeds work budget");
                const auto &candidate = image.methods[i];
                if (candidate.declared || image.types[candidate.owner] != m.owner || candidate.name != name) continue;
                const auto declaration = reflected_declaration(i);
                if (declaration.metadata.parameters == parameters && declaration.metadata.return_type == m.return_type) {
                    result.managed = i; break;
                }
            }
            return result;
        }
        return {};
    }
    ObjectId lookup_public_method(std::span<const Value> args,bool declared_only=false) {
        const auto target = std::string(runtime.represented_class(reference(args[0])));
        const auto text = runtime.string(reference(args[1]));
        if (text.size() > 1024) fail("METHOD_LIMIT", "Reflective method name exceeds 1024 UTF-16 units");
        std::string name;
        for (const auto c : text) {
            if (c > 127) fail("API_UNSUPPORTED", "Reflective non-ASCII method names are not implemented");
            name.push_back(static_cast<char>(c));
        }
        std::vector<std::string> parameters;
        const auto array = reference(args[2]);
        if (array) {
            if (object(array).type != "[Ljava/lang/Class;") runtime.raise("Ljava/lang/IllegalArgumentException;");
            for (const auto value : object(array).elements) {
                if(!reference(value))runtime.raise("Ljava/lang/NoSuchMethodException;",u"parameter type is null");
                parameters.emplace_back(runtime.represented_class(reference(value)));
            }
        }
        if (name == "<init>" || name == "<clinit>") runtime.raise("Ljava/lang/NoSuchMethodException;", text);
        std::size_t work = 0;
        const auto step = [&] {
            if (++work > 262144) fail("CLASS_LIMIT", "Reflective method lookup exceeds work budget");
        };
        const auto choose = [&](std::optional<ReflectedMethod> &selected, ReflectedMethod candidate) {
            if (!selected) { selected = std::move(candidate); return; }
            const auto &a = selected->metadata.return_type, &b = candidate.metadata.return_type;
            if (a == b) return;
            if (reference_type(a) && reference_type(b)) {
                if (subtype(b, a)) { selected = std::move(candidate); return; }
                if (subtype(a, b)) return;
            }
            fail("API_UNSUPPORTED", "Reflective return-type ambiguity is not implemented");
        };
        const auto declared = [&](std::string_view owner, bool inherited_interface) -> std::optional<ReflectedMethod> {
            std::optional<ReflectedMethod> selected;
            if (const auto *definition = resolve_class(owner)) {
                if (std::popcount(definition->flags & 7u) > 1)
                    fail("METHOD_METADATA", "Reflected declaring class has contradictory visibility modifiers");
                const auto scan = [&](const std::vector<Index> &methods) {
                    for (const auto index : methods) {
                        step();
                        const auto &m = image.methods.at(index);
                        if (std::popcount(m.flags & 7u) > 1)
                            fail("METHOD_METADATA", "Reflected method has contradictory visibility modifiers");
                        if (!m.declared || (!declared_only && !(m.flags & 1)) || m.name != name || m.name == "<init>" || m.name == "<clinit>" ||
                            (inherited_interface && (m.flags & 8))) continue;
                        auto candidate = reflected_declaration(index);
                        if (candidate.metadata.parameters == parameters) choose(selected, std::move(candidate));
                    }
                };
                scan(definition->direct_methods); scan(definition->virtual_methods);
                return selected;
            }
            if (owner == "Ldalvik/system/VMRuntime;") {
                if(name=="getRuntime" && parameters.empty()) {
                    if(!runtime.hidden_api_access_allowed(u"Ldalvik/system/VMRuntime;->getRuntime()Ldalvik/system/VMRuntime;"))runtime.raise("Ljava/lang/NoSuchMethodException;");
                    ReflectedMethod candidate;candidate.metadata={std::string(owner),"getRuntime",std::string(owner),{},9};
                    candidate.vm_runtime_operation=1;return candidate;
                }
                if(name=="setHiddenApiExemptions" && parameters==std::vector<std::string>{"[Ljava/lang/String;"}) {
                    if(!runtime.hidden_api_access_allowed(u"Ldalvik/system/VMRuntime;->setHiddenApiExemptions([Ljava/lang/String;)V"))runtime.raise("Ljava/lang/NoSuchMethodException;");
                    ReflectedMethod candidate;candidate.metadata={std::string(owner),name,"V",parameters,0x101};
                    candidate.vm_runtime_operation=2;return candidate;
                }
                fail("API_UNSUPPORTED","VMRuntime reflective declaration/operation is unsupported: "+name);
            }
            if(owner.starts_with('[') && declared_only)return {};
            if (owner == "Ljava/lang/Object;" || owner.starts_with('[')) {
                auto method=object_public_method(name,parameters);
                if(declared_only && !method)fail("API_UNSUPPORTED","Declared Object method inventory is incomplete");
                return method;
            }
            if (!reference_type(owner)) return {};
            if(declared_only)fail("API_UNSUPPORTED","Declared provider method inventory is incomplete for "+std::string(owner)+"."+name);
            if (host) if (auto metadata = provider_call([&] { return host->public_method(owner, name, parameters); })) {
                if (!subtype(owner, metadata->owner) || metadata->name != name || metadata->parameters != parameters ||
                    (metadata->flags & 7u) != 1u || (metadata->flags & ~0x1dffu) || metadata->return_type.empty())
                    fail("HOST_METADATA", "Invalid reflected provider declaration");
                if (inherited_interface && (metadata->flags & 8)) return {};
                ReflectedMethod candidate; candidate.metadata = std::move(*metadata); candidate.provider = true;
                return candidate;
            }
            fail("API_UNSUPPORTED", "Public reflective method metadata is incomplete for " + std::string(owner) + "." + name);
        };
        std::optional<ReflectedMethod> selected;
        std::vector<std::string> interfaces;
        std::set<std::string> seen;
        auto current = target;
        bool target_interface = is_interface(target);
        while (!current.empty()) {
            step();
            if (!seen.insert(current).second || seen.size() > 65536)
                fail("CLASS_LIMIT", "Reflective superclass traversal is cyclic or exceeds class budget");
            if (auto candidate = declared(current, false)) { selected = std::move(candidate); break; }
            if(declared_only)break;
            if (const auto *definition = resolve_class(current)) {
                for (const auto parent : definition->interfaces) interfaces.push_back(image.types.at(parent));
                if (target_interface || definition->superclass == no_index) break;
                current = image.types.at(definition->superclass);
            } else if (current.starts_with('[')) current = "Ljava/lang/Object;";
            else break; // Object/primitive has a complete inventory; partial providers fail above.
        }
        if (!selected && !declared_only) {
            std::vector<ReflectedMethod> candidates;
            seen.clear();
            while (!interfaces.empty()) {
                step();
                auto type = std::move(interfaces.back()); interfaces.pop_back();
                if (!seen.insert(type).second) continue;
                if (seen.size() > 65536) fail("CLASS_LIMIT", "Reflective interface lookup exceeds class budget");
                if (auto candidate = declared(type, true)) candidates.push_back(std::move(*candidate));
                if (const auto *definition = resolve_class(type))
                    for (const auto parent : definition->interfaces) interfaces.push_back(image.types.at(parent));
            }
            for (auto &candidate : candidates) {
                bool shadowed = false;
                for (const auto &other : candidates) {
                    step();
                    if (candidate.metadata.owner != other.metadata.owner && subtype(other.metadata.owner, candidate.metadata.owner)) {
                        shadowed = true; break;
                    }
                }
                if (!shadowed) choose(selected, candidate);
            }
        }
        if (!selected) runtime.raise("Ljava/lang/NoSuchMethodException;", text);
        Object result; result.type = "Ljava/lang/reflect/Method;";
        result.reflected_method = std::make_unique<const ReflectedMethod>(std::move(*selected));
        return allocate(std::move(result));
    }
    Value vm_runtime() {
        if(!vm_runtime_object) {
            Object value;value.type="Ldalvik/system/VMRuntime;";
            vm_runtime_object=allocate(std::move(value));
        }
        return Value::reference(vm_runtime_object);
    }
    Value set_hidden_api_exemptions(ObjectId receiver,ObjectId array) {
        if(receiver!=vm_runtime_object)fail("STATE","VMRuntime is not this runtime's singleton");
        if(!array)fail("VALUE_TYPE","Null hidden-API exemption array is unsupported");
        const auto &source=object(array);if(source.type!="[Ljava/lang/String;")fail("VALUE_TYPE","Hidden-API exemptions require String[]");
        if(source.elements.size()>1024)fail("HEAP_LIMIT","Hidden-API exemption count exceeds 1024");
        std::vector<std::u16string> replacement;replacement.reserve(source.elements.size());std::size_t units=0;
        for(const auto value:source.elements) {
            if(!reference(value))fail("VALUE_TYPE","Null hidden-API exemption prefix is unsupported");
            const auto prefix=runtime.string(reference(value));
            if(prefix.size()>65536-units)fail("HEAP_LIMIT","Hidden-API exemption text exceeds 65536 UTF-16 units");
            units+=prefix.size();replacement.emplace_back(prefix);
        }
        std::size_t bytes=replacement.capacity()*sizeof(std::u16string);
        for(const auto &prefix:replacement)bytes+=prefix.capacity()*sizeof(char16_t);
        if(bytes>limits.heap_bytes)fail("HEAP_LIMIT","Hidden-API exemption storage exceeds heap quota");
        if(bytes>hidden_api_bytes && bytes-hidden_api_bytes>limits.heap_bytes-metrics.heap_bytes)collect();
        if(bytes>hidden_api_bytes && bytes-hidden_api_bytes>limits.heap_bytes-metrics.heap_bytes)fail("HEAP_LIMIT","Hidden-API exemption storage exceeds available heap");
        metrics.heap_bytes=metrics.heap_bytes-hidden_api_bytes+bytes;hidden_api_bytes=bytes;
        hidden_api_exemptions.swap(replacement);return Value::nothing();
    }
    Value invoke_reflected_method(std::span<const Value> args) {
        const auto &state = object(reference(args[0])).reflected_method;
        if (!state) fail("REFERENCE", "Method object has no validated declaration");
        const auto &method = state->metadata;
        if (method.return_type != "V" && !reference_type(method.return_type))
            fail("API_UNSUPPORTED", "Reflected primitive return boxing is not implemented");
        for (const auto &parameter : method.parameters)
            if (!reference_type(parameter)) fail("API_UNSUPPORTED", "Reflected primitive argument unboxing is not implemented");
        const auto *declaring_class = resolve_class(method.owner);
        if (declaring_class && std::popcount(declaring_class->flags & 7u) > 1)
            fail("METHOD_METADATA", "Reflected declaring class has contradictory visibility modifiers");
        if (declaring_class && !(declaring_class->flags & 1) &&
            !object(reference(args[0])).reflective_access_override) {
            std::string_view caller;
            if (const auto index = caller_frame_method(); index != no_index) caller = image.types.at(image.methods.at(index).owner);
            const auto package = [](std::string_view type) { const auto slash=type.rfind('/'); return type.substr(0,slash==type.npos?0:slash); };
            if (caller.empty() || (caller != method.owner && package(caller) != package(method.owner)))
                runtime.raise("Ljava/lang/IllegalAccessException;", u"Reflected declaring class is inaccessible");
        }
        if(!(method.flags&1) && !object(reference(args[0])).reflective_access_override) {
            std::string_view caller;
            if(const auto index=caller_frame_method();index!=no_index)caller=image.types.at(image.methods.at(index).owner);
            const auto package=[](std::string_view type){const auto slash=type.rfind('/');return type.substr(0,slash==type.npos?0:slash);};
            bool allowed=!caller.empty() && caller==method.owner;
            if(!caller.empty() && !(method.flags&2)) {
                allowed=allowed || package(caller)==package(method.owner);
                if((method.flags&4) && subtype(caller,method.owner)) {
                    allowed=allowed || (method.flags&8) || (reference(args[1]) && subtype(object(reference(args[1])).type,caller));
                }
            }
            if(!allowed)runtime.raise("Ljava/lang/IllegalAccessException;");
        }
        const bool stat = (method.flags & 8) != 0;
        std::vector<Value> delegated;
        if (!stat) {
            const auto receiver = reference(args[1]);
            if (!receiver) runtime.raise("Ljava/lang/NullPointerException;");
            if (!subtype(object(receiver).type, method.owner)) runtime.raise("Ljava/lang/IllegalArgumentException;");
            delegated.push_back(Value::reference(receiver));
        }
        const auto array = reference(args[2]);
        if (array && !object(array).type.starts_with("[L") && !object(array).type.starts_with("[["))
            runtime.raise("Ljava/lang/IllegalArgumentException;");
        const auto count = array ? object(array).elements.size() : 0;
        if (count != method.parameters.size()) runtime.raise("Ljava/lang/IllegalArgumentException;");
        for (std::size_t n=0; n<count; ++n) {
            const auto value=object(array).elements[n]; const auto id=reference(value);
            if (id && !subtype(object(id).type, method.parameters[n])) runtime.raise("Ljava/lang/IllegalArgumentException;");
            delegated.push_back(Value::reference(id));
        }
        // Class initialization errors precede target invocation and are not wrapped.
        if (stat) initialize(method.owner);
        try {
            Value result;
            if(state->vm_runtime_operation) {
                result=state->vm_runtime_operation==1?vm_runtime():set_hidden_api_exemptions(reference(delegated[0]),reference(delegated[1]));
            } else if (state->provider) {
                if (!host) fail("API_UNSUPPORTED", "Reflected provider is detached");
                result = typed(provider_call([&] { return host->invoke_reflected(runtime, method, delegated); }), method.return_type);
            } else if (state->managed != no_index) {
                result = (stat || (method.flags&2)) ? runtime.invoke(state->managed, delegated) : runtime.invoke_virtual(state->managed, delegated);
            } else fail("API_UNSUPPORTED", "Reflected Object declaration has no executable dispatch reference");
            return method.return_type == "V" ? Value::reference(0) : result;
        } catch (const JavaException &cause) {
            current_context().last_exception = cause.object;
            const auto wrapper = runtime.new_object("Ljava/lang/reflect/InvocationTargetException;");
            object(wrapper).cause = cause.object;
            ++metrics.exceptions; current_context().last_exception = wrapper;
            throw JavaException(wrapper);
        }
    }
    void validate_reflected_field(const HostField &field) const {
        if (std::popcount(field.flags & 7u) > 1 || (field.flags & ~0x50dfu))
            fail("FIELD_METADATA", "Reflected field has invalid or contradictory modifiers");
        if (const auto *definition = resolve_class(field.owner); definition && std::popcount(definition->flags & 7u) > 1)
            fail("FIELD_METADATA", "Reflected declaring class has contradictory visibility modifiers");
        known(field.type);
        if (field.type == "V") fail("FIELD_METADATA", "Reflected field cannot have void type");
    }
    ObjectId lookup_declared_field(std::span<const Value> args) {
        const auto declaring_type=std::string(runtime.represented_class(reference(args[0])));
        const auto text=runtime.string(reference(args[1]));
        if (text.size()>1024) fail("FIELD_LIMIT", "Reflective field name exceeds 1024 UTF-16 units");
        std::string name;
        for (const auto c:text) {
            if(c>127) fail("FIELD_UNSUPPORTED", "Reflective non-ASCII field names are not implemented");
            name.push_back(static_cast<char>(c));
        }
        ReflectedField selected;
        if (const auto *definition=resolve_class(declaring_type)) {
            if (std::popcount(definition->flags & 7u)>1)
                fail("FIELD_METADATA", "Reflected declaring class has contradictory visibility modifiers");
            std::size_t work=0;
            const auto inspect=[&](const std::vector<Index> &fields, bool stat) {
                for (const auto index:fields) {
                    if(++work>262144) fail("FIELD_LIMIT", "Declared field lookup exceeds work budget");
                    const auto &field=image.fields.at(index);
                    if (!field.declared || image.types.at(field.owner)!=declaring_type || ((field.flags&8)!=0)!=stat)
                        fail("FIELD_METADATA", "Declared field metadata has the wrong owner or storage kind");
                    if(field.name!=name) continue;
                    if(selected.managed!=no_index) fail("FIELD_AMBIGUOUS", "Reflective field name has multiple declarations");
                    selected.managed=index;
                    selected.metadata={declaring_type,name,image.types.at(field.type),field.flags,(definition->flags&1)!=0};
                    validate_reflected_field(selected.metadata);
                }
            };
            inspect(definition->instance_fields,false);inspect(definition->static_fields,true);
            if(selected.managed==no_index) runtime.raise("Ljava/lang/NoSuchFieldException;",text);
        } else if (!reference_type(declaring_type) || declaring_type.starts_with('[') || declaring_type=="Ljava/lang/Object;") {
            // Complete declared field inventory for primitives, arrays and Object is empty.
            runtime.raise("Ljava/lang/NoSuchFieldException;",text);
        } else {
            const auto metadata=host ? provider_call([&] { return host->declared_field(declaring_type,name); }) : std::nullopt;
            if(!metadata) fail("FIELD_UNSUPPORTED", "Declared reflective field metadata is incomplete for "+declaring_type+"."+name);
            if(metadata->owner!=declaring_type || metadata->name!=name)
                fail("FIELD_METADATA", "Reflected provider field metadata does not match exact declaration");
            validate_reflected_field(*metadata);selected.metadata=*metadata;selected.provider=true;
        }
        Object result;result.type="Ljava/lang/reflect/Field;";
        result.reflected_field=std::make_unique<const ReflectedField>(std::move(selected));
        return allocate(std::move(result));
    }
    Value read_reflected_field(std::span<const Value> args) {
        const auto &field_object=object(reference(args[0]));
        const auto &state=field_object.reflected_field;
        if(!state) fail("REFERENCE", "Field object has no validated declaration");
        const auto &field=state->metadata;
        validate_reflected_field(field);
        if(!reference_type(field.type)) fail("FIELD_UNSUPPORTED", "Reflected primitive field boxing is not implemented");
        const bool stat=(field.flags&8)!=0;
        const auto receiver=stat ? ObjectId{0} : reference(args[1]);
        if(!stat) {
            if(!receiver) runtime.raise("Ljava/lang/NullPointerException;");
            if(!subtype(object(receiver).type,field.owner)) runtime.raise("Ljava/lang/IllegalArgumentException;");
        }
        if(!field_object.reflective_access_override) {
            std::string_view caller;
            if (const auto index = caller_frame_method(); index != no_index) caller=image.types.at(image.methods.at(index).owner);
            const auto package=[](std::string_view type) {const auto slash=type.rfind('/');return type.substr(0,slash==type.npos?0:slash);};
            const bool same_class=!caller.empty() && caller==field.owner;
            const bool same_package=!caller.empty() && package(caller)==package(field.owner);
            if(!field.declaring_class_public && !same_class && !same_package)
                runtime.raise("Ljava/lang/IllegalAccessException;",u"Reflected declaring class is inaccessible");
            const bool protected_subclass=(field.flags&4) && !caller.empty() && subtype(caller,field.owner);
            const bool accessible=(field.flags&1) || same_class || (!(field.flags&2) && (same_package || protected_subclass));
            if(!accessible || (!stat && protected_subclass && !same_package && !same_class && !subtype(object(receiver).type,caller)))
                runtime.raise("Ljava/lang/IllegalAccessException;",u"Reflected field is inaccessible to caller");
        }
        if(stat) initialize(field.owner);
        if(state->provider) {
            if(!host) fail("FIELD_UNSUPPORTED", "Reflected field provider is detached");
            return typed(provider_call([&] { return host->read_reflected_field(runtime,field,receiver); }),field.type);
        }
        if(stat) return runtime.get_static(state->managed);
        const auto slot=object(receiver).fields.find(state->managed);
        if(slot==object(receiver).fields.end()) fail("FIELD_METADATA", "Receiver has no declared field slot");
        return typed(slot->second,field.type);
    }
    Value read_public_provider_field(Index index, const Frame &frame, std::uint32_t receiver_register) {
        const auto &reference_field=image.fields.at(index);
        const auto &declaring_type=image.types.at(reference_field.owner);
        const auto metadata=host ? provider_call([&] { return host->public_field(declaring_type,reference_field.name); }) : std::nullopt;
        if(!metadata) fail("FIELD_UNSUPPORTED", "External instance field metadata is incomplete: "+declaring_type+"."+reference_field.name);
        if(!subtype(declaring_type,metadata->owner) || metadata->name!=reference_field.name || metadata->type!=image.types.at(reference_field.type))
            fail("FIELD_METADATA", "External instance field does not match its exact provider declaration");
        validate_reflected_field(*metadata);
        if((metadata->flags&7u)!=1u || !metadata->declaring_class_public || (metadata->flags&8))
            fail("FIELD_UNSUPPORTED", "External instance reads require a public nonstatic field and public declaring class");
        if(!reference_type(metadata->type)) fail("VALUE_TYPE", "iget-object requires a reference field");
        // Resolve the provider declaration before touching guest registers: an
        // unsupported native field must not become a fabricated receiver error.
        const auto receiver=reference(frame.get(receiver_register));
        if(!receiver) runtime.raise("Ljava/lang/NullPointerException;");
        if(!subtype(object(receiver).type,declaring_type)) runtime.raise("Ljava/lang/ClassCastException;");
        return typed(provider_call([&] { return host->read_reflected_field(runtime,*metadata,receiver); }),metadata->type);
    }
    [[noreturn]] void reflection_failure(std::string_view cause_type, std::u16string_view message) {
        try {
            runtime.raise(cause_type, message);
        } catch (const JavaException &cause) {
            // current_context().last_exception roots the cause during wrapper allocation.
            const auto wrapper = runtime.new_object("Ljava/lang/RuntimeException;");
            object(wrapper).cause = cause.object;
            replace_text(wrapper, std::u16string(message));
            ++metrics.exceptions;
            current_context().last_exception = wrapper;
            throw JavaException(wrapper);
        }
    }
    ObjectId new_field_updater(std::span<const Value> args) {
        const auto target = runtime.represented_class(reference(args[0]));
        const auto value_type = runtime.represented_class(reference(args[1]));
        const auto name = runtime.string(reference(args[2]));
        if (name.size() > 1024)
            fail("FIELD_LIMIT", "Atomic updater field name exceeds 1024 UTF-16 units");
        const auto *definition = resolve_class(target);
        if (!definition)
            fail("API_UNSUPPORTED", "Atomic field updaters require a held managed class definition");
        const auto caller_index = caller_frame_method();
        if (caller_index == no_index)
            fail("API_UNSUPPORTED", "Atomic field updater creation requires a managed caller");
        const auto &caller_method = image.methods.at(caller_index);
        if (!caller_method.declared || !caller_method.code)
            fail("API_UNSUPPORTED", "Atomic field updater caller is not managed bytecode");
        const auto caller = std::string_view(image.types.at(caller_method.owner));
        Index selected = no_index;
        const auto inspect = [&](std::span<const Index> fields) {
            for (const auto index : fields) {
                const auto &field = image.fields.at(index);
                // Executable DEX identifiers currently have an ASCII bound.
                if (field.name.size() == name.size() &&
                    std::equal(field.name.begin(), field.name.end(), name.begin(),
                               [](unsigned char a, char16_t b) { return a == b; })) {
                    if (selected != no_index)
                        fail("FIELD_AMBIGUOUS", "Atomic updater field name has multiple declarations");
                    selected = index;
                }
            }
        };
        inspect(definition->instance_fields);
        inspect(definition->static_fields);
        if (selected == no_index)
            reflection_failure("Ljava/lang/NoSuchFieldException;", name);
        const auto &field = image.fields.at(selected);
        if (!field.declared || image.types.at(field.owner) != target)
            fail("FIELD", "Atomic updater field metadata has the wrong declaring class");
        if (std::popcount(field.flags & 7u) > 1)
            fail("FIELD", "Atomic updater field has contradictory access modifiers");
        const auto package = [](std::string_view type) {
            const auto slash = type.rfind('/');
            return slash == std::string_view::npos ? std::string_view{} : type.substr(0, slash);
        };
        const bool same_class = caller == target, same_package = package(caller) == package(target);
        if (!(definition->flags & 1) && !same_class && !same_package)
            reflection_failure("Ljava/lang/IllegalAccessException;",
                               u"Declaring class is inaccessible to updater caller");
        const bool subclass = (field.flags & 4) && subtype(caller, target);
        const bool accessible =
            (field.flags & 1) || same_class || (!(field.flags & 2) && (same_package || subclass));
        if (!accessible)
            reflection_failure("Ljava/lang/IllegalAccessException;",
                               u"Field is inaccessible to updater caller");
        if (image.types.at(field.type) != value_type)
            runtime.raise("Ljava/lang/ClassCastException;");
        if (!reference_type(value_type) || !(field.flags & 0x40) || (field.flags & (8 | 16)))
            runtime.raise("Ljava/lang/IllegalArgumentException;",
                          u"Updater requires a volatile non-final instance reference field");
        Object updater;
        updater.type = field_updater_implementation_type;
        updater.updater = std::make_unique<ReferenceFieldUpdater>();
        updater.updater->field = selected;
        updater.updater->receiver_type =
            (field.flags & 4) && !same_package && !same_class ? caller_method.owner : field.owner;
        return allocate(std::move(updater));
    }
    bool enqueue_reference(ObjectId id) {
        auto &ref = *object(id).weak;
        ref.check();
        if (!ref.queue || ref.retired)
            return false;
        auto &queue = *object(ref.queue).queue;
        queue.check();
        if (queue.tail)
            object(queue.tail).weak->next = id;
        else
            queue.head = id;
        queue.tail = id;
        ref.queue = 0;
        ref.next = 0;
        ref.retired = ref.enqueued = true;
        return true;
    }
    ObjectId poll_reference(ObjectId id) {
        auto &queue = *object(id).queue;
        queue.check();
        const auto first = queue.head;
        if (!first)
            return 0;
        auto &ref = *object(first).weak;
        queue.head = ref.next;
        if (!queue.head)
            queue.tail = 0;
        ref.next = 0;
        ref.enqueued = false;
        return first;
    }
    ObjectId time_unit(std::size_t ordinal) {
        if (ordinal >= time_units.size())
            fail("ENUM_STATE", "Invalid TimeUnit ordinal");
        if (!time_units[ordinal]) {
            const auto ascii = time_unit_names[ordinal];
            const auto name = runtime.new_string(std::u16string(ascii.begin(), ascii.end()));
            runtime.retain(name);
            struct Release { ManagedRuntime &runtime; ObjectId id; ~Release(){ runtime.release(id); } } release{runtime,name};
            Object value; value.type = time_unit_type; value.enumeration = std::make_unique<ManagedEnum>();
            const std::array args{Value::reference(0), Value::reference(name), Value::word(static_cast<std::uint32_t>(ordinal))};
            (void)value.enumeration->invoke(runtime,"<init>","(Ljava/lang/String;I)V",args);
            time_units[ordinal] = allocate(std::move(value));
        }
        return time_units[ordinal];
    }
    bool declared_enum(std::string_view type) {
        if (type == time_unit_type || type==async_status_type) return true;
        if (type.empty() || type.front() != 'L' || core_type(type))
            return false;
        const auto *definition = resolve_class(type);
        return definition && (definition->flags & 0x4000) && definition->superclass != no_index &&
               image.types.at(definition->superclass) == enum_type;
    }
    std::string_view declaring_enum(ObjectId id) {
        auto type = std::string_view(object(id).type);
        if (type == time_unit_type || type==async_status_type) return type;
        for (unsigned depth = 0; depth < 256; ++depth) {
            const auto *definition = resolve_class(type);
            if (!definition || definition->superclass == no_index)
                fail("ENUM_STATE", "Enum object has no declaring managed class");
            const auto parent = std::string_view(image.types.at(definition->superclass));
            if (parent == enum_type)
                return type;
            type = parent;
        }
        fail("CLASS_LIMIT", "Enum hierarchy exceeds limit");
    }
    std::vector<ObjectId> enum_constants(std::string_view type) {
        initialize(type);
        if(type==async_status_type) {
            std::vector<ObjectId> values;
            for(std::size_t n=0;n<3;++n)values.push_back(async_status(n));
            return values;
        }
        if (type == time_unit_type) {
            std::vector<ObjectId> values;
            for (std::size_t n=0;n<time_units.size();++n) values.push_back(time_unit(n));
            return values;
        }
        const auto *definition = resolve_class(type);
        std::vector<ObjectId> constants;
        for (const auto index : definition->static_fields) {
            const auto &field = image.fields.at(index);
            if (!(field.flags & 0x4000))
                continue;
            if ((field.flags & (8 | 16)) != (8 | 16) || image.types.at(field.type) != type)
                fail("ENUM_STATE", "Enum constant field has invalid flags or type");
            if (constants.size() == limits.array_length)
                fail("ENUM_LIMIT", "Enum constants exceed the managed array bound");
            const auto id = reference(runtime.get_static(index));
            if (!id || !object(id).enumeration || declaring_enum(id) != type)
                fail("ENUM_STATE", "Enum constant field is not an initialized value of its declaring type");
            (void)object(id).enumeration->ordinal();
            constants.push_back(id);
        }
        std::sort(constants.begin(), constants.end(), [&](ObjectId a, ObjectId b) {
            return object(a).enumeration->ordinal() < object(b).enumeration->ordinal();
        });
        for (std::size_t n = 0; n < constants.size(); ++n)
            if (object(constants[n]).enumeration->ordinal() != n)
                fail("ENUM_STATE", "Enum constant ordinals are not contiguous declaration positions");
        return constants;
    }
    Value string_split(ObjectId receiver,ObjectId source,std::int32_t limit) {
        // Reuse the existing UTF16 ICU pattern/matcher, error translation and
        // native reservations. The invocation frame roots both String inputs.
        const auto pattern=compile_regex(source,0);RegexRoot pattern_root(runtime,pattern);
        const auto matcher=create_regex_matcher(pattern,receiver);RegexRoot matcher_root(runtime,matcher);
        auto &split_matcher=*object(matcher).regex_matcher->native;
        const auto text=split_matcher.input(); // Stable matcher-owned storage, retained through GC.
        struct Part {std::uint32_t first,length;};
        // A consuming final match can be followed by an empty EOF match, then
        // the final empty remainder (for example "a" split by "a|$").
        const auto capacity=limit>0?std::min(text.size()+2,static_cast<std::size_t>(limit)):text.size()+2;
        regex_preflight(capacity*sizeof(Part),false);
        std::vector<Part> parts;parts.reserve(capacity);
        const auto bytes=parts.capacity()*sizeof(Part);
        regex_preflight(bytes,false);RegexCharge scratch(metrics.heap_bytes,bytes);
        std::size_t count=0,index=0;
        const auto append=[&](std::size_t first,std::size_t length) {
            if(count>=capacity)fail("REGEX_BACKEND","Split result exceeded its bounded span storage");
            parts.push_back({static_cast<std::uint32_t>(first),static_cast<std::uint32_t>(length)});++count;
        };
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(50);
        const auto work=[&] {
            auto &context=current_context();
            if(!context.remaining)fail("BUDGET","String split instruction allowance exhausted");
            --context.remaining;
            if(scheduled_task()) {
                if(!task_work_remaining)fail("BUDGET","String split task batch allowance exhausted");
                --task_work_remaining;
            } else if(main_callback_inflight) {
                if(!main_callback_work_remaining)fail("BUDGET","String split main callback allowance exhausted");
                --main_callback_work_remaining;
            }
            if(std::chrono::steady_clock::now()>=deadline)fail("REGEX_LIMIT","String split exceeded its aggregate deadline");
        };
        try {
            while(limit<=0 || count<static_cast<std::size_t>(limit-1)) {
                work();const auto found=split_matcher.find();work();
                if(!found)break;
                const auto first=split_matcher.start(0),last=split_matcher.end(0);
                if(first<0 || last<first || static_cast<std::size_t>(last)>text.size() ||
                   static_cast<std::size_t>(first)<index)
                    fail("REGEX_BACKEND","ICU returned invalid split offsets");
                // Modern Android (target API >28) skips an initial zero-width
                // delimiter. Legacy target-dependent behavior is unsupported.
                if(!index && !first && !last)continue;
                append(index,static_cast<std::size_t>(first)-index);index=static_cast<std::size_t>(last);
            }
        } catch(const host::RegexError &error){regex_error(error);}
        // A skipped initial zero-width delimiter is not an effective split;
        // no-match empty input therefore remains a singleton empty String.
        if(!index && !count)append(0,text.size());
        else {
            append(index,text.size()-index);
            if(!limit)while(count && !parts[count-1].length)--count;
        }
        if(count>limits.array_length)fail("ARRAY_LIMIT","String split result exceeds the managed array bound");
        const auto result=runtime.new_array("[Ljava/lang/String;",static_cast<std::int32_t>(count));
        RegexRoot result_root(runtime,result);
        for(std::size_t n=0;n<count;++n) {
            work();const auto part=parts[n];
            const auto value=!part.first && part.length==text.size()?receiver:
                runtime.new_string(text.substr(part.first,part.length));
            RegexRoot value_root(runtime,value);
            runtime.array_set(result,static_cast<std::int32_t>(n),Value::reference(value));
        }
        return Value::reference(result);
    }
    Value substring_index(std::u16string_view text,std::u16string_view needle,std::int32_t from) {
        const auto start=std::min(static_cast<std::size_t>(std::max(from,0)),text.size());
        if(needle.empty()) return Value::word(static_cast<std::uint32_t>(start));
        if(needle.size()>text.size()-start) return Value::word(0xffffffffu);
        if(needle.size()==1) {
            const auto found=text.find(needle.front(),start);
            return Value::word(found==std::u16string_view::npos ? 0xffffffffu : static_cast<std::uint32_t>(found));
        }
        // Linear prefix matching bounds repeated-prefix inputs. This native
        // scratch storage participates in the same heap budget as managed data.
        if(needle.size()>std::numeric_limits<std::uint32_t>::max() ||
           needle.size()>std::numeric_limits<std::size_t>::max()/sizeof(std::uint32_t))
            fail("STRING_LIMIT", "String search prefix size exceeds index bounds");
        const auto bytes=needle.size()*sizeof(std::uint32_t);
        if(bytes>limits.heap_bytes-metrics.heap_bytes) collect();
        if(bytes>limits.heap_bytes-metrics.heap_bytes)
            fail("HEAP_LIMIT", "String search scratch exceeds managed heap budget");
        std::vector<std::uint32_t> prefix(needle.size());
        const auto reserved=prefix.capacity()*sizeof(std::uint32_t);
        if(reserved>limits.heap_bytes-metrics.heap_bytes)
            fail("HEAP_LIMIT", "String search scratch capacity exceeds managed heap budget");
        metrics.heap_bytes+=reserved;
        struct Scratch {
            std::size_t &heap_bytes;std::size_t bytes;
            ~Scratch(){heap_bytes-=bytes;}
        } scratch{metrics.heap_bytes,reserved};
        for(std::size_t at=1,matched=0;at<needle.size();++at) {
            while(matched && needle[at]!=needle[matched]) matched=prefix[matched-1];
            if(needle[at]==needle[matched]) ++matched;
            prefix[at]=static_cast<std::uint32_t>(matched);
        }
        for(std::size_t at=start,matched=0;at<text.size();++at) {
            while(matched && text[at]!=needle[matched]) matched=prefix[matched-1];
            if(text[at]==needle[matched]) ++matched;
            if(matched==needle.size()) return Value::word(static_cast<std::uint32_t>(at+1-matched));
        }
        return Value::word(0xffffffffu);
    }
    Value append_boolean(ObjectId receiver,bool value) {
        if(object(receiver).type!="Ljava/lang/StringBuilder;")fail("VALUE_TYPE","Boolean append requires a StringBuilder");
        const auto text=runtime.char_sequence(receiver);
        const std::u16string_view suffix=value?u"true":u"false";
        if(suffix.size()>limits.array_length-text.size())fail("STRING_LIMIT","StringBuilder append exceeds length limit");
        replace_text(receiver,std::u16string(text)+std::u16string(suffix));
        return Value::reference(receiver);
    }
    Value append_object(ObjectId receiver,ObjectId value) {
        (void)object(receiver);
        ObjectId snapshot=0;
        if(value) {
            if(!current_context().barriers)fail("STATE","StringBuilder.append lacks its core barrier");
            SuspendCoreBarrier allow(current_context());
            snapshot=reference(runtime.invoke_virtual_named(value,"toString","()Ljava/lang/String;"));
        }
        runtime.retain(snapshot);
        struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} root{runtime,snapshot};
        // The callback may mutate this builder or collect its old storage. Read
        // the latest contents only after it returns, keeping its result rooted.
        const auto growth=(snapshot?runtime.string(snapshot).size():4U)*sizeof(char16_t);
        if(growth>limits.heap_bytes-metrics.heap_bytes)collect();
        const auto appended=snapshot?runtime.string(snapshot):std::u16string_view(u"null");
        const auto &text=object(receiver).text;
        if(appended.size()>limits.array_length-text.size())fail("STRING_LIMIT","StringBuilder append exceeds length limit");
        replace_text(receiver,std::u16string(text)+std::u16string(appended));
        return Value::reference(receiver);
    }
    Value string_contains(ObjectId receiver,ObjectId sequence) {
        // The enclosing invocation frame roots receiver/sequence. Drop only this
        // exact core operation's barrier for the real virtual toString callback;
        // outer provider/native/loading/monitor restrictions remain in force.
        if(!current_context().barriers)fail("STATE","String.contains lacks its core barrier");
        ObjectId snapshot;
        {
            SuspendCoreBarrier allow(current_context());
            snapshot=reference(runtime.invoke_virtual_named(sequence,"toString","()Ljava/lang/String;"));
        }
        runtime.retain(snapshot);
        struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} root{runtime,snapshot};
        // Reacquire both immutable views after callbacks/GC, never retaining an
        // Object reference or character view across arbitrary managed execution.
        const auto result=substring_index(runtime.string(receiver),runtime.string(snapshot),0);
        return Value::word(word(result)!=0xffffffffu);
    }
    Value string_concat(ObjectId receiver,ObjectId suffix) {
        const auto left=runtime.string(receiver),right=runtime.string(suffix);
        if(right.empty())return Value::reference(receiver);
        if(right.size()>limits.array_length-left.size())fail("STRING_LIMIT","String concatenation exceeds length limit");
        std::u16string combined(left);combined.append(right);
        return Value::reference(runtime.new_string(combined));
    }
    Value typed_array_copy(ObjectId source,std::int32_t length,ObjectId requested_class) {
        const auto descriptor=std::string(runtime.represented_class(requested_class));
        // Arrays.copyOf constructs the requested array before inspecting source.
        // A non-array Class has no component type and fails like a null component.
        if(!descriptor.starts_with('['))runtime.raise("Ljava/lang/NullPointerException;");
        const auto result=runtime.new_array(descriptor,length);runtime.retain(result);
        struct Root {ManagedRuntime &runtime;ObjectId id;~Root(){runtime.release(id);}} result_root{runtime,result};
        if(!reference_type(std::string_view(descriptor).substr(1)))runtime.raise("Ljava/lang/ClassCastException;");
        const auto count=std::min(runtime.array_length(source),static_cast<std::size_t>(length));
        for(std::size_t at=0;at<count;++at) {
            const auto element=runtime.array_get(source,static_cast<std::int32_t>(at));
            const auto id=reference(element);runtime.retain(id);Root element_root{runtime,id};
            // Type/provider callbacks can collect and mutate the source. Keep
            // both the captured element and fresh result rooted, with no spans.
            runtime.array_set(result,static_cast<std::int32_t>(at),element);
        }
        return Value::reference(result);
    }
    Value core(Index index, std::span<const Value> args, bool virtual_dispatch) {
        NonYielding barrier(current_context());
        report_progress(RuntimeProgressStage::core_enter,index);
        ProgressEnd progress{*this,RuntimeProgressStage::core_exit,index,0};
        const auto &method = image.methods.at(index);
        const auto &type = image.types.at(method.owner);
        const auto &signature = image.prototypes.at(method.prototype).descriptor;
        ++metrics.core_calls;
        if(type=="Ljava/util/ArrayList;" && method.name=="<init>" && signature=="(Ljava/util/Collection;)V")
            return array_list_construct_collection(reference(args[0]),reference(args[1]));
        if(type=="Ljava/lang/StringBuilder;" && method.name=="append" && signature=="(Z)Ljava/lang/StringBuilder;")
            return append_boolean(reference(args[0]),word(args[1])!=0);
        if(type=="Ljava/lang/StringBuilder;" && method.name=="append" && signature=="(Ljava/lang/Object;)Ljava/lang/StringBuilder;")
            return append_object(reference(args[0]),reference(args[1]));
        const bool object_view_method=type=="Ljava/lang/Object;" && virtual_dispatch &&
            ((method.name=="equals" && signature=="(Ljava/lang/Object;)Z") ||
             (method.name=="hashCode" && signature=="()I") || (method.name=="toString" && signature=="()Ljava/lang/String;"));
        const bool map_set_owner=type==map_backed_set_type || type=="Ljava/util/Set;" || type=="Ljava/util/AbstractSet;" ||
            type=="Ljava/util/Collection;" || type=="Ljava/util/AbstractCollection;" || object_view_method ||
            (type=="Ljava/lang/Iterable;" && method.name=="iterator" && signature=="()Ljava/util/Iterator;");
        if(map_set_owner && (virtual_dispatch || type==map_backed_set_type) && map_backed_set_method(method.name,signature) &&
            !args.empty() && args[0].kind==ValueKind::reference && args[0].bits && object(reference(args[0])).type==map_backed_set_type)
            return invoke_map_backed_set(reference(args[0]),method.name,signature,args);
        if(((virtual_dispatch && (collection_class(type) || type==synchronized_collection_type) && type!=arrays_type) ||
            synchronized_list_class(type) || type==synchronized_collection_type || object_view_method) && synchronized_list_owner_method(type,method.name,signature)) {
            const auto receiver=reference(args[0]);
            if(synchronized_list_class(object(receiver).type)) {
                if(!virtual_dispatch && type==synchronized_collection_type &&
                   ((method.name=="equals" && signature=="(Ljava/lang/Object;)Z") || (method.name=="hashCode" && signature=="()I")))
                    return method.name=="equals"?Value::word(receiver==reference(args[1])):Value::word(static_cast<std::uint32_t>(receiver^(receiver>>32)));
                return invoke_synchronized_list(receiver,method.name,signature,args);
            }
        }
        if(((virtual_dispatch && collection_class(type) && type!=arrays_type) || unmodifiable_class(type) || object_view_method) &&
           unmodifiable_owner_method(type,method.name,signature)) {
            const auto receiver=reference(args[0]);const auto &actual_type=object(receiver).type;
            if(!virtual_dispatch && type==unmodifiable_collection_type &&
               ((method.name=="equals" && signature=="(Ljava/lang/Object;)Z") || (method.name=="hashCode" && signature=="()I")))
                return method.name=="equals"?Value::word(receiver==reference(args[1])):Value::word(static_cast<std::uint32_t>(receiver^(receiver>>32)));
            if((unmodifiable_list_class(actual_type) && unmodifiable_list_method(method.name,signature)) ||
               (unmodifiable_iterator_class(actual_type) && unmodifiable_iterator_method(method.name,signature,actual_type==unmodifiable_list_iterator_type)))
                return invoke_unmodifiable(receiver,method.name,signature,args);
        }
        if(type==thread_local_type && thread_local_method(method.name,signature))
            if(const auto result=invoke_thread_local(reference(args[0]),method.name,signature,args))return *result;
        if(type==pattern_type) {
            if(method.name=="compile" && (signature=="(Ljava/lang/String;)Ljava/util/regex/Pattern;" ||
                signature=="(Ljava/lang/String;I)Ljava/util/regex/Pattern;"))
                return Value::reference(compile_regex(reference(args[0]),args.size()==1?0:word(args[1])));
            if(method.name=="quote" && signature=="(Ljava/lang/String;)Ljava/lang/String;") {
                const auto text=runtime.string(reference(args[0]));
                if(text.size()>4096)fail("REGEX_LIMIT","Regex quote exceeds 4096 UTF16 units");
                return Value::reference(runtime.new_string(regex_quote(text)));
            }
            if(method.name=="matches" && signature=="(Ljava/lang/String;Ljava/lang/CharSequence;)Z") {
                const auto pattern=compile_regex(reference(args[0]),0);RegexRoot pattern_root(runtime,pattern);
                const auto matcher=create_regex_matcher(pattern,reference(args[1]));RegexRoot matcher_root(runtime,matcher);
                const std::array values{Value::reference(matcher)};return *invoke_regex(matcher,"matches","()Z",values);
            }
        }
        if(!args.empty() && (regex_method(type,method.name,signature) ||
            (type=="Ljava/lang/Object;" && virtual_dispatch && method.name=="toString" && signature=="()Ljava/lang/String;" &&
             object(reference(args[0])).regex_pattern)))
            if(const auto result=invoke_regex(reference(args[0]),method.name,signature,args))return *result;
        if(type==collections_utility_type && (method.name=="emptyMap" && signature=="()Ljava/util/Map;"))
            return Value::reference(canonical_empty(empty_map_type));
        if(type==collections_utility_type && (method.name=="emptySet" && signature=="()Ljava/util/Set;"))
            return Value::reference(canonical_empty(empty_set_type));
        const bool empty_collection_owner=type==empty_map_type || type==empty_set_type || type==empty_map_iterator_type ||
            type=="Ljava/util/Map;" || type=="Ljava/util/AbstractMap;" || type=="Ljava/util/Set;" ||
            type=="Ljava/util/AbstractSet;" || type=="Ljava/util/Collection;" || type=="Ljava/util/AbstractCollection;" ||
            type=="Ljava/lang/Iterable;" || type=="Ljava/util/Iterator;" || (type=="Ljava/lang/Object;" && virtual_dispatch);
        if(empty_collection_owner && !args.empty()) {
            const auto &receiver_type=object(reference(args[0])).type;
            if(empty_map_method(receiver_type,method.name,signature))
                if(const auto result=invoke_empty_map(runtime,receiver_type,method.name,signature,args,
                    [&](std::string_view kind){return canonical_empty(kind);}))return *result;
        }

        if(type==print_stream_type && print_stream_method(method.name,signature))
            return invoke_print_stream(reference(args[0]),method.name,args);
        if((type==input_stream_type || type==file_input_stream_type || type==byte_input_stream_type ||
            type==reader_type || type==string_reader_type || type==input_reader_type || type==buffered_reader_type ||
            type=="Ljava/io/Closeable;" || type=="Ljava/lang/AutoCloseable;" || type=="Ljava/lang/Readable;") &&
            !args.empty() && object(reference(args[0])).stream)
            if(const auto result=invoke_stream(reference(args[0]),type,method.name,signature,args,virtual_dispatch))return *result;

        if(type=="Landroid/text/TextUtils;" && method.name=="isEmpty" && signature=="(Ljava/lang/CharSequence;)Z") {
            const auto sequence=reference(args[0]);
            if(!sequence)return Value::word(1);
            // Only this exact SDK callback gateway drops its own core barrier.
            // Provider/native/class-initializer/monitor boundaries remain intact.
            require_suspendable();SuspendCoreBarrier allow(current_context());
            const auto length=runtime.invoke_virtual_named(sequence,"length","()I");
            return Value::word(word(length)==0);
        }

        if(type==android_process_type && method.name=="myPid" && signature=="()I") {
            const auto pid=host::current_process_id();
            if(!pid || pid>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
                fail("PROCESS_ID_UNSUPPORTED","The actual host process ID does not fit a positive Java int");
            return Value::word(pid);
        }
        if(type==android_process_type && method.name=="setThreadPriority" && signature=="(I)V") {
            process_priority(std::bit_cast<std::int32_t>(word(args[0])));return Value::nothing();
        }
        if(type==android_binder_type && method.name=="flushPendingCommands" && signature=="()V") {
            binder_flush();return Value::nothing();
        }
        if(type==async_task_type && method.name=="execute" && signature=="(Ljava/lang/Runnable;)V") {
            async_main_owner();require_suspendable();SuspendCoreBarrier allow(current_context());ensure_async_runtime();
            const std::array<Value,1> job{args[0]};
            (void)runtime.invoke_virtual_named(async_globals[1],"execute","(Ljava/lang/Runnable;)V",job);return Value::nothing();
        }
        if(!args.empty() && type==async_task_type)
            if(const auto result=invoke_async(reference(args[0]),method.name,signature,args))return *result;
        if(!args.empty() && (async_internal_type(type) || type==callable_type || type=="Ljava/lang/Runnable;" ||
            type=="Ljava/util/concurrent/Executor;" || type==thread_factory_type || type==rejection_handler_type) && object(reference(args[0])).async_sdk)
            if(const auto result=invoke_async_sdk(reference(args[0]),method.name,signature,args))return *result;
        if(type==async_status_type) {
            if(method.name=="values" && signature=="()[Landroid/os/AsyncTask$Status;") {
                const auto result=runtime.new_array("[Landroid/os/AsyncTask$Status;",3);runtime.retain(result);
                struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} release{runtime,result};
                for(std::size_t n=0;n<3;++n)runtime.array_set(result,static_cast<std::int32_t>(n),Value::reference(async_status(n)));
                return Value::reference(result);
            }
            if(method.name=="valueOf" && signature=="(Ljava/lang/String;)Landroid/os/AsyncTask$Status;") {
                const auto name=runtime.string(reference(args[0]));
                static constexpr std::array<std::u16string_view,3> names{u"PENDING",u"RUNNING",u"FINISHED"};
                for(std::size_t n=0;n<3;++n)if(name==names[n])return Value::reference(async_status(n));
                runtime.raise("Ljava/lang/IllegalArgumentException;");
            }
        }
        if(!args.empty() && future_class(type) && object(reference(args[0])).future)
            if(const auto result=invoke_future(reference(args[0]),method.name,signature,args))return *result;
        if(!args.empty() && (type=="Ljava/lang/Runnable;" || type==runnable_future_type) &&
            method.name=="run" && signature=="()V" && object(reference(args[0])).future) {
            (void)run_future(reference(args[0]),false);return Value::nothing();
        }
        if (!args.empty() && thread_pool_class(type)) {
            auto &receiver = object(reference(args[0]));
            if (receiver.pool) {
                auto &pool = *receiver.pool;
                if (type == thread_pool_type && method.name == "<init>") {
                    const std::string prefix="(IIJLjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;";
                    const bool base=signature==prefix+")V";
                    const bool factory=signature==prefix+"Ljava/util/concurrent/ThreadFactory;)V";
                    const bool handler=signature==prefix+"Ljava/util/concurrent/RejectedExecutionHandler;)V";
                    const bool both=signature==prefix+"Ljava/util/concurrent/ThreadFactory;Ljava/util/concurrent/RejectedExecutionHandler;)V";
                    if (base||factory||handler||both) {
                        if (pool.initialized()) fail("STATE","ThreadPoolExecutor constructor invoked twice");
                        const auto core=std::bit_cast<std::int32_t>(word(args[1]));
                        const auto maximum=std::bit_cast<std::int32_t>(word(args[2]));
                        const auto keep=std::bit_cast<std::int64_t>(wide(args[3]));
                        if (core<0||maximum<=0||maximum<core||keep<0)runtime.raise("Ljava/lang/IllegalArgumentException;");
                        const auto &unit=object(reference(args[4]));
                        if (unit.type!=time_unit_type||!unit.enumeration)fail("ENUM_STATE","Invalid executor TimeUnit");
                        const auto nanos=convert_time_unit(keep,unit.enumeration->ordinal(),0);
                        const auto queue=reference(args[5]);
                        (void)validate_pool_queue(queue);
                        ObjectId factory_id=(factory||both)?reference(args[6]):0;
                        ObjectId handler_id=(handler||both)?reference(args[both?7:6]):0;
                        if ((factory||both)&&!factory_id)runtime.raise("Ljava/lang/NullPointerException;");
                        if ((handler||both)&&!handler_id)runtime.raise("Ljava/lang/NullPointerException;");
                        if (!factory_id) {
                            const auto creator=runtime.current_thread();
                            Object value;value.type=default_thread_factory_type;value.factory=std::make_unique<DefaultFactory>();
                            value.factory->group=thread_state(creator).group?thread_state(creator).group:thread_group();
                            factory_id=allocate(std::move(value));
                        }
                        runtime.retain(factory_id);
                        struct Release { ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);} } release{runtime,factory_id};
                        if (!handler_id) {
                            Object value;value.type=abort_policy_type;value.abort_policy=std::make_unique<AbortPolicy>();
                            (void)value.abort_policy->invoke(runtime,abort_policy_type,"<init>","()V");
                            handler_id=allocate(std::move(value));
                        }
                        pool.initialize(static_cast<std::uint32_t>(core),static_cast<std::uint32_t>(maximum),nanos,queue,factory_id,handler_id);
                        return Value::nothing();
                    }
                } else {
                    std::optional<std::uint32_t> ordinal;
                    if ((method.name=="getKeepAliveTime"&&signature=="(Ljava/util/concurrent/TimeUnit;)J")||
                        (method.name=="setKeepAliveTime"&&signature=="(JLjava/util/concurrent/TimeUnit;)V")) {
                        const auto &unit=object(reference(args[method.name=="getKeepAliveTime"?1:2]));
                        if (unit.type!=time_unit_type||!unit.enumeration)fail("ENUM_STATE","Invalid executor TimeUnit");
                        ordinal=unit.enumeration->ordinal();
                    }
                    if (const auto result=invoke_pool(reference(args[0]),method.name,signature,args,ordinal)) return *result;
                }
            }
        }
        if(!args.empty() && (type==thread_factory_type || type==default_thread_factory_type) &&
            method.name=="newThread" && signature=="(Ljava/lang/Runnable;)Ljava/lang/Thread;" && object(reference(args[0])).factory)
            return Value::reference(default_factory_thread(reference(args[0]),reference(args[1])));
        if(!args.empty() && (type=="Ljava/lang/Runnable;" || type==pool_worker_type) &&
            method.name=="run" && signature=="()V" && object(reference(args[0])).pool_worker) {
            require_suspendable();SuspendCoreBarrier allow(current_context());
            run_pool_worker(reference(args[0]));return Value::nothing();
        }
        if (type == "Ljava/lang/Math;") {
            if ((method.name == "min" || method.name == "max") && signature == "(II)I") {
                const auto a=std::bit_cast<std::int32_t>(word(args[0])), b=std::bit_cast<std::int32_t>(word(args[1]));
                return Value::word(static_cast<std::uint32_t>(method.name == "min" ? std::min(a,b) : std::max(a,b)));
            }
            if ((method.name == "min" || method.name == "max") && signature == "(JJ)J") {
                const auto a=std::bit_cast<std::int64_t>(wide(args[0])), b=std::bit_cast<std::int64_t>(wide(args[1]));
                return Value::wide(static_cast<std::uint64_t>(method.name == "min" ? std::min(a,b) : std::max(a,b)));
            }
            if (method.name == "abs" && signature == "(I)I") {
                const auto bits=word(args[0]);
                return Value::word(std::bit_cast<std::int32_t>(bits)<0 ? std::uint32_t{0}-bits : bits);
            }
            if (method.name == "abs" && signature == "(J)J") {
                const auto bits=wide(args[0]);
                return Value::wide(std::bit_cast<std::int64_t>(bits)<0 ? std::uint64_t{0}-bits : bits);
            }
        }
        if(type=="Ldalvik/system/VMRuntime;") {
            if(method.name=="getRuntime" && signature=="()Ldalvik/system/VMRuntime;")return vm_runtime();
            if(method.name=="setHiddenApiExemptions" && signature=="([Ljava/lang/String;)V")return set_hidden_api_exemptions(reference(args[0]),reference(args[1]));
            fail("API_UNSUPPORTED","VMRuntime operation is unsupported: "+method.name+signature);
        }
        if (type == "Ljava/lang/Runtime;") {
            if (method.name == "getRuntime" && signature == "()Ljava/lang/Runtime;") {
                if (!runtime_object) {
                    Object value; value.type = "Ljava/lang/Runtime;";
                    runtime_object = allocate(std::move(value));
                }
                return Value::reference(runtime_object);
            }
            if (method.name == "availableProcessors" && signature == "()I") {
                if (reference(args[0]) != runtime_object)
                    fail("STATE", "Runtime is not this application's attached runtime");
                const auto processors = host::available_processors();
                if (!processors)
                    fail("PLATFORM_UNSUPPORTED", "Processor query unavailable or CPU-set/multiple-group topology unsupported");
                return Value::word(processors);
            }
        }
        if (type == time_unit_type) {
            if (method.name == "values" && signature == "()[Ljava/util/concurrent/TimeUnit;") {
                const auto constants = enum_constants(type);
                const auto array = runtime.new_array("[Ljava/util/concurrent/TimeUnit;",7);
                for (std::size_t n=0;n<constants.size();++n)
                    runtime.array_set(array,static_cast<std::int32_t>(n),Value::reference(constants[n]));
                return Value::reference(array);
            }
            if (method.name == "valueOf" && signature == "(Ljava/lang/String;)Ljava/util/concurrent/TimeUnit;") {
                const auto name = runtime.string(reference(args[0]));
                for (std::size_t n=0;n<time_unit_names.size();++n) {
                    const auto ascii=time_unit_names[n];
                    if (name == std::u16string(ascii.begin(),ascii.end())) return Value::reference(time_unit(n));
                }
                runtime.raise("Ljava/lang/IllegalArgumentException;");
            }
            const auto target = time_unit_target(method.name);
            if ((target && signature == "(J)J") ||
                (method.name == "convert" && signature == "(JLjava/util/concurrent/TimeUnit;)J")) {
                const auto id = reference(args[0]);
                const auto &receiver = object(id);
                if (!receiver.enumeration) fail("ENUM_STATE","TimeUnit is not initialized");
                auto source = receiver.enumeration->ordinal();
                auto destination = target ? *target : source;
                if (!target) {
                    const auto &other = object(reference(args[2]));
                    if (other.type != time_unit_type || !other.enumeration) fail("ENUM_STATE","Invalid source TimeUnit");
                    source = other.enumeration->ordinal();
                }
                return Value::wide(static_cast<std::uint64_t>(convert_time_unit(
                    std::bit_cast<std::int64_t>(wide(args[1])),source,destination)));
            }
        }
        if (!args.empty() && (type == abort_policy_type || type == rejection_handler_type)) {
            auto &receiver = object(reference(args[0]));
            if (receiver.abort_policy)
                if (const auto result = receiver.abort_policy->invoke(runtime, type, method.name, signature))
                    return *result;
        }
        if (type == "Ljava/lang/Thread;") {
            if(method.name=="getDefaultUncaughtExceptionHandler" && signature=="()Ljava/lang/Thread$UncaughtExceptionHandler;")
                return Value::reference(default_uncaught_handler);
            if(method.name=="setDefaultUncaughtExceptionHandler" && signature=="(Ljava/lang/Thread$UncaughtExceptionHandler;)V") {
                const auto handler=reference(args[0]);
                if(handler && !subtype(object(handler).type,"Ljava/lang/Thread$UncaughtExceptionHandler;"))fail("VALUE_TYPE","Default handler does not implement UncaughtExceptionHandler");
                default_uncaught_handler=handler;
                return Value::nothing();
            }
            if((method.name=="getUncaughtExceptionHandler" && signature=="()Ljava/lang/Thread$UncaughtExceptionHandler;") ||
               (method.name=="setUncaughtExceptionHandler" && signature=="(Ljava/lang/Thread$UncaughtExceptionHandler;)V"))
                return *thread_handler_call(reference(args[0]),type,method.name,signature,args);
            if (method.name == "<init>" &&
                (signature == "()V" || signature == "(Ljava/lang/Runnable;)V" ||
                 signature == "(Ljava/lang/String;)V" || signature == "(Ljava/lang/Runnable;Ljava/lang/String;)V")) {
                const auto receiver = reference(args[0]);
                auto &state = thread_state(receiver, false);
                if (state.initialized) fail("THREAD_STATE", "Thread constructor invoked more than once");
                const bool has_target = signature == "(Ljava/lang/Runnable;)V" ||
                    signature == "(Ljava/lang/Runnable;Ljava/lang/String;)V";
                const bool has_name = signature == "(Ljava/lang/String;)V" ||
                    signature == "(Ljava/lang/Runnable;Ljava/lang/String;)V";
                const auto name = has_name ? reference(args[has_target ? 2 : 1]) : ObjectId{0};
                if (has_name) (void)runtime.string(name); // Null name is a real Java NPE.
                const auto parent = runtime.current_thread();
                const auto &parent_state = thread_state(parent);
                if (has_name) state.name = name;
                else {
                    std::u16string generated = u"Thread-";
                    for (const auto c : std::to_string(receiver)) generated.push_back(c);
                    state.name = runtime.new_string(generated);
                }
                state.group = parent_state.group ? parent_state.group : thread_group();
                state.daemon = parent_state.daemon;
                state.target = has_target ? reference(args[1]) : ObjectId{0};
                state.initialized = true;
                return Value::nothing();
            }
            if (method.name == "start" && signature == "()V") {
                start_java_thread(reference(args[0]));
                return Value::nothing();
            }
            if (method.name == "run" && signature == "()V") {
                const auto target = thread_state(reference(args[0])).target;
                if (target) {
                    // Only this exact core callback gateway may drop its own
                    // barrier. Managed wrapper frames remain live and traced.
                    require_suspendable();
                    SuspendCoreBarrier allow(current_context());
                    run_runnable(target, true);
                }
                return Value::nothing();
            }
            if (method.name == "isAlive" && signature == "()Z") {
                const auto receiver = reference(args[0]);
                (void)thread_state(receiver);
                return Value::word(active_thread(receiver));
            }
            if (method.name == "isDaemon" && signature == "()Z")
                return Value::word(thread_state(reference(args[0])).daemon);
            if (method.name == "setDaemon" && signature == "(Z)V") {
                const auto receiver = reference(args[0]);
                auto &state = thread_state(receiver);
                if (active_thread(receiver))
                    runtime.raise("Ljava/lang/IllegalThreadStateException;");
                state.daemon = word(args[1]) != 0;
                return Value::nothing();
            }
            if (method.name == "setName" && signature == "(Ljava/lang/String;)V") {
                auto &state = thread_state(reference(args[0]));
                const auto name = reference(args[1]);
                (void)runtime.string(name);
                state.name = name;
                return Value::nothing();
            }
            if (method.name == "sleep" && (signature == "(J)V" || signature == "(JI)V")) {
                thread_sleep(std::bit_cast<std::int64_t>(wide(args[0])),
                    signature == "(JI)V" ? std::bit_cast<std::int32_t>(word(args[1])) : 0);
                return Value::nothing();
            }
            if (method.name == "yield" && signature == "()V") {
                thread_yield();
                return Value::nothing();
            }
            if (method.name == "interrupted" && signature == "()Z") {
                auto &context = current_context();
                const auto status = context.interrupted;
                context.interrupted = false;
                return Value::word(status);
            }
            if ((method.name == "interrupt" && signature == "()V") ||
                (method.name == "isInterrupted" && signature == "()Z")) {
                const auto receiver = reference(args[0]);
                (void)thread_state(receiver);
                auto *context = live_thread_context(receiver);
                if (method.name == "isInterrupted") return Value::word(context && context->interrupted);
                if (context) {
                    context->interrupted = true;
                    for (const auto &task : tasks)
                        if (task && &task->context == context) { scheduler->wake(task->id); break; }
                }
                return Value::nothing();
            }
            if (method.name == "holdsLock" && signature == "(Ljava/lang/Object;)Z") {
                const auto id = reference(args[0]);
                (void)object(id); // Includes null and foreign-reference checks.
                for (const auto *frame : current_context().frames)
                    for (std::size_t n = 0; n < frame->monitor_count; ++n)
                        if (frame->monitors[n] == id)
                            return Value::word(1);
                return Value::word(0);
            }
            if (method.name == "currentThread" && signature == "()Ljava/lang/Thread;")
                return Value::reference(runtime.current_thread());
            if (method.name == "getThreadGroup" && signature == "()Ljava/lang/ThreadGroup;") {
                const auto receiver = reference(args[0]);
                auto &state = thread_state(receiver);
                if (state.synthetic && !active_thread(receiver)) return Value::reference(0);
                if (!state.group && state.lifecycle != ThreadState::Lifecycle::terminated)
                    state.group = thread_group();
                return Value::reference(state.group);
            }
            if ((method.name == "getId" && signature == "()J") ||
                (method.name == "getName" && signature == "()Ljava/lang/String;")) {
                const auto receiver = reference(args[0]);
                auto &state = thread_state(receiver);
                if (method.name == "getId") return Value::wide(receiver);
                if (!state.name && state.synthetic) state.name = runtime.new_string(object(receiver).text);
                return Value::reference(state.name);
            }
        }
        if ((type=="Ljava/lang/ThreadGroup;" || type=="Ljava/lang/Thread$UncaughtExceptionHandler;") &&
            method.name=="uncaughtException" && signature=="(Ljava/lang/Thread;Ljava/lang/Throwable;)V")
            return *thread_handler_call(reference(args[0]),type,method.name,signature,args);
        if (type == "Ljava/lang/ThreadGroup;" &&
            ((method.name == "getName" && signature == "()Ljava/lang/String;") ||
             (method.name == "getParent" && signature == "()Ljava/lang/ThreadGroup;"))) {
            if (!thread_group_object || reference(args[0]) != thread_group_object)
                fail("THREAD_STATE", "ThreadGroup is not this runtime's owner group");
            return method.name=="getParent" ? Value::reference(0)
                : Value::reference(runtime.new_string(object(thread_group_object).text));
        }
        if (type == "Ljava/lang/Object;" &&
            ((method.name == "equals" && signature == "(Ljava/lang/Object;)Z") ||
             (method.name == "hashCode" && signature == "()I"))) {
            const auto receiver = reference(args[0]);
            if (virtual_dispatch) {
                // Owned overrides are normally resolved before entry. This also
                // validates provider semantics before any identity fast path.
                if (const auto target = object_override(receiver, method.name, signature))
                    return runtime.invoke_virtual(*target, args);
                auto &value = object(receiver);
                if(value.uuid) {
                    const auto other=method.name=="equals"?reference(args[1]):ObjectId{0};
                    return *value.uuid->invoke(runtime,method.name,signature,args,other?object(other).uuid.get():nullptr);
                }
                if(value.boolean) {
                    const auto other=method.name=="equals"?reference(args[1]):ObjectId{0};
                    return *value.boolean->invoke(runtime,method.name,signature,args,other?object(other).boolean.get():nullptr);
                }
                if (value.integer) {
                    const auto other = method.name == "equals" ? reference(args[1]) : ObjectId{0};
                    return *value.integer->invoke(runtime, method.name, signature, args,
                                                  other ? object(other).integer.get() : nullptr);
                }
                if (value.enumeration)
                    return *value.enumeration->invoke(runtime, method.name, signature, args);
                return method.name == "equals" ? Value::word(key_equal(receiver, reference(args[1])))
                                               : Value::word(key_hash(receiver));
            }
            // invoke-super and explicit nonvirtual calls select Object itself.
            return method.name == "equals"
                       ? Value::word(receiver == reference(args[1]))
                       : Value::word(static_cast<std::uint32_t>(receiver ^ (receiver >> 32)));
        }
        if(type==random_type && random_method(method.name,signature))
            return invoke_random(reference(args[0]),method.name,signature,args);
        if(type==uuid_type && method.name=="randomUUID" && signature=="()Ljava/util/UUID;") {
            std::array<std::uint8_t,16> entropy{};
            if(!host::secure_random_128(entropy))fail("UUID_ENTROPY_UNAVAILABLE","Windows cryptographic entropy is unavailable");
            const auto bits=uuid_v4_bits(entropy);
            Object value;value.type=uuid_type;value.uuid=std::make_unique<ManagedUuid>();
            value.uuid->initialize(bits[0],bits[1]);return Value::reference(allocate(std::move(value)));
        }
        if(!args.empty() && (type==uuid_type || type=="Ljava/lang/Comparable;" || (type=="Ljava/lang/Object;" && virtual_dispatch)) &&
            ((method.name=="<init>" && signature=="(JJ)V") ||
             ((method.name=="getMostSignificantBits" || method.name=="getLeastSignificantBits") && signature=="()J") ||
             ((method.name=="version" || method.name=="variant" || method.name=="hashCode") && signature=="()I") ||
             (method.name=="toString" && signature=="()Ljava/lang/String;") ||
             (method.name=="equals" && signature=="(Ljava/lang/Object;)Z") ||
             (method.name=="compareTo" && (signature=="(Ljava/util/UUID;)I" || signature=="(Ljava/lang/Object;)I"))))
            if(object(reference(args[0])).uuid)
                if(const auto result=invoke_uuid(reference(args[0]),method.name,signature,args))return *result;
        if(type==long_type || type==short_type) {
            const bool large=type==long_type;
            if(method.name=="valueOf" && signature==(large?"(J)Ljava/lang/Long;":"(S)Ljava/lang/Short;"))return Value::reference(box_integral(type,args[0].bits));
            const auto normalized=[&](Value value){return large?value.bits:static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(word(value)))));};
            if(method.name=="compare" && signature==(large?"(JJ)I":"(SS)I")) {
                const auto a=std::bit_cast<std::int64_t>(normalized(args[0])),b=std::bit_cast<std::int64_t>(normalized(args[1]));
                return Value::word(static_cast<std::uint32_t>(large?(a>b)-(a<b):a-b));
            }
            if(method.name=="hashCode" && signature==(large?"(J)I":"(S)I")) {
                const auto value=normalized(args[0]);return Value::word(static_cast<std::uint32_t>(large?value^(value>>32):value));
            }
            if(method.name=="toString" && signature==(large?"(J)Ljava/lang/String;":"(S)Ljava/lang/String;")) {
                const auto text=std::to_string(std::bit_cast<std::int64_t>(normalized(args[0])));
                return Value::reference(runtime.new_string(std::u16string(text.begin(),text.end())));
            }
        }
        const bool integral_object_method=(method.name=="equals" && signature=="(Ljava/lang/Object;)Z") ||
            (method.name=="hashCode" && signature=="()I") || (method.name=="toString" && signature=="()Ljava/lang/String;");
        const bool integral_numeric_method=(method.name=="byteValue" && signature=="()B") ||
            (method.name=="shortValue" && signature=="()S") || (method.name=="intValue" && signature=="()I") ||
            (method.name=="longValue" && signature=="()J") || (method.name=="floatValue" && signature=="()F") ||
            (method.name=="doubleValue" && signature=="()D");
        const bool integral_owner_method=((type==long_type || type==short_type) && integral_method(type,method.name,signature)) ||
            (type==number_type && (integral_numeric_method || (virtual_dispatch && integral_object_method))) ||
            (type=="Ljava/lang/Comparable;" && method.name=="compareTo" && signature=="(Ljava/lang/Object;)I") ||
            (type=="Ljava/lang/Object;" && virtual_dispatch && integral_object_method);
        if(!args.empty() && integral_owner_method && object(reference(args[0])).integral)
            if(const auto result=invoke_integral(reference(args[0]),method.name,signature,args))return *result;
        if(type==float_type || type==double_type) {
            if(method.name=="valueOf" && signature==(type==double_type?"(D)Ljava/lang/Double;":"(F)Ljava/lang/Float;"))
                return Value::reference(box_floating(type,args[0].bits));
            if(const auto result=floating_static_call(type,method.name,signature,args))return *result;
        }
        if(method.name=="toString" && signature=="()Ljava/lang/String;" && !args.empty() &&
            (type==float_type || type==double_type || ((type==number_type || type=="Ljava/lang/Object;") && virtual_dispatch)) &&
            object(reference(args[0])).floating)
            fail("API_UNSUPPORTED","Java floating decimal formatting is not implemented");
        const bool floating_object_method=(method.name=="equals" && signature=="(Ljava/lang/Object;)Z") ||
            (method.name=="hashCode" && signature=="()I");
        const bool floating_numeric_method=(method.name=="byteValue" && signature=="()B") ||
            (method.name=="shortValue" && signature=="()S") || (method.name=="intValue" && signature=="()I") ||
            (method.name=="longValue" && signature=="()J") || (method.name=="floatValue" && signature=="()F") ||
            (method.name=="doubleValue" && signature=="()D");
        const bool floating_owner_method=((type==float_type || type==double_type) && floating_method(type,method.name,signature)) ||
            (type==number_type && (floating_numeric_method || (virtual_dispatch && floating_object_method))) ||
            (type=="Ljava/lang/Comparable;" && method.name=="compareTo" && signature=="(Ljava/lang/Object;)I") ||
            (type=="Ljava/lang/Object;" && virtual_dispatch && floating_object_method);
        if(!args.empty() && floating_owner_method && object(reference(args[0])).floating)
            if(const auto result=invoke_floating(reference(args[0]),method.name,signature,args))return *result;
        if(type==byte_type) {
            if(method.name=="valueOf" && signature=="(B)Ljava/lang/Byte;")return Value::reference(box_byte(word(args[0])));
            const auto signed_byte=[](Value value){return static_cast<std::int32_t>(std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(word(value))));};
            if(method.name=="compare" && signature=="(BB)I")return Value::word(static_cast<std::uint32_t>(signed_byte(args[0])-signed_byte(args[1])));
            if(method.name=="hashCode" && signature=="(B)I")return Value::word(static_cast<std::uint32_t>(signed_byte(args[0])));
            if(method.name=="toUnsignedInt" && signature=="(B)I")return Value::word(word(args[0])&255U);
            if(method.name=="toUnsignedLong" && signature=="(B)J")return Value::wide(word(args[0])&255U);
            if(method.name=="toString" && signature=="(B)Ljava/lang/String;") {
                const auto text=std::to_string(signed_byte(args[0]));return Value::reference(runtime.new_string(std::u16string(text.begin(),text.end())));
            }
        }
        const bool byte_object_method=(method.name=="equals" && signature=="(Ljava/lang/Object;)Z") ||
            (method.name=="hashCode" && signature=="()I") || (method.name=="toString" && signature=="()Ljava/lang/String;");
        const bool byte_numeric_method=(method.name=="byteValue" && signature=="()B") ||
            (method.name=="shortValue" && signature=="()S") || (method.name=="intValue" && signature=="()I") ||
            (method.name=="longValue" && signature=="()J") || (method.name=="floatValue" && signature=="()F") ||
            (method.name=="doubleValue" && signature=="()D");
        const bool byte_owner_method=(type==byte_type && byte_method(method.name,signature)) ||
            (type==number_type && (byte_numeric_method || (virtual_dispatch && byte_object_method))) ||
            (type=="Ljava/lang/Comparable;" && method.name=="compareTo" && signature=="(Ljava/lang/Object;)I") ||
            (type=="Ljava/lang/Object;" && virtual_dispatch && byte_object_method);
        if(!args.empty() && byte_owner_method)
            if(object(reference(args[0])).byte)
                if(const auto result=invoke_byte(reference(args[0]),method.name,signature,args))return *result;
        if(type==boolean_type) {
            if(method.name=="valueOf" && signature=="(Z)Ljava/lang/Boolean;")
                return Value::reference(box_boolean(word(args[0])!=0));
            if(method.name=="compare" && signature=="(ZZ)I")
                return Value::word(static_cast<std::uint32_t>(static_cast<int>(word(args[0])!=0)-static_cast<int>(word(args[1])!=0)));
            if(method.name=="hashCode" && signature=="(Z)I")return Value::word(word(args[0])?1231:1237);
            if(method.name=="toString" && signature=="(Z)Ljava/lang/String;")
                return Value::reference(runtime.new_string(word(args[0])?u"true":u"false"));
        }
        if(!args.empty() && (type==boolean_type || type=="Ljava/lang/Comparable;" ||
            (type=="Ljava/lang/Object;" && virtual_dispatch)) &&
            ((method.name=="<init>" && signature=="(Z)V") || (method.name=="booleanValue" && signature=="()Z") ||
             (method.name=="hashCode" && signature=="()I") || (method.name=="toString" && signature=="()Ljava/lang/String;") ||
             (method.name=="equals" && signature=="(Ljava/lang/Object;)Z") ||
             (method.name=="compareTo" && (signature=="(Ljava/lang/Boolean;)I" || signature=="(Ljava/lang/Object;)I"))))
            if(object(reference(args[0])).boolean)
                if(const auto result=invoke_boolean(reference(args[0]),method.name,signature,args))return *result;
        if (type == integer_type && method.name == "parseInt" &&
            (signature == "(Ljava/lang/String;)I" || signature == "(Ljava/lang/String;I)I"))
            return Value::word(parse_integer(runtime, reference(args[0]),
                args.size() == 2 ? std::bit_cast<std::int32_t>(word(args[1])) : 10));
        if (type == integer_type && method.name == "valueOf") {
            if (signature != "(I)Ljava/lang/Integer;")
                fail("API_UNSUPPORTED", type + "." + method.name + signature + " is not implemented");
            const auto bits = word(args[0]);
            const auto number = std::bit_cast<std::int32_t>(bits);
            const bool cached = number >= -128 && number <= 127;
            const auto slot = cached ? static_cast<std::size_t>(number + 128) : 0;
            if (cached && integer_cache[slot])
                return Value::reference(integer_cache[slot]);
            Object result;
            result.type = integer_type;
            result.integer = std::make_unique<ManagedInteger>();
            result.integer->initialize(bits);
            const auto id = allocate(std::move(result));
            if (cached)
                integer_cache[slot] = id;
            return Value::reference(id);
        }
        if (type == integer_type || type == number_type || type == "Ljava/lang/Comparable;") {
            auto &receiver = object(reference(args[0]));
            if (receiver.integer) {
                const ManagedInteger *other = nullptr;
                if ((method.name == "equals" && signature == "(Ljava/lang/Object;)Z") ||
                    (method.name == "compareTo" &&
                     (signature == "(Ljava/lang/Integer;)I" || signature == "(Ljava/lang/Object;)I"))) {
                    const auto id = reference(args[1]);
                    if (id)
                        other = object(id).integer.get();
                }
                if (const auto result =
                        receiver.integer->invoke(runtime, method.name, signature, args, other))
                    return *result;
            }
        }
        if (type == atomic_field_updater_type && method.name == "newUpdater" &&
            signature == "(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/"
                         "AtomicReferenceFieldUpdater;")
            return Value::reference(new_field_updater(args));
        if (!args.empty() && method.name != "newUpdater" &&
            (type == atomic_field_updater_type || type == field_updater_implementation_type)) {
            auto &receiver = object(reference(args[0]));
            if (type == atomic_field_updater_type && method.name == "<init>" && signature == "()V")
                return Value::nothing();
            if (receiver.updater && field_updater_method(method.name, signature)) {
                const auto &updater = *receiver.updater;
                const auto &field = image.fields.at(updater.field);
                const auto target = reference(args[1]);
                if (!target || !subtype(object(target).type, image.types.at(field.owner)))
                    runtime.raise("Ljava/lang/ClassCastException;");
                if (!subtype(object(target).type, image.types.at(updater.receiver_type)))
                    reflection_failure("Ljava/lang/IllegalAccessException;",
                                       u"Protected updater receiver is outside the caller's subclass");
                const auto slot = object(target).fields.find(updater.field);
                if (slot == object(target).fields.end())
                    fail("FIELD", "Atomic updater receiver has no selected field slot");
                return updater.invoke(runtime, slot->second, image.types.at(field.type), method.name, args);
            }
        }
        if ((type == reference_type_name || type == weak_reference_type) &&
            method.name == "reachabilityFence" && signature == "(Ljava/lang/Object;)V")
            // The invocation frame already keeps its argument strongly rooted.
            return Value::nothing();
        if (type == reference_queue_type) {
            auto &receiver = object(reference(args[0]));
            if (receiver.queue) {
                if (method.name == "<init>" && signature == "()V") {
                    if (receiver.queue->initialized)
                        fail("STATE", "ReferenceQueue constructor invoked twice");
                    receiver.queue->initialized = true;
                    return Value::nothing();
                }
                if (method.name == "poll" && signature == "()Ljava/lang/ref/Reference;")
                    return Value::reference(poll_reference(reference(args[0])));
            }
        }
        if (!args.empty() &&
            (type == weak_reference_type || type == reference_type_name ||
             (reference_instance_method(method.name, signature) && subtype(type, weak_reference_type)))) {
            auto &receiver = object(reference(args[0]));
            if (receiver.weak) {
                if (type == weak_reference_type && method.name == "<init>" &&
                    (signature == "(Ljava/lang/Object;)V" ||
                     signature == "(Ljava/lang/Object;Ljava/lang/ref/ReferenceQueue;)V")) {
                    auto &ref = *receiver.weak;
                    if (ref.initialized)
                        fail("STATE", "WeakReference constructor invoked twice");
                    const auto queue = args.size() == 3 ? reference(args[2]) : 0;
                    if (queue) {
                        if (!object(queue).queue)
                            fail("STATE", "Reference queue has no supported payload");
                        object(queue).queue->check();
                    }
                    ref.referent = reference(args[1]);
                    ref.queue = queue;
                    ref.initialized = true;
                    return Value::nothing();
                }
                if (const auto result = receiver.weak->invoke(runtime, method.name, signature, args))
                    return *result;
                if (method.name == "enqueue" && signature == "()Z")
                    return Value::word(enqueue_reference(reference(args[0])));
            }
        }
        if (type == enum_type && method.name == "valueOf" &&
            signature == "(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;") {
            const auto represented = runtime.represented_class(reference(args[0]));
            const auto requested = runtime.string(reference(args[1]));
            if (!declared_enum(represented))
                runtime.raise("Ljava/lang/IllegalArgumentException;");
            for (const auto id : enum_constants(represented))
                if (runtime.string(object(id).enumeration->reference().bits) == requested)
                    return Value::reference(id);
            runtime.raise("Ljava/lang/IllegalArgumentException;");
        }
        if (type == "Ljava/lang/Class;" && method.name == "isArray" && signature == "()Z")
            return Value::word(runtime.represented_class(reference(args[0])).starts_with('['));
        if (type == "Ljava/lang/Class;" && method.name == "isEnum" && signature == "()Z")
            return Value::word(declared_enum(runtime.represented_class(reference(args[0]))));
        if (type == "Ljava/lang/Class;" && method.name == "getEnumConstants" &&
            signature == "()[Ljava/lang/Object;") {
            const auto represented = runtime.represented_class(reference(args[0]));
            if (!declared_enum(represented))
                return Value::reference(0);
            const auto constants = enum_constants(represented);
            const auto array = runtime.new_array("[" + std::string(represented),
                                                 static_cast<std::int32_t>(constants.size()));
            for (std::size_t n = 0; n < constants.size(); ++n)
                runtime.array_set(array, static_cast<std::int32_t>(n), Value::reference(constants[n]));
            return Value::reference(array);
        }
        if (!args.empty() &&
            (type == enum_type || (enum_instance_method(method.name, signature) &&
                                   (subtype(type, enum_type) ||
                                    (type == "Ljava/lang/Comparable;" && method.name == "compareTo"))))) {
            const auto id = reference(args[0]);
            auto &receiver = object(id);
            if (receiver.enumeration) {
                if (const auto result = receiver.enumeration->invoke(runtime, method.name, signature, args))
                    return *result;
                if (method.name == "getDeclaringClass" && signature == "()Ljava/lang/Class;")
                    return Value::reference(runtime.class_object(declaring_enum(id)));
                if (method.name == "compareTo" &&
                    (signature == "(Ljava/lang/Enum;)I" || signature == "(Ljava/lang/Object;)I")) {
                    const auto other = reference(args[1]);
                    if (!object(other).enumeration || declaring_enum(id) != declaring_enum(other))
                        runtime.raise("Ljava/lang/ClassCastException;");
                    return Value::word(receiver.enumeration->ordinal() -
                                       object(other).enumeration->ordinal());
                }
            }
        }
        if(type==arrays_type && method.name=="copyOf" && signature=="([Ljava/lang/Object;ILjava/lang/Class;)[Ljava/lang/Object;")
            return typed_array_copy(reference(args[0]),std::bit_cast<std::int32_t>(word(args[1])),reference(args[2]));
        if (type == arrays_type && method.name == "asList" &&
            signature == "([Ljava/lang/Object;)Ljava/util/List;") {
            const auto array = reference(args[0]);
            (void)runtime.array_length(array);
            Object result;
            result.type = array_list_type;
            result.elements = {Value::reference(array)};
            return Value::reference(allocate(std::move(result)));
        }
        if(type==copy_list_type && method.name=="addIfAbsent" && signature=="(Ljava/lang/Object;)Z")
            return copy_list_add_if_absent(reference(args[0]),reference(args[1]));
        if(type==collections_utility_type && method.name=="newSetFromMap" && signature=="(Ljava/util/Map;)Ljava/util/Set;")
            return Value::reference(wrap_map_backed_set(reference(args[0])));
        if(type==collections_utility_type && method.name=="synchronizedList" && signature=="(Ljava/util/List;)Ljava/util/List;")
            return Value::reference(wrap_synchronized_list(reference(args[0])));
        if(type==collections_utility_type && method.name=="unmodifiableList" && signature=="(Ljava/util/List;)Ljava/util/List;")
            return Value::reference(wrap_unmodifiable_list(reference(args[0])));
        if(type==collections_utility_type&&method.name=="singletonList"&&signature=="(Ljava/lang/Object;)Ljava/util/List;") {
            if(!limits.array_length)fail("COLLECTION_LIMIT","Singleton list exceeds managed element bound");
            const auto element=reference(args[0]);if(element)(void)object(element);
            Object result;result.type=singleton_list_type;result.elements={Value::reference(element)};
            return Value::reference(allocate(std::move(result)));
        }
        if (type == collections_utility_type && method.name == "emptyList" && signature == "()Ljava/util/List;") {
            if (!empty_list) {
                Object result;result.type = empty_list_type;
                empty_list = allocate(std::move(result));
            }
            return Value::reference(empty_list);
        }
        if (type == collections_utility_type && method.name == "synchronizedSet" &&
            signature == "(Ljava/util/Set;)Ljava/util/Set;") {
            const auto backing = reference(args[0]);
            (void)object(backing);
            Object result;
            result.type = synchronized_set_type;
            result.synchronized_set = std::make_unique<SynchronizedSet>(backing);
            return Value::reference(allocate(std::move(result)));
        }
        if (type == collections_utility_type && method.name == "synchronizedMap" &&
            signature == "(Ljava/util/Map;)Ljava/util/Map;") {
            const auto backing=reference(args[0]);
            if (!subtype(object(backing).type,"Ljava/util/Map;"))fail("VALUE_TYPE","synchronizedMap requires a Map");
            Object result;result.type=synchronized_map_type;
            result.synchronized_map=std::make_unique<SynchronizedMap>(backing);
            return Value::reference(allocate(std::move(result)));
        }
        if (map_class(type)) {
            auto &receiver = object(reference(args[0]));
            if (receiver.synchronized_map && type=="Ljava/util/Map;") {
                if (method.name=="values"||method.name=="keySet"||method.name=="entrySet")
                    fail("API_UNSUPPORTED","Synchronized map view locking is not implemented");
                std::lock_guard lock(receiver.synchronized_map->mutex);
                std::vector<Value> delegated(args.begin(),args.end());
                delegated.front()=Value::reference(receiver.synchronized_map->backing);
                return runtime.invoke_virtual(index,delegated);
            }
            if (receiver.map) {
                if ((method.name=="values"&&signature=="()Ljava/util/Collection;") ||
                    (method.name=="entrySet"&&signature=="()Ljava/util/Set;")) {
                    if (!receiver.map->initialized())fail("STATE","Map must be initialized before creating a values view");
                    if (receiver.type!=hash_map_type&&receiver.type!=linked_map_type)
                        fail("API_UNSUPPORTED","Values view requires native strong map traversal; receiver="+receiver.type);
                    Object result;result.type=method.name=="entrySet"?map_entries_type:map_values_type;
                    result.map_values=std::make_unique<MapValues>();
                    result.map_values->entry_set=method.name=="entrySet";
                    result.map_values->map=reference(args[0]);return Value::reference(allocate(std::move(result)));
                }
                const bool keys =
                    method.name == "keySet" &&
                    (signature == "()Ljava/util/Set;" ||
                     signature == "()Ljava/util/concurrent/ConcurrentHashMap$KeySetView;" ||
                     signature == "(Ljava/lang/Object;)Ljava/util/concurrent/ConcurrentHashMap$KeySetView;");
                if (receiver.map->concurrent() && keys) {
                    if (!receiver.map->initialized())
                        fail("STATE", "Concurrent map must be initialized before creating a view");
                    const auto mapped = args.size() == 2 ? reference(args[1]) : 0;
                    if (args.size() == 2 && !mapped)
                        runtime.raise("Ljava/lang/NullPointerException;");
                    Object result;
                    result.type = map_keys_type;
                    result.map_keys = std::make_unique<MapKeys>();
                    result.map_keys->map = reference(args[0]);
                    result.map_keys->mapped_value = mapped;
                    return Value::reference(allocate(std::move(result)));
                }
                const MapCallbacks callbacks{[&](ObjectId key) { return key_hash(key); },
                                             [&](ObjectId a, ObjectId b) { return key_equal(a, b); }};
                if (method.name=="putAll"&&signature=="(Ljava/util/Map;)V") {
                    auto &source=object(reference(args[1]));
                    if(source.type==empty_map_type) {
                        if(!receiver.map->initialized())fail("STATE","Map must be initialized before putAll");
                        return Value::nothing();
                    }
                    const auto concrete=[](std::string_view t){return t==hash_map_type||t==weak_map_type||t==linked_map_type||t==concurrent_map_type;};
                    if (!concrete(receiver.type)||!concrete(source.type)||!source.map)
                        fail("API_UNSUPPORTED","putAll requires native map traversal; receiver="+receiver.type+" source="+source.type);
                    receiver.map->put_all(runtime,*source.map,reference(args[0]),
                        {receiver.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length},callbacks);
                    return Value::nothing();
                }
                if (const auto result = receiver.map->invoke(
                        runtime, type, method.name, signature, args,
                        {receiver.bytes, metrics.heap_bytes, limits.heap_bytes, limits.array_length},
                        callbacks))
                    return *result;
            }
        }
        if (!args.empty()&&(map_view_class(type)||type=="Ljava/util/Collection;"||type=="Ljava/util/AbstractCollection;"||
                            type=="Ljava/util/Set;"||type=="Ljava/util/AbstractSet;"||type=="Ljava/lang/Iterable;"||type=="Ljava/util/Iterator;")) {
            auto &receiver=object(reference(args[0]));
            if (receiver.map_entry) {
                const auto &entry=*receiver.map_entry;
                auto &backing=object(entry.map);
                if (!backing.map)fail("STATE","Entry has no backing map");
                if (const auto result=backing.map->invoke_entry(runtime,entry,method.name,signature,args))return *result;
            }
            if (receiver.map_values) {
                auto &view=*receiver.map_values;auto &backing=object(view.map);
                if (!backing.map||!backing.map->initialized())fail("STATE","Values view has no initialized backing map");
                if (!view.iterator&&method.name=="iterator"&&signature=="()Ljava/util/Iterator;") {
                    Object result;result.type=view.entry_set?map_entry_iterator_type:map_value_iterator_type;
                    result.map_values=std::make_unique<MapValues>();result.map_values->entry_set=view.entry_set;
                    result.map_values->map=view.map;result.map_values->iterator=true;
                    result.map_values->expected_structure=backing.map->structure_revision();
                    return Value::reference(allocate(std::move(result)));
                }
                if (view.entry_set&&view.iterator&&method.name=="next"&&signature=="()Ljava/lang/Object;") {
                    if (view.expected_structure!=backing.map->structure_revision())
                        runtime.raise("Ljava/util/ConcurrentModificationException;");
                    if (view.cursor>=backing.map->entries().size())runtime.raise("Ljava/util/NoSuchElementException;");
                    Object result;result.type=map_entry_type;result.map_entry=std::make_unique<MapEntryReference>();
                    *result.map_entry={view.map,view.cursor,view.expected_structure};
                    const auto id=allocate(std::move(result));
                    view.last=view.cursor++;
                    return Value::reference(id);
                }
                const MapCallbacks callbacks{[&](ObjectId key){return key_hash(key);},[&](ObjectId a,ObjectId b){return key_equal(a,b);}};
                if (const auto result=backing.map->invoke_values(runtime,view,method.name,signature,args,callbacks))return *result;
            }
        }
        if (!args.empty() && (map_view_class(type) || set_class(type) || type == "Ljava/util/Collection;" ||
                              type == "Ljava/lang/Iterable;" || type == "Ljava/util/Iterator;")) {
            auto &receiver = object(reference(args[0]));
            if (receiver.map_keys) {
                auto &keys = *receiver.map_keys;
                auto &backing = object(keys.map);
                if (!backing.map || (!backing.map->concurrent() && !keys.hash_set) ||
                    !backing.map->initialized())
                    fail("STATE", "Concurrent key view has no initialized backing map");
                if (!keys.iterator && method.name == "iterator" && signature == "()Ljava/util/Iterator;") {
                    Object result;
                    result.type = map_key_iterator_type;
                    result.map_keys = std::make_unique<MapKeys>();
                    result.map_keys->map = keys.map;
                    result.map_keys->iterator = true;
                    const auto entries = backing.map->entries();
                    result.map_keys->snapshot.reserve(entries.size());
                    for (const auto &entry : entries)
                        result.map_keys->snapshot.push_back(Value::reference(entry.key));
                    return Value::reference(allocate(std::move(result)));
                }
                const MapCallbacks callbacks{[&](ObjectId key) { return key_hash(key); },
                                             [&](ObjectId a, ObjectId b) { return key_equal(a, b); }};
                if (const auto result = backing.map->invoke_keys(
                        runtime, keys, method.name, signature, args,
                        {backing.bytes, metrics.heap_bytes, limits.heap_bytes, limits.array_length},
                        callbacks))
                    return *result;
            }
        }
        if (type == "Ljava/util/concurrent/CountDownLatch;") {
            auto &receiver=object(reference(args[0]));
            const auto *state=dynamic_cast<const CountDownLatchState *>(receiver.host_state.get());
            if(!state) fail("STATE", "CountDownLatch has no runtime-owned counter state");
            if(method.name=="<init>") {
                if(signature!="(I)V") fail("API_UNSUPPORTED", "CountDownLatch constructor signature is not implemented");
                if(state->initialized) fail("STATE", "CountDownLatch constructor invoked twice");
                const auto count=std::bit_cast<std::int32_t>(word(args[1]));
                if(count<0) runtime.raise("Ljava/lang/IllegalArgumentException;",u"count < 0");
                receiver.host_state=std::make_unique<CountDownLatchState>(count,true);
                return Value::nothing();
            }
            if(!state->initialized) fail("STATE", "CountDownLatch must be initialized before use");
            if(method.name=="getCount" && signature=="()J") return Value::wide(static_cast<std::uint64_t>(state->count));
            if(method.name=="countDown" && signature=="()V") {
                if(state->count>0) receiver.host_state=std::make_unique<CountDownLatchState>(state->count-1,true);
                return Value::nothing();
            }
            if(method.name=="await" && signature=="()V") {
                if(state->count>0) fail("THREAD_UNSUPPORTED", "Positive CountDownLatch.await requires guest parallel execution, which is not implemented");
                return Value::nothing();
            }
        }
        if (type == atomic_reference_type) {
            auto &receiver = object(reference(args[0]));
            if (receiver.atomic)
                if (const auto result = receiver.atomic->invoke(method.name, signature, args))
                    return *result;
        }
        if (type == atomic_boolean_type ||
            (type == "Ljava/lang/Object;" && method.name == "toString" && signature == "()Ljava/lang/String;" &&
             subtype(object(reference(args[0])).type,atomic_boolean_type))) {
            auto &receiver=object(reference(args[0]));
            if(receiver.atomic_integer)
                if(const auto result=receiver.atomic_integer->invoke(runtime,method.name,signature,args)) return *result;
        }
        if (type == atomic_long_type || (((type == number_type && method.name != "<init>") ||
             (type == "Ljava/lang/Object;" && virtual_dispatch && method.name == "toString" && signature == "()Ljava/lang/String;")) &&
             !args.empty() && object(reference(args[0])).atomic_long)) {
            auto &state = object(reference(args[0])).atomic_long;
            if (!state) fail("STATE", "AtomicLong lacks authenticated storage");
            if (const auto result = state->invoke(runtime, method.name, signature, args)) return *result;
        }
        if (type == atomic_integer_type || type == number_type) {
            auto &receiver = object(reference(args[0]));
            if (type == number_type && method.name == "<init>" && signature == "()V")
                return Value::nothing();
            if (receiver.atomic_integer &&
                (type == atomic_integer_type || method.name == "intValue" || method.name == "longValue" ||
                 method.name == "floatValue" || method.name == "doubleValue" || method.name == "toString"))
                if (const auto result =
                        receiver.atomic_integer->invoke(runtime, method.name, signature, args))
                    return *result;
        }
        if (type == "Ljava/lang/Object;" && method.name == "getClass" && signature == "()Ljava/lang/Class;")
            return Value::reference(runtime.class_object(object(reference(args[0])).type));
        if ((type == "Ljava/lang/ClassLoader;" || type == "Laether/dex/RuntimeClassLoader;") &&
            method.name == "loadClass" && signature == "(Ljava/lang/String;)Ljava/lang/Class;") {
            if(reference(args[0])!=loader_object || !loader_object)
                fail("CLASS_LOADER_UNSUPPORTED", "Class loading requires this runtime's canonical held class space");
            const auto name=runtime.string(reference(args[1]));
            const auto descriptor=binary_descriptor(name);
            if(!descriptor || descriptor->starts_with('[')) runtime.raise("Ljava/lang/ClassNotFoundException;",name);
            if(!resolve_class(*descriptor) && !core_type(*descriptor)) {
                const auto metadata=host ? provider_call([&] { return host->class_info(*descriptor); }) : std::nullopt;
                if(!metadata) {
                    if(descriptor->starts_with("Ljava/") || descriptor->starts_with("Ljavax/") ||
                       descriptor->starts_with("Landroid/") || descriptor->starts_with("Ldalvik/"))
                        fail("CLASS_UNSUPPORTED", "Platform class is not implemented: "+*descriptor);
                    runtime.raise("Ljava/lang/ClassNotFoundException;",name);
                }
                if(!metadata->bootstrap_class) fail("CLASS_LOADER_UNSUPPORTED", "Native class loader provenance is incomplete");
            }
            return Value::reference(runtime.class_object(*descriptor)); // Loading never initializes the class.
        }
        if(type=="Ljava/lang/Class;" && method.name=="getClassLoader" && signature=="()Ljava/lang/ClassLoader;") {
            auto represented=runtime.represented_class(reference(args[0]));
            while(represented.starts_with('[')) represented.remove_prefix(1);
            if(resolve_class(represented)) return Value::reference(runtime.class_loader());
            if(represented.size()==1 || core_type(represented)) return Value::reference(0);
            if(host) if(const auto metadata=provider_call([&] { return host->class_info(represented); });metadata && metadata->bootstrap_class)
                return Value::reference(0);
            fail("CLASS_LOADER_UNSUPPORTED", "Class loader provenance is incomplete for "+std::string(represented));
        }
        if (type == "Ljava/lang/Class;" && method.name == "getDeclaredField" &&
            signature == "(Ljava/lang/String;)Ljava/lang/reflect/Field;")
            return Value::reference(lookup_declared_field(args));
        if ((type == "Ljava/lang/reflect/AccessibleObject;" || type == "Ljava/lang/reflect/Executable;" ||
             type == "Ljava/lang/reflect/Field;" || type == "Ljava/lang/reflect/Method;") && !args.empty() &&
            ((method.name == "setAccessible" && signature == "(Z)V") ||
             (method.name == "isAccessible" && signature == "()Z"))) {
            auto &member=object(reference(args[0]));
            if(!member.reflected_field && !member.reflected_method)
                fail("REFERENCE","AccessibleObject has no authenticated supported member declaration");
            if(method.name=="setAccessible") {
                member.reflective_access_override=word(args[1])!=0;return Value::nothing();
            }
            // This is the wrapper's suppression flag, not a public-access test.
            return Value::word(member.reflective_access_override);
        }
        if (type == "Ljava/lang/reflect/Field;" && !args.empty()) {
            auto &field_object=object(reference(args[0]));
            if(field_object.reflected_field) {
                const auto &metadata=field_object.reflected_field->metadata;
                if(method.name=="get" && signature=="(Ljava/lang/Object;)Ljava/lang/Object;") return read_reflected_field(args);
                if(method.name=="set") fail("FIELD_UNSUPPORTED", "Reflected field writes are not implemented");
                if(method.name=="getName" && signature=="()Ljava/lang/String;")
                    return Value::reference(runtime.new_string(std::u16string(metadata.name.begin(),metadata.name.end())));
                if(method.name=="getType" && signature=="()Ljava/lang/Class;") return Value::reference(runtime.class_object(metadata.type));
                if(method.name=="getDeclaringClass" && signature=="()Ljava/lang/Class;") return Value::reference(runtime.class_object(metadata.owner));
                if(method.name=="getModifiers" && signature=="()I") return Value::word(metadata.flags & 0xffff);
            }
        }
        if (type == "Ljava/lang/Class;" && (method.name == "getMethod" || method.name=="getDeclaredMethod") &&
            signature == "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;")
            return Value::reference(lookup_public_method(args,method.name=="getDeclaredMethod"));
        if (type == "Ljava/lang/reflect/Method;") {
            const auto &state = object(reference(args[0])).reflected_method;
            if (!state) fail("REFERENCE", "Method object has no validated declaration");
            const auto &metadata = state->metadata;
            if (method.name == "invoke" && signature == "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;")
                return invoke_reflected_method(args);
            if (method.name == "getName" && signature == "()Ljava/lang/String;")
                return Value::reference(runtime.new_string(std::u16string(metadata.name.begin(), metadata.name.end())));
            if (method.name == "getDeclaringClass" && signature == "()Ljava/lang/Class;")
                return Value::reference(runtime.class_object(metadata.owner));
            if (method.name == "getReturnType" && signature == "()Ljava/lang/Class;")
                return Value::reference(runtime.class_object(metadata.return_type));
            if (method.name == "getModifiers" && signature == "()I") {
                if (state->provider) fail("API_UNSUPPORTED", "Reflected provider modifier metadata is incomplete");
                return Value::word(metadata.flags & 0xffff);
            }
        }
        if (type == "Ljava/lang/Class;" && method.name == "getName" && signature == "()Ljava/lang/String;")
            return Value::reference(
                runtime.new_string(binary_name(runtime.represented_class(reference(args[0])))));
        if (type == "Ljava/lang/Class;" && method.name == "forName" &&
            signature == "(Ljava/lang/String;)Ljava/lang/Class;") {
            const auto name = runtime.string(reference(args[0]));
            const auto descriptor = binary_descriptor(name);
            if (!descriptor)
                runtime.raise("Ljava/lang/ClassNotFoundException;", name);
            auto component = std::string_view(*descriptor);
            while (component.starts_with('['))
                component.remove_prefix(1);
            if (component.size() > 1 && !core_type(component) && !resolve_class(component) &&
                !(host && provider_call([&] { return host->class_info(component); }))) {
                // Missing app/library classes are lookup misses; unavailable
                // platform providers remain explicit compatibility failures.
                if (component.starts_with("Ljava/") || component.starts_with("Ljavax/") ||
                    component.starts_with("Landroid/") || component.starts_with("Ldalvik/"))
                    fail("CLASS_UNSUPPORTED",
                         "Reflective platform class is not implemented: " + std::string(component));
                runtime.raise("Ljava/lang/ClassNotFoundException;", name);
            }
            // Arrays load their component type but do not initialize it.
            if (!descriptor->starts_with('['))
                initialize(*descriptor);
            return Value::reference(runtime.class_object(*descriptor));
        }
        if (!args.empty() && (set_class(type) || type == "Ljava/util/AbstractCollection;" ||
                              type == "Ljava/util/Collection;" || type == "Ljava/lang/Iterable;")) {
            auto &receiver = object(reference(args[0]));
            if (receiver.synchronized_set && (type == "Ljava/util/Set;" || type == "Ljava/util/Collection;" ||
                                              type == "Ljava/lang/Iterable;")) {
                // The original interface method must go through virtual dispatch
                // so owned Set implementations keep their actual overrides.
                std::lock_guard lock(receiver.synchronized_set->mutex);
                std::vector<Value> delegated(args.begin(), args.end());
                delegated.front() = Value::reference(receiver.synchronized_set->backing);
                return runtime.invoke_virtual(index, delegated);
            }
            if (receiver.map) {
                if(method.name=="removeAll" && signature=="(Ljava/util/Collection;)Z" &&
                   (type==hash_set_type || type==linked_hash_set_type || type=="Ljava/util/AbstractSet;" ||
                    (virtual_dispatch && (type=="Ljava/util/AbstractCollection;" || type=="Ljava/util/Set;" || type=="Ljava/util/Collection;"))))
                    return inherited_set_remove_all(reference(args[0]),reference(args[1]));
                if(method.name=="addAll" && signature=="(Ljava/util/Collection;)Z" &&
                   (type==hash_set_type || type==linked_hash_set_type || type=="Ljava/util/AbstractSet;" ||
                    type=="Ljava/util/AbstractCollection;" ||
                    (virtual_dispatch && (type=="Ljava/util/Set;" || type=="Ljava/util/Collection;"))))
                    return inherited_set_add_all(reference(args[0]),reference(args[1]));
                if(type==linked_hash_set_type && method.name=="<init>" && signature=="(Ljava/util/Collection;)V") {
                    if(receiver.map->initialized())fail("STATE","Set constructor invoked twice");
                    // The Java copy constructor calls virtual addAll, whose inherited
                    // implementation calls virtual add. Do not bypass guest overrides.
                    auto destination_type=std::string_view(receiver.type);
                    for(unsigned depth=0;destination_type!=linked_hash_set_type;++depth) {
                        if(depth>=256)fail("CLASS_LIMIT","Set constructor hierarchy exceeds limit");
                        const auto *definition=resolve_class(destination_type);
                        if(!definition)fail("API_UNSUPPORTED","Set copy constructor requires inherited insertion semantics");
                        for(const auto candidate:definition->virtual_methods) {
                            const auto &declaration=image.methods.at(candidate);
                            const auto &descriptor=image.prototypes.at(declaration.prototype).descriptor;
                            if((declaration.name=="add" && descriptor=="(Ljava/lang/Object;)Z") ||
                               (declaration.name=="addAll" && descriptor=="(Ljava/util/Collection;)Z"))
                                fail("API_UNSUPPORTED","Set copy constructor with overridden add/addAll is not implemented");
                        }
                        if(definition->superclass==no_index)fail("API_UNSUPPORTED","Set copy constructor has no LinkedHashSet ancestor");
                        destination_type=image.types.at(definition->superclass);
                    }
                    const auto source=reference(args[1]);
                    if(!source)runtime.raise("Ljava/lang/NullPointerException;");
                    const MapCallbacks callbacks{[&](ObjectId key){return key_hash(key);},
                                                 [&](ObjectId a,ObjectId b){return key_equal(a,b);}};
                    const auto source_size=std::bit_cast<std::int32_t>(word(runtime.invoke_virtual_named(source,"size","()I")));
                    if(source_size<0)fail("COLLECTION_STATE","Collection reported a negative size");
                    const auto capacity=std::max<std::uint64_t>(11,static_cast<std::uint64_t>(source_size)*2);
                    if(capacity>limits.array_length)fail("SET_LIMIT","Collection copy capacity exceeds the managed element bound");
                    const std::array initial{args[0],Value::word(static_cast<std::uint32_t>(capacity))};
                    (void)receiver.map->invoke_hash_set(runtime,type,"<init>","(I)V",initial,
                        {receiver.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length},callbacks);
                    const auto iterator=reference(runtime.invoke_virtual_named(source,"iterator","()Ljava/util/Iterator;"));
                    if(!iterator)runtime.raise("Ljava/lang/NullPointerException;");
                    runtime.retain(iterator);
                    struct IteratorRoot {ManagedRuntime &runtime;ObjectId id;~IteratorRoot(){runtime.release(id);}} iterator_root{runtime,iterator};
                    std::size_t traversed=0;
                    while(word(runtime.invoke_virtual_named(iterator,"hasNext","()Z"))) {
                        if(traversed++>=limits.array_length)fail("SET_LIMIT","Collection copy traversal exceeds the managed element bound");
                        const auto element=runtime.invoke_virtual_named(iterator,"next","()Ljava/lang/Object;");
                        const auto id=reference(element);runtime.retain(id);
                        IteratorRoot element_root{runtime,id};
                        const std::array insertion{args[0],element};
                        (void)receiver.map->invoke_hash_set(runtime,type,"add","(Ljava/lang/Object;)Z",insertion,
                            {receiver.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length},callbacks);
                    }
                    return Value::nothing();
                }
                if (receiver.map->initialized() && method.name == "iterator" &&
                    signature == "()Ljava/util/Iterator;") {
                    Object result;
                    result.type = hash_set_iterator_type;
                    result.map_keys = std::make_unique<MapKeys>();
                    result.map_keys->map = reference(args[0]);
                    result.map_keys->iterator = true;
                    result.map_keys->hash_set = true;
                    result.map_keys->expected_revision = receiver.map->revision();
                    const auto entries = receiver.map->entries();
                    result.map_keys->snapshot.reserve(entries.size());
                    for (const auto &entry : entries)
                        result.map_keys->snapshot.push_back(Value::reference(entry.key));
                    return Value::reference(allocate(std::move(result)));
                }
                const MapCallbacks callbacks{[&](ObjectId key) { return key_hash(key); },
                                             [&](ObjectId a, ObjectId b) { return key_equal(a, b); }};
                if (const auto result = receiver.map->invoke_hash_set(
                        runtime, type, method.name, signature, args,
                        {receiver.bytes, metrics.heap_bytes, limits.heap_bytes, limits.array_length},
                        callbacks))
                    return *result;
            }
            if (receiver.set) {
                if (receiver.set->initialized() && method.name == "iterator" &&
                    signature == "()Ljava/util/Iterator;") {
                    Object result;
                    result.type = snapshot_iterator_type;
                    result.iterator = std::make_unique<SnapshotIterator>(receiver.set->references(), 0);
                    return Value::reference(allocate(std::move(result)));
                }
                if (const auto result = receiver.set->invoke(
                        runtime, type, method.name, signature, args,
                        {receiver.bytes, metrics.heap_bytes, limits.heap_bytes, limits.array_length},
                        [&](ObjectId a, ObjectId b) { return key_equal(a, b); }))
                    return *result;
            }
        }
        if (collection_class(type) && type != arrays_type) {
            auto &receiver = object(reference(args[0]));
            if(receiver.type==singleton_list_type)
                if(const auto result=singleton_list_call(reference(args[0]),method.name,signature,args))return *result;
            if (receiver.type == empty_list_type) {
                const bool iterator = method.name == "iterator" && signature == "()Ljava/util/Iterator;";
                const bool list_iterator = method.name == "listIterator" &&
                    (signature == "()Ljava/util/ListIterator;" || signature == "(I)Ljava/util/ListIterator;");
                if (iterator || list_iterator) {
                    if (args.size() == 2 && word(args[1]) != 0)
                        runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
                    Object result;result.type = empty_iterator_type;
                    return Value::reference(allocate(std::move(result)));
                }
                if (const auto result = invoke_empty_list(runtime, method.name, signature, args))
                    return *result;
            }
            if (receiver.type == empty_iterator_type)
                if (const auto result = invoke_empty_iterator(runtime, method.name, signature))
                    return *result;
            if(receiver.deque_iterator) {
                auto &backing=object(receiver.deque_iterator->backing);
                if(!backing.deque)fail("STATE","Deque iterator has no backing deque");
                if(const auto result=backing.deque->iterate(runtime,*receiver.deque_iterator,method.name,signature))return *result;
            }
            if(receiver.deque) {
                if((method.name=="iterator"||method.name=="descendingIterator")&&signature=="()Ljava/util/Iterator;") {
                    if(!receiver.deque->initialized())fail("STATE","Deque must be initialized before iteration");
                    Object result;result.type=deque_iterator_type;result.deque_iterator=std::make_unique<DequeIterator>();
                    const bool reverse=method.name=="descendingIterator";
                    *result.deque_iterator={reference(args[0]),reverse?receiver.deque->references().size():0,{},receiver.deque->revision(),reverse};
                    return Value::reference(allocate(std::move(result)));
                }
                if(const auto result=receiver.deque->invoke(runtime,method.name,signature,args,
                    {receiver.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length},
                    [&](ObjectId a,ObjectId b){return key_equal(a,b);}))return *result;
            }
            if(receiver.queue_iterator) {
                const auto queue=receiver.queue_iterator->backing;
                auto &backing=object(queue);
                if(!backing.fifo)fail("STATE", "Queue iterator has no runtime backing queue");
                const auto revision=backing.fifo->revision();
                try {
                    if(const auto result=backing.fifo->iterate(runtime,*receiver.queue_iterator,method.name,signature)) {
                        if(revision!=backing.fifo->revision())wake_queue_pools(queue);
                        return *result;
                    }
                } catch(...) {
                    const auto error=std::current_exception();
                    if(revision!=backing.fifo->revision())try{wake_queue_pools(queue);}catch(...){}
                    std::rethrow_exception(error);
                }
            }
            if (receiver.fifo) {
                if(method.name=="iterator" && signature=="()Ljava/util/Iterator;") {
                    if(!receiver.fifo->initialized())fail("STATE", "Queue must be initialized before iteration");
                    Object value;value.type=queue_iterator_type;value.queue_iterator=std::make_unique<QueueIterator>();
                    value.queue_iterator->backing=reference(args[0]);return Value::reference(allocate(std::move(value)));
                }
                if(const auto result=native_queue_call(reference(args[0]),type,method.name,signature,args))return *result;
            }
            if (receiver.type == array_iterator_type)
                if (const auto result =
                        invoke_array_iterator(runtime, receiver.elements, method.name, signature, args))
                    return *result;
            if (receiver.type == array_list_type) {
                if (receiver.elements.size() != 1 || receiver.elements[0].kind != ValueKind::reference)
                    fail("STATE", "Array-list view has no backing array");
                const auto array = receiver.elements[0].bits;
                const bool iterator = method.name == "iterator" && signature == "()Ljava/util/Iterator;";
                const bool list_iterator =
                    method.name == "listIterator" &&
                    (signature == "()Ljava/util/ListIterator;" || signature == "(I)Ljava/util/ListIterator;");
                if (iterator || list_iterator) {
                    const auto position = args.size() == 2 ? std::bit_cast<std::int32_t>(word(args[1])) : 0;
                    if (position < 0 || static_cast<std::size_t>(position) > runtime.array_length(array))
                        runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
                    Object result;
                    result.type = array_iterator_type;
                    result.elements = {Value::reference(array),
                                       Value::word(static_cast<std::uint32_t>(position)),
                                       Value::word(UINT32_MAX)};
                    return Value::reference(allocate(std::move(result)));
                }
                if (const auto result =
                        invoke_array_view(runtime, array, method.name, signature, args,
                                          [&](ObjectId a, ObjectId b) { return key_equal(a, b); }))
                    return *result;
            }
            if (receiver.live_iterator) {
                auto &backing=object(receiver.live_iterator->backing());
                if (!backing.list)fail("STATE","Live iterator has no backing list");
                if (const auto result=receiver.live_iterator->invoke(runtime,*backing.list,method.name,signature,args,
                    {backing.bytes,metrics.heap_bytes,limits.heap_bytes,limits.array_length}))return *result;
            }
            if (receiver.iterator)
                if (const auto result = receiver.iterator->invoke(runtime, type, method.name, signature))
                    return *result;
            if (receiver.list) {
                const bool collection_owner=type==copy_list_type || type=="Ljava/util/ArrayList;" || type=="Ljava/util/List;" ||
                    type=="Ljava/util/Collection;" || type=="Ljava/util/AbstractList;" || type=="Ljava/util/AbstractCollection;";
                if(collection_owner && !receiver.list->snapshots() && (type=="Ljava/util/ArrayList;" || virtual_dispatch) &&
                   method.name=="contains" && signature=="(Ljava/lang/Object;)Z")
                    return array_list_contains(reference(args[0]),reference(args[1]));
                if(collection_owner && (type==copy_list_type || type=="Ljava/util/ArrayList;" || virtual_dispatch) && method.name=="toArray" && signature=="()[Ljava/lang/Object;")return list_array(reference(args[0]));
                if(collection_owner && method.name=="addAll" && signature=="(Ljava/util/Collection;)Z" &&
                   ((receiver.list->snapshots() && (type==copy_list_type || virtual_dispatch)) ||
                    (!receiver.list->snapshots() && (type=="Ljava/util/ArrayList;" || virtual_dispatch))))
                    return list_add_all(reference(args[0]),reference(args[1]));
                const bool iterator = method.name == "iterator" && signature == "()Ljava/util/Iterator;";
                const bool list_iterator =
                    method.name == "listIterator" &&
                    (signature == "()Ljava/util/ListIterator;" || signature == "(I)Ljava/util/ListIterator;");
                const bool factory_owner =
                    type == copy_list_type || type == "Ljava/util/ArrayList;" || type == "Ljava/util/AbstractList;" || type == "Ljava/util/List;" ||
                    (iterator && (type == "Ljava/util/AbstractCollection;" || type == "Ljava/util/Collection;" || type == "Ljava/lang/Iterable;"));
                if (factory_owner && (iterator || list_iterator) && !receiver.list->initialized())
                    fail("STATE","List must be initialized before iterator creation");
                if (!receiver.list->snapshots() && factory_owner && (iterator || list_iterator)) {
                    if (receiver.type!="Ljava/util/ArrayList;")
                        fail("API_UNSUPPORTED","ArrayList subclass iterators require virtual mutation support");
                    const auto position=signature[1]=='I'?std::bit_cast<std::int32_t>(word(args[1])):0;
                    if (position<0||static_cast<std::size_t>(position)>receiver.list->references().size())
                        runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
                    Object result;result.type=list_iterator?live_list_iterator_type:live_iterator_type;
                    result.live_iterator=std::make_unique<LiveListIterator>(reference(args[0]),static_cast<std::size_t>(position),
                        receiver.list->revision(),list_iterator);
                    return Value::reference(allocate(std::move(result)));
                }
                if (receiver.list->snapshots() && factory_owner && (iterator || list_iterator)) {
                    const auto position =
                        signature[1] == 'I' ? std::bit_cast<std::int32_t>(word(args[1])) : 0;
                    const auto values = receiver.list->references();
                    if (position < 0 || static_cast<std::size_t>(position) > values.size())
                        runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
                    Object result;
                    result.type = snapshot_iterator_type;
                    result.iterator =
                        std::make_unique<SnapshotIterator>(values, static_cast<std::size_t>(position));
                    return Value::reference(allocate(std::move(result)));
                }
                const auto value = receiver.list->invoke(
                    runtime, type, method.name, signature, args,
                    {receiver.bytes, metrics.heap_bytes, limits.heap_bytes, limits.array_length});
                if (value)
                    return *value;
            }
        }
        if ((type.starts_with('[') || type == "Ljava/lang/Object;") && method.name == "clone" &&
            signature == "()Ljava/lang/Object;" && object(reference(args[0])).type.starts_with('[')) {
            // The invoke frame roots the source and all referenced elements
            // while allocate enforces the ordinary heap/object limits and may
            // collect. Preserve the concrete array type and shallow identity.
            const auto &source = object(reference(args[0]));
            Object copy;
            copy.type = source.type;
            copy.elements = source.elements;
            return Value::reference(allocate(std::move(copy)));
        }
        if (type == "Ljava/lang/Object;" && method.name == "<init>" && signature == "()V")
            return Value::nothing();
        if (core_type(type) && subtype(type, "Ljava/lang/Throwable;") && method.name == "getCause" &&
            signature == "()Ljava/lang/Throwable;")
            return Value::reference(object(reference(args[0])).cause);
        if (core_type(type) && subtype(type, "Ljava/lang/Throwable;") && method.name == "<init>" &&
            signature == "()V") {
            replace_text(reference(args[0]), {});
            return Value::nothing();
        }
        if(type=="Ljava/lang/String;" && method.name=="valueOf") {
            if(signature=="(I)Ljava/lang/String;") {
                const auto decimal=std::to_string(std::bit_cast<std::int32_t>(word(args[0])));
                return Value::reference(runtime.new_string(std::u16string(decimal.begin(),decimal.end())));
            }
            fail("API_UNSUPPORTED",type+"."+method.name+signature+" is not implemented");
        }
        if(type=="Ljava/lang/String;" && method.name=="concat" && signature=="(Ljava/lang/String;)Ljava/lang/String;")
            return string_concat(reference(args[0]),reference(args[1]));
        if(type=="Ljava/lang/String;" && method.name=="contains" && signature=="(Ljava/lang/CharSequence;)Z")
            return string_contains(reference(args[0]),reference(args[1]));
        if(type=="Ljava/lang/String;" && method.name=="split" &&
           (signature=="(Ljava/lang/String;)[Ljava/lang/String;" ||
            signature=="(Ljava/lang/String;I)[Ljava/lang/String;"))
            return string_split(reference(args[0]),reference(args[1]),
                args.size()==3?std::bit_cast<std::int32_t>(word(args[2])):0);
        if (type == "Ljava/lang/String;" || type == "Ljava/lang/CharSequence;" ||
            type == "Ljava/lang/StringBuilder;") {
            const auto id = reference(args[0]);
            const auto text = runtime.char_sequence(id);
            if (type == "Ljava/lang/String;") {
                if ((method.name == "startsWith" &&
                     (signature == "(Ljava/lang/String;)Z" || signature == "(Ljava/lang/String;I)Z")) ||
                    (method.name == "endsWith" && signature == "(Ljava/lang/String;)Z")) {
                    const auto other = runtime.string(reference(args[1]));
                    if (method.name == "endsWith")
                        return Value::word(text.ends_with(other));
                    const auto offset = args.size() == 3 ? std::bit_cast<std::int32_t>(word(args[2])) : 0;
                    if (offset < 0 || static_cast<std::size_t>(offset) > text.size())
                        return Value::word(0);
                    return Value::word(text.substr(static_cast<std::size_t>(offset)).starts_with(other));
                }
                if (method.name == "substring" &&
                    (signature == "(I)Ljava/lang/String;" || signature == "(II)Ljava/lang/String;")) {
                    const auto begin = std::bit_cast<std::int32_t>(word(args[1]));
                    const auto end = args.size() == 3 ? std::bit_cast<std::int32_t>(word(args[2]))
                                                     : static_cast<std::int32_t>(text.size());
                    if (begin < 0 || end < begin || static_cast<std::size_t>(end) > text.size())
                        runtime.raise("Ljava/lang/StringIndexOutOfBoundsException;");
                    if (begin == 0 && static_cast<std::size_t>(end) == text.size())
                        return Value::reference(id);
                    return Value::reference(runtime.new_string(text.substr(static_cast<std::size_t>(begin),
                                                                         static_cast<std::size_t>(end - begin))));
                }
                if (method.name == "indexOf" &&
                    (signature == "(Ljava/lang/String;)I" || signature == "(Ljava/lang/String;I)I")) {
                    const auto needle=runtime.string(reference(args[1])); // Null remains a Java NPE, including empty haystacks.
                    const auto from=args.size()==3 ? std::bit_cast<std::int32_t>(word(args[2])) : 0;
                    return substring_index(text,needle,from);
                }
                if (method.name == "lastIndexOf" && (signature == "(I)I" || signature == "(II)I")) {
                    const auto character = std::bit_cast<std::int32_t>(word(args[1]));
                    const auto from = args.size() == 3 ? std::bit_cast<std::int32_t>(word(args[2]))
                                                      : static_cast<std::int32_t>(text.size());
                    if (from < 0 || character < 0 || character > 0x10ffff || text.empty())
                        return Value::word(0xffffffffu);
                    const auto start = std::min(static_cast<std::size_t>(from), text.size() - 1);
                    for (std::size_t cursor = start + 1; cursor; ) {
                        const auto at = --cursor;
                        bool match = false;
                        if (character <= 0xffff)
                            match = text[at] == character;
                        else if (at + 1 < text.size()) {
                            const auto supplementary = static_cast<std::uint32_t>(character - 0x10000);
                            match = text[at] == 0xd800 + (supplementary >> 10) &&
                                    text[at + 1] == 0xdc00 + (supplementary & 0x3ff);
                        }
                        if (match)
                            return Value::word(static_cast<std::uint32_t>(at));
                    }
                    return Value::word(0xffffffffu);
                }
                if(method.name=="isEmpty" && signature=="()Z")return Value::word(text.empty());
                if (method.name == "hashCode" && signature == "()I")
                    return Value::word(string_hash(text));
                if (method.name == "equals" && signature == "(Ljava/lang/Object;)Z") {
                    const auto other = reference(args[1]);
                    return Value::word(other && object(other).type == "Ljava/lang/String;" &&
                                       text == object(other).text);
                }
            }
            if (method.name == "length" && signature == "()I")
                return Value::word(static_cast<std::uint32_t>(text.size()));
            if (method.name == "charAt" && signature == "(I)C") {
                const auto at = std::bit_cast<std::int32_t>(word(args[1]));
                if (at < 0 || static_cast<std::size_t>(at) >= text.size())
                    runtime.raise("Ljava/lang/StringIndexOutOfBoundsException;");
                return Value::word(text[static_cast<std::size_t>(at)]);
            }
            if (method.name == "toString" && signature == "()Ljava/lang/String;")
                return Value::reference(object(id).type == "Ljava/lang/String;" ? id
                                                                                : runtime.new_string(text));
            if (type == "Ljava/lang/StringBuilder;") {
                if (method.name == "<init>" && signature == "()V") {
                    replace_text(id, {});
                    return Value::nothing();
                }
                if (method.name == "<init>" && signature == "(Ljava/lang/String;)V") {
                    replace_text(id, std::u16string(runtime.string(reference(args[1]))));
                    return Value::nothing();
                }
                if (method.name == "append") {
                    std::u16string appended;
                    if(signature=="(C)Ljava/lang/StringBuilder;") {
                        // A Java char is one UTF-16 code unit, including NUL
                        // and isolated surrogates; it is never decimal text.
                        appended.push_back(static_cast<char16_t>(word(args[1]) & 0xffffu));
                    } else if (signature == "(I)Ljava/lang/StringBuilder;") {
                        const auto decimal = std::to_string(std::bit_cast<std::int32_t>(word(args[1])));
                        appended.assign(decimal.begin(), decimal.end());
                    } else if (signature == "(Ljava/lang/String;)Ljava/lang/StringBuilder;" ||
                               signature == "(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;") {
                        const auto other = reference(args[1]);
                        appended = other ? runtime.char_sequence(other) : u"null";
                    } else
                        fail("API_UNSUPPORTED", type + "." + method.name + signature + " is not implemented");
                    if (appended.size() > limits.array_length - text.size())
                        fail("STRING_LIMIT", "StringBuilder append exceeds length limit");
                    replace_text(id, std::u16string(text) + appended);
                    return Value::reference(id);
                }
            }
        }
        if(type=="Ljava/lang/System;" && method.name=="getProperty" &&
           (signature=="(Ljava/lang/String;)Ljava/lang/String;" ||
            signature=="(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;")) {
            const auto key=runtime.string(reference(args[0])); // Null key is a Java NPE.
            if(key.empty())runtime.raise("Ljava/lang/IllegalArgumentException;",u"key can't be empty");
            // Immutable initial compatibility profile, separate from host
            // environment/registry values. Android documents java.version as 0;
            // this does not advertise a Java SE or Android OS release.
            if(key==u"java.version") {
                if(!java_version_property)java_version_property=runtime.new_string(u"0");
                return Value::reference(java_version_property);
            }
            return args.size()==2?args[1]:Value::reference(0);
        }
        if (type == "Ljava/lang/System;" && method.name == "getSecurityManager" &&
            signature == "()Ljava/lang/SecurityManager;") {
            // No in-VM Java SecurityManager is installed. LPAC and capability
            // enforcement are independent host boundaries, never changed here.
            return Value::reference(0);
        }
        if(type==android_process_type && method.name=="getStartUptimeMillis" && signature=="()J") {
            if(!host)fail("TIME_UNAVAILABLE","Process.getStartUptimeMillis requires a bound startup clock provider");
            return provider_call([&]{return host->invoke(runtime,index,args);});
        }
        if(type=="Ljava/lang/System;" && method.name=="nanoTime" && signature=="()J") {
            if(!host)fail("TIME_UNAVAILABLE","System.nanoTime requires a broker-backed uptime provider");
            return provider_call([&]{return host->invoke(runtime,index,args);});
        }
        if (type == "Ljava/lang/System;" && method.name == "currentTimeMillis" && signature == "()J") {
            if (!host)
                fail("TIME_UNAVAILABLE", "System.currentTimeMillis requires a broker-backed wall-clock provider");
            return provider_call([&] { return host->invoke(runtime, index, args); });
        }
        if (type == "Ljava/lang/System;" && method.name == "loadLibrary" &&
            signature == "(Ljava/lang/String;)V") {
            if (!native)
                fail("NATIVE_UNAVAILABLE", "System.loadLibrary requires an attached native interface");
            if(background() && (native_context_depth || !native->supports_background()))fail("TASK_NATIVE_UNSUPPORTED","Background native loading requires per-context JNI/CPU state");
            NonYielding native_barrier(current_context());
            report_progress(RuntimeProgressStage::native_enter,index);
            ProgressEnd native_progress{*this,RuntimeProgressStage::native_exit,index,0};
            native->load_library(runtime, runtime.string(reference(args[0])));
            return Value::nothing();
        }
        if(host && type=="Landroid/text/TextUtils;" && method.name=="equals" &&
            signature=="(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z")
            // isEmpty is an exact core callback gateway; the existing equals
            // implementation remains inside its ordinary provider boundary.
            return provider_call([&]{return host->invoke(runtime,index,args);});
        if (host && !core_type(type))
            return provider_call([&] { return host->invoke(runtime, index, args); });
        auto message = type + "." + method.name + signature + " is not implemented";
        if (collection_class(type) && !args.empty() && !method_is_static(index))
            message += " receiver=" + object(reference(args[0])).type.substr(0,160);
        fail("API_UNSUPPORTED", message);
    }
    std::optional<Index> default_target(Index index, std::vector<std::string_view> roots) const {
        const auto &method = image.methods.at(index);
        std::set<std::string_view> seen;
        std::vector<Index> candidates;
        std::size_t work = 0;
        const auto step = [&] {
            if (++work > 262144)
                fail("CLASS_LIMIT", "Interface method search exceeds its work budget");
        };
        while (!roots.empty()) {
            step();
            const auto type = roots.back();
            roots.pop_back();
            if (!seen.insert(type).second)
                continue;
            if (seen.size() > 65536)
                fail("CLASS_LIMIT", "Interface method search exceeds its class budget");
            const auto *definition = resolve_class(type);
            if (!definition)
                continue;
            if (definition->flags & 0x200) {
                for (const auto candidate : definition->virtual_methods) {
                    step();
                    const auto &m = image.methods.at(candidate);
                    if (m.name == method.name && image.prototypes.at(m.prototype).descriptor ==
                                                     image.prototypes.at(method.prototype).descriptor)
                        candidates.push_back(candidate);
                }
            } else if (definition->superclass != no_index)
                roots.push_back(image.types.at(definition->superclass));
            for (const auto parent : definition->interfaces)
                roots.push_back(image.types.at(parent));
        }
        // A declaration in a more specific interface suppresses its ancestor,
        // including an abstract redeclaration of an inherited default method.
        // Visit the union of their strict ancestors once, avoiding pairwise
        // subtype walks over an attacker-controlled interface graph.
        std::set<Index> ancestors;
        std::vector<Index> pending;
        for (const auto candidate : candidates) {
            const auto *declaring = resolve_class(image.types.at(image.methods.at(candidate).owner));
            pending.insert(pending.end(), declaring->interfaces.begin(), declaring->interfaces.end());
        }
        while (!pending.empty()) {
            step();
            const auto type = pending.back();
            pending.pop_back();
            if (!ancestors.insert(type).second)
                continue;
            if (const auto *declaring = resolve_class(image.types.at(type)))
                pending.insert(pending.end(), declaring->interfaces.begin(), declaring->interfaces.end());
        }
        std::optional<Index> selected;
        for (const auto candidate : candidates) {
            const auto &m = image.methods.at(candidate);
            if (!ancestors.contains(m.owner) && !(m.flags & (0x400 | 8)) && !m.direct && m.code) {
                if (selected)
                    fail("INVOKE_KIND", "Conflicting maximally specific interface default methods");
                selected = candidate;
            }
        }
        if (!selected && !candidates.empty())
            fail("METHOD_NOT_FOUND", "Interface method has no concrete maximally specific implementation");
        return selected;
    }
    Index virtual_target(Index index, ObjectId receiver) const {
        const auto &method = image.methods.at(index);
        auto type = std::string_view(object(receiver).type);
        if (method_is_static(index) || (method.declared && method.direct) ||
            !subtype(type, image.types.at(method.owner)))
            fail("INVOKE_KIND", "Virtual/interface call has an incompatible method or receiver");
        for (unsigned depth = 0; depth < 256; ++depth) {
            const auto *definition = resolve_class(type);
            if (!definition)
                break;
            for (const auto candidate : definition->virtual_methods) {
                const auto &m = image.methods.at(candidate);
                if (m.name == method.name && image.prototypes.at(m.prototype).descriptor ==
                                                 image.prototypes.at(method.prototype).descriptor)
                    return candidate;
            }
            if (definition->superclass == no_index)
                break;
            type = image.types.at(definition->superclass);
        }
        if (const auto target = default_target(index, {object(receiver).type}))
            return *target;
        return index;
    }
    Index super_target(Index caller, Index index, ObjectId receiver) const {
        const auto &method = image.methods.at(index);
        const auto &caller_type = image.types.at(image.methods.at(caller).owner);
        const auto *definition = resolve_class(caller_type);
        const auto &caller_code = image.methods.at(caller).code;
        const auto version =
            caller_code && caller_code->references ? caller_code->references->version : image.version;
        if (is_interface(image.types.at(method.owner))) {
            if (version < 37 || !definition || method_is_static(index) ||
                (method.declared && method.direct) || !subtype(object(receiver).type, caller_type))
                fail("INVOKE_KIND", "Interface invoke-super requires DEX 037 and a compatible receiver");
            // Interface.super is resolved from the named superinterface,
            // not from unrelated interfaces implemented by the receiver.
            if (!subtype(caller_type, image.types.at(method.owner)))
                fail("INVOKE_KIND", "Interface invoke-super target is not in the caller's hierarchy");
            if (const auto target = default_target(index, {image.types.at(method.owner)}))
                return *target;
            fail("METHOD_NOT_FOUND", "Interface invoke-super has no unambiguous concrete default");
        }
        if (!definition || definition->superclass == no_index || method_is_static(index) ||
            (method.declared && method.direct) || is_interface(image.types.at(method.owner)) ||
            !subtype(object(receiver).type, caller_type))
            fail("INVOKE_KIND", "invoke-super requires a superclass method and compatible receiver");
        auto type = std::string_view(image.types.at(definition->superclass));
        if (!subtype(type, image.types.at(method.owner)))
            fail("INVOKE_KIND", "invoke-super target is not in the caller's superclass hierarchy");
        for (unsigned depth = 0; depth < 256; ++depth) {
            definition = resolve_class(type);
            if (!definition)
                return index;
            for (const auto candidate : definition->virtual_methods) {
                const auto &m = image.methods.at(candidate);
                if (m.name == method.name && image.prototypes.at(m.prototype).descriptor ==
                                                 image.prototypes.at(method.prototype).descriptor)
                    return candidate;
            }
            if (definition->superclass == no_index)
                break;
            type = image.types.at(definition->superclass);
        }
        fail("METHOD_NOT_FOUND", "invoke-super could not resolve the superclass implementation");
    }
    Value binary(unsigned op, Value left, Value right) {
        if (op <= 0x9a) {
            const auto a = word(left), b = word(right);
            const auto sa = std::bit_cast<std::int32_t>(a), sb = std::bit_cast<std::int32_t>(b);
            std::uint32_t value = 0;
            switch (op) {
            case 0x90:
                value = a + b;
                break;
            case 0x91:
                value = a - b;
                break;
            case 0x92:
                value = a * b;
                break;
            case 0x93:
            case 0x94:
                if (!b)
                    runtime.raise("Ljava/lang/ArithmeticException;");
                if (sa == std::numeric_limits<std::int32_t>::min() && sb == -1)
                    value = op == 0x93 ? a : 0;
                else
                    value = static_cast<std::uint32_t>(op == 0x93 ? sa / sb : sa % sb);
                break;
            case 0x95:
                value = a & b;
                break;
            case 0x96:
                value = a | b;
                break;
            case 0x97:
                value = a ^ b;
                break;
            case 0x98:
                value = a << (b & 31);
                break;
            case 0x99:
                value = static_cast<std::uint32_t>(sa >> (b & 31));
                break;
            case 0x9a:
                value = a >> (b & 31);
                break;
            default:
                fail("OPCODE_UNSUPPORTED", "Invalid integer arithmetic opcode");
            }
            return Value::word(value);
        }
        if (op <= 0xa5) {
            const auto a = wide(left), b = op >= 0xa3 ? word(right) : wide(right);
            const auto sa = std::bit_cast<std::int64_t>(a), sb = std::bit_cast<std::int64_t>(b);
            std::uint64_t value = 0;
            switch (op) {
            case 0x9b:
                value = a + b;
                break;
            case 0x9c:
                value = a - b;
                break;
            case 0x9d:
                value = a * b;
                break;
            case 0x9e:
            case 0x9f:
                if (!b)
                    runtime.raise("Ljava/lang/ArithmeticException;");
                if (sa == std::numeric_limits<std::int64_t>::min() && sb == -1)
                    value = op == 0x9e ? a : 0;
                else
                    value = static_cast<std::uint64_t>(op == 0x9e ? sa / sb : sa % sb);
                break;
            case 0xa0:
                value = a & b;
                break;
            case 0xa1:
                value = a | b;
                break;
            case 0xa2:
                value = a ^ b;
                break;
            case 0xa3:
                value = a << (b & 63);
                break;
            case 0xa4:
                value = static_cast<std::uint64_t>(sa >> (b & 63));
                break;
            case 0xa5:
                value = a >> (b & 63);
                break;
            default:
                fail("OPCODE_UNSUPPORTED", "Invalid long arithmetic opcode");
            }
            return Value::wide(value);
        }
        if (op <= 0xaa) {
            const auto a = std::bit_cast<float>(word(left)), b = std::bit_cast<float>(word(right));
            float value = 0;
            switch (op) {
            case 0xa6:
                value = a + b;
                break;
            case 0xa7:
                value = a - b;
                break;
            case 0xa8:
                value = a * b;
                break;
            case 0xa9:
                value = a / b;
                break;
            case 0xaa:
                value = std::fmod(a, b);
                break;
            }
            return Value::word(std::bit_cast<std::uint32_t>(value));
        }
        const auto a = std::bit_cast<double>(wide(left)), b = std::bit_cast<double>(wide(right));
        double value = 0;
        switch (op) {
        case 0xab:
            value = a + b;
            break;
        case 0xac:
            value = a - b;
            break;
        case 0xad:
            value = a * b;
            break;
        case 0xae:
            value = a / b;
            break;
        case 0xaf:
            value = std::fmod(a, b);
            break;
        default:
            fail("OPCODE_UNSUPPORTED", "Invalid double arithmetic opcode");
        }
        return Value::wide(std::bit_cast<std::uint64_t>(value));
    }
    Value execute(Frame &frame, const VerifiedCode &code) {
        report_progress(RuntimeProgressStage::managed_enter,frame.method,frame.pc);
        const auto &method = image.methods.at(frame.method);
        for (;;) {
            safepoint();
            if (!scheduled_task() && main_callback_inflight) {
                if (!main_callback_work_remaining)
                    fail("BUDGET", "Main callback batch instruction budget exhausted");
                --main_callback_work_remaining;
            }
            if(scheduled_task()) {
                if (!task_work_remaining) fail("BUDGET", "Managed task batch instruction budget exhausted");
                --task_work_remaining;
            }
            if (!current_context().remaining)
                fail("BUDGET", "Managed instruction budget exhausted");
            --current_context().remaining;
            ++metrics.instructions;
            if((metrics.instructions&1023U)==0)report_progress(RuntimeProgressStage::managed_sample,frame.method,frame.pc);
            if (frame.pc >= code.at.size() || code.at[frame.pc] == no_index)
                fail("CONTROL_FLOW", "Invalid instruction pointer");
            const auto &ins = code.instructions[code.at[frame.pc]];
            const auto op = ins.opcode;
            const auto get = [&](std::uint32_t r) { return frame.get(r); };
            const auto put = [&](Value v) { frame.put(ins.a, v); };
            auto next = ins.next;
            if (op < 0x0a || op > 0x0c)
                frame.result = {};
            if (op != 0x0d)
                frame.caught = 0;
            try {
                if (!op) { /* nop */
                } else if (op <= 9) {
                    const auto v = get(ins.b);
                    if (op <= 3)
                        put(Value::word(word(v)));
                    else if (op <= 6)
                        put(Value::wide(wide(v)));
                    else
                        put(Value::reference(reference(v)));
                } else if (op >= 0x0a && op <= 0x0c) {
                    if (frame.result.kind == ValueKind::empty)
                        fail("RESULT", "No result available for move-result");
                    put(frame.result);
                    frame.result = {};
                } else if (op == 0x0d) {
                    if (!frame.caught)
                        fail("EXCEPTION", "No caught exception at handler entry");
                    put(Value::reference(frame.caught));
                    frame.caught = 0;
                } else if (op >= 0x0e && op <= 0x11) {
                    return typed(op == 0x0e ? Value::nothing() : get(ins.a),
                                 image.types.at(image.prototypes.at(method.prototype).return_type));
                } else if (op <= 0x19) {
                    put(op >= 0x16 ? Value::wide(ins.literal)
                                   : Value::word(static_cast<std::uint32_t>(ins.literal)));
                } else if (op == 0x1a || op == 0x1b)
                    put(Value::reference(intern(ins.index)));
                else if (op == 0x1c)
                    put(Value::reference(runtime.class_object(image.types.at(ins.index))));
                else if (op == 0x1d || op == 0x1e) {
                    const auto id = reference(get(ins.a));
                    (void)object(id);
                    if (op == 0x1d) {
                        if (frame.monitor_count == frame.monitors.size())
                            fail("MONITOR_LIMIT", "Monitor nesting exceeds 32 acquisitions per invocation");
                        check_monitor_available(id);frame.monitors[frame.monitor_count++] = id;
                    } else {
                        auto at = frame.monitor_count;
                        while (at && frame.monitors[at - 1] != id)
                            --at;
                        if (!at)
                            runtime.raise("Ljava/lang/IllegalMonitorStateException;");
                        std::move(frame.monitors.begin() + at,
                                  frame.monitors.begin() + frame.monitor_count,
                                  frame.monitors.begin() + at - 1);
                        frame.monitors[--frame.monitor_count] = 0;
                    }
                } else if (op == 0x1f) {
                    const auto id = reference(get(ins.a));
                    if (!runtime.assignable(id, image.types.at(ins.index)))
                        runtime.raise("Ljava/lang/ClassCastException;");
                    put(Value::reference(id));
                } else if (op == 0x20) {
                    const auto id = reference(get(ins.b));
                    put(Value::word(id && runtime.assignable(id, image.types.at(ins.index))));
                } else if (op == 0x21)
                    put(Value::word(static_cast<std::uint32_t>(runtime.array_length(reference(get(ins.b))))));
                else if (op == 0x22)
                    put(Value::reference(runtime.new_object(image.types.at(ins.index))));
                else if (op == 0x23)
                    put(Value::reference(runtime.new_array(image.types.at(ins.index),
                                                           std::bit_cast<std::int32_t>(word(get(ins.b))))));
                else if (op == 0x24 || op == 0x25) {
                    const auto id = runtime.new_array(image.types.at(ins.index),
                                                      static_cast<std::int32_t>(ins.arguments.size()));
                    frame.result = Value::reference(id);
                    for (std::size_t n = 0; n < ins.arguments.size(); ++n)
                        runtime.array_set(id, static_cast<std::int32_t>(n), get(ins.arguments[n]));
                } else if (op == 0x27) {
                    const auto id = reference(get(ins.a));
                    if (!id)
                        runtime.raise("Ljava/lang/NullPointerException;");
                    if (!runtime.assignable(id, "Ljava/lang/Throwable;"))
                        fail("VALUE_TYPE", "throw operand is not a Throwable");
                    ++metrics.exceptions;
                    throw JavaException(id);
                } else if (op >= 0x28 && op <= 0x2a)
                    next = static_cast<std::uint32_t>(std::int64_t(ins.pc) + ins.branch);
                else if (op == 0x2b) {
                    const auto key = std::bit_cast<std::int32_t>(word(get(ins.a)));
                    const auto at = std::int64_t(key) - ins.switch_first;
                    if (at >= 0 && static_cast<std::uint64_t>(at) < ins.switch_targets.size())
                        next = ins.switch_targets[static_cast<std::size_t>(at)];
                } else if (op == 0x2c) {
                    const auto key = std::bit_cast<std::int32_t>(word(get(ins.a)));
                    const auto found = std::lower_bound(ins.switch_keys.begin(), ins.switch_keys.end(), key);
                    if (found != ins.switch_keys.end() && *found == key)
                        next = ins.switch_targets[static_cast<std::size_t>(found - ins.switch_keys.begin())];
                } else if (op >= 0x2d && op <= 0x31) {
                    std::int32_t compare = 0;
                    if (op == 0x31) {
                        const auto a = std::bit_cast<std::int64_t>(wide(get(ins.b))),
                                   b = std::bit_cast<std::int64_t>(wide(get(ins.c)));
                        compare = a < b ? -1 : (a == b ? 0 : 1);
                    } else {
                        const auto a = op < 0x2f ? double(std::bit_cast<float>(word(get(ins.b))))
                                                 : std::bit_cast<double>(wide(get(ins.b)));
                        const auto b = op < 0x2f ? double(std::bit_cast<float>(word(get(ins.c))))
                                                 : std::bit_cast<double>(wide(get(ins.c)));
                        compare = std::isnan(a) || std::isnan(b) ? ((op == 0x2d || op == 0x2f) ? -1 : 1)
                                                                 : (a < b ? -1 : (a == b ? 0 : 1));
                    }
                    put(Value::word(static_cast<std::uint32_t>(compare)));
                } else if (op >= 0x32 && op <= 0x3d) {
                    const auto a = get(ins.a), b = op < 0x38 ? get(ins.b) : Value::word(0);
                    const auto cond = (op - 0x32) % 6;
                    bool yes = false;
                    if (cond <= 1 && (a.kind == ValueKind::reference || b.kind == ValueKind::reference)) {
                        const auto equal = reference(a) == reference(b);
                        yes = cond == 0 ? equal : !equal;
                    } else {
                        const auto left = std::bit_cast<std::int32_t>(word(a)),
                                   right = std::bit_cast<std::int32_t>(word(b));
                        switch (cond) {
                        case 0:
                            yes = left == right;
                            break;
                        case 1:
                            yes = left != right;
                            break;
                        case 2:
                            yes = left < right;
                            break;
                        case 3:
                            yes = left >= right;
                            break;
                        case 4:
                            yes = left > right;
                            break;
                        case 5:
                            yes = left <= right;
                            break;
                        }
                    }
                    if (yes)
                        next = static_cast<std::uint32_t>(std::int64_t(ins.pc) + ins.branch);
                } else if (op >= 0x44 && op <= 0x51) {
                    const auto id = reference(get(ins.b));
                    const auto at = std::bit_cast<std::int32_t>(word(get(ins.c)));
                    const auto &type = object(id).type;
                    if (type.front() != '[')
                        fail("VALUE_TYPE", "Array opcode requires array object");
                    const auto element = std::string_view(type).substr(1);
                    const auto category = unsigned(op - 0x44) % 7;
                    const auto expected = reference_type(element) ? 2u : (type_words(element) == 2 ? 1u : 0u);
                    if ((category == 0 && element != "I" && element != "F") ||
                        (category < 3 && category != expected) || (category == 3 && element != "Z") ||
                        (category == 4 && element != "B") || (category == 5 && element != "C") ||
                        (category == 6 && element != "S"))
                        fail("VALUE_TYPE", "Array opcode disagrees with component type");
                    if (op < 0x4b)
                        put(runtime.array_get(id, at));
                    else
                        runtime.array_set(id, at, get(ins.a));
                } else if (op >= 0x52 && op <= 0x6d) {
                    const auto &field = image.fields.at(ins.index);
                    if (loader)
                        provider_call([&] { ensure_class(image.types.at(field.owner)); });
                    const bool time_constant = op == 0x62 && image.types.at(field.owner) == time_unit_type &&
                        image.types.at(field.type) == time_unit_type && time_unit_index(field.name).has_value();
                    const auto field_name = image.types.at(field.owner) + "." + field.name + ":" + image.types.at(field.type);
                    if (!field.declared && op == 0x54) {
                        put(read_public_provider_field(ins.index,frame,ins.b));
                        frame.pc=next;
                        continue;
                    }
                    if (!field.declared && !time_constant && !(op >= 0x60 && op < 0x67))
                        fail("FIELD_UNSUPPORTED", "External field is not implemented: " + field_name);
                    if (!field.declared && op >= 0x60 && op < 0x67) {
                        const auto &descriptor = image.types.at(field.type);
                        const auto category = unsigned(op - 0x60);
                        if ((category == 0 && descriptor != "I" && descriptor != "F") ||
                            (category == 1 && descriptor != "J" && descriptor != "D") ||
                            (category == 2 && !reference_type(descriptor)) ||
                            (category == 3 && descriptor != "Z") || (category == 4 && descriptor != "B") ||
                            (category == 5 && descriptor != "C") || (category == 6 && descriptor != "S"))
                            fail("VALUE_TYPE", "Static field opcode disagrees with field type: " + field_name);
                    }
                    const auto &type = image.types.at(field.type);
                    if (op >= 0x60) {
                        if (op < 0x67)
                            put(runtime.get_static(ins.index));
                        else
                            runtime.set_static(ins.index, get(ins.a));
                    } else {
                        auto &instance = object(reference(get(ins.b)));
                        const auto it = instance.fields.find(ins.index);
                        if (it == instance.fields.end())
                            fail("FIELD", "Field does not belong to this object");
                        if (op < 0x59)
                            put(it->second);
                        else
                            it->second = typed(get(ins.a), type);
                    }
                } else if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
                    const auto stat = op == 0x71 || op == 0x77;
                    const auto &target = image.methods.at(ins.index);
                    const auto &proto = image.prototypes.at(target.prototype);
                    std::vector<Value> args;
                    std::size_t at = 0;
                    if (!stat)
                        args.push_back(Value::reference(reference(get(ins.arguments[at++]))));
                    for (const auto type : proto.parameters) {
                        auto argument=get(ins.arguments[at]);
                        if((image.types.at(target.owner)==atomic_boolean_type || image.types.at(target.owner)==boolean_type) && image.types.at(type)=="Z")
                            argument=Value::word(word(argument)!=0);
                        args.push_back(typed(argument,image.types.at(type)));
                        at += type_words(image.types[type]);
                    }
                    if (method_is_static(ins.index) != stat)
                        fail("INVOKE_KIND", "Invoke opcode disagrees with method staticness");
                    const bool interface_call = op == 0x72 || op == 0x78;
                    const bool virtual_call = op == 0x6e || op == 0x74;
                    if ((interface_call || virtual_call) &&
                        interface_call != is_interface(image.types.at(target.owner)))
                        fail("INVOKE_KIND", "Invoke opcode disagrees with class/interface method owner");
                    if ((op == 0x70 || op == 0x76) && target.declared && !target.direct)
                        fail("INVOKE_KIND", "invoke-direct requires a direct method");
                    auto dispatch = ins.index;
                    if (op == 0x6e || op == 0x74 || op == 0x72 || op == 0x78)
                        dispatch = virtual_target(ins.index, reference(args[0]));
                    else if (op == 0x6f || op == 0x75)
                        dispatch = super_target(frame.method, ins.index, reference(args[0]));
                    frame.result = runtime.invoke_resolved(dispatch, args, virtual_call || interface_call);
                } else if (op >= 0x8d && op <= 0x8f) {
                    // Narrow the low bits, then explicitly extend the signed
                    // byte/short or unsigned Java char back to a full DEX word.
                    // Read before writing so overlapping source/destination work.
                    const auto bits=word(get(ins.b));
                    if(op==0x8e)put(Value::word(bits & 0xffffu));
                    else if(op==0x8d)
                        put(Value::word(static_cast<std::uint32_t>(static_cast<std::int32_t>(
                            std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(bits))))));
                    else
                        put(Value::word(static_cast<std::uint32_t>(static_cast<std::int32_t>(
                            std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(bits))))));
                } else if (op == 0x87) {
                    put(Value::word(float_int_bits(word(get(ins.b)))));
                } else if (op == 0x82) {
                    put(Value::word(int_float_bits(word(get(ins.b)))));
                } else if (op == 0x84) {
                    put(Value::word(static_cast<std::uint32_t>(wide(get(ins.b)))));
                } else if (op == 0x81) {
                    const auto value = std::int64_t(std::bit_cast<std::int32_t>(word(get(ins.b))));
                    put(Value::wide(static_cast<std::uint64_t>(value)));
                } else if (op >= 0x90 && op <= 0xcf) {
                    const auto binary_op = op >= 0xb0 ? op - 0x20u : op;
                    put(binary(binary_op, get(op >= 0xb0 ? ins.a : ins.b), get(op >= 0xb0 ? ins.b : ins.c)));
                } else if (op >= 0xd0 && op <= 0xe2) {
                    const auto operation = op < 0xd8 ? op - 0xd0 : op - 0xd8;
                    const auto literal = Value::word(static_cast<std::uint32_t>(ins.literal));
                    put(operation == 1 ? binary(0x91, literal, get(ins.b))
                                       : binary(0x90 + operation, get(ins.b), literal));
                } else
                    fail("OPCODE_UNSUPPORTED", "Missing opcode executor");
            } catch (const JavaException &error) {
                execution_checkpoint();
                bool handled = false;
                for (const auto &block : method.code->tries) {
                    const auto exception_pc = op == 0x1e ? ins.next : ins.pc;
                    if (exception_pc < block.start || exception_pc - block.start >= block.count)
                        continue;
                    for (const auto &handler : block.handlers) {
                        if (handler.type == no_index ||
                            runtime.assignable(error.object, image.types.at(handler.type))) {
                            frame.caught = error.object;
                            frame.result = {};
                            next = handler.target;
                            handled = true;
                            break;
                        }
                    }
                    break;
                }
                if (!handled)
                    throw;
            } catch (const DexError &error) {
                execution_checkpoint();
                throw DexError(error.code, image.types.at(method.owner) + "." + method.name +
                                               " pc=" + std::to_string(ins.pc) + ": " + error.what());
            }
            frame.pc = next;
        }
    }
    Value invoke(Index index, std::span<const Value> arguments, bool virtual_dispatch) {
        check_thread();
        execution_checkpoint();
        if (index >= image.methods.size())
            fail("METHOD_NOT_FOUND", "Method index outside DEX table");
        if (frame_count() >= limits.frames)
            fail("CALL_DEPTH", "Shared managed frame limit exceeded");
        const auto &method = image.methods[index];
        const auto &prototype = image.prototypes[method.prototype];
        const auto &type = image.types[method.owner];
        const bool stat = method_is_static(index);
        if (arguments.size() != prototype.parameters.size() + (stat ? 0 : 1))
            fail("SIGNATURE", "Wrong argument count for " + type + "." + method.name + prototype.descriptor);
        Frame frame;
        frame.method = index;
        std::size_t at = 0;
        if (!stat) {
            const auto receiver = reference(arguments[at++]);
            (void)object(receiver);
            frame.arguments.push_back(typed(Value::reference(receiver), type));
        }
        for (const auto parameter : prototype.parameters) {
            auto argument=arguments[at++];
            if((type==atomic_boolean_type || type==boolean_type) && image.types[parameter]=="Z")
                argument=Value::word(word(argument)!=0);
            frame.arguments.push_back(typed(argument,image.types[parameter]));
        }
        current_context().frames.push_back(&frame);
        struct Pop {
            ExecutionContext &owner_context;
            ~Pop() { owner_context.frames.pop_back(); }
        } pop{current_context()};
        metrics.maximum_frames = std::max(metrics.maximum_frames, frame_count());
        if (stat && method.name != "<clinit>")
            initialize(type);
        Value result;
        // DEX declaration metadata (0x20000) has no execution effect. Managed
        // synchronized bodies carry real monitor opcodes. The distinct 0x20
        // native implicit-monitor contract remains unsupported, never skipped.
        if (method.declared && (method.flags & 0x20))
            fail("SYNCHRONIZATION_UNSUPPORTED", "Implicit synchronized method monitors are not implemented");
        if (!method.declared)
            result = core(index, frame.arguments, virtual_dispatch);
        else if (method.flags & 0x100) {
            if(background() && (native_context_depth || !native || !native->supports_background()))fail("TASK_NATIVE_UNSUPPORTED","Background managed native calls require per-context JNI/CPU state");
            NonYielding barrier(current_context());
            if (!native)
                fail("NATIVE_UNAVAILABLE", "Native method requires an attached native interface");
            ++metrics.native_calls;
            report_progress(RuntimeProgressStage::native_enter,index,frame.pc);
            ProgressEnd progress{*this,RuntimeProgressStage::native_exit,index,frame.pc};
            result = native->invoke(runtime, index, frame.arguments);
        } else {
            if (!method.code)
                fail("ABSTRACT_METHOD", "Method has no executable body");
            if (!verified.contains(index))
                verified.emplace(index, verify(image, index));
            ++metrics.managed_calls;
            frame.registers.resize(method.code->registers);
            auto reg = std::uint32_t(method.code->registers - method.code->incoming);
            for (auto value : frame.arguments) {
                frame.put(reg, value);
                reg += value.kind == ValueKind::wide ? 2 : 1;
            }
            try {
                result = execute(frame, verified.at(index));
            } catch (const JavaException &) {
                if (frame.monitor_count)
                    runtime.raise("Ljava/lang/IllegalMonitorStateException;");
                throw;
            }
            if (frame.monitor_count)
                runtime.raise("Ljava/lang/IllegalMonitorStateException;");
        }
        frame.result=result; // Root newly returned references through subtype/loader callbacks.
        execution_checkpoint();
        return typed(result, image.types[prototype.return_type]);
    }
};
ManagedRuntime::ManagedRuntime(DexImage image, RuntimeLimits limits)
    : impl_(std::make_unique<Impl>(*this, std::move(image), limits)) {}
ManagedRuntime::ManagedRuntime(std::shared_ptr<ClassSource> source, RuntimeLimits limits)
    : impl_(std::make_unique<Impl>(*this, DexImage{}, limits, std::move(source))) {}
ManagedRuntime::~ManagedRuntime() = default;
void ManagedRuntime::set_progress_sink(RuntimeProgressSink *sink) {
    auto &p=*impl_;p.check_thread(true);
    if (sink && !sink->prepare_native_stack())
        fail("PROGRESS_STACK", "Cannot prepare bounded native fault diagnostics on owner stack");
    p.progress_sink=sink;
}
void ManagedRuntime::set_native_interface(NativeInterface *interface) {
    impl_->check_thread(interface == nullptr);
    if (!impl_->current_context().frames.empty() || impl_->active_tasks())
        fail("STATE", "Cannot replace native interface while execution or managed tasks are active");
    impl_->native = interface;
}
void ManagedRuntime::set_host_interface(HostInterface *interface) {
    impl_->check_thread(interface == nullptr);
    if (!impl_->current_context().frames.empty() || impl_->active_tasks())
        fail("STATE", "Cannot replace host interface while execution or managed tasks are active");
    if(impl_->host_generation==std::numeric_limits<std::uint64_t>::max())fail("STATE","Host provider binding generation exhausted");
    ++impl_->host_generation;
    impl_->host = interface;
}
const DexImage &ManagedRuntime::image() const noexcept { return impl_->image; }
const Class *ManagedRuntime::class_definition(std::string_view descriptor) const {
    return impl_->resolve_class(descriptor);
}
Index ManagedRuntime::resolve_method(std::string_view owner, std::string_view name,
                                     std::string_view signature) const {
    (void)impl_->resolve_class(owner);
    return impl_->image.method(owner, name, signature);
}
const RuntimeMetrics &ManagedRuntime::metrics() const noexcept { return impl_->metrics; }
Value ManagedRuntime::invoke(Index method, std::span<const Value> arguments) {
    return invoke_resolved(method, arguments, false);
}
Value ManagedRuntime::invoke_resolved(Index method, std::span<const Value> arguments, bool virtual_dispatch) {
    auto &p = *impl_;
    p.check_thread(true);p.execution_checkpoint();
    p.check_thread();
    const bool outer = !p.current_context().invocations;
    if (outer) {
        p.current_context().remaining = p.limits.instructions;
        p.current_context().last_result = {};
        p.current_context().last_exception = 0;
    }
    ++p.current_context().invocations;
    struct End {
        ExecutionContext &owner_context;
        ~End() { --owner_context.invocations; }
    } end{p.current_context()};
    try {
        const auto result = p.invoke(method, arguments, virtual_dispatch);
        if (outer)
            p.current_context().last_result = result;
        return result;
    } catch (const JavaException &error) {
        p.execution_checkpoint();
        p.current_context().last_exception = error.object;
        throw;
    } catch(...) {
        p.failure_checkpoint();throw;
    }
}
Value ManagedRuntime::invoke_static(std::string_view owner, std::string_view name, std::string_view signature,
                                    std::span<const Value> arguments) {
    return invoke(lookup(owner, name, signature, true), arguments);
}
Value ManagedRuntime::invoke_virtual(Index method, std::span<const Value> arguments) {
    impl_->check_thread();
    if (arguments.empty())
        fail("SIGNATURE", "Virtual call requires a receiver");
    return invoke_resolved(impl_->virtual_target(method, reference(arguments[0])), arguments, true);
}
Value ManagedRuntime::invoke_virtual_named(ObjectId receiver, std::string_view name,
                                           std::string_view signature, std::span<const Value> arguments) {
    auto &p = *impl_;
    p.check_thread(true);p.execution_checkpoint();
    p.check_thread();
    auto &context = p.current_context();
    const bool outer = !context.invocations;
    if (outer) {
        context.remaining = p.limits.instructions;
        context.last_result = {};
        context.last_exception = 0;
    }
    ++context.invocations;
    struct End { ExecutionContext &context; ~End() { --context.invocations; } } end{context};
    try {
        if (!receiver) raise("Ljava/lang/NullPointerException;");
        const auto result = p.call_virtual_named(receiver, name, signature, arguments);
        if (outer) context.last_result = result;
        return result;
    } catch (const JavaException &error) {
        p.execution_checkpoint();
        context.last_exception = error.object;
        throw;
    } catch(...) {
        p.failure_checkpoint();throw;
    }
}
Index ManagedRuntime::lookup(std::string_view owner, std::string_view name, std::string_view signature,
                             bool is_static) const {
    impl_->check_thread();
    impl_->known(owner);
    const auto index = impl_->image.method(owner, name, signature);
    const auto actual = impl_->method_is_static(index);
    if (actual != is_static)
        fail("SIGNATURE", "Method lookup static/instance mismatch");
    return index;
}
void ManagedRuntime::initialize(std::string_view descriptor) { impl_->initialize(descriptor); }
ObjectId ManagedRuntime::new_object(std::string_view type) {
    auto &p = *impl_;
    p.initialize(type);
    if (type.empty() || type.front() != 'L' || type == "Ljava/lang/String;" || type == "Ljava/lang/Class;")
        fail("ALLOCATION_UNSUPPORTED", "Use the typed string/class/array allocator");
    const auto host_class = p.host ? p.provider_call([&] { return p.host->class_info(type); }) : std::nullopt;
    const auto async=async_task_class(type);
    const auto stream=stream_class(type);
    const auto empty=empty_map_class(type);
    const auto uuid=uuid_class(type);
    const auto boolean=boolean_class(type);
    const auto future=future_class(type);
    const auto pool = thread_pool_class(type);
    const auto policy = execution_policy_class(type);
    const auto collection = collection_class(type);
    const auto map = map_class(type);
    const auto set = set_class(type);
    const auto enumeration = enum_class(type);
    const auto reference_info = reference_class(type);
    const auto atomic_info = atomic_class(type);
    const auto literal=literal_metadata_class(type);
    if (type == "Ljava/lang/CharSequence;" || type == "Ljava/lang/Runnable;" || type == "Ljava/lang/reflect/Type;" ||
        (host_class && (host_class->is_abstract || host_class->is_interface)) ||
        (async && (async->is_abstract || async->is_interface)) ||
        (stream && (stream->is_abstract || stream->is_interface)) ||
        (empty && (empty->is_abstract || empty->is_interface)) ||
        (uuid && (uuid->is_abstract || uuid->is_interface)) ||
        (boolean && (boolean->is_abstract || boolean->is_interface)) ||
        (future && (future->is_abstract || future->is_interface)) ||
        (pool && (pool->is_abstract || pool->is_interface)) ||
        (policy && (policy->is_abstract || policy->is_interface)) ||
        (collection && (collection->is_abstract || collection->is_interface)) ||
        (map && (map->is_abstract || map->is_interface)) ||
        (set && (set->is_abstract || set->is_interface)) ||
        (enumeration && (enumeration->is_abstract || enumeration->is_interface)) ||
        (reference_info && (reference_info->is_abstract || reference_info->is_interface)) ||
        (atomic_info && (atomic_info->is_abstract || atomic_info->is_interface)) ||
        (literal && (literal->is_abstract || literal->is_interface)))
        fail("ALLOCATION", "Cannot instantiate abstract class or interface");
    Object result;
    result.type = type;
    if (type == snapshot_iterator_type)
        fail("ALLOCATION_UNSUPPORTED", "Snapshot iterators require a collection factory");
    if (type == field_updater_implementation_type)
        fail("ALLOCATION_UNSUPPORTED", "Field updaters require a validated factory");
    for (unsigned depth = 0; depth < 256; ++depth) {
        if(type==print_stream_type || type=="Ljava/io/FilterOutputStream;")
            fail("ALLOCATION_UNSUPPORTED","Output stream construction is unsupported; use canonical System streams");
        if(type==map_backed_set_type)
            fail("ALLOCATION_UNSUPPORTED","Map-backed sets require their validated factory");
        if(synchronized_list_class(type))
            fail("ALLOCATION_UNSUPPORTED","Synchronized list views require their validated collection factory");
        if(unmodifiable_class(type))
            fail("ALLOCATION_UNSUPPORTED","Unmodifiable views require their validated collection factory");
        if(literal_metadata_class(type))
            fail("ALLOCATION_UNSUPPORTED",std::string(type)+" has class metadata only; storage and methods are not implemented");
        if(type=="Ljava/util/BitSet;")
            fail("ALLOCATION_UNSUPPORTED","BitSet class metadata is available; BitSet storage and methods are not implemented");
        if(type=="Ljava/lang/Void;")
            fail("ALLOCATION_UNSUPPORTED","Void is a final non-instantiable primitive Class holder");
        if (type == pool_worker_type || type == queue_iterator_type || async_internal_type(type) ||
            type==async_status_type || type==android_process_type || type==android_binder_type || type=="Landroid/text/TextUtils;")
            fail("ALLOCATION_UNSUPPORTED", "Internal/static SDK ancestry cannot be constructed by guest code");
        if(type==async_task_type)result.async_task=std::make_unique<AsyncTaskState>();
        if (type == "Ljava/lang/Math;")
            fail("ALLOCATION_UNSUPPORTED", "Math is a static utility class");
        if (type == "Ljava/lang/Runtime;" || type == "Ldalvik/system/VMRuntime;")
            fail("ALLOCATION_UNSUPPORTED", "Runtime objects require getRuntime");
        if (type == "Ljava/lang/Thread;")
            result.thread = std::make_unique<ThreadState>();
        if (type == "Ljava/lang/ThreadGroup;")
            fail("ALLOCATION_UNSUPPORTED", "Guest ThreadGroup creation is not implemented; use the owner group");
        if (type == "Ljava/lang/ClassLoader;" || type == "Laether/dex/RuntimeClassLoader;")
            fail("ALLOCATION_UNSUPPORTED", "ClassLoader objects require the canonical runtime class space");
        if (type == "Ljava/lang/reflect/Method;" || type == "Ljava/lang/reflect/Field;" ||
            type == "Ljava/lang/reflect/Executable;" || type == "Ljava/lang/reflect/AccessibleObject;")
            fail("ALLOCATION_UNSUPPORTED", "Reflection objects require validated lookup");
        if (type == synchronized_map_type)
            fail("ALLOCATION_UNSUPPORTED", "Synchronized maps require the Collections factory");
        if (type == collections_utility_type || type == synchronized_set_type ||
            type == synchronized_collection_type)
            fail("ALLOCATION_UNSUPPORTED", "Synchronized set wrappers require the Collections factory");
        if (array_view_class(type))
            fail("ALLOCATION_UNSUPPORTED", "Array utility views and iterators require the asList factory");
        if (map_view_class(type))
            fail("ALLOCATION_UNSUPPORTED", "Concurrent map views and iterators require a map factory");
        if(type==deque_iterator_type)fail("ALLOCATION_UNSUPPORTED","Deque iterators require a factory");
        if(type==array_deque_type)result.deque=std::make_unique<ManagedDeque>();
        if (type == live_iterator_type || type == live_list_iterator_type)
            fail("ALLOCATION_UNSUPPORTED", "Live list iterators require a backing-list factory");
        if(type=="Ljava/util/function/Supplier;")fail("ALLOCATION","Cannot instantiate Supplier interface");
        if(type=="Ljava/util/regex/MatchResult;")fail("ALLOCATION","Cannot instantiate regex interface");
        if(type==pattern_type || type==matcher_type)fail("ALLOCATION_UNSUPPORTED","Pattern and Matcher require authenticated factories");
        if(type==empty_map_type || type==empty_set_type || type==empty_map_iterator_type)
            fail("ALLOCATION_UNSUPPORTED","Immutable empty map/set objects require their canonical factory");
        if (type == empty_list_type || type == empty_iterator_type || type == singleton_list_type)
            fail("ALLOCATION_UNSUPPORTED", "Immutable empty lists and iterators require their factories");
        if (type == default_thread_factory_type)
            fail("ALLOCATION_UNSUPPORTED", "Default thread factories require an executor factory");
        if(type==future_task_type)result.future=std::make_unique<FutureState>();
        if (type == thread_pool_type)
            result.pool = std::make_unique<ThreadPoolState>();
        if (type == abort_policy_type)
            result.abort_policy = std::make_unique<AbortPolicy>();
        if (type == concurrent_queue_type || type == blocking_queue_type || type==synchronous_queue_type)
            result.fifo = std::make_unique<ManagedQueue>(type != concurrent_queue_type,type==synchronous_queue_type);
        if (type == "Ljava/util/ArrayList;" || type == copy_list_type)
            result.list = std::make_unique<ManagedList>(type == copy_list_type);
        if (type == "Ljava/util/concurrent/CountDownLatch;")
            result.host_state=std::make_unique<CountDownLatchState>();
        if (type == atomic_reference_type)
            result.atomic = std::make_unique<AtomicReference>();
        if (type == atomic_boolean_type)
            result.atomic_integer = std::make_unique<AtomicInteger>(true);
        if (type == atomic_integer_type)
            result.atomic_integer = std::make_unique<AtomicInteger>();
        if (type == atomic_long_type)
            result.atomic_long = std::make_unique<AtomicLong>();
        if(!result.stream) {
            using Kind=ManagedStream::Kind;
            if(type==input_stream_type)result.stream=std::make_unique<ManagedStream>(Kind::input);
            else if(type==file_input_stream_type)result.stream=std::make_unique<ManagedStream>(Kind::file);
            else if(type==byte_input_stream_type)result.stream=std::make_unique<ManagedStream>(Kind::bytes);
            else if(type==reader_type)result.stream=std::make_unique<ManagedStream>(Kind::reader);
            else if(type==string_reader_type)result.stream=std::make_unique<ManagedStream>(Kind::string);
            else if(type==input_reader_type)result.stream=std::make_unique<ManagedStream>(Kind::decoder);
            else if(type==buffered_reader_type)result.stream=std::make_unique<ManagedStream>(Kind::buffered);
        }
        if(type==uuid_type) {
            if(result.type!=type)fail("ALLOCATION_UNSUPPORTED","UUID is final and cannot be subclassed");
            result.uuid=std::make_unique<ManagedUuid>();
        }
        if(type==random_type)result.random=std::make_unique<ManagedRandom>();
        if(type==thread_local_type)result.thread_local_key=std::make_unique<ManagedThreadLocal>();
        if(type==long_type || type==short_type) {
            if(result.type!=type)fail("ALLOCATION_UNSUPPORTED","Integral wrappers are final and cannot be subclassed");
            result.integral=std::make_unique<ManagedIntegral>(type==long_type);
        }
        if(type==float_type || type==double_type) {
            if(result.type!=type)fail("ALLOCATION_UNSUPPORTED","Floating wrappers are final and cannot be subclassed");
            result.floating=std::make_unique<ManagedFloating>(type==double_type);
        }
        if(type==byte_type) {
            if(result.type!=type)fail("ALLOCATION_UNSUPPORTED","Byte is final and cannot be subclassed");
            result.byte=std::make_unique<ManagedByte>();
        }
        if(type==boolean_type) {
            if(result.type!=type)fail("ALLOCATION_UNSUPPORTED","Boolean is final and cannot be subclassed");
            result.boolean=std::make_unique<ManagedBoolean>();
        }
        if (type == integer_type) {
            if (result.type != type)
                fail("ALLOCATION_UNSUPPORTED", "Integer is final and cannot be subclassed");
            result.integer = std::make_unique<ManagedInteger>();
        }
        if (type == weak_map_type || type == hash_map_type)
            result.map = std::make_unique<ManagedMap>(type == weak_map_type);
        if (type == concurrent_map_type)
            result.map = std::make_unique<ManagedMap>(false, false, true);
        if (type == hash_set_type || type == linked_hash_set_type)
            result.map = std::make_unique<ManagedMap>(false, type == linked_hash_set_type);
        if (type == linked_map_type) {
            if (result.type != type)
                fail("ALLOCATION_UNSUPPORTED", "LinkedHashMap subclasses require eviction-policy dispatch");
            result.map = std::make_unique<ManagedMap>(false, true);
        }
        if (type == copy_set_type)
            result.set = std::make_unique<ManagedSet>();
        if (type == enum_type)
            result.enumeration = std::make_unique<ManagedEnum>();
        if (type == weak_reference_type)
            result.weak = std::make_unique<WeakReference>();
        if (type == reference_queue_type)
            result.queue = std::make_unique<ReferenceQueue>();
        const auto *definition = p.resolve_class(type);
        if (!definition)
            break;
        if (!depth && (definition->flags & (0x200 | 0x400)))
            fail("ALLOCATION", "Cannot instantiate abstract class or interface");
        for (const auto index : definition->instance_fields)
            result.fields[index] = default_value(p.image.types.at(p.image.fields.at(index).type));
        if (definition->superclass == no_index)
            break;
        type = p.image.types.at(definition->superclass);
    }
    return p.allocate(std::move(result));
}
host::PriorityResult ManagedRuntime::thread_priority(std::optional<std::int32_t> nice) {auto &p=*impl_;p.check_thread();return p.priority(nice);}
int ManagedRuntime::thread_priority_baseline() {auto &p=*impl_;p.check_thread();return p.priority_baseline();}
void ManagedRuntime::bind_process_state(std::shared_ptr<ProcessState> state) {
    auto &p=*impl_;p.check_thread(true);
    if(!state)fail("PROCESS_STATE","Missing shared process state");
    p.execution_checkpoint();
    if(p.process_bound && p.process!=state)fail("PROCESS_STATE","Cannot replace the app process state");
    if(p.scheduler)p.scheduler->bind_process_state(state);
    p.process=std::move(state);
    p.process_bound=true;
    p.execution_checkpoint();
}
std::shared_ptr<ProcessState> ManagedRuntime::process_state() const {
    impl_->check_thread(true);return impl_->process;
}
[[noreturn]] void ManagedRuntime::exit_current_thread(std::uint64_t value) {
    auto &p=*impl_;p.check_thread(true);p.execution_checkpoint();
    if(!p.background())fail("THREAD_EXIT_UNSUPPORTED","Exiting the root managed thread requires a process lifecycle model");
    auto &context=p.current_context();
    if(!context.thread_exit)context.thread_exit=value;
    throw ThreadExit{*context.thread_exit};
}
void ManagedRuntime::run_native_thread(const std::function<void()> &entry,const host::PriorityService &priority) {
    auto &p=*impl_;p.check_thread();
    p.execution_checkpoint();
    if(!entry || p.native_context_depth==p.native_contexts.size())fail("NATIVE_THREAD_LIMIT","Native context nesting exhausted");
    auto &parent=p.current_context();ExecutionContext child;child.native_priority=priority?&priority:nullptr;
    child.remaining=parent.invocations?parent.remaining:p.limits.instructions;
    child.invocations=1;child.barriers=1;const auto initial=child.remaining;
    p.native_cpu_unattributed=true;
    p.native_context_tokens[p.native_context_depth]=Scheduler::execution_token();
    p.native_contexts[p.native_context_depth++]=&child;
    struct Restore {
        Impl &p;ExecutionContext &parent,&child;std::uint64_t initial;
        ~Restore(){
            p.discard_native_context(child);
            p.end_native_thread(child);
            --p.native_context_depth;p.native_contexts[p.native_context_depth]=nullptr;
            if(parent.invocations){const auto spent=initial-child.remaining;parent.remaining=spent>=parent.remaining?0:parent.remaining-spent;}
        }
    } restore{p,parent,child,initial};
    try {
        try {entry();}catch(...) {
            // A cleanup failure outranks this child's already latched pthread exit.
            // Process termination remains authoritative; ordinary paths keep the
            // existing sticky-exit checkpoint and never resume the dying context.
            if(child.native_finalization_failure) {
                p.process->checkpoint();std::rethrow_exception(child.native_finalization_failure);
            }
            p.failure_checkpoint();
            throw;
        }
        p.execution_checkpoint();
    } catch(const JavaException &error) {
        // The child's traced roots disappear in Restore. Transfer the actual
        // propagated throwable before retirement so its caller can catch/collect
        // without the exception's opaque ObjectId becoming an unrooted reference.
        parent.last_exception=error.object;
        throw;
    }
}
void ManagedRuntime::run_thread_finalizers(const std::function<void()> &entry) {
    auto &p=*impl_;p.check_thread();p.process->checkpoint();
    auto &context=p.current_context();
    if(!entry || !p.background() || context.native_finalization_started || context.cancellation_requested)
        fail("THREAD_FINALIZATION_STATE","Finalizers require one active owned background context and cannot repeat");
    context.native_finalization_started=true;
    context.native_finalizing_exit=context.thread_exit;
    context.native_finalizing=true;
    // Managed callbacks during cleanup belong to the original invocation budget,
    // even though its top-level DEX body has already unwound.
    ++context.invocations;
    struct Restore {
        ExecutionContext &context;
        ~Restore(){--context.invocations;context.native_finalizing=false;context.native_finalizing_exit.reset();}
    } restore{context};
    NonYielding barrier(context);
    try {entry();p.execution_checkpoint();}
    catch(const JavaException &error) {
        context.last_exception=error.object;
        context.native_finalization_failure=std::current_exception();
        p.process->checkpoint();throw;
    } catch(...) {
        context.native_finalization_failure=std::current_exception();
        p.process->checkpoint();throw;
    }
}
std::uint64_t ManagedRuntime::thread_instruction_budget() const {
    auto &p=*impl_;p.check_thread(true);p.process->checkpoint();
    if(p.current_context().cancellation_requested)fail("TASK_CANCELLED","Cancelled context cannot admit native work");
    auto remaining=p.current_context().remaining;
    if(p.scheduled_task())remaining=std::min(remaining,p.task_work_remaining);
    else if(p.main_callback_inflight)remaining=std::min(remaining,p.main_callback_work_remaining);
    return remaining;
}
void ManagedRuntime::charge_thread_instructions(std::uint64_t instructions) {
    auto &p=*impl_;p.check_thread(true);p.process->checkpoint();
    auto &context=p.current_context();
    if(instructions>thread_instruction_budget())fail("BUDGET","Native instructions exceed the remaining logical thread allowance");
    context.remaining-=instructions;
    if(p.scheduled_task())p.task_work_remaining-=instructions;
    else if(p.main_callback_inflight)p.main_callback_work_remaining-=instructions;
}
bool ManagedRuntime::detach_native_thread() {
    auto &p=*impl_;p.check_thread();if(!p.native_context_depth)return false;
    auto &context=p.current_context();if(!context.frames.empty() || context.invocations!=1)return false;
    p.end_native_thread(context);
    context.last_result={};context.last_exception=0;context.interrupted=false;return true;
}
bool ManagedRuntime::hidden_api_exempt(std::u16string_view member)const {
    auto &p=*impl_;p.check_thread();
    return std::any_of(p.hidden_api_exemptions.begin(),p.hidden_api_exemptions.end(),[&](const auto &prefix){return member.starts_with(prefix);});
}
bool ManagedRuntime::hidden_api_access_allowed(std::u16string_view member)const {
    impl_->check_thread();(void)member;
    // Aether currently uses Disabled enforcement, matching the existing open
    // supported-platform inventory. Exemptions do not create implementations.
    return true;
}
bool ManagedRuntime::thread_alive(ObjectId thread)const {
    impl_->check_thread();(void)impl_->thread_state(thread);return impl_->active_thread(thread);
}
std::uint64_t ManagedRuntime::thread_initial_signal_mask(ObjectId thread)const {
    impl_->check_thread();return impl_->thread_state(thread).inherited_signal_mask;
}
ObjectId ManagedRuntime::current_thread() {
    auto &p = *impl_;
    p.check_thread();
    if (!p.background()) return p.synthetic_thread(p.main_context, u"main");
    if (p.current_context().thread_object) return p.current_context().thread_object;
    std::u16string name = p.native_context_depth?u"native-":u"task-";
    for (const auto character : std::to_string(Scheduler::execution_token())) name.push_back(character);
    return p.synthetic_thread(p.current_context(), name);
}
ObjectId ManagedRuntime::main_thread() {
    auto &p = *impl_;
    p.check_thread();
    return p.synthetic_thread(p.main_context, u"main");
}
bool ManagedRuntime::is_main_thread() const {
    impl_->check_thread();
    return !impl_->background();
}
bool ManagedRuntime::has_background_execution() const {
    impl_->check_thread();
    return impl_->background_executed;
}
std::uint64_t ManagedRuntime::logical_thread_cpu_millis(std::uint64_t seconds,std::uint64_t nanos) const {
    const auto &p=*impl_;p.check_thread();
    if(p.execution_owner)fail("THREAD_CPU_UNSUPPORTED","Borrowed runtime CPU accounting is unsupported");
    constexpr std::uint64_t maximum=INT64_MAX,ticks_per_second=10'000'000;
    if(nanos>=1'000'000'000 || seconds>(maximum-nanos/1'000'000)/1000)
        fail("THREAD_CPU_INVALID","Thread CPU clock cannot be represented in Java milliseconds");
    if(p.native_cpu_unattributed)fail("THREAD_CPU_UNSUPPORTED","Native logical thread CPU attribution is not implemented");
    if(!p.background_executed)return seconds*1000+nanos/1'000'000;
    if(nanos%100 || seconds>(UINT64_MAX-nanos/100)/ticks_per_second)
        fail("THREAD_CPU_INVALID","Thread CPU clock cannot be represented in scheduler 100ns units");
    return p.scheduler->logical_cpu_ticks(seconds*ticks_per_second+nanos/100)/10'000;
}
ManagedRuntime::TaskId ManagedRuntime::schedule(Index method, std::span<const Value> arguments, bool virtual_dispatch) {
    auto &p = *impl_;
    p.task_owner(); // Preserve the existing external-main-only host API.
    return p.submit_task(method, arguments, virtual_dispatch);
}
ManagedRuntime::TaskId ManagedRuntime::schedule_owned(Index method, std::span<const Value> arguments, bool virtual_dispatch) {
    return impl_->submit_task(method, arguments, virtual_dispatch);
}
ManagedRuntime::TaskId ManagedRuntime::schedule_worker(std::unique_ptr<ManagedWorkerEntry> entry) {
    auto &p = *impl_;
    p.check_thread();
    if (p.execution_owner != 0)
        fail("TASK_STATE", "Persistent worker admission requires an owned runtime");
    if (p.scheduler) (void)p.scheduler->current();
    if (!entry) fail("WORKER_ENTRY", "Persistent worker entry is null");
    return p.submit_task(no_index, {}, false, std::move(entry));
}
void ManagedRuntime::park_worker(std::optional<std::chrono::steady_clock::time_point> deadline) {
    auto &p = *impl_;
    auto &entry = p.persistent_worker();
    entry.context.last_result = Value::nothing();
    if (!p.task_work_remaining) fail("BUDGET", "Managed worker batch park budget exhausted");
    --p.task_work_remaining;
    if (deadline) p.scheduler->park_until(*deadline);
    else p.scheduler->park();
}
void ManagedRuntime::unpark_worker(TaskId id) {
    auto &p = *impl_;
    p.check_thread();
    if (p.execution_owner != 0 || !p.scheduler)
        fail("TASK_STATE", "Persistent worker unpark requires an owned runtime");
    (void)p.scheduler->current();
    auto &entry = p.task(id);
    if (!entry.worker) fail("TASK_STATE", "Unpark target is not a persistent worker");
    (void)entry.checked_worker_roots();
    p.scheduler->unpark(id);
}
void ManagedRuntime::worker_checkpoint() {
    auto &p = *impl_;
    p.execution_checkpoint();
    auto &entry = p.persistent_worker();
    entry.context.last_result = Value::nothing();
    if (!p.task_work_remaining) fail("BUDGET", "Managed worker batch checkpoint budget exhausted");
    --p.task_work_remaining;
    p.scheduler->yield();
    p.execution_checkpoint();
}
bool ManagedRuntime::run_task() {
    auto &p = *impl_;
    p.task_owner(true);
    return p.pump_task();
}
std::optional<std::chrono::steady_clock::time_point> ManagedRuntime::next_task_deadline() const {
    const auto &p = *impl_;
    p.task_owner(true);
    return p.scheduler ? p.scheduler->next_deadline() : std::nullopt;
}
Scheduler::State ManagedRuntime::task_state(TaskId id) const {
    auto &p = *impl_;
    p.task_owner(); (void)p.task(id);
    return p.scheduler->state(id);
}
Value ManagedRuntime::task_result(TaskId id) const {
    auto &p = *impl_;
    p.task_owner(); const auto &task = p.task(id);
    if(task.context.thread_exit)fail("THREAD_EXITED","Logical thread exited without a managed return value");
    if (p.scheduler->state(id) != Scheduler::State::completed)
        fail("TASK_STATE", "Managed task has no completed result");
    return task.context.last_result;
}
std::exception_ptr ManagedRuntime::task_exception(TaskId id) const {
    auto &p = *impl_;
    p.task_owner(); (void)p.task(id);
    return p.scheduler->exception(id);
}
void ManagedRuntime::cancel_task(TaskId id) {
    auto &p = *impl_;
    p.task_owner();auto &task=p.task(id);
    p.scheduler->cancel(id);task.context.cancellation_requested=true;
}
void ManagedRuntime::release_task(TaskId id) {
    auto &p = *impl_;
    p.task_owner(); auto &task = p.task(id);
    if (!task.context.frames.empty() || task.context.invocations)
        fail("TASK_STATE", "Managed task stack has not unwound");
    p.scheduler->release(id); // Reject nonterminal state before dropping any roots.
    p.finish_task_context(task.context);
    p.metrics.heap_bytes -= task.charged;
    for (auto &entry : p.tasks) if (entry.get() == &task) { entry.reset(); return; }
}
void ManagedRuntime::close_tasks() {
    auto &p = *impl_;
    p.check_thread(true); // Teardown must still cancel stacks after loader poisoning.
    if (!p.scheduler) return;
    if (p.background() || p.execution_owner != 0 || !p.main_context.frames.empty() || p.main_context.barriers)
        fail("TASK_STATE", "Managed task shutdown requires an idle external main context");
    (void)p.scheduler->current();
    p.tasks_closing=true;
    for(auto &task:p.tasks)if(task)task->context.cancellation_requested=true;
    p.scheduler->close();
    for(auto &task:p.tasks)if(task)p.finish_task_context(task->context);
    p.reap_java_threads();
}
void ManagedRuntime::post_main(Index method, std::span<const Value> arguments, bool virtual_dispatch) {
    auto &p=*impl_;
    p.main_post_owner();
    if(method>=p.image.methods.size())fail("METHOD_NOT_FOUND", "Main callback method is outside the held DEX table");
    if(arguments.size()>256 || p.main_callback_count==p.main_callbacks.size())
        fail("MAIN_CALLBACK_LIMIT", "Main callback queue or argument bound exceeded");
    auto callback=std::make_unique<MainCallback>();
    callback->method=method;callback->virtual_dispatch=virtual_dispatch;
    callback->arguments.assign(arguments.begin(),arguments.end());
    for(auto argument:callback->arguments)
        if(argument.kind==ValueKind::reference && argument.bits)(void)p.object(argument.bits);
    p.accept_main_callback(std::move(callback));
}
void ManagedRuntime::post_main(std::unique_ptr<ManagedMainEntry> entry) {
    auto &p=*impl_;
    p.main_post_owner();
    if(!entry)fail("MAIN_CALLBACK_ENTRY", "Trusted main entry cannot be null");
    if(p.main_callback_count==p.main_callbacks.size())fail("MAIN_CALLBACK_LIMIT", "Main callback queue bound exceeded");
    const auto roots=entry->values();
    const auto bytes=entry->bytes();
    if(bytes<sizeof(ManagedMainEntry) || (!roots.empty() && !roots.data()))
        fail("MAIN_CALLBACK_ENTRY", "Trusted main entry has invalid fixed metadata");
    if(roots.size()>256)fail("MAIN_CALLBACK_LIMIT", "Trusted main entry roots exceed 256 values");
    for(auto root:roots)if(root.kind==ValueKind::reference && root.bits)(void)p.object(root.bits);
    auto callback=std::make_unique<MainCallback>();
    callback->entry_roots=roots;callback->entry_bytes=bytes;callback->entry=std::move(entry);
    p.accept_main_callback(std::move(callback));
}
bool ManagedRuntime::run_main_callback() {
    auto &p = *impl_;
    p.main_callback_owner();
    if (!p.main_callback_count) return false;
    p.main_callback_inflight = std::move(p.main_callbacks[p.main_callback_head]);
    p.main_callback_head = (p.main_callback_head + 1) % p.main_callbacks.size();
    --p.main_callback_count;
    struct DeliveryEnd {
        Impl &owner;
        ~DeliveryEnd() {
            // Delivery exposes no return Value. Preserve last_exception for a
            // propagated JavaException, as ordinary invocation does, but do not
            // keep an ignored callback result alive after its entry is consumed.
            owner.main_context.last_result = {};
            owner.metrics.heap_bytes -= owner.main_callback_inflight->charged;
            owner.main_callback_inflight.reset();
            if (!owner.main_callback_count && owner.main_callback_capacity_charged) {
                owner.metrics.heap_bytes -= sizeof(owner.main_callbacks);
                owner.main_callback_capacity_charged = false;
            }
        }
    } delivery_end{p};
    // Charge dispatch as well as DEX instructions: even a provider-only callback
    // that reposts itself cannot turn the queue into an unbudgeted execution loop.
    if (!p.main_callback_work_remaining)
        fail("BUDGET", "Main callback batch dispatch budget exhausted");
    --p.main_callback_work_remaining;
    const auto &callback = *p.main_callback_inflight;
    if(callback.entry) {
        for(auto root:callback.checked_roots())
            if(root.kind==ValueKind::reference && root.bits)(void)p.object(root.bits);
        p.main_context.last_result={};p.main_context.last_exception=0;p.main_context.remaining=p.limits.instructions;
        try {callback.entry->run(*this);}
        catch(const JavaException &error) {
            p.execution_checkpoint();
            (void)p.object(error.object);p.main_context.last_exception=error.object;throw;
        }
    } else if (callback.virtual_dispatch) (void)invoke_virtual(callback.method, callback.arguments);
    else (void)invoke(callback.method, callback.arguments);
    p.execution_checkpoint();
    return true;
}
bool ManagedRuntime::has_main_callbacks() const {
    impl_->check_thread();
    return impl_->main_callback_count != 0;
}
void ManagedRuntime::close_main_callbacks() {
    auto &p = *impl_;
    p.check_thread(true);
    // A runtime constructed inside an external scheduler owns no deliverable
    // main queue. Its empty teardown must remain valid during owner unwinding.
    if (p.execution_owner != 0 && !p.main_callback_count && !p.main_callback_inflight) {
        p.main_callbacks_closed = true;
        return;
    }
    p.main_callback_owner(true);
    for (auto &callback : p.main_callbacks) if (callback) {
        p.metrics.heap_bytes -= callback->charged;
        callback.reset();
    }
    if (p.main_callback_capacity_charged) {
        p.metrics.heap_bytes -= sizeof(p.main_callbacks);
        p.main_callback_capacity_charged = false;
    }
    p.main_callback_count = p.main_callback_head = 0;
    p.main_callbacks_closed = true;
}
ObjectId ManagedRuntime::new_string(std::u16string_view value) {
    if (value.size() > impl_->limits.array_length)
        fail("STRING_LIMIT", "Managed string exceeds length limit");
    Object result;
    result.type = "Ljava/lang/String;";
    result.text = value;
    return impl_->allocate(std::move(result));
}
ObjectId ManagedRuntime::new_string_set(std::span<const std::optional<std::u16string>> values) {
    auto &p=*impl_;p.check_thread();
    if(values.size()>p.limits.array_length)fail("MAP_LIMIT","Managed string set exceeds element limit");
    const auto id=new_object(hash_set_type);retain(id);
    struct Release {ManagedRuntime &runtime;ObjectId id;~Release(){runtime.release(id);}} root{*this,id};
    auto &set=p.object(id);
    const MapCallbacks callbacks{[&](ObjectId key){return p.key_hash(key);},[&](ObjectId a,ObjectId b){return p.key_equal(a,b);}};
    const std::array initial{Value::reference(id)};
    (void)set.map->invoke_hash_set(*this,hash_set_type,"<init>","()V",initial,
        {set.bytes,p.metrics.heap_bytes,p.limits.heap_bytes,p.limits.array_length},callbacks);
    for(const auto &value:values) {
        const auto text=value?new_string(*value):ObjectId{0};retain(text);Release element{*this,text};
        (void)invoke_virtual_named(id,"add","(Ljava/lang/Object;)Z",std::array{Value::reference(text)});
    }
    return id;
}
ObjectId ManagedRuntime::class_object(std::string_view descriptor) {
    auto &p = *impl_;
    p.check_thread();
    p.known(descriptor);
    const auto it = p.class_objects.find(descriptor);
    if (it != p.class_objects.end())
        return it->second;
    Object result;
    result.type = "Ljava/lang/Class;";
    result.represented = descriptor;
    const auto id = p.allocate(std::move(result));
    p.class_objects.emplace(descriptor, id);
    return id;
}
ObjectId ManagedRuntime::class_loader() {
    auto &p=*impl_;p.check_thread();
    if(!p.loader_object) {
        if(p.resolve_class("Ljava/lang/ClassLoader;") || p.resolve_class("Laether/dex/RuntimeClassLoader;"))
            fail("CLASS_LOADER_UNSUPPORTED", "Held class collides with the runtime ClassLoader implementation or base");
        Object loader;loader.type="Laether/dex/RuntimeClassLoader;";
        p.loader_object=p.allocate(std::move(loader));
    }
    return p.loader_object;
}
ObjectId ManagedRuntime::new_array(std::string_view descriptor, std::int32_t length) {
    auto &p = *impl_;
    p.check_thread();
    if (descriptor.size() < 2 || descriptor[0] != '[' || descriptor.substr(1) == "V")
        fail("ARRAY_TYPE", "Invalid array descriptor");
    p.known(descriptor);
    if (length < 0)
        raise("Ljava/lang/NegativeArraySizeException;");
    if (static_cast<std::size_t>(length) > p.limits.array_length)
        fail("ARRAY_LIMIT", "Managed array exceeds length limit");
    Object result;
    result.type = descriptor;
    result.elements.resize(static_cast<std::size_t>(length), default_value(descriptor.substr(1)));
    return p.allocate(std::move(result));
}
std::string_view ManagedRuntime::object_type(ObjectId object) const { return impl_->object(object).type; }
std::string_view ManagedRuntime::represented_class(ObjectId object) const {
    const auto &o = impl_->object(object);
    if (o.type != "Ljava/lang/Class;")
        fail("VALUE_TYPE", "Expected a class object");
    return o.represented;
}
std::u16string_view ManagedRuntime::string(ObjectId object) const {
    const auto &o = impl_->object(object);
    if (o.type != "Ljava/lang/String;")
        fail("VALUE_TYPE", "Expected a string object");
    return o.text;
}
std::u16string_view ManagedRuntime::char_sequence(ObjectId object) const {
    const auto &o = impl_->object(object);
    if (o.type != "Ljava/lang/String;" && o.type != "Ljava/lang/StringBuilder;")
        fail("API_UNSUPPORTED", "CharSequence implementation is not supported: " + o.type);
    return o.text;
}
std::u16string_view ManagedRuntime::exception_message(ObjectId object) const {
    const auto &o = impl_->object(object);
    if (!impl_->subtype(o.type, "Ljava/lang/Throwable;"))
        fail("VALUE_TYPE", "Expected a Throwable object");
    return o.text;
}
std::size_t ManagedRuntime::array_length(ObjectId object) const {
    const auto &o = impl_->object(object);
    if (o.type.front() != '[')
        fail("VALUE_TYPE", "Expected an array object");
    return o.elements.size();
}
Value ManagedRuntime::array_get(ObjectId object, std::int32_t index) const {
    const auto &o = impl_->object(object);
    if (o.type.front() != '[')
        fail("VALUE_TYPE", "Expected an array object");
    if (index < 0 || static_cast<std::size_t>(index) >= o.elements.size())
        const_cast<ManagedRuntime *>(this)->raise("Ljava/lang/ArrayIndexOutOfBoundsException;");
    return o.elements[static_cast<std::size_t>(index)];
}
void ManagedRuntime::array_set(ObjectId object, std::int32_t index, Value value) {
    auto &o = impl_->object(object);
    if (o.type.front() != '[')
        fail("VALUE_TYPE", "Expected an array object");
    if (index < 0 || static_cast<std::size_t>(index) >= o.elements.size())
        raise("Ljava/lang/ArrayIndexOutOfBoundsException;");
    const auto component = std::string_view(o.type).substr(1);
    if (reference_type(component) && !assignable(reference(value), component))
        raise("Ljava/lang/ArrayStoreException;");
    o.elements[static_cast<std::size_t>(index)] = impl_->typed(value, component);
}
bool ManagedRuntime::assignable(ObjectId object, std::string_view type) const {
    impl_->check_thread();
    return !object || impl_->subtype(impl_->object(object).type, type);
}
const HostObjectState *ManagedRuntime::host_state(ObjectId id) const {
    impl_->check_thread();
    return impl_->object(id).host_state.get();
}
void ManagedRuntime::set_host_state(ObjectId id, std::unique_ptr<HostObjectState> state) {
    auto &p = *impl_;
    if(!state) {
        // Releasing authenticated existing roots is teardown, not class-space
        // execution. A poisoned loader or detached provider must not prevent it.
        // Do not perform resolution, subtype checks, collection or new rooting.
        p.check_thread(true);
        const auto found=p.heap.find(id);
        if(found==p.heap.end())fail("REFERENCE","Provider state target is not a live managed object");
        auto &target=found->second;
        if(core_type(target.type) || target.type.starts_with('['))
            fail("HOST_STATE","Provider state requires a noncore framework object");
        target.bytes-=target.host_bytes;p.metrics.heap_bytes-=target.host_bytes;
        target.host_bytes=0;target.host_state.reset();return;
    }
    p.check_thread();
    const auto &object = p.object(id);
    if (!p.host || core_type(object.type) || object.type.starts_with('['))
        fail("HOST_STATE", "Attaching provider state requires an attached framework object");
    const auto bytes = state ? state->bytes() : 0;
    const auto values = state ? state->values() : std::span<const Value>{};
    if (values.size() > p.limits.array_length || bytes > p.limits.heap_bytes ||
        (state && bytes < sizeof(HostObjectState)))
        fail("HEAP_LIMIT", "Provider state exceeds the managed storage budget");
    struct Roots {
        ManagedRuntime &runtime;
        std::vector<ObjectId> ids;
        ~Roots() {
            for (const auto id : ids)
                runtime.release(id);
        }
        void add(ObjectId id) {
            runtime.retain(id);
            ids.push_back(id);
        }
    } roots{*this, {}};
    roots.ids.reserve(values.size() + 1);
    roots.add(id);
    for (const auto value : values) {
        if (value.kind == ValueKind::reference)
            roots.add(value.bits);
        else if (value.kind != ValueKind::word && value.kind != ValueKind::wide)
            fail("VALUE_TYPE", "Provider state contains an invalid managed value");
    }
    const auto old = object.host_bytes;
    if (bytes > old && bytes - old > p.limits.heap_bytes - p.metrics.heap_bytes)
        p.collect();
    if (bytes > old && bytes - old > p.limits.heap_bytes - p.metrics.heap_bytes)
        fail("HEAP_LIMIT", "Provider state exhausts the managed heap budget");
    auto &target = p.object(id);
    target.bytes = target.bytes - old + bytes;
    p.metrics.heap_bytes = p.metrics.heap_bytes - old + bytes;
    target.host_bytes = bytes;
    target.host_state = std::move(state);
}
Value ManagedRuntime::get_static(Index index) {
    auto &p = *impl_;
    p.check_thread();
    const auto &field = p.image.fields.at(index);
    if (p.loader)
        p.provider_call([&] { p.ensure_class(p.image.types.at(field.owner)); });
    if (!field.declared && p.image.types.at(field.owner) == time_unit_type &&
        p.image.types.at(field.type) == time_unit_type)
        if (const auto ordinal = time_unit_index(field.name))
            return Value::reference(p.time_unit(*ordinal));
    if(!field.declared) {
        const auto &owner_type=p.image.types.at(field.owner);
        if(owner_type=="Ljava/lang/Void;" && field.name=="TYPE" &&
            p.image.types.at(field.type)=="Ljava/lang/Class;")
            return Value::reference(class_object("V"));
        if((owner_type==integer_type || owner_type=="Ljava/lang/Character;") &&
            field.name=="TYPE" && p.image.types.at(field.type)=="Ljava/lang/Class;")
            return Value::reference(class_object(owner_type==integer_type?"I":"C"));
        if(owner_type==collections_utility_type) {
            if(field.name=="EMPTY_MAP" && p.image.types.at(field.type)=="Ljava/util/Map;")return Value::reference(p.canonical_empty(empty_map_type));
            if(field.name=="EMPTY_SET" && p.image.types.at(field.type)=="Ljava/util/Set;")return Value::reference(p.canonical_empty(empty_set_type));
        }
        if(owner_type==pattern_type && p.image.types.at(field.type)=="I") {
            static constexpr std::array<std::string_view,9> names{"UNIX_LINES","CASE_INSENSITIVE","COMMENTS","MULTILINE","LITERAL","DOTALL","UNICODE_CASE","CANON_EQ","UNICODE_CHARACTER_CLASS"};
            for(std::size_t n=0;n<names.size();++n)if(field.name==names[n])return Value::word(1U<<n);
        }
        if(owner_type=="Ljava/lang/System;" && p.image.types.at(field.type)==print_stream_type &&
           (field.name=="out" || field.name=="err")) {
            const auto slot=field.name=="err"?1U:0U;
            if(!p.standard_streams[slot]) {
                Object stream;stream.type=print_stream_type;
                p.standard_streams[slot]=p.allocate(std::move(stream));
            }
            return Value::reference(p.standard_streams[slot]);
        }
        if(owner_type==long_type || owner_type==short_type) {
            const bool large=owner_type==long_type;const auto &descriptor=p.image.types.at(field.type);
            if(field.name=="TYPE" && descriptor=="Ljava/lang/Class;")return Value::reference(class_object(large?"J":"S"));
            if(descriptor=="I") {
                if(field.name=="SIZE")return Value::word(large?64:16);
                if(field.name=="BYTES")return Value::word(large?8:2);
            }
            if(descriptor==(large?"J":"S")) {
                if(field.name=="MIN_VALUE")return large?Value::wide(0x8000000000000000ULL):Value::word(static_cast<std::uint32_t>(-32768));
                if(field.name=="MAX_VALUE")return large?Value::wide(0x7fffffffffffffffULL):Value::word(32767);
            }
        }
        if(owner_type==float_type || owner_type==double_type) {
            const auto &descriptor=p.image.types.at(field.type);
            if(field.name=="TYPE" && descriptor=="Ljava/lang/Class;")return Value::reference(class_object(owner_type==double_type?"D":"F"));
            if(const auto value=floating_constant(owner_type,field.name,descriptor))return *value;
        }
        if(owner_type==byte_type) {
            const auto &field_type=p.image.types.at(field.type);
            if(field.name=="TYPE" && field_type=="Ljava/lang/Class;")return Value::reference(class_object("B"));
            if(field_type=="B") {
                if(field.name=="MIN_VALUE")return Value::word(static_cast<std::uint32_t>(-128));
                if(field.name=="MAX_VALUE")return Value::word(127);
            }
            if(field_type=="I") {
                if(field.name=="SIZE")return Value::word(8);
                if(field.name=="BYTES")return Value::word(1);
            }
        }
        if(owner_type==boolean_type) {
            if(p.image.types.at(field.type)==boolean_type) {
                if(field.name=="TRUE")return Value::reference(p.box_boolean(true));
                if(field.name=="FALSE")return Value::reference(p.box_boolean(false));
            }
            if(field.name=="TYPE" && p.image.types.at(field.type)=="Ljava/lang/Class;")
                return Value::reference(class_object("Z"));
        }
        if(owner_type==async_task_type && p.image.types.at(field.type)=="Ljava/util/concurrent/Executor;") {
            p.ensure_async_runtime();
            if(field.name=="THREAD_POOL_EXECUTOR")return Value::reference(p.async_globals[0]);
            if(field.name=="SERIAL_EXECUTOR")return Value::reference(p.async_globals[1]);
        }
        if(owner_type==async_status_type && p.image.types.at(field.type)==async_status_type) {
            static constexpr std::array<std::string_view,3> names{"PENDING","RUNNING","FINISHED"};
            for(std::size_t n=0;n<3;++n)if(field.name==names[n])return Value::reference(p.async_status(n));
        }
        if(owner_type==android_process_type && p.image.types.at(field.type)=="I") {
            if(field.name=="THREAD_PRIORITY_DEFAULT")return Value::word(0);
            if(field.name=="THREAD_PRIORITY_BACKGROUND")return Value::word(10);
        }
    }
    if (!field.declared) {
        if (p.host)
            if (const auto value = p.provider_call([&] { return p.host->static_field(*this, index); }))
                return p.typed(*value, p.image.types.at(field.type));
        fail("FIELD_UNSUPPORTED", "External field is not implemented: " + p.image.types.at(field.owner) +
                                  "." + field.name + ":" + p.image.types.at(field.type));
    }
    if (!(field.flags & 8))
        fail("FIELD", "Expected a defined static field");
    p.initialize(p.image.types.at(field.owner));
    return p.statics.at(index);
}
void ManagedRuntime::set_static(Index index, Value value) {
    auto &p = *impl_;
    p.check_thread();
    const auto &field = p.image.fields.at(index);
    if (p.loader)
        p.provider_call([&] { p.ensure_class(p.image.types.at(field.owner)); });
    if (!field.declared || !(field.flags & 8))
        fail("FIELD", "Expected a defined static field");
    p.initialize(p.image.types.at(field.owner));
    p.statics[index] = p.typed(value, p.image.types.at(field.type));
}
void ManagedRuntime::retain(ObjectId id) {
    if (!id)
        return;
    auto &p = *impl_;
    p.check_thread(true);
    if(!p.heap.contains(id))fail("REFERENCE","Retain of an invalid managed object");
    if (p.metrics.pinned_references >= 65536)
        fail("ROOT_LIMIT", "Too many retained managed roots");
    ++p.pins[id];
    ++p.metrics.pinned_references;
}
void ManagedRuntime::release(ObjectId id) {
    if (!id)
        return;
    auto &p = *impl_;
    p.check_thread(true);
    const auto it = p.pins.find(id);
    if (it == p.pins.end())
        fail("REFERENCE", "Release of an unretained managed root");
    if (!--it->second)
        p.pins.erase(it);
    --p.metrics.pinned_references;
}
void ManagedRuntime::collect() { impl_->collect(); }
[[noreturn]] void ManagedRuntime::raise(std::string_view type, std::u16string_view message) {
    auto &p = *impl_;
    p.check_thread();
    if (!p.subtype(type, "Ljava/lang/Throwable;"))
        fail("EXCEPTION", "Exception type does not derive from Throwable");
    if (message.size() > p.limits.array_length)
        fail("STRING_LIMIT", "Exception message exceeds length limit");
    const auto id = new_object(type);
    if (message.size() * 2 > p.limits.heap_bytes - p.metrics.heap_bytes)
        fail("HEAP_LIMIT", "Exception message exceeds heap limit");
    auto &o = p.object(id);
    o.text = message;
    o.bytes += message.size() * 2;
    p.metrics.heap_bytes += message.size() * 2;
    ++p.metrics.exceptions;
    p.current_context().last_exception = id;
    throw JavaException(id);
}
} // namespace aether::dex
