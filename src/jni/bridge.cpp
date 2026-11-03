#include "aether/jni/bridge.hpp"
#include "aether/audio/guest.hpp"
#include "aether/graphics/guest.hpp"
#include "aether/android/native.hpp"
#include "aether/android/native_window.hpp"
#include "aether/android/native_activity.hpp"
#include "aether/android/profile.hpp"
#include "aether/common/thread_exit.hpp"
#include "aether/host/process_info.hpp"
#include <algorithm>
#include <atomic>
#include <bit>
#include <cmath>
#include <exception>
#include <map>
#include <new>
#include <thread>
#include <type_traits>
#include <utility>

namespace aether::jni {
namespace {
using a64::Address;
using dex::ObjectId;
using dex::Value;
using Handle = std::uint64_t;
constexpr Address tables = 0x60000, function_table = 0x61000, vm_table = 0x60800;
// The observed constructor chain needs 131040 bytes, beyond the former
// 61440 usable bytes. Match the already admitted native-thread default while
// retaining lazy ownership, top headroom and an unmapped gap between slots.
constexpr Address trampolines = 0x62000, stacks = 0x32000000, stride = 0x100000, stack_size = 0xf8000;
static_assert(stride >= stack_size + 4096);
static_assert(stacks + 32 * stride <= 0x36000000); // Managed TLS begins here.
// NativeAssets uses the first 64 MiB at 1 TiB. Keep Activity incarnations
// outside every existing low-address directory/stdio/TLS/heap/stack arena.
constexpr Address native_activity_base = (Address{1} << 40) + 0x10000000;
static_assert(native_activity_base + 32 * 0x20000 < a64::GuestMemory::address_limit);
constexpr std::uint32_t first_service = 0x800, first_vm_service = 0xa00;
constexpr std::size_t function_count = 233;
std::atomic<std::uint64_t> next_handle{1};
[[noreturn]] void bad(std::string_view code, const std::string &message) {
    throw dex::DexError("AETHER_JNI_" + std::string(code), message);
}
std::string ascii(std::u16string_view text) {
    std::string out;
    for (auto c : text) {
        if (!c || c > 127)
            bad("NAME", "Expected a nonempty ASCII class, method or library name");
        out.push_back(static_cast<char>(c));
    }
    if (out.empty())
        bad("NAME", "Empty name");
    return out;
}
std::string mangled(std::string_view name) {
    std::string out;
    for (auto c : name) {
        if (c == '/')
            out += '_';
        else if (c == '_')
            out += "_1";
        else if (c == ';')
            out += "_2";
        else if (c == '[')
            out += "_3";
        else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
            out += c;
        else
            bad("NAME_UNSUPPORTED",
                "JNI export mangling currently supports ASCII identifiers without special characters");
    }
    return out;
}
std::string modified_utf8(std::u16string_view text) {
    std::string out;
    for (auto c : text) {
        if (c && c < 0x80)
            out.push_back(static_cast<char>(c));
        else if (c < 0x800) {
            out.push_back(static_cast<char>(0xc0 | (c >> 6)));
            out.push_back(static_cast<char>(0x80 | (c & 63)));
        } else {
            out.push_back(static_cast<char>(0xe0 | (c >> 12)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 63)));
            out.push_back(static_cast<char>(0x80 | (c & 63)));
        }
    }
    return out;
}
std::u16string from_modified_utf8(std::string_view text) {
    std::u16string out;
    for (std::size_t at = 0; at < text.size();) {
        const auto b = static_cast<std::uint8_t>(text[at++]);
        unsigned value = b, count = 0;
        if (b >= 0xc0 && b <= 0xdf) {
            value = b & 31;
            count = 1;
        } else if (b >= 0xe0 && b <= 0xef) {
            value = b & 15;
            count = 2;
        } else if (!b || b >= 0x80)
            bad("MUTF8", "Invalid modified UTF-8 leading byte");
        for (unsigned n = 0; n < count; ++n) {
            if (at >= text.size())
                bad("MUTF8", "Truncated modified UTF-8");
            const auto c = static_cast<std::uint8_t>(text[at++]);
            if ((c & 0xc0) != 0x80)
                bad("MUTF8", "Invalid modified UTF-8 continuation");
            value = (value << 6) | (c & 63);
        }
        if ((count == 1 && value && value < 0x80) || (count == 2 && value < 0x800))
            bad("MUTF8", "Overlong modified UTF-8");
        out.push_back(static_cast<char16_t>(value));
    }
    return out;
}
class Imports final : public elf::ImportResolver {
    bionic::GuestPosixServices &posix;
    audio::GuestAudioServices *audio_services;
    graphics::GuestGraphicsServices *graphics_services;
    android::NativePlatformServices &platform;
  public:
    Imports(bionic::GuestPosixServices &posix, audio::GuestAudioServices *audio,
            graphics::GuestGraphicsServices *graphics, android::NativePlatformServices &platform)
        : posix(posix), audio_services(audio), graphics_services(graphics), platform(platform) {}
    bool has_library(std::string_view library) const noexcept override {
        return posix.has_library(library) || (audio_services && audio_services->has_library(library)) ||
               (graphics_services && graphics_services->has_library(library)) || platform.has_library(library);
    }
    std::optional<elf::GuestSymbol> resolve(std::string_view library, std::string_view name,
                                           std::string_view version) const override {
        if (graphics_services && graphics_services->has_library(library))
            return graphics_services->resolve(library, name, version);
        if (platform.has_library(library)) return platform.resolve(library, name, version);
        // Existing platform libraries retain their exact resolver/version rules.
        // Audio adds only its own registered library; unknown exports still fail.
        return audio_services && audio_services->has_library(library)
                   ? audio_services->resolve(library, name, version)
                   : posix.resolve(library, name, version);
    }
};
struct JniLocalFrame {
    std::vector<Handle> handles;
    std::size_t guaranteed_capacity = 0;
    bool explicit_frame = false;
    explicit JniLocalFrame(bool is_explicit = false) : explicit_frame(is_explicit) {
        // Successful local-capacity promises have their backing before publication.
        handles.reserve(1024);
    }
};
// Selection remains synchronous: this aggregate is only exchanged by the
// existing stack-owned LogicalScope/native-worker restoration below. It is not
// a public parked-task capsule or permission to switch a live native fiber.
struct JniExecutionState {
    std::size_t native_depth = 0;
    std::vector<JniLocalFrame> frames;
    ObjectId pending = 0;
    Address context = 0, current_environment = Bridge::environment;
    bool attached = true;
    ObjectId active_managed_thread = 0;
    std::uint64_t active_execution_token = 0;
    std::vector<ObjectId> *resolved_weak_roots = nullptr;
    std::uint64_t native_charged_ticks = 0;
};
static_assert(std::is_nothrow_swappable_v<JniExecutionState>);
} // namespace
struct Bridge::Impl : JniExecutionState {
    Bridge &bridge;
    dex::ManagedRuntime &runtime;
    a64::GuestMemory &memory;
    std::shared_ptr<ProcessState> process;
    bionic::GuestPosixServices posix;
    audio::GuestAudioServices *audio_services;
    graphics::GuestGraphicsServices *graphics_services;
    android::NativePlatformServices platform;
    Imports imports;
    elf::GuestLoader loader;
    a64::GuestCpu cpu;
    struct MainWorkCpu;
    std::unique_ptr<MainWorkCpu> main_work_cpu;
    std::string root, error;
    Metrics metrics;
    std::vector<std::string> loaded_roots;
    // Structural NativeActivity ownership is not a Java System.loadLibrary
    // publication. It survives Activity recreation and later JNI root changes.
    std::string native_activity_root;
    bool native_activity_initialized = false;
    unsigned load_state = 0;
    bool on_load_active = false;
    void *initialization_context=nullptr;
    elf::InitializationObserver initialization_observer=nullptr;
    ModuleProvider module_provider;
    bool dynamic_poisoned=false;
    bool native_windows_bound = false;
    std::shared_ptr<android::NativeWindows> native_windows;
    android::NativeActivityInputCompletionFactory input_completion_factory;
    android::NativeActivityHostWorkFactory host_work_factory;
    std::string_view host_work_rejection;
    std::uint64_t next_host_work = 1;
    bool host_work_first = true;
    bool native_configuration_bound = false;
    bool native_closing=false,native_extension_active=false;
    struct NativeActivityStorage {
        ObjectId activity = 0, assets = 0, content = 0;
        Handle clazz = 0, manager = 0, content_root = 0;
        Address address = 0, paths = 0, saved = 0;
        std::size_t path_size = 0, saved_size = 0;
        std::optional<a64::GuestMemory::WordIdentity> identity, path_identity, saved_identity;
        std::array<std::uint8_t, 80> canonical{};
        std::vector<std::uint8_t> path_bytes;
        std::string library, function;
        std::uint64_t generation = 0;
        std::shared_ptr<android::NativeWindowProducer> window;
        std::uint64_t window_id = 0, queue = 0;
        android::NativeWindowGeometry geometry;
        bool window_destroy_started = false, queue_destroy_started = false;
        bool created = false, destroy_started = false;
        std::shared_ptr<android::NativeActivityHostWorkScope> work_scope = std::make_shared<android::NativeActivityHostWorkScope>();
        std::array<android::NativeActivityHostWork, 64> work{};
        std::size_t work_head = 0, work_count = 0;
    };
    std::unique_ptr<NativeActivityStorage> native_activity_storage;
    std::uint32_t native_activity_incarnations = 0;
    bool native_activity_dispatching = false, native_activity_failed = false;
    std::shared_ptr<a64::ThreadRegisterState> graphics_owner;
    const std::thread::id owner_thread = std::this_thread::get_id();
    bool closed = false, shutdown_failed = false;
    bool attach_interface = true;
    struct Ref {
        ObjectId object;
        std::size_t frame, root_slot;
        bool global, weak = false;
        Address context;
    };
    using LocalFrame = JniLocalFrame;
    static_assert(std::is_nothrow_move_constructible_v<LocalFrame>);
    static_assert(std::is_nothrow_move_constructible_v<std::pair<Handle, Ref>>);
    struct MethodId {
        dex::Index index;
        // Owned declarations are canonical by stable DEX index; zero means
        // their declaring class comes from that metadata. Symbolic adapters
        // retain the exact lookup Class identity and existing dispatch rules.
        ObjectId owner;
        bool is_static;
    };
    struct Buffer {
        ObjectId object;
        bool utf8;
        std::size_t bytes;
        Address context;
        // Zero denotes a string; otherwise this is the exact primitive descriptor.
        char component = 0;
        bool critical = false;
    };
    // Opaque identities increase monotonically, so this bounded, once-reserved
    // table remains sorted when appending. Removal only moves trivial records;
    // GC roots occupy independent stable cells, never vector element addresses.
    std::vector<std::pair<Handle, Ref>> refs;
    std::array<ObjectId, 4096> reference_roots{};
    std::uint64_t reference_roots_token = 0;
    // Includes guarantees held by suspended logical/native contexts whose
    // frames are temporarily moved away from this active vector.
    std::size_t unused_local_capacity = 0, local_frame_count = 0;
    // A weak argument is promoted only for its current JNI operation. Nested
    // callbacks keep independent scopes so an inner collection cannot retire
    // arguments still in use by a suspended outer operation.
    struct WeakRoots {
        Impl &owner;
        std::vector<ObjectId> values;
        std::vector<ObjectId> *previous;
        explicit WeakRoots(Impl &impl) : owner(impl), previous(impl.resolved_weak_roots) {
            owner.resolved_weak_roots = &values;
        }
        ~WeakRoots() {
            owner.resolved_weak_roots = previous;
            for (const auto id : values)
                owner.runtime.release(id);
        }
    };
    std::map<Handle, MethodId> methods;
    // Field IDs identify runtime declarations, never JNI reference handles.
    std::map<Handle, dex::Index> fields;
    std::map<dex::Index, Address> registered;
    std::map<Address, Buffer> buffers;
    std::vector<Address> mappings;
    std::array<bool, 32> stack_owned{};
    std::array<bool, 32> stack_leased{}; // Aggregate across all live JNI scopes.
    Address buffer_next = 0x50000000;
    std::size_t buffer_bytes = 0;
    ObjectId allocation_error = 0; // Borrowed runtime-owned OOME; never retained/released as a pending pin.
    struct ManagedBinding {ObjectId thread=0;Address tls=0;bool mapped=false;std::uint32_t tid=0;std::shared_ptr<a64::ThreadRegisterState> registers;};
    std::array<ManagedBinding,16> managed_bindings{};
    std::uint32_t next_managed_tid=0x40000000;
    Impl(Bridge &bridge, dex::ManagedRuntime &runtime, a64::GuestMemory &memory, const a64::AppContext &app,
         const host::TimeService &time, std::span<const elf::ModuleInput> modules, std::string root,
         host::FileService *files, bool attach_interface,std::string_view package,
         audio::GuestAudioServices *audio, graphics::GuestGraphicsServices *graphics)
        : bridge(bridge), runtime(runtime), memory(memory), process(app.process_state), posix(memory, app, time, 1, files,nullptr,package),
          audio_services(audio), graphics_services(graphics), platform(memory, app), imports(posix, audio, graphics, platform), loader(memory, imports), cpu(memory, app, &bridge), root(std::move(root)),
          attach_interface(attach_interface) {
        try {
            runtime.bind_process_state(process);process->checkpoint();
            allocation_error = runtime.prepare_native_allocation_error();
            refs.reserve(reference_roots.size());
            reference_roots_token = runtime.register_native_roots(reference_roots);
            posix.set_managed_priority_service(runtime.thread_priority_baseline(),[this](std::optional<std::int32_t> nice){return this->runtime.thread_priority(nice);});
            cpu.set_thread_pointer(posix.thread_pointer());
            posix.set_once_runner([this](Address entry,Address stack,Address tls,std::uint64_t budget){return execute_cpu_bounded(entry,{},stack,budget,{},tls);});
            platform.bind_looper([this](std::string_view name, a64::ServiceState &state, bool full_frame) {
                return posix.invoke_looper(name, state, full_frame);
            }, [this] { return posix.last_rejection(); });
            platform.bind_input_queue([this](std::string_view name, a64::ServiceState &state, bool full_frame) {
                return posix.invoke_input_queue(name, state, full_frame);
            }, [this] { return posix.last_rejection(); });
            posix.set_looper_runner([this](Address entry, std::array<std::uint64_t,3> args,
                                           Address stack, Address tls, std::uint64_t budget) {
                const auto before = cpu.active_ticks();
                auto result = execute_cpu_bounded(entry, args, stack, budget, {}, tls);
                return bionic::GuestPosixServices::PhdrExecution{std::move(result), cpu.active_ticks() - before};
            });
            posix.set_phdr_runner([this](Address entry,std::array<std::uint64_t,3> args,Address stack,Address tls,std::uint64_t budget){
                const auto before=cpu.active_ticks();
                auto result=execute_cpu_bounded(entry,args,stack,budget,{},tls);
                return bionic::GuestPosixServices::PhdrExecution{std::move(result),cpu.active_ticks()-before};
            });
            platform.bind_activity_host_ops([this](std::string_view name, a64::ServiceState &state, bool) {
                return admit_activity_host_work(name,state);
            }, [this] { return host_work_rejection; });
            posix.set_comparator_runner([this](Address entry,std::array<std::uint64_t,3> arguments,Address stack,Address tls,std::uint64_t budget){
                const auto before=cpu.active_ticks();
                auto result=execute_cpu_bounded(entry,std::span<const std::uint64_t>(arguments).first(2),stack,budget,{},tls);
                return bionic::GuestPosixServices::PhdrExecution{std::move(result),cpu.active_ticks()-before};
            });
            posix.set_cxa_runner([this](Address entry,Address argument,Address stack,Address tls,std::uint64_t budget){
                const auto before=cpu.active_ticks();
                auto result=execute_cpu_bounded(entry,std::array{argument},stack,budget,{},tls);
                return bionic::GuestPosixServices::CxaExecution{std::move(result),cpu.active_ticks()-before};
            });
            posix.set_signal_runner([this](Address entry,std::uint32_t signal,Address stack,Address tls){return execute_cpu_bounded(entry,std::array<std::uint64_t,1>{signal},stack,1'000'000,{},tls);});
            posix.set_fault_signal_runner([this](const a64::SignalEntry &entry,Address trusted_tls,std::uint64_t budget){
                return execute_cpu_bounded(entry.state.pc,{},entry.state.sp,budget,{},trusted_tls,&entry);
            });
        posix.set_thread_factory([this](const bionic::GuestPosixServices::ThreadSpec &spec){return std::make_unique<NativeTask>(*this,spec);});
        posix.set_deferred_yield([this]{return active_native_task && cpu.request_execution_yield();});
        posix.set_deferred_wait_admission([this]{return active_native_task && cpu.execution_progress_allowance().has_value() && native_depth<=1 && !resolved_weak_roots && !critical_active() && !native_closing && !native_extension_active && posix.native_switch_safe();});
            posix.set_address_lookup([this](Address address){return loader.address_info(address);});
            posix.set_program_header_lookup([this](std::size_t index){return loader.program_header_info(index);});
            loader.load(modules, this->root);
            posix.set_dynamic_linker({[this](std::string_view name){dynamic_open(name);},
                [this](std::string_view module,std::string_view name){return loader.lookup(module,name);}});
            map(tables, 8192);
            map(trampolines, 4096);
            write(Bridge::environment, function_table, 8);
            write(Bridge::java_vm, vm_table, 8);
            for (std::size_t i = 4; i < function_count; ++i) {
                const auto address = trampolines + i * 8;
                write(function_table + i * 8, address, 8);
                write(address, 0xd4000001u | ((first_service + i) << 5), 4);
                write(address + 4, 0xd65f03c0, 4);
            }
            for (std::uint32_t i = 3; i < 8; ++i) {
                const auto address = trampolines + 0x800 + i * 8;
                write(vm_table + i * 8, address, 8);
                write(address, 0xd4000001u | ((first_vm_service + i) << 5), 4);
                write(address + 4, 0xd65f03c0, 4);
            }
            memory.protect(tables, a64::Permission::read);
            memory.protect(trampolines, a64::read_execute);
            if (attach_interface)
                runtime.set_native_interface(&bridge);
            if(runtime.main_work_budget()) {
                main_work_cpu=std::make_unique<MainWorkCpu>(*this);
                loader.set_initializer_driver(this,
                    [](void *driver_owner,a64::GuestCpu &,Address entry,std::span<const std::uint64_t> args,
                       Address stack,std::optional<Address> tls) {
                        auto &owner=*static_cast<Impl *>(driver_owner);
                        return owner.execute_cpu(entry,args,stack,1'000'000,{},tls);
                    });
            }
        } catch (...) {
            cleanup();
            throw;
        }
    }
    ~Impl() { cleanup(); }
    void map(Address address, std::size_t size) {
        mappings.reserve(mappings.size() + 1);
        memory.map(address, size, a64::read_write);
        mappings.push_back(address);
    }
    void cleanup() noexcept {
        native_closing=true;
        loader.set_initializer_driver(nullptr,nullptr);
        main_work_cpu.reset();
        posix.close_thread_tasks(); // All task stacks/capsules retire while CPU and JNI roots still live.
        try { retire_native_activity(); } catch (...) { }
        // Normal shutdown reaches here after native finalizers; constructor
        // failure/destruction perform nonexecuting app-owned cleanup only.
        try { platform.shutdown(); } catch (...) { }
        if (reference_roots_token) {
            // The runtime must never retain a span into destroyed Bridge
            // storage, even if later unrelated cleanup fails. Registration is
            // teardown-safe; an ownership violation cannot safely continue.
            try { runtime.unregister_native_roots(reference_roots_token); }
            catch (...) { std::terminate(); }
            reference_roots_token = 0;
        }
        refs.clear();
        frames.clear();
        unused_local_capacity = local_frame_count = 0;
        metrics.local_references = metrics.global_references = 0;
        try {
            pending_exception(0);
            fields.clear();
            for (auto &[address, buffer] : buffers) {
                runtime.release(buffer.object);
                memory.unmap(address);
            }
            buffers.clear();
            metrics.string_buffers = 0;
            for(auto &binding:managed_bindings)release_managed_binding(binding);
            for (auto it = mappings.rbegin(); it != mappings.rend(); ++it)
                memory.unmap(*it);
            mappings.clear();
            stack_owned.fill(false);
        } catch (...) { /* Destruction cannot unwind; all resources are app-owned. */
        }
    }
    std::uint64_t read(Address address, std::size_t size) const {
        std::array<std::uint8_t, 8> bytes{};
        if (size > 8 || !memory.read(address, std::span{bytes}.first(size)))
            bad("MEMORY", "Invalid guest read at " + std::to_string(address));
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < size; ++i)
            value |= std::uint64_t(bytes[i]) << (i * 8);
        return value;
    }
    void write(Address address, std::uint64_t value, std::size_t size) {
        std::array<std::uint8_t, 8> bytes{};
        for (std::size_t i = 0; i < size; ++i)
            bytes[i] = static_cast<std::uint8_t>(value >> (i * 8));
        if (size > 8 || !memory.write(address, std::span{bytes}.first(size)))
            bad("MEMORY", "Invalid guest write at " + std::to_string(address));
    }
    std::string text(Address address, std::size_t limit = 65536) const {
        std::string out;
        for (std::size_t i = 0; i < limit; ++i) {
            if (address > UINT64_MAX - i)
                bad("MEMORY", "Guest C string address overflow");
            const auto value = static_cast<char>(read(address + i, 1));
            if (!value)
                return out;
            out.push_back(value);
        }
        bad("STRING_LIMIT", "Guest C string is not terminated within limit");
    }
    Handle identity() {
        const auto id = next_handle.fetch_add(1, std::memory_order_relaxed);
        if (id >= (std::uint64_t{1} << 48))
            bad("HANDLE_LIMIT", "JNI identity space exhausted");
        return 0x7000000000000000ull | id;
    }
    auto find_reference(Handle handle) {
        const auto found = std::lower_bound(refs.begin(), refs.end(), handle,
                                            [](const auto &entry, Handle value) { return entry.first < value; });
        return found != refs.end() && found->first == handle ? found : refs.end();
    }
    auto find_reference(Handle handle) const {
        const auto found = std::lower_bound(refs.begin(), refs.end(), handle,
                                            [](const auto &entry, Handle value) { return entry.first < value; });
        return found != refs.end() && found->first == handle ? found : refs.end();
    }
    // promote_weak=false is restricted to immediate reference publication or
    // frame retirement/promotion: all intervening steps use preallocated native
    // backing, perform no managed allocation/callback/collection or scheduling.
    ObjectId resolve(Handle handle, bool promote_weak = true) const {
        if (!handle)
            return 0;
        const auto it = find_reference(handle);
        if (it == refs.end() || (!it->second.global && it->second.context!=context))
            bad("REFERENCE", "Invalid, deleted or foreign JNI reference");
        if (!it->second.weak)
            return it->second.object;
        const auto object = runtime.native_weak_referent(it->second.object);
        if (object && promote_weak && resolved_weak_roots &&
            std::find(resolved_weak_roots->begin(), resolved_weak_roots->end(), object) == resolved_weak_roots->end()) {
            runtime.retain(object);
            try { resolved_weak_roots->push_back(object); }
            catch (...) { runtime.release(object); throw; }
        }
        return object;
    }
    Handle reference(ObjectId object, bool global = false) {
        if (!object)
            return 0;
        if (refs.size() >= reference_roots.size() ||
            (!global && (frames.empty() || frames.back().handles.size() >= 1024)))
            bad("REFERENCE_LIMIT", "JNI reference/frame quota exhausted");
        const bool promised = !global && frames.back().handles.size() < frames.back().guaranteed_capacity;
        if (!promised && refs.size() + unused_local_capacity >= reference_roots.size())
            bad("REFERENCE_LIMIT", "JNI unreserved shared reference quota exhausted");
        const auto cell = std::find(reference_roots.begin(), reference_roots.end(), ObjectId{0});
        if (cell == reference_roots.end())
            bad("REFERENCE_LIMIT", "JNI shared root backing exhausted");
        const auto root_slot = static_cast<std::size_t>(cell - reference_roots.begin());
        const auto handle = identity();
        // Validation and publication allocate nothing and cannot collect. Both
        // vectors have admitted backing and trivially movable element types.
        runtime.set_native_root(reference_roots_token, root_slot, object);
        refs.emplace_back(handle, Ref{object, frames.size(), root_slot, global, false, context});
        if (!global) {
            frames.back().handles.push_back(handle);
            if (promised)
                --unused_local_capacity;
        }
        ++metrics.references_created;
        if (global)
            ++metrics.global_references;
        else
            ++metrics.local_references;
        return handle;
    }
    Handle weak_reference(ObjectId object) {
        if (!object)
            return 0;
        if (refs.size() + unused_local_capacity >= reference_roots.size())
            bad("REFERENCE_LIMIT", "JNI shared reference quota exhausted");
        const auto wrapper = runtime.new_native_weak(object);
        // No managed allocation/collection occurs in reference(): its native
        // table insertion retains this wrapper immediately. Only the wrapper
        // is a strong global root; resolve() never exposes it to guest code.
        const auto handle = reference(wrapper, true);
        find_reference(handle)->second.weak = true;
        // global_references counts both strong and weak global handles in the
        // existing metrics bucket; both use the same shared reference quota.
        return handle;
    }
    void erase(Handle handle, bool global, bool weak = false) {
        if (!handle)
            return;
        const auto it = find_reference(handle);
        if (it == refs.end() || it->second.global != global || it->second.weak != weak ||
            (!global && it->second.context!=context))
            bad("REFERENCE", "Reference deletion has wrong kind or stale handle");
        runtime.set_native_root(reference_roots_token, it->second.root_slot, 0);
        if (global)
            --metrics.global_references;
        else {
            auto &frame = frames.at(it->second.frame - 1);
            // Deleting a promised local restores the same reserved capacity;
            // locals created beyond that guarantee restore no promise.
            if (frame.handles.size() <= frame.guaranteed_capacity)
                ++unused_local_capacity;
            const auto local = std::find(frame.handles.begin(), frame.handles.end(), handle);
            if (local == frame.handles.end())
                std::terminate();
            frame.handles.erase(local);
            --metrics.local_references;
        }
        refs.erase(it);
    }
    void pop() {
        if (frames.empty())
            bad("FRAME", "No JNI local frame");
        // Retire the promise before deleting any locals, so their deletion
        // cannot restore capacity into a frame that is being discarded.
        const auto count = frames.back().handles.size();
        if (frames.back().guaranteed_capacity > count)
            unused_local_capacity -= frames.back().guaranteed_capacity - count;
        frames.back().guaranteed_capacity = 0;
        while (!frames.back().handles.empty()) {
            erase(*frames.back().handles.begin(), false);
            ++metrics.automatic_local_deletions;
        }
        frames.pop_back();
        --local_frame_count;
    }
    void ensure_local_capacity(std::size_t capacity) {
        if (frames.empty() || capacity > 1024 - frames.back().handles.size())
            bad("REFERENCE_LIMIT", "Insufficient JNI local capacity");
        auto &frame = frames.back();
        const auto target = frame.handles.size() + capacity;
        if (target <= frame.guaranteed_capacity)
            return;
        const auto previous = frame.guaranteed_capacity > frame.handles.size()
                                  ? frame.guaranteed_capacity - frame.handles.size() : 0;
        const auto additional = capacity - previous;
        if (additional > reference_roots.size() - refs.size() - unused_local_capacity)
            bad("REFERENCE_LIMIT", "Insufficient JNI shared capacity for local guarantee");
        frame.guaranteed_capacity = target;
        unused_local_capacity += additional;
    }
    void push_frame(std::size_t capacity, bool is_explicit = false) {
        if (capacity > 1024 || local_frame_count >= 128 ||
            capacity > reference_roots.size() - refs.size() - unused_local_capacity)
            bad("REFERENCE_LIMIT", "Insufficient JNI local frame capacity");
        LocalFrame frame(is_explicit);
        frame.guaranteed_capacity = capacity;
        frames.push_back(std::move(frame));
        // Only a fully published frame acquires a promise. Vector/backing
        // allocation failure above leaves every parent/context budget intact.
        unused_local_capacity += capacity;
        ++local_frame_count;
    }
    void release_managed_binding(ManagedBinding &binding) {
        if(!binding.thread)return;
        posix.discard_thread(binding.tid,binding.tls);
        for(auto it=buffers.begin();it!=buffers.end();) {
            if(it->second.context!=binding.tls){++it;continue;}
            memory.unmap(it->first);runtime.release(it->second.object);buffer_bytes-=it->second.bytes;it=buffers.erase(it);
        }
        update_buffer_metrics();
        if(binding.mapped)memory.unmap(binding.tls);
        runtime.release(binding.thread);binding={};
    }
    bionic::GuestPosixServices::ThreadBinding managed_binding(ObjectId thread) {
        std::size_t slot=0;
        for(;slot<managed_bindings.size();++slot)if(managed_bindings[slot].thread==thread)break;
        if(slot==managed_bindings.size()) {
            for(slot=0;slot<managed_bindings.size();++slot)if(!managed_bindings[slot].thread || !runtime.thread_alive(managed_bindings[slot].thread))break;
            if(slot==managed_bindings.size())bad("THREAD_LIMIT","Sixteen live managed native bindings exhausted");
            if(next_managed_tid==0x7fffffffU)bad("THREAD_LIMIT","Managed native thread ID lifetime range exhausted");
            auto id=next_managed_tid+1;if(id==host::current_process_id())++id;
            if(id>0x7fffffffU)bad("THREAD_LIMIT","Managed native thread ID lifetime range exhausted");
            const auto tls=Address{0x36000000}+slot*0x2000;
            auto registers=std::make_shared<a64::ThreadRegisterState>(a64::ThreadRegisterState{tls,0});
            auto &binding=managed_bindings[slot];release_managed_binding(binding);
            runtime.retain(thread);bool mapped=false;
            try {
                memory.map(tls,4096,a64::read_write);mapped=true;
                write(tls,tls,8);write(tls+8,id,8);write(tls+40,read(0x25028,8),8);write(tls+0x200,function_table,8);
                binding={thread,tls,true,id,std::move(registers)};next_managed_tid=id;
            }catch(...){if(mapped)memory.unmap(tls);runtime.release(thread);throw;}
        }
        const auto &binding=managed_bindings[slot];const auto tls=binding.tls;
        return {binding.tid,tls,tls+0x100,runtime.thread_initial_signal_mask(thread),binding.registers};
    }
    struct NativeTask;
    NativeTask *active_native_task=nullptr;
    std::array<NativeTask*,16> native_tasks{};
    struct NativeTask final : bionic::GuestPosixServices::PreparedThread {
        using State=bionic::GuestPosixServices::ThreadTaskState;
        using Slice=bionic::GuestPosixServices::ThreadSlice;
        using Execution=bionic::GuestPosixServices::ThreadExecution;
        Impl &p;bionic::GuestPosixServices::ThreadSpec spec;
        std::unique_ptr<a64::GuestCpu::ExecutionContext> cpu_state;
        JniExecutionState jni_state;
        bionic::GuestPosixServices::ExecutionBinding binding;
        dex::ManagedRuntime::TaskId id=0;
        std::uint64_t allowance=0,ticks=0,reported=0,accounted_ticks=0,accounted_charge=0;
        State cached=State::prepared;bool published=false,cancelled=false,entered=false;
        std::optional<Execution> output;
        std::shared_ptr<a64::DeferredService> waiting;
        struct Entry final : dex::ManagedWorkerEntry {
            NativeTask &task;explicit Entry(NativeTask &t):task(t){}
            void run(dex::ManagedRuntime &) override {task.run();}
            std::span<const Value> values() const noexcept override {return {};}
            std::size_t bytes() const noexcept override {return sizeof(Entry)+sizeof(NativeTask);}
        };
        NativeTask(Impl &owner,const bionic::GuestPosixServices::ThreadSpec &value):p(owner),spec(value) {
            if(p.native_closing)bad("STATE","Native task admission is closing");
            // A running startup poll quantum is not this dormant child's
            // permanent finite post-startup allowance.
            allowance=p.runtime.main_work_budget()?p.runtime.deferred_native_worker_budget():
                std::min(spec.allowance,p.runtime.native_thread_admission_budget());
            if(!allowance)bad("BUDGET","No native task admission allowance");
            const auto selected=p.posix.prepare_thread_execution(spec.id,spec.owner);
            if(!selected)bad("THREAD","Native task identity is not admitted");
            binding=*selected;
            const auto slot=std::find(p.native_tasks.begin(),p.native_tasks.end(),nullptr);
            if(slot==p.native_tasks.end())bad("THREAD","Native wait registry exhausted");
            cpu_state=p.cpu.prepare_execution_context([this](const a64::GuestCpu::ExecutionBoundary &boundary){return boundary_step(boundary);},10000,
                [this](const std::shared_ptr<a64::DeferredService> &operation){wait_for(operation);});
            id=p.runtime.prepare_native_worker(std::make_unique<Entry>(*this),{this,enter,leave});
            *slot=this;
        }
        ~NativeTask() noexcept override {close();for(auto &slot:p.native_tasks)if(slot==this)slot=nullptr;}
        static State translate(dex::Scheduler::State state) noexcept {
            using S=dex::Scheduler::State;
            switch(state){case S::prepared:return State::prepared;case S::runnable:return State::runnable;case S::running:return State::running;
            case S::sleeping:case S::parked:return State::waiting;case S::completed:return State::completed;case S::cancelled:return State::cancelled;case S::failed:return State::failed;}
            return State::failed;
        }
        State state() const noexcept override {
            if(!id)return cached;
            try{
                const auto value=translate(p.runtime.native_worker_state(id));
                return value==State::waiting && waiting && waiting->ready()?State::runnable:value;
            }catch(...){return State::failed;}
        }
        void wait_for(const std::shared_ptr<a64::DeferredService> &operation) {
            if(p.active_native_task!=this || !operation || waiting || !p.posix.native_switch_safe() ||
               p.critical_active() || p.resolved_weak_roots || p.native_closing || p.native_extension_active)
                bad("NATIVE_WAIT_UNSUPPORTED","Native service cannot park across this provider boundary");
            if(operation->ready())return;
            waiting=operation;
            struct Clear {NativeTask &n;~Clear(){n.waiting.reset();}} clear{*this};
            // Alarm ownership/deadlines may change while another child runs.
            // The host idle deadline query observes the live operation; do not
            // freeze a cancelable alarm in the scheduler park record.
            p.runtime.native_worker_park();
        }
        bool started() const noexcept override {return entered;}
        bool publish() noexcept override {
            if(!id || published || p.native_closing || !p.runtime.publish_worker(id))return false;
            published=true;cached=State::runnable;return true;
        }
        bool root_ready() const noexcept {
            const bool idle=p.cpu.execution_idle() && !p.native_depth && p.frames.empty();
            const bool service=p.cpu.execution_progress_allowance().has_value() && p.native_depth<=1;
            return (idle || service) && !p.resolved_weak_roots && !p.critical_active() &&
                p.posix.native_switch_safe() && p.posix.execution_binding_valid(binding) &&
                p.cpu.can_exchange_execution_context(*cpu_state);
        }
        static void enter(void *value,dex::Scheduler::TaskId task) noexcept {
            auto &n=*static_cast<NativeTask*>(value);
            if(task!=n.id || n.p.active_native_task || !n.root_ready())std::terminate();
            n.p.cpu.commit_execution_context(*n.cpu_state);
            n.p.exchange_jni_execution(n.jni_state);
            n.p.posix.exchange_execution_binding(n.binding);
            n.p.active_native_task=&n;
        }
        static void leave(void *value,dex::Scheduler::TaskId task) noexcept {
            auto &n=*static_cast<NativeTask*>(value);
            if(task!=n.id || n.p.active_native_task!=&n || !n.p.cpu.can_exchange_execution_context(*n.cpu_state) ||
               !n.p.posix.execution_binding_valid(n.binding) || (!n.p.cpu.execution_idle() && !n.p.posix.native_switch_safe()))std::terminate();
            n.ticks=n.p.cpu.active_ticks();
            n.p.cpu.commit_execution_context(*n.cpu_state);
            n.p.exchange_jni_execution(n.jni_state);
            n.p.posix.exchange_execution_binding(n.binding);
            n.p.active_native_task=nullptr;
        }
        std::uint64_t boundary_step(const a64::GuestCpu::ExecutionBoundary &boundary) {
            const auto delta=boundary.ticks-accounted_ticks;
            const auto nested=p.native_charged_ticks-accounted_charge;
            const auto uncharged=delta>=nested?delta-nested:0;
            const auto remaining=p.runtime.thread_instruction_budget();
            const auto debit=std::min(uncharged,remaining);
            p.runtime.charge_thread_instructions(debit);p.native_charged_ticks+=debit;
            accounted_ticks=boundary.ticks;accounted_charge=p.native_charged_ticks;
            auto dimensions=p.runtime.native_instruction_budget();
            if(uncharged>remaining || !dimensions.retained || !dimensions.shared ||
               (dimensions.slice && !*dimensions.slice))return 0;
            auto work=std::min(dimensions.retained,dimensions.shared);
            if(dimensions.slice)work=std::min(work,*dimensions.slice);
            // This only narrows the original hard CPU-tick lease. Provider work
            // consumes aggregate hard headroom, without inventing guest ticks.
            if(!p.cpu.limit_execution_slice(work))std::terminate();
            const bool need_quantum=dimensions.soft_quantum && !*dimensions.soft_quantum;
            if((boundary.yield_requested || need_quantum) && boundary.can_yield){
                if(p.posix.native_switch_safe() && !p.critical_active() && !p.resolved_weak_roots && !p.native_closing && !p.native_extension_active)
                    p.runtime.native_worker_checkpoint();
            }
            // Soft expiry cannot unwind a nested/provider stack. Keep its real
            // continuation until an actual parkable boundary; hard dimensions
            // and the original CPU-tick lease remain authoritative throughout.
            dimensions=p.runtime.native_instruction_budget();
            if(!dimensions.retained || !dimensions.shared ||
               (dimensions.slice && !*dimensions.slice))return 0;
            work=std::min(dimensions.retained,dimensions.shared);
            if(dimensions.slice)work=std::min(work,*dimensions.slice);
            if(!p.cpu.limit_execution_slice(work))std::terminate();
            return dimensions.retained; // A temporary work lease never truncates fatal allowance.
        }
        void run() {
            entered=true;
            struct Capture {NativeTask &n;~Capture(){n.ticks=n.p.cpu.active_ticks();}} capture{*this};
            output=p.run_worker(spec.entry,spec.argument,spec.stack_top,spec.tls,allowance);
        }
        Slice resume_slice(std::uint64_t grant,std::int32_t priority) override {
            auto current=state();
            if(current==State::runnable){
                if(cancelled){close();return {State::cancelled,0,{}};}
                if(p.closed || p.native_closing || p.load_state!=2 || p.on_load_active || p.native_extension_active || !grant || !root_ready())
                    bad("NATIVE_SLICE_UNSUPPORTED","Native peers require an idle root or authenticated ordinary parent service");
                const auto scheduler_state=p.runtime.native_worker_state(id);
                if(scheduler_state==dex::Scheduler::State::parked || scheduler_state==dex::Scheduler::State::sleeping){
                    if(!waiting || !waiting->ready())return {State::waiting,0,{}};
                    p.runtime.wake_native_worker(id);
                }
                const auto parent_cpu=p.cpu.execution_progress_allowance();
                const auto requested=grant;
                if(parent_cpu)grant=std::min(grant,*parent_cpu);
                if(!grant || !p.runtime.native_thread_admission_budget())return {State::runnable,0,{},a64::Fault::budget};
                if(!p.cpu.set_execution_slice_allowance(*cpu_state,grant))bad("THREAD","Invalid retained CPU slice state");
                struct ParentCpuEnd {
                    NativeTask &task;std::uint64_t before;bool live;
                    ~ParentCpuEnd() noexcept {
                        if(!live)return;
                        if(task.ticks<before || !task.p.cpu.debit_external_progress(task.ticks-before))std::terminate();
                        // The restored parent lease includes child Java work as
                        // well as native ticks. Narrow its CPU headroom without
                        // inventing ticks or replenishing a transient grant.
                        if(const auto budget=task.p.runtime.native_progress_budget()){
                            auto work=std::min(budget->retained,budget->shared);
                            if(budget->slice)work=std::min(work,*budget->slice);
                            if(!task.p.cpu.limit_external_progress(budget->retained,work))std::terminate();
                        }
                    }
                };
                {
                    const auto before=ticks;
                    ParentCpuEnd debit{*this,before,parent_cpu.has_value()};
                    try{(void)p.runtime.run_native_worker(id,priority,requested);}
                    catch(const dex::DexError &failure){
                        if(failure.code=="AETHER_DEX_BUDGET" && ticks==before && state()==State::runnable)
                            return {State::runnable,0,{},a64::Fault::budget};
                        throw;
                    }
                }
                current=state();
            }
            cached=current;
            const auto spent=ticks-reported;reported=ticks;
            if(current==State::completed || current==State::failed || current==State::cancelled){
                if(!output){
                    Execution failed;failed.result.fault=p.process->exit_status()?a64::Fault::process_exit:a64::Fault::unsupported_service;
                    if(current==State::failed){
                        try {if(const auto failure=p.runtime.native_worker_exception(id))std::rethrow_exception(failure);}
                        catch(const dex::DexError &error){p.error=error.code+": "+error.what();failed.result.fault=error.code=="AETHER_DEX_BUDGET"?a64::Fault::budget:a64::Fault::windows_service;}
                        catch(const std::exception &error){p.error=error.what();failed.result.fault=a64::Fault::windows_service;}
                        catch(...){p.error="Native task failed during host execution";failed.result.fault=a64::Fault::windows_service;}
                    }
                    output=std::move(failed);
                }
                return {current,spent,output};
            }
            return {current,spent,{}};
        }
        void cancel() noexcept override {cancelled=true;}
        void close() noexcept override {
            if(!id)return;
            try {
                if(p.runtime.discard_prepared_worker(id)){id=0;cached=State::cancelled;return;}
                auto current=state();
                if(current!=State::completed && current!=State::failed && current!=State::cancelled){
                    if(!root_ready())std::terminate();
                    p.runtime.cancel_native_worker(id);
                }
                if(!p.runtime.release_native_worker(id))std::terminate();
                id=0;cached=State::cancelled;
            }catch(...){std::terminate();}
        }
    };
    void exchange_jni_execution(JniExecutionState &stored) noexcept {
        using std::swap;
        swap(static_cast<JniExecutionState &>(*this),stored);
    }
    struct LogicalScope {
        Impl &p;ObjectId owner;std::uint64_t token;bool switched=false;
        JniExecutionState previous;
        Address tls=0;
        std::optional<bionic::GuestPosixServices::ThreadBinding> binding;
        explicit LogicalScope(Impl &p):p(p),owner(p.active_managed_thread),token(p.active_execution_token) {
            const auto thread=p.runtime.current_thread(),execution=dex::Scheduler::execution_token();
            if(p.native_depth && (owner!=thread || token!=execution))bad("THREAD","Native CPU belongs to another logical thread");
            const bool main=p.runtime.is_main_thread();
            if(!main) {
                // An attached pthread already owns this exact environment/TLS.
                // Do not replace it with a separate managed-thread binding on
                // a same-owner JNI -> managed -> native callback.
                const bool reuse=owner==thread && token==execution && p.attached && p.context==p.posix.thread_pointer();
                if(!reuse) {
                    const auto selected=p.managed_binding(thread);
                    if(p.context!=selected.tls) {
                        if(p.native_depth)bad("THREAD","Cannot switch a live native attachment");
                        tls=p.posix.thread_pointer();p.cpu.set_thread_pointer(selected.tls);
                        try{binding=p.posix.exchange_thread_binding(selected);}catch(...){p.cpu.set_thread_pointer(tls);throw;}
                        p.exchange_jni_execution(previous);
                        p.context=selected.tls;p.current_environment=selected.tls+0x200;p.attached=true;switched=true;
                    }
                }
            } else if(p.context)bad("THREAD","Main entry cannot borrow a background attachment");
            p.active_managed_thread=thread;p.active_execution_token=execution;
        }
        ~LogicalScope(){
            if(switched){while(!p.frames.empty())p.pop();p.pending_exception(0);p.exchange_jni_execution(previous);p.posix.exchange_thread_binding(binding);p.cpu.set_thread_pointer(tls);}
            p.active_managed_thread=owner;p.active_execution_token=token;
        }
    };
    struct Scope {
        Impl &p;
        std::size_t base, slot;
        explicit Scope(Impl &p, std::size_t capacity = 16) : p(p), base(p.frames.size()),slot(0) {
            while(slot<p.stack_leased.size() && p.stack_leased[slot])++slot;
            if (p.native_depth >= 32 || slot==p.stack_leased.size())
                bad("CALL_DEPTH", "Aggregate native stack slots exhausted");
            if (!p.allocation_reference([&] { p.push_frame(capacity); return Handle{1}; }))
                p.check_pending();
            p.stack_leased[slot]=true;
            ++p.native_depth;
        }
        Scope(const Scope &)=delete;
        Scope &operator=(const Scope &)=delete;
        ~Scope() {
            while (p.frames.size() > base)
                p.pop();
            --p.native_depth;
            p.stack_leased[slot]=false;
        }
        Address stack() const {
            const auto address = stacks + slot * stride;
            if (!p.stack_owned[slot]) {
                // map() records ownership only after a successful, nonoverlapping
                // allocation. Never adopt an existing guest mapping as a stack.
                p.map(address, stack_size);
                p.stack_owned[slot] = true;
            }
            return address + stack_size - 4096;
        }
    };
    // A synchronous native lifecycle has a real runtime invocation but no
    // scheduler task. Keep its hard work grant and accounting at every CPU
    // boundary, including nested JNI and fault handlers, without yielding.
    // The logical-main entry retains this CPU and its actual host stack.
    // While parked, root admits/resumes only this task, never another guest.
    struct MainWorkCpu {
        Impl &p;
        std::unique_ptr<a64::GuestCpu::ExecutionContext> previous;
        std::uint64_t accounted=0,witness=0;
        bool installed=false;
        explicit MainWorkCpu(Impl &owner):p(owner),witness(p.native_charged_ticks) {
            const auto budget=p.runtime.main_work_budget();
            if(!budget)bad("MAIN_WORK_STATE","Resource CPU requires the selected retained main entry");
            previous=p.cpu.prepare_resource_execution_context(
                [this](const a64::GuestCpu::ExecutionBoundary &boundary) {
                    account(boundary.ticks);
                    p.runtime.main_work_checkpoint(boundary.can_yield);
                    const auto current=p.runtime.main_work_budget();
                    if(!current)bad("MAIN_WORK_STATE","Retained main work lost its resource controller");
                    return a64::GuestCpu::ResourceBudget{current->retained,current->quantum_remaining};
                },4096,budget->retained);
            if(!p.cpu.exchange_execution_context(*previous))
                bad("MAIN_WORK_STATE","Resource CPU context requires an idle owned CPU");
            // Prepared CPU contexts intentionally start without a logical TLS
            // owner. Bind this retained main entry's actual owned TLS after
            // installing its context, before any default-TLS initializer call.
            try{p.cpu.set_thread_pointer(p.posix.thread_pointer());}
            catch(...){
                if(!p.cpu.exchange_execution_context(*previous))std::terminate();
                throw;
            }
            installed=true;accounted=p.cpu.active_ticks();
        }
        void account(std::uint64_t ticks) {
            if(ticks<accounted || p.native_charged_ticks<witness)std::terminate();
            const auto elapsed=ticks-accounted,nested=p.native_charged_ticks-witness;
            if(nested>elapsed)std::terminate();
            const auto uncharged=elapsed-nested;
            if(uncharged>UINT64_MAX-p.native_charged_ticks)
                bad("BUDGET","Native main-work accounting exhausted");
            if(uncharged)p.runtime.charge_thread_instructions(uncharged);
            p.native_charged_ticks+=uncharged;
            accounted=ticks;witness=p.native_charged_ticks;
        }
        void finish() {
            if(!installed)return;
            if(!p.cpu.execution_idle())bad("MAIN_WORK_STATE","Cannot retire a live retained CPU call");
            if(p.cpu.active_ticks()!=accounted)
                bad("MAIN_WORK_STATE","Native main-work tail was not settled before leaving its task");
            if(!p.cpu.exchange_execution_context(*previous))
                bad("MAIN_WORK_STATE","Cannot restore the owned root CPU context");
            installed=false;
        }
        ~MainWorkCpu(){if(installed){try{finish();}catch(...){std::terminate();}}}
    };
    a64::ExecutionResult execute_cpu(Address entry,std::span<const std::uint64_t> args,Address stack,
                                     std::uint64_t budget,std::span<const a64::Vector> floats={},
                                     std::optional<Address> tls={},const a64::SignalEntry *signal=nullptr,bool bounded=false) {
        if(!main_work_cpu)return cpu.call(entry,args,stack,budget,floats,tls,signal);
        try {
            auto result=cpu.call_resource_metered(entry,args,stack,floats,tls,signal,
                bounded?std::optional<std::uint64_t>{budget}:std::nullopt);
            main_work_cpu->account(cpu.active_ticks());
            return result;
        }catch(...){
            const auto failure=std::current_exception();
            main_work_cpu->account(cpu.active_ticks());
            std::rethrow_exception(failure);
        }
    }
    a64::ExecutionResult execute_cpu_bounded(Address entry,std::span<const std::uint64_t> args,Address stack,
                                             std::uint64_t budget,std::span<const a64::Vector> floats={},
                                             std::optional<Address> tls={},const a64::SignalEntry *signal=nullptr) {
        return execute_cpu(entry,args,stack,budget,floats,tls,signal,true);
    }
    struct NativeActivityCpu {
        Impl &p;
        std::unique_ptr<a64::GuestCpu::ExecutionContext> state;
        std::uint64_t accounted = 0, witness = 0;
        bool installed = false;
        explicit NativeActivityCpu(Impl &owner) : p(owner), witness(p.native_charged_ticks) {
            const auto budget = p.runtime.native_instruction_budget();
            auto grant = std::min(budget.retained, budget.shared);
            if (budget.slice) grant = std::min(grant, *budget.slice);
            if (!grant) bad("BUDGET", "NativeActivity has no remaining invocation allowance");
            state = p.cpu.prepare_execution_context([this](const a64::GuestCpu::ExecutionBoundary &boundary) {
                account(boundary.ticks);
                const auto remaining = p.runtime.native_instruction_budget();
                auto work = std::min(remaining.retained, remaining.shared);
                if (remaining.slice) work = std::min(work, *remaining.slice);
                if (!p.cpu.limit_execution_slice(work)) std::terminate();
                return remaining.retained;
            }, 0);
            if (!p.cpu.set_execution_slice_allowance(*state, grant) || !p.cpu.exchange_execution_context(*state))
                bad("NATIVE_ACTIVITY_STATE", "NativeActivity requires an idle owned CPU execution");
            installed = true;
        }
        void account(std::uint64_t ticks) {
            if (ticks < accounted || p.native_charged_ticks < witness) std::terminate();
            const auto elapsed = ticks - accounted;
            const auto nested = p.native_charged_ticks - witness;
            if (nested > elapsed) std::terminate();
            const auto uncharged = elapsed - nested;
            const auto allowance = p.runtime.thread_instruction_budget();
            const auto debit = std::min(uncharged, allowance);
            if (debit > UINT64_MAX - p.native_charged_ticks) bad("BUDGET", "NativeActivity accounting exhausted");
            p.runtime.charge_thread_instructions(debit);
            p.native_charged_ticks += debit;
            accounted = ticks;
            witness = p.native_charged_ticks;
            if (uncharged > allowance) bad("BUDGET", "NativeActivity exceeded its remaining invocation allowance");
        }
        void finish() { account(p.cpu.active_ticks()); }
        ~NativeActivityCpu() {
            if (installed && (!p.cpu.execution_idle() || !p.cpu.exchange_execution_context(*state))) std::terminate();
        }
    };
    template<class Function> void native_activity_cpu(Function &&operation) {
        if(main_work_cpu){operation();return;}
        NativeActivityCpu execution(*this);
        try { operation(); execution.finish(); }
        catch (...) {
            const auto failure = std::current_exception();
            try { execution.finish(); } catch (...) { process->checkpoint(); }
            std::rethrow_exception(failure);
        }
    }
    bool native_activity_backing(Address address, std::size_t size,
                                 const std::optional<a64::GuestMemory::WordIdentity> &identity,
                                 a64::Permission permission) const noexcept {
        if (!address || !size || !identity || !memory.accessible(address, size, permission)) return false;
        for (std::size_t offset = 0; offset < size; offset += a64::GuestMemory::page_size) {
            const auto current = memory.word_identity(address + offset, permission);
            if (!current || !current->same_backing(*identity) ||
                current->backing_offset() != identity->backing_offset() + offset) return false;
        }
        return true;
    }
    void native_activity_mapping(Address address, std::size_t size,
                                 const std::optional<a64::GuestMemory::WordIdentity> &identity) {
        if (!address) return;
        // Retire only the allocation this record published, never a replacement
        // guest mapping installed at the same numerical address.
        if (native_activity_backing(address, size, identity, a64::Permission::read)) memory.unmap_range(address, size);
        const auto entry = std::find(mappings.begin(), mappings.end(), address);
        if (entry != mappings.end()) mappings.erase(entry);
    }
    void cancel_activity_host_work(NativeActivityStorage &storage) noexcept {
        auto &scope=*storage.work_scope; scope.active=false;
        for(auto &credit:scope.credits)if(credit.serial && !credit.posted){credit={};--scope.outstanding;}
        storage.work={};storage.work_head=storage.work_count=0;
    }
    a64::Fault admit_activity_host_work(std::string_view name, a64::ServiceState &state) noexcept {
        host_work_rejection={};
        const auto refuse=[&](a64::Fault fault,std::string_view message){host_work_rejection=message;return fault;};
        try {
            if(std::this_thread::get_id()!=owner_thread || closed || native_closing || native_activity_failed ||
                !native_activity_storage || cpu.execution_idle())
                return refuse(a64::Fault::invalid_call,"Native Activity work requires an actual live native call owner");
            if(active_native_task) {
                if(!posix.execution_binding_valid(active_native_task->binding))
                    return refuse(a64::Fault::invalid_call,"Native Activity work has a stale native thread binding");
            } else if(!native_depth || frames.empty() || !attached || !posix.thread_register_state(posix.thread_pointer()))
                return refuse(a64::Fault::invalid_call,"Native Activity work has no actual logical JNI/native owner");
            auto &storage=*native_activity_storage;
            if(state.registers[0]!=storage.address || storage.destroy_started || !storage.work_scope->active ||
                (!storage.created && !(native_activity_dispatching && native_activity_initialized)))
                return refuse(a64::Fault::invalid_call,"Native Activity work identifies a retired or different incarnation");
            validate_native_activity();
            android::NativeActivityHostOperation operation;
            if(name=="ANativeActivity_finish")operation=android::NativeActivityHostOperation::finish;
            else if(name=="ANativeActivity_hideSoftInput")operation=android::NativeActivityHostOperation::hide_soft_input;
            else if(name=="ANativeActivity_showSoftInput")operation=android::NativeActivityHostOperation::show_soft_input;
            else return refuse(a64::Fault::unsupported_service,"Native Activity window format/flags require an actual supported host policy consumer");
            if(operation!=android::NativeActivityHostOperation::finish && static_cast<std::uint32_t>(state.registers[1]))
                return refuse(a64::Fault::unsupported_service,"Native Activity soft input supports only actual flag-zero dispatch");
            auto &scope=*storage.work_scope;
            if(scope.outstanding>=scope.credits.size() || storage.work_count>=storage.work.size() || next_host_work==UINT64_MAX)
                return refuse(a64::Fault::unsupported_service,"Native Activity queued-plus-posted work capacity exhausted");
            const auto slot=std::find_if(scope.credits.begin(),scope.credits.end(),[](const auto &credit){return !credit.serial;});
            if(slot==scope.credits.end())return refuse(a64::Fault::invalid_call,"Native Activity work credit invariant failed");
            android::NativeActivityHostWork work;
            work.activity=storage.activity;work.content=storage.content;work.window_generation=storage.generation;
            work.serial=next_host_work++;work.credit_slot=static_cast<std::uint32_t>(slot-scope.credits.begin());
            work.operation=operation;work.scope=storage.work_scope;
            storage.work[(storage.work_head+storage.work_count)%storage.work.size()]=work;
            *slot={work.serial,false};++scope.outstanding;++storage.work_count;
            return a64::Fault::none;
        }catch(...){return refuse(a64::Fault::unsupported_service,"Native Activity copied work admission failed before supported dispatch");}
    }
    void retire_native_activity() {
        if (!native_activity_storage) return;
        auto &storage = *native_activity_storage;
        cancel_activity_host_work(storage);
        if (storage.queue) {
            if (posix.current_input_queue() != storage.queue)
                bad("NATIVE_INPUT_STATE", "NativeActivity cannot retire another input queue incarnation");
            posix.retire_input_queue(storage.queue);
            storage.queue = 0;
        }
        if (storage.window) {
            if (!native_windows) bad("NATIVE_ACTIVITY_WINDOW", "Native window registry is unavailable during retirement");
            native_windows->release_activity(storage.window);
            storage.window.reset(); storage.window_id = 0;
        }
        native_activity_mapping(storage.saved, storage.saved_size, storage.saved_identity);
        native_activity_mapping(storage.paths, storage.path_size, storage.path_identity);
        native_activity_mapping(storage.address, a64::GuestMemory::page_size, storage.identity);
        for (const auto handle : {storage.manager, storage.clazz, storage.content_root}) {
            const auto found = find_reference(handle);
            if (found != refs.end() && found->second.global && !found->second.weak) erase(handle, true);
        }
        native_activity_storage.reset();
    }
    void validate_native_activity() {
        if (!native_activity_storage) bad("NATIVE_ACTIVITY_STATE", "NativeActivity has no live backing");
        const auto &storage = *native_activity_storage;
        std::array<std::uint8_t, 80> actual{};
        if (!native_activity_backing(storage.address, a64::GuestMemory::page_size, storage.identity, a64::read_write) ||
            !memory.read(storage.address, actual))
            bad("NATIVE_ACTIVITY_MAPPING", "NativeActivity ABI backing is no longer its owned writable allocation");
        for (std::size_t i = 0; i < actual.size(); ++i)
            if ((i < 56 || i >= 64) && actual[i] != storage.canonical[i])
                bad("NATIVE_ACTIVITY_METADATA", "NativeActivity canonical metadata or callback-table pointer changed");
        std::array<std::uint8_t, 8192> text{};
        if (!native_activity_backing(storage.paths, storage.path_size, storage.path_identity, a64::Permission::read) ||
            !memory.read(storage.paths, std::span(text).first(storage.path_bytes.size())) ||
            !std::equal(storage.path_bytes.begin(), storage.path_bytes.end(), text.begin()) ||
            resolve(storage.clazz) != storage.activity || resolve(storage.manager) != storage.assets ||
            resolve(storage.content_root) != storage.content)
            bad("NATIVE_ACTIVITY_METADATA", "NativeActivity canonical paths or global Java identities changed");
    }
    void dynamic_open(std::string_view name) try {
        if(native_extension_active)bad("LOAD_STATE","Recursive native extension is unsupported");
        native_extension_active=true;
        struct ExtensionEnd {Impl &p;~ExtensionEnd(){p.native_extension_active=false;}} extension_end{*this};
        process->checkpoint();
        if(std::this_thread::get_id()!=owner_thread || closed || dynamic_poisoned)
            throw elf::ElfError("AETHER_ELF_LOAD_STATE","Dynamic module owner is unavailable");
        if(imports.has_library(name))return;
        for(const auto &module:loader.modules())
            if((module.image.soname==name || module.image.declared_soname==name) && module.initialized)return;
        if(!module_provider)throw elf::ElfError("AETHER_ELF_SOURCE","No authorized module inventory");
        // Do not relax the constructor-time extension guard or expose provisional modules.
        for(const auto &module:loader.modules())if(!module.initialized)
            throw elf::ElfError("AETHER_ELF_LOAD_STATE","Constructor-time module extension is unsupported");
        auto modules=module_provider(name);
        Scope scope(*this);
        loader.extend(modules,name);
        try {loader.initialize(cpu,scope.stack(),posix.thread_pointer());process->checkpoint();}
        catch(const elf::InitializerError &failure){dynamic_poisoned=true;throw bionic::DynamicLinkExecution{failure.fault};}
        catch(...){dynamic_poisoned=true;throw;}
        // Plain dlopen runs ELF constructors, never JNI_OnLoad or JNI-root rebinding.
    }catch(const elf::ElfError &failure){throw bionic::DynamicLinkSourceError{failure.code};}
    void clear_attachment() {
        while(!frames.empty())pop();
        pending_exception(0);
        for(auto it=buffers.begin();it!=buffers.end();) {
            if(it->second.context!=context){++it;continue;}
            memory.unmap(it->first);runtime.release(it->second.object);buffer_bytes-=it->second.bytes;it=buffers.erase(it);
        }
        update_buffer_metrics();attached=false;
    }
    bionic::GuestPosixServices::ThreadExecution thread_guest_call(Address entry,Address argument,Address stack,Address tls,std::uint64_t budget) {
        process->checkpoint();
        if(main_work_cpu){
            const auto before=cpu.active_ticks();
            auto result=execute_cpu_bounded(entry,std::array{argument},stack,budget,{},tls);
            return {std::move(result),cpu.active_ticks()-before};
        }
        // Only the configured native root has an independent hard slice grant.
        // Do not turn that transient grant into its permanent fatal allowance.
        const bool retained_root=active_native_task && native_depth==1 && cpu.execution_idle();
        const auto available=std::min(budget,retained_root?runtime.native_instruction_budget().retained:runtime.thread_instruction_budget());
        bionic::GuestPosixServices::ThreadExecution out;
        if(!available){out.result.fault=a64::Fault::budget;return out;}
        const auto before=cpu.active_ticks(),charged_before=native_charged_ticks;
        out.result=execute_cpu(entry,std::array{argument},stack,available,{},tls);
        out.ticks=cpu.active_ticks()-before;
        // Nested native workers debit their context and its parent on return.
        // Their inclusive CPU ticks must not be charged again by this caller.
        const auto nested=native_charged_ticks-charged_before;
        const auto uncharged=out.ticks>=nested?out.ticks-nested:0;
        const auto remaining=runtime.thread_instruction_budget();
        const auto charged=std::min(uncharged,remaining);
        runtime.charge_thread_instructions(charged);native_charged_ticks+=charged;
        if(uncharged>remaining && out.result.fault==a64::Fault::none){out.result.returned=false;out.result.fault=a64::Fault::budget;}
        return out;
    }
    bionic::GuestPosixServices::ThreadExecution finalize_bound_thread(Address stack,std::uint64_t budget) {
        return posix.finish_current_thread([&](Address entry,Address argument,std::uint64_t remaining){
            Scope scope(*this);
            return thread_guest_call(entry,argument,stack,posix.thread_pointer(),remaining);
        },budget);
    }
    bionic::GuestPosixServices::ThreadExecution run_worker(Address entry,Address argument,Address stack,Address tls,std::uint64_t budget) {
        const auto before=cpu.active_ticks();a64::ExecutionResult result;bool finalization_failed=false;
        try {runtime.run_native_thread([&]{
            JniExecutionState previous;
            exchange_jni_execution(previous);
            // This native root uses its owned pthread stack, not a JNI Scope
            // stack lease. The marker prevents borrowing a live attachment.
            native_depth=1;context=tls;current_environment=tls+0x200;attached=false;
            active_execution_token=dex::Scheduler::execution_token();
            struct Restore {
                Impl &p;JniExecutionState previous;
                ~Restore(){
                    p.clear_attachment();
                    const auto charged=p.native_charged_ticks;
                    p.exchange_jni_execution(previous);
                    // Synchronous nested CPU ticks include this child. Runtime
                    // already debits its parent; carry the charge witness once
                    // so the enclosing thread_guest_call does not debit twice.
                    if(charged>UINT64_MAX-p.native_charged_ticks)std::terminate();
                    p.native_charged_ticks+=charged;
                }
            } restore{*this,std::move(previous)};
            write(current_environment,function_table,8);
            result=thread_guest_call(entry,argument,stack,tls,budget).result;
            if(result.returned || result.fault==a64::Fault::thread_exit){
                runtime.run_thread_finalizers([&]{
                    const auto spent=cpu.active_ticks()-before;
                    const auto cleanup=finalize_bound_thread(stack,spent>=budget?0:budget-spent);
                    if(cleanup.finalization_failed){result=cleanup.result;result.returned=false;finalization_failed=true;}
                });
            }
        },[this](std::optional<std::int32_t> nice){return posix.current_thread_priority(nice);},budget);}
        catch(const ThreadExit &exit){process->checkpoint();if(!finalization_failed){posix.request_thread_exit(exit.value);result.fault=a64::Fault::thread_exit;result.registers[0]=exit.value;}}
        return {result,cpu.active_ticks()-before,finalization_failed};
    }
    void pending_exception(ObjectId object) {
        if (object && object != allocation_error)
            runtime.retain(object);
        if (pending && pending != allocation_error)
            runtime.release(pending);
        pending = object;
    }
    template <class Function> Handle allocation_reference(Function &&function) {
        const auto exhausted = [&]() -> Handle {
            // Preparation is mandatory before native execution. Reporting an
            // exhausted heap/reference/root quota must not allocate another
            // object, pin or diagnostic string. Cleanup preserves a prior
            // exception, particularly PopLocalFrame with an exception pending.
            if (!allocation_error)
                bad("STATE", "JNI allocation error reserve is unavailable");
            if (!pending)
                pending = allocation_error;
            return 0;
        };
        try { return function(); }
        catch (const std::bad_alloc &) { return exhausted(); }
        catch (const dex::DexError &failure) {
            if (failure.code != "AETHER_JNI_REFERENCE_LIMIT" && failure.code != "AETHER_JNI_FIELD_LIMIT" &&
                failure.code != "AETHER_JNI_METHOD_LIMIT" &&
                failure.code != "AETHER_DEX_ROOT_LIMIT" &&
                failure.code != "AETHER_DEX_HEAP_LIMIT")
                throw;
            return exhausted();
        }
    }
    void java_error(std::string_view type, std::u16string_view message = {}) {
        try {
            runtime.raise(type, message);
        } catch (const dex::JavaException &e) {
            pending_exception(e.object);
        }
    }
    void check_pending() {
        if (!pending)
            return;
        const auto exception = pending;
        pending_exception(0);
        throw dex::JavaException(exception);
    }
    a64::ExecutionResult call(Address address, std::span<const std::uint64_t> args, Address stack,
                              std::span<const a64::Vector> floats = {}, std::uint64_t budget = 1'000'000,
                              Address *returned_pointer = nullptr) {
        process->checkpoint();
        const auto before=cpu.active_ticks();
        const auto result = execute_cpu(address, args, stack, budget, floats,posix.thread_pointer());
        if(result.fault==a64::Fault::process_exit){process->request_exit(result.detail);process->checkpoint();}
        if(result.fault==a64::Fault::thread_exit)runtime.exit_current_thread(result.registers[0]);
        if (!result.returned)
            bad("NATIVE_EXECUTION", std::string(a64::fault_name(result.fault)) + ": " + error + "; " +
                                        std::string(posix.last_rejection()));
        // Preserve a normally returned save pointer before later JNI checks.
        if (returned_pointer) *returned_pointer = result.registers[0];
        if (critical_active())
            bad("CRITICAL", "Native return with an unreleased JNI critical copy");
        (void)before; // Native factory peers run at the audited idle host pump.
        return result;
    }
    Value decode(std::uint64_t bits, std::string_view type) {
        if (dex::reference_type(type))
            return Value::reference(resolve(bits));
        return dex::type_words(type) == 2 ? Value::wide(bits) : Value::word(static_cast<std::uint32_t>(bits));
    }
    std::vector<Value> arguments(const dex::Prototype &prototype, a64::ServiceState &state,
                                 unsigned variant, unsigned first_argument = 3) {
        std::vector<Value> result;
        unsigned gp = first_argument, fp = 0;
        Address stack = state.stack_pointer, gr_top = 0, vr_top = 0;
        std::int32_t gr_off = 0, vr_off = 0;
        if (variant == 1) {
            const auto list = state.registers[first_argument];
            stack = read(list, 8);
            gr_top = read(list + 8, 8);
            vr_top = read(list + 16, 8);
            gr_off = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(read(list + 24, 4)));
            vr_off = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(read(list + 28, 4)));
            if (gr_off < -64 || gr_off > 0 || gr_off % 8 || vr_off < -128 || vr_off > 0 || vr_off % 16)
                bad("VARARGS", "Invalid AArch64 va_list register offsets");
        }
        for (std::size_t i = 0; i < prototype.parameters.size(); ++i) {
            const auto &type = runtime.image().types.at(prototype.parameters[i]);
            const bool floating = type == "F" || type == "D";
            std::uint64_t bits = 0;
            if (variant == 2)
                bits = read(state.registers[first_argument] + i * 8, 8);
            else if (variant == 1) {
                auto &offset = floating ? vr_off : gr_off;
                if (offset < 0) {
                    const auto top = floating ? vr_top : gr_top;
                    if (top < static_cast<std::uint64_t>(-offset))
                        bad("VARARGS", "va_list address underflow");
                    bits = read(top - static_cast<std::uint64_t>(-offset), 8);
                    offset += floating ? 16 : 8;
                } else {
                    bits = read(stack, 8);
                    stack += 8;
                }
            } else if (floating && fp < 8)
                bits = state.vectors[fp++][0];
            else if (!floating && gp < 8)
                bits = state.registers[gp++];
            else {
                bits = read(stack, 8);
                stack += 8;
            }
            if (type == "F" && variant != 2)
                bits = std::bit_cast<std::uint32_t>(static_cast<float>(std::bit_cast<double>(bits)));
            result.push_back(decode(bits, type));
        }
        return result;
    }
    bool method_class_compatible(const MethodId &id, ObjectId supplied) {
        const auto &method = runtime.image().methods.at(id.index);
        if (!method.declared)
            return supplied == id.owner; // Preserve symbolic provider/core handling.
        const auto actual = std::string(runtime.represented_class(supplied));
        const auto &declaring = runtime.image().types.at(method.owner);
        const auto *definition = runtime.image().definition(declaring);
        if (!definition)
            bad("METHOD_ID", "Owned method ID has no declaring class inventory");
        // Constructors are never inherited, nor are static interface methods.
        if (method.name == "<init>" || (id.is_static && (definition->flags & 0x200)))
            return actual == declaring;
        // Canonical IDs must still be the exact declaration lookup would
        // choose through this class. Ancestry alone would admit overridden or
        // hidden base methods. This shared lookup path never initializes it.
        return runtime.jni_method_compatible(id.index, actual);
    }
    void callback(unsigned slot, a64::ServiceState &state, bool full_frame) {
        const bool stat = slot >= 114;
        const bool nonvirtual = slot >= 64 && slot <= 93;
        const auto first = stat ? 114u : nonvirtual ? 64u : 34u;
        const auto category = (slot - first) / 3, variant = (slot - first) % 3;
        const auto it = methods.find(state.registers[nonvirtual ? 3 : 2]);
        if (it == methods.end() || it->second.is_static != stat)
            bad("METHOD_ID", "Invalid JNI method ID/category");
        const auto &id = it->second;
        const auto &method = runtime.image().methods.at(id.index);
        const auto &prototype = runtime.image().prototypes.at(method.prototype);
        const auto &type = runtime.image().types.at(prototype.return_type);
        if (!full_frame && (type == "F" || type == "D" || (variant == 0 &&
            std::any_of(prototype.parameters.begin(), prototype.parameters.end(), [this](dex::Index parameter) {
                const auto &parameter_type = runtime.image().types.at(parameter);
                return parameter_type == "F" || parameter_type == "D";
            }))))
            bad("FRAME", "JNI floating method calls require a full register frame");
        constexpr std::string_view returns = "LZBCSIJFDV";
        if ((category == 0 && !dex::reference_type(type)) ||
            (category != 0 && type != returns.substr(category, 1)))
            bad("SIGNATURE", "JNI Call* return category disagrees with method prototype");
        auto args = arguments(prototype, state, variant, nonvirtual ? 4u : 3u);
        if (stat) {
            if (!method_class_compatible(id, resolve(state.registers[1])))
                bad("METHOD_ID", "Method ID does not belong to the supplied class");
        } else {
            const auto receiver = resolve(state.registers[1]);
            if (nonvirtual) {
                const auto supplied = resolve(state.registers[2]);
                if (!method_class_compatible(id, supplied))
                    bad("METHOD_ID", "Nonvirtual method ID is incompatible with the supplied class");
                if (!runtime.assignable(receiver, runtime.represented_class(supplied)))
                    bad("METHOD_ID", "Nonvirtual receiver is incompatible with the supplied class");
            }
            args.insert(args.begin(), Value::reference(receiver));
        }
        ++metrics.managed_callbacks;
        // Explicit-class calls deliberately bypass virtual target selection.
        const auto result = stat || nonvirtual ? runtime.invoke(id.index, args)
                                              : runtime.invoke_virtual(id.index, args);
        if (dex::reference_type(type))
            state.registers[0] = reference(result.bits);
        else if (type == "F" || type == "D")
            state.vectors[0] = {result.bits, 0};
        else
            state.registers[0] = result.bits;
    }
    void construct(unsigned slot, a64::ServiceState &state, bool full_frame) {
        const auto owner = resolve(state.registers[1]);
        const auto type = std::string(runtime.represented_class(owner));
        const auto found = methods.find(state.registers[2]);
        if (found == methods.end() || found->second.is_static)
            bad("METHOD_ID", "NewObject requires a constructor ID from the supplied class");
        const auto &method = runtime.image().methods.at(found->second.index);
        if (!method.declared && found->second.owner != owner)
            bad("METHOD_ID", "Symbolic constructor ID was not obtained through the supplied class");
        const auto &prototype = runtime.image().prototypes.at(method.prototype);
        if (method.name != "<init>" || runtime.image().types.at(method.owner) != type ||
            runtime.image().types.at(prototype.return_type) != "V")
            bad("METHOD_ID", "NewObject requires the supplied class's void constructor");
        if (!full_frame && slot == 28 && std::any_of(prototype.parameters.begin(), prototype.parameters.end(),
                                      [this](dex::Index parameter) {
                const auto &parameter_type = runtime.image().types.at(parameter);
                return parameter_type == "F" || parameter_type == "D";
            }))
            bad("FRAME", "JNI floating constructor arguments require a full register frame");
        auto args = arguments(prototype, state, slot - 28);
        // Allocation initializes the class but does not run an instance
        // constructor. Retain its fresh receiver before invoking the exact ID.
        const auto object = runtime.new_object(type);
        const auto handle = reference(object);
        try {
            args.insert(args.begin(), Value::reference(object));
            ++metrics.managed_callbacks;
            (void)runtime.invoke(found->second.index, args);
        } catch (...) {
            erase(handle, false);
            throw;
        }
        state.registers[0] = handle;
    }
    Handle method_id(dex::Index index, ObjectId lookup_owner, bool stat) {
        const auto &method = runtime.image().methods.at(index);
        if (method.declared && bool(method.flags & 8) != stat)
            bad("METHOD_ID", "Owned method ID static kind differs from its declaration");
        const auto owner = method.declared ? ObjectId{0} : lookup_owner;
        if (!method.declared && !owner)
            bad("METHOD_ID", "Symbolic method ID requires its actual lookup Class");
        for (const auto &[handle, id] : methods)
            if (id.index == index && id.owner == owner && id.is_static == stat)
                return handle;
        if (methods.size() >= 4096)
            bad("METHOD_LIMIT", "Too many JNI method IDs");
        const auto handle = identity();
        methods.emplace(handle, MethodId{index, owner, stat});
        return handle;
    }
    void method_lookup(a64::ServiceState &state, bool stat) {
        const auto owner = resolve(state.registers[1]);
        const auto type = runtime.represented_class(owner);
        const auto name = text(state.registers[2], 1024), signature = text(state.registers[3], 1024);
        dex::Index index;
        try {
            index = runtime.lookup_jni_method(type, name, signature, stat);
        } catch (const dex::DexError &e) {
            if (e.code != "AETHER_DEX_METHOD_NOT_FOUND" && e.code != "AETHER_DEX_SIGNATURE")
                throw;
            error = e.code + ": " + e.what();
            java_error("Ljava/lang/NoSuchMethodError;");
            state.registers[0] = 0;
            return;
        }
        state.registers[0] = method_id(index, owner, stat);
    }
    Handle field_id(dex::Index index) {
        for (const auto &[handle, field] : fields)
            if (field == index)
                return handle;
        if (fields.size() >= 4096)
            bad("FIELD_LIMIT", "Too many JNI field IDs");
        const auto handle = identity();
        fields.emplace(handle, index);
        return handle;
    }
    void field_lookup(a64::ServiceState &state, bool stat) {
        const auto type = std::string(runtime.represented_class(resolve(state.registers[1])));
        const auto name = text(state.registers[2], 1024);
        const auto descriptor = text(state.registers[3], 1024);
        dex::Index index;
        try {
            // Runtime initialization precedes semantic signature validation and lookup.
            index = stat ? runtime.lookup_static_field(type, name, descriptor)
                         : runtime.lookup_instance_field(type, name, descriptor);
        } catch (const dex::DexError &e) {
            if (e.code != "AETHER_DEX_FIELD_NOT_FOUND")
                throw;
            error = e.code + ": " + e.what();
            java_error("Ljava/lang/NoSuchFieldError;");
            state.registers[0] = 0;
            return;
        }
        state.registers[0] = field_id(index);
    }
    void instance_field_access(unsigned slot, a64::ServiceState &state, bool full_frame) {
        const bool set = slot >= 104;
        const auto category = slot - (set ? 104u : 95u);
        constexpr std::string_view categories = "LZBCSIJFD";
        const auto found = fields.find(state.registers[2]);
        if (found == fields.end())
            bad("FIELD_ID", "Invalid or foreign JNI instance field ID");
        const auto index = found->second;
        const auto &field = runtime.image().fields.at(index);
        if (!field.declared || (field.flags & 8))
            bad("FIELD_ID", "JNI instance accessor requires an owned nonstatic field ID");
        const auto type = std::string(runtime.image().types.at(field.type));
        if ((category == 0 && !dex::reference_type(type)) ||
            (category != 0 && type != categories.substr(category, 1)))
            bad("SIGNATURE", "JNI instance field category disagrees with declaration");
        const bool floating = category >= 7;
        if (floating && !full_frame)
            bad("FRAME", "JNI floating instance field access requires a full register frame");
        const auto receiver = resolve(state.registers[1]);
        if (set) {
            const auto bits = floating ? state.vectors[0][0] : state.registers[3];
            runtime.set_instance_field(receiver, index, decode(bits, type));
        } else {
            const auto result = runtime.get_instance_field(receiver, index);
            if (category == 0)
                state.registers[0] = reference(result.bits);
            else if (floating)
                state.vectors[0] = {result.bits, 0};
            else
                state.registers[0] = result.bits;
        }
    }
    void static_field_access(unsigned slot, a64::ServiceState &state, bool full_frame) {
        const bool set = slot >= 154;
        const auto category = slot - (set ? 154u : 145u);
        constexpr std::string_view categories = "LZBCSIJFD";
        const auto found = fields.find(state.registers[2]);
        if (found == fields.end())
            bad("FIELD_ID", "Invalid or foreign JNI static field ID");
        const auto index = found->second;
        const auto &field = runtime.image().fields.at(index);
        if (!field.declared || !(field.flags & 8))
            bad("FIELD_ID", "JNI static accessor requires an owned static field ID");
        const auto type = std::string(runtime.image().types.at(field.type));
        if ((category == 0 && !dex::reference_type(type)) ||
            (category != 0 && type != categories.substr(category, 1)))
            bad("SIGNATURE", "JNI static field category disagrees with declaration");
        const auto supplied = std::string(runtime.represented_class(resolve(state.registers[1])));
        if (!runtime.static_field_compatible(index, supplied))
            bad("FIELD_ID", "Static field ID is incompatible with the supplied class");
        const bool floating = category >= 7;
        if (floating && !full_frame)
            bad("FRAME", "JNI floating static field access requires a full register frame");
        if (set) {
            const auto bits = floating ? state.vectors[0][0] : state.registers[3];
            runtime.set_static_uninitialized(index, decode(bits, type));
        } else {
            const auto result = runtime.get_static_uninitialized(index);
            if (category == 0)
                state.registers[0] = reference(result.bits);
            else if (floating)
                state.vectors[0] = {result.bits, 0};
            else
                state.registers[0] = result.bits;
        }
    }
    void update_buffer_metrics() {
        metrics.string_buffers = static_cast<std::size_t>(std::count_if(
            buffers.begin(), buffers.end(), [](const auto &entry) { return !entry.second.component; }));
    }
    bool critical_active() const {
        return std::any_of(buffers.begin(), buffers.end(), [this](const auto &entry) {
            return entry.second.context == context && entry.second.critical;
        });
    }
    Address copy_buffer(ObjectId id, std::span<const std::uint8_t> bytes,
                        bool utf8, char component = 0, bool critical = false) {
        // Strings and primitive copies share the original buffer count, byte and
        // address budgets. Empty arrays still get a distinct, releasable address.
        if (bytes.size() > 1024 * 1024)
            bad("BUFFER_LIMIT", "JNI copy buffer exceeds the shared byte budget");
        const auto size = (std::max(std::size_t{1}, bytes.size()) + 4095) & ~std::size_t{4095};
        if (buffers.size() >= 256 || size > 1024 * 1024 - buffer_bytes || buffer_next + size >= 0x60000000)
            bad("BUFFER_LIMIT", "JNI copy buffer quota exhausted");
        const auto address = buffer_next;
        buffer_next += size;
        memory.map(address, size, a64::read_write);
        bool retained = false;
        try {
            if (!bytes.empty() && !memory.write(address, bytes))
                bad("MEMORY", "Cannot populate JNI copy buffer");
            if (!component)
                memory.protect(address, a64::Permission::read);
            runtime.retain(id);
            retained = true;
            buffers.emplace(address, Buffer{id, utf8, size, context, component, critical});
        } catch (...) {
            if (retained)
                runtime.release(id);
            memory.unmap(address);
            throw;
        }
        buffer_bytes += size;
        update_buffer_metrics();
        return address;
    }
    Address string_buffer(ObjectId id, bool utf8, bool critical = false) {
        const auto string = runtime.string(id);
        std::vector<std::uint8_t> bytes;
        if (utf8) {
            const auto value = modified_utf8(string);
            bytes.assign(value.begin(), value.end());
            bytes.push_back(0);
        } else {
            for (auto c : string) {
                bytes.push_back(static_cast<std::uint8_t>(c));
                bytes.push_back(static_cast<std::uint8_t>(c >> 8));
            }
            bytes.push_back(0);
            bytes.push_back(0);
        }
        return copy_buffer(id, bytes, utf8, 0, critical);
    }
    void release_string(ObjectId id, Address address, bool utf8, bool critical = false) {
        const auto it = buffers.find(address);
        if (it == buffers.end() || it->second.object != id || it->second.utf8 != utf8 ||
            it->second.context != context || it->second.component || it->second.critical != critical)
            bad("BUFFER", "Mismatched or double JNI string release");
        memory.unmap(address);
        runtime.release(id);
        buffer_bytes -= it->second.bytes;
        buffers.erase(it);
        update_buffer_metrics();
    }
    static unsigned primitive_width(char component) {
        constexpr std::string_view types = "ZBCSIJFD";
        constexpr std::array<unsigned, 8> widths{1, 1, 2, 2, 4, 8, 4, 8};
        const auto kind = types.find(component);
        if (kind == std::string_view::npos)
            bad("ARRAY_TYPE", "Expected a primitive JNI array");
        return widths[kind];
    }
    char primitive_component(ObjectId id) {
        const auto type = runtime.object_type(id);
        if (type.size() != 2 || type[0] != '[')
            bad("ARRAY_TYPE", "Expected a primitive JNI array");
        (void)primitive_width(type[1]);
        return type[1];
    }
    Address array_elements(ObjectId id, char component, bool critical) {
        if (primitive_component(id) != component)
            bad("ARRAY_TYPE", "JNI array elements have the wrong component type");
        const auto width = primitive_width(component);
        const auto length = runtime.array_length(id);
        if (length > (1024 * 1024) / width)
            bad("BUFFER_LIMIT", "JNI primitive copy exceeds the shared byte budget");
        std::vector<std::uint8_t> bytes(length * width);
        for (std::size_t n = 0; n < length; ++n) {
            const auto value = runtime.array_get(id, static_cast<std::int32_t>(n)).bits;
            for (unsigned b = 0; b < width; ++b)
                bytes[n * width + b] = static_cast<std::uint8_t>(value >> (8 * b));
        }
        return copy_buffer(id, bytes, false, component, critical);
    }
    void release_array(ObjectId id, Address address, std::int32_t mode, char component, bool critical) {
        if (mode != 0 && mode != 1 && mode != 2)
            bad("BUFFER_MODE", "JNI array release mode must be 0, JNI_COMMIT or JNI_ABORT");
        const auto it = buffers.find(address);
        if (it == buffers.end() || it->second.object != id || it->second.context != context ||
            it->second.component != component || it->second.critical != critical)
            bad("BUFFER", "Mismatched or double JNI array release");
        if (primitive_component(id) != component)
            bad("ARRAY_TYPE", "JNI array release has the wrong component type");
        if (mode != 2) {
            const auto width = primitive_width(component);
            const auto length = runtime.array_length(id);
            // Read the complete copy before changing managed storage, so a bad
            // guest range cannot leave a partially committed Java array.
            std::vector<std::uint8_t> bytes(length * width);
            if (!bytes.empty() && !memory.read(address, bytes))
                bad("MEMORY", "JNI array copy is no longer readable");
            for (std::size_t n = 0; n < length; ++n) {
                std::uint64_t value = 0;
                for (unsigned b = 0; b < width; ++b)
                    value |= std::uint64_t(bytes[n * width + b]) << (8 * b);
                runtime.array_set(id, static_cast<std::int32_t>(n),
                                  decode(value, std::string_view(&component, 1)));
            }
        }
        // JNI_COMMIT copies back while retaining this exact copy and its root.
        // Mode 0 copies back and releases; JNI_ABORT releases without copying.
        if (mode != 1) {
            memory.unmap(address);
            runtime.release(id);
            buffer_bytes -= it->second.bytes;
            buffers.erase(it);
            update_buffer_metrics();
        }
    }
    void string_region(a64::ServiceState &state, bool utf8) {
        const auto value = runtime.string(resolve(state.registers[1]));
        const auto begin = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.registers[2]));
        const auto count = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.registers[3]));
        if (begin < 0 || count < 0 || static_cast<std::size_t>(begin) > value.size() ||
            static_cast<std::size_t>(count) > value.size() - begin)
            runtime.raise("Ljava/lang/StringIndexOutOfBoundsException;");
        const auto region = value.substr(static_cast<std::size_t>(begin), static_cast<std::size_t>(count));
        std::vector<std::uint8_t> bytes;
        if (utf8) {
            const auto encoded = modified_utf8(region);
            bytes.assign(encoded.begin(), encoded.end());
        } else {
            bytes.reserve(region.size() * 2);
            for (const auto unit : region) {
                bytes.push_back(static_cast<std::uint8_t>(unit));
                bytes.push_back(static_cast<std::uint8_t>(unit >> 8));
            }
        }
        // Region functions write exactly the selected units/encoded bytes and
        // never append a terminator. Zero-length regions need no guest buffer.
        if (!bytes.empty() && (!memory.accessible(state.registers[4], bytes.size(), a64::Permission::write) ||
                               !memory.write(state.registers[4], bytes)))
            bad("MEMORY", "JNI string region exceeds the writable guest buffer");
    }
    void array_region(unsigned slot, a64::ServiceState &state) {
        const bool set = slot >= 207;
        const auto kind = slot - (set ? 207u : 199u);
        constexpr std::string_view types = "ZBCSIJFD";
        constexpr std::array<unsigned, 8> widths{1, 1, 2, 2, 4, 8, 4, 8};
        const auto id = resolve(state.registers[1]);
        if (runtime.object_type(id) != "[" + std::string(types.substr(kind, 1)))
            bad("ARRAY_TYPE", "JNI array region has wrong component type");
        const auto begin = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.registers[2]));
        const auto count = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(state.registers[3]));
        const auto length = runtime.array_length(id);
        if (begin < 0 || count < 0 || static_cast<std::size_t>(begin) > length ||
            static_cast<std::size_t>(count) > length - begin)
            runtime.raise("Ljava/lang/ArrayIndexOutOfBoundsException;");
        const auto pointer = state.registers[4];
        if (count && !memory.accessible(pointer, std::size_t(count) * widths[kind],
                                        set ? a64::Permission::read : a64::Permission::write))
            bad("MEMORY", "JNI array region exceeds guest buffer");
        for (std::int32_t i = 0; i < count; ++i) {
            const auto address = pointer + std::uint64_t(i) * widths[kind];
            if (set)
                runtime.array_set(id, begin + i, decode(read(address, widths[kind]), types.substr(kind, 1)));
            else
                write(address, runtime.array_get(id, begin + i).bits, widths[kind]);
        }
    }
    a64::Fault invoke_service(std::uint32_t service, Address instruction,
                              a64::ServiceState &state, bool full_frame) noexcept;
    void dispatch(unsigned slot, a64::ServiceState &state, bool full_frame) {
        auto &r = state.registers;
        if (!attached || r[0] != current_environment)
            bad("ENVIRONMENT", "JNIEnv does not belong to this app/thread");
        if (critical_active() && slot != 222 && slot != 223 && slot != 224 && slot != 225)
            bad("CRITICAL", "Only nested critical acquisition/release is allowed while a JNI critical copy is held");
        if (pending && slot != 15 && slot != 17 && slot != 228 && slot != 22 && slot != 23 && slot != 20 &&
            slot != 166 && slot != 170 && !(slot >= 191 && slot <= 198) && slot != 223 && slot != 225 && slot != 227)
            bad("PENDING_EXCEPTION", "JNI operation is not allowed with a pending exception");
        if ((slot >= 34 && slot <= 93) || (slot >= 114 && slot <= 143)) {
            callback(slot, state, full_frame);
            return;
        }
        if (slot >= 145 && slot <= 162) {
            static_field_access(slot, state, full_frame);
            return;
        }
        if (slot >= 95 && slot <= 112) {
            instance_field_access(slot, state, full_frame);
            return;
        }
        if (slot >= 199 && slot <= 214) {
            array_region(slot, state);
            return;
        }
        if (slot >= 183 && slot <= 198) {
            constexpr std::string_view types = "ZBCSIJFD";
            const bool release = slot >= 191;
            const auto component = types[slot - (release ? 191u : 183u)];
            const auto id = resolve(r[1]);
            if (release)
                release_array(id, r[2], std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[3])),
                              component, false);
            else {
                if (r[2] && !memory.accessible(r[2], 1, a64::Permission::write))
                    bad("MEMORY", "Invalid isCopy address");
                const auto buffer = array_elements(id, component, false);
                if (r[2])
                    write(r[2], 1, 1);
                r[0] = buffer;
            }
            return;
        }
        if (slot >= 175 && slot <= 182) {
            constexpr std::string_view types = "ZBCSIJFD";
            r[0] =
                reference(runtime.new_array("[" + std::string(types.substr(slot - 175, 1)),
                                            std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[1]))));
            return;
        }
        switch (slot) {
        case 4:
            r[0] = 0x00010006;
            break;
        case 6: {
            const auto name = text(r[1], 1024);
            const auto type = name.starts_with('[') ? name : "L" + name + ";";
            try {
                const auto id = runtime.class_object(type);
                runtime.initialize(type);
                r[0] = reference(id);
            } catch (const dex::DexError &e) {
                if (e.code != "AETHER_DEX_CLASS_UNSUPPORTED")
                    throw;
                error = e.what();
                java_error("Ljava/lang/NoClassDefFoundError;");
                r[0] = 0;
            }
            break;
        }
        case 7:
            r[0] = allocation_reference([&] {
                const auto index = runtime.reflected_method_index(resolve(r[1]));
                return method_id(index, 0, bool(runtime.image().methods.at(index).flags & 8));
            });
            break;
        case 8:
            r[0] = allocation_reference([&] {
                return field_id(runtime.reflected_field_index(resolve(r[1])));
            });
            break;
        case 9:
            r[0] = allocation_reference([&] {
                const auto found = methods.find(r[2]);
                if (found == methods.end())
                    bad("METHOD_ID", "ToReflectedMethod requires an existing JNI method ID");
                const auto &id = found->second;
                const auto &method = runtime.image().methods.at(id.index);
                if (!method.declared)
                    bad("METHOD_UNSUPPORTED", "Provider and symbolic methods have no owned reflective declaration");
                if (id.is_static != (static_cast<std::uint8_t>(r[3]) != 0) ||
                    !method_class_compatible(id, resolve(r[1])))
                    bad("METHOD_ID", "ToReflectedMethod class or static kind differs from its declaration");
                return reference(runtime.new_reflected_method(id.index));
            });
            break;
        case 10: {
            const auto type = runtime.represented_class(resolve(r[1]));
            const auto parent = runtime.superclass(type);
            r[0] = parent ? reference(runtime.class_object(*parent)) : 0;
            break;
        }
        case 11: {
            const auto from = runtime.represented_class(resolve(r[1]));
            const auto to = runtime.represented_class(resolve(r[2]));
            r[0] = runtime.class_assignable(from, to);
            break;
        }
        case 12:
            r[0] = allocation_reference([&] {
                const auto found = fields.find(r[2]);
                if (found == fields.end())
                    bad("FIELD_ID", "ToReflectedField requires an existing owned JNI field ID");
                const auto index = found->second;
                const auto &field = runtime.image().fields.at(index);
                const bool stat = static_cast<std::uint8_t>(r[3]) != 0;
                if (!field.declared || bool(field.flags & 8) != stat)
                    bad("FIELD_ID", "ToReflectedField static kind differs from its declaration");
                const auto supplied = std::string(runtime.represented_class(resolve(r[1])));
                if (!runtime.class_assignable(supplied, runtime.image().types.at(field.owner)))
                    bad("FIELD_ID", "ToReflectedField class is incompatible with its declaration");
                // Construction may collect before producing the result; its
                // immediate fixed-cell local publication cannot collect.
                return reference(runtime.new_reflected_field(index));
            });
            break;
        case 13: {
            const auto id = resolve(r[1]);
            if (!id || !runtime.assignable(id, "Ljava/lang/Throwable;"))
                bad("EXCEPTION", "Throw requires a Throwable reference");
            pending_exception(id);
            r[0] = 0;
            break;
        }
        case 14: {
            const auto type = runtime.represented_class(resolve(r[1]));
            const auto message = r[2] ? from_modified_utf8(text(r[2])) : std::u16string{};
            java_error(type, message);
            r[0] = 0;
            break;
        }
        case 15:
            // Reading the pending exception creates a local reference. If its
            // allocation fails, keep that exception pending and return null;
            // ExceptionCheck still distinguishes this from no pending error.
            r[0] = allocation_reference([&] { return reference(pending); });
            break;
        case 17:
            pending_exception(0);
            r[0] = 0;
            break;
        case 19: {
            const auto capacity = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[1]));
            if (capacity <= 0)
                bad("FRAME_CAPACITY", "PushLocalFrame capacity must be positive");
            r[0] = allocation_reference([&] {
                push_frame(static_cast<std::size_t>(capacity), true);
                return Handle{1};
            }) ? 0 : static_cast<std::uint32_t>(-1);
            break;
        }
        case 20: {
            if (frames.empty() || !frames.back().explicit_frame)
                bad("FRAME", "Cannot pop the native call's automatic frame");
            r[0] = allocation_reference([&]() -> Handle {
                struct Pop {
                    Impl &owner;
                    bool active = true;
                    ~Pop() { if (active) owner.pop(); }
                    void now() { active = false; owner.pop(); }
                } popped{*this};
                const auto object = resolve(r[1], false);
                // Resolution, retirement and fixed-cell parent publication
                // form one allocation/GC/callback-free interval. This applies
                // equally to weak referents and does not need an ordinary pin
                // that could consume or fail outside the promised capacity.
                popped.now();
                return reference(object);
            });
            break;
        }
        case 21:
            r[0] = allocation_reference([&] { return reference(resolve(r[1], false), true); });
            break;
        case 22:
            erase(r[1], true);
            r[0] = 0;
            break;
        case 23:
            erase(r[1], false);
            r[0] = 0;
            break;
        case 24:
            r[0] = resolve(r[1]) == resolve(r[2]);
            break;
        case 25:
            r[0] = allocation_reference([&] { return reference(resolve(r[1], false)); });
            break;
        case 26: {
            const auto capacity = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[1]));
            if (capacity < 0)
                bad("FRAME_CAPACITY", "EnsureLocalCapacity capacity must be nonnegative");
            r[0] = allocation_reference([&] {
                ensure_local_capacity(static_cast<std::size_t>(capacity));
                return Handle{1};
            }) ? 0 : static_cast<std::uint32_t>(-1);
            break;
        }
        case 27:
            r[0] = reference(runtime.new_object(runtime.represented_class(resolve(r[1]))));
            break;
        case 28:
        case 29:
        case 30:
            construct(slot, state, full_frame);
            break;
        case 31:
            r[0] = reference(runtime.class_object(runtime.object_type(resolve(r[1]))));
            break;
        case 32:
            r[0] = runtime.assignable(resolve(r[1]), runtime.represented_class(resolve(r[2])));
            break;
        case 33:
            method_lookup(state, false);
            break;
        case 113:
            method_lookup(state, true);
            break;
        case 94:
        case 144:
            field_lookup(state, slot == 144);
            break;
        case 163: {
            const auto count = r[2];
            if (count > 65536)
                bad("STRING_LIMIT", "Invalid NewString length");
            std::u16string value;
            for (std::size_t i = 0; i < count; ++i)
                value.push_back(static_cast<char16_t>(read(r[1] + i * 2, 2)));
            r[0] = reference(runtime.new_string(value));
            break;
        }
        case 164:
            r[0] = runtime.string(resolve(r[1])).size();
            break;
        case 165:
        case 169: {
            if (r[2] && !memory.accessible(r[2], 1, a64::Permission::write))
                bad("MEMORY", "Invalid isCopy address");
            const auto buffer = string_buffer(resolve(r[1]), slot == 169);
            if (r[2])
                write(r[2], 1, 1);
            r[0] = buffer;
            break;
        }
        case 166:
        case 170:
            release_string(resolve(r[1]), r[2], slot == 170);
            r[0] = 0;
            break;
        case 167:
            r[0] = reference(runtime.new_string(from_modified_utf8(text(r[1]))));
            break;
        case 168:
            r[0] = modified_utf8(runtime.string(resolve(r[1]))).size();
            break;
        case 171:
            r[0] = runtime.array_length(resolve(r[1]));
            break;
        case 172: {
            const auto type = "[" + std::string(runtime.represented_class(resolve(r[2])));
            const auto initial = resolve(r[3]);
            const auto array =
                runtime.new_array(type, std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[1])));
            const auto handle = reference(array);
            for (std::size_t i = 0; i < runtime.array_length(array); ++i)
                runtime.array_set(array, static_cast<std::int32_t>(i), Value::reference(initial));
            r[0] = handle;
            break;
        }
        case 173:
        case 174: {
            const auto id = resolve(r[1]);
            const auto type = runtime.object_type(id);
            if (!type.starts_with('[') || !dex::reference_type(type.substr(1)))
                bad("ARRAY_TYPE", "Expected an object array");
            const auto index = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[2]));
            if (slot == 173)
                r[0] = reference(runtime.array_get(id, index).bits);
            else {
                runtime.array_set(id, index, Value::reference(resolve(r[3])));
                r[0] = 0;
            }
            break;
        }
        case 215: {
            const auto type = runtime.represented_class(resolve(r[1]));
            if (r[3] > 128)
                bad("REGISTER_NATIVES", "Invalid native registration count");
            std::map<dex::Index, Address> additions;
            for (std::size_t i = 0; i < r[3]; ++i) {
                const auto entry = r[2] + i * 24;
                const auto name = text(read(entry, 8), 1024), signature = text(read(entry + 8, 8), 1024);
                const auto index = runtime.resolve_method(type, name, signature);
                if (!(runtime.image().methods.at(index).flags & 0x100))
                    bad("REGISTER_NATIVES", "Cannot register a non-native method");
                const auto address = read(entry + 16, 8);
                if (address % 4 || !memory.accessible(address, 4, a64::Permission::execute) ||
                    !additions.emplace(index, address).second)
                    bad("REGISTER_NATIVES", "Invalid native function address or duplicate registration");
            }
            for (const auto &[index, address] : additions)
                registered[index] = address;
            r[0] = 0;
            break;
        }
        case 216: {
            const auto type = runtime.represented_class(resolve(r[1]));
            for (auto it = registered.begin(); it != registered.end();)
                if (runtime.image().types.at(runtime.image().methods.at(it->first).owner) == type)
                    it = registered.erase(it);
                else
                    ++it;
            r[0] = 0;
            break;
        }
        case 219:
            write(r[1], Bridge::java_vm, 8);
            r[0] = 0;
            break;
        case 220:
        case 221:
            string_region(state, slot == 221);
            break;
        case 222:
        case 224: {
            if (r[2] && !memory.accessible(r[2], 1, a64::Permission::write))
                bad("MEMORY", "Invalid isCopy address");
            const auto id = resolve(r[1]);
            const auto buffer = slot == 222 ? array_elements(id, primitive_component(id), true)
                                             : string_buffer(id, false, true);
            if (r[2])
                write(r[2], 1, 1);
            r[0] = buffer;
            break;
        }
        case 223: {
            const auto id = resolve(r[1]);
            release_array(id, r[2], std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[3])),
                          primitive_component(id), true);
            break;
        }
        case 225:
            release_string(resolve(r[1]), r[2], false, true);
            break;
        case 226:
            r[0] = allocation_reference([&] { return weak_reference(resolve(r[1])); });
            break;
        case 227:
            erase(r[1], true, true);
            r[0] = 0;
            break;
        case 228:
            r[0] = pending != 0;
            break;
        case 232: {
            if (!r[1]) {
                r[0] = 0;
                break;
            }
            const auto found = find_reference(r[1]);
            if (found == refs.end() || (!found->second.global && found->second.context != context))
                bad("REFERENCE", "Invalid, deleted or foreign JNI reference");
            // A cleared weak reference still has weak-global handle type. Do
            // not infer validity or kind from its nullable resolved referent.
            r[0] = found->second.weak ? 3 : found->second.global ? 2 : 1;
            break;
        }
        default:
            bad("FUNCTION_UNSUPPORTED",
                "JNI function table index " + std::to_string(slot) + " is not implemented");
        }
    }
};
Bridge::Bridge(dex::ManagedRuntime &runtime, a64::GuestMemory &memory, const a64::AppContext &app,
               const host::TimeService &time, std::span<const elf::ModuleInput> modules, std::string root,
               host::FileService *files, bool attach_interface,std::string_view package,
               audio::GuestAudioServices *audio, graphics::GuestGraphicsServices *graphics)
    : impl_(std::make_unique<Impl>(*this, runtime, memory, app, time, modules, std::move(root), files,
                                   attach_interface,package,audio,graphics)) {}
Bridge::~Bridge() {
    if (impl_ && impl_->attach_interface)
        impl_->runtime.set_native_interface(nullptr);
}
bool Bridge::has_library(std::string_view root) const noexcept {
    return impl_->root == root || (impl_->native_activity_initialized && impl_->native_activity_root == root) ||
           std::find(impl_->loaded_roots.begin(), impl_->loaded_roots.end(), root) != impl_->loaded_roots.end();
}
void Bridge::add_library(std::span<const elf::ModuleInput> modules, std::string root) {
    auto &p = *impl_;p.process->checkpoint();
    if (std::this_thread::get_id() != p.owner_thread || p.closed || p.native_depth || p.load_state != 2)
        bad("LOAD_STATE", "Additional native graphs require an idle initialized bridge");
    Impl::LogicalScope logical_scope(p);
    if (has_library(root)) return;
    p.loaded_roots.reserve(p.loaded_roots.size() + 1);
    p.loader.extend(modules, root);
    p.root = std::move(root);
    p.load_state = 0;
}
void Bridge::finish_logical_thread(dex::ManagedRuntime &runtime) {
    auto &p=*impl_;p.process->checkpoint();
    if(&runtime!=&p.runtime || p.closed || p.native_depth || std::this_thread::get_id()!=p.owner_thread)
        bad("THREAD","Logical finalization requires the idle native owner");
    const auto thread=runtime.current_thread();
    if(std::none_of(p.managed_bindings.begin(),p.managed_bindings.end(),[&](const auto &binding){return binding.thread==thread;}))return;
    Impl::LogicalScope logical(p);Impl::Scope scope(p);
    const auto result=p.finalize_bound_thread(scope.stack(),std::min(std::uint64_t{1000000},runtime.thread_instruction_budget()));
    if(result.finalization_failed){
        if(result.result.fault==a64::Fault::process_exit){p.process->request_exit(result.result.detail);p.process->checkpoint();}
        bad("NATIVE_FINALIZATION",std::string(a64::fault_name(result.result.fault))+": "+std::string(p.posix.last_rejection()));
    }
    p.check_pending();
}
void Bridge::discard_logical_thread(dex::ObjectId thread) noexcept {
    auto &p=*impl_;
    // Terminal bookkeeping is nonexecuting: retire values and release the held
    // JNI buffers, thread pin and TLS mapping before this identity can be reused.
    for(auto &binding:p.managed_bindings)if(binding.thread==thread)p.release_managed_binding(binding);
}
void Bridge::set_module_provider(ModuleProvider provider) {
    auto &p=*impl_;
    if(std::this_thread::get_id()!=p.owner_thread || p.closed || p.native_depth)
        bad("LOAD_STATE","Module provider requires the idle bridge owner");
    p.module_provider=std::move(provider);
}
void Bridge::finish_main_work() {
    auto &p=*impl_;
    if(std::this_thread::get_id()!=p.owner_thread || p.native_depth)
        bad("MAIN_WORK_STATE","Main-work retirement requires the idle bridge owner");
    if(p.main_work_cpu){p.main_work_cpu->finish();p.main_work_cpu.reset();}
    p.loader.set_initializer_driver(nullptr,nullptr);
}
void Bridge::set_initialization_observer(void *context,elf::InitializationObserver observer) {
    auto &p=*impl_;
    if(std::this_thread::get_id()!=p.owner_thread || p.closed || p.native_depth ||
       p.load_state || p.active_native_task || !p.cpu.execution_idle())
        bad("LOAD_STATE","Initialization observer requires the idle owner before guest initialization");
    p.initialization_context=context;p.initialization_observer=observer;
    p.loader.set_initialization_observer(context,observer);
}
void Bridge::set_assets(const apk::PackageView &package, std::function<bool(ObjectId)> validate_manager) {
    auto &p = *impl_;
    if (std::this_thread::get_id() != p.owner_thread || p.closed || p.native_depth || !validate_manager)
        bad("ASSET_STATE", "Asset source requires the idle bridge owner and canonical manager check");
    p.platform.bind_assets(package, [&p, validate_manager = std::move(validate_manager)](Address env, Handle object) {
        if (p.closed || !p.attached || p.frames.empty() || env != p.current_environment || !object) return false;
        return validate_manager(p.resolve(object));
    });
}
void Bridge::set_assets(const apk::PackageView &package, ManagedAssetManagerAccess access) {
    auto &p = *impl_;
    if (std::this_thread::get_id() != p.owner_thread || p.closed || p.native_depth ||
        !access.publish || !access.owns)
        bad("ASSET_STATE", "Asset identities require the idle bridge owner and complete managed ownership checks");
    android::NativeAssetManagerAccess native_access;
    native_access.from_java = [&p, publish = std::move(access.publish)](Address env, Handle object) -> std::uint64_t {
        if (p.closed || !p.attached || p.frames.empty() || env != p.current_environment || !object) return 0;
        // A live weak referent needs no promotion here: publication consumes
        // only its scalar identity, and the trusted producer cannot collect,
        // allocate, run guests or retain the unrooted referent across return.
        const auto identity = p.resolve(object, false);
        return identity ? publish(identity) : 0;
    };
    native_access.owns = [&p, owns = std::move(access.owns)](std::uint64_t token) {
        if (p.closed || std::this_thread::get_id() != p.owner_thread || !token) return false;
        return owns(token);
    };
    p.platform.bind_assets(package, std::move(native_access));
}
void Bridge::set_display_configuration(const android::DisplayConfiguration &configuration) {
    auto &p=*impl_;
    if(std::this_thread::get_id()!=p.owner_thread || p.closed || p.native_depth || !configuration.valid())
        bad("CONFIGURATION_STATE", "Native configuration requires the idle owner and actual valid display facts");
    p.process->checkpoint();
    if(p.native_configuration_bound)p.platform.update_configuration(configuration);
    else {p.platform.bind_configuration(configuration);p.native_configuration_bound=true;}
}
void Bridge::set_native_windows(std::shared_ptr<android::NativeWindows> windows,
                               std::function<std::shared_ptr<android::NativeWindowProducer>(ObjectId)> resolve_surface) {
    auto &p = *impl_;
    if (std::this_thread::get_id() != p.owner_thread || p.closed || p.native_depth || p.load_state ||
        p.native_windows_bound || !windows || !windows->owned_by_current_thread() || !resolve_surface)
        bad("WINDOW_STATE", "Native windows require the initial idle bridge owner and a genuine Surface resolver");
    p.process->checkpoint();
    windows->bind_java_resolver([&p, resolve_surface = std::move(resolve_surface)](Address env, Handle object)
                                   -> std::shared_ptr<android::NativeWindowProducer> {
        // Native dispatch creates WeakRoots before entering the platform. A
        // direct registry call cannot bypass that JNI handle admission scope.
        if (std::this_thread::get_id() != p.owner_thread || p.closed || !p.attached || p.frames.empty() ||
            !p.resolved_weak_roots || env != p.current_environment || !object)
            return {};
        return resolve_surface(p.resolve(object));
    });
    try {
        p.platform.bind_windows(windows);
    } catch (...) {
        windows->clear_java_resolver();
        throw;
    }
    p.native_windows_bound = true;
    p.native_windows = std::move(windows);
}
void Bridge::set_native_input_completion_factory(android::NativeActivityInputCompletionFactory factory) {
    auto &p=*impl_;
    if(std::this_thread::get_id()!=p.owner_thread || p.closed || p.native_depth || p.load_state ||
        p.input_completion_factory || !factory)
        bad("NATIVE_INPUT_STATE", "Input completion requires the initial idle owner and an actual main entry factory");
    p.process->checkpoint();
    p.input_completion_factory=std::move(factory);
}
void Bridge::set_native_activity_host_work_factory(android::NativeActivityHostWorkFactory factory) {
    auto &p=*impl_;
    if(std::this_thread::get_id()!=p.owner_thread || p.closed || p.native_depth || p.load_state || p.host_work_factory || !factory)
        bad("NATIVE_ACTIVITY_STATE","Host work requires the initial idle owner and actual main factory");
    p.process->checkpoint();p.host_work_factory=std::move(factory);
}
void Bridge::bind_main_looper() {
    auto &p = *impl_;
    if (std::this_thread::get_id() != p.owner_thread || p.closed || p.native_depth ||
        !p.posix.is_main_native_thread() || p.load_state)
        bad("LOOPER_STATE", "Managed main Looper binding requires the idle initial native main owner");
    a64::ServiceState state;
    state.registers[0] = 0; // The Java MessageQueue's Looper does not allow non-callback registrations.
    if (p.posix.invoke_looper("ALooper_prepare", state, false) != a64::Fault::none || !state.registers[0])
        bad("LOOPER_STATE", "Cannot bind the existing managed main event loop to its native owner");
}
android::NativeActivityResult Bridge::native_activity(const android::NativeActivityRequest &request, std::string_view library,
                             std::string_view function) {
    using Stage = android::NativeActivityStage;
    auto &p = *impl_;
    android::NativeActivityResult saved_result;
    p.process->checkpoint();
    if (std::this_thread::get_id() != p.owner_thread || p.closed || p.native_closing || p.native_depth ||
        p.active_native_task || !p.cpu.execution_idle() || p.native_activity_dispatching || p.native_activity_failed ||
        !p.runtime.is_main_thread() || !p.posix.is_main_native_thread())
        bad("NATIVE_ACTIVITY_STATE", "NativeActivity lifecycle requires its idle live main owner");
    if (!request.activity || !request.asset_manager || !request.content_view || !request.window_generation || !request.configuration.valid() ||
        library.empty() || library.size() > 127 || function.empty() || function.size() > 4096 ||
        function.find('\0') != std::string_view::npos ||
        std::any_of(function.begin(), function.end(), [](unsigned char c) { return c < 0x20 || c == 0x7f; }))
        bad("NATIVE_ACTIVITY_METADATA", "NativeActivity requires actual owned identities and validated entry metadata");
    Impl::LogicalScope logical(p);
    if (p.current_environment != environment || p.context || !p.attached)
        bad("NATIVE_ACTIVITY_THREAD", "NativeActivity callbacks cannot borrow a background JNIEnv");
    p.check_pending();
    Impl::Scope scope(p);
    const auto stack = scope.stack();
    p.native_activity_dispatching = true;
    struct End { bool &active; ~End() { active = false; } } end{p.native_activity_dispatching};
    try {
        if (request.stage == Stage::create) {
            if (!p.native_activity_root.empty() && p.native_activity_root != library)
                bad("NATIVE_ACTIVITY_ROOT", "This NativeActivity package cannot change its prepared native root");
            if (p.native_activity_storage || p.native_activity_incarnations >= 32 ||
                request.saved_state.size() > 65536 || (!request.saved_state_present && !request.saved_state.empty()) ||
                request.internal_data_path.empty() || request.internal_data_path.size() > 8191 ||
                std::any_of(request.internal_data_path.begin(), request.internal_data_path.end(),
                            [](unsigned char c) { return c < 0x20 || c == 0x7f; }) ||
                !p.runtime.assignable(request.activity, "Landroid/app/NativeActivity;") ||
                p.runtime.object_type(request.content_view) != "Landroid/app/NativeActivity$NativeContentView;" ||
                std::none_of(p.loader.modules().begin(), p.loader.modules().end(),
                             [&](const auto &module) { return module.image.soname == library; }))
                bad("NATIVE_ACTIVITY_STATE", "NativeActivity creation requires fresh bounded owned backing");
            if (p.native_activity_root.empty()) p.native_activity_root = library;
            auto storage = std::make_unique<Impl::NativeActivityStorage>();
            storage->activity = request.activity;
            storage->assets = request.asset_manager;
            storage->content = request.content_view;
            storage->generation = request.window_generation;
            storage->library = library;
            storage->function = function;
            storage->path_bytes.assign(request.internal_data_path.begin(), request.internal_data_path.end());
            storage->path_bytes.push_back(0);
            // Every attempted incarnation consumes a reserved address forever;
            // deletion/remapping cannot turn a stale Activity pointer into a new one.
            storage->address = native_activity_base + Address{p.native_activity_incarnations++} * 0x20000;
            storage->paths = storage->address + a64::GuestMemory::page_size;
            p.native_activity_storage = std::move(storage);
            auto &created = *p.native_activity_storage;
            p.map(created.address, a64::GuestMemory::page_size);
            created.identity = p.memory.word_identity(created.address, a64::read_write);
            created.path_size = (created.path_bytes.size() + 4095) & ~std::size_t{4095};
            p.map(created.paths, created.path_size);
            created.path_identity = p.memory.word_identity(created.paths, a64::read_write);
            if (!p.memory.write(created.paths, created.path_bytes)) bad("NATIVE_ACTIVITY_MAPPING", "Cannot publish owned logical paths");
            p.memory.protect(created.paths, a64::Permission::read);
            created.clazz = p.reference(request.activity, true);
            created.manager = p.reference(request.asset_manager, true);
            created.content_root = p.reference(request.content_view, true);
            const auto manager = p.platform.publish_asset_manager(p.current_environment, created.manager);
            const std::array<std::uint8_t, 128> empty_callbacks{};
            if (!p.memory.write(created.address + 128, empty_callbacks))
                bad("NATIVE_ACTIVITY_MAPPING", "Cannot initialize the owned callback table");
            p.write(created.address, created.address + 128, 8);
            p.write(created.address + 8, java_vm, 8);
            p.write(created.address + 16, environment, 8);
            p.write(created.address + 24, created.clazz, 8);
            p.write(created.address + 32, created.paths, 8);
            p.write(created.address + 40, 0, 8); // No hosted external volume.
            p.write(created.address + 48, android::compatibility_sdk, 4);
            p.write(created.address + 52, 0, 4);
            p.write(created.address + 56, 0, 8); // App-owned instance field.
            p.write(created.address + 64, manager, 8);
            p.write(created.address + 72, 0, 8); // No hosted OBB volume.
            if (!p.memory.read(created.address, created.canonical)) bad("NATIVE_ACTIVITY_MAPPING", "Cannot retain canonical ABI fields");
            if (request.saved_state_present) {
                created.saved = created.address + 0x4000;
                created.saved_size = (std::max(request.saved_state.size(), std::size_t{1}) + 4095) & ~std::size_t{4095};
                p.map(created.saved, created.saved_size);
                created.saved_identity = p.memory.word_identity(created.saved, a64::read_write);
                if (!request.saved_state.empty() && !p.memory.write(created.saved, request.saved_state))
                    bad("NATIVE_ACTIVITY_MAPPING", "Cannot copy the actual saved-state input");
            }
            p.native_activity_cpu([&] {
                if (p.load_state == 0) {
                    p.load_state = 1;
                    try { p.loader.initialize(p.cpu, stack, p.posix.thread_pointer()); p.load_state = 2; }
                    catch (...) { p.load_state = 3; throw; }
                } else if (p.load_state != 2) bad("LOAD_STATE", "NativeActivity cannot reuse a recursive or failed library initialization");
                p.check_pending();
                if (std::none_of(p.loader.modules().begin(), p.loader.modules().end(),
                                 [&](const auto &module) { return module.image.soname == created.library && module.initialized; }))
                    bad("LOAD_STATE", "NativeActivity root has not completed structural initialization");
                p.native_activity_initialized = true;
                const auto entry = p.loader.lookup(created.library, created.function);
                if (!entry || entry->type == 1 || !entry->address || entry->address % 4 ||
                    !p.memory.accessible(entry->address, 4, a64::Permission::execute))
                    bad("NATIVE_ACTIVITY_ENTRY", "Prepared NativeActivity entry is not an aligned executable function");
                p.validate_native_activity();
                const std::array<std::uint64_t, 3> arguments{created.address, created.saved, request.saved_state.size()};
                const auto budget = p.main_work_cpu?std::uint64_t{1'000'000}:
                    std::min(std::uint64_t{1'000'000}, p.runtime.native_instruction_budget().retained);
                if (!budget) bad("BUDGET", "NativeActivity entry has no retained invocation allowance");
                (void)p.call(entry->address, arguments, stack, {}, budget);
                p.check_pending();
                p.validate_native_activity();
            });
            if (p.load_state != 2) bad("LOAD_STATE", "NativeActivity entry left a failed native library initialization");
            created.created = true;
            p.native_activity_mapping(created.saved, created.saved_size, created.saved_identity);
            created.saved = 0;
            created.saved_identity.reset();
            return {};
        }
        p.validate_native_activity();
        auto &storage = *p.native_activity_storage;
        if (p.load_state != 2 || !storage.created || storage.destroy_started || storage.activity != request.activity ||
            storage.assets != request.asset_manager || storage.content != request.content_view || storage.generation != request.window_generation ||
            storage.library != library || storage.function != function)
            bad("NATIVE_ACTIVITY_STATE", "NativeActivity lifecycle belongs to a stale or different incarnation");
        unsigned slot = 0;
        std::uint64_t secondary = request.focused;
        bool has_secondary = request.stage == Stage::window_focus;
        const auto geometry_matches = [](const android::NativeWindowGeometry &left, const android::NativeWindowGeometry &right) {
            return left.width == right.width && left.height == right.height && left.format == right.format;
        };
        const auto validate_window = [&] {
            if (!p.native_windows || !request.window_producer || storage.window != request.window_producer || !storage.window_id)
                bad("NATIVE_ACTIVITY_WINDOW", "Native window callback does not identify its retained producer");
            const auto binding = p.native_windows->resolve_for_egl(storage.window_id);
            if (!binding || binding->retained != storage.window || !geometry_matches(binding->geometry, request.window_geometry))
                bad("NATIVE_ACTIVITY_WINDOW", "Native window callback differs from its actual admitted producer geometry");
        };
        switch (request.stage) {
        case Stage::start: slot = 0; break;
        case Stage::resume: slot = 1; break;
        case Stage::save_state: slot = 2; break;
        case Stage::pause: slot = 3; break;
        case Stage::stop: slot = 4; break;
        case Stage::destroy:
            if (storage.window || storage.queue)
                bad("NATIVE_ACTIVITY_STATE", "Native window and input queue must retire before Activity destruction");
            slot = 5; storage.destroy_started = true; break;
        case Stage::window_focus: slot = 6; break;
        case Stage::configuration_changed: slot = 14; break;
        case Stage::low_memory: slot = 15; break;
        case Stage::window_created:
            if (!p.native_windows || !request.window_producer || storage.window)
                bad("NATIVE_ACTIVITY_WINDOW", "Native window creation requires a fresh actual admitted producer");
            storage.window_id = p.native_windows->retain_activity(request.window_producer);
            storage.window = request.window_producer;
            storage.window_destroy_started = false;
            validate_window();
            storage.geometry = request.window_geometry;
            slot = 7; secondary = storage.window_id; has_secondary = true; break;
        case Stage::window_resized:
            if (storage.window_destroy_started) bad("NATIVE_ACTIVITY_WINDOW", "Native window destruction has already begun");
            validate_window();
            storage.geometry = request.window_geometry;
            slot = 8; secondary = storage.window_id; has_secondary = true; break;
        case Stage::window_destroyed:
            if (storage.window_destroy_started) bad("NATIVE_ACTIVITY_WINDOW", "Native window destruction cannot be repeated");
            validate_window();
            if (!geometry_matches(storage.geometry, request.window_geometry))
                bad("NATIVE_ACTIVITY_WINDOW", "Native window retirement changed the retained geometry");
            storage.window_destroy_started = true;
            slot = 10; secondary = storage.window_id; has_secondary = true; break;
        case Stage::input_queue_created:
            if (storage.queue || storage.queue_destroy_started || p.posix.current_input_queue())
                bad("NATIVE_INPUT_STATE", "NativeActivity requires one fresh owned input queue");
            storage.queue = p.posix.create_input_queue();
            if (!storage.queue || p.posix.current_input_queue() != storage.queue)
                bad("NATIVE_INPUT_STATE", "Native input queue creation did not publish its actual identity");
            slot = 11; secondary = storage.queue; has_secondary = true; break;
        case Stage::input_queue_destroyed:
            if (!storage.queue || storage.queue_destroy_started || p.posix.current_input_queue() != storage.queue)
                bad("NATIVE_INPUT_STATE", "Native input queue destruction is stale or repeated");
            storage.queue_destroy_started = true;
            slot = 12; secondary = storage.queue; has_secondary = true; break;
        default: bad("NATIVE_ACTIVITY_STATE", "NativeActivity lifecycle stage is invalid");
        }
        const auto callback = p.read(storage.address + 128 + slot * 8, 8);

        if (callback) {
            if (callback % 4 || !p.memory.accessible(callback, 4, a64::Permission::execute))
                bad("NATIVE_ACTIVITY_CALLBACK", "NativeActivity callback is not an aligned executable guest function");
            const bool saving = request.stage == Stage::save_state;
            struct SavedReturn {
                bionic::GuestPosixServices &posix;
                Address address = 0;
                ~SavedReturn() { if (address) (void)posix.copy_release_owned_heap(address, {}); }
            } returned{p.posix};
            if (saving) {
                // Owned ABI struct0..79, callbacks128..255, aligned size_t256..263.
                saved_result.saved_state.resize(65536);
                secondary = storage.address + 256; has_secondary = true;
                p.write(secondary, 0, 8);
            }
            p.native_activity_cpu([&] {
                const std::array<std::uint64_t, 2> arguments{storage.address, secondary};
                const auto budget = p.main_work_cpu?std::uint64_t{1'000'000}:
                    std::min(std::uint64_t{1'000'000}, p.runtime.native_instruction_budget().retained);
                if (!budget) bad("BUDGET", "NativeActivity callback has no retained invocation allowance");
                (void)p.call(callback, std::span(arguments).first(has_secondary ? 2 : 1), stack, {}, budget, saving ? &returned.address : nullptr);
                p.check_pending();
                p.validate_native_activity();
            });
            // Strict guest tail accounting completes before output publication.
            // No further guest work occurs before exact owned copy and free.
            if (saving) {
                p.validate_native_activity();
                const auto size = p.read(secondary, 8);
                if (size > 65536) bad("NATIVE_ACTIVITY_STATE_LIMIT", "Native saved-state output exceeds 65536 bytes");
                if (!returned.address) {
                    if (size) bad("NATIVE_ACTIVITY_SAVE", "Native saved-state size has no returned buffer");
                    saved_result.saved_state.clear();
                } else {
                    const auto fault = p.posix.copy_release_owned_heap(returned.address,
                        std::span(saved_result.saved_state).first(static_cast<std::size_t>(size)));
                    if (fault != a64::Fault::none)
                        bad("NATIVE_ACTIVITY_SAVE", "Native saved-state output is not an exact readable malloc allocation: " + std::string(a64::fault_name(fault)));
                    returned.address = 0;
                    saved_result.saved_state.resize(static_cast<std::size_t>(size));
                    saved_result.saved_state_present = size != 0;
                }
            }
        }
        if (request.stage == Stage::window_destroyed) {
            p.native_windows->release_activity(storage.window);
            storage.window.reset(); storage.window_id = 0;
        }
        if (request.stage == Stage::input_queue_destroyed) {
            p.posix.retire_input_queue(storage.queue);
            storage.queue = 0;
        }
        // As on Android, the application synchronizes window/worker access in
        // its real destroy callback. Activity recreation does not cancel app-
        // global pthreads. Whole-Bridge cleanup cancels all retained task stacks
        // before it retires any remaining ABI backing or JNI globals.
        if (request.stage == Stage::destroy) p.retire_native_activity();
        return saved_result;
    } catch (...) {
        p.native_activity_failed = true;
        if(p.native_activity_storage)p.cancel_activity_host_work(*p.native_activity_storage);
        throw;
    }
}
bool Bridge::native_activity_pointer(const android::NativeActivityPointerInput &input) {
    auto &p = *impl_;
    p.process->checkpoint();
    if (std::this_thread::get_id() != p.owner_thread || p.closed || p.native_closing ||
        p.active_native_task || p.native_activity_failed ||
        !p.runtime.is_main_thread() || !p.posix.is_main_native_thread() || p.context || !p.attached ||
        p.current_environment != environment || (!input.synthetic_cancel &&
            (p.native_depth || !p.cpu.execution_idle() || p.native_activity_dispatching || p.resolved_weak_roots || p.critical_active())))
        bad("NATIVE_INPUT_STATE", "Native pointer capture requires its live main owner and ordinary idle capture or trusted cancellation");
    if (!p.native_activity_storage) return false;
    auto &storage = *p.native_activity_storage;
    const auto &sample = input.sample;
    if (!storage.created || storage.destroy_started || storage.window_destroy_started || storage.queue_destroy_started ||
        !storage.queue || p.posix.current_input_queue() != storage.queue || !storage.window || !p.native_windows ||
        input.activity != storage.activity || input.root != storage.content || input.window_generation != storage.generation ||
        sample.root != storage.content || !sample.native_producer || sample.capture_dpi < 48 || sample.capture_dpi > 960 ||
        static_cast<std::uint32_t>(sample.action) > 3 || sample.pointer > 31 ||
        (sample.source != 0x2002 && sample.source != 0x1002) || !input.input_generation || !input.down_time_known ||
        input.down_time_ms > std::uint64_t{INT64_MAX} || !std::isfinite(sample.x) || !std::isfinite(sample.y) ||
        std::abs(sample.x) > 65536 || std::abs(sample.y) > 65536) return false;
    if (input.synthetic_cancel) {
        if (sample.action != android::PointerAction::cancel ||
            (sample.time_known ? (sample.down_time_ms != input.down_time_ms || sample.event_time_ms < input.down_time_ms ||
                sample.event_time_ms > std::uint64_t{INT64_MAX}) : (sample.down_time_ms || sample.event_time_ms))) return false;
    } else if (!sample.time_known || !android::valid_pointer_context(sample) || sample.down_time_ms != input.down_time_ms)
        return false;
    p.validate_native_activity();
    const auto binding = p.native_windows->resolve_for_egl(storage.window_id);
    if (!binding || binding->retained != storage.window || binding->incarnation != sample.native_producer ||
        binding->geometry.width != sample.native_width || binding->geometry.height != sample.native_height ||
        storage.geometry.width != sample.native_width || storage.geometry.height != sample.native_height ||
        storage.geometry.format != binding->geometry.format) return false;
    return p.posix.enqueue_input_queue(storage.queue, input);
}
bool Bridge::native_activity_key(const android::NativeActivityKeyInput &input) {
    auto &p=*impl_;
    if(std::this_thread::get_id()!=p.owner_thread)
        bad("NATIVE_INPUT_STATE", "Native key capture belongs to another host owner");
    if(!p.native_activity_storage)return false;
    auto &storage=*p.native_activity_storage;
    // Cancellation is a pure revocation of an owned continuation reservation.
    // It remains available during teardown and never calls a process/provider.
    if(input.stage==android::NativeKeyStage::cancel) {
        if(!storage.queue || input.activity!=storage.activity || input.sample.root!=storage.content ||
            input.sample.window_generation!=storage.generation)return false;
        return p.posix.enqueue_key_input_queue(storage.queue,input);
    }
    p.process->checkpoint();
    if(p.closed || p.native_closing || p.active_native_task || p.native_activity_failed ||
        p.native_depth || !p.cpu.execution_idle() || p.native_activity_dispatching ||
        p.resolved_weak_roots || p.critical_active() || !p.runtime.is_main_thread() ||
        !p.posix.is_main_native_thread() || p.context || !p.attached || p.current_environment!=environment)
        bad("NATIVE_INPUT_STATE", "Native key admission requires its actual idle main owner");
    const auto &sample=input.sample;
    if(!storage.created || storage.destroy_started || storage.window_destroy_started || storage.queue_destroy_started ||
        !storage.queue || p.posix.current_input_queue()!=storage.queue || !storage.window || !p.native_windows ||
        input.activity!=storage.activity || sample.root!=storage.content || sample.window_generation!=storage.generation ||
        !input.request || !android::valid_key_input(sample) || !sample.event_time_known || !sample.source_known ||
        (input.stage!=android::NativeKeyStage::pre_ime && input.stage!=android::NativeKeyStage::post_ime))return false;
    p.validate_native_activity();
    const auto binding=p.native_windows->resolve_for_egl(storage.window_id);
    if(!binding || binding->retained!=storage.window || binding->geometry.width!=storage.geometry.width ||
        binding->geometry.height!=storage.geometry.height || binding->geometry.format!=storage.geometry.format)return false;
    return p.posix.enqueue_key_input_queue(storage.queue,input);
}
void Bridge::load_library(dex::ManagedRuntime &runtime, std::u16string_view name) {
    auto &p = *impl_;p.process->checkpoint();
    if (std::this_thread::get_id() != p.owner_thread)
        bad("THREAD", "Native library belongs to another runtime thread");
    if (&runtime != &p.runtime || p.closed)
        bad("STATE", "Wrong or closed runtime");
    Impl::LogicalScope logical_scope(p);
    const auto requested = "lib" + ascii(name) + ".so";
    if (p.load_state == 3) bad("LOAD_STATE", "Previously failed JNI library load");
    if (std::find(p.loaded_roots.begin(), p.loaded_roots.end(), requested) != p.loaded_roots.end()) return;
    if (p.native_extension_active) bad("LOAD_STATE", "JNI root publication cannot interrupt native module extension");
    if (requested != p.root) {
        if (p.load_state != 2 || p.on_load_active || !p.native_activity_initialized || requested != p.native_activity_root)
            bad("LIBRARY_UNSUPPORTED", "Additional native root lib"+ascii(name)+".so requires another dependency graph; active root is "+p.root);
        // This exact resident root was admitted and initialized for the one
        // immutable NativeActivity package. Select it for actual JNI_OnLoad
        // and recursive JNI resolution, without extending/initializing again.
        p.root = p.native_activity_root;
    }
    const bool initialized = p.load_state == 2;
    // FindClass in JNI_OnLoad can initialize another class that loads this library.
    // This VM has one owner thread; ELF initialization has already finished here.
    if (p.load_state == 1 && p.on_load_active)
        return;
    if (p.load_state && !initialized)
        bad("LOAD_STATE", "Recursive or previously failed JNI library load");
    p.load_state = 1;
    Impl::Scope scope(p);
    try {
        if (!initialized) p.loader.initialize(p.cpu, scope.stack());
        // Constructor/OnLoad peers remain dormant until the idle host pump.
        std::optional<Address> on_load;
        try {
            on_load = p.loader.symbol(p.root, "JNI_OnLoad").address;
        } catch (const elf::ElfError &e) {
            if (e.code != "AETHER_ELF_SYMBOL_UNRESOLVED")
                throw;
        }
        if (on_load) {
            ++p.metrics.on_load_calls;
            const std::array<std::uint64_t, 2> args{java_vm, 0};
            p.on_load_active = true;
            struct EndOnLoad {
                Impl &p;
                ~EndOnLoad() { p.on_load_active = false; }
            } end_on_load{p};
            const bool observed=p.initialization_observer && *on_load%4==0 &&
                p.memory.accessible(*on_load,4,a64::Permission::execute);
            if(observed)p.initialization_observer(p.initialization_context,
                {elf::InitializationStage::jni_on_load_begin,p.root,*on_load});
            const auto result = p.call(*on_load, args, scope.stack());
            if(observed)p.initialization_observer(p.initialization_context,
                {elf::InitializationStage::jni_on_load_end,p.root,*on_load});
            p.check_pending();
            if (result.registers[0] != 0x10006)
                bad("VERSION", "JNI_OnLoad must return the supported JNI 1.6 version");
        }
        p.loaded_roots.push_back(p.root);
        p.load_state = 2;
    } catch(const ThreadExit &exit){
        p.load_state=3;p.pending_exception(0);p.process->checkpoint();p.runtime.exit_current_thread(exit.value);
    } catch (...) {
        p.load_state = 3;
        p.pending_exception(0);
        throw;
    }
}
Value Bridge::invoke(dex::ManagedRuntime &runtime, dex::Index index, std::span<const Value> arguments) {
    auto &p = *impl_;p.process->checkpoint();
    if (std::this_thread::get_id() != p.owner_thread)
        bad("THREAD", "Native library belongs to another runtime thread");
    if (&runtime != &p.runtime || p.closed || (p.load_state != 2 && !p.on_load_active))
        bad("STATE", "Native library is not initialized in this runtime");
    Impl::LogicalScope logical_scope(p);
    p.check_pending();
    p.error.clear();
    const auto &method = runtime.image().methods.at(index);
    const auto &prototype = runtime.image().prototypes.at(method.prototype);
    const auto &owner = runtime.image().types.at(method.owner);
    const auto stat = bool(method.flags & 8);
    // Reserve argument handles as well as the JNI entry guarantee. Null
    // arguments create no handles, so the guest starts with at least sixteen
    // genuinely backed additional locals after marshalling completes.
    std::size_t argument_handles = 1; // Receiver or nonnull declaring Class.
    for (std::size_t i = 0; i < prototype.parameters.size(); ++i)
        if (dex::reference_type(runtime.image().types.at(prototype.parameters[i])) &&
            arguments[i + (stat ? 0 : 1)].bits)
            ++argument_handles;
    Impl::Scope scope(p, argument_handles + 16);
    Address address = 0;
    if (const auto it = p.registered.find(index); it != p.registered.end())
        address = it->second;
    else {
        const auto short_name = "Java_" + mangled(std::string_view(owner).substr(1, owner.size() - 2)) + "_" +
                                mangled(method.name);
        const auto parameters =
            std::string_view(prototype.descriptor).substr(1, prototype.descriptor.find(')') - 1);
        std::vector<std::string_view> roots;
        for (const auto &root : p.loaded_roots) roots.push_back(root);
        if (p.on_load_active) roots.push_back(p.root);
        for (const auto root : roots) {
            for (const auto &symbol : {short_name, short_name + "__" + mangled(parameters)}) {
                try { address = p.loader.symbol(root, symbol).address; break; }
                catch (const elf::ElfError &error) {
                    if (error.code != "AETHER_ELF_SYMBOL_UNRESOLVED") throw;
                }
            }
            if (address) break;
        }
        if (!address) bad("METHOD_UNSUPPORTED", "No loaded native root exports " + short_name);
    }
    std::vector<std::uint64_t> integers{p.current_environment,
                                        p.reference(stat ? runtime.class_object(owner) : arguments[0].bits)};
    std::vector<a64::Vector> floating;
    std::vector<std::uint64_t> spilled;
    for (std::size_t i = 0; i < prototype.parameters.size(); ++i) {
        const auto &type = runtime.image().types.at(prototype.parameters[i]);
        const auto value = arguments[i + (stat ? 0 : 1)];
        const auto bits = dex::reference_type(type) ? p.reference(value.bits) : value.bits;
        if (type == "F" || type == "D") {
            if (floating.size() < 8)
                floating.push_back({bits, 0});
            else
                spilled.push_back(bits);
        } else if (integers.size() < 8)
            integers.push_back(bits);
        else
            spilled.push_back(bits);
    }
    const auto stack = scope.stack();
    if (spilled.size() > 256)
        bad("ARGUMENT_LIMIT", "Too many native stack arguments");
    for (std::size_t i = 0; i < spilled.size(); ++i)
        p.write(stack + i * 8, spilled[i], 8);
    ++p.metrics.native_calls;
    a64::ExecutionResult result;
    try {
        result = p.call(address, integers, stack, floating);
    } catch (...) {
        p.pending_exception(0);
        throw;
    }
    p.check_pending();
    const auto &type = runtime.image().types.at(prototype.return_type);
    if (type == "V")
        return Value::nothing();
    return p.decode(type == "F" || type == "D" ? result.vectors[0][0] : result.registers[0], type);
}
std::optional<std::uint64_t> Bridge::thread_exit_value(Address tls) const noexcept {return impl_->posix.thread_exit_value(tls);}
std::shared_ptr<a64::ThreadRegisterState> Bridge::thread_register_state(Address trusted_tls) const {return impl_->posix.thread_register_state(trusted_tls);}
a64::CpuFaultAction Bridge::synchronous_fault(const a64::CpuException &exception,a64::ArchitecturalState &candidate,
                                               const a64::CpuFaultBoundary &boundary) noexcept {
    if(impl_->closed)return a64::CpuFaultAction::unhandled;
    return impl_->posix.synchronous_fault(exception,candidate,boundary);
}
bool Bridge::pending_signal_entry(const a64::SignalEntry &entry,Address trusted_tls,std::uint64_t invocation) const noexcept {
    return !impl_->closed && impl_->posix.pending_signal_entry(entry,trusted_tls,invocation);
}
bool Bridge::event_pending() noexcept {return impl_->posix.event_pending();}
a64::Fault Bridge::checkpoint(a64::ServiceState &state) noexcept {return impl_->posix.checkpoint(state);}

a64::Fault Bridge::invoke(std::uint32_t service, Address instruction,
                          std::array<std::uint64_t, 31> &registers) noexcept {
    a64::ServiceState state;
    state.registers = registers;
    const auto fault = impl_->invoke_service(service, instruction, state, false);
    registers = state.registers;
    return fault;
}
a64::Fault Bridge::invoke_frame(std::uint32_t service, Address instruction,
                                a64::ServiceState &state) noexcept {
    return impl_->invoke_service(service, instruction, state, true);
}
a64::Fault Bridge::Impl::invoke_service(std::uint32_t service, Address instruction,
                                       a64::ServiceState &state, bool full_frame) noexcept {
    auto &p = *this;
    if(p.process->exit_status())return a64::Fault::process_exit;
    try {
        if (p.closed)bad("STATE","JNI service in closed bridge");
        // Critical APIs return rooted guest copies, never managed heap or host
        // pointers. Guest service calls could block or reenter Java; reject them
        // until the owning context releases every critical copy. CPU budgeting
        // and process-exit checks remain active independently of this guard.
        if (p.critical_active() && !(service >= first_service + 222 && service <= first_service + 225))
            bad("CRITICAL", "Guest service calls are forbidden while a JNI critical copy is held");
        if (service < first_service)
            return p.posix.invoke_frame(service, instruction, state);
        WeakRoots weak_roots(p);
        if (android::NativePlatformServices::handles_service(service)) {
            const auto fault = full_frame ? p.platform.invoke_frame(service, instruction, state)
                                          : p.platform.invoke(service, instruction, state.registers);
            if (fault != a64::Fault::none) p.error = p.platform.last_error();
            return fault;
        }
        if (p.graphics_services && graphics::GuestGraphicsServices::handles_service(service)) {
            const auto owner=p.posix.thread_register_state(p.posix.thread_pointer());
            if(!owner)bad("GRAPHICS_OWNER","Graphics owner is not live");
            if(p.graphics_owner && p.graphics_owner!=owner)bad("GRAPHICS_OWNER_UNSUPPORTED","Multiple logical EGL/GLES owners require explicit binding restoration");
            if(!p.graphics_owner)p.graphics_owner=owner;
            const auto fault = p.graphics_services->invoke_frame(service, instruction, state);
            if (fault != a64::Fault::none) p.error = p.graphics_services->last_error();
            return fault;
        }
        if (p.audio_services && audio::GuestAudioServices::handles_service(service)) {
            const auto fault = p.audio_services->invoke(service, instruction, state.registers);
            if (fault != a64::Fault::none)
                p.error = p.audio_services->last_error();
            return fault;
        }
        ++p.metrics.calls;
        if (service >= first_service && service < first_service + function_count) {
            const auto slot = service - first_service;
            if (instruction != trampolines + slot * 8)
                bad("TRAMPOLINE", "JNI service called from an unregistered PC");
            if(!p.attached || p.frames.empty())bad("THREAD_UNSUPPORTED","Native thread has no JNI attachment");
            p.dispatch(slot, state, full_frame);
        } else if (service >= first_vm_service + 3 && service <= first_vm_service + 7) {
            const auto slot = service - first_vm_service;
            if (instruction != trampolines + 0x800 + slot * 8 || state.registers[0] != java_vm)
                bad("VM", "Invalid JavaVM service identity");
            if(slot==3)bad("THREAD_UNSUPPORTED","DestroyJavaVM is not supported");
            if(slot==7)bad("THREAD_ATTRIBUTES_UNSUPPORTED","Daemon attachment is not implemented");
            if(slot==5) {
                if(p.posix.is_main_native_thread() || !p.runtime.detach_native_thread()){state.registers[0]=static_cast<std::uint32_t>(-1);return a64::Fault::none;}
                p.clear_attachment();state.registers[0]=0;return a64::Fault::none;
            }
            if(!p.memory.accessible(state.registers[1],8,a64::Permission::write))bad("MEMORY","JavaVM output is not writable");
            if(slot==4 || slot==7) {
                if(!p.attached) {
                    if(state.registers[2])bad("THREAD_ATTRIBUTES_UNSUPPORTED","Custom native attachment arguments are not implemented");
                    const auto thread=p.runtime.current_thread();
                    if (!p.allocation_reference([&] { p.push_frame(16); return Handle{1}; })) {
                        p.write(state.registers[1], 0, 8);
                        state.registers[0] = static_cast<std::uint32_t>(-1);
                        return a64::Fault::none;
                    }
                    p.attached=true;p.active_managed_thread=thread;
                    p.active_execution_token=dex::Scheduler::execution_token();
                }
                p.write(state.registers[1],p.current_environment,8);state.registers[0]=0;
            } else if(state.registers[2]!=0x10006) {
                p.write(state.registers[1],0,8);state.registers[0]=static_cast<std::uint32_t>(-3);
            } else {
                p.write(state.registers[1],p.attached?p.current_environment:0,8);
                state.registers[0]=p.attached?0:static_cast<std::uint32_t>(-2);
            }
        } else
            bad("FUNCTION_UNSUPPORTED", "Unknown JNI service ID");
        return a64::Fault::none;
    } catch(const ThreadExit &exit){
        if(p.process->exit_status())return a64::Fault::process_exit;
        p.posix.request_thread_exit(exit.value);return a64::Fault::thread_exit;
    } catch(const ProcessExit &exit){
        p.process->request_exit(exit.status);return a64::Fault::process_exit;
    } catch (const dex::JavaException &e) {
        try {
            p.pending_exception(e.object);
            const auto slot = service - first_service;
            if (slot >= 95 && slot <= 112) {
                if (slot == 102 || slot == 103)
                    state.vectors[0] = {};
                else if (slot <= 101)
                    state.registers[0] = 0;
            } else if (slot < 144 || slot > 162) {
                state.registers[0] = 0;
                state.vectors[0] = {};
            } else if (slot == 152 || slot == 153)
                state.vectors[0] = {};
            else if (slot <= 151)
                state.registers[0] = 0;
            return a64::Fault::none;
        } catch (...) {
            p.error = "AETHER_JNI_EXCEPTION_ROOT: Cannot retain pending exception";
        }
    } catch (const dex::DexError &e) {
        p.error = e.code + ": " + e.what();
    } catch (const std::exception &e) {
        p.error = e.what();
    } catch (...) {
        p.error = "Unknown JNI host failure";
    }
    ++p.metrics.rejected_calls;
    return a64::Fault::unsupported_service;
}
std::optional<std::chrono::steady_clock::time_point> Bridge::next_native_deadline() const {
    std::optional<std::chrono::steady_clock::time_point> result;
    for(const auto *task:impl_->native_tasks)if(task && task->waiting){
        const auto deadline=task->waiting->deadline();
        if(deadline && (!result || *deadline<*result))result=deadline;
    }
    return result;
}
bool Bridge::pump_native_tasks(dex::ManagedRuntime &runtime) {
    auto &p=*impl_;
    if(&runtime!=&p.runtime || p.closed || p.native_closing || p.load_state!=2 || p.on_load_active || p.native_extension_active)return false;
    if(std::this_thread::get_id()!=p.owner_thread || p.native_depth || p.active_native_task ||
        !p.cpu.execution_idle() || !p.frames.empty() || p.resolved_weak_roots || p.critical_active() ||
        p.native_activity_dispatching || p.context || !p.attached || p.current_environment!=environment ||
        !p.posix.native_switch_safe() || !runtime.is_main_thread() || !p.posix.is_main_native_thread())
        bad("NATIVE_INPUT_STATE", "Native idle pump requires its actual idle main owner");
    bool progress=false;
    if(p.posix.has_pending_threads()) {
        const auto fault=p.posix.run_pending_threads(1000000);
        if(fault==a64::Fault::process_exit)p.process->checkpoint();
        if(fault!=a64::Fault::none)bad("NATIVE_EXECUTION",std::string(a64::fault_name(fault))+": "+std::string(p.posix.last_rejection()));
        progress=true;
    }
    const auto post_host_work = [&]() -> bool {
    if(p.native_activity_storage && p.native_activity_storage->created && !p.native_activity_failed) {
        auto &storage=*p.native_activity_storage;
        if(storage.work_count) {
            if(!p.host_work_factory)bad("NATIVE_ACTIVITY_STATE","Queued host work has no managed main consumer");
            const auto work=storage.work[storage.work_head];
            auto entry=p.host_work_factory(work);
            const bool posted = static_cast<bool>(entry);
            try {if(entry)runtime.post_main(std::move(entry));}
            catch(const dex::DexError &error){if(error.code=="AETHER_DEX_MAIN_CALLBACK_LIMIT")return false;throw;}
            auto &credit=storage.work_scope->credits[work.credit_slot];
            if(credit.serial!=work.serial || credit.posted)bad("NATIVE_ACTIVITY_STATE","Host work lost its exact queued credit");
            if(entry)std::terminate(); // Ownership must have moved when a live entry was returned.
            // post_main does not run guest code; arm destructor accounting only now.
            if(posted)credit.posted=true;
            else {credit={};--storage.work_scope->outstanding;}
            storage.work[storage.work_head]={};storage.work_head=(storage.work_head+1)%storage.work.size();--storage.work_count;
            return true;
        }
    }
        return false;
    };
    const bool host_first = p.host_work_first; p.host_work_first = !p.host_work_first;
    if(host_first)progress = post_host_work() || progress;
    // finishEvent only publishes an ordered outcome. Posting occurs here after
    // native frames have returned, never across a service/provider boundary.
    const auto completion=p.posix.peek_input_completion();
    if(completion) {
        if(!p.input_completion_factory)
            bad("NATIVE_INPUT_STATE", "Native input completion has no bound managed main receiver");
        auto entry=p.input_completion_factory(*completion);
        // A null entry is the trusted factory's stale-receiver cancellation.
        try { if(entry)runtime.post_main(std::move(entry)); }
        catch(const dex::DexError &error) {
            if(error.code=="AETHER_DEX_MAIN_CALLBACK_LIMIT")return progress;
            throw;
        }
        // post_main cannot execute guest code. Successful transfer or trusted
        // stale cancellation permits exact head retirement.
        if(!p.posix.commit_input_completion(completion->queue,completion->event))
            bad("NATIVE_INPUT_STATE", "Posted input completion lost its exact ordered queue head");
        progress=true;
    }
    if(!host_first)progress = post_host_work() || progress;
    return progress;
}
std::uint64_t Bridge::capture_signal_mask(dex::ManagedRuntime &runtime) {
    auto &p=*impl_;
    if(&runtime!=&p.runtime)throw a64::GuestError("AETHER_JNI_THREAD","Signal-mask capture from another runtime refused");
    if(p.native_depth || runtime.is_main_thread())return p.posix.signal_mask();
    const auto thread=runtime.current_thread();
    for(const auto &binding:p.managed_bindings)if(binding.thread==thread)return p.posix.binding_signal_mask({binding.tid,binding.tls,binding.tls+0x100,runtime.thread_initial_signal_mask(thread)});
    return runtime.thread_initial_signal_mask(thread);
}
const Metrics &Bridge::metrics() const noexcept { return impl_->metrics; }
const a64::Metrics &Bridge::cpu_metrics() const noexcept { return impl_->cpu.metrics(); }
bool Bridge::trim_translation_cache() {
    auto &p=*impl_;
    if(std::this_thread::get_id()!=p.owner_thread || p.closed || p.native_closing ||
       p.native_depth || !p.frames.empty() || p.pending || p.resolved_weak_roots ||
       p.critical_active() || p.active_native_task || p.on_load_active ||
       p.native_extension_active || p.native_activity_dispatching || !p.cpu.execution_idle())return false;
    if(p.local_frame_count || std::any_of(p.stack_leased.begin(),p.stack_leased.end(),[](bool used){return used;}))
        return false;
    // A different task may have retained its real native C++ stack while the
    // currently selected CPU is idle. Do not turn that parked state into an
    // idle maintenance admission; dormant, never-started children are harmless.
    using TaskState=bionic::GuestPosixServices::ThreadTaskState;
    for(const auto *task:p.native_tasks)
        if(task && task->entered && task->cached!=TaskState::completed &&
           task->cached!=TaskState::cancelled && task->cached!=TaskState::failed)return false;
    return p.cpu.trim_translation_cache();
}
std::string_view Bridge::last_error() const noexcept { return impl_->error; }
void Bridge::shutdown() {
    auto &p = *impl_;
    if(p.active_native_task || p.native_depth || !p.cpu.execution_idle())bad("STATE","Native shutdown requires an idle owner");
    p.native_closing=true;
    p.posix.close_thread_tasks();
    if (p.closed)
        return;
    if(p.process->exit_status()){p.closed=true;if(p.attach_interface)p.runtime.set_native_interface(nullptr);p.cleanup();return;}
    if(p.shutdown_failed)bad("NATIVE_FINALIZATION","Previous native shutdown failed; guest finalization cannot be retried");
    Impl::LogicalScope logical_scope(p);
    if (p.native_depth)
        bad("STATE", "Cannot shut down an active native call");
    if (p.load_state == 2) {
        Impl::Scope scope(p);
        const auto drain=[&]{
            a64::ServiceState state;
            state.stack_pointer=state.stack_top=scope.stack();
            const auto fault=p.posix.finalize_cxa(state);
            p.process->checkpoint();
            if(fault==a64::Fault::thread_exit){
                const auto value=p.posix.thread_exit_value(p.posix.thread_pointer());
                if(!value)bad("NATIVE_FINALIZATION","C++ destructor thread exit has no owned terminal value");
                p.runtime.exit_current_thread(*value);
            }
            if(fault!=a64::Fault::none)
                bad("NATIVE_FINALIZATION",std::string(a64::fault_name(fault))+": "+std::string(p.posix.last_rejection()));
        };
        try{
            // Explicit app-close ordering, not a claim about universal C exit:
            // drain existing registrations, run the ELF fini arrays, then drain
            // registrations created by those arrays before detaching JNI/TLS.
            drain();p.loader.finalize(p.cpu, scope.stack());drain();
        }catch(const ThreadExit &exit){
            p.shutdown_failed=true;p.load_state=3;
            p.process->checkpoint();p.runtime.exit_current_thread(exit.value);
        }catch(...){p.shutdown_failed=true;p.load_state=3;throw;}
    }
    p.closed = true;
    if (p.attach_interface)
        p.runtime.set_native_interface(nullptr);
    p.cleanup();
}
} // namespace aether::jni
