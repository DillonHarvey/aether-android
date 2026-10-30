#include "aether/jni/bridge.hpp"
#include "aether/audio/guest.hpp"
#include "aether/common/thread_exit.hpp"
#include "aether/host/process_info.hpp"
#include <algorithm>
#include <atomic>
#include <bit>
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
constexpr Address trampolines = 0x62000, stacks = 0x32000000, stride = 0x11000, stack_size = 0x10000;
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
  public:
    Imports(bionic::GuestPosixServices &posix, audio::GuestAudioServices *audio) : posix(posix), audio_services(audio) {}
    bool has_library(std::string_view library) const noexcept override {
        return posix.has_library(library) || (audio_services && audio_services->has_library(library));
    }
    std::optional<elf::GuestSymbol> resolve(std::string_view library, std::string_view name,
                                           std::string_view version) const override {
        // Existing platform libraries retain their exact resolver/version rules.
        // Audio adds only its own registered library; unknown exports still fail.
        return audio_services && audio_services->has_library(library)
                   ? audio_services->resolve(library, name, version)
                   : posix.resolve(library, name, version);
    }
};
} // namespace
struct Bridge::Impl {
    Bridge &bridge;
    dex::ManagedRuntime &runtime;
    a64::GuestMemory &memory;
    std::shared_ptr<ProcessState> process;
    bionic::GuestPosixServices posix;
    audio::GuestAudioServices *audio_services;
    Imports imports;
    elf::GuestLoader loader;
    a64::GuestCpu cpu;
    std::string root, error;
    Metrics metrics;
    std::vector<std::string> loaded_roots;
    unsigned load_state = 0;
    bool on_load_active = false;
    ModuleProvider module_provider;
    bool dynamic_poisoned=false;
    const std::thread::id owner_thread = std::this_thread::get_id();
    std::size_t native_depth = 0;
    bool closed = false, shutdown_failed = false;
    bool attach_interface = true;
    struct Ref {
        ObjectId object;
        std::size_t frame, root_slot;
        bool global, weak = false;
        Address context;
    };
    struct LocalFrame {
        std::vector<Handle> handles;
        std::size_t guaranteed_capacity = 0;
        bool explicit_frame = false;
        explicit LocalFrame(bool is_explicit = false) : explicit_frame(is_explicit) {
            // Every published frame owns reusable backing for its full local
            // bound. Push may fail here; successful Ensure never allocates.
            handles.reserve(1024);
        }
    };
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
    std::vector<ObjectId> *resolved_weak_roots = nullptr;
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
    std::vector<LocalFrame> frames;
    std::map<Handle, MethodId> methods;
    // Field IDs identify runtime declarations, never JNI reference handles.
    std::map<Handle, dex::Index> fields;
    std::map<dex::Index, Address> registered;
    std::map<Address, Buffer> buffers;
    std::vector<Address> mappings;
    std::array<bool, 32> stack_owned{};
    Address buffer_next = 0x50000000;
    std::size_t buffer_bytes = 0;
    ObjectId pending = 0;
    ObjectId allocation_error = 0; // Borrowed runtime-owned OOME; never retained/released as a pending pin.
    Address context=0,current_environment=Bridge::environment;
    bool attached=true;
    struct ManagedBinding {ObjectId thread=0;Address tls=0;bool mapped=false;std::uint32_t tid=0;};
    std::array<ManagedBinding,16> managed_bindings{};
    std::uint32_t next_managed_tid=0x40000000;
    ObjectId active_managed_thread=0;
    std::uint64_t active_execution_token=0;
    Impl(Bridge &bridge, dex::ManagedRuntime &runtime, a64::GuestMemory &memory, const a64::AppContext &app,
         const host::TimeService &time, std::span<const elf::ModuleInput> modules, std::string root,
         host::FileService *files, bool attach_interface,std::string_view package,
         audio::GuestAudioServices *audio)
        : bridge(bridge), runtime(runtime), memory(memory), process(app.process_state), posix(memory, app, time, 1, files,nullptr,package),
          audio_services(audio), imports(posix, audio), loader(memory, imports), cpu(memory, app, &bridge), root(std::move(root)),
          attach_interface(attach_interface) {
        try {
            runtime.bind_process_state(process);process->checkpoint();
            allocation_error = runtime.prepare_native_allocation_error();
            refs.reserve(reference_roots.size());
            reference_roots_token = runtime.register_native_roots(reference_roots);
            posix.set_managed_priority_service(runtime.thread_priority_baseline(),[this](std::optional<std::int32_t> nice){return this->runtime.thread_priority(nice);});
            cpu.set_thread_pointer(posix.thread_pointer());
            posix.set_once_runner([this](Address entry,Address stack,Address tls,std::uint64_t budget){return cpu.call(entry,{},stack,budget,{},tls);});
            posix.set_phdr_runner([this](Address entry,std::array<std::uint64_t,3> args,Address stack,Address tls,std::uint64_t budget){
                const auto before=cpu.metrics().guest_ticks;
                auto result=cpu.call(entry,args,stack,budget,{},tls);
                return bionic::GuestPosixServices::PhdrExecution{std::move(result),cpu.metrics().guest_ticks-before};
            });
            posix.set_cxa_runner([this](Address entry,Address argument,Address stack,Address tls,std::uint64_t budget){
                const auto before=cpu.metrics().guest_ticks;
                auto result=cpu.call(entry,std::array{argument},stack,budget,{},tls);
                return bionic::GuestPosixServices::CxaExecution{std::move(result),cpu.metrics().guest_ticks-before};
            });
            posix.set_signal_runner([this](Address entry,std::uint32_t signal,Address stack,Address tls){return cpu.call(entry,std::array<std::uint64_t,1>{signal},stack,1'000'000,{},tls);});
        posix.set_thread_runner([this](Address entry,Address argument,Address stack,Address tls,std::uint64_t budget) {
                return run_worker(entry,argument,stack,tls,budget);
            });
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
            auto &binding=managed_bindings[slot];release_managed_binding(binding);
            const auto tls=Address{0x36000000}+slot*0x2000;runtime.retain(thread);bool mapped=false;
            try {
                memory.map(tls,4096,a64::read_write);mapped=true;
                write(tls,tls,8);write(tls+8,id,8);write(tls+40,read(0x25028,8),8);write(tls+0x200,function_table,8);
                binding={thread,tls,true,id};next_managed_tid=id;
            }catch(...){if(mapped)memory.unmap(tls);runtime.release(thread);throw;}
        }
        const auto tls=managed_bindings[slot].tls;return {managed_bindings[slot].tid,tls,tls+0x100,runtime.thread_initial_signal_mask(thread)};
    }
    struct LogicalScope {
        Impl &p;ObjectId owner;std::uint64_t token;bool switched=false;
        std::vector<LocalFrame> frames;ObjectId pending=0;Address context=0,environment=0,tls=0;bool attached=false;
        std::optional<bionic::GuestPosixServices::ThreadBinding> binding;
        explicit LogicalScope(Impl &p):p(p),owner(p.active_managed_thread),token(p.active_execution_token) {
            const auto thread=p.runtime.current_thread(),execution=dex::Scheduler::execution_token();
            if(p.native_depth && (owner!=thread || token!=execution))bad("THREAD","Native CPU belongs to another logical thread");
            const bool main=p.runtime.is_main_thread();
            if(!main) {
                const auto selected=p.managed_binding(thread);
                if(p.context!=selected.tls) {
                    if(p.native_depth)bad("THREAD","Cannot switch a live native attachment");
                    tls=p.posix.thread_pointer();p.cpu.set_thread_pointer(selected.tls);
                    try{binding=p.posix.exchange_thread_binding(selected);}catch(...){p.cpu.set_thread_pointer(tls);throw;}
                    frames=std::move(p.frames);pending=std::exchange(p.pending,0);context=p.context;environment=p.current_environment;attached=p.attached;
                    p.context=selected.tls;p.current_environment=selected.tls+0x200;p.attached=true;p.frames.clear();switched=true;
                }
            } else if(p.context)bad("THREAD","Main entry cannot borrow a background attachment");
            p.active_managed_thread=thread;p.active_execution_token=execution;
        }
        ~LogicalScope(){
            if(switched){while(!p.frames.empty())p.pop();p.pending_exception(0);p.frames=std::move(frames);p.pending=pending;p.context=context;p.current_environment=environment;p.attached=attached;p.posix.exchange_thread_binding(binding);p.cpu.set_thread_pointer(tls);}
            p.active_managed_thread=owner;p.active_execution_token=token;
        }
    };
    struct Scope {
        Impl &p;
        std::size_t base;
        explicit Scope(Impl &p, std::size_t capacity = 16) : p(p), base(p.frames.size()) {
            if (p.native_depth >= 32)
                bad("CALL_DEPTH", "Native stack depth exceeded");
            if (!p.allocation_reference([&] { p.push_frame(capacity); return Handle{1}; }))
                p.check_pending();
            ++p.native_depth;
        }
        ~Scope() {
            while (p.frames.size() > base)
                p.pop();
            --p.native_depth;
        }
        Address stack() const {
            const auto depth = p.native_depth - 1;
            const auto address = stacks + depth * stride;
            if (!p.stack_owned[depth]) {
                // map() records ownership only after a successful, nonoverlapping
                // allocation. Never adopt an existing guest mapping as a stack.
                p.map(address, stack_size);
                p.stack_owned[depth] = true;
            }
            return address + stack_size - 4096;
        }
    };
    void dynamic_open(std::string_view name) try {
        process->checkpoint();
        if(std::this_thread::get_id()!=owner_thread || closed || dynamic_poisoned)
            throw elf::ElfError("AETHER_ELF_LOAD_STATE","Dynamic module owner is unavailable");
        if(imports.has_library(name))return;
        for(const auto &module:loader.modules())if(module.image.soname==name && module.initialized)return;
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
    std::uint64_t native_charged_ticks=0;
    bionic::GuestPosixServices::ThreadExecution thread_guest_call(Address entry,Address argument,Address stack,Address tls,std::uint64_t budget) {
        process->checkpoint();
        const auto available=std::min(budget,runtime.thread_instruction_budget());
        bionic::GuestPosixServices::ThreadExecution out;
        if(!available){out.result.fault=a64::Fault::budget;return out;}
        const auto before=cpu.metrics().guest_ticks,charged_before=native_charged_ticks;
        out.result=cpu.call(entry,std::array{argument},stack,available,{},tls);
        out.ticks=cpu.metrics().guest_ticks-before;
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
        const auto before=cpu.metrics().guest_ticks;a64::ExecutionResult result;bool finalization_failed=false;
        try {runtime.run_native_thread([&]{
            auto parent_frames=std::move(frames);const auto parent_pending=std::exchange(pending,0);
            const auto parent_context=context,parent_environment=current_environment;const auto parent_attached=attached;
            context=tls;current_environment=tls+0x200;attached=false;frames.clear();
            struct Restore {
                Impl &p;std::vector<LocalFrame> frames;ObjectId pending;Address context,environment;bool attached;
                ~Restore(){p.clear_attachment();p.frames=std::move(frames);p.pending=pending;p.context=context;p.current_environment=environment;p.attached=attached;}
            } restore{*this,std::move(parent_frames),parent_pending,parent_context,parent_environment,parent_attached};
            write(current_environment,function_table,8);
            result=thread_guest_call(entry,argument,stack,tls,budget).result;
            if(result.returned || result.fault==a64::Fault::thread_exit){
                runtime.run_thread_finalizers([&]{
                    const auto spent=cpu.metrics().guest_ticks-before;
                    const auto cleanup=finalize_bound_thread(stack,spent>=budget?0:budget-spent);
                    if(cleanup.finalization_failed){result=cleanup.result;result.returned=false;finalization_failed=true;}
                });
            }
        },[this](std::optional<std::int32_t> nice){return posix.current_thread_priority(nice);});}
        catch(const ThreadExit &exit){process->checkpoint();if(!finalization_failed){posix.request_thread_exit(exit.value);result.fault=a64::Fault::thread_exit;result.registers[0]=exit.value;}}
        return {result,cpu.metrics().guest_ticks-before,finalization_failed};
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
                              std::span<const a64::Vector> floats = {}) {
        process->checkpoint();
        const auto before=cpu.metrics().guest_ticks;
        const auto result = cpu.call(address, args, stack, 1'000'000, floats,posix.thread_pointer());
        if(result.fault==a64::Fault::process_exit){process->request_exit(result.detail);process->checkpoint();}
        if(result.fault==a64::Fault::thread_exit)runtime.exit_current_thread(result.registers[0]);
        if (!result.returned)
            bad("NATIVE_EXECUTION", std::string(a64::fault_name(result.fault)) + ": " + error + "; " +
                                        std::string(posix.last_rejection()));
        if (critical_active())
            bad("CRITICAL", "Native return with an unreleased JNI critical copy");
        const auto spent=cpu.metrics().guest_ticks-before;
        const auto thread_fault=posix.run_pending_threads(spent>=1000000?0:1000000-spent);
        if(thread_fault==a64::Fault::process_exit)process->checkpoint();
        if(thread_fault!=a64::Fault::none)bad("NATIVE_EXECUTION",std::string(a64::fault_name(thread_fault))+": "+error+"; "+std::string(posix.last_rejection()));
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
               audio::GuestAudioServices *audio)
    : impl_(std::make_unique<Impl>(*this, runtime, memory, app, time, modules, std::move(root), files,
                                   attach_interface,package,audio)) {}
Bridge::~Bridge() {
    if (impl_ && impl_->attach_interface)
        impl_->runtime.set_native_interface(nullptr);
}
bool Bridge::has_library(std::string_view root) const noexcept {
    return impl_->root == root || std::find(impl_->loaded_roots.begin(), impl_->loaded_roots.end(), root) != impl_->loaded_roots.end();
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
    if (requested != p.root)
        bad("LIBRARY_UNSUPPORTED", "Additional native root lib"+ascii(name)+".so requires another dependency graph; active root is "+p.root);
    if (p.load_state == 2)
        return;
    // FindClass in JNI_OnLoad can initialize another class that loads this library.
    // This VM has one owner thread; ELF initialization has already finished here.
    if (p.load_state == 1 && p.on_load_active)
        return;
    if (p.load_state)
        bad("LOAD_STATE", "Recursive or previously failed JNI library load");
    p.load_state = 1;
    Impl::Scope scope(p);
    try {
        p.loader.initialize(p.cpu, scope.stack());
        if(const auto fault=p.posix.run_pending_threads();fault!=a64::Fault::none){p.process->checkpoint();bad("NATIVE_EXECUTION",std::string(a64::fault_name(fault))+": "+std::string(p.posix.last_rejection()));}
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
            const auto result = p.call(*on_load, args, scope.stack());
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
                    p.runtime.current_thread();
                    if (!p.allocation_reference([&] { p.push_frame(16); return Handle{1}; })) {
                        p.write(state.registers[1], 0, 8);
                        state.registers[0] = static_cast<std::uint32_t>(-1);
                        return a64::Fault::none;
                    }
                    p.attached=true;
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
std::string_view Bridge::last_error() const noexcept { return impl_->error; }
void Bridge::shutdown() {
    auto &p = *impl_;
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
