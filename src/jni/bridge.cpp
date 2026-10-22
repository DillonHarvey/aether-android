#include "aether/jni/bridge.hpp"
#include "aether/common/thread_exit.hpp"
#include "aether/host/process_info.hpp"
#include <algorithm>
#include <atomic>
#include <bit>
#include <map>
#include <set>
#include <thread>
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
} // namespace
struct Bridge::Impl {
    Bridge &bridge;
    dex::ManagedRuntime &runtime;
    a64::GuestMemory &memory;
    std::shared_ptr<ProcessState> process;
    bionic::GuestPosixServices posix;
    elf::GuestLoader loader;
    a64::GuestCpu cpu;
    std::string root, error;
    Metrics metrics;
    std::vector<std::string> loaded_roots;
    unsigned load_state = 0;
    bool on_load_active = false;
    const std::thread::id owner_thread = std::this_thread::get_id();
    std::size_t native_depth = 0;
    bool closed = false;
    bool attach_interface = true;
    struct Ref {
        ObjectId object;
        std::size_t frame;
        bool global;
        Address context;
    };
    struct LocalFrame {
        std::set<Handle> handles;
        bool explicit_frame = false;
    };
    struct MethodId {
        dex::Index index;
        ObjectId owner;
        bool is_static;
    };
    struct Buffer {
        ObjectId string;
        bool utf8;
        std::size_t bytes;
        Address context;
    };
    std::map<Handle, Ref> refs;
    std::vector<LocalFrame> frames;
    std::map<Handle, MethodId> methods;
    std::map<dex::Index, Address> registered;
    std::map<Address, Buffer> buffers;
    std::vector<Address> mappings;
    Address buffer_next = 0x50000000;
    std::size_t buffer_bytes = 0;
    ObjectId pending = 0;
    Address context=0,current_environment=Bridge::environment;
    bool attached=true;
    struct ManagedBinding {ObjectId thread=0;Address tls=0;bool mapped=false;std::uint32_t tid=0;};
    std::array<ManagedBinding,16> managed_bindings{};
    std::uint32_t next_managed_tid=0x40000000;
    ObjectId active_managed_thread=0;
    std::uint64_t active_execution_token=0;
    Impl(Bridge &bridge, dex::ManagedRuntime &runtime, a64::GuestMemory &memory, const a64::AppContext &app,
         const host::TimeService &time, std::span<const elf::ModuleInput> modules, std::string root,
         host::FileService *files, bool attach_interface,std::string_view package)
        : bridge(bridge), runtime(runtime), memory(memory), process(app.process_state), posix(memory, app, time, 1, files,nullptr,package),
          loader(memory, posix), cpu(memory, app, &bridge), root(std::move(root)),
          attach_interface(attach_interface) {
        try {
            runtime.bind_process_state(process);process->checkpoint();
            posix.set_managed_priority_service(runtime.thread_priority_baseline(),[this](std::optional<std::int32_t> nice){return this->runtime.thread_priority(nice);});
            cpu.set_thread_pointer(posix.thread_pointer());
            posix.set_signal_runner([this](Address entry,std::uint32_t signal,Address stack,Address tls){return cpu.call(entry,std::array<std::uint64_t,1>{signal},stack,1'000'000,{},tls);});
        posix.set_thread_runner([this](Address entry,Address argument,Address stack,Address tls,std::uint64_t budget) {
                return run_worker(entry,argument,stack,tls,budget);
            });
            loader.load(modules, this->root);
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
            for (unsigned i = 0; i < 32; ++i)
                map(stacks + i * stride, stack_size);
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
        try {
            if (pending) {
                runtime.release(pending);
                pending = 0;
            }
            for (auto &[handle, ref] : refs) {
                (void)handle;
                runtime.release(ref.object);
            }
            refs.clear();
            frames.clear();
            metrics.local_references = metrics.global_references = 0;
            for (auto &[address, buffer] : buffers) {
                runtime.release(buffer.string);
                memory.unmap(address);
            }
            buffers.clear();
            metrics.string_buffers = 0;
            for(auto &binding:managed_bindings)release_managed_binding(binding);
            for (auto it = mappings.rbegin(); it != mappings.rend(); ++it)
                memory.unmap(*it);
            mappings.clear();
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
    ObjectId resolve(Handle handle) const {
        if (!handle)
            return 0;
        const auto it = refs.find(handle);
        if (it == refs.end() || (!it->second.global && it->second.context!=context))
            bad("REFERENCE", "Invalid, deleted or foreign JNI reference");
        return it->second.object;
    }
    Handle reference(ObjectId object, bool global = false) {
        if (!object)
            return 0;
        if (refs.size() >= 4096 || (!global && (frames.empty() || frames.back().handles.size() >= 1024)))
            bad("REFERENCE_LIMIT", "JNI reference/frame quota exhausted");
        const auto handle = identity();
        runtime.retain(object);
        try {
            refs.emplace(handle, Ref{object, frames.size(), global,context});
            if (!global)
                frames.back().handles.insert(handle);
        } catch (...) {
            refs.erase(handle);
            runtime.release(object);
            throw;
        }
        ++metrics.references_created;
        if (global)
            ++metrics.global_references;
        else
            ++metrics.local_references;
        return handle;
    }
    void erase(Handle handle, bool global) {
        if (!handle)
            return;
        const auto it = refs.find(handle);
        if (it == refs.end() || it->second.global != global || (!global && it->second.context!=context))
            bad("REFERENCE", "Reference deletion has wrong kind or stale handle");
        runtime.release(it->second.object);
        if (global)
            --metrics.global_references;
        else {
            frames.at(it->second.frame - 1).handles.erase(handle);
            --metrics.local_references;
        }
        refs.erase(it);
    }
    void pop() {
        if (frames.empty())
            bad("FRAME", "No JNI local frame");
        while (!frames.back().handles.empty()) {
            erase(*frames.back().handles.begin(), false);
            ++metrics.automatic_local_deletions;
        }
        frames.pop_back();
    }
    void release_managed_binding(ManagedBinding &binding) {
        if(!binding.thread)return;
        for(auto it=buffers.begin();it!=buffers.end();) {
            if(it->second.context!=binding.tls){++it;continue;}
            memory.unmap(it->first);runtime.release(it->second.string);buffer_bytes-=it->second.bytes;it=buffers.erase(it);
        }
        metrics.string_buffers=buffers.size();
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
        explicit Scope(Impl &p) : p(p), base(p.frames.size()) {
            if (p.native_depth >= 32)
                bad("CALL_DEPTH", "Native stack depth exceeded");
            p.frames.push_back({});
            ++p.native_depth;
        }
        ~Scope() {
            while (p.frames.size() > base)
                p.pop();
            --p.native_depth;
        }
        Address stack() const { return stacks + (p.native_depth - 1) * stride + stack_size - 4096; }
    };
    void clear_attachment() {
        while(!frames.empty())pop();
        pending_exception(0);
        for(auto it=buffers.begin();it!=buffers.end();) {
            if(it->second.context!=context){++it;continue;}
            memory.unmap(it->first);runtime.release(it->second.string);buffer_bytes-=it->second.bytes;it=buffers.erase(it);
        }
        metrics.string_buffers=buffers.size();attached=false;
    }
    bionic::GuestPosixServices::ThreadExecution run_worker(Address entry,Address argument,Address stack,Address tls,std::uint64_t budget) {
        const auto before=cpu.metrics().guest_ticks;a64::ExecutionResult result;
        try {runtime.run_native_thread([&]{
            auto parent_frames=std::move(frames);const auto parent_pending=std::exchange(pending,0);
            const auto parent_context=context,parent_environment=current_environment;const auto parent_attached=attached;
            context=tls;current_environment=tls+0x200;attached=false;frames.clear();
            struct Restore {
                Impl &p;std::vector<LocalFrame> frames;ObjectId pending;Address context,environment;bool attached;
                ~Restore(){p.clear_attachment();p.frames=std::move(frames);p.pending=pending;p.context=context;p.current_environment=environment;p.attached=attached;}
            } restore{*this,std::move(parent_frames),parent_pending,parent_context,parent_environment,parent_attached};
            write(current_environment,function_table,8);
            result=cpu.call(entry,std::array{argument},stack,budget,{},tls);
        },[this](std::optional<std::int32_t> nice){return posix.current_thread_priority(nice);});}
        catch(const ThreadExit &exit){process->checkpoint();posix.request_thread_exit(exit.value);result.fault=a64::Fault::thread_exit;result.registers[0]=exit.value;}
        return {result,cpu.metrics().guest_ticks-before};
    }
    void pending_exception(ObjectId object) {
        if (object)
            runtime.retain(object);
        if (pending)
            runtime.release(pending);
        pending = object;
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
                                 unsigned variant) {
        std::vector<Value> result;
        unsigned gp = 3, fp = 0;
        Address stack = state.stack_pointer, gr_top = 0, vr_top = 0;
        std::int32_t gr_off = 0, vr_off = 0;
        if (variant == 1) {
            const auto list = state.registers[3];
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
                bits = read(state.registers[3] + i * 8, 8);
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
    void callback(unsigned slot, a64::ServiceState &state) {
        const bool stat = slot >= 114;
        const auto first = stat ? 114u : 34u;
        const auto category = (slot - first) / 3, variant = (slot - first) % 3;
        const auto it = methods.find(state.registers[2]);
        if (it == methods.end() || it->second.is_static != stat)
            bad("METHOD_ID", "Invalid JNI method ID/category");
        const auto &id = it->second;
        const auto &method = runtime.image().methods.at(id.index);
        const auto &prototype = runtime.image().prototypes.at(method.prototype);
        const auto &type = runtime.image().types.at(prototype.return_type);
        constexpr std::string_view returns = "LZBCSIJFDV";
        if ((category == 0 && !dex::reference_type(type)) ||
            (category != 0 && type != returns.substr(category, 1)))
            bad("SIGNATURE", "JNI Call* return category disagrees with method prototype");
        auto args = arguments(prototype, state, variant);
        if (stat) {
            if (resolve(state.registers[1]) != id.owner)
                bad("METHOD_ID", "Method ID does not belong to the supplied class");
        } else
            args.insert(args.begin(), Value::reference(resolve(state.registers[1])));
        ++metrics.managed_callbacks;
        const auto result = stat ? runtime.invoke(id.index, args) : runtime.invoke_virtual(id.index, args);
        if (dex::reference_type(type))
            state.registers[0] = reference(result.bits);
        else if (type == "F" || type == "D")
            state.vectors[0] = {result.bits, 0};
        else
            state.registers[0] = result.bits;
    }
    void method_lookup(a64::ServiceState &state, bool stat) {
        const auto owner = resolve(state.registers[1]);
        const auto type = runtime.represented_class(owner);
        const auto name = text(state.registers[2], 1024), signature = text(state.registers[3], 1024);
        dex::Index index;
        try {
            index = runtime.lookup(type, name, signature, stat);
            runtime.initialize(type);
        } catch (const dex::DexError &e) {
            if (e.code != "AETHER_DEX_METHOD_NOT_FOUND" && e.code != "AETHER_DEX_SIGNATURE")
                throw;
            error = e.code + ": " + e.what();
            java_error("Ljava/lang/NoSuchMethodError;");
            state.registers[0] = 0;
            return;
        }
        for (const auto &[handle, id] : methods)
            if (id.index == index && id.owner == owner && id.is_static == stat) {
                state.registers[0] = handle;
                return;
            }
        if (methods.size() >= 4096)
            bad("METHOD_LIMIT", "Too many JNI method IDs");
        const auto handle = identity();
        methods.emplace(handle, MethodId{index, owner, stat});
        state.registers[0] = handle;
    }
    Address string_buffer(ObjectId id, bool utf8) {
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
        const auto size = (bytes.size() + 4095) & ~std::size_t{4095};
        if (buffers.size() >= 256 || size > 1024 * 1024 - buffer_bytes || buffer_next + size >= 0x60000000)
            bad("BUFFER_LIMIT", "JNI string buffer quota exhausted");
        const auto address = buffer_next;
        buffer_next += size;
        memory.map(address, size, a64::read_write);
        bool retained = false;
        try {
            if (!memory.write(address, bytes))
                bad("MEMORY", "Cannot populate JNI string buffer");
            memory.protect(address, a64::Permission::read);
            runtime.retain(id);
            retained = true;
            buffers.emplace(address, Buffer{id, utf8, size,context});
        } catch (...) {
            if (retained)
                runtime.release(id);
            memory.unmap(address);
            throw;
        }
        buffer_bytes += size;
        metrics.string_buffers = buffers.size();
        return address;
    }
    void release_string(ObjectId id, Address address, bool utf8) {
        const auto it = buffers.find(address);
        if (it == buffers.end() || it->second.string != id || it->second.utf8 != utf8 || it->second.context!=context)
            bad("BUFFER", "Mismatched or double JNI string release");
        memory.unmap(address);
        runtime.release(id);
        buffer_bytes -= it->second.bytes;
        buffers.erase(it);
        metrics.string_buffers = buffers.size();
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
    void dispatch(unsigned slot, a64::ServiceState &state) {
        auto &r = state.registers;
        if (!attached || r[0] != current_environment)
            bad("ENVIRONMENT", "JNIEnv does not belong to this app/thread");
        if (pending && slot != 15 && slot != 17 && slot != 228 && slot != 22 && slot != 23 && slot != 20 &&
            slot != 166 && slot != 170)
            bad("PENDING_EXCEPTION", "JNI operation is not allowed with a pending exception");
        if ((slot >= 34 && slot <= 63) || (slot >= 114 && slot <= 143)) {
            callback(slot, state);
            return;
        }
        if (slot >= 199 && slot <= 214) {
            array_region(slot, state);
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
            r[0] = reference(pending);
            break;
        case 17:
            pending_exception(0);
            r[0] = 0;
            break;
        case 19:
            if (r[1] > 1024 || frames.size() >= 128)
                bad("FRAME_LIMIT", "Invalid JNI local frame capacity");
            frames.push_back({{}, true});
            r[0] = 0;
            break;
        case 20: {
            if (frames.empty() || !frames.back().explicit_frame)
                bad("FRAME", "Cannot pop the native call's automatic frame");
            const auto object = resolve(r[1]);
            if (object)
                runtime.retain(object);
            pop();
            try {
                r[0] = reference(object);
            } catch (...) {
                if (object)
                    runtime.release(object);
                throw;
            }
            if (object)
                runtime.release(object);
            break;
        }
        case 21:
            r[0] = reference(resolve(r[1]), true);
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
            r[0] = reference(resolve(r[1]));
            break;
        case 26:
            if (r[1] > 1024 || frames.empty() || r[1] > 1024 - frames.back().handles.size())
                bad("REFERENCE_LIMIT", "Insufficient JNI local capacity");
            r[0] = 0;
            break;
        case 27:
            r[0] = reference(runtime.new_object(runtime.represented_class(resolve(r[1]))));
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
        case 228:
            r[0] = pending != 0;
            break;
        case 232: {
            if (!r[1]) {
                r[0] = 0;
                break;
            }
            (void)resolve(r[1]);
            r[0] = refs.at(r[1]).global ? 2 : 1;
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
               host::FileService *files, bool attach_interface,std::string_view package)
    : impl_(std::make_unique<Impl>(*this, runtime, memory, app, time, modules, std::move(root), files,
                                   attach_interface,package)) {}
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
    Impl::Scope scope(p);
    const auto &method = runtime.image().methods.at(index);
    const auto &prototype = runtime.image().prototypes.at(method.prototype);
    const auto &owner = runtime.image().types.at(method.owner);
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
    const auto stat = bool(method.flags & 8);
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

a64::Fault Bridge::invoke(std::uint32_t service, Address instruction,
                          std::array<std::uint64_t, 31> &registers) noexcept {
    a64::ServiceState state;
    state.registers = registers;
    const auto fault = invoke_frame(service, instruction, state);
    registers = state.registers;
    return fault;
}
a64::Fault Bridge::invoke_frame(std::uint32_t service, Address instruction,
                                a64::ServiceState &state) noexcept {
    auto &p = *impl_;
    if(p.process->exit_status())return a64::Fault::process_exit;
    if (service < first_service)
        return p.posix.invoke_frame(service, instruction, state);
    try {
        ++p.metrics.calls;
        if (p.closed)bad("STATE","JNI service in closed bridge");
        if (service >= first_service && service < first_service + function_count) {
            const auto slot = service - first_service;
            if (instruction != trampolines + slot * 8)
                bad("TRAMPOLINE", "JNI service called from an unregistered PC");
            if(!p.attached || p.frames.empty())bad("THREAD_UNSUPPORTED","Native thread has no JNI attachment");
            p.dispatch(slot, state);
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
                    p.runtime.current_thread();p.frames.push_back({});p.attached=true;
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
            state.registers[0] = 0;
            state.vectors[0] = {};
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
    Impl::LogicalScope logical_scope(p);
    if (p.native_depth)
        bad("STATE", "Cannot shut down an active native call");
    if (p.load_state == 2) {
        Impl::Scope scope(p);
        try{p.loader.finalize(p.cpu, scope.stack());}
        catch(const ThreadExit &exit){p.process->checkpoint();p.runtime.exit_current_thread(exit.value);}
    }
    p.closed = true;
    if (p.attach_interface)
        p.runtime.set_native_interface(nullptr);
    p.cleanup();
}
} // namespace aether::jni
