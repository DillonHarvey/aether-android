#include "aether/elf/guest_loader.hpp"
#include "aether/common/thread_exit.hpp"
#include "aether/apk/hash.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <map>
#include <set>

namespace aether::elf {
InitializerError::InitializerError(a64::Fault fault_, std::string message, InitializerContext context_)
    : ElfError("AETHER_ELF_INITIALIZER_FAILED", std::move(message)), fault(fault_), context(std::move(context_)) {}
namespace {
std::string initializer_message(a64::Fault fault, const InitializerContext &context, bool module_truncated) {
    std::string message = "Guest initializer/finalizer failed: " + std::string(a64::fault_name(fault));
    message += context.finalizer ? "; phase=fini; module=\"" : "; phase=init; module=\"";
    std::string suffix = "\"";
    const auto hex = [&](std::string_view name, std::uint64_t value) {
        std::array<char, 16> digits{};
        const auto converted = std::to_chars(digits.data(), digits.data() + digits.size(), value, 16);
        suffix += ' ';suffix += name;suffix += "=0x";
        suffix.append(digits.data(), static_cast<std::size_t>(converted.ptr - digits.data()));
    };
    hex("entry", context.entry);hex("fault_address", context.fault_address);hex("pc", context.pc);
    hex("detail(raw)", context.detail);
    constexpr std::array<std::string_view, 4> names{"x0", "x1", "x2", "x8"};
    for (std::size_t i = 0; i < names.size(); ++i) hex(names[i], context.arguments[i]);
    // All numeric fields remain visible within 350 bytes. Escape only a bounded
    // module prefix; it is an untrusted identity, never format or control text.
    const auto room = 350 - std::min<std::size_t>(350, message.size() + suffix.size());
    const auto end = std::min<std::size_t>(48, context.module.size());
    const auto start = message.size();
    constexpr char digits[] = "0123456789ABCDEF";
    std::size_t at = 0;
    for (; at < end; ++at) {
        const auto byte = static_cast<unsigned char>(context.module[at]);
        std::array<char, 4> escaped{};std::size_t count = 1;
        if (byte == '\\' || byte == '"') {escaped[0] = '\\';escaped[1] = static_cast<char>(byte);count = 2;}
        else if (byte < 0x20 || byte > 0x7e) {escaped = {'\\', 'x', digits[byte >> 4], digits[byte & 15]};count = 4;}
        else escaped[0] = static_cast<char>(byte);
        const auto used = message.size() - start;
        if (room < 3 || used > room - 3 || count > room - 3 - used) break;
        message.append(escaped.data(), count);
    }
    if ((module_truncated || at < context.module.size()) && room >= 3) message += "...";
    message += suffix;
    return message;
}
constexpr Address page = a64::GuestMemory::page_size;
Address down(Address value) { return value & ~(page - 1); }
Address up(Address value) { return down(value + page - 1); }
Address add_signed(Address value, std::int64_t addend) {
    if (addend >= 0) {
        if (static_cast<std::uint64_t>(addend) > std::numeric_limits<Address>::max() - value)
            throw ElfError("AETHER_ELF_RELOCATION_OVERFLOW", "Relocation result overflows 64 bits");
        return value + static_cast<std::uint64_t>(addend);
    }
    const auto magnitude = std::uint64_t{0} - static_cast<std::uint64_t>(addend);
    if (magnitude > value)
        throw ElfError("AETHER_ELF_RELOCATION_OVERFLOW", "Relocation result underflows 64 bits");
    return value - magnitude;
}
GuestSymbol located(const GuestModule &m, const Symbol &s) {
    return {s.name, m.image.soname, s.version, s.absolute ? s.value : m.base + s.value, s.size, s.type};
}
} // namespace
struct GuestLoader::Impl {
    a64::GuestMemory &memory;
    const ImportResolver &imports;
    std::vector<GuestModule> modules;
    std::vector<std::size_t> scope, init_order;
    std::vector<Address> mappings;
    // Owned names survive resident module vector growth across appended graphs.
    // Each list retains breadth-first module order and dynamic symbol order.
    std::map<std::string, std::vector<std::pair<std::size_t, std::size_t>>, std::less<>> exports;
    using LookupIndex=std::map<std::string,std::vector<std::size_t>,std::less<>>;
    // Committed immutable symbol tables; avoid rescanning them on every guest dlsym.
    mutable std::map<std::string,LookupIndex,std::less<>> lookup_exports;
    std::size_t resolution_steps = 0;
    std::size_t relocations = 0;
    std::vector<std::string> hashes;
    Address next = 0x10000000;
    std::uint64_t input_bytes = 0, mapped_bytes = 0;
    bool finalized = false;
    bool loaded = false, loading = false, initialization_started = false, initialization_failed = false;
    Impl(a64::GuestMemory &m, const ImportResolver &i) : memory(m), imports(i) {}
    ~Impl() { clear(); }
    void clear() noexcept {
        // Only mappings successfully created by this loader are owned here.
        for (const auto address : mappings) {
            try {
                memory.unmap(address);
            } catch (...) { /* Already unmapped by the owner. */
            }
        }
        mappings.clear();
        exports.clear();
        lookup_exports.clear();
        modules.clear();
        scope.clear();
        init_order.clear();
        loaded = false;
        relocations = 0;
        resolution_steps = 0;
    }
    std::optional<std::size_t> index(std::string_view name) const {
        for (std::size_t i = 0; i < modules.size(); ++i)
            if (modules[i].image.soname == name)
                return i;
        return std::nullopt;
    }
    void dependencies(std::size_t root, std::size_t first_new) {
        scope.push_back(root);
        for (std::size_t i = 0; i < scope.size(); ++i)
            for (const auto &name : modules[scope[i]].image.needed) {
                const auto dep = index(name);
                if (!dep && !imports.has_library(name))
                    throw ElfError("AETHER_ELF_DEPENDENCY_MISSING", "No registered dependency: " + name + " required by " + modules[scope[i]].image.soname);
                if (dep && std::find(scope.begin(), scope.end(), *dep) == scope.end())
                    scope.push_back(*dep);
            }
        if (std::any_of(modules.begin() + first_new, modules.end(), [&](const auto &m) {
                return std::find(scope.begin(), scope.end(), static_cast<std::size_t>(&m - modules.data())) == scope.end();
            }))
            throw ElfError("AETHER_ELF_DEPENDENCY_UNUSED",
                           "Input contains a module outside the dependency closure");
        std::vector<unsigned> state(modules.size());
        const auto visit = [&](auto &&self, std::size_t at) -> void {
            if (state[at] == 2)
                return;
            if (state[at] == 1)
                throw ElfError("AETHER_ELF_DEPENDENCY_CYCLE",
                               "Cyclic guest dependency initialization is unsupported");
            state[at] = 1;
            for (const auto &name : modules[at].image.needed)
                if (const auto dep = index(name))
                    self(self, *dep);
            state[at] = 2;
            if (at >= first_new) init_order.push_back(at);
        };
        visit(visit, root);
        for (const auto at : scope)
            for (std::size_t i = 0; i < modules[at].image.symbols.size(); ++i) {
                const auto &s = modules[at].image.symbols[i];
                if (s.defined && s.binding != 0 && s.visibility != 1 && s.visibility != 2)
                    exports[s.name].emplace_back(at, i);
            }
    }
    void resolution_step() {
        // One full maximum-size graph scan, shared by all relocation lookups.
        // The name index avoids quadratic scans for ordinary distinct exports;
        // ambiguous version candidates and repeated import searches remain bounded.
        if (resolution_steps == 16 * 65536)
            throw ElfError("AETHER_ELF_LIMIT", "Symbol resolution exceeds 1048576 candidate visits");
        ++resolution_steps;
    }
    std::optional<GuestSymbol> resolve(const GuestModule &owner, const Symbol &s) {
        if (s.defined && (s.binding == 0 || s.visibility != 0))
            return located(owner, s);
        if (const auto found = exports.find(s.name); found != exports.end())
            for (const auto &[at, symbol] : found->second) {
                resolution_step();
                const auto &m = modules[at];
                const auto &candidate = m.image.symbols[symbol];
                if ((s.version_library.empty() || s.defined || m.image.soname == s.version_library) &&
                    (s.version.empty() ? !candidate.version_hidden : s.version == candidate.version))
                    return located(m, candidate);
            }
        std::set<std::string> visited;
        for (const auto at : scope)
            for (const auto &dependency : modules[at].image.needed) {
                resolution_step();
                if (index(dependency) || !visited.insert(dependency).second ||
                    (!s.version_library.empty() && dependency != s.version_library))
                    continue;
                if (const auto found = imports.resolve(dependency, s.name, s.version))
                    return found;
            }
        return std::nullopt;
    }
    void call(a64::GuestCpu &cpu, Address address, Address stack_top,
              std::string_view module, bool finalizer,
              std::optional<Address> thread_pointer = {}) const {
        if (!address || address == std::numeric_limits<Address>::max())
            return;
        if (address % 4 || !memory.accessible(address, 4, a64::Permission::execute))
            throw ElfError("AETHER_ELF_INITIALIZER", "Initializer/finalizer target is not guest executable");
        constexpr std::array<std::uint64_t, 3> arguments{}; // argc, argv, envp for Android constructors.
        const auto result = cpu.call(address, arguments, stack_top, 1'000'000, {}, thread_pointer);
        if(result.fault==a64::Fault::process_exit){cpu.process_checkpoint();throw ProcessExit{static_cast<std::uint8_t>(result.detail)};}
        if(result.fault==a64::Fault::thread_exit)throw ThreadExit{result.registers[0]};
        if (!result.returned) {
            InitializerContext context{std::string(module.substr(0, 48)), address, result.fault_address, result.pc,
                                       result.detail, {result.registers[0], result.registers[1],
                                                       result.registers[2], result.registers[8]}, finalizer};
            const auto fault = result.fault == a64::Fault::none ? a64::Fault::invalid_call : result.fault;
            auto message = initializer_message(fault, context, module.size() > context.module.size());
            throw InitializerError(fault, std::move(message), std::move(context));
        }
    }
    Address read_pointer(Address address) const {
        std::array<std::uint8_t, 8> bytes{};
        if (!memory.read(address, bytes))
            throw ElfError("AETHER_ELF_INITIALIZER", "Cannot read initializer/finalizer array");
        Address value = 0;
        for (std::size_t i = 0; i < bytes.size(); ++i)
            value |= Address{bytes[i]} << (i * 8);
        return value;
    }
};
GuestLoader::GuestLoader(a64::GuestMemory &memory, const ImportResolver &imports)
    : impl_(std::make_unique<Impl>(memory, imports)) {}
GuestLoader::~GuestLoader() = default;
void GuestLoader::load(std::span<const ModuleInput> inputs, std::string_view root) {
    load_graph(inputs, root, false);
}
void GuestLoader::extend(std::span<const ModuleInput> inputs, std::string_view root) {
    load_graph(inputs, root, true);
}
void GuestLoader::load_graph(std::span<const ModuleInput> inputs, std::string_view root, bool additional) {
    auto &p = *impl_;
    if (p.loading || inputs.empty() || inputs.size() > native_graph_modules ||
        (!additional && p.loaded) ||
        (additional && (!p.loaded || !p.initialization_started || p.initialization_failed || p.finalized ||
                       std::any_of(p.modules.begin(), p.modules.end(), [](const auto &m) { return !m.initialized; }))))
        throw ElfError("AETHER_ELF_LOAD_STATE", "Native graph requires a fresh loader or successfully initialized resident modules");
    // A ModuleSource can call trusted observers while being read. Never expose
    // provisional modules before the complete graph mutation has committed.
    struct Loading {
        bool &state;
        explicit Loading(bool &value) : state(value) { state = true; }
        ~Loading() { state = false; }
    } loading{p.loading};
    const auto old_modules = p.modules.size(), old_mappings = p.mappings.size(), old_init = p.init_order.size();
    const auto old_steps = p.resolution_steps;
    auto old_scope = std::move(p.scope);
    auto old_exports = std::move(p.exports);
    Address next = p.next;
    std::uint64_t total_bytes = p.input_bytes, total_relocations = p.relocations, mapped_bytes = p.mapped_bytes;
    try {
        std::vector<std::shared_ptr<ModuleSource>> sources;
        std::set<std::string> supplied;
        const bool streaming =
            std::any_of(inputs.begin(), inputs.end(), [](const auto &input) { return bool(input.source); });
        for (const auto &input : inputs) {
            if (input.source && !input.bytes.empty())
                throw ElfError("AETHER_ELF_SOURCE", "Native input has two competing byte representations");
            if (!supplied.insert(input.name).second)
                throw ElfError("AETHER_ELF_SONAME", "Repeated input SONAME");
            const auto size = input.source ? input.source->size() : input.bytes.size();
            if (size > streamed_native_bytes)
                throw ElfError("AETHER_ELF_LIMIT", "Native input exceeds 128 MiB");
            if (const auto resident = p.index(input.name)) {
                apk::Sha256 hash;
                if (input.source) {
                    std::uint64_t consumed = 0;
                    input.source->stream([&](std::uint64_t offset, Bytes bytes) {
                        if (offset != consumed || bytes.empty() || bytes.size() > 65536 || offset > size || bytes.size() > size-offset)
                            throw ElfError("AETHER_ELF_SOURCE", "Invalid resident identity stream");
                        hash.update(bytes); consumed += bytes.size();
                    });
                    if (consumed != size) throw ElfError("AETHER_ELF_SOURCE", "Incomplete resident identity stream");
                } else hash.update(input.bytes);
                if (hash.finish() != p.hashes[*resident])
                    throw ElfError("AETHER_ELF_SONAME", "Resident SONAME has different content: " + input.name);
                continue;
            }
            if (p.modules.size() == native_graph_modules)
                throw ElfError("AETHER_ELF_LIMIT", "Resident native modules exceed 16");
            if (size > streamed_native_bytes - total_bytes)
                throw ElfError("AETHER_ELF_LIMIT", "Dependency graph exceeds 128 MiB of ELF input");
            total_bytes += size;
            auto image = [&] {
                try { return input.source ? parse(*input.source) : parse(input.bytes); }
                catch (const ElfError &error) {
                    throw ElfError(error.code, "ELF module " + input.name + ": " + error.what());
                }
            }();
            if (image.relocations.size() > 1'048'576 - total_relocations)
                throw ElfError("AETHER_ELF_LIMIT", "Dependency graph exceeds 1048576 relocations");
            total_relocations += image.relocations.size();
            for (const auto &s : image.segments) {
                const auto bytes = up(s.address + s.memory_size) - down(s.address);
                const auto limit = streaming ? streamed_native_bytes : a64::GuestMemory::maximum_bytes;
                if (mapped_bytes > limit || bytes > limit - mapped_bytes)
                    throw ElfError("AETHER_ELF_LIMIT",
                                   "Native dependency graph exceeds its mapped-image budget");
                mapped_bytes += bytes;
            }
            if (input.name != image.soname || p.index(input.name) || p.imports.has_library(input.name))
                throw ElfError("AETHER_ELF_SONAME",
                               "Input identity differs from SONAME or shadows a registered module");
            const auto span = image.span;
            const auto advance = (span + 0xffff) & ~Address{0xffff};
            if (advance > 0x20000000 - next)
                throw ElfError("AETHER_ELF_LIMIT", "Native module addresses exceed reserved image range");
            p.hashes.push_back(input.source ? std::string{} : apk::sha256(input.bytes));
            p.modules.push_back({std::move(image), next});
            sources.push_back(input.source);
            next += (span + 0xffff) & ~Address{0xffff};
        }
        const auto root_index = p.index(root);
        if (!root_index)
            throw ElfError("AETHER_ELF_DEPENDENCY_MISSING", "Root module was not supplied");
        p.dependencies(*root_index, old_modules);
        struct Write {
            Address address, value;
        };
        std::vector<Write> writes;
        writes.reserve(static_cast<std::size_t>(total_relocations));
        // All symbols/relocations resolve before the first guest mapping is made.
        for (std::size_t at = old_modules; at < p.modules.size(); ++at)
            for (const auto &r : p.modules[at].image.relocations) {
                const auto &m = p.modules[at];
                Address value = m.base;
                if (r.type == 1027) {
                    if (r.addend < 0 || static_cast<std::uint64_t>(r.addend) >= m.image.span)
                        throw ElfError("AETHER_ELF_RELOCATION",
                                       "Relative relocation points outside its module span");
                } else {
                    const auto &s = m.image.symbols[r.symbol];
                    const auto symbol = p.resolve(m, s);
                    if (!symbol && (s.binding != 2 || s.defined))
                        throw ElfError(
                            s.version.empty() ? "AETHER_ELF_SYMBOL_UNRESOLVED" : "AETHER_ELF_SYMBOL_VERSION",
                            "Unresolved symbol " + s.name + (s.version.empty() ? "" : "@" + s.version));
                    if (symbol &&
                        ((s.type != 0 && symbol->type != s.type) || (r.type == 1026 && symbol->type != 2)))
                        throw ElfError("AETHER_ELF_SYMBOL_TYPE",
                                       "Incompatible relocation symbol type: " + s.name);
                    value = symbol ? symbol->address : 0;
                }
                writes.push_back({m.base + r.offset, add_signed(value, r.addend)});
            }
        struct Protection {
            Address address;
            a64::Permission permissions;
        };
        std::vector<Protection> protections;
        for (std::size_t module = old_modules; module < p.modules.size(); ++module) {
            const auto &m = p.modules[module];
            for (const auto &s : m.image.segments) {
                const auto begin = down(s.address), end = up(s.address + s.memory_size);
                std::vector<Address> cuts{begin, end};
                for (auto bound : {m.image.relro_begin, m.image.relro_end})
                    if (bound > begin && bound < end)
                        cuts.push_back(bound);
                std::sort(cuts.begin(), cuts.end());
                cuts.erase(std::unique(cuts.begin(), cuts.end()), cuts.end());
                for (std::size_t i = 1; i < cuts.size(); ++i) {
                    auto permissions = s.permissions;
                    if (cuts[i - 1] >= m.image.relro_begin && cuts[i] <= m.image.relro_end)
                        permissions = a64::Permission::read;
                    const auto address = m.base + cuts[i - 1];
                    // Reserve vector capacity before map so allocation failure cannot lose ownership.
                    p.mappings.reserve(p.mappings.size() + 1);
                    p.memory.map(address, static_cast<std::size_t>(cuts[i] - cuts[i - 1]), a64::read_write);
                    p.mappings.push_back(address);
                    protections.push_back({address, permissions});
                }
                if (!sources[module - old_modules] && s.file_size &&
                    !p.memory.write(m.base + s.address,
                                    Bytes{m.image.bytes}.subspan(static_cast<std::size_t>(s.offset),
                                                                 static_cast<std::size_t>(s.file_size))))
                    throw ElfError("AETHER_ELF_MAPPING", "Could not populate guest load segment");
            }
            if (sources[module - old_modules]) {
                apk::Sha256 hash;
                std::uint64_t consumed = 0;
                const auto size = sources[module - old_modules]->size();
                sources[module - old_modules]->stream([&](std::uint64_t offset, Bytes bytes) {
                    if (offset != consumed || bytes.empty() || bytes.size() > 65536 || offset > size ||
                        bytes.size() > size - offset)
                        throw ElfError("AETHER_ELF_SOURCE",
                                       "Native stream has a gap, overlap or invalid chunk");
                    hash.update(bytes);
                    for (const auto &s : m.image.segments) {
                        const auto begin = (std::max)(offset, s.offset);
                        const auto end = (std::min)(offset + bytes.size(), s.offset + s.file_size);
                        if (begin < end &&
                            !p.memory.write(m.base + s.address + begin - s.offset,
                                            bytes.subspan(static_cast<std::size_t>(begin - offset),
                                                          static_cast<std::size_t>(end - begin))))
                            throw ElfError("AETHER_ELF_MAPPING", "Could not stream guest load segment");
                    }
                    consumed += bytes.size();
                });
                if (consumed != size)
                    throw ElfError("AETHER_ELF_SOURCE",
                                   "Native stream ended before the declared file extent");
                p.hashes[module] = hash.finish();
            }
        }
        for (const auto &w : writes) {
            std::array<std::uint8_t, 8> bytes{};
            for (std::size_t i = 0; i < bytes.size(); ++i)
                bytes[i] = static_cast<std::uint8_t>(w.value >> (i * 8));
            if (!p.memory.write(w.address, bytes))
                throw ElfError("AETHER_ELF_RELOCATION", "Could not write guest relocation");
        }
        for (const auto &protection : protections)
            p.memory.protect(protection.address, protection.permissions);
        p.relocations = static_cast<std::size_t>(total_relocations);
        p.input_bytes = total_bytes; p.mapped_bytes = mapped_bytes; p.next = next;
        p.loaded = true;
        p.initialization_started = false;
    } catch (...) {
        while (p.mappings.size() > old_mappings) {
            p.memory.unmap(p.mappings.back()); p.mappings.pop_back();
        }
        p.modules.resize(old_modules); p.hashes.resize(old_modules); p.init_order.resize(old_init);
        p.scope = std::move(old_scope); p.exports = std::move(old_exports); p.resolution_steps = old_steps;
        throw;
    }
}
GuestSymbol GuestLoader::symbol(std::string_view module, std::string_view name) const {
    const auto &p = *impl_;
    if (!p.loaded)
        throw ElfError("AETHER_ELF_LOAD_STATE", "No loaded dependency graph");
    if (const auto at = p.index(module))
        for (const auto &s : p.modules[*at].image.symbols)
            if (s.name == name && s.defined && s.binding && s.visibility != 1 && s.visibility != 2 &&
                !s.version_hidden)
                return located(p.modules[*at], s);
    throw ElfError("AETHER_ELF_SYMBOL_UNRESOLVED", "Export was not found: " + std::string(name));
}
std::optional<GuestSymbol> GuestLoader::lookup(std::string_view root, std::string_view name) const {
    const auto &p = *impl_;
    if (p.loading || (!p.index(root) && !p.imports.has_library(root))) return std::nullopt;
    const std::string symbol_name(name);
    // Rebuild this root's scope, rather than reusing the latest appended graph's
    // relocation scope. Owned names remain valid if a trusted resolver appends a
    // graph; no references into the resident module vector survive its callback.
    std::vector<std::string> scope{std::string(root)};
    std::set<std::string, std::less<>> visited{scope.front()};
    for (std::size_t i = 0; i < scope.size(); ++i)
        if (const auto at = p.index(scope[i]))
            for (const auto &dependency : p.modules[*at].image.needed)
                if (visited.insert(dependency).second) scope.push_back(dependency);
    // At most native_graph_modules parsed symbol tables and their bounded
    // DT_NEEDED lists are visited. Unrelated resident roots are never searched.
    for (const auto &library : scope) {
        if (const auto at = p.index(library)) {
            const auto &module = p.modules[*at];
            auto cached=p.lookup_exports.find(module.image.soname);
            if(cached==p.lookup_exports.end()){
                Impl::LookupIndex index;
                for(std::size_t i=0;i<module.image.symbols.size();++i){
                    const auto &symbol=module.image.symbols[i];
                    if(symbol.defined && (symbol.binding==1 || symbol.binding==2) &&
                        symbol.visibility!=1 && symbol.visibility!=2 && !symbol.version_hidden && symbol.type<=2)
                        index[symbol.name].push_back(i);
                }
                cached=p.lookup_exports.emplace(module.image.soname,std::move(index)).first;
            }
            if(const auto found=cached->second.find(symbol_name);found!=cached->second.end())
                return located(module,module.image.symbols[found->second.front()]);
        } else if (const auto found = p.imports.resolve(library, symbol_name, {}); found && found->type <= 2) {
            return found;
        }
    }
    return std::nullopt;
}
std::optional<AddressInfo> GuestLoader::address_info(Address address) const {
    const auto &p = *impl_;
    if (!p.loaded || p.loading) return std::nullopt;
    for (const auto &module : p.modules) {
        if (address < module.base) continue;
        const auto relative = address - module.base;
        const bool contained = std::any_of(module.image.segments.begin(), module.image.segments.end(),
            [relative](const auto &segment) {
                return relative >= segment.address && relative - segment.address < segment.memory_size;
            });
        if (!contained) continue;
        const auto lowest = std::min_element(module.image.segments.begin(), module.image.segments.end(),
            [](const auto &left, const auto &right) { return left.address < right.address; });
        AddressInfo result{module.image.soname, {}, module.base + down(lowest->address), 0};
        for (const auto &symbol : module.image.symbols) {
            if (symbol.defined && symbol.type != 6 && relative >= symbol.value &&
                relative - symbol.value < symbol.size) {
                result.has_symbol = true;
                result.symbol = symbol.name;
                result.symbol_address = symbol.absolute ? symbol.value : module.base + symbol.value;
                break;
            }
        }
        return result;
    }
    return std::nullopt;
}
std::optional<ProgramHeaderInfo> GuestLoader::program_header_info(std::size_t index) const {
    const auto &p = *impl_;
    if (p.loading)
        throw ElfError("AETHER_ELF_LOAD_STATE", "Program headers are unavailable during graph mutation");
    if (!p.loaded || index >= p.modules.size()) return std::nullopt;
    const auto &module = p.modules[index];
    // Modules remain pinned after dlclose. Each committed module is one actual
    // image load; neither an open handle nor a virtual service is a new image.
    return ProgramHeaderInfo{module.image.soname, module.base, module.image.program_headers,
                             static_cast<std::uint64_t>(p.modules.size())};
}
void GuestLoader::initialize(a64::GuestCpu &cpu, Address stack_top, std::optional<Address> thread_pointer) {
    auto &p = *impl_;
    if (!p.loaded || p.initialization_started)
        throw ElfError("AETHER_ELF_LOAD_STATE",
                       "Initialization requires a fresh, fully loaded dependency graph");
    p.initialization_started = true;
    try {
        for (const auto at : p.init_order) {
            auto &m = p.modules[at];
            if (m.initialized) continue;
            if (m.image.init)
                p.call(cpu, m.base + m.image.init, stack_top, m.image.soname, false, thread_pointer);
            for (std::uint64_t i = 0; i < m.image.init_count; ++i)
                p.call(cpu, p.read_pointer(m.base + m.image.init_array + i * 8), stack_top, m.image.soname, false, thread_pointer);
            m.initialized = true;
        }
    } catch (...) {
        p.initialization_failed = true;
        throw;
    }
}
void GuestLoader::finalize(a64::GuestCpu &cpu, Address stack_top) {
    auto &p = *impl_;
    if (!p.loaded || !p.initialization_started || p.initialization_failed)
        throw ElfError("AETHER_ELF_LOAD_STATE", "Finalization requires successful initialization");
    p.finalized = true;
    for (auto i = p.init_order.rbegin(); i != p.init_order.rend(); ++i) {
        auto &m = p.modules[*i];
        if (m.finalized)
            continue;
        // Do not repeat partially executed finalizers after a guest fault.
        m.finalized = true;
        for (auto j = m.image.fini_count; j > 0; --j)
            p.call(cpu, p.read_pointer(m.base + m.image.fini_array + (j - 1) * 8), stack_top, m.image.soname, true);
        if (m.image.fini)
            p.call(cpu, m.base + m.image.fini, stack_top, m.image.soname, true);
    }
}
const std::vector<GuestModule> &GuestLoader::modules() const noexcept { return impl_->modules; }
std::size_t GuestLoader::relocation_count() const noexcept { return impl_->relocations; }
} // namespace aether::elf
