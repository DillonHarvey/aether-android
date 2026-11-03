#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "aether/elf/limits.hpp"
#include <array>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aether::elf {
using a64::Address;
using Bytes = std::span<const std::uint8_t>;
struct ModuleRange {
    std::uint64_t offset = 0, size = 0;
};
// Immutable, caller-authorized module content. Reads retain only requested
// metadata; streaming visits the complete file without retaining a file image.
class ModuleSource {
  public:
    virtual ~ModuleSource() = default;
    virtual std::uint64_t size() const noexcept = 0;
    virtual std::vector<std::uint8_t> read(std::uint64_t offset, std::size_t size) = 0;
    // At most 16 ranges and 16 MiB in aggregate, returned in request order.
    // Providers may verify one complete stream for the batch; the default
    // preserves individual read behavior. No result is published on failure.
    virtual std::vector<std::vector<std::uint8_t>> read_ranges(std::span<const ModuleRange> ranges);
    virtual void stream(const std::function<void(std::uint64_t, Bytes)> &visitor) = 0;
};
class ElfError : public std::runtime_error {
  public:
    ElfError(std::string code, std::string message);
    const std::string code;
};
inline std::vector<std::vector<std::uint8_t>> ModuleSource::read_ranges(std::span<const ModuleRange> ranges) {
    constexpr std::uint64_t maximum = 16ULL * 1024 * 1024;
    if (ranges.size() > 16)
        throw ElfError("AETHER_ELF_LIMIT", "Native metadata batch exceeds 16 read ranges");
    if (ranges.empty())
        return {};
    const auto extent = size();
    std::uint64_t retained = 0;
    for (const auto &range : ranges) {
        if (range.offset > extent || range.size > extent - range.offset || range.size > maximum - retained)
            throw ElfError("AETHER_ELF_BOUNDS", "Native metadata batch exceeds its source or 16 MiB retained bound");
        retained += range.size;
    }
    std::vector<std::vector<std::uint8_t>> result;
    result.reserve(ranges.size());
    for (const auto &range : ranges) {
        auto bytes = read(range.offset, static_cast<std::size_t>(range.size));
        if (bytes.size() != range.size)
            throw ElfError("AETHER_ELF_SOURCE", "Native metadata source returned an incomplete range");
        result.emplace_back(std::move(bytes));
    }
    return result;
}
struct InitializerContext {
    // At most the first 48 bytes of the validated loaded-module identity.
    std::string module;
    Address entry = 0, fault_address = 0, pc = 0;
    // Raw CPU detail, not necessarily a syscall number or deepest fault.
    std::uint32_t detail = 0;
    // Existing result registers x0, x1, x2 and x8, in that order.
    std::array<std::uint64_t, 4> arguments{};
    bool finalizer = false;
};
class InitializerError : public ElfError {
  public:
    InitializerError(a64::Fault fault, std::string message, InitializerContext context = {});
    const a64::Fault fault;
    const InitializerContext context;
};
struct Segment {
    std::uint64_t offset = 0, address = 0, file_size = 0, memory_size = 0;
    a64::Permission permissions = a64::Permission::none;
};
struct Symbol {
    std::string name, version, version_library;
    std::uint64_t value = 0, size = 0;
    std::uint8_t binding = 0, type = 0, visibility = 0;
    bool defined = false, absolute = false, version_hidden = false;
};
struct Relocation {
    std::uint64_t offset = 0;
    std::int64_t addend = 0;
    std::uint32_t type = 0, symbol = 0;
};
// Contiguous parsing owns its file bytes; streamed parsing retains metadata only.
// No section table is needed to load either representation.
struct ElfImage {
    std::vector<std::uint8_t> bytes;
    // Exact ELF64 Phdr bytes, retained for both input representations.
    // The parser validates 1..128 entries of 56 bytes each.
    std::vector<std::uint8_t> program_headers;
    // Effective loaded identity: the exact authorized input filename after
    // GuestLoader admission. Standalone parsing initially uses DT_SONAME.
    std::string soname;
    // Actual DT_SONAME, if present; it need not have a .so suffix.
    std::string declared_soname;
    std::vector<std::string> needed;
    std::vector<Segment> segments;
    std::vector<Symbol> symbols;
    std::vector<Relocation> relocations;
    std::uint64_t span = 0, relro_begin = 0, relro_end = 0;
    std::uint64_t init = 0, fini = 0, init_array = 0, fini_array = 0;
    std::uint64_t init_count = 0, fini_count = 0;
};
ElfImage parse(Bytes bytes);
ElfImage parse(ModuleSource &source);

struct GuestSymbol {
    std::string name, module, version;
    Address address = 0;
    std::uint64_t size = 0;
    std::uint8_t type = 0;
};
struct AddressInfo {
    std::string module, symbol;
    // Lowest mapped PT_LOAD page, rather than the ELF relocation load bias.
    Address base = 0, symbol_address = 0;
    bool has_symbol = !symbol.empty();
};
struct ProgramHeaderInfo {
    std::string name;
    Address load_bias = 0;
    std::vector<std::uint8_t> headers;
    std::uint64_t adds = 0;
};
class ImportResolver {
  public:
    virtual ~ImportResolver() = default;
    virtual bool has_library(std::string_view library) const noexcept = 0;
    virtual std::optional<GuestSymbol> resolve(std::string_view library, std::string_view name,
                                               std::string_view version) const = 0;
};
struct ModuleInput {
    std::string name;
    Bytes bytes;
    // Supply exactly one representation. Sources need only outlive load().
    std::shared_ptr<ModuleSource> source;
};
struct GuestModule {
    ElfImage image;
    Address base = 0;
    bool initialized = false, finalized = false;
};
enum class InitializationStage : std::uint32_t {
    initializer_begin=1,initializer_end,finalizer_begin,finalizer_end,jni_on_load_begin,jni_on_load_end
};
struct InitializationProgress {
    InitializationStage stage;
    std::string_view module;
    Address entry;
};
// Diagnostic-only trusted callback. It must not allocate, reenter guest/runtime
// work, retain the borrowed module view, or alter budgets/deadlines. Its context
// outlives the loader and every callback. Null preserves existing behavior.
using InitializationObserver=void(*)(void *,const InitializationProgress &) noexcept;
// Caller-owned execution/admission across the complete graph. Unlike the
// diagnostic observer this may propagate normal trusted control-flow unwinds.
// It must execute the supplied entry once, without restarting/replaying it.
using InitializerDriver=a64::ExecutionResult(*)(void *,a64::GuestCpu &,Address,
    std::span<const std::uint64_t>,Address,std::optional<Address>);
// Single owner thread. Memory, CPU and resolver are scoped to the same app.
// Loading is structural validation only; the caller must authorize execution.
class GuestLoader {
  public:
    GuestLoader(a64::GuestMemory &memory, const ImportResolver &imports);
    ~GuestLoader();
    GuestLoader(const GuestLoader &) = delete;
    GuestLoader &operator=(const GuestLoader &) = delete;
    void load(std::span<const ModuleInput> inputs, std::string_view root);
    // Append an authorized root after successful initialization; resident content must match.
    void extend(std::span<const ModuleInput> inputs, std::string_view root);
    GuestSymbol symbol(std::string_view module, std::string_view name) const;
    // Search a committed root and its DT_NEEDED closure in breadth-first order.
    // Registered virtual libraries are terminal nodes in that same scope.
    std::optional<GuestSymbol> lookup(std::string_view root, std::string_view name) const;
    // Observe committed guest PT_LOAD spans and their covering dynamic symbols.
    // Page padding, gaps and in-progress/rolled-back modules have no identity.
    std::optional<AddressInfo> address_info(Address address) const;
    // Committed load order, with owned values safe across callback reentry.
    // Provisional graph observations throw; an absent index returns nullopt.
    std::optional<ProgramHeaderInfo> program_header_info(std::size_t index) const;
    void initialize(a64::GuestCpu &cpu, Address stack_top, std::optional<Address> thread_pointer = {});
    void finalize(a64::GuestCpu &cpu, Address stack_top);
    void set_initialization_observer(void *context,InitializationObserver) noexcept;
    // Configure/clear while no initializer is active; context outlives all calls.
    // Null retains the existing finite one-million-tick legacy behavior.
    void set_initializer_driver(void *context,InitializerDriver) noexcept;
    const std::vector<GuestModule> &modules() const noexcept;
    std::size_t relocation_count() const noexcept;

  private:
    void load_graph(std::span<const ModuleInput> inputs, std::string_view root, bool additional);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::elf
