#pragma once
#include "aether/a64/guest_cpu.hpp"
#include "aether/elf/limits.hpp"
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aether::elf {
using a64::Address;
using Bytes = std::span<const std::uint8_t>;
// Immutable, caller-authorized module content. Reads retain only requested
// metadata; streaming visits the complete file without retaining a file image.
class ModuleSource {
  public:
    virtual ~ModuleSource() = default;
    virtual std::uint64_t size() const noexcept = 0;
    virtual std::vector<std::uint8_t> read(std::uint64_t offset, std::size_t size) = 0;
    virtual void stream(const std::function<void(std::uint64_t, Bytes)> &visitor) = 0;
};
class ElfError : public std::runtime_error {
  public:
    ElfError(std::string code, std::string message);
    const std::string code;
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
    std::string soname;
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
// Single owner thread. Memory, CPU and resolver are scoped to the same app.
// Loading is structural validation only; the caller must authorize execution.
class GuestLoader {
  public:
    GuestLoader(a64::GuestMemory &memory, const ImportResolver &imports);
    ~GuestLoader();
    GuestLoader(const GuestLoader &) = delete;
    GuestLoader &operator=(const GuestLoader &) = delete;
    void load(std::span<const ModuleInput> inputs, std::string_view root);
    GuestSymbol symbol(std::string_view module, std::string_view name) const;
    void initialize(a64::GuestCpu &cpu, Address stack_top);
    void finalize(a64::GuestCpu &cpu, Address stack_top);
    const std::vector<GuestModule> &modules() const noexcept;
    std::size_t relocation_count() const noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::elf
