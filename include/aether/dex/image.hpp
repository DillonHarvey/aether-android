#pragma once
#include "aether/dex/string_table.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace aether::dex {
using Index = std::uint32_t;
inline constexpr Index no_index = 0xffffffffu;
class DexError : public std::runtime_error {
  public:
    DexError(std::string code, std::string message)
        : std::runtime_error(std::move(message)), code(std::move(code)) {}
    const std::string code;
};
struct Prototype {
    Index return_type = 0;
    std::vector<Index> parameters;
    std::string descriptor;
    std::uint32_t argument_words = 0;
};
struct CatchHandler {
    Index type = no_index;
    std::uint32_t target = 0;
};
struct TryBlock {
    std::uint32_t start = 0, count = 0;
    std::vector<CatchHandler> handlers;
};
struct IndexMap {
    std::string source;
    std::uint16_t version = 35;
    std::vector<Index> strings, types, fields, methods;
};
struct Code {
    std::uint16_t registers = 0, incoming = 0, outgoing = 0;
    std::uint32_t file_offset = 0;
    std::vector<std::uint16_t> units;
    std::vector<TryBlock> tries;
    // Bytecode operands remain file-local. Verification translates them through
    // this immutable map; decoded instructions can use the full 32-bit index.
    std::shared_ptr<const IndexMap> references;
};
// Owning optional code with value semantics. Empty method-ID references carry
// only a pointer; copies own independent mutable buffers, while IndexMap stays
// shared and immutable. Dereference requires an engaged value, as with optional.
class CodeStorage {
  public:
    CodeStorage() noexcept;
    CodeStorage(std::nullopt_t) noexcept;
    CodeStorage(const Code &value);
    CodeStorage(Code &&value);
    CodeStorage(const std::optional<Code> &value);
    CodeStorage(std::optional<Code> &&value);
    CodeStorage(const CodeStorage &other);
    CodeStorage(CodeStorage &&other) noexcept;
    ~CodeStorage();
    CodeStorage &operator=(const CodeStorage &other);
    CodeStorage &operator=(CodeStorage &&other) noexcept;
    CodeStorage &operator=(std::nullopt_t) noexcept;
    CodeStorage &operator=(const Code &value);
    CodeStorage &operator=(Code &&value);
    explicit operator bool() const noexcept;
    bool has_value() const noexcept;
    Code &operator*() noexcept;
    const Code &operator*() const noexcept;
    Code *operator->() noexcept;
    const Code *operator->() const noexcept;
    Code &value();
    const Code &value() const;
    void reset() noexcept;
    Code &emplace();
    void swap(CodeStorage &other) noexcept;
  private:
    std::unique_ptr<Code> value_;
};
struct Method {
    Index owner = 0, prototype = 0;
    std::string name;
    std::uint32_t flags = 0;
    bool declared = false, direct = false;
    CodeStorage code;
};
// Preserve the previous conservative per-ID metadata charge, including capacity
// for one Code even on references without a body. Actual boxes are not charged
// again; bytecode units, try regions and handler payloads keep their own charges.
inline constexpr std::size_t method_metadata_charge=sizeof(Method)+sizeof(Code);
struct Field {
    Index owner = 0, type = 0;
    std::string name;
    std::uint32_t flags = 0;
    bool declared = false;
};
struct EncodedValue {
    std::uint8_t type = 0x1e; // DEX VALUE_NULL by default.
    std::uint64_t bits = 0;
};
struct Class {
    Index type = 0, superclass = no_index;
    std::uint32_t flags = 0;
    std::vector<Index> interfaces, static_fields, instance_fields, direct_methods, virtual_methods;
    std::vector<EncodedValue> static_values;
};
struct DexImage {
    std::string sha256;
    // Demand linking appends while existing frames/JNI calls retain references.
    // Stable pages preserve element addresses; callers retain no iterators.
    StringTable strings;
    StableTable<std::string> types;
    StableTable<Prototype> prototypes;
    StableTable<Field> fields;
    StableTable<Method> methods;
    StableTable<Class> classes;
    std::uint16_t version = 35;
    struct Source {
        std::string name, sha256;
        std::uint16_t version = 35;
    };
    std::vector<Source> sources;
    Index method(std::string_view owner, std::string_view name, std::string_view descriptor) const;
    const Class *definition(std::string_view descriptor) const noexcept;
};
// Structural DEX 035/037/038 subset; dynamic-call/handle tables are refused.
// Executable-code verification is a separate stage.
DexImage parse(std::span<const std::uint8_t> bytes);
bool reference_type(std::string_view descriptor) noexcept;
std::uint32_t type_words(std::string_view descriptor) noexcept;
} // namespace aether::dex
