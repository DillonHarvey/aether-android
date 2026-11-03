#pragma once
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>

namespace aether::a64 {
using Address = std::uint64_t;
enum class Permission : unsigned { none = 0, read = 1, write = 2, execute = 4 };
constexpr Permission operator|(Permission a, Permission b) {
    return static_cast<Permission>(static_cast<unsigned>(a) | static_cast<unsigned>(b));
}
constexpr bool has(Permission value, Permission bit) {
    return (static_cast<unsigned>(value) & static_cast<unsigned>(bit)) != 0;
}
inline constexpr Permission read_write = Permission::read | Permission::write;
inline constexpr Permission read_execute = Permission::read | Permission::execute;
enum class MemoryFailureKind { invalid, unmapped, protection };
struct MemoryFailure {
    MemoryFailureKind kind = MemoryFailureKind::invalid;
    Address address = 0;
    Permission permission = Permission::none;
};

class GuestError : public std::runtime_error {
  public:
    GuestError(std::string code, std::string message);
    const std::string code;
};

// A single-thread-owned guest address space. ARM64 bytes are never host executable.
// Executable mapping/protection changes invalidate the CPU cache at the next
// execution boundary. Data mappings remain checked by live memory callbacks.
class GuestMemory {
  public:
    static constexpr std::size_t page_size = 4096;
    static constexpr std::size_t maximum_bytes = 256 * 1024 * 1024;
    static constexpr Address address_limit = Address{1} << 48;
    GuestMemory();
    ~GuestMemory();
    GuestMemory(const GuestMemory &) = delete;
    GuestMemory &operator=(const GuestMemory &) = delete;
    void map(Address address, std::size_t size, Permission permissions);
    void protect(Address address, Permission permissions);
    void unmap(Address address);
    // Page ranges may split views while retaining their original guarded backing.
    // Partial unmaps retain the backing's full quota charge until its last view dies.
    void protect_range(Address address, std::size_t size, Permission permissions);
    void unmap_range(Address address, std::size_t size);
    // Host-owned relocation/resize: target is the same address or a disjoint,
    // vacant range. Retained bytes keep their backing, offsets and permissions;
    // growth is zero-filled with the last source view's permission. All
    // allocations/quota checks precede publication, including PROT_NONE views.
    void remap_range(Address address, std::size_t size, Address target, std::size_t new_size);
    std::optional<Address> find_free(Address begin, Address end, std::size_t size) const noexcept;
    // Pure whole-request proof. Failure identifies the first inaccessible byte;
    // invalid/empty requests are distinct from guest mapping/protection faults.
    std::optional<MemoryFailure> access_failure(Address address, std::size_t size,
                                              Permission permission) const noexcept;
    bool accessible(Address address, std::size_t size, Permission permission) const noexcept;
    bool read(Address address, std::span<std::uint8_t> target,
              Permission permission = Permission::read) const noexcept;
    bool write(Address address, std::span<const std::uint8_t> source) noexcept;
    std::uint64_t generation() const noexcept;
    // Separate executable-view epoch for the shared JIT cache. Ordinary heap
    // allocation/free still advances generation(), without invalidating code.
    std::uint64_t code_generation() const noexcept;
    std::size_t mapped_bytes() const noexcept;
    struct Mapping {Address address;std::size_t size;Permission permissions;};
    // Guest-only bounds/protection; never exposes a host allocation or pointer.
    std::optional<Mapping> mapping(Address address) const noexcept;
    // Host-only observation, never permission or an address-space capability.
    // Weak identity retains no mapped bytes or quota charge and exposes no host
    // pointer. Comparisons remain meaningful after the observed backing dies.
    class WordIdentity final {
      public:
        WordIdentity(const WordIdentity &) noexcept = default;
        WordIdentity &operator=(const WordIdentity &) noexcept = default;
        WordIdentity(WordIdentity &&) noexcept = default;
        WordIdentity &operator=(WordIdentity &&) noexcept = default;
        bool operator==(const WordIdentity &) const noexcept;
        bool same_backing(const WordIdentity &) const noexcept;
        std::size_t backing_offset() const noexcept {return offset_;}
      private:
        WordIdentity(std::weak_ptr<const void>,std::size_t) noexcept;
        std::weak_ptr<const void> backing_;
        std::size_t offset_;
        friend class GuestMemory;
    };
    // Observe one aligned four-byte word wholly inside a current view with the
    // requested nonempty access. Requery before access: old tokens grant none.
    // Splits/protection preserve backing+offset; unmap/remap produces a new key.
    std::optional<WordIdentity> word_identity(Address,Permission required=Permission::read) const noexcept;
    bool host_pages_are_non_executable() const noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::a64
