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

class GuestError : public std::runtime_error {
  public:
    GuestError(std::string code, std::string message);
    const std::string code;
};

// A single-thread-owned guest address space. ARM64 bytes are never host executable.
// Mapping/protection changes invalidate the CPU cache at the next call boundary.
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
    std::optional<Address> find_free(Address begin, Address end, std::size_t size) const noexcept;
    bool accessible(Address address, std::size_t size, Permission permission) const noexcept;
    bool read(Address address, std::span<std::uint8_t> target,
              Permission permission = Permission::read) const noexcept;
    bool write(Address address, std::span<const std::uint8_t> source) noexcept;
    std::uint64_t generation() const noexcept;
    std::size_t mapped_bytes() const noexcept;
    struct Mapping {Address address;std::size_t size;Permission permissions;};
    // Guest-only bounds/protection; never exposes a host allocation or pointer.
    std::optional<Mapping> mapping(Address address) const noexcept;
    bool host_pages_are_non_executable() const noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::a64
