#include "aether/a64/guest_memory.hpp"
#include <algorithm>
#include <cstring>
#include <limits>
#include <vector>
#include <windows.h>

namespace aether::a64 {
GuestError::GuestError(std::string code_, std::string message)
    : std::runtime_error(std::move(message)), code(std::move(code_)) {}
namespace {
void validate_permissions(Permission p) {
    if ((static_cast<unsigned>(p) & ~7u) || (has(p, Permission::write) && has(p, Permission::execute)) ||
        (p != Permission::none && !has(p, Permission::read)))
        throw GuestError("AETHER_GUEST_PERMISSION", "Mappings require read permission and prohibit W+X");
}
DWORD host_protection(Permission p) {
    if (has(p, Permission::write))
        return PAGE_READWRITE;
    return has(p, Permission::read) ? PAGE_READONLY : PAGE_NOACCESS;
}
} // namespace
struct GuestMemory::Impl {
    struct Region {
        Address address;
        std::size_t size;
        Permission permissions;
        std::uint8_t *allocation;
        std::uint8_t *data() const { return allocation + page_size; }
        ~Region() {
            if (allocation)
                VirtualFree(allocation, 0, MEM_RELEASE);
        }
    };
    std::vector<std::unique_ptr<Region>> regions;
    std::size_t total = 0;
    std::uint64_t generation = 1;
    Region *find(Address address, std::size_t size, Permission permission) const noexcept {
        if (!size || size > std::numeric_limits<Address>::max() - address)
            return nullptr;
        for (const auto &r : regions) {
            if (address >= r->address && address - r->address < r->size &&
                size <= r->size - static_cast<std::size_t>(address - r->address) &&
                permission != Permission::none &&
                (static_cast<unsigned>(r->permissions) & static_cast<unsigned>(permission)) ==
                    static_cast<unsigned>(permission))
                return r.get();
        }
        return nullptr;
    }
};
GuestMemory::GuestMemory() : impl_(std::make_unique<Impl>()) {}
GuestMemory::~GuestMemory() = default;
void GuestMemory::map(Address address, std::size_t size, Permission permissions) {
    validate_permissions(permissions);
    if (!address || address >= address_limit || size > address_limit - address || address % page_size ||
        !size || size % page_size || size > std::numeric_limits<Address>::max() - address ||
        size > maximum_bytes - impl_->total || impl_->regions.size() >= 4096)
        throw GuestError("AETHER_GUEST_MAPPING", "Invalid, unaligned or oversized guest mapping");
    for (const auto &r : impl_->regions)
        if (address < r->address + r->size && r->address < address + size)
            throw GuestError("AETHER_GUEST_MAPPING", "Guest mappings overlap");
    auto region = std::make_unique<Impl::Region>();
    region->address = address;
    region->size = size;
    region->permissions = permissions;
    region->allocation =
        static_cast<std::uint8_t *>(VirtualAlloc(nullptr, size + 2 * page_size, MEM_RESERVE, PAGE_NOACCESS));
    if (!region->allocation || !VirtualAlloc(region->data(), size, MEM_COMMIT, host_protection(permissions)))
        throw GuestError("AETHER_GUEST_ALLOCATION", "Windows could not allocate guarded guest memory");
    impl_->regions.push_back(std::move(region));
    impl_->total += size;
    ++impl_->generation;
}
void GuestMemory::protect(Address address, Permission permissions) {
    validate_permissions(permissions);
    for (auto &r : impl_->regions)
        if (r->address == address) {
            DWORD old = 0;
            if (!VirtualProtect(r->data(), r->size, host_protection(permissions), &old))
                throw GuestError("AETHER_GUEST_PROTECTION", "Windows rejected guest memory protection");
            r->permissions = permissions;
            ++impl_->generation;
            return;
        }
    throw GuestError("AETHER_GUEST_MAPPING", "No mapping starts at this guest address");
}
void GuestMemory::unmap(Address address) {
    const auto it = std::find_if(impl_->regions.begin(), impl_->regions.end(),
                                 [address](const auto &r) { return r->address == address; });
    if (it == impl_->regions.end())
        throw GuestError("AETHER_GUEST_MAPPING", "No mapping starts at this guest address");
    impl_->total -= (*it)->size;
    impl_->regions.erase(it);
    ++impl_->generation;
}
bool GuestMemory::accessible(Address address, std::size_t size, Permission permission) const noexcept {
    if (!size || address >= address_limit || size > address_limit - address)
        return false;
    while (size) {
        const auto r = impl_->find(address, 1, permission);
        if (!r)
            return false;
        const auto count = std::min(size, r->size - static_cast<std::size_t>(address - r->address));
        address += count;
        size -= count;
    }
    return true;
}
bool GuestMemory::read(Address address, std::span<std::uint8_t> target,
                       Permission permission) const noexcept {
    if (!accessible(address, target.size(), permission))
        return false;
    while (!target.empty()) {
        const auto r = impl_->find(address, 1, permission);
        const auto count = std::min(target.size(), r->size - static_cast<std::size_t>(address - r->address));
        std::memcpy(target.data(), r->data() + (address - r->address), count);
        address += count;
        target = target.subspan(count);
    }
    return true;
}
bool GuestMemory::write(Address address, std::span<const std::uint8_t> source) noexcept {
    // Preflight the complete range so a later gap/protected page cannot cause a partial write.
    if (!accessible(address, source.size(), Permission::write))
        return false;
    while (!source.empty()) {
        const auto r = impl_->find(address, 1, Permission::write);
        const auto count = std::min(source.size(), r->size - static_cast<std::size_t>(address - r->address));
        std::memcpy(r->data() + (address - r->address), source.data(), count);
        address += count;
        source = source.subspan(count);
    }
    return true;
}
std::uint64_t GuestMemory::generation() const noexcept { return impl_->generation; }
std::size_t GuestMemory::mapped_bytes() const noexcept { return impl_->total; }
bool GuestMemory::host_pages_are_non_executable() const noexcept {
    for (const auto &r : impl_->regions) {
        MEMORY_BASIC_INFORMATION info{};
        if (!VirtualQuery(r->data(), &info, sizeof(info)) || info.State != MEM_COMMIT ||
            info.RegionSize < r->size || info.Protect != host_protection(r->permissions))
            return false;
    }
    return true;
}
} // namespace aether::a64
