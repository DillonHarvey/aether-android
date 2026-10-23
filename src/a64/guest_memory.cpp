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
void validate_range(Address address, std::size_t size) {
    if (address >= GuestMemory::address_limit || address % GuestMemory::page_size || !size ||
        size % GuestMemory::page_size || size > GuestMemory::address_limit - address)
        throw GuestError("AETHER_GUEST_MAPPING", "Invalid, unaligned or wrapping guest page range");
}
} // namespace
struct GuestMemory::Impl {
    struct Backing {
        std::uint8_t *allocation = nullptr;
        std::size_t size = 0;
        std::size_t *charge = nullptr;
        ~Backing() {
            if (allocation)
                VirtualFree(allocation, 0, MEM_RELEASE);
            if (charge) *charge -= size;
        }
    };
    struct Region {
        Address address;
        std::size_t size;
        Permission permissions;
        std::shared_ptr<Backing> backing;
        std::size_t offset = 0;
        std::uint8_t *data() const { return backing->allocation + page_size + offset; }
    };
    // Declared before regions so every backing dies before this counter does.
    std::size_t backing_total = 0;
    std::vector<Region> regions; // Always ordered by guest address, without overlaps.
    std::size_t total = 0;
    std::uint64_t generation = 1;
    const Region *find(Address address, std::size_t size, Permission permission) const noexcept {
        if (!size || size > std::numeric_limits<Address>::max() - address)
            return nullptr;
        for (auto &r : regions) {
            if (address >= r.address && address - r.address < r.size &&
                size <= r.size - static_cast<std::size_t>(address - r.address) &&
                permission != Permission::none &&
                (static_cast<unsigned>(r.permissions) & static_cast<unsigned>(permission)) ==
                    static_cast<unsigned>(permission))
                return &r;
        }
        return nullptr;
    }
};
GuestMemory::GuestMemory() : impl_(std::make_unique<Impl>()) {}
GuestMemory::~GuestMemory() = default;
std::optional<GuestMemory::Mapping> GuestMemory::mapping(Address address) const noexcept {
    for(const auto &r:impl_->regions)if(address>=r.address && address-r.address<r.size)return Mapping{r.address,r.size,r.permissions};
    return {};
}
void GuestMemory::map(Address address, std::size_t size, Permission permissions) {
    validate_permissions(permissions);
    if (!address || address >= address_limit || size > address_limit - address || address % page_size ||
        !size || size % page_size || size > std::numeric_limits<Address>::max() - address ||
        size > maximum_bytes - impl_->backing_total || impl_->regions.size() >= 4096)
        throw GuestError("AETHER_GUEST_MAPPING", "Invalid, unaligned or oversized guest mapping");
    for (const auto &r : impl_->regions)
        if (address < r.address + r.size && r.address < address + size)
            throw GuestError("AETHER_GUEST_MAPPING", "Guest mappings overlap");
    if (impl_->regions.capacity() == impl_->regions.size())
        impl_->regions.reserve(std::min<std::size_t>(4096, std::max<std::size_t>(8, impl_->regions.size() * 2)));
    auto backing = std::make_shared<Impl::Backing>();
    backing->size = size;
    backing->allocation =
        static_cast<std::uint8_t *>(VirtualAlloc(nullptr, size + 2 * page_size, MEM_RESERVE, PAGE_NOACCESS));
    if (!backing->allocation || !VirtualAlloc(backing->allocation + page_size, size, MEM_COMMIT, host_protection(permissions)))
        throw GuestError("AETHER_GUEST_ALLOCATION", "Windows could not allocate guarded guest memory");
    const auto position = std::lower_bound(impl_->regions.begin(), impl_->regions.end(), address,
        [](const auto &region, Address value) { return region.address < value; });
    impl_->regions.insert(position, {address, size, permissions, backing, 0});
    impl_->backing_total += size;
    backing->charge = &impl_->backing_total;
    impl_->total += size;
    ++impl_->generation;
}
void GuestMemory::protect(Address address, Permission permissions) {
    validate_permissions(permissions);
    for (auto &r : impl_->regions)
        if (r.address == address) {
            DWORD old = 0;
            if (!VirtualProtect(r.data(), r.size, host_protection(permissions), &old))
                throw GuestError("AETHER_GUEST_PROTECTION", "Windows rejected guest memory protection");
            r.permissions = permissions;
            ++impl_->generation;
            return;
        }
    throw GuestError("AETHER_GUEST_MAPPING", "No mapping starts at this guest address");
}
void GuestMemory::unmap(Address address) {
    const auto it = std::find_if(impl_->regions.begin(), impl_->regions.end(),
                                 [address](const auto &r) { return r.address == address; });
    if (it == impl_->regions.end())
        throw GuestError("AETHER_GUEST_MAPPING", "No mapping starts at this guest address");
    impl_->total -= it->size;
    impl_->regions.erase(it);
    ++impl_->generation;
}
void GuestMemory::unmap_range(Address address, std::size_t size) {
    validate_range(address, size);
    const auto end = address + size;
    std::size_t count = 0, removed = 0;
    for (const auto &region : impl_->regions) {
        const auto first = std::max(address, region.address), last = std::min(end, region.address + region.size);
        if (first >= last) { ++count; continue; }
        removed += static_cast<std::size_t>(last - first);
        count += (region.address < first) + (last < region.address + region.size);
    }
    if (!removed) return;
    if (count > 4096) throw GuestError("AETHER_GUEST_MAPPING", "Guest range split exceeds 4096 views");
    std::vector<Impl::Region> prepared;
    prepared.reserve(count);
    for (const auto &region : impl_->regions) {
        const auto first = std::max(address, region.address), last = std::min(end, region.address + region.size);
        if (first >= last) { prepared.push_back(region); continue; }
        if (region.address < first)
            prepared.push_back({region.address, static_cast<std::size_t>(first - region.address), region.permissions, region.backing, region.offset});
        if (last < region.address + region.size)
            prepared.push_back({last, static_cast<std::size_t>(region.address + region.size - last), region.permissions, region.backing,
                                region.offset + static_cast<std::size_t>(last - region.address)});
    }
    impl_->regions.swap(prepared);
    impl_->total -= removed;
    ++impl_->generation;
    // Only this scope's last backing references release Windows allocations and charge.
}
void GuestMemory::protect_range(Address address, std::size_t size, Permission permissions) {
    validate_permissions(permissions);
    validate_range(address, size);
    const auto end = address + size;
    auto cursor = address;
    std::size_t count = 0;
    bool changes = false;
    for (const auto &region : impl_->regions) {
        const auto first = std::max(address, region.address), last = std::min(end, region.address + region.size);
        if (first >= last) { ++count; continue; }
        if (first > cursor) throw GuestError("AETHER_GUEST_MAPPING", "Guest protection range contains an unmapped gap");
        cursor = last;
        if (region.permissions == permissions) ++count;
        else { changes = true; count += 1 + (region.address < first) + (last < region.address + region.size); }
    }
    if (cursor != end) throw GuestError("AETHER_GUEST_MAPPING", "Guest protection range contains an unmapped gap");
    if (!changes) return;
    if (count > 4096) throw GuestError("AETHER_GUEST_MAPPING", "Guest range split exceeds 4096 views");
    std::vector<Impl::Region> prepared;
    prepared.reserve(count);
    for (const auto &region : impl_->regions) {
        const auto first = std::max(address, region.address), last = std::min(end, region.address + region.size);
        if (first >= last || region.permissions == permissions) { prepared.push_back(region); continue; }
        if (region.address < first)
            prepared.push_back({region.address, static_cast<std::size_t>(first - region.address), region.permissions, region.backing, region.offset});
        prepared.push_back({first, static_cast<std::size_t>(last - first), region.permissions, region.backing,
                            region.offset + static_cast<std::size_t>(first - region.address)});
        if (last < region.address + region.size)
            prepared.push_back({last, static_cast<std::size_t>(region.address + region.size - last), region.permissions, region.backing,
                                region.offset + static_cast<std::size_t>(last - region.address)});
    }
    bool changed = false;
    for (auto &region : prepared) {
        if (region.address < address || region.address + region.size > end || region.permissions == permissions) continue;
        DWORD old = 0;
        if (!VirtualProtect(region.data(), region.size, host_protection(permissions), &old)) {
            if (changed) { impl_->regions.swap(prepared); ++impl_->generation; }
            throw GuestError("AETHER_GUEST_PROTECTION", "Windows rejected part of a guest protection range");
        }
        region.permissions = permissions;
        changed = true;
    }
    impl_->regions.swap(prepared);
    ++impl_->generation;
}
std::optional<Address> GuestMemory::find_free(Address begin, Address end, std::size_t size) const noexcept {
    if (!begin || begin >= end || end > address_limit || begin % page_size || end % page_size || !size || size % page_size || size > end - begin)
        return std::nullopt;
    auto candidate = begin;
    for (const auto &region : impl_->regions) {
        if (region.address + region.size <= candidate) continue;
        if (region.address >= end) break;
        if (region.address > candidate && size <= region.address - candidate) return candidate;
        candidate = region.address + region.size;
        if (candidate >= end || size > end - candidate) return std::nullopt;
    }
    return size <= end - candidate ? std::optional<Address>{candidate} : std::nullopt;
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
        if (!VirtualQuery(r.data(), &info, sizeof(info)) || info.State != MEM_COMMIT ||
            static_cast<std::uint8_t *>(info.BaseAddress) > r.data() ||
            static_cast<std::size_t>(r.data() - static_cast<std::uint8_t *>(info.BaseAddress)) > info.RegionSize ||
            r.size > info.RegionSize - static_cast<std::size_t>(r.data() - static_cast<std::uint8_t *>(info.BaseAddress)) ||
            info.Protect != host_protection(r.permissions))
            return false;
    }
    return true;
}
} // namespace aether::a64
