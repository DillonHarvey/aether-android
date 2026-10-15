#include "aether/bionic/guest_posix.hpp"
#include <algorithm>
#include <array>
#include <map>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
enum class Operation {
    finalize,
    atexit,
    atfork,
    clock,
    error,
    length,
    copy,
    move,
    fill,
    allocate,
    release,
    tid,
    open,
    read,
    write,
    close,
    create_thread
};
struct Entry {
    std::string_view name;
    Operation operation;
};
constexpr std::array entries{Entry{"__cxa_finalize", Operation::finalize},
                             Entry{"__cxa_atexit", Operation::atexit},
                             Entry{"__register_atfork", Operation::atfork},
                             Entry{"clock_gettime", Operation::clock},
                             Entry{"__errno", Operation::error},
                             Entry{"strlen", Operation::length},
                             Entry{"memcpy", Operation::copy},
                             Entry{"memmove", Operation::move},
                             Entry{"memset", Operation::fill},
                             Entry{"malloc", Operation::allocate},
                             Entry{"free", Operation::release},
                             Entry{"gettid", Operation::tid},
                             Entry{"open", Operation::open},
                             Entry{"read", Operation::read},
                             Entry{"write", Operation::write},
                             Entry{"close", Operation::close},
                             Entry{"pthread_create", Operation::create_thread}};
constexpr std::uint32_t first_service = 0x100;
constexpr std::size_t maximum_transfer = 1024 * 1024, maximum_heap = 16 * 1024 * 1024;
constexpr std::uint32_t guest_eio = 5, guest_enomem = 12, guest_eacces = 13, guest_efault = 14,
                        guest_einval = 22;
template <std::size_t N> std::array<std::uint8_t, N> little(std::uint64_t value) {
    static_assert(N <= 8);
    std::array<std::uint8_t, N> bytes{};
    for (std::size_t i = 0; i < N; ++i)
        bytes[i] = static_cast<std::uint8_t>(value >> (i * 8));
    return bytes;
}
} // namespace
struct GuestPosixServices::Impl {
    a64::GuestMemory &memory;
    const a64::AppContext &app;
    const host::TimeService &time;
    host::FileService *files;
    const std::uint32_t tid;
    ServiceMetrics stats;
    std::string_view rejection;
    std::map<Address, std::size_t> allocations;
    Address next_heap = 0x40000000;
    bool trampoline_owned = false, errno_owned = false;
    Impl(a64::GuestMemory &m, const a64::AppContext &a, const host::TimeService &t, std::uint32_t id,
         host::FileService *f)
        : memory(m), app(a), time(t), files(f), tid(id) {}
    ~Impl() {
        for (const auto &[address, size] : allocations) {
            (void)size;
            unmap(address);
        }
        if (trampoline_owned)
            unmap(trampoline_base);
        if (errno_owned)
            unmap(errno_address);
    }
    void unmap(Address address) noexcept {
        try {
            memory.unmap(address);
        } catch (...) {
        }
    }
    Fault error(std::array<std::uint64_t, 31> &r, std::uint32_t value, bool null_return = false) {
        ++stats.errors;
        if (!memory.write(errno_address, little<4>(value)))
            return Fault::write;
        r[0] = null_return ? 0 : ~std::uint64_t{0};
        return Fault::none;
    }
    Fault dispatch(Operation operation, std::array<std::uint64_t, 31> &r) {
        switch (operation) {
        case Operation::finalize:
            // No callback registration can succeed in this subset. An empty list is therefore exact.
            return Fault::none;
        case Operation::atexit:
            rejection = "__cxa_atexit: guest destructor callback registration is unsupported";
            ++stats.rejected_operations;
            return Fault::unsupported_service;
        case Operation::atfork:
            rejection = "__register_atfork: guest fork handlers are unsupported";
            ++stats.rejected_operations;
            return Fault::unsupported_service;
        case Operation::create_thread:
            rejection = "pthread_create: concurrent guest threads and TLS are unsupported";
            ++stats.rejected_operations;
            return Fault::unsupported_service;
        case Operation::error:
            r[0] = errno_address;
            return Fault::none;
        case Operation::tid:
            r[0] = tid;
            return Fault::none;
        case Operation::clock: {
            if (!app.monotonic_time_allowed)
                return error(r, guest_eacces);
            // Android clockid_t is signed 32-bit; upper argument bits are not part of the value.
            if (static_cast<std::uint32_t>(r[0]) != 1)
                return error(r, guest_einval);
            if (!memory.accessible(r[1], 16, a64::Permission::write))
                return error(r, guest_efault);
            host::MonotonicTime now;
            const auto status = time.read_monotonic(now);
            if (status != host::TimeStatus::ok)
                return error(r, status == host::TimeStatus::denied ? guest_eacces : guest_eio);
            std::array<std::uint8_t, 16> bytes{};
            const auto seconds = little<8>(now.seconds), nanos = little<8>(now.nanoseconds);
            std::copy(seconds.begin(), seconds.end(), bytes.begin());
            std::copy(nanos.begin(), nanos.end(), bytes.begin() + 8);
            if (!memory.write(r[1], bytes))
                return error(r, guest_efault);
            ++stats.clock_reads;
            r[0] = 0;
            return Fault::none;
        }
        case Operation::length: {
            for (std::size_t n = 0; n < maximum_transfer; ++n) {
                if (r[0] >= a64::GuestMemory::address_limit || n >= a64::GuestMemory::address_limit - r[0])
                    return Fault::read;
                std::array<std::uint8_t, 1> byte{};
                if (!memory.read(r[0] + n, byte))
                    return Fault::read;
                if (!byte[0]) {
                    r[0] = n;
                    return Fault::none;
                }
            }
            rejection = "strlen: string exceeds 1 MiB service limit";
            ++stats.rejected_operations;
            return Fault::unsupported_service;
        }
        case Operation::copy:
        case Operation::move:
        case Operation::fill: {
            if (r[2] > maximum_transfer) {
                rejection = "memory operation exceeds 1 MiB service limit";
                ++stats.rejected_operations;
                return Fault::unsupported_service;
            }
            const auto size = static_cast<std::size_t>(r[2]);
            if (!size)
                return Fault::none;
            if (!memory.accessible(r[0], size, a64::Permission::write))
                return Fault::write;
            if (operation != Operation::fill && !memory.accessible(r[1], size, a64::Permission::read))
                return Fault::read;
            if (operation == Operation::copy && r[0] < r[1] + size && r[1] < r[0] + size) {
                rejection = "memcpy: overlapping ranges violate the guest API contract";
                ++stats.rejected_operations;
                return Fault::unsupported_service;
            }
            std::vector<std::uint8_t> bytes(size, static_cast<std::uint8_t>(r[1]));
            if (operation != Operation::fill && !memory.read(r[1], bytes))
                return Fault::read;
            return memory.write(r[0], bytes) ? Fault::none : Fault::write;
        }
        case Operation::allocate: {
            if (r[0] > maximum_heap || allocations.size() >= 4096)
                return error(r, guest_enomem, true);
            const auto size =
                (std::max<std::size_t>(static_cast<std::size_t>(r[0]), 1) + 4095) & ~std::size_t{4095};
            if (size > maximum_heap - stats.allocated_bytes || next_heap + size > 0x50000000)
                return error(r, guest_enomem, true);
            const auto address = next_heap;
            const auto [it, inserted] = allocations.emplace(address, size);
            if (!inserted)
                return error(r, guest_enomem, true);
            try {
                memory.map(address, size, a64::read_write);
            } catch (const a64::GuestError &) {
                allocations.erase(it);
                return error(r, guest_enomem, true);
            }
            next_heap +=
                size + 4096; // Unmapped page between allocations; addresses are not immediately reused.
            stats.allocated_bytes += size;
            ++stats.allocations;
            r[0] = address;
            return Fault::none;
        }
        case Operation::release: {
            if (!r[0])
                return Fault::none;
            const auto it = allocations.find(r[0]);
            if (it == allocations.end()) {
                rejection = "free: address is not a live allocation";
                ++stats.rejected_operations;
                return Fault::invalid_call;
            }
            memory.unmap(it->first);
            stats.allocated_bytes -= it->second;
            allocations.erase(it);
            ++stats.frees;
            return Fault::none;
        }
        case Operation::open:
        case Operation::read:
        case Operation::write:
        case Operation::close: {
            if (!files)
                return error(r, guest_eacces);
            host::FileResult result;
            if (operation == Operation::open) {
                std::string name;
                for (std::size_t i = 0; i < 128; ++i) {
                    std::array<std::uint8_t, 1> c{};
                    if (r[0] >= a64::GuestMemory::address_limit ||
                        i >= a64::GuestMemory::address_limit - r[0] || !memory.read(r[0] + i, c))
                        return error(r, guest_efault);
                    if (!c[0])
                        break;
                    name.push_back(static_cast<char>(c[0]));
                }
                const auto flags = static_cast<std::uint32_t>(r[1]);
                // Android O_ACCMODE, O_CREAT, O_EXCL, O_TRUNC, O_CLOEXEC. No guest exec exists.
                if ((flags & ~std::uint32_t{3 | 64 | 128 | 512 | 0x80000}) || (flags & 3) == 3)
                    return error(r, 95); // EOPNOTSUPP: unsupported flags are never silently ignored.
                if ((flags & 64) && static_cast<std::uint32_t>(r[2]) != 0600)
                    return error(r,
                                 95); // One guest identity per scope; host ACL isolation is a Phase 7 gate.
                result = files->open(name, {(flags & 3) != 1, (flags & 3) != 0, (flags & 64) != 0,
                                            (flags & 128) != 0, (flags & 512) != 0});
            } else if (operation == Operation::close) {
                result = files->close(static_cast<std::int32_t>(r[0]));
            } else {
                if (r[2] > maximum_transfer)
                    return error(r, guest_einval);
                const auto count = static_cast<std::size_t>(r[2]);
                if (count && !memory.accessible(r[1], count,
                                                operation == Operation::read ? a64::Permission::write
                                                                             : a64::Permission::read))
                    return error(r, guest_efault);
                std::vector<std::uint8_t> buffer(count);
                if (operation == Operation::write) {
                    if (count && !memory.read(r[1], buffer))
                        return error(r, guest_efault);
                    result = files->write(static_cast<std::int32_t>(r[0]), buffer);
                } else {
                    result = files->read(static_cast<std::int32_t>(r[0]), buffer);
                    if (result.error == host::FileError::none && result.value > 0 &&
                        !memory.write(r[1], std::span{buffer}.first(static_cast<std::size_t>(result.value))))
                        return error(r, guest_efault);
                }
            }
            ++stats.file_operations;
            switch (result.error) {
            case host::FileError::none:
                r[0] = static_cast<std::uint64_t>(result.value);
                return Fault::none;
            case host::FileError::missing:
                return error(r, 2);
            case host::FileError::denied:
                return error(r, guest_eacces);
            case host::FileError::exists:
                return error(r, 17);
            case host::FileError::bad_descriptor:
                return error(r, 9);
            case host::FileError::invalid:
                return error(r, guest_einval);
            case host::FileError::unsupported:
                return error(r, 95);
            case host::FileError::descriptor_limit:
                return error(r, 24);
            case host::FileError::quota:
                return error(r, 28);
            case host::FileError::io:
                return error(r, guest_eio);
            }
        }
        }
        return Fault::unsupported_service;
    }
};
GuestPosixServices::GuestPosixServices(a64::GuestMemory &memory, const a64::AppContext &app,
                                       const host::TimeService &time, std::uint32_t logical_thread,
                                       host::FileService *files)
    : impl_(std::make_unique<Impl>(memory, app, time, logical_thread, files)) {
    if (!logical_thread || logical_thread > 0x7fffffff)
        throw a64::GuestError("AETHER_GUEST_THREAD_ID", "Logical guest thread ID must be a positive pid_t");
    memory.map(trampoline_base, 4096, a64::read_write);
    impl_->trampoline_owned = true;
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto svc = little<4>(0xd4000001u | ((first_service + static_cast<std::uint32_t>(i)) << 5));
        constexpr auto ret = std::array<std::uint8_t, 4>{0xc0, 0x03, 0x5f, 0xd6};
        if (!memory.write(trampoline_base + i * 8, svc) || !memory.write(trampoline_base + i * 8 + 4, ret))
            throw a64::GuestError("AETHER_GUEST_MAPPING", "Could not initialize service trampolines");
    }
    memory.protect(trampoline_base, a64::read_execute);
    memory.map(errno_address, 4096, a64::read_write);
    impl_->errno_owned = true;
}
GuestPosixServices::~GuestPosixServices() = default;
bool GuestPosixServices::has_library(std::string_view library) const noexcept {
    return library == "libc.so" || library == "libm.so" || library == "libdl.so";
}
std::optional<elf::GuestSymbol> GuestPosixServices::resolve(std::string_view library, std::string_view name,
                                                            std::string_view version) const {
    if (library != "libc.so" || (!version.empty() && version != "LIBC"))
        return std::nullopt;
    for (std::size_t i = 0; i < entries.size(); ++i)
        if (entries[i].name == name)
            return elf::GuestSymbol{std::string(name), "libc.so", "LIBC", trampoline_base + i * 8, 8, 2};
    return std::nullopt;
}
a64::Fault GuestPosixServices::invoke(std::uint32_t service, Address instruction,
                                      std::array<std::uint64_t, 31> &registers) noexcept {
    auto &p = *impl_;
    if (service < first_service || service - first_service >= entries.size() ||
        instruction != trampoline_base + (service - first_service) * 8) {
        p.rejection = "service trap is not at its registered guest call site";
        ++p.stats.rejected_operations;
        return Fault::unsupported_service;
    }
    ++p.stats.calls;
    try {
        return p.dispatch(entries[service - first_service].operation, registers);
    } catch (const std::bad_alloc &) {
        p.rejection = "host allocation failed while marshalling a service";
    } catch (...) {
        p.rejection = "host service raised an exception";
    }
    ++p.stats.rejected_operations;
    return Fault::unsupported_service;
}
const ServiceMetrics &GuestPosixServices::metrics() const noexcept { return impl_->stats; }
std::string_view GuestPosixServices::last_rejection() const noexcept { return impl_->rejection; }
} // namespace aether::bionic
