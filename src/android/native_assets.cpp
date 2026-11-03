#include "native_assets.hpp"
#include "aether/android/native.hpp"
#include <algorithm>
#include <bit>
#include <limits>
#include <map>
#include <new>
#include <set>
#include <thread>

namespace aether::android {
namespace {
using a64::Address;
using a64::Fault;
constexpr std::uint64_t transfer_limit = 1024 * 1024, buffer_limit = 16 * 1024 * 1024;
constexpr Address arena_begin = Address{1} << 40, arena_end = arena_begin + 64 * 1024 * 1024;
constexpr std::uint64_t manager_token = 0xa55e00000001ULL;
struct Failure { Fault fault; std::string_view reason; };
[[noreturn]] void fail(Fault fault, std::string_view reason) { throw Failure{fault, reason}; }
bool valid_path(std::string_view name, bool directory) {
    if (name.empty()) return directory;
    if (name.size() > 504 || name.front() == '/' || name.back() == '/' ||
        name.find('\\') != std::string_view::npos || name.find(':') != std::string_view::npos)
        return false;
    for (std::size_t at = 0; at < name.size();) {
        const auto end = name.find('/', at);
        const auto part = name.substr(at, end == std::string_view::npos ? name.size() - at : end - at);
        if (part.empty() || part == "." || part == "..") return false;
        at = end == std::string_view::npos ? name.size() : end + 1;
    }
    return true;
}
std::size_t rounded(std::uint64_t bytes) {
    // Only bounded buffers and one-page directory names call this helper.
    return static_cast<std::size_t>((std::max)(bytes, std::uint64_t{1}) + 4095) & ~std::size_t{4095};
}
} // namespace

struct NativeAssets::Impl {
    struct Asset {
        apk::PackageView::Member member;
        std::uint64_t length = 0, cursor = 0;
        Address buffer = 0;
        std::size_t mapped = 0;
        std::optional<apk::Bytes> stored;
    };
    struct Directory {
        std::vector<std::string> names;
        std::size_t next = 0;
        Address text = 0;
    };
    a64::GuestMemory &memory;
    const apk::PackageView &package;
    std::function<bool(Address, std::uint64_t)> validate_java;
    NativeAssetManagerAccess manager_access;
    const std::thread::id owner = std::this_thread::get_id();
    std::map<std::uint64_t, Asset> assets;
    std::map<std::uint64_t, Directory> directories;
    std::uint64_t next_handle = manager_token + 1;
    std::size_t buffer_bytes = 0;
    bool manager_published = false, closed = false;
    std::string_view error;

    Impl(a64::GuestMemory &space, const apk::PackageView &input,
         std::function<bool(Address, std::uint64_t)> validate)
        : memory(space), package(input), validate_java(std::move(validate)) {}
    Impl(a64::GuestMemory &space, const apk::PackageView &input, NativeAssetManagerAccess access)
        : memory(space), package(input), manager_access(std::move(access)) {
        if (!manager_access.from_java || !manager_access.owns)
            throw a64::GuestError("AETHER_ANDROID_ASSET_BINDING", "Native manager identity requires publication and live-owner validation");
    }
    bool owns_manager(std::uint64_t handle) const {
        if (manager_access.owns)
            return (handle & ~native_asset_manager_identity_mask) == native_asset_manager_identity_tag &&
                   (handle & native_asset_manager_identity_mask) && manager_access.owns(handle);
        return manager_published && handle == manager_token;
    }
    void require_owner() const {
        if (owner != std::this_thread::get_id() || closed)
            fail(Fault::invalid_call, "native assets belong to a live owning thread");
    }
    void require_manager(std::uint64_t handle) const {
        if (!owns_manager(handle))
            fail(Fault::invalid_call, "native AssetManager handle is not owned by this app");
    }
    std::uint64_t publish_manager(Address environment, std::uint64_t object) {
        require_owner();
        if (manager_access.from_java) {
            const auto token = manager_access.from_java(environment, object);
            require_owner();
            if (!token) return 0;
            if (!owns_manager(token))
                fail(Fault::invalid_call, "native manager publication has no live issued owner");
            return token;
        }
        if (!validate_java || !validate_java(environment, object)) return 0;
        require_owner();
        manager_published = true;
        return manager_token;
    }
    std::uint64_t handle() {
        if (next_handle > native_asset_manager_identity_mask)
            fail(Fault::unsupported_service, "native asset/directory identity space exhausted");
        return next_handle++;
    }
    std::string path(Address address) const {
        std::string result;
        for (std::uint64_t i = 0; i <= 504; ++i) {
            std::array<std::uint8_t, 1> byte{};
            if (address >= a64::GuestMemory::address_limit || i >= a64::GuestMemory::address_limit - address ||
                !memory.read(address + i, byte))
                fail(Fault::read, "native asset path is outside readable guest memory");
            if (!byte[0]) return result;
            result.push_back(static_cast<char>(byte[0]));
        }
        fail(Fault::unsupported_service, "native asset path exceeds 504 bytes");
    }
    Asset &asset(std::uint64_t handle_value) {
        const auto found = assets.find(handle_value);
        if (found == assets.end()) fail(Fault::invalid_call, "native asset handle is stale or foreign");
        return found->second;
    }
    Directory &directory(std::uint64_t handle_value) {
        const auto found = directories.find(handle_value);
        if (found == directories.end()) fail(Fault::invalid_call, "native asset directory is stale or foreign");
        return found->second;
    }
    Address allocate(std::size_t size) {
        const auto address = memory.find_free(arena_begin, arena_end, size);
        if (!address) fail(Fault::unsupported_service, "native asset guest buffer arena exhausted");
        memory.map(*address, size, a64::read_write);
        return *address;
    }
    std::vector<std::uint8_t> bytes(Asset &asset_value, std::uint64_t at, std::uint64_t count) {
        // Package bytes are immutable and outlive this adapter. Validate a
        // stored member's CRC once, then retain only a host-private borrowed
        // view: a guest receives a copy, never this host address.
        if (asset_value.member.archive->entries()[asset_value.member.index].stored) {
            if (!asset_value.stored)
                asset_value.stored = asset_value.member.archive->stored_view(asset_value.member.index);
            if (asset_value.stored->size() != asset_value.length)
                fail(Fault::unsupported_service, "native stored asset has an inconsistent extent");
            const auto range = asset_value.stored->subspan(static_cast<std::size_t>(at),
                                                           static_cast<std::size_t>(count));
            return {range.begin(), range.end()};
        }
        const apk::ArchiveRange range{at, count};
        // Even empty assets pass complete size/CRC validation. No output escapes
        // until Archive has accepted the entire original member.
        auto read = asset_value.member.archive->read_ranges(asset_value.member.index, std::span(&range, 1));
        if (read.ranges.size() != 1 || read.ranges.front().size() != count)
            fail(Fault::unsupported_service, "native asset archive returned an incomplete range");
        return std::move(read.ranges.front());
    }
    void close_asset(Asset &asset_value) {
        if (asset_value.buffer) {
            memory.unmap(asset_value.buffer);
            buffer_bytes -= asset_value.mapped;
            asset_value.buffer = 0;
            asset_value.mapped = 0;
        }
    }
    void close_directory(Directory &directory_value) {
        if (directory_value.text) {
            memory.unmap(directory_value.text);
            directory_value.text = 0;
        }
    }
};

NativeAssets::NativeAssets(a64::GuestMemory &memory, const apk::PackageView &package,
                           std::function<bool(Address, std::uint64_t)> validate_java)
    : impl_(std::make_unique<Impl>(memory, package, std::move(validate_java))) {}
NativeAssets::NativeAssets(a64::GuestMemory &memory, const apk::PackageView &package,
                           NativeAssetManagerAccess access)
    : impl_(std::make_unique<Impl>(memory, package, std::move(access))) {}
NativeAssets::~NativeAssets() {
    // The parent adapter is single-owner; destruction does not call guests or
    // access the borrowed package. Best-effort cleanup cannot throw outward.
    try { shutdown(); } catch (...) { }
}
bool NativeAssets::owns_manager(std::uint64_t handle) const noexcept {
    const auto &p = *impl_;
    if (p.owner != std::this_thread::get_id() || p.closed) return false;
    // Observation callbacks are trusted nonallocating checks. A malformed
    // producer cannot turn an exception into accepted native authority.
    try { return p.owns_manager(handle); } catch (...) { return false; }
}
std::uint64_t NativeAssets::publish_manager(Address environment, std::uint64_t java_manager) {
    const auto manager = impl_->publish_manager(environment, java_manager);
    if (!manager)
        throw a64::GuestError("AETHER_ANDROID_ASSET_MANAGER", "Native lifecycle requires an authenticated owned Java AssetManager");
    return manager;
}

Fault NativeAssets::invoke(std::string_view name, std::array<std::uint64_t, 31> &r) noexcept {
    auto &p = *impl_;
    if (p.owner != std::this_thread::get_id()) return Fault::invalid_call;
    p.error = {};
    try {
        p.require_owner();
        if (name == "AAssetManager_fromJava") {
            r[0] = p.publish_manager(r[0], r[1]);
            return Fault::none;
        }
        if (name == "AAssetManager_open") {
            p.require_manager(r[0]);
            const auto mode = static_cast<std::int32_t>(static_cast<std::uint32_t>(r[2]));
            if (mode < 0 || mode > 3) { r[0] = 0; return Fault::none; }
            const auto path = p.path(r[1]);
            if (!valid_path(path, false)) { r[0] = 0; return Fault::none; }
            if (p.assets.size() >= 64) fail(Fault::unsupported_service, "native assets exceed 64 live handles");
            apk::PackageView::Member member;
            try { member = p.package.asset(path); }
            catch (const apk::InspectError &failure) {
                if (failure.diagnostic.code == "AETHER_PACKAGE_ASSET_NOT_FOUND") { r[0] = 0; return Fault::none; }
                throw;
            }
            const auto length = member.archive->entries()[member.index].bytes;
            const auto handle_value = p.handle();
            Impl::Asset asset_value;
            asset_value.member = std::move(member);
            asset_value.length = length;
            p.assets.emplace(handle_value, std::move(asset_value));
            r[0] = handle_value;
            return Fault::none;
        }
        if (name == "AAssetManager_openDir") {
            p.require_manager(r[0]);
            const auto path = p.path(r[1]);
            if (!valid_path(path, true)) { r[0] = 0; return Fault::none; }
            if (p.directories.size() >= 32)
                fail(Fault::unsupported_service, "native assets exceed 32 live directories");
            const auto prefix = std::string("assets/") + (path.empty() ? "" : path + '/');
            std::set<std::string> names;
            std::size_t name_bytes = 0;
            for (const auto &part : p.package.parts) {
                for (const auto &entry : part.archive->entries()) {
                    if (entry.directory || !entry.path.starts_with(prefix)) continue;
                    const auto leaf = std::string_view(entry.path).substr(prefix.size());
                    if (leaf.empty() || leaf.find('/') != std::string_view::npos) continue;
                    if (!valid_path(leaf, false))
                        fail(Fault::unsupported_service, "native asset directory contains unsupported names");
                    if (names.contains(std::string(leaf)))
                        fail(Fault::unsupported_service, "native asset directory is ambiguous across APK members");
                    if (names.size() >= 4096 || leaf.size() + 1 > 1024 * 1024 - name_bytes)
                        fail(Fault::unsupported_service, "native asset directory listing exceeds its metadata bound");
                    name_bytes += leaf.size() + 1;
                    names.emplace(leaf);
                }
            }
            Impl::Directory directory;
            directory.names.assign(names.begin(), names.end());
            const auto handle_value = p.handle();
            p.directories.emplace(handle_value, std::move(directory));
            r[0] = handle_value;
            return Fault::none;
        }
        if (name.starts_with("AAssetDir_")) {
            auto &directory = p.directory(r[0]);
            if (name == "AAssetDir_close") {
                p.close_directory(directory);
                p.directories.erase(r[0]);
                return Fault::none;
            }
            if (name == "AAssetDir_rewind") {
                p.close_directory(directory);
                directory.next = 0;
                return Fault::none;
            }
            if (name == "AAssetDir_getNextFileName") {
                if (directory.next == directory.names.size()) { r[0] = 0; return Fault::none; }
                const auto &text = directory.names[directory.next];
                std::vector<std::uint8_t> output(text.begin(), text.end());
                output.push_back(0);
                const auto address = p.allocate(a64::GuestMemory::page_size);
                try {
                    if (!p.memory.write(address, output)) fail(Fault::write, "native asset directory name copy failed");
                    p.memory.protect(address, a64::Permission::read);
                } catch (...) { p.memory.unmap(address); throw; }
                try { p.close_directory(directory); }
                catch (...) { p.memory.unmap(address); throw; }
                directory.text = address;
                ++directory.next;
                r[0] = address;
                return Fault::none;
            }
            fail(Fault::unsupported_service, "native asset directory operation is unsupported");
        }
        auto &asset = p.asset(r[0]);
        if (name == "AAsset_close") {
            p.close_asset(asset);
            p.assets.erase(r[0]);
            return Fault::none;
        }
        // ARM64 is LP64: off_t and off64_t are both signed64-bit here.
        if (name == "AAsset_getLength" || name == "AAsset_getLength64") {
            r[0] = asset.length; return Fault::none;
        }
        if (name == "AAsset_getRemainingLength" || name == "AAsset_getRemainingLength64") {
            r[0] = asset.length - asset.cursor; return Fault::none;
        }
        if (name == "AAsset_seek" || name == "AAsset_seek64") {
            const auto delta = std::bit_cast<std::int64_t>(r[1]);
            const auto whence = static_cast<std::uint32_t>(r[2]);
            if (whence > 2) { r[0] = UINT64_MAX; return Fault::none; }
            const auto base = whence == 0 ? 0 : whence == 1 ? asset.cursor : asset.length;
            std::uint64_t target = base;
            if (delta < 0) {
                const auto magnitude = std::uint64_t{0} - std::bit_cast<std::uint64_t>(delta);
                if (magnitude > base) { r[0] = UINT64_MAX; return Fault::none; }
                target -= magnitude;
            } else {
                const auto amount = static_cast<std::uint64_t>(delta);
                if (amount > asset.length - base) { r[0] = UINT64_MAX; return Fault::none; }
                target += amount;
            }
            asset.cursor = target;
            r[0] = target;
            return Fault::none;
        }
        if (name == "AAsset_read") {
            if (r[2] > transfer_limit)
                fail(Fault::unsupported_service, "native asset read exceeds the 1 MiB transfer bound");
            const auto count = (std::min)(r[2], asset.length - asset.cursor);
            if (!count) { r[0] = 0; return Fault::none; }
            if (!p.memory.accessible(r[1], static_cast<std::size_t>(count), a64::Permission::write))
                fail(Fault::write, "native asset output is outside writable guest memory");
            auto output = p.bytes(asset, asset.cursor, count);
            if (!p.memory.write(r[1], output)) fail(Fault::write, "native asset output copy failed");
            asset.cursor += count;
            r[0] = count;
            return Fault::none;
        }
        if (name == "AAsset_getBuffer") {
            if (asset.buffer) { r[0] = asset.buffer; return Fault::none; }
            if (asset.length > buffer_limit) { r[0] = 0; return Fault::none; }
            const auto allocation = rounded(asset.length);
            if (allocation > buffer_limit - p.buffer_bytes) { r[0] = 0; return Fault::none; }
            Address address = 0;
            try {
                auto output = p.bytes(asset, 0, asset.length);
                const auto available = p.memory.find_free(arena_begin, arena_end, allocation);
                if (!available) { r[0] = 0; return Fault::none; }
                p.memory.map(*available, allocation, a64::read_write);
                address = *available;
                if (!output.empty() && !p.memory.write(address, output))
                    fail(Fault::write, "native asset buffer copy failed");
                p.memory.protect(address, a64::Permission::read);
            } catch (const std::bad_alloc &) {
                if (address) p.memory.unmap(address);
                r[0] = 0;
                return Fault::none;
            } catch (const a64::GuestError &failure) {
                if (address) p.memory.unmap(address);
                // The admitted address/size are already aligned and free in
                // this single-owner arena. Mapping/OS allocation or sealing
                // failure is this API's ordinary NULL result, not fake data.
                if (failure.code == "AETHER_GUEST_ALLOCATION" || failure.code == "AETHER_GUEST_MAPPING" ||
                    failure.code == "AETHER_GUEST_PROTECTION") { r[0] = 0; return Fault::none; }
                throw;
            } catch (...) {
                if (address) p.memory.unmap(address);
                throw; // Archive integrity and invalid copy failures stay explicit.
            }
            asset.buffer = address;
            asset.mapped = allocation;
            p.buffer_bytes += allocation;
            r[0] = address;
            return Fault::none;
        }
        if (name == "AAsset_isAllocated") {
            // This adapter streams archive ranges until a whole guest buffer is
            // requested. Every such buffer is allocated RAM, never a host mmap.
            r[0] = asset.buffer ? 1 : 0;
            return Fault::none;
        }
        fail(Fault::unsupported_service, "native asset operation is unsupported");
    } catch (const Failure &failure) {
        p.error = failure.reason;
        return failure.fault;
    } catch (const apk::InspectError &) {
        p.error = "native asset archive failed validation or is ambiguous";
        return Fault::unsupported_service;
    } catch (const a64::GuestError &) {
        p.error = "native asset guest mapping failed";
        return Fault::windows_service;
    } catch (...) {
        p.error = "native asset host allocation or internal operation failed";
        return Fault::unsupported_service;
    }
}

std::string_view NativeAssets::last_error() const noexcept {
    if (impl_->owner != std::this_thread::get_id()) return "native assets belong to another owner thread";
    return impl_->error;
}
void NativeAssets::shutdown() {
    auto &p = *impl_;
    if (p.owner != std::this_thread::get_id())
        throw a64::GuestError("AETHER_ANDROID_ASSET_OWNER", "Native asset shutdown belongs to another thread");
    p.closed = true;
    p.manager_published = false;
    for (auto &[id, asset] : p.assets) { (void)id; p.close_asset(asset); }
    for (auto &[id, directory] : p.directories) { (void)id; p.close_directory(directory); }
    p.assets.clear();
    p.directories.clear();
    p.validate_java = {};
    p.manager_access = {};
}
} // namespace aether::android
