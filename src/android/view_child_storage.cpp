#include "aether/android/view_child_storage.hpp"
#include <algorithm>
#include <exception>
#include <limits>
#include <utility>

namespace aether::android {
namespace {
using Children = std::vector<dex::ObjectId>;
static_assert(noexcept(std::declval<Children &>().swap(std::declval<Children &>())));
static_assert(sizeof(std::size_t) <= sizeof(std::uint64_t));

[[noreturn]] void fail(const char *code, const char *message) {
    throw dex::DexError(code, message);
}
std::size_t capacity_bytes(std::size_t capacity) {
    if (capacity > std::numeric_limits<std::size_t>::max() / sizeof(dex::ObjectId))
        fail("AETHER_ANDROID_VIEW_CHILD_LIMIT", "View child storage byte size overflows");
    return capacity * sizeof(dex::ObjectId);
}
std::size_t validate_storage(dex::ManagedRuntime &runtime, const Children &children) {
    if (children.size() > children.capacity() || children.capacity() > children.max_size())
        fail("AETHER_ANDROID_VIEW_CHILD_STORAGE", "View child vector has an invalid size/capacity domain");
    const auto bytes = capacity_bytes(children.capacity());
    // This aggregate check cannot establish per-vector ownership. That remains
    // the caller's contract; no shadow ownership table or guest authority lives here.
    if (bytes > runtime.metrics().provider_storage_reserved_bytes)
        fail("AETHER_ANDROID_VIEW_CHILD_STORAGE", "View child capacity has no live provider reservation");
    return bytes;
}
std::uint64_t work_sum(std::size_t first, std::size_t second, std::size_t last) {
    const auto a = static_cast<std::uint64_t>(first);
    const auto b = static_cast<std::uint64_t>(second);
    const auto c = static_cast<std::uint64_t>(last);
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    if (b > maximum - a || c > maximum - a - b)
        fail("AETHER_ANDROID_VIEW_CHILD_LIMIT", "View child storage work count overflows");
    return a + b + c;
}
struct Reservation {
    dex::ManagedRuntime &runtime;
    std::size_t bytes;
    Reservation(dex::ManagedRuntime &owner, std::size_t amount) : runtime(owner), bytes(amount) {
        runtime.reserve_provider_storage(bytes);
    }
    ~Reservation() { runtime.release_provider_storage(bytes); }
    Reservation(const Reservation &) = delete;
    Reservation &operator=(const Reservation &) = delete;
    void transfer_to_installed_vector() noexcept { bytes = 0; }
};
} // namespace

void insert_view_child(dex::ManagedRuntime &runtime, Children &children,
                       std::size_t index, dex::ObjectId child) {
    const auto size = children.size();
    if (index > size)
        fail("AETHER_ANDROID_VIEW_CHILD_INDEX", "View child insertion index is outside the current vector");
    validate_storage(runtime, children);
    const auto maximum = std::min(children.max_size(),
        std::numeric_limits<std::size_t>::max() / sizeof(dex::ObjectId));
    if (size >= maximum)
        fail("AETHER_ANDROID_VIEW_CHILD_LIMIT", "View child storage cannot represent another child");

    if (size < children.capacity()) {
        // One new-slot zero, one visit per shifted child, and one child write.
        // ObjectId construction/assignment cannot throw; capacity already exists.
        runtime.charge_provider_work(work_sum(size - index, 1, 1));
        children.resize(size + 1, dex::ObjectId{0});
        for (auto at = size; at > index; --at)
            children[at] = children[at - 1];
        children[index] = child;
        return;
    }

    const auto old_capacity = children.capacity();
    const auto increment = std::max(old_capacity / 2, std::size_t{1});
    const auto grown = increment > maximum - old_capacity ? maximum : old_capacity + increment;
    const auto capacity = std::max(size + 1, grown);
    // Reserve fresh bytes while the old vector is still fully charged. Declare
    // the guard first so every exceptional path frees fresh before refunding it.
    Reservation reservation(runtime, capacity_bytes(capacity));
    Children fresh;
    // Preserve the runtime provider boundary's authoritative native allocation
    // failure transport; stack unwinding frees fresh before refunding the guard.
    fresh.reserve(capacity);
    // MSVC 14.44 C++20 reserve uses allocator.allocate(requested), including
    // _Allocate_at_least_helper's pre-C++23 branch. Refuse a changed policy before
    // any live publication rather than admitting extra capacity after allocation.
    if (fresh.capacity() != capacity)
        fail("AETHER_ANDROID_VIEW_CHILD_STORAGE_UNSUPPORTED",
             "View child allocation changed its admitted capacity");

    // Allocation has succeeded: failed allocation incurs no zero/copy work.
    // After this admission all population/publication is nonthrowing and has no
    // allocation, GC, guest call or reentry. Every fresh cell is really zeroed.
    runtime.charge_provider_work(work_sum(capacity, size, 1));
    fresh.resize(capacity, dex::ObjectId{0});
    for (std::size_t at = 0; at < index; ++at)
        fresh[at] = children[at];
    for (auto at = index; at < size; ++at)
        fresh[at + 1] = children[at];
    fresh[index] = child;
    fresh.resize(size + 1);
    children.swap(fresh);
    reservation.transfer_to_installed_vector();
    // fresh now owns the OLD charged buffer. Its actual deallocation must
    // precede the old-capacity refund; the installed reservation stays live.
    release_view_child_storage(runtime, fresh);
}

dex::ObjectId erase_view_child(dex::ManagedRuntime &runtime, Children &children,
                               std::size_t index) {
    const auto size = children.size();
    if (index >= size)
        fail("AETHER_ANDROID_VIEW_CHILD_INDEX", "View child removal index is outside the current vector");
    validate_storage(runtime, children);
    // One removed-ID capture, one visit per shifted child, and one tail zero.
    runtime.charge_provider_work(work_sum(size - index - 1, 1, 1));
    const auto removed = children[index];
    for (auto at = index; at + 1 < size; ++at)
        children[at] = children[at + 1];
    children.back() = 0;
    children.pop_back();
    return removed; // Capacity remains allocated, zero-spared, and charged.
}

void release_view_child_storage(dex::ManagedRuntime &runtime, Children &children) noexcept {
    const auto capacity = children.capacity();
    if (capacity > std::numeric_limits<std::size_t>::max() / sizeof(dex::ObjectId))
        std::terminate();
    const auto bytes = capacity * sizeof(dex::ObjectId);
    Children{}.swap(children); // Temporary destruction deallocates before refund.
    runtime.release_provider_storage(bytes);
}
} // namespace aether::android
