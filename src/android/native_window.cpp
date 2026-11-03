#include "aether/android/native_window.hpp"
#include "aether/graphics/shared_window.hpp"
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <thread>

namespace aether::android {
namespace {
constexpr std::uint64_t first_native_id = 0xa7d0000000000001ULL;
constexpr std::uint32_t maximum_references = 4096, maximum_total_references = 16384;
struct Failure : std::runtime_error {
    const a64::Fault fault;
    const std::string_view reason;
    Failure(a64::Fault kind, std::string_view text) : std::runtime_error(std::string(text)), fault(kind), reason(text) {}
};
[[noreturn]] void fail(a64::Fault fault, std::string_view reason) { throw Failure{fault, reason}; }
void geometry(NativeWindowGeometry value) {
    if (!value.width || value.width > 1024 || !value.height || value.height > 1024 || value.format <= 0)
        throw std::invalid_argument("AETHER_NATIVE_WINDOW_GEOMETRY: actual bounded producer geometry is required");
}
bool backend_token(std::uint64_t value) {
    return (value & 0xffff000000000000ULL) == graphics::SharedWindowGrant::token_prefix &&
           (value & 0x0000ffffffffffffULL) != 0;
}
} // namespace

NativeWindowProducer::NativeWindowProducer(std::weak_ptr<const void> owner, std::uint64_t incarnation,
                                           std::uint64_t backend_token_value, std::uint64_t native_id,
                                           NativeWindowGeometry value)
    : owner_(std::move(owner)), incarnation_(incarnation), backend_token_(backend_token_value),
      native_id_(native_id), geometry_(value) {}

struct NativeWindows::Impl {
    const std::thread::id owner = std::this_thread::get_id();
    // A distinct owner object fences foreign registries even if an allocator
    // later recycles this registry's host address.
    std::shared_ptr<const void> identity = std::make_shared<const std::uint8_t>(std::uint8_t{0});
    std::map<std::uint64_t, std::shared_ptr<NativeWindowProducer>> producers;
    std::set<std::uint64_t> incarnations;
    std::uint64_t next_native_id = first_native_id;
    std::uint32_t total_references = 0;
    bool closed = false, java_bound = false;
    JavaResolver java;
    std::string_view error;

    void require_owner() const {
        if (owner != std::this_thread::get_id() || closed)
            fail(a64::Fault::invalid_call, "native window registry belongs to a live owning thread");
    }
    void validate(const std::shared_ptr<const NativeWindowProducer> &producer) const {
        if (!producer || producer->owner_.lock() != identity)
            fail(a64::Fault::invalid_call, "native window producer is foreign or retired");
        const auto found = producers.find(producer->native_id_);
        if (found == producers.end() || found->second.get() != producer.get())
            fail(a64::Fault::invalid_call, "native window producer incarnation is not registered");
    }
    std::shared_ptr<NativeWindowProducer> native(std::uint64_t id) const {
        const auto found = producers.find(id);
        if (found == producers.end() || (!found->second->native_references_ && !found->second->activity_references_))
            fail(a64::Fault::invalid_call, "native window argument has no acquired or Activity-borrowed reference");
        return found->second;
    }
    void acquire(const std::shared_ptr<NativeWindowProducer> &producer) {
        if (producer->native_references_ >= maximum_references - producer->activity_references_ || total_references >= maximum_total_references)
            fail(a64::Fault::unsupported_service, "native window reference capacity exhausted");
        ++producer->native_references_;
        ++total_references;
    }
    void prune() {
        for (auto it = producers.begin(); it != producers.end();) {
            // A genuine Java association or EGL ledger owns another shared_ptr.
            // Its stable producer/native identity survives a zero NDK count.
            if (it->second->abandoned_ && !it->second->native_references_ && !it->second->activity_references_ && it->second.use_count() == 1)
                it = producers.erase(it);
            else ++it;
        }
    }
    NativeWindowBinding binding(const std::shared_ptr<const NativeWindowProducer> &producer) const {
        return {producer->incarnation_, producer->backend_token_, producer->geometry_, producer};
    }
};

NativeWindows::NativeWindows() : impl_(std::make_unique<Impl>()) {}
NativeWindows::~NativeWindows() { try { shutdown(); } catch (...) { } }
std::shared_ptr<NativeWindowProducer> NativeWindows::publish(std::uint64_t incarnation,
                                                           std::uint64_t token,
                                                           NativeWindowGeometry value) {
    auto &p = *impl_;
    p.require_owner();
    geometry(value);
    if (!incarnation || !backend_token(token))
        throw std::invalid_argument("AETHER_NATIVE_WINDOW_PRODUCER: trusted producer and renderer ACK identity required");
    p.prune();
    if (p.producers.size() >= 64 || p.incarnations.size() >= 4096 ||
        p.next_native_id == (std::numeric_limits<std::uint64_t>::max)())
        fail(a64::Fault::unsupported_service, "native window producer identity capacity exhausted");
    if (p.incarnations.contains(incarnation))
        fail(a64::Fault::invalid_call, "native window producer incarnation cannot be republished");
    const auto native_id = p.next_native_id++;
    auto producer = std::shared_ptr<NativeWindowProducer>(
        new NativeWindowProducer(p.identity, incarnation, token, native_id, value));
    // Reserve the incarnation permanently before publication. Allocation failure
    // may consume an identity; it must never make an old identity reusable.
    p.incarnations.insert(incarnation);
    p.producers.emplace(native_id, producer);
    return producer;
}
void NativeWindows::update(const std::shared_ptr<NativeWindowProducer> &producer, NativeWindowGeometry value) {
    auto &p = *impl_;
    p.require_owner();
    p.validate(producer);
    if (producer->abandoned_) fail(a64::Fault::invalid_call, "abandoned native window producer cannot reopen");
    geometry(value);
    producer->geometry_ = value;
}
void NativeWindows::abandon(const std::shared_ptr<NativeWindowProducer> &producer) {
    auto &p = *impl_;
    p.require_owner();
    p.validate(producer);
    producer->abandoned_ = true;
    p.prune();
}
std::uint64_t NativeWindows::retain_activity(const std::shared_ptr<NativeWindowProducer> &producer) {
    auto &p=*impl_;p.require_owner();p.validate(producer);
    if(producer->abandoned_)fail(a64::Fault::invalid_call,"Activity cannot borrow an abandoned native window");
    if(producer->activity_references_ >= maximum_references - producer->native_references_ ||
       p.total_references >= maximum_total_references)
        fail(a64::Fault::unsupported_service,"native window reference capacity exhausted");
    ++producer->activity_references_;++p.total_references;
    return producer->native_id_;
}
void NativeWindows::release_activity(const std::shared_ptr<NativeWindowProducer> &producer) {
    auto &p=*impl_;p.require_owner();p.validate(producer);
    if(!producer->activity_references_)fail(a64::Fault::invalid_call,"Activity native window custody was already retired");
    --producer->activity_references_;--p.total_references;
    p.prune();
}
void NativeWindows::bind_java_resolver(JavaResolver resolver) {
    auto &p = *impl_;
    p.require_owner();
    if (p.java_bound || !resolver) fail(a64::Fault::invalid_call, "native window Java resolver is absent or already bound");
    p.java = std::move(resolver);
    p.java_bound = true;
}
void NativeWindows::clear_java_resolver() noexcept {
    if (impl_->owner == std::this_thread::get_id()) {
        impl_->java = {};
        impl_->java_bound = true;
    }
}
bool NativeWindows::owned_by_current_thread() const noexcept {
    return impl_->owner == std::this_thread::get_id() && !impl_->closed;
}

a64::Fault NativeWindows::invoke(std::string_view name, std::array<std::uint64_t, 31> &r) noexcept {
    auto &p = *impl_;
    if (p.owner != std::this_thread::get_id()) return a64::Fault::invalid_call;
    p.error = {};
    try {
        p.require_owner();
        p.prune();
        if (name == "ANativeWindow_fromSurface") {
            if (!p.java || !r[1]) { r[0] = 0; return a64::Fault::none; }
            const auto resolver = p.java;
            const auto producer = resolver(r[0], r[1]);
            p.require_owner(); // Trusted resolution may synchronously retire the session.
            if (!producer) { r[0] = 0; return a64::Fault::none; }
            p.validate(producer);
            // Consumer abandonment differs from Java release. A Java Surface
            // can still wrap this producer; conversion acquires its real object,
            // while subsequent width/height queries return the producer error.
            p.acquire(producer);
            r[0] = producer->native_id_;
            return a64::Fault::none;
        }
        const auto producer = p.native(r[0]);
        if (name == "ANativeWindow_acquire") {
            p.acquire(producer); return a64::Fault::none;
        }
        if (name == "ANativeWindow_release") {
            if(!producer->native_references_)
                fail(a64::Fault::invalid_call,"guest native window release cannot consume Activity custody");
            --producer->native_references_;
            --p.total_references;
            return a64::Fault::none;
        }
        if (name == "ANativeWindow_getWidth" || name == "ANativeWindow_getHeight" ||
            name == "ANativeWindow_getFormat") {
            if (producer->abandoned_) {
                r[0] = static_cast<std::uint64_t>(std::int64_t{-19}); // Android -ENODEV.
            } else if (name == "ANativeWindow_getWidth") r[0] = producer->geometry_.width;
            else if (name == "ANativeWindow_getHeight") r[0] = producer->geometry_.height;
            else r[0] = static_cast<std::uint32_t>(producer->geometry_.format);
            return a64::Fault::none;
        }
        fail(a64::Fault::unsupported_service, "native window operation is unsupported");
    } catch (const Failure &failure) {
        p.error = failure.reason; return failure.fault;
    } catch (...) {
        p.error = "native window resolver or host allocation failed";
        return a64::Fault::unsupported_service;
    }
}
std::string_view NativeWindows::last_error() const noexcept {
    if (impl_->owner != std::this_thread::get_id()) return "native window registry belongs to another thread";
    return impl_->error;
}
std::optional<NativeWindowBinding> NativeWindows::resolve_for_egl(std::uint64_t native_id) const {
    const auto &p = *impl_;
    p.require_owner();
    const auto producer = p.native(native_id);
    if (producer->abandoned_) return {};
    return p.binding(producer);
}
std::optional<NativeWindowBinding> NativeWindows::query_for_egl(const NativeWindowBinding &binding) const {
    const auto &p = *impl_;
    p.require_owner();
    p.validate(binding.retained);
    if (binding.incarnation != binding.retained->incarnation_ || binding.backend_token != binding.retained->backend_token_)
        fail(a64::Fault::invalid_call, "native window EGL binding identity changed");
    if (binding.retained->abandoned_) return {};
    return p.binding(binding.retained);
}
void NativeWindows::shutdown() {
    auto &p = *impl_;
    if (p.owner != std::this_thread::get_id())
        throw std::invalid_argument("AETHER_NATIVE_WINDOW_OWNER: shutdown belongs to the registry owner");
    if (p.closed) return;
    p.closed = true;
    for (auto &[id, producer] : p.producers) { (void)id; producer->abandoned_ = true; }
    p.java = {};
    p.producers.clear();
    p.total_references = 0;
    p.identity.reset();
}
} // namespace aether::android
