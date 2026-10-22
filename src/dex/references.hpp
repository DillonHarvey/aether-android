#pragma once
#include "aether/dex/runtime.hpp"

namespace aether::dex {
inline constexpr std::string_view reference_type_name = "Ljava/lang/ref/Reference;";
inline constexpr std::string_view weak_reference_type = "Ljava/lang/ref/WeakReference;";
inline constexpr std::string_view reference_queue_type = "Ljava/lang/ref/ReferenceQueue;";
std::optional<HostClass> reference_class(std::string_view descriptor);
bool reference_instance_method(std::string_view name, std::string_view signature);
// The queue link is strong only while enqueued; the referent is always weak.
// Queue membership is intrusive so collection never allocates queue storage.
struct WeakReference {
    ObjectId referent = 0, queue = 0, next = 0;
    bool initialized = false, enqueued = false, retired = false;
    void check() const;
    std::optional<Value> invoke(ManagedRuntime &runtime, std::string_view name, std::string_view signature,
                                std::span<const Value> args);
};
struct ReferenceQueue {
    ObjectId head = 0, tail = 0;
    bool initialized = false;
    void check() const;
};
} // namespace aether::dex
