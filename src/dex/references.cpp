#include "references.hpp"

namespace aether::dex {
std::optional<HostClass> reference_class(std::string_view descriptor) {
    if (descriptor == weak_reference_type)
        return HostClass{reference_type_name, {}};
    if (descriptor == reference_type_name)
        return HostClass{"Ljava/lang/Object;", {}, true};
    if (descriptor == reference_queue_type)
        return HostClass{"Ljava/lang/Object;", {}};
    return {};
}
bool reference_instance_method(std::string_view name, std::string_view signature) {
    return (name == "get" && signature == "()Ljava/lang/Object;") ||
           (name == "clear" && signature == "()V") ||
           ((name == "enqueue" || name == "isEnqueued") && signature == "()Z") ||
           (name == "refersTo" && signature == "(Ljava/lang/Object;)Z") ||
           (name == "clone" && signature == "()Ljava/lang/Object;");
}
void WeakReference::check() const {
    if (!initialized)
        throw DexError("AETHER_DEX_STATE", "WeakReference must be initialized before use");
}
void ReferenceQueue::check() const {
    if (!initialized)
        throw DexError("AETHER_DEX_STATE", "ReferenceQueue must be initialized before use");
}
std::optional<Value> WeakReference::invoke(ManagedRuntime &runtime, std::string_view name,
                                           std::string_view signature, std::span<const Value> args) {
    if (!reference_instance_method(name, signature))
        return {};
    check();
    if (name == "get")
        return Value::reference(referent);
    if (name == "clear") {
        referent = 0;
        return Value::nothing();
    }
    if (name == "isEnqueued")
        return Value::word(enqueued);
    if (name == "refersTo")
        return Value::word(referent == args[1].bits);
    if (name == "clone")
        runtime.raise("Ljava/lang/CloneNotSupportedException;");
    return {};
}
} // namespace aether::dex
