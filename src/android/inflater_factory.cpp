#include "aether/android/inflater_factory.hpp"
#include <array>
#include <memory>
#include <span>

namespace aether::android {
namespace {
class InflaterReference final {
    dex::ManagedRuntime &runtime_;
    dex::ObjectId object_;

  public:
    InflaterReference(dex::ManagedRuntime &runtime, dex::ObjectId object)
        : runtime_(runtime), object_(object) {
        runtime_.retain(object_);
    }
    ~InflaterReference() { runtime_.release(object_); }
    InflaterReference(const InflaterReference &) = delete;
    InflaterReference &operator=(const InflaterReference &) = delete;
};

class FactoryMergerState final : public dex::HostObjectState {
  public:
    const std::array<dex::Value, 4> factories;
    FactoryMergerState(dex::ObjectId f1, dex::ObjectId f12,
                       dex::ObjectId f2, dex::ObjectId f22)
        : factories{dex::Value::reference(f1), dex::Value::reference(f12),
                    dex::Value::reference(f2), dex::Value::reference(f22)} {}
    std::span<const dex::Value> values() const noexcept override { return factories; }
    std::size_t bytes() const noexcept override { return sizeof(*this); }
};

dex::ObjectId invoke_merged_factory(dex::ManagedRuntime &runtime, dex::ObjectId factory,
    std::span<const dex::Value> arguments, bool parent_aware) {
    InflaterReference factory_root(runtime, factory);
    runtime.charge_provider_work(1);
    // A null field is legal in the merger constructor. Its invocation has the
    // original NPE, rather than being treated as an absent/fallback factory.
    const auto result = runtime.invoke_virtual_named(factory, "onCreateView", parent_aware
        ? "(Landroid/view/View;Ljava/lang/String;Landroid/content/Context;Landroid/util/AttributeSet;)Landroid/view/View;"
        : "(Ljava/lang/String;Landroid/content/Context;Landroid/util/AttributeSet;)Landroid/view/View;", arguments);
    if (result.kind != dex::ValueKind::reference &&
        !(result.kind == dex::ValueKind::word && !result.bits))
        runtime.raise("Ljava/lang/IllegalStateException;", u"Inflater factory returned a non-reference");
    InflaterReference result_root(runtime, result.bits);
    if (result.bits && !runtime.assignable(result.bits, "Landroid/view/View;"))
        runtime.raise("Ljava/lang/ClassCastException;", u"Inflater factory returned a non-View");
    return result.bits;
}
} // namespace

dex::ObjectId new_inflater_factory_merger(dex::ManagedRuntime &runtime,
    dex::ObjectId f1, dex::ObjectId f12, dex::ObjectId f2, dex::ObjectId f22) {
    InflaterReference first_root(runtime, f1), first2_root(runtime, f12),
        second_root(runtime, f2), second2_root(runtime, f22);
    runtime.charge_provider_work(5);
    if (runtime.class_definition(inflater_factory_merger_type))
        runtime.raise("Ljava/lang/IllegalStateException;", u"Package class collides with the issued inflater factory merger");
    const auto object = runtime.new_object(inflater_factory_merger_type);
    InflaterReference object_root(runtime, object);
    // Keep the new native header charged before its allocation and across any
    // later admission. The four factory references and target are rooted above.
    runtime.reserve_provider_storage(sizeof(FactoryMergerState));
    struct Storage {
        dex::ManagedRuntime &runtime;
        std::size_t bytes;
        ~Storage() { runtime.release_provider_storage(bytes); }
    } storage{runtime, sizeof(FactoryMergerState)};
    auto metadata = std::make_unique<FactoryMergerState>(f1, f12, f2, f22);
    runtime.charge_provider_work(4); // Actual traced-reference validation at publication.
    runtime.set_host_state_with_storage(object, std::move(metadata), storage.bytes);
    return object;
}

dex::ObjectId invoke_inflater_factory_merger(dex::ManagedRuntime &runtime,
    dex::ObjectId receiver, std::span<const dex::Value> arguments, bool parent_aware) {
    InflaterReference receiver_root(runtime, receiver);
    if (!receiver) runtime.raise("Ljava/lang/NullPointerException;");
    if (arguments.size() != (parent_aware ? 4u : 3u))
        runtime.raise("Ljava/lang/IllegalArgumentException;", u"Inflater factory merger arguments have the wrong arity");
    // Four fixed roots require no temporary native container. Original nullable
    // references remain alive even when a callback replaces inflater state.
    for (const auto value : arguments)
        if (value.kind != dex::ValueKind::reference &&
            !(value.kind == dex::ValueKind::word && !value.bits))
            runtime.raise("Ljava/lang/IllegalArgumentException;", u"Inflater factory merger requires reference arguments");
    InflaterReference arg0_root(runtime, arguments[0].bits), arg1_root(runtime, arguments[1].bits),
        arg2_root(runtime, arguments[2].bits), arg3_root(runtime, parent_aware ? arguments[3].bits : 0);
    const std::array copied_arguments{arguments[0], arguments[1], arguments[2],
        parent_aware ? arguments[3] : dex::Value::reference(0)};
    const auto stable_arguments = std::span<const dex::Value>(copied_arguments).first(arguments.size());
    runtime.charge_provider_work(1);
    const auto *metadata = dynamic_cast<const FactoryMergerState *>(runtime.host_state(receiver));
    if (!metadata || runtime.object_type(receiver) != inflater_factory_merger_type)
        runtime.raise("Ljava/lang/IllegalStateException;", u"Inflater factory merger is not an issued carrier");
    // Copy only scalar IDs; the rooted receiver keeps the four final references
    // traced. Do not retain a borrowed host-state pointer across guest code.
    const auto fields = metadata->factories;
    const auto invoke_pair = [&](std::size_t index) {
        runtime.charge_provider_work(1);
        if (parent_aware && fields[index + 1].bits)
            return invoke_merged_factory(runtime, fields[index + 1].bits, stable_arguments, true);
        return invoke_merged_factory(runtime, fields[index].bits,
            stable_arguments.subspan(parent_aware ? 1u : 0u), false);
    };
    if (const auto result = invoke_pair(0)) return result;
    return invoke_pair(2);
}

dex::ObjectId invoke_inflater_factories(dex::ManagedRuntime &runtime,
                                       dex::ObjectId inflater, dex::ObjectId parent,
                                       dex::ObjectId name, dex::ObjectId context,
                                       dex::ObjectId attributes, InflaterFactoryAccess access) {
    InflaterReference inflater_root(runtime, inflater), parent_root(runtime, parent),
        name_root(runtime, name), context_root(runtime, context), attrs_root(runtime, attributes);
    // tryCreateView dereferences the name, but passes nullable Context and
    // AttributeSet to the original factories without inventing replacements.
    if (!inflater || !name)
        runtime.raise("Ljava/lang/NullPointerException;", u"Inflater or factory tag name is null");
    if (!access.read)
        runtime.raise("Ljava/lang/IllegalStateException;", u"Inflater factory source is not attached");
    if (!runtime.assignable(inflater, "Landroid/view/LayoutInflater;") ||
        (context && !runtime.assignable(context, "Landroid/content/Context;")) ||
        (attributes && !runtime.assignable(attributes, "Landroid/util/AttributeSet;")) ||
        (parent && !runtime.assignable(parent, "Landroid/view/View;")))
        runtime.raise("Ljava/lang/IllegalArgumentException;", u"Inflater factory arguments have invalid types");
    (void)runtime.string(name);

    const auto invoke = [&](dex::ObjectId factory, bool parent_aware) -> dex::ObjectId {
        InflaterReference factory_root(runtime, factory);
        const auto family = parent_aware ? "Landroid/view/LayoutInflater$Factory2;"
                                         : "Landroid/view/LayoutInflater$Factory;";
        if (!runtime.assignable(factory, family))
            runtime.raise("Ljava/lang/IllegalStateException;", u"Inflater factory state has an invalid receiver");
        const std::array full{dex::Value::reference(parent), dex::Value::reference(name),
                              dex::Value::reference(context), dex::Value::reference(attributes)};
        const auto args = std::span<const dex::Value>(full).subspan(parent_aware ? 0u : 1u);
        const auto result = runtime.invoke_virtual_named(factory, "onCreateView", parent_aware
            ? "(Landroid/view/View;Ljava/lang/String;Landroid/content/Context;Landroid/util/AttributeSet;)Landroid/view/View;"
            : "(Ljava/lang/String;Landroid/content/Context;Landroid/util/AttributeSet;)Landroid/view/View;", args);
        if (result.kind != dex::ValueKind::reference &&
            !(result.kind == dex::ValueKind::word && !result.bits))
            runtime.raise("Ljava/lang/IllegalStateException;", u"Inflater factory returned a non-reference");
        InflaterReference result_root(runtime, result.bits);
        if (result.bits && !runtime.assignable(result.bits, "Landroid/view/View;"))
            runtime.raise("Ljava/lang/ClassCastException;", u"Inflater factory returned a non-View");
        return result.bits;
    };

    dex::ObjectId result = 0;
    if (const auto factory2 = access.read(access.owner, inflater, InflaterFactorySlot::factory2))
        result = invoke(factory2, true);
    else if (const auto factory = access.read(access.owner, inflater, InflaterFactorySlot::factory))
        result = invoke(factory, false);
    if (result) return result;
    // A public callback may change the private chain. Read its actual state
    // afterwards, without retaining a pointer into replaceable owner metadata.
    if (const auto factory = access.read(access.owner, inflater, InflaterFactorySlot::private_factory))
        return invoke(factory, true);
    return 0;
}
} // namespace aether::android
