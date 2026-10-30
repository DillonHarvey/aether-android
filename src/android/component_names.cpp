#include "component_names.hpp"
#include "../dex/class_names.hpp"
#include <algorithm>
#include <array>
#include <bit>

namespace aether::android {
namespace {
using dex::ObjectId;
using dex::Value;

// Original Aether state. Observable value rules are reviewed against Android15
// ComponentName.java, framework revision 4e43ad12e1b211f15152e9c5b16b0fe88e6b93f3.
// No AOSP implementation is imported. Original String identities stay traced.
class ComponentState final : public dex::HostObjectState {
  public:
    const std::array<Value, 2> references;
    ComponentState(ObjectId package, ObjectId class_name)
        : references{Value::reference(package), Value::reference(class_name)} {}
    std::span<const Value> values() const noexcept override { return references; }
    std::size_t bytes() const noexcept override { return sizeof(*this); }
};
class Root final {
    dex::ManagedRuntime &runtime;
    ObjectId object;
  public:
    Root(dex::ManagedRuntime &runtime, ObjectId object) : runtime(runtime), object(object) {
        runtime.retain(object);
    }
    ~Root() { runtime.release(object); }
    Root(const Root &) = delete;
    Root &operator=(const Root &) = delete;
};
[[noreturn]] void bad(std::string_view code, std::string_view message) {
    throw dex::DexError("AETHER_ANDROID_" + std::string(code), std::string(message));
}
ObjectId reference(Value value) {
    if (value.kind != dex::ValueKind::reference) bad("COMPONENT_ARGUMENT", "ComponentName requires references");
    return value.bits;
}
void check_units(std::u16string_view text) {
    if (text.size() > component_name_units)
        bad("COMPONENT_LIMIT", "ComponentName field exceeds 4096 UTF-16 units");
}
const ComponentState &state(dex::ManagedRuntime &runtime, ObjectId object) {
    if (!object) runtime.raise("Ljava/lang/NullPointerException;");
    if (runtime.object_type(object) != component_type)
        bad("COMPONENT_STATE", "ComponentName requires its exact final-class receiver");
    const auto *stored = dynamic_cast<const ComponentState *>(runtime.host_state(object));
    if (!stored) bad("COMPONENT_STATE", "ComponentName constructor has not completed");
    return *stored;
}
void initialize(dex::ManagedRuntime &runtime, ObjectId receiver, ObjectId package, ObjectId class_name,
                bool require_package) {
    if (!receiver) runtime.raise("Ljava/lang/NullPointerException;");
    if (runtime.object_type(receiver) != component_type)
        bad("COMPONENT_STATE", "ComponentName requires its exact final-class receiver");
    if (runtime.host_state(receiver)) bad("COMPONENT_STATE", "ComponentName constructor invoked twice");
    if (require_package && !package) runtime.raise("Ljava/lang/NullPointerException;", u"package name is null");
    if (!class_name) runtime.raise("Ljava/lang/NullPointerException;", u"class name is null");
    if (package) check_units(runtime.string(package));
    check_units(runtime.string(class_name));
    runtime.set_host_state(receiver, std::make_unique<ComponentState>(package, class_name));
}
ObjectId from_references(dex::ManagedRuntime &runtime, ObjectId package, ObjectId class_name) {
    Root package_root(runtime, package), class_root(runtime, class_name);
    const auto result = runtime.new_object(component_type);
    Root result_root(runtime, result);
    initialize(runtime, result, package, class_name, true);
    return result;
}
ObjectId context_package(dex::ManagedRuntime &runtime, ObjectId context) {
    // Preserve actual ContextWrapper/guest override behavior and exceptions.
    return reference(runtime.invoke_virtual_named(context, "getPackageName", "()Ljava/lang/String;"));
}
ObjectId class_string(dex::ManagedRuntime &runtime, ObjectId mirror) {
    // Class is final; this is exactly the original helper used by Class.getName.
    // Copy the descriptor before new_string may load or collect managed state.
    const auto descriptor = std::string(runtime.represented_class(mirror));
    const auto text = dex::binary_name(descriptor);
    check_units(text);
    return runtime.new_string(text);
}
ObjectId relative(dex::ManagedRuntime &runtime, ObjectId package, ObjectId class_name) {
    if (!class_name || runtime.string(class_name).empty())
        runtime.raise("Ljava/lang/IllegalArgumentException;", u"class name cannot be empty");
    const auto text = std::u16string(runtime.string(class_name));
    check_units(text);
    if (text.front() != u'.') return from_references(runtime, package, class_name);
    auto expanded = package ? std::u16string(runtime.string(package)) : std::u16string(u"null");
    if (package) check_units(expanded);
    if (text.size() > component_name_units - expanded.size())
        bad("COMPONENT_LIMIT", "Relative ComponentName class exceeds 4096 UTF-16 units");
    expanded += text;
    const auto name = runtime.new_string(expanded);
    Root name_root(runtime, name);
    return from_references(runtime, package, name);
}
std::u16string_view short_class(std::u16string_view package, std::u16string_view class_name) {
    return class_name.starts_with(package) && class_name.size() > package.size() &&
                   class_name[package.size()] == u'.' ? class_name.substr(package.size()) : class_name;
}
std::uint32_t java_hash(std::u16string_view text) noexcept {
    std::uint32_t result = 0;
    for (const auto unit : text) result = result * 31u + static_cast<std::uint32_t>(unit);
    return result;
}
std::int32_t java_compare(std::u16string_view left, std::u16string_view right) noexcept {
    for (std::size_t n = 0, count = std::min(left.size(), right.size()); n < count; ++n)
        if (left[n] != right[n]) return static_cast<std::int32_t>(left[n]) - static_cast<std::int32_t>(right[n]);
    return static_cast<std::int32_t>(left.size()) - static_cast<std::int32_t>(right.size());
}
} // namespace

dex::ObjectId new_component(dex::ManagedRuntime &runtime, std::u16string_view package,
                            std::u16string_view class_name) {
    check_units(package);
    check_units(class_name);
    // Inputs may be borrowed managed String views. Own both before allocating.
    const auto package_copy = std::u16string(package), class_copy = std::u16string(class_name);
    const auto package_id = runtime.new_string(package_copy);
    Root package_root(runtime, package_id);
    const auto class_id = runtime.new_string(class_copy);
    Root class_root(runtime, class_id);
    return from_references(runtime, package_id, class_id);
}
std::pair<std::u16string, std::u16string> component_parts(dex::ManagedRuntime &runtime, ObjectId component) {
    Root component_root(runtime, component);
    const auto references = state(runtime, component).references;
    return {std::u16string(runtime.string(references[0].bits)),
            std::u16string(runtime.string(references[1].bits))};
}
dex::Value invoke_component(dex::ManagedRuntime &runtime, std::string_view name,
                            std::string_view signature, std::span<const Value> args) {
    if (args.size() > 3) bad("COMPONENT_ARGUMENT", "ComponentName argument count exceeds its profile");
    std::array<ObjectId, 3> ids{};
    for (std::size_t n = 0; n < args.size(); ++n) ids[n] = reference(args[n]);
    Root first(runtime, ids[0]), second(runtime, ids[1]), third(runtime, ids[2]);
    const auto count = [&](std::size_t expected) {
        if (args.size() != expected) bad("COMPONENT_ARGUMENT", "ComponentName argument count differs from signature");
    };
    if (name == "createRelative" &&
        (signature == "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/ComponentName;" ||
         signature == "(Landroid/content/Context;Ljava/lang/String;)Landroid/content/ComponentName;")) {
        count(2);
        const auto package = signature.starts_with("(Landroid/content/Context;") ? context_package(runtime, ids[0]) : ids[0];
        Root package_root(runtime, package);
        return Value::reference(relative(runtime, package, ids[1]));
    }
    if (name == "unflattenFromString" && signature == "(Ljava/lang/String;)Landroid/content/ComponentName;") {
        count(1);
        const auto text = std::u16string(runtime.string(ids[0]));
        if (text.size() > component_name_units * 2 + 1)
            bad("COMPONENT_LIMIT", "Flattened ComponentName exceeds its bounded representation");
        const auto slash = text.find(u'/');
        if (slash == text.npos || slash + 1 == text.size()) return Value::reference(0);
        const auto package = text.substr(0, slash);
        auto class_name = text.substr(slash + 1);
        if (class_name.front() == u'.') class_name.insert(0, package);
        return Value::reference(new_component(runtime, package, class_name));
    }
    if (name == "flattenToShortString" && signature == "(Landroid/content/ComponentName;)Ljava/lang/String;") {
        count(1);
        if (!ids[0]) return Value::reference(0);
        const auto [package, class_name] = component_parts(runtime, ids[0]);
        return Value::reference(runtime.new_string(package + u"/" + std::u16string(short_class(package, class_name))));
    }
    if (name == "<init>") {
        count(3);
        if (signature == "(Ljava/lang/String;Ljava/lang/String;)V") {
            initialize(runtime, ids[0], ids[1], ids[2], true);
        } else if (signature == "(Landroid/content/Context;Ljava/lang/String;)V") {
            if (!ids[2]) runtime.raise("Ljava/lang/NullPointerException;", u"class name is null");
            const auto package = context_package(runtime, ids[1]);
            Root package_root(runtime, package);
            initialize(runtime, ids[0], package, ids[2], false);
        } else if (signature == "(Landroid/content/Context;Ljava/lang/Class;)V") {
            const auto package = context_package(runtime, ids[1]);
            Root package_root(runtime, package);
            const auto class_name = class_string(runtime, ids[2]);
            Root class_root(runtime, class_name);
            initialize(runtime, ids[0], package, class_name, false);
        } else bad("API_UNSUPPORTED", "ComponentName constructor is outside the supported profile");
        return Value::nothing();
    }
    if (args.empty()) bad("COMPONENT_ARGUMENT", "ComponentName instance call requires a receiver");
    if (name == "compareTo" && signature == "(Ljava/lang/Object;)I") {
        count(2);
        // Java's Comparable bridge casts before entering typed compareTo;
        // a malformed package from a real Context override must not hide it.
        if (ids[1] && runtime.object_type(ids[1]) != component_type)
            runtime.raise("Ljava/lang/ClassCastException;");
    }
    const auto references = state(runtime, ids[0]).references;
    if (name == "getPackageName" && signature == "()Ljava/lang/String;") { count(1); return references[0]; }
    if (name == "getClassName" && signature == "()Ljava/lang/String;") { count(1); return references[1]; }
    if (name == "describeContents" && signature == "()I") { count(1); return Value::word(0); }
    if (name == "clone" && (signature == "()Landroid/content/ComponentName;" || signature == "()Ljava/lang/Object;")) {
        count(1);
        return Value::reference(from_references(runtime, references[0].bits, references[1].bits));
    }
    if (name == "equals" && signature == "(Ljava/lang/Object;)Z") {
        count(2);
        if (!ids[1] || runtime.object_type(ids[1]) != component_type) return Value::word(0);
        const auto other = state(runtime, ids[1]).references;
        // Preserve String.equals(null) and the package-first short circuit.
        const auto package = runtime.string(references[0].bits);
        if (!other[0].bits || package != runtime.string(other[0].bits)) return Value::word(0);
        const auto class_name = runtime.string(references[1].bits);
        return Value::word(other[1].bits && class_name == runtime.string(other[1].bits));
    }
    if (signature == "()Ljava/lang/String;" &&
        (name == "flattenToString" || name == "toShortString" || name == "toString")) {
        count(1);
        // A genuine guest Context override can return null. The Context
        // constructors retain that result; Java concatenation spells it null,
        // whereas short-name/hash/compare operations still dereference it.
        const auto package = references[0].bits ? std::u16string(runtime.string(references[0].bits)) : std::u16string(u"null");
        const auto class_name = std::u16string(runtime.string(references[1].bits));
        if (name == "flattenToString") return Value::reference(runtime.new_string(package + u"/" + class_name));
        if (name == "toShortString") return Value::reference(runtime.new_string(u"{" + package + u"/" + class_name + u"}"));
        return Value::reference(runtime.new_string(u"ComponentInfo{" + package + u"/" + class_name + u"}"));
    }
    const auto [package, class_name] = component_parts(runtime, ids[0]);
    if (name == "hashCode" && signature == "()I") {
        count(1); return Value::word(java_hash(package) + java_hash(class_name));
    }
    if (name == "compareTo" &&
        (signature == "(Landroid/content/ComponentName;)I" || signature == "(Ljava/lang/Object;)I")) {
        count(2);
        if (!ids[1]) runtime.raise("Ljava/lang/NullPointerException;");
        if (runtime.object_type(ids[1]) != component_type) runtime.raise("Ljava/lang/ClassCastException;");
        const auto [other_package, other_class] = component_parts(runtime, ids[1]);
        const auto package_order = java_compare(package, other_package);
        return Value::word(std::bit_cast<std::uint32_t>(package_order ? package_order : java_compare(class_name, other_class)));
    }
    if (signature == "()Ljava/lang/String;") {
        count(1);
        if (name == "getShortClassName") {
            const auto shortened = short_class(package, class_name);
            if (shortened.size() == class_name.size()) return references[1];
            return Value::reference(runtime.new_string(shortened));
        }
        if (name == "flattenToShortString")
            return Value::reference(runtime.new_string(package + u"/" + std::u16string(short_class(package, class_name))));
    }
    bad("API_UNSUPPORTED", "ComponentName operation is outside the supported value-object profile");
}
} // namespace aether::android
