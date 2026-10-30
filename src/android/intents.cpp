#include "intents.hpp"
#include "component_names.hpp"
#include "intent_categories.hpp"
#include "uris.hpp"
#include <algorithm>
#include <array>
#include <optional>
#include <vector>

namespace aether::android {
namespace {
using dex::ManagedRuntime;
using dex::ObjectId;
using dex::Value;
constexpr std::string_view string_type = "Ljava/lang/String;";
enum Slot : std::size_t { action, package_name, component, categories, data_uri, mime_type, identifier, slot_count };

[[noreturn]] void fail(std::string_view code, std::string message) {
    throw dex::DexError("AETHER_ANDROID_" + std::string(code), std::move(message));
}
ObjectId reference(Value value) {
    if (value.kind != dex::ValueKind::reference) fail("INTENT_ARGUMENT", "Intent requires reference arguments");
    return value.bits;
}
std::uint32_t word(Value value) {
    if (value.kind != dex::ValueKind::word) fail("INTENT_ARGUMENT", "Intent flags require an int");
    return static_cast<std::uint32_t>(value.bits);
}
struct Root {
    ManagedRuntime &runtime;
    ObjectId id;
    Root(ManagedRuntime &runtime, ObjectId id) : runtime(runtime), id(id) { runtime.retain(id); }
    ~Root() { runtime.release(id); }
    Root(const Root &) = delete;
    Root &operator=(const Root &) = delete;
};
class IntentState final : public dex::HostObjectState {
  public:
    std::array<Value, slot_count> references;
    std::uint32_t flags = 0;
    IntentState() { references.fill(Value::reference(0)); }
    ObjectId get(Slot slot) const noexcept { return references[slot].bits; }
    void set(Slot slot, ObjectId id) noexcept { references[slot] = Value::reference(id); }
    std::span<const Value> values() const noexcept override { return references; }
    std::size_t bytes() const noexcept override { return sizeof(*this); }
};
const IntentState &state(ManagedRuntime &runtime, ObjectId id) {
    if (!id) runtime.raise("Ljava/lang/NullPointerException;");
    const auto *current = dynamic_cast<const IntentState *>(runtime.host_state(id));
    if (!current) fail("INTENT_STATE", "Intent has no authenticated initialized value state");
    return *current;
}
struct Snapshot {
    IntentState value;
    Root action_root, package_root, component_root, categories_root, data_root, mime_root, identifier_root;
    Snapshot(ManagedRuntime &runtime, ObjectId id)
        : value(state(runtime, id)), action_root(runtime, value.get(action)),
          package_root(runtime, value.get(package_name)), component_root(runtime, value.get(component)),
          categories_root(runtime, value.get(categories)), data_root(runtime, value.get(data_uri)),
          mime_root(runtime, value.get(mime_type)), identifier_root(runtime, value.get(identifier)) {}
};
struct FieldPair {
    ObjectId left, right;
    Root left_root, right_root;
    FieldPair(ManagedRuntime &runtime, ObjectId a, ObjectId b, Slot slot)
        : left(state(runtime, a).get(slot)), right(state(runtime, b).get(slot)),
          left_root(runtime, left), right_root(runtime, right) {}
};
std::u16string text(ManagedRuntime &runtime, ObjectId id, bool nullable = false) {
    if (!id) {
        if (nullable) return {};
        runtime.raise("Ljava/lang/NullPointerException;");
    }
    const auto value = runtime.string(id);
    if (value.size() > intent_text_units) fail("INTENT_LIMIT", "Intent text exceeds 4096 UTF-16 units");
    return std::u16string(value);
}
ObjectId intern(ManagedRuntime &runtime, ObjectId id) {
    if (!id) return 0;
    (void)text(runtime, id);
    return reference(runtime.invoke_virtual_named(id, "intern", "()Ljava/lang/String;"));
}
Value category_call(ManagedRuntime &runtime, ObjectId set, std::string_view name,
                     std::string_view signature, std::span<const Value> tail = {}) {
    if (tail.size() > 1) fail("INTENT_STATE", "Unexpected internal category argument count");
    std::array<Value, 2> args{Value::reference(set), Value::reference(0)};
    if (!tail.empty()) args[1] = tail[0];
    return invoke_intent_categories(runtime, intent_categories_type, name, signature,
        std::span<const Value>(args.data(), tail.size() + 1));
}
ObjectId category_array(ManagedRuntime &runtime, ObjectId set) {
    if (runtime.object_type(set) != intent_categories_type)
        fail("INTENT_STATE", "Intent category set is not its actual owned ArraySet");
    return reference(category_call(runtime, set, "toArray", "()[Ljava/lang/Object;"));
}
void validate_category(ManagedRuntime &runtime, ObjectId id) {
    if (id && runtime.object_type(id) != string_type)
        fail("API_UNSUPPORTED", "Intent category set was mutated to contain a non-String value");
    if (id) (void)text(runtime, id);
}
std::vector<std::optional<std::u16string>> category_values(ManagedRuntime &runtime, ObjectId set) {
    if (!set) return {};
    const auto array = category_array(runtime, set);
    Root array_root(runtime, array);
    const auto count = runtime.array_length(array);
    std::vector<std::optional<std::u16string>> result;
    result.reserve(count);
    for (std::size_t n = 0; n < count; ++n) {
        const auto id = reference(runtime.array_get(array, static_cast<std::int32_t>(n)));
        validate_category(runtime, id);
        result.push_back(id ? std::optional{text(runtime, id)} : std::nullopt);
    }
    return result;
}
ObjectId copy_categories(ManagedRuntime &runtime, ObjectId set) {
    if (!set) return 0;
    return copy_intent_categories(runtime, set);
}
std::unique_ptr<IntentState> copy_state(ManagedRuntime &runtime, ObjectId source, bool filter) {
    Snapshot captured(runtime, source);
    auto next = std::make_unique<IntentState>(captured.value);
    if (filter) next->flags = 0;
    next->set(categories, copy_categories(runtime, captured.value.get(categories)));
    return next;
}
std::uint32_t hash(std::u16string_view value) noexcept {
    std::uint32_t result = 0;
    for (const auto unit : value) result = result * 31u + static_cast<std::uint16_t>(unit);
    return result;
}
bool equal_text(ManagedRuntime &runtime, ObjectId left, ObjectId right) {
    if (left == right) return true;
    if (!left || !right) return false;
    return text(runtime, left) == text(runtime, right);
}
ObjectId construct_component(ManagedRuntime &runtime, ObjectId first, ObjectId second,
                             std::string_view signature) {
    const auto result = runtime.new_object(component_type);
    Root result_root(runtime, result);
    const std::array args{Value::reference(result), Value::reference(first), Value::reference(second)};
    // Reuse genuine ComponentName construction, including original String
    // identities, Context callbacks and constructor-specific null ordering.
    (void)invoke_component(runtime, "<init>", signature, args);
    return result;
}
ObjectId allocate(ManagedRuntime &runtime, std::unique_ptr<IntentState> next) {
    // State references must survive allocation of the Intent object itself.
    const auto action_id = next->get(action), package_id = next->get(package_name);
    const auto component_id = next->get(component), categories_id = next->get(categories);
    Root action_root(runtime, action_id), package_root(runtime, package_id),
         component_root(runtime, component_id), categories_root(runtime, categories_id),
         data_root(runtime, next->get(data_uri)), mime_root(runtime, next->get(mime_type)),
         identifier_root(runtime, next->get(identifier));
    const auto result = runtime.new_object(intent_type);
    Root result_root(runtime, result);
    runtime.set_host_state(result, std::move(next));
    return result;
}
std::size_t argument_count(std::string_view name, std::string_view signature) {
    if (name == "<init>") {
        if (signature == "()V") return 0;
        if (signature == "(Landroid/content/Intent;)V" || signature == "(Ljava/lang/String;)V") return 1;
        if (signature == "(Landroid/content/Context;Ljava/lang/Class;)V") return 2;
        if (signature == "(Ljava/lang/String;Landroid/net/Uri;)V") return 2;
        if (signature == "(Ljava/lang/String;Landroid/net/Uri;Landroid/content/Context;Ljava/lang/Class;)V") return 4;
    }
    if ((name == "getAction" || name == "getPackage" || name == "getType" || name == "getIdentifier" ||
         name == "getDataString" || name == "getScheme") && signature == "()Ljava/lang/String;") return 0;
    if (name == "getData" && signature == "()Landroid/net/Uri;") return 0;
    if (name == "getComponent" && signature == "()Landroid/content/ComponentName;") return 0;
    if (name == "getCategories" && signature == "()Ljava/util/Set;") return 0;
    if ((name == "getFlags" || name == "filterHashCode") && signature == "()I") return 0;
    if (name == "clone" && signature == "()Ljava/lang/Object;") return 0;
    if (name == "cloneFilter" && signature == "()Landroid/content/Intent;") return 0;
    if ((name == "setAction" || name == "setPackage" || name == "addCategory" || name == "setType" || name == "setIdentifier") &&
        signature == "(Ljava/lang/String;)Landroid/content/Intent;") return 1;
    if (name == "setData" && signature == "(Landroid/net/Uri;)Landroid/content/Intent;") return 1;
    if (name == "setDataAndType" && signature == "(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/Intent;") return 2;
    if (name == "setComponent" && signature == "(Landroid/content/ComponentName;)Landroid/content/Intent;") return 1;
    if (name == "setClass" && signature == "(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;") return 2;
    if (name == "setClassName" && (signature == "(Landroid/content/Context;Ljava/lang/String;)Landroid/content/Intent;" ||
        signature == "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;")) return 2;
    if (name == "hasCategory" && signature == "(Ljava/lang/String;)Z") return 1;
    if (name == "removeCategory" && signature == "(Ljava/lang/String;)V") return 1;
    if ((name == "setFlags" || name == "addFlags") && signature == "(I)Landroid/content/Intent;") return 1;
    if (name == "removeFlags" && signature == "(I)V") return 1;
    if (name == "filterEquals" && signature == "(Landroid/content/Intent;)Z") return 1;
    fail("API_UNSUPPORTED", "Intent method is outside the implemented value-object profile");
}
} // namespace

ObjectId intent_component(ManagedRuntime &runtime, ObjectId intent) {
    Root root(runtime, intent);
    return state(runtime, intent).get(component);
}
apk::IntentValue capture_intent(ManagedRuntime &runtime, ObjectId intent) {
    Root intent_root(runtime, intent);
    Snapshot captured(runtime, intent);
    apk::IntentValue result;
    const auto read = [&](Slot slot) -> std::optional<std::u16string> {
        const auto id = captured.value.get(slot);
        if (!id) return {};
        if (runtime.object_type(id) != string_type)
            fail("INTENT_CAPTURE_UNSUPPORTED", "Intent text does not have its supported actual String representation");
        return text(runtime, id);
    };
    result.action = read(action);
    result.package = read(package_name);
    result.mime_type = read(mime_type);
    result.identifier = read(identifier);
    result.flags = captured.value.flags;
    if (const auto id = captured.value.get(data_uri)) {
        if (runtime.object_type(id) != string_uri_type)
            fail("INTENT_CAPTURE_UNSUPPORTED", "Intent capture supports only the authenticated StringUri representation");
        result.data = uri_text(runtime, id);
    }
    if (const auto id = captured.value.get(component)) {
        if (runtime.object_type(id) != component_type)
            fail("INTENT_CAPTURE_UNSUPPORTED", "Intent component is not the supported actual ComponentName representation");
        const std::array args{Value::reference(id)};
        // Direct final-class accessors authenticate stored references without
        // invoking a guest override or replacing null with an empty String.
        const auto package_id = reference(invoke_component(runtime, "getPackageName", "()Ljava/lang/String;", args));
        const auto class_id = reference(invoke_component(runtime, "getClassName", "()Ljava/lang/String;", args));
        if (!package_id || !class_id)
            fail("INTENT_CAPTURE_UNSUPPORTED", "Intent component capture requires nonnull package and class Strings");
        result.component = apk::IntentComponentValue{text(runtime, package_id), text(runtime, class_id)};
    }
    if (const auto set = captured.value.get(categories)) result.categories = category_values(runtime, set);
    result.resolved_mime_type = result.mime_type;
    if (!result.mime_type && result.data) {
        const uri::Parsed parsed(*result.data);
        if (const auto scheme = parsed.part(uri::Part::scheme);
            scheme && std::u16string_view(*result.data).substr(scheme->first, scheme->last - scheme->first) == u"content")
            result.mime_state = apk::IntentMimeState::unresolved;
    }
    result.validate();
    return result;
}
ObjectId materialize_intent(ManagedRuntime &runtime, const apk::IntentValue &value) {
    value.validate();
    auto next = std::make_unique<IntentState>();
    std::array<std::optional<Root>, slot_count> roots;
    const auto store = [&](Slot slot, ObjectId id) {
        roots[slot].emplace(runtime, id);
        next->set(slot, id);
    };
    const auto string = [&](Slot slot, const std::optional<std::u16string> &value, bool canonical = false) {
        if (!value) return;
        const auto id = runtime.new_string(*value);
        Root string_root(runtime, id);
        store(slot, canonical ? intern(runtime, id) : id);
    };
    string(action, value.action, true);
    string(package_name, value.package);
    // Query MIME provenance/default-only policy do not change actual mType or
    // manufacture a provider result in the delivered Android Intent.
    string(mime_type, value.mime_type);
    string(identifier, value.identifier);
    if (value.component) store(component, new_component(runtime, value.component->package, value.component->class_name));
    if (value.data) store(data_uri, new_uri(runtime, *value.data));
    if (value.categories) {
        const auto set = new_intent_categories(runtime);
        store(categories, set);
        for (const auto &category : *value.categories) {
            const auto id = category ? runtime.new_string(*category) : ObjectId{0};
            Root category_root(runtime, id);
            const auto canonical = category ? intern(runtime, id) : ObjectId{0};
            Root canonical_root(runtime, canonical);
            const std::array args{Value::reference(canonical)};
            (void)category_call(runtime, set, "add", "(Ljava/lang/Object;)Z", args);
        }
    }
    next->flags = value.flags;
    return allocate(runtime, std::move(next));
}
ObjectId make_launch_intent(ManagedRuntime &runtime, std::u16string_view package,
                            std::u16string_view class_name) {
    auto next = std::make_unique<IntentState>();
    const auto selected = new_component(runtime, package, class_name);
    Root component_root(runtime, selected);
    const auto main = runtime.new_string(u"android.intent.action.MAIN");
    Root main_root(runtime, main);
    const auto main_action = intern(runtime, main);
    Root action_root(runtime, main_action);
    const auto category = runtime.new_string(u"android.intent.category.LAUNCHER");
    Root category_root(runtime, category);
    const auto canonical_category = intern(runtime, category);
    Root canonical_root(runtime, canonical_category);
    const auto set = new_intent_categories(runtime);
    Root set_root(runtime, set);
    const std::array args{Value::reference(canonical_category)};
    (void)category_call(runtime, set, "add", "(Ljava/lang/Object;)Z", args);
    next->set(action, main_action);
    next->set(component, selected);
    next->set(categories, set);
    next->flags = 0x10000000u; // FLAG_ACTIVITY_NEW_TASK, metadata only here.
    return allocate(runtime, std::move(next));
}
Value intent_api(ManagedRuntime &runtime, std::string_view name, std::string_view signature,
                 std::span<const Value> args) {
    const auto count = argument_count(name, signature);
    if (args.size() != count + 1) fail("INTENT_ARGUMENT", "Intent argument count disagrees with its descriptor");
    // Named host entry points also use this helper. Keep every incoming
    // reference live before receiver-type resolution or any Context callback.
    std::array<std::optional<Root>, 5> input_roots;
    for (std::size_t n = 0; n < args.size(); ++n) {
        if (args[n].kind == dex::ValueKind::reference) input_roots[n].emplace(runtime, args[n].bits);
        else if (args[n].kind != dex::ValueKind::word)
            fail("INTENT_ARGUMENT", "Intent argument kind disagrees with its descriptor");
    }
    const auto receiver = reference(args[0]);
    Root receiver_root(runtime, receiver);
    if (!receiver) runtime.raise("Ljava/lang/NullPointerException;");
    if (!runtime.assignable(receiver, intent_type)) fail("INTENT_ARGUMENT", "Intent receiver has an incompatible type");
    if (name == "<init>") {
        if (runtime.host_state(receiver)) fail("INTENT_STATE", "Intent constructor invoked twice");
        auto next = std::make_unique<IntentState>();
        if (signature == "(Landroid/content/Intent;)V") {
            const auto source = reference(args[1]);
            Root source_root(runtime, source);
            next = copy_state(runtime, source, false);
            runtime.set_host_state(receiver, std::move(next));
            return Value::nothing();
        }
        runtime.set_host_state(receiver, std::move(next));
        if (signature.starts_with("(Ljava/lang/String;")) {
            const auto id = reference(args[1]);
            Root input_root(runtime, id);
            // Android's constructor calls the overridable setter. Publish the
            // real default fields before reentry and keep the override's state.
            const std::array call{Value::reference(id)};
            (void)runtime.invoke_virtual_named(receiver, "setAction", "(Ljava/lang/String;)Landroid/content/Intent;", call);
            if (count > 1) {
                const auto data = reference(args[2]);
                if (data && !runtime.assignable(data, uri_type))
                    fail("INTENT_ARGUMENT", "Intent constructor data is not a Uri");
                auto current = std::make_unique<IntentState>(state(runtime, receiver));
                // Constructor assignment does not clear a type set by an
                // actual overridden setAction callback.
                current->set(data_uri, data);
                runtime.set_host_state(receiver, std::move(current));
            }
        }
        if (signature == "(Landroid/content/Context;Ljava/lang/Class;)V" || count == 4) {
            const auto context = reference(args[count == 4 ? 3 : 1]), target = reference(args[count == 4 ? 4 : 2]);
            Root context_root(runtime, context), target_root(runtime, target);
            const auto selected = construct_component(runtime, context, target,
                "(Landroid/content/Context;Ljava/lang/Class;)V");
            Root component_root(runtime, selected);
            auto current = std::make_unique<IntentState>(state(runtime, receiver));
            current->set(component, selected);
            runtime.set_host_state(receiver, std::move(current));
        }
        return Value::nothing();
    }
    (void)state(runtime, receiver);
    if (name == "getAction") return Value::reference(state(runtime, receiver).get(action));
    if (name == "getPackage") return Value::reference(state(runtime, receiver).get(package_name));
    if (name == "getData") return Value::reference(state(runtime, receiver).get(data_uri));
    if (name == "getType") return Value::reference(state(runtime, receiver).get(mime_type));
    if (name == "getIdentifier") return Value::reference(state(runtime, receiver).get(identifier));
    if (name == "getDataString" || name == "getScheme") {
        const auto data = state(runtime, receiver).get(data_uri);
        Root data_root(runtime, data);
        if (!data) return Value::reference(0);
        return runtime.invoke_virtual_named(data, name == "getDataString" ? "toString" : "getScheme", "()Ljava/lang/String;");
    }
    if (name == "getComponent") return Value::reference(state(runtime, receiver).get(component));
    if (name == "getCategories") return Value::reference(state(runtime, receiver).get(categories));
    if (name == "getFlags") return Value::word(state(runtime, receiver).flags);
    if (name == "clone" || name == "cloneFilter")
        return Value::reference(allocate(runtime, copy_state(runtime, receiver, name == "cloneFilter")));
    if (name == "setFlags" || name == "addFlags" || name == "removeFlags") {
        const auto bits = word(args[1]);
        auto next = std::make_unique<IntentState>(state(runtime, receiver));
        if (name == "setFlags") next->flags = bits;
        else if (name == "addFlags") next->flags |= bits;
        else next->flags &= ~bits;
        runtime.set_host_state(receiver, std::move(next));
        return name == "removeFlags" ? Value::nothing() : Value::reference(receiver);
    }
    if (name == "setData" || name == "setType" || name == "setDataAndType" || name == "setIdentifier") {
        const auto first = reference(args[1]);
        if (name == "setData" || name == "setDataAndType") {
            if (first && !runtime.assignable(first, uri_type)) fail("INTENT_ARGUMENT", "Intent data is not a Uri");
        } else if (first) (void)text(runtime, first);
        const auto type = name == "setDataAndType" ? reference(args[2]) : ObjectId{0};
        if (type) (void)text(runtime, type);
        auto next = std::make_unique<IntentState>(state(runtime, receiver));
        if (name == "setIdentifier") next->set(identifier, first);
        else {
            next->set(data_uri, name == "setType" ? 0 : first);
            next->set(mime_type, name == "setDataAndType" ? type : name == "setType" ? first : 0);
        }
        runtime.set_host_state(receiver, std::move(next));
        return Value::reference(receiver);
    }
    if (name == "setAction" || name == "setPackage" || name == "setComponent") {
        auto id = reference(args[1]);
        Root input_root(runtime, id);
        if (name == "setComponent") {
            if (id) {
                const std::array call{Value::reference(id)};
                (void)invoke_component(runtime, "getClassName", "()Ljava/lang/String;", call);
            }
        }
        else if (name == "setAction") id = intern(runtime, id);
        else if (id) (void)text(runtime, id);
        Root value_root(runtime, id);
        auto next = std::make_unique<IntentState>(state(runtime, receiver));
        next->set(name == "setAction" ? action : name == "setPackage" ? package_name : component, id);
        runtime.set_host_state(receiver, std::move(next));
        return Value::reference(receiver);
    }
    if (name == "setClass" || name == "setClassName") {
        const auto first = reference(args[1]), second = reference(args[2]);
        Root first_root(runtime, first), second_root(runtime, second);
        const auto constructor_signature = signature.starts_with("(Ljava/lang/String;") ?
            "(Ljava/lang/String;Ljava/lang/String;)V" : name == "setClass" ?
            "(Landroid/content/Context;Ljava/lang/Class;)V" :
            "(Landroid/content/Context;Ljava/lang/String;)V";
        const auto id = construct_component(runtime, first, second, constructor_signature);
        Root component_root(runtime, id);
        // A Context callback may have changed other fields. Replace only the
        // component on the then-current receiver after the callback returns.
        auto next = std::make_unique<IntentState>(state(runtime, receiver));
        next->set(component, id);
        runtime.set_host_state(receiver, std::move(next));
        return Value::reference(receiver);
    }
    if (name == "addCategory" || name == "removeCategory" || name == "hasCategory") {
        const auto input = reference(args[1]);
        Root input_root(runtime, input);
        const auto set = state(runtime, receiver).get(categories);
        Root set_root(runtime, set);
        const auto values = category_values(runtime, set);
        if (name == "hasCategory") {
            const auto requested = input ? std::optional{text(runtime, input)} : std::nullopt;
            return Value::word(std::find(values.begin(), values.end(), requested) != values.end());
        }
        if (name == "removeCategory" && !set) return Value::nothing();
        const auto active_set = set ? set : new_intent_categories(runtime);
        Root active_root(runtime, active_set);
        if (!set) {
            auto next = std::make_unique<IntentState>(state(runtime, receiver));
            next->set(categories, active_set);
            runtime.set_host_state(receiver, std::move(next));
        }
        // Android assigns its first empty set before calling category.intern().
        // Therefore addCategory(null) leaves that real empty set and throws.
        if (name == "addCategory" && !input) runtime.raise("Ljava/lang/NullPointerException;");
        if (input) (void)text(runtime, input);
        const auto category = name == "addCategory" ? intern(runtime, input) : input;
        Root category_root(runtime, category);
        const std::array call{Value::reference(category)};
        (void)category_call(runtime, active_set, name == "addCategory" ? "add" : "remove", "(Ljava/lang/Object;)Z", call);
        if (name == "removeCategory" && word(category_call(runtime, active_set, "isEmpty", "()Z"))) {
            auto next = std::make_unique<IntentState>(state(runtime, receiver));
            next->set(categories, 0);
            runtime.set_host_state(receiver, std::move(next));
        }
        return name == "removeCategory" ? Value::nothing() : Value::reference(receiver);
    }
    if (name == "filterEquals") {
        const auto other = reference(args[1]);
        Root other_root(runtime, other);
        if (!other) return Value::word(0);
        (void)state(runtime, other);
        // URI equality is an actual virtual call. Re-read each later field
        // after it returns, matching Java's sequential field comparisons.
        for (const auto slot : {action, data_uri, mime_type, identifier, package_name, component, categories}) {
            FieldPair pair(runtime, receiver, other, slot);
            if (pair.left == pair.right) continue;
            if (!pair.left || !pair.right) return Value::word(0);
            if (slot == data_uri || slot == component) {
                const std::array call{Value::reference(pair.right)};
                if (!word(runtime.invoke_virtual_named(pair.left, "equals", "(Ljava/lang/Object;)Z", call)))
                    return Value::word(0);
            } else if (slot == categories) {
                auto left_values = category_values(runtime, pair.left), right_values = category_values(runtime, pair.right);
                std::sort(left_values.begin(), left_values.end());
                std::sort(right_values.begin(), right_values.end());
                if (left_values != right_values) return Value::word(0);
            } else if (!equal_text(runtime, pair.left, pair.right)) return Value::word(0);
        }
        return Value::word(1);
    }
    if (name == "filterHashCode") {
        std::uint32_t result = 0;
        for (const auto slot : {action, data_uri, mime_type, identifier, package_name, component, categories}) {
            const auto id = state(runtime, receiver).get(slot);
            Root field_root(runtime, id);
            if (!id) continue;
            if (slot == data_uri || slot == component) {
                result += word(runtime.invoke_virtual_named(id, "hashCode", "()I"));
            } else if (slot == categories) {
                for (const auto &category : category_values(runtime, id))
                    if (category) result += hash(*category);
            } else result += hash(text(runtime, id));
        }
        return Value::word(result);
    }
    fail("API_UNSUPPORTED", "Intent method is outside the implemented value-object profile");
}
} // namespace aether::android
