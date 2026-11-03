#include "aether/android/xml_view_constructor.hpp"
#include <array>

namespace aether::android {
namespace {
class ConstructorRoot final {
    dex::ManagedRuntime &runtime_;
    dex::ObjectId object_;
  public:
    ConstructorRoot(dex::ManagedRuntime &runtime, dex::ObjectId object)
        : runtime_(runtime), object_(object) {
        runtime_.retain(object_);
    }
    ~ConstructorRoot() { runtime_.release(object_); }
    ConstructorRoot(const ConstructorRoot &) = delete;
    ConstructorRoot &operator=(const ConstructorRoot &) = delete;
};

bool constructor_text_equal(dex::ManagedRuntime &runtime,
                            std::string_view actual, std::string_view expected) {
    runtime.charge_provider_work(1);
    if (actual.size() != expected.size()) return false;
    for (std::size_t index = 0; index < actual.size(); ++index) {
        runtime.charge_provider_work(1);
        if (actual[index] != expected[index]) return false;
    }
    return true;
}
} // namespace

dex::ObjectId lookup_owned_xml_constructor(dex::ManagedRuntime &runtime,
                                          std::string_view descriptor,
                                          dex::ObjectId selected_loader) {
    ConstructorRoot loader_root(runtime, selected_loader);
    if (!selected_loader || selected_loader != runtime.class_loader())
        runtime.raise("Ljava/lang/UnsupportedOperationException;",
                      u"XML view loader is outside this runtime's closed class space");

    const auto *definition = runtime.class_definition(descriptor);
    if (!definition)
        runtime.raise("Ljava/lang/UnsupportedOperationException;",
                      u"XML custom view requires an original owned class declaration");
    const auto &image = runtime.image();
    // The input may be borrowed from a parser that original class initialization
    // can close or replace. Canonical type storage survives demand loading and
    // guest callbacks; never carry the borrowed XML name into initialization.
    const auto &owned_descriptor = image.types.at(definition->type);
    if (!runtime.class_assignable(owned_descriptor, "Landroid/view/View;"))
        runtime.raise("Ljava/lang/ClassCastException;", u"XML class does not extend View");

    dex::Index constructor = dex::no_index;
    for (const auto index : definition->direct_methods) {
        runtime.charge_provider_work(1);
        const auto &method = image.methods.at(index);
        if (method.owner != definition->type || !method.declared || !method.direct ||
            !constructor_text_equal(runtime, method.name, "<init>"))
            continue;
        if (!constructor_text_equal(runtime, image.prototypes.at(method.prototype).descriptor,
                                    "(Landroid/content/Context;Landroid/util/AttributeSet;)V"))
            continue;
        if (!(method.flags & 1u) || !(method.flags & 0x10000u) ||
            (method.flags & (8u | 0x100u | 0x400u)))
            runtime.raise("Ljava/lang/NoSuchMethodException;",
                          u"XML view requires its public declared Context/AttributeSet constructor");
        constructor = index;
        break;
    }
    if (constructor == dex::no_index)
        runtime.raise("Ljava/lang/NoSuchMethodException;",
                      u"XML view has no public declared Context/AttributeSet constructor");
    // Use the existing authenticated core reflection path, as the SDK inflater
    // does. Only exceptions from the real constructor BODY acquire an
    // InvocationTargetException; clinit/allocation/argument failures keep their
    // original identity. The selected constructor is an actual owned DEX ID.
    const auto reflected = runtime.new_reflected_method(constructor);
    ConstructorRoot reflected_root(runtime, reflected);
    const std::array accessible{dex::Value::word(1)};
    (void)runtime.invoke_virtual_named(reflected, "setAccessible", "(Z)V", accessible);
    return reflected;
}

dex::ObjectId invoke_owned_xml_constructor(dex::ManagedRuntime &runtime,
                                          dex::ObjectId constructor,
                                          dex::ObjectId arguments) {
    ConstructorRoot constructor_root(runtime, constructor), arguments_root(runtime, arguments);
    if (!constructor || !arguments)
        runtime.raise("Ljava/lang/NullPointerException;", u"XML constructor and its actual argument array must be nonnull");
    if (runtime.object_type(constructor) != "Ljava/lang/reflect/Constructor;")
        runtime.raise("Ljava/lang/ClassCastException;", u"XML constructor cache contains a non-Constructor");
    if (runtime.object_type(arguments) != "[Ljava/lang/Object;" || runtime.array_length(arguments) != 2)
        runtime.raise("Ljava/lang/IllegalArgumentException;", u"XML constructor requires its actual two-slot Object array");
    // Authenticate a cached token against its actual owned declaration without
    // repeating class-loader callbacks, discovery or accessibility mutation.
    const auto index = runtime.reflected_method_index(constructor);
    const auto &image = runtime.image();
    const auto &method = image.methods.at(index);
    runtime.charge_provider_work(1);
    if (!(method.flags & 1u) || !(method.flags & 0x10000u) || !method.direct ||
        !constructor_text_equal(runtime, method.name, "<init>") ||
        !constructor_text_equal(runtime, image.prototypes.at(method.prototype).descriptor,
                                "(Landroid/content/Context;Landroid/util/AttributeSet;)V") ||
        !runtime.class_assignable(image.types.at(method.owner), "Landroid/view/View;"))
        runtime.raise("Ljava/lang/IllegalArgumentException;", u"Cached constructor is not a public owned XML View constructor");
    // Do not snapshot these cells: the real constructor's class initializer
    // can reenter the inflater and mutate its shared argument array. Existing
    // core reflection reads that live array after initialization, as the SDK does.
    const std::array invocation{dex::Value::reference(arguments)};
    const auto result = runtime.invoke_virtual_named(constructor, "newInstance",
        "([Ljava/lang/Object;)Ljava/lang/Object;", invocation);
    if (result.kind != dex::ValueKind::reference || !result.bits)
        runtime.raise("Ljava/lang/ClassCastException;", u"XML constructor did not return its actual View instance");
    ConstructorRoot result_root(runtime, result.bits);
    if (!runtime.assignable(result.bits, "Landroid/view/View;"))
        runtime.raise("Ljava/lang/ClassCastException;", u"XML constructor did not return its actual View instance");
    return result.bits;
}

dex::ObjectId invoke_owned_xml_constructor(dex::ManagedRuntime &runtime,
                                          dex::ObjectId constructor,
                                          dex::ObjectId context,
                                          dex::ObjectId attributes) {
    ConstructorRoot constructor_root(runtime, constructor), context_root(runtime, context),
        attributes_root(runtime, attributes);
    if (!context)
        runtime.raise("Ljava/lang/NullPointerException;", u"XML constructor Context must be nonnull");
    if (!runtime.assignable(context, "Landroid/content/Context;") ||
        !runtime.assignable(attributes, "Landroid/util/AttributeSet;"))
        runtime.raise("Ljava/lang/IllegalArgumentException;", u"XML constructor arguments have incompatible types");
    const auto arguments = runtime.new_array("[Ljava/lang/Object;", 2);
    ConstructorRoot arguments_root(runtime, arguments);
    runtime.array_set(arguments, 0, dex::Value::reference(context));
    runtime.array_set(arguments, 1, dex::Value::reference(attributes));
    return invoke_owned_xml_constructor(runtime, constructor, arguments);
}

dex::ObjectId construct_owned_xml_view(dex::ManagedRuntime &runtime,
                                     std::string_view descriptor,
                                     dex::ObjectId context,
                                     dex::ObjectId attributes,
                                     dex::ObjectId selected_loader) {
    ConstructorRoot context_root(runtime, context), attributes_root(runtime, attributes),
        loader_root(runtime, selected_loader);
    if (!context)
        runtime.raise("Ljava/lang/NullPointerException;", u"XML view construction requires its actual Context");
    const auto constructor = lookup_owned_xml_constructor(runtime, descriptor, selected_loader);
    ConstructorRoot constructor_root(runtime, constructor);
    return invoke_owned_xml_constructor(runtime, constructor, context, attributes);
}
} // namespace aether::android
