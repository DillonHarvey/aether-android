#include "aether/dex/runtime.hpp"
#include "aether/dex/bytecode.hpp"
#include "aether/dex/source.hpp"
#include <algorithm>
#include <atomic>
#include <bit>
#include <cmath>
#include <limits>
#include <map>
#include <set>
#include <thread>
#include <utility>

namespace aether::dex {
namespace {
[[noreturn]] void fail(std::string_view kind, const std::string &message) {
    throw DexError("AETHER_DEX_" + std::string(kind), message);
}
std::uint32_t word(Value v) {
    if (v.kind != ValueKind::word)
        fail("VALUE_TYPE", "Expected a 32-bit register value");
    return static_cast<std::uint32_t>(v.bits);
}
std::uint64_t wide(Value v) {
    if (v.kind != ValueKind::wide)
        fail("VALUE_TYPE", "Expected a 64-bit register pair");
    return v.bits;
}
ObjectId reference(Value v) {
    if (v.kind == ValueKind::word && !v.bits)
        return 0; // DEX const/4 zero is also null.
    if (v.kind != ValueKind::reference)
        fail("VALUE_TYPE", "Expected an object reference");
    return v.bits;
}
Value default_value(std::string_view type) {
    if (reference_type(type))
        return Value::reference(0);
    if (type == "V")
        return Value::nothing();
    return type_words(type) == 2 ? Value::wide(0) : Value::word(0);
}
std::string_view core_super(std::string_view type) {
    if (type == "Ljava/lang/Object;")
        return {};
    if (type == "Ljava/lang/String;" || type == "Ljava/lang/StringBuilder;" ||
        type == "Ljava/lang/CharSequence;" || type == "Ljava/lang/Class;" || type == "Ljava/lang/System;" ||
        type == "Ljava/lang/Throwable;")
        return "Ljava/lang/Object;";
    if (type == "Ljava/lang/Exception;" || type == "Ljava/lang/Error;")
        return "Ljava/lang/Throwable;";
    if (type == "Ljava/lang/RuntimeException;")
        return "Ljava/lang/Exception;";
    if (type == "Ljava/lang/NullPointerException;" || type == "Ljava/lang/ArithmeticException;" ||
        type == "Ljava/lang/IndexOutOfBoundsException;" || type == "Ljava/lang/NegativeArraySizeException;" ||
        type == "Ljava/lang/ArrayStoreException;" || type == "Ljava/lang/ClassCastException;" ||
        type == "Ljava/lang/IllegalStateException;" || type == "Ljava/lang/IllegalArgumentException;" ||
        type == "Ljava/lang/SecurityException;" || type == "Ljava/lang/UnsupportedOperationException;")
        return "Ljava/lang/RuntimeException;";
    if (type == "Ljava/lang/ArrayIndexOutOfBoundsException;" ||
        type == "Ljava/lang/StringIndexOutOfBoundsException;")
        return "Ljava/lang/IndexOutOfBoundsException;";
    if (type == "Ljava/lang/ExceptionInInitializerError;" || type == "Ljava/lang/NoClassDefFoundError;" ||
        type == "Ljava/lang/NoSuchMethodError;")
        return "Ljava/lang/Error;";
    return {};
}
bool core_type(std::string_view type) { return type == "Ljava/lang/Object;" || !core_super(type).empty(); }
std::atomic<std::uint64_t> next_identity{1};
struct Object {
    std::string type, represented;
    std::u16string text;
    std::map<Index, Value> fields;
    std::vector<Value> elements;
    std::size_t bytes = 0;
    bool marked = false;
};
struct Frame {
    Index method = 0;
    std::uint32_t pc = 0;
    std::vector<Value> arguments, registers;
    Value result;
    ObjectId caught = 0;
    Value get(std::uint32_t r) const {
        if (r >= registers.size())
            fail("REGISTER", "Register outside frame");
        const auto v = registers[r];
        if (v.kind == ValueKind::empty || v.kind == ValueKind::wide_tail)
            fail("VALUE_TYPE", "Read from uninitialized register or high half");
        if (v.kind == ValueKind::wide &&
            (r + 1 >= registers.size() || registers[r + 1].kind != ValueKind::wide_tail))
            fail("VALUE_TYPE", "Broken wide register pair");
        return v;
    }
    void put(std::uint32_t r, Value v) {
        const auto width = v.kind == ValueKind::wide ? 2u : 1u;
        if (r >= registers.size() || width > registers.size() - r)
            fail("REGISTER", "Register write outside frame");
        const auto invalidate = [&](std::uint32_t at) {
            if (registers[at].kind == ValueKind::wide && at + 1 < registers.size())
                registers[at + 1] = {};
            if (registers[at].kind == ValueKind::wide_tail && at)
                registers[at - 1] = {};
            registers[at] = {};
        };
        invalidate(r);
        if (width == 2)
            invalidate(r + 1);
        registers[r] = v;
        if (width == 2)
            registers[r + 1] = {ValueKind::wide_tail, 0};
    }
};
} // namespace
struct ManagedRuntime::Impl {
    ManagedRuntime &runtime;
    DexImage image;
    std::unique_ptr<ClassLoader> loader;
    RuntimeLimits limits;
    RuntimeMetrics metrics;
    NativeInterface *native = nullptr;
    HostInterface *host = nullptr;
    std::thread::id owner = std::this_thread::get_id();
    std::map<ObjectId, Object> heap;
    std::map<ObjectId, std::size_t> pins;
    std::map<std::string, ObjectId, std::less<>> class_objects;
    std::map<Index, ObjectId> strings;
    std::map<std::string, unsigned, std::less<>> class_state;
    std::map<Index, Value> statics;
    std::map<Index, VerifiedCode> verified;
    std::vector<Frame *> frames;
    Value last_result;
    ObjectId last_exception = 0;
    std::uint64_t remaining = 0;
    std::size_t invocations = 0;
    Impl(ManagedRuntime &runtime, DexImage input, RuntimeLimits limits,
         std::shared_ptr<ClassSource> source = {})
        : runtime(runtime), image(std::move(input)), limits(limits) {
        if (!limits.instructions || limits.instructions > 10'000'000 || !limits.frames ||
            limits.frames > 128 || !limits.objects || limits.objects > 65536 || limits.heap_bytes < 1024 ||
            limits.heap_bytes > 64 * 1024 * 1024 || !limits.array_length || limits.array_length > 1'048'576)
            fail("LIMIT", "Invalid managed runtime limits");
        if (source)
            loader = std::make_unique<ClassLoader>(image, std::move(source));
        for (const auto &p : image.prototypes) {
            if (p.return_type >= image.types.size())
                fail("INDEX", "Invalid return type");
            for (auto t : p.parameters)
                if (t >= image.types.size())
                    fail("INDEX", "Invalid parameter type");
        }
        for (const auto &m : image.methods)
            if (m.owner >= image.types.size() || m.prototype >= image.prototypes.size())
                fail("INDEX", "Invalid method metadata");
        for (const auto &f : image.fields)
            if (f.owner >= image.types.size() || f.type >= image.types.size())
                fail("INDEX", "Invalid field metadata");
    }
    void check_thread(bool teardown = false) const {
        if (owner != std::this_thread::get_id())
            fail("THREAD", "Managed runtime belongs to another thread");
        // Failed loading blocks execution, but root release and interface
        // detachment must still work while framework/JNI owners unwind.
        if (loader && !teardown)
            loader->check();
    }
    const Class *resolve_class(std::string_view descriptor) const {
        check_thread();
        if (loader)
            return loader->definition(descriptor);
        return image.definition(descriptor);
    }
    const Object &object(ObjectId id) const {
        check_thread();
        if (!id)
            const_cast<ManagedRuntime &>(runtime).raise("Ljava/lang/NullPointerException;");
        const auto it = heap.find(id);
        if (it == heap.end())
            fail("REFERENCE", "Invalid, collected, or foreign managed reference");
        return it->second;
    }
    Object &object(ObjectId id) { return const_cast<Object &>(std::as_const(*this).object(id)); }
    void known(std::string_view type) const {
        std::size_t dimensions = 0;
        while (!type.empty() && type.front() == '[') {
            ++dimensions;
            type.remove_prefix(1);
        }
        if (dimensions > 255 || type.empty() || (dimensions && type == "V"))
            fail("CLASS_NOT_FOUND", "Invalid or excessively deep class/array descriptor");
        if (type.size() == 1 && std::string_view("VZBSCIJFD").find(type[0]) != std::string_view::npos)
            return;
        if (!core_type(type) && !resolve_class(type) && !(host && host->class_info(type)))
            fail("CLASS_UNSUPPORTED", "Class not implemented: " + std::string(type));
    }
    bool subtype(std::string_view from, std::string_view to) const {
        if (from == to)
            return true;
        if (from.empty() || to.empty())
            return false;
        if (from.front() == '[') {
            if (to == "Ljava/lang/Object;" || to == "Ljava/lang/Cloneable;" || to == "Ljava/io/Serializable;")
                return true;
            return to.front() == '[' && reference_type(from.substr(1)) && reference_type(to.substr(1)) &&
                   subtype(from.substr(1), to.substr(1));
        }
        std::vector<std::string_view> todo{from};
        std::set<std::string_view> seen;
        while (!todo.empty()) {
            const auto current = todo.back();
            todo.pop_back();
            if (current == to)
                return true;
            if (current.empty() || !seen.insert(current).second)
                continue;
            if (seen.size() > 65536)
                fail("CLASS_LIMIT", "Class hierarchy exceeds limit");
            if (const auto *definition = resolve_class(current)) {
                if (definition->superclass != no_index)
                    todo.push_back(image.types.at(definition->superclass));
                for (const auto type : definition->interfaces)
                    todo.push_back(image.types.at(type));
            } else if (host && host->class_info(current)) {
                const auto info = *host->class_info(current);
                todo.push_back(info.superclass);
                todo.insert(todo.end(), info.interfaces.begin(), info.interfaces.end());
            } else {
                todo.push_back(core_super(current));
                if (current == "Ljava/lang/String;" || current == "Ljava/lang/StringBuilder;")
                    todo.push_back("Ljava/lang/CharSequence;");
            }
        }
        return false;
    }
    Value typed(Value v, std::string_view type) const {
        if (reference_type(type)) {
            const auto id = reference(v);
            if (id && !subtype(object(id).type, type))
                fail("VALUE_TYPE", "Object is incompatible with " + std::string(type));
            return Value::reference(id);
        }
        if (type == "V") {
            if (v.kind != ValueKind::void_value)
                fail("VALUE_TYPE", "Expected void result");
            return v;
        }
        if (type_words(type) == 2)
            return Value::wide(wide(v));
        auto bits = word(v);
        if (type == "Z")
            bits &= 1;
        else if (type == "B")
            bits = static_cast<std::uint32_t>(
                static_cast<std::int32_t>(std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(bits))));
        else if (type == "S")
            bits = static_cast<std::uint32_t>(
                static_cast<std::int32_t>(std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(bits))));
        else if (type == "C")
            bits &= 0xffff;
        return Value::word(bits);
    }
    void mark(ObjectId id, std::vector<ObjectId> &todo) {
        if (!id)
            return;
        const auto it = heap.find(id);
        if (it == heap.end())
            fail("REFERENCE", "A root refers to a collected object");
        if (!it->second.marked) {
            it->second.marked = true;
            todo.push_back(id);
        }
    }
    void collect() {
        check_thread();
        ++metrics.collections;
        for (auto &[id, value] : heap) {
            (void)id;
            value.marked = false;
        }
        std::vector<ObjectId> todo;
        const auto value = [&](Value v) {
            if (v.kind == ValueKind::reference)
                mark(v.bits, todo);
        };
        for (const auto &[id, count] : pins) {
            (void)count;
            mark(id, todo);
        }
        for (const auto &[name, id] : class_objects) {
            (void)name;
            mark(id, todo);
        }
        for (const auto &[index, id] : strings) {
            (void)index;
            mark(id, todo);
        }
        for (const auto &[index, v] : statics) {
            (void)index;
            value(v);
        }
        value(last_result);
        mark(last_exception, todo);
        for (const auto *frame : frames) {
            for (auto v : frame->arguments)
                value(v);
            for (auto v : frame->registers)
                value(v);
            value(frame->result);
            mark(frame->caught, todo);
        }
        while (!todo.empty()) {
            const auto id = todo.back();
            todo.pop_back();
            const auto &o = heap.at(id);
            for (const auto &[field, v] : o.fields) {
                (void)field;
                value(v);
            }
            for (auto v : o.elements)
                value(v);
        }
        for (auto it = heap.begin(); it != heap.end();) {
            if (!it->second.marked) {
                metrics.heap_bytes -= it->second.bytes;
                ++metrics.reclaimed;
                it = heap.erase(it);
            } else
                ++it;
        }
        metrics.live_objects = heap.size();
    }
    ObjectId allocate(Object value) {
        check_thread();
        value.bytes = sizeof(Object) + value.type.size() + value.represented.size() + value.text.size() * 2 +
                      value.elements.size() * sizeof(Value) + value.fields.size() * (sizeof(Value) + 64);
        if (heap.size() >= limits.objects || value.bytes > limits.heap_bytes - metrics.heap_bytes)
            collect();
        if (heap.size() >= limits.objects || value.bytes > limits.heap_bytes - metrics.heap_bytes)
            fail("HEAP_LIMIT", "Managed heap quota exhausted");
        const auto id = next_identity.fetch_add(1, std::memory_order_relaxed);
        if (!id || id == std::numeric_limits<ObjectId>::max())
            fail("IDENTITY_LIMIT", "Managed identity space exhausted");
        const auto bytes = value.bytes;
        heap.emplace(id, std::move(value));
        metrics.heap_bytes += bytes;
        ++metrics.allocations;
        metrics.live_objects = heap.size();
        return id;
    }
    ObjectId intern(Index index) {
        if (index >= image.strings.size())
            fail("INDEX", "Invalid string index");
        if (const auto it = strings.find(index); it != strings.end())
            return it->second;
        const auto id = runtime.new_string(image.strings[index]);
        strings.emplace(index, id);
        return id;
    }
    void initialize(std::string_view type) {
        check_thread();
        known(type);
        const auto *definition = resolve_class(type);
        if (!definition)
            return;
        auto &state = class_state[std::string(type)];
        if (state == 1 || state == 2)
            return;
        if (state == 3)
            runtime.raise("Ljava/lang/NoClassDefFoundError;");
        state = 1;
        try {
            for (const auto index : definition->static_fields)
                statics[index] = default_value(image.types.at(image.fields.at(index).type));
            for (std::size_t i = 0; i < definition->static_values.size(); ++i) {
                const auto index = definition->static_fields.at(i);
                const auto &entry = definition->static_values[i];
                const auto &field_type = image.types[image.fields[index].type];
                const auto exact_kind = [&](unsigned kind) {
                    if (entry.type != kind)
                        fail("STATIC_VALUE", "Encoded static value disagrees with declared field type");
                };
                Value v;
                if (reference_type(field_type)) {
                    if (entry.type == 0x1e)
                        v = Value::reference(0);
                    else if (entry.type == 0x17 && field_type == "Ljava/lang/String;")
                        v = Value::reference(intern(static_cast<Index>(entry.bits)));
                    else if (entry.type == 0x18 && field_type == "Ljava/lang/Class;")
                        v = Value::reference(
                            runtime.class_object(image.types.at(static_cast<Index>(entry.bits))));
                    else
                        fail("STATIC_VALUE", "Unsupported encoded reference initializer");
                } else {
                    const std::map<std::string_view, unsigned> kinds{{"B", 0},    {"S", 2},   {"C", 3},
                                                                     {"I", 4},    {"J", 6},   {"F", 0x10},
                                                                     {"D", 0x11}, {"Z", 0x1f}};
                    exact_kind(kinds.at(field_type));
                    v = type_words(field_type) == 2 ? Value::wide(entry.bits)
                                                    : Value::word(static_cast<std::uint32_t>(entry.bits));
                }
                statics[index] = typed(v, field_type);
            }
            if (!(definition->flags & 0x200)) {
                if (definition->superclass != no_index)
                    initialize(image.types.at(definition->superclass));
                // Class initialization visits superinterfaces in declaration
                // order, parents first, initializing only default declarers.
                // Initializing an interface itself does not initialize parents.
                std::set<Index> seen;
                std::vector<std::pair<Index, bool>> pending;
                const auto parents = [&](const Class &c) {
                    for (auto it = c.interfaces.rbegin(); it != c.interfaces.rend(); ++it)
                        pending.emplace_back(*it, false);
                };
                parents(*definition);
                std::size_t work = 0;
                while (!pending.empty()) {
                    if (++work > 262144)
                        fail("CLASS_LIMIT", "Default interface initialization exceeds its work budget");
                    const auto [index, visited] = pending.back();
                    pending.pop_back();
                    const auto *parent = resolve_class(image.types.at(index));
                    if (!parent)
                        continue;
                    if (!visited) {
                        if (!seen.insert(index).second)
                            continue;
                        pending.emplace_back(index, true);
                        parents(*parent);
                    } else {
                        for (const auto method : parent->virtual_methods) {
                            if (++work > 262144)
                                fail("CLASS_LIMIT",
                                     "Default interface initialization exceeds its work budget");
                            const auto &m = image.methods.at(method);
                            if (!(m.flags & (0x400 | 8)) && !m.direct && m.code) {
                                initialize(image.types.at(index));
                                break;
                            }
                        }
                    }
                }
            }
            for (const auto index : definition->direct_methods)
                if (image.methods.at(index).name == "<clinit>")
                    (void)runtime.invoke(index);
            state = 2;
        } catch (const JavaException &error) {
            state = 3;
            if (subtype(object(error.object).type, "Ljava/lang/Error;"))
                throw;
            runtime.raise("Ljava/lang/ExceptionInInitializerError;");
        } catch (...) {
            state = 3;
            throw;
        }
    }
    bool method_is_static(Index index) const {
        if (loader)
            loader->ensure(image.types.at(image.methods.at(index).owner));
        const auto &method = image.methods.at(index);
        if (method.declared)
            return bool(method.flags & 8);
        const auto &owner_type = image.types.at(method.owner);
        if (core_type(owner_type))
            return owner_type == "Ljava/lang/System;";
        if (owner_type.starts_with('[')) {
            if (method.name == "clone" &&
                image.prototypes.at(method.prototype).descriptor == "()Ljava/lang/Object;")
                return false;
            fail("API_UNSUPPORTED", owner_type + "." + method.name +
                                        image.prototypes.at(method.prototype).descriptor +
                                        " is not implemented");
        }
        if (host)
            return host->method_is_static(image, index);
        fail("API_UNSUPPORTED", owner_type + "." + method.name +
                                    image.prototypes.at(method.prototype).descriptor + " is not implemented");
    }
    bool is_interface(std::string_view type) const {
        if (const auto *definition = resolve_class(type))
            return bool(definition->flags & 0x200);
        if (host)
            if (const auto info = host->class_info(type))
                return info->is_interface;
        return type == "Ljava/lang/CharSequence;";
    }
    void replace_text(ObjectId id, std::u16string text) {
        if (text.size() > limits.array_length)
            fail("STRING_LIMIT", "Managed character sequence exceeds length limit");
        auto &value = object(id);
        const auto before = value.text.size() * 2, after = text.size() * 2;
        if (after > before && after - before > limits.heap_bytes - metrics.heap_bytes)
            fail("HEAP_LIMIT", "Managed character sequence exceeds heap limit");
        value.text = std::move(text);
        value.bytes = value.bytes - before + after;
        metrics.heap_bytes = metrics.heap_bytes - before + after;
    }
    Value core(Index index, std::span<const Value> args) {
        const auto &method = image.methods.at(index);
        const auto &type = image.types.at(method.owner);
        const auto &signature = image.prototypes.at(method.prototype).descriptor;
        ++metrics.core_calls;
        if (type.starts_with('[') && method.name == "clone" && signature == "()Ljava/lang/Object;") {
            // The invoke frame roots the source and all referenced elements
            // while allocate enforces the ordinary heap/object limits and may
            // collect. Preserve the concrete array type and shallow identity.
            const auto &source = object(reference(args[0]));
            Object copy;
            copy.type = source.type;
            copy.elements = source.elements;
            return Value::reference(allocate(std::move(copy)));
        }
        if (type == "Ljava/lang/Object;" && method.name == "<init>" && signature == "()V")
            return Value::nothing();
        if (core_type(type) && subtype(type, "Ljava/lang/Throwable;") && method.name == "<init>" &&
            signature == "()V") {
            replace_text(reference(args[0]), {});
            return Value::nothing();
        }
        if (type == "Ljava/lang/String;" || type == "Ljava/lang/CharSequence;" ||
            type == "Ljava/lang/StringBuilder;") {
            const auto id = reference(args[0]);
            const auto text = runtime.char_sequence(id);
            if (method.name == "length" && signature == "()I")
                return Value::word(static_cast<std::uint32_t>(text.size()));
            if (method.name == "charAt" && signature == "(I)C") {
                const auto at = std::bit_cast<std::int32_t>(word(args[1]));
                if (at < 0 || static_cast<std::size_t>(at) >= text.size())
                    runtime.raise("Ljava/lang/StringIndexOutOfBoundsException;");
                return Value::word(text[static_cast<std::size_t>(at)]);
            }
            if (method.name == "toString" && signature == "()Ljava/lang/String;")
                return Value::reference(object(id).type == "Ljava/lang/String;" ? id
                                                                                : runtime.new_string(text));
            if (type == "Ljava/lang/StringBuilder;") {
                if (method.name == "<init>" && signature == "()V") {
                    replace_text(id, {});
                    return Value::nothing();
                }
                if (method.name == "<init>" && signature == "(Ljava/lang/String;)V") {
                    replace_text(id, std::u16string(runtime.string(reference(args[1]))));
                    return Value::nothing();
                }
                if (method.name == "append") {
                    std::u16string appended;
                    if (signature == "(I)Ljava/lang/StringBuilder;") {
                        const auto decimal = std::to_string(std::bit_cast<std::int32_t>(word(args[1])));
                        appended.assign(decimal.begin(), decimal.end());
                    } else if (signature == "(Ljava/lang/String;)Ljava/lang/StringBuilder;" ||
                               signature == "(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;") {
                        const auto other = reference(args[1]);
                        appended = other ? runtime.char_sequence(other) : u"null";
                    } else
                        fail("API_UNSUPPORTED", type + "." + method.name + signature + " is not implemented");
                    if (appended.size() > limits.array_length - text.size())
                        fail("STRING_LIMIT", "StringBuilder append exceeds length limit");
                    replace_text(id, std::u16string(text) + appended);
                    return Value::reference(id);
                }
            }
        }
        if (type == "Ljava/lang/System;" && method.name == "loadLibrary" &&
            signature == "(Ljava/lang/String;)V") {
            if (!native)
                fail("NATIVE_UNAVAILABLE", "System.loadLibrary requires an attached native interface");
            native->load_library(runtime, runtime.string(reference(args[0])));
            return Value::nothing();
        }
        if (host && !core_type(type))
            return host->invoke(runtime, index, args);
        fail("API_UNSUPPORTED", type + "." + method.name + signature + " is not implemented");
    }
    std::optional<Index> default_target(Index index, std::vector<std::string_view> roots) const {
        const auto &method = image.methods.at(index);
        std::set<std::string_view> seen;
        std::vector<Index> candidates;
        std::size_t work = 0;
        const auto step = [&] {
            if (++work > 262144)
                fail("CLASS_LIMIT", "Interface method search exceeds its work budget");
        };
        while (!roots.empty()) {
            step();
            const auto type = roots.back();
            roots.pop_back();
            if (!seen.insert(type).second)
                continue;
            if (seen.size() > 65536)
                fail("CLASS_LIMIT", "Interface method search exceeds its class budget");
            const auto *definition = resolve_class(type);
            if (!definition)
                continue;
            if (definition->flags & 0x200) {
                for (const auto candidate : definition->virtual_methods) {
                    step();
                    const auto &m = image.methods.at(candidate);
                    if (m.name == method.name && image.prototypes.at(m.prototype).descriptor ==
                                                     image.prototypes.at(method.prototype).descriptor)
                        candidates.push_back(candidate);
                }
            } else if (definition->superclass != no_index)
                roots.push_back(image.types.at(definition->superclass));
            for (const auto parent : definition->interfaces)
                roots.push_back(image.types.at(parent));
        }
        // A declaration in a more specific interface suppresses its ancestor,
        // including an abstract redeclaration of an inherited default method.
        // Visit the union of their strict ancestors once, avoiding pairwise
        // subtype walks over an attacker-controlled interface graph.
        std::set<Index> ancestors;
        std::vector<Index> pending;
        for (const auto candidate : candidates) {
            const auto *declaring = resolve_class(image.types.at(image.methods.at(candidate).owner));
            pending.insert(pending.end(), declaring->interfaces.begin(), declaring->interfaces.end());
        }
        while (!pending.empty()) {
            step();
            const auto type = pending.back();
            pending.pop_back();
            if (!ancestors.insert(type).second)
                continue;
            if (const auto *declaring = resolve_class(image.types.at(type)))
                pending.insert(pending.end(), declaring->interfaces.begin(), declaring->interfaces.end());
        }
        std::optional<Index> selected;
        for (const auto candidate : candidates) {
            const auto &m = image.methods.at(candidate);
            if (!ancestors.contains(m.owner) && !(m.flags & (0x400 | 8)) && !m.direct && m.code) {
                if (selected)
                    fail("INVOKE_KIND", "Conflicting maximally specific interface default methods");
                selected = candidate;
            }
        }
        if (!selected && !candidates.empty())
            fail("METHOD_NOT_FOUND", "Interface method has no concrete maximally specific implementation");
        return selected;
    }
    Index virtual_target(Index index, ObjectId receiver) const {
        const auto &method = image.methods.at(index);
        auto type = std::string_view(object(receiver).type);
        if (method_is_static(index) || (method.declared && method.direct) ||
            !subtype(type, image.types.at(method.owner)))
            fail("INVOKE_KIND", "Virtual/interface call has an incompatible method or receiver");
        for (unsigned depth = 0; depth < 256; ++depth) {
            const auto *definition = resolve_class(type);
            if (!definition)
                break;
            for (const auto candidate : definition->virtual_methods) {
                const auto &m = image.methods.at(candidate);
                if (m.name == method.name && image.prototypes.at(m.prototype).descriptor ==
                                                 image.prototypes.at(method.prototype).descriptor)
                    return candidate;
            }
            if (definition->superclass == no_index)
                break;
            type = image.types.at(definition->superclass);
        }
        if (const auto target = default_target(index, {object(receiver).type}))
            return *target;
        return index;
    }
    Index super_target(Index caller, Index index, ObjectId receiver) const {
        const auto &method = image.methods.at(index);
        const auto &caller_type = image.types.at(image.methods.at(caller).owner);
        const auto *definition = resolve_class(caller_type);
        const auto &caller_code = image.methods.at(caller).code;
        const auto version =
            caller_code && caller_code->references ? caller_code->references->version : image.version;
        if (is_interface(image.types.at(method.owner))) {
            if (version < 37 || !definition || method_is_static(index) ||
                (method.declared && method.direct) || !subtype(object(receiver).type, caller_type))
                fail("INVOKE_KIND", "Interface invoke-super requires DEX 037 and a compatible receiver");
            // Interface.super is resolved from the named superinterface,
            // not from unrelated interfaces implemented by the receiver.
            if (!subtype(caller_type, image.types.at(method.owner)))
                fail("INVOKE_KIND", "Interface invoke-super target is not in the caller's hierarchy");
            if (const auto target = default_target(index, {image.types.at(method.owner)}))
                return *target;
            fail("METHOD_NOT_FOUND", "Interface invoke-super has no unambiguous concrete default");
        }
        if (!definition || definition->superclass == no_index || method_is_static(index) ||
            (method.declared && method.direct) || is_interface(image.types.at(method.owner)) ||
            !subtype(object(receiver).type, caller_type))
            fail("INVOKE_KIND", "invoke-super requires a superclass method and compatible receiver");
        auto type = std::string_view(image.types.at(definition->superclass));
        if (!subtype(type, image.types.at(method.owner)))
            fail("INVOKE_KIND", "invoke-super target is not in the caller's superclass hierarchy");
        for (unsigned depth = 0; depth < 256; ++depth) {
            definition = resolve_class(type);
            if (!definition)
                return index;
            for (const auto candidate : definition->virtual_methods) {
                const auto &m = image.methods.at(candidate);
                if (m.name == method.name && image.prototypes.at(m.prototype).descriptor ==
                                                 image.prototypes.at(method.prototype).descriptor)
                    return candidate;
            }
            if (definition->superclass == no_index)
                break;
            type = image.types.at(definition->superclass);
        }
        fail("METHOD_NOT_FOUND", "invoke-super could not resolve the superclass implementation");
    }
    Value binary(unsigned op, Value left, Value right) {
        if (op <= 0x9a) {
            const auto a = word(left), b = word(right);
            const auto sa = std::bit_cast<std::int32_t>(a), sb = std::bit_cast<std::int32_t>(b);
            std::uint32_t value = 0;
            switch (op) {
            case 0x90:
                value = a + b;
                break;
            case 0x91:
                value = a - b;
                break;
            case 0x92:
                value = a * b;
                break;
            case 0x93:
            case 0x94:
                if (!b)
                    runtime.raise("Ljava/lang/ArithmeticException;");
                if (sa == std::numeric_limits<std::int32_t>::min() && sb == -1)
                    value = op == 0x93 ? a : 0;
                else
                    value = static_cast<std::uint32_t>(op == 0x93 ? sa / sb : sa % sb);
                break;
            case 0x95:
                value = a & b;
                break;
            case 0x96:
                value = a | b;
                break;
            case 0x97:
                value = a ^ b;
                break;
            case 0x98:
                value = a << (b & 31);
                break;
            case 0x99:
                value = static_cast<std::uint32_t>(sa >> (b & 31));
                break;
            case 0x9a:
                value = a >> (b & 31);
                break;
            default:
                fail("OPCODE_UNSUPPORTED", "Invalid integer arithmetic opcode");
            }
            return Value::word(value);
        }
        if (op <= 0xa5) {
            const auto a = wide(left), b = op >= 0xa3 ? word(right) : wide(right);
            const auto sa = std::bit_cast<std::int64_t>(a), sb = std::bit_cast<std::int64_t>(b);
            std::uint64_t value = 0;
            switch (op) {
            case 0x9b:
                value = a + b;
                break;
            case 0x9c:
                value = a - b;
                break;
            case 0x9d:
                value = a * b;
                break;
            case 0x9e:
            case 0x9f:
                if (!b)
                    runtime.raise("Ljava/lang/ArithmeticException;");
                if (sa == std::numeric_limits<std::int64_t>::min() && sb == -1)
                    value = op == 0x9e ? a : 0;
                else
                    value = static_cast<std::uint64_t>(op == 0x9e ? sa / sb : sa % sb);
                break;
            case 0xa0:
                value = a & b;
                break;
            case 0xa1:
                value = a | b;
                break;
            case 0xa2:
                value = a ^ b;
                break;
            case 0xa3:
                value = a << (b & 63);
                break;
            case 0xa4:
                value = static_cast<std::uint64_t>(sa >> (b & 63));
                break;
            case 0xa5:
                value = a >> (b & 63);
                break;
            default:
                fail("OPCODE_UNSUPPORTED", "Invalid long arithmetic opcode");
            }
            return Value::wide(value);
        }
        if (op <= 0xaa) {
            const auto a = std::bit_cast<float>(word(left)), b = std::bit_cast<float>(word(right));
            float value = 0;
            switch (op) {
            case 0xa6:
                value = a + b;
                break;
            case 0xa7:
                value = a - b;
                break;
            case 0xa8:
                value = a * b;
                break;
            case 0xa9:
                value = a / b;
                break;
            case 0xaa:
                value = std::fmod(a, b);
                break;
            }
            return Value::word(std::bit_cast<std::uint32_t>(value));
        }
        const auto a = std::bit_cast<double>(wide(left)), b = std::bit_cast<double>(wide(right));
        double value = 0;
        switch (op) {
        case 0xab:
            value = a + b;
            break;
        case 0xac:
            value = a - b;
            break;
        case 0xad:
            value = a * b;
            break;
        case 0xae:
            value = a / b;
            break;
        case 0xaf:
            value = std::fmod(a, b);
            break;
        default:
            fail("OPCODE_UNSUPPORTED", "Invalid double arithmetic opcode");
        }
        return Value::wide(std::bit_cast<std::uint64_t>(value));
    }
    Value execute(Frame &frame, const VerifiedCode &code) {
        const auto &method = image.methods.at(frame.method);
        for (;;) {
            if (!remaining)
                fail("BUDGET", "Managed instruction budget exhausted");
            --remaining;
            ++metrics.instructions;
            if (frame.pc >= code.at.size() || code.at[frame.pc] == no_index)
                fail("CONTROL_FLOW", "Invalid instruction pointer");
            const auto &ins = code.instructions[code.at[frame.pc]];
            const auto op = ins.opcode;
            const auto get = [&](std::uint32_t r) { return frame.get(r); };
            const auto put = [&](Value v) { frame.put(ins.a, v); };
            auto next = ins.next;
            if (op < 0x0a || op > 0x0c)
                frame.result = {};
            if (op != 0x0d)
                frame.caught = 0;
            try {
                if (!op) { /* nop */
                } else if (op <= 9) {
                    const auto v = get(ins.b);
                    if (op <= 3)
                        put(Value::word(word(v)));
                    else if (op <= 6)
                        put(Value::wide(wide(v)));
                    else
                        put(Value::reference(reference(v)));
                } else if (op >= 0x0a && op <= 0x0c) {
                    if (frame.result.kind == ValueKind::empty)
                        fail("RESULT", "No result available for move-result");
                    put(frame.result);
                    frame.result = {};
                } else if (op == 0x0d) {
                    if (!frame.caught)
                        fail("EXCEPTION", "No caught exception at handler entry");
                    put(Value::reference(frame.caught));
                    frame.caught = 0;
                } else if (op >= 0x0e && op <= 0x11) {
                    return typed(op == 0x0e ? Value::nothing() : get(ins.a),
                                 image.types.at(image.prototypes.at(method.prototype).return_type));
                } else if (op <= 0x19) {
                    put(op >= 0x16 ? Value::wide(ins.literal)
                                   : Value::word(static_cast<std::uint32_t>(ins.literal)));
                } else if (op == 0x1a || op == 0x1b)
                    put(Value::reference(intern(ins.index)));
                else if (op == 0x1c)
                    put(Value::reference(runtime.class_object(image.types.at(ins.index))));
                else if (op == 0x1f) {
                    const auto id = reference(get(ins.a));
                    if (!runtime.assignable(id, image.types.at(ins.index)))
                        runtime.raise("Ljava/lang/ClassCastException;");
                    put(Value::reference(id));
                } else if (op == 0x20) {
                    const auto id = reference(get(ins.b));
                    put(Value::word(id && runtime.assignable(id, image.types.at(ins.index))));
                } else if (op == 0x21)
                    put(Value::word(static_cast<std::uint32_t>(runtime.array_length(reference(get(ins.b))))));
                else if (op == 0x22)
                    put(Value::reference(runtime.new_object(image.types.at(ins.index))));
                else if (op == 0x23)
                    put(Value::reference(runtime.new_array(image.types.at(ins.index),
                                                           std::bit_cast<std::int32_t>(word(get(ins.b))))));
                else if (op == 0x24 || op == 0x25) {
                    const auto id = runtime.new_array(image.types.at(ins.index),
                                                      static_cast<std::int32_t>(ins.arguments.size()));
                    frame.result = Value::reference(id);
                    for (std::size_t n = 0; n < ins.arguments.size(); ++n)
                        runtime.array_set(id, static_cast<std::int32_t>(n), get(ins.arguments[n]));
                } else if (op == 0x27) {
                    const auto id = reference(get(ins.a));
                    if (!id)
                        runtime.raise("Ljava/lang/NullPointerException;");
                    if (!runtime.assignable(id, "Ljava/lang/Throwable;"))
                        fail("VALUE_TYPE", "throw operand is not a Throwable");
                    ++metrics.exceptions;
                    throw JavaException(id);
                } else if (op >= 0x28 && op <= 0x2a)
                    next = static_cast<std::uint32_t>(std::int64_t(ins.pc) + ins.branch);
                else if (op == 0x2b) {
                    const auto key = std::bit_cast<std::int32_t>(word(get(ins.a)));
                    const auto at = std::int64_t(key) - ins.switch_first;
                    if (at >= 0 && static_cast<std::uint64_t>(at) < ins.switch_targets.size())
                        next = ins.switch_targets[static_cast<std::size_t>(at)];
                } else if (op >= 0x2d && op <= 0x31) {
                    std::int32_t compare = 0;
                    if (op == 0x31) {
                        const auto a = std::bit_cast<std::int64_t>(wide(get(ins.b))),
                                   b = std::bit_cast<std::int64_t>(wide(get(ins.c)));
                        compare = a < b ? -1 : (a == b ? 0 : 1);
                    } else {
                        const auto a = op < 0x2f ? double(std::bit_cast<float>(word(get(ins.b))))
                                                 : std::bit_cast<double>(wide(get(ins.b)));
                        const auto b = op < 0x2f ? double(std::bit_cast<float>(word(get(ins.c))))
                                                 : std::bit_cast<double>(wide(get(ins.c)));
                        compare = std::isnan(a) || std::isnan(b) ? ((op == 0x2d || op == 0x2f) ? -1 : 1)
                                                                 : (a < b ? -1 : (a == b ? 0 : 1));
                    }
                    put(Value::word(static_cast<std::uint32_t>(compare)));
                } else if (op >= 0x32 && op <= 0x3d) {
                    const auto a = get(ins.a), b = op < 0x38 ? get(ins.b) : Value::word(0);
                    const auto cond = (op - 0x32) % 6;
                    bool yes = false;
                    if (cond <= 1 && (a.kind == ValueKind::reference || b.kind == ValueKind::reference)) {
                        const auto equal = reference(a) == reference(b);
                        yes = cond == 0 ? equal : !equal;
                    } else {
                        const auto left = std::bit_cast<std::int32_t>(word(a)),
                                   right = std::bit_cast<std::int32_t>(word(b));
                        switch (cond) {
                        case 0:
                            yes = left == right;
                            break;
                        case 1:
                            yes = left != right;
                            break;
                        case 2:
                            yes = left < right;
                            break;
                        case 3:
                            yes = left >= right;
                            break;
                        case 4:
                            yes = left > right;
                            break;
                        case 5:
                            yes = left <= right;
                            break;
                        }
                    }
                    if (yes)
                        next = static_cast<std::uint32_t>(std::int64_t(ins.pc) + ins.branch);
                } else if (op >= 0x44 && op <= 0x51) {
                    const auto id = reference(get(ins.b));
                    const auto at = std::bit_cast<std::int32_t>(word(get(ins.c)));
                    const auto &type = object(id).type;
                    if (type.front() != '[')
                        fail("VALUE_TYPE", "Array opcode requires array object");
                    const auto element = std::string_view(type).substr(1);
                    const auto category = unsigned(op - 0x44) % 7;
                    const auto expected = reference_type(element) ? 2u : (type_words(element) == 2 ? 1u : 0u);
                    if ((category == 0 && element != "I" && element != "F") ||
                        (category < 3 && category != expected) || (category == 3 && element != "Z") ||
                        (category == 4 && element != "B") || (category == 5 && element != "C") ||
                        (category == 6 && element != "S"))
                        fail("VALUE_TYPE", "Array opcode disagrees with component type");
                    if (op < 0x4b)
                        put(runtime.array_get(id, at));
                    else
                        runtime.array_set(id, at, get(ins.a));
                } else if (op >= 0x52 && op <= 0x6d) {
                    const auto &field = image.fields.at(ins.index);
                    if (loader)
                        loader->ensure(image.types.at(field.owner));
                    if (!field.declared)
                        fail("FIELD_UNSUPPORTED", "External field is not implemented: " + field.name);
                    const auto &type = image.types.at(field.type);
                    if (op >= 0x60) {
                        if (op < 0x67)
                            put(runtime.get_static(ins.index));
                        else
                            runtime.set_static(ins.index, get(ins.a));
                    } else {
                        auto &instance = object(reference(get(ins.b)));
                        const auto it = instance.fields.find(ins.index);
                        if (it == instance.fields.end())
                            fail("FIELD", "Field does not belong to this object");
                        if (op < 0x59)
                            put(it->second);
                        else
                            it->second = typed(get(ins.a), type);
                    }
                } else if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
                    const auto stat = op == 0x71 || op == 0x77;
                    const auto &target = image.methods.at(ins.index);
                    const auto &proto = image.prototypes.at(target.prototype);
                    std::vector<Value> args;
                    std::size_t at = 0;
                    if (!stat)
                        args.push_back(Value::reference(reference(get(ins.arguments[at++]))));
                    for (const auto type : proto.parameters) {
                        args.push_back(typed(get(ins.arguments[at]), image.types.at(type)));
                        at += type_words(image.types[type]);
                    }
                    if (method_is_static(ins.index) != stat)
                        fail("INVOKE_KIND", "Invoke opcode disagrees with method staticness");
                    const bool interface_call = op == 0x72 || op == 0x78;
                    const bool virtual_call = op == 0x6e || op == 0x74;
                    if ((interface_call || virtual_call) &&
                        interface_call != is_interface(image.types.at(target.owner)))
                        fail("INVOKE_KIND", "Invoke opcode disagrees with class/interface method owner");
                    if ((op == 0x70 || op == 0x76) && target.declared && !target.direct)
                        fail("INVOKE_KIND", "invoke-direct requires a direct method");
                    auto dispatch = ins.index;
                    if (op == 0x6e || op == 0x74 || op == 0x72 || op == 0x78)
                        dispatch = virtual_target(ins.index, reference(args[0]));
                    else if (op == 0x6f || op == 0x75)
                        dispatch = super_target(frame.method, ins.index, reference(args[0]));
                    frame.result = runtime.invoke(dispatch, args);
                } else if (op >= 0x90 && op <= 0xcf) {
                    const auto binary_op = op >= 0xb0 ? op - 0x20u : op;
                    put(binary(binary_op, get(op >= 0xb0 ? ins.a : ins.b), get(op >= 0xb0 ? ins.b : ins.c)));
                } else if (op >= 0xd0 && op <= 0xe2) {
                    const auto operation = op < 0xd8 ? op - 0xd0 : op - 0xd8;
                    const auto literal = Value::word(static_cast<std::uint32_t>(ins.literal));
                    put(operation == 1 ? binary(0x91, literal, get(ins.b))
                                       : binary(0x90 + operation, get(ins.b), literal));
                } else
                    fail("OPCODE_UNSUPPORTED", "Missing opcode executor");
            } catch (const JavaException &error) {
                bool handled = false;
                for (const auto &block : method.code->tries) {
                    if (ins.pc < block.start || ins.pc - block.start >= block.count)
                        continue;
                    for (const auto &handler : block.handlers) {
                        if (handler.type == no_index ||
                            runtime.assignable(error.object, image.types.at(handler.type))) {
                            frame.caught = error.object;
                            frame.result = {};
                            next = handler.target;
                            handled = true;
                            break;
                        }
                    }
                    break;
                }
                if (!handled)
                    throw;
            } catch (const DexError &error) {
                throw DexError(error.code, image.types.at(method.owner) + "." + method.name +
                                               " pc=" + std::to_string(ins.pc) + ": " + error.what());
            }
            frame.pc = next;
        }
    }
    Value invoke(Index index, std::span<const Value> arguments) {
        check_thread();
        if (index >= image.methods.size())
            fail("METHOD_NOT_FOUND", "Method index outside DEX table");
        if (frames.size() >= limits.frames)
            fail("CALL_DEPTH", "Managed call depth exceeded");
        const auto &method = image.methods[index];
        const auto &prototype = image.prototypes[method.prototype];
        const auto &type = image.types[method.owner];
        const bool stat = method_is_static(index);
        if (arguments.size() != prototype.parameters.size() + (stat ? 0 : 1))
            fail("SIGNATURE", "Wrong argument count for " + type + "." + method.name + prototype.descriptor);
        Frame frame;
        frame.method = index;
        std::size_t at = 0;
        if (!stat) {
            const auto receiver = reference(arguments[at++]);
            (void)object(receiver);
            frame.arguments.push_back(typed(Value::reference(receiver), type));
        }
        for (const auto parameter : prototype.parameters)
            frame.arguments.push_back(typed(arguments[at++], image.types[parameter]));
        frames.push_back(&frame);
        struct Pop {
            Impl &impl;
            ~Pop() { impl.frames.pop_back(); }
        } pop{*this};
        metrics.maximum_frames = std::max(metrics.maximum_frames, frames.size());
        if (stat && method.name != "<clinit>")
            initialize(type);
        Value result;
        if (!method.declared)
            result = core(index, frame.arguments);
        else if (method.flags & 0x100) {
            if (!native)
                fail("NATIVE_UNAVAILABLE", "Native method requires an attached native interface");
            ++metrics.native_calls;
            result = native->invoke(runtime, index, frame.arguments);
        } else {
            if (!method.code)
                fail("ABSTRACT_METHOD", "Method has no executable body");
            if (method.flags & (0x20 | 0x20000))
                fail("SYNCHRONIZATION_UNSUPPORTED", "Synchronized methods are not implemented");
            if (!verified.contains(index))
                verified.emplace(index, verify(image, index));
            ++metrics.managed_calls;
            frame.registers.resize(method.code->registers);
            auto reg = std::uint32_t(method.code->registers - method.code->incoming);
            for (auto value : frame.arguments) {
                frame.put(reg, value);
                reg += value.kind == ValueKind::wide ? 2 : 1;
            }
            result = execute(frame, verified.at(index));
        }
        return typed(result, image.types[prototype.return_type]);
    }
};
ManagedRuntime::ManagedRuntime(DexImage image, RuntimeLimits limits)
    : impl_(std::make_unique<Impl>(*this, std::move(image), limits)) {}
ManagedRuntime::ManagedRuntime(std::shared_ptr<ClassSource> source, RuntimeLimits limits)
    : impl_(std::make_unique<Impl>(*this, DexImage{}, limits, std::move(source))) {}
ManagedRuntime::~ManagedRuntime() = default;
void ManagedRuntime::set_native_interface(NativeInterface *interface) {
    impl_->check_thread(interface == nullptr);
    if (!impl_->frames.empty())
        fail("STATE", "Cannot replace native interface during execution");
    impl_->native = interface;
}
void ManagedRuntime::set_host_interface(HostInterface *interface) {
    impl_->check_thread(interface == nullptr);
    if (!impl_->frames.empty())
        fail("STATE", "Cannot replace host interface during execution");
    impl_->host = interface;
}
const DexImage &ManagedRuntime::image() const noexcept { return impl_->image; }
const Class *ManagedRuntime::class_definition(std::string_view descriptor) const {
    return impl_->resolve_class(descriptor);
}
Index ManagedRuntime::resolve_method(std::string_view owner, std::string_view name,
                                     std::string_view signature) const {
    (void)impl_->resolve_class(owner);
    return impl_->image.method(owner, name, signature);
}
const RuntimeMetrics &ManagedRuntime::metrics() const noexcept { return impl_->metrics; }
Value ManagedRuntime::invoke(Index method, std::span<const Value> arguments) {
    auto &p = *impl_;
    p.check_thread();
    const bool outer = !p.invocations;
    if (outer) {
        p.remaining = p.limits.instructions;
        p.last_result = {};
        p.last_exception = 0;
    }
    ++p.invocations;
    struct End {
        Impl &p;
        ~End() { --p.invocations; }
    } end{p};
    try {
        const auto result = p.invoke(method, arguments);
        if (outer)
            p.last_result = result;
        return result;
    } catch (const JavaException &error) {
        p.last_exception = error.object;
        throw;
    }
}
Value ManagedRuntime::invoke_static(std::string_view owner, std::string_view name, std::string_view signature,
                                    std::span<const Value> arguments) {
    return invoke(lookup(owner, name, signature, true), arguments);
}
Value ManagedRuntime::invoke_virtual(Index method, std::span<const Value> arguments) {
    impl_->check_thread();
    if (arguments.empty())
        fail("SIGNATURE", "Virtual call requires a receiver");
    return invoke(impl_->virtual_target(method, reference(arguments[0])), arguments);
}
Index ManagedRuntime::lookup(std::string_view owner, std::string_view name, std::string_view signature,
                             bool is_static) const {
    impl_->check_thread();
    impl_->known(owner);
    const auto index = impl_->image.method(owner, name, signature);
    const auto actual = impl_->method_is_static(index);
    if (actual != is_static)
        fail("SIGNATURE", "Method lookup static/instance mismatch");
    return index;
}
void ManagedRuntime::initialize(std::string_view descriptor) { impl_->initialize(descriptor); }
ObjectId ManagedRuntime::new_object(std::string_view type) {
    auto &p = *impl_;
    p.initialize(type);
    if (type.empty() || type.front() != 'L' || type == "Ljava/lang/String;" || type == "Ljava/lang/Class;")
        fail("ALLOCATION_UNSUPPORTED", "Use the typed string/class/array allocator");
    const auto host_class = p.host ? p.host->class_info(type) : std::nullopt;
    if (type == "Ljava/lang/CharSequence;" ||
        (host_class && (host_class->is_abstract || host_class->is_interface)))
        fail("ALLOCATION", "Cannot instantiate abstract class or interface");
    Object result;
    result.type = type;
    for (unsigned depth = 0; depth < 256; ++depth) {
        const auto *definition = p.resolve_class(type);
        if (!definition)
            break;
        if (!depth && (definition->flags & (0x200 | 0x400)))
            fail("ALLOCATION", "Cannot instantiate abstract class or interface");
        for (const auto index : definition->instance_fields)
            result.fields[index] = default_value(p.image.types.at(p.image.fields.at(index).type));
        if (definition->superclass == no_index)
            break;
        type = p.image.types.at(definition->superclass);
    }
    return p.allocate(std::move(result));
}
ObjectId ManagedRuntime::new_string(std::u16string_view value) {
    if (value.size() > impl_->limits.array_length)
        fail("STRING_LIMIT", "Managed string exceeds length limit");
    Object result;
    result.type = "Ljava/lang/String;";
    result.text = value;
    return impl_->allocate(std::move(result));
}
ObjectId ManagedRuntime::class_object(std::string_view descriptor) {
    auto &p = *impl_;
    p.check_thread();
    p.known(descriptor);
    const auto it = p.class_objects.find(descriptor);
    if (it != p.class_objects.end())
        return it->second;
    Object result;
    result.type = "Ljava/lang/Class;";
    result.represented = descriptor;
    const auto id = p.allocate(std::move(result));
    p.class_objects.emplace(descriptor, id);
    return id;
}
ObjectId ManagedRuntime::new_array(std::string_view descriptor, std::int32_t length) {
    auto &p = *impl_;
    p.check_thread();
    if (descriptor.size() < 2 || descriptor[0] != '[' || descriptor.substr(1) == "V")
        fail("ARRAY_TYPE", "Invalid array descriptor");
    p.known(descriptor);
    if (length < 0)
        raise("Ljava/lang/NegativeArraySizeException;");
    if (static_cast<std::size_t>(length) > p.limits.array_length)
        fail("ARRAY_LIMIT", "Managed array exceeds length limit");
    Object result;
    result.type = descriptor;
    result.elements.resize(static_cast<std::size_t>(length), default_value(descriptor.substr(1)));
    return p.allocate(std::move(result));
}
std::string_view ManagedRuntime::object_type(ObjectId object) const { return impl_->object(object).type; }
std::string_view ManagedRuntime::represented_class(ObjectId object) const {
    const auto &o = impl_->object(object);
    if (o.type != "Ljava/lang/Class;")
        fail("VALUE_TYPE", "Expected a class object");
    return o.represented;
}
std::u16string_view ManagedRuntime::string(ObjectId object) const {
    const auto &o = impl_->object(object);
    if (o.type != "Ljava/lang/String;")
        fail("VALUE_TYPE", "Expected a string object");
    return o.text;
}
std::u16string_view ManagedRuntime::char_sequence(ObjectId object) const {
    const auto &o = impl_->object(object);
    if (o.type != "Ljava/lang/String;" && o.type != "Ljava/lang/StringBuilder;")
        fail("API_UNSUPPORTED", "CharSequence implementation is not supported: " + o.type);
    return o.text;
}
std::u16string_view ManagedRuntime::exception_message(ObjectId object) const {
    const auto &o = impl_->object(object);
    if (!impl_->subtype(o.type, "Ljava/lang/Throwable;"))
        fail("VALUE_TYPE", "Expected a Throwable object");
    return o.text;
}
std::size_t ManagedRuntime::array_length(ObjectId object) const {
    const auto &o = impl_->object(object);
    if (o.type.front() != '[')
        fail("VALUE_TYPE", "Expected an array object");
    return o.elements.size();
}
Value ManagedRuntime::array_get(ObjectId object, std::int32_t index) const {
    const auto &o = impl_->object(object);
    if (o.type.front() != '[')
        fail("VALUE_TYPE", "Expected an array object");
    if (index < 0 || static_cast<std::size_t>(index) >= o.elements.size())
        const_cast<ManagedRuntime *>(this)->raise("Ljava/lang/ArrayIndexOutOfBoundsException;");
    return o.elements[static_cast<std::size_t>(index)];
}
void ManagedRuntime::array_set(ObjectId object, std::int32_t index, Value value) {
    auto &o = impl_->object(object);
    if (o.type.front() != '[')
        fail("VALUE_TYPE", "Expected an array object");
    if (index < 0 || static_cast<std::size_t>(index) >= o.elements.size())
        raise("Ljava/lang/ArrayIndexOutOfBoundsException;");
    const auto component = std::string_view(o.type).substr(1);
    if (reference_type(component) && !assignable(reference(value), component))
        raise("Ljava/lang/ArrayStoreException;");
    o.elements[static_cast<std::size_t>(index)] = impl_->typed(value, component);
}
bool ManagedRuntime::assignable(ObjectId object, std::string_view type) const {
    impl_->check_thread();
    return !object || impl_->subtype(impl_->object(object).type, type);
}
Value ManagedRuntime::get_static(Index index) {
    auto &p = *impl_;
    p.check_thread();
    const auto &field = p.image.fields.at(index);
    if (p.loader)
        p.loader->ensure(p.image.types.at(field.owner));
    if (!field.declared || !(field.flags & 8))
        fail("FIELD", "Expected a defined static field");
    p.initialize(p.image.types.at(field.owner));
    return p.statics.at(index);
}
void ManagedRuntime::set_static(Index index, Value value) {
    auto &p = *impl_;
    p.check_thread();
    const auto &field = p.image.fields.at(index);
    if (p.loader)
        p.loader->ensure(p.image.types.at(field.owner));
    if (!field.declared || !(field.flags & 8))
        fail("FIELD", "Expected a defined static field");
    p.initialize(p.image.types.at(field.owner));
    p.statics[index] = p.typed(value, p.image.types.at(field.type));
}
void ManagedRuntime::retain(ObjectId id) {
    if (!id)
        return;
    auto &p = *impl_;
    (void)p.object(id);
    if (p.metrics.pinned_references >= 65536)
        fail("ROOT_LIMIT", "Too many retained managed roots");
    ++p.pins[id];
    ++p.metrics.pinned_references;
}
void ManagedRuntime::release(ObjectId id) {
    if (!id)
        return;
    auto &p = *impl_;
    p.check_thread(true);
    const auto it = p.pins.find(id);
    if (it == p.pins.end())
        fail("REFERENCE", "Release of an unretained managed root");
    if (!--it->second)
        p.pins.erase(it);
    --p.metrics.pinned_references;
}
void ManagedRuntime::collect() { impl_->collect(); }
[[noreturn]] void ManagedRuntime::raise(std::string_view type, std::u16string_view message) {
    auto &p = *impl_;
    p.check_thread();
    if (!p.subtype(type, "Ljava/lang/Throwable;"))
        fail("EXCEPTION", "Exception type does not derive from Throwable");
    if (message.size() > p.limits.array_length)
        fail("STRING_LIMIT", "Exception message exceeds length limit");
    const auto id = new_object(type);
    if (message.size() * 2 > p.limits.heap_bytes - p.metrics.heap_bytes)
        fail("HEAP_LIMIT", "Exception message exceeds heap limit");
    auto &o = p.object(id);
    o.text = message;
    o.bytes += message.size() * 2;
    p.metrics.heap_bytes += message.size() * 2;
    ++p.metrics.exceptions;
    p.last_exception = id;
    throw JavaException(id);
}
} // namespace aether::dex
