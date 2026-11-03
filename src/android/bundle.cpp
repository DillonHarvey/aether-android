#include "bundle.hpp"
#include <algorithm>
#include <limits>

namespace aether::android {
namespace {
using dex::Value;
using Kind = BundleValueKind;
struct Key {
    std::u16string text;
    bool is_null = false;
    Kind kind = Kind::integer;
};
class BundleState final : public dex::HostObjectState {
  public:
    std::vector<Key> keys;
    std::vector<Value> entries;
    std::span<const Value> values() const noexcept override { return entries; }
    std::size_t bytes() const noexcept override {
        auto total = sizeof(BundleState) + keys.capacity() * sizeof(Key) + entries.capacity() * sizeof(Value);
        for (const auto &key : keys)
            if (key.text.capacity() > std::u16string{}.capacity())
                total += (key.text.capacity() + 1) * sizeof(char16_t);
        return total;
    }

};
[[noreturn]] void fail(std::string_view code, std::string message) {
    throw dex::DexError("AETHER_ANDROID_" + std::string(code), std::move(message));
}
const BundleState &state(dex::ManagedRuntime &runtime, dex::ObjectId id) {
    if (!id)
        runtime.raise("Ljava/lang/NullPointerException;");
    const auto *value = dynamic_cast<const BundleState *>(runtime.host_state(id));
    if (!value)
        fail("BUNDLE_STATE", "Bundle constructor has not completed");
    return *value;
}
Kind kind(std::string_view name) {
    if (name.ends_with("ByteArray"))
        return Kind::byte_array;
    if (name.ends_with("Float"))
        return Kind::floating;
    if (name.ends_with("Int"))
        return Kind::integer;
    if (name.ends_with("Long"))
        return Kind::wide;
    if (name.ends_with("Boolean"))
        return Kind::boolean;
    if (name.ends_with("String"))
        return Kind::string;
    if (name.ends_with("Bundle"))
        return Kind::bundle;
    fail("API_UNSUPPORTED", "Unknown Bundle value kind");
}
struct Reservation {
    dex::ManagedRuntime &runtime;
    std::size_t bytes = 0;
    ~Reservation() { runtime.release_provider_storage(bytes); }
    void refund(std::size_t amount) noexcept {
        runtime.release_provider_storage(amount);
        bytes -= amount;
    }
    void add(std::size_t amount) {
        if (amount > std::numeric_limits<std::size_t>::max() - bytes)
            fail("BUNDLE_LIMIT", "Bundle native storage size overflows");
        runtime.reserve_provider_storage(amount);
        bytes += amount;
    }
};
std::size_t storage_product(std::size_t count, std::size_t width) {
    if (count > std::numeric_limits<std::size_t>::max() / width)
        fail("BUNDLE_LIMIT", "Bundle native storage size overflows");
    return count * width;
}
void publish_bundle_snapshot(dex::ManagedRuntime &runtime, dex::ObjectId target,
        std::span<const BundleSnapshotEntry> input, std::size_t actual_native_input_bytes) {
    if (actual_native_input_bytes > runtime.metrics().provider_storage_reserved_bytes)
        fail("BUNDLE_STATE", "Bundle input storage has no live provider reservation");
    Reservation scratch{runtime}, output{runtime};
    // Ordering work is charged before comparisons, including UTF-16 units.
    // Original position breaks equal-key ties, giving the SDK's last put wins.
    scratch.add(storage_product(input.size(), sizeof(std::size_t)));
    std::vector<std::size_t> order;
    order.reserve(input.size());
    if (order.capacity() != input.size())
        fail("BUNDLE_STORAGE_UNSUPPORTED", "Bundle index allocation changed its admitted capacity");
    for (std::size_t i = 0; i < input.size(); ++i) {
        runtime.charge_provider_work(1);
        order.push_back(i);
    }
    const auto compare_key = [&](std::size_t a, std::size_t b) {
        runtime.charge_provider_work(1);
        if (input[a].null_key != input[b].null_key)
            return input[a].null_key ? -1 : 1;
        if (input[a].null_key) return 0;
        const auto left = input[a].key, right = input[b].key;
        for (std::size_t n = 0; n < std::min(left.size(), right.size()); ++n) {
            runtime.charge_provider_work(1);
            if (left[n] != right[n]) return left[n] < right[n] ? -1 : 1;
        }
        return left.size() == right.size() ? 0 : left.size() < right.size() ? -1 : 1;
    };
    std::sort(order.begin(), order.end(), [&](auto a, auto b) {
        const auto compared = compare_key(a, b);
        return compared ? compared < 0 : a < b;
    });
    std::size_t distinct = 0;
    for (std::size_t i = 0; i < order.size(); ++i)
        if (i + 1 == order.size() || compare_key(order[i], order[i + 1]) != 0)
            ++distinct;
    output.add(sizeof(BundleState));
    auto next = std::make_unique<BundleState>();
    output.add(storage_product(distinct, sizeof(Key)));
    next->keys.reserve(distinct);
    if (next->keys.capacity() != distinct)
        fail("BUNDLE_STORAGE_UNSUPPORTED", "Bundle key allocation changed its admitted capacity");
    output.add(storage_product(distinct, sizeof(Value)));
    next->entries.reserve(distinct);
    if (next->entries.capacity() != distinct)
        fail("BUNDLE_STORAGE_UNSUPPORTED", "Bundle value allocation changed its admitted capacity");
    for (std::size_t i = 0; i < order.size(); ++i) {
        if (i + 1 != order.size() && compare_key(order[i], order[i + 1]) == 0) continue;
        const auto &entry = input[order[i]];
        const auto text = entry.null_key ? std::u16string_view{} : entry.key;
        const auto reference_kind = entry.kind == Kind::string || entry.kind == Kind::bundle ||
                                    entry.kind == Kind::byte_array;
        if ((reference_kind && entry.value.kind != dex::ValueKind::reference) ||
            (!reference_kind && entry.value.kind != (entry.kind == Kind::wide ?
                dex::ValueKind::wide : dex::ValueKind::word)))
            fail("BUNDLE_STATE", "Bundle snapshot value has an incompatible representation");
        if (reference_kind && entry.value.bits) {
            const auto type = entry.kind == Kind::string ? "Ljava/lang/String;" :
                              entry.kind == Kind::bundle ? bundle_type : "[B";
            if (!runtime.assignable(entry.value.bits, type))
                fail("BUNDLE_STATE", "Bundle snapshot reference has an incompatible type");
        }
        // Inline key storage is already part of sizeof(Key). Charge separate
        // native storage only when the string actually uses a heap buffer.
        // Windows MSVC C++20 xstring rounds a fresh char16_t allocation with
        // mask 7, and compares it with the empty capacity's 3/2 growth.
        // Admit a conservative mask-15 ceiling before constructing the key;
        // refund unused space without a collecting admission after allocation.
        const auto capacity = text.size() | std::size_t{15};
        if (capacity == std::numeric_limits<std::size_t>::max())
            fail("BUNDLE_LIMIT", "Bundle key storage size overflows");
        const auto inline_capacity = std::u16string{}.capacity();
        const auto admitted = text.size() <= inline_capacity ? 0 :
            storage_product(capacity + 1, sizeof(char16_t));
        output.add(admitted);
        runtime.charge_provider_work(text.size() + 1);
        next->keys.push_back({std::u16string(text), entry.null_key, entry.kind});
        const auto actual_capacity = next->keys.back().text.capacity();
        if (actual_capacity > capacity)
            fail("BUNDLE_STORAGE_UNSUPPORTED", "Bundle string allocation changed its admitted capacity");
        const auto actual = actual_capacity <= inline_capacity ? 0 :
            storage_product(actual_capacity + 1, sizeof(char16_t));
        if (actual > admitted)
            fail("BUNDLE_STORAGE_UNSUPPORTED", "Bundle key storage exceeds its admitted allocation");
        output.refund(admitted - actual);
        next->entries.push_back(entry.kind == Kind::boolean ?
            Value::word(entry.value.bits != 0) : entry.value);
    }
    // Publication computes bytes() and validates values(): charge both distinct
    // linear visits separately from construction and sorting work above.
    runtime.charge_provider_work(distinct);
    runtime.charge_provider_work(distinct);
    runtime.set_host_state_with_storage(target, std::move(next), output.bytes);
}
} // namespace

dex::ObjectId new_bundle_snapshot(dex::ManagedRuntime &runtime,
        std::span<const BundleSnapshotEntry> input, std::size_t actual_native_input_bytes) {
    const auto id = runtime.new_object(bundle_type);
    runtime.retain(id);
    struct Root {
        dex::ManagedRuntime &runtime;
        dex::ObjectId id;
        ~Root() { runtime.release(id); }
    } root{runtime, id};
    publish_bundle_snapshot(runtime, id, input, actual_native_input_bytes);
    return id;
}

dex::Value invoke_bundle(dex::ManagedRuntime &runtime, std::string_view owner, std::string_view name,
                         std::string_view signature, std::span<const Value> args) {
    // Legacy host save/restore enters one actual SDK event when the managed
    // main is idle. Nested/retained invocations always keep their existing work.
    if (!runtime.has_provider_work_context()) {
        Value result;
        runtime.run_host_callback([&] { result = invoke_bundle(runtime, owner, name, signature, args); });
        return result;
    }
    struct ArgumentRoots {
        dex::ManagedRuntime &runtime;
        std::span<const Value> args;
        std::size_t processed = 0;
        ~ArgumentRoots() {
            for (std::size_t i = 0; i < processed; ++i)
                if (args[i].kind == dex::ValueKind::reference) runtime.release(args[i].bits);
        }
        void retain_all() {
            for (; processed < args.size(); ++processed)
                if (args[processed].kind == dex::ValueKind::reference) runtime.retain(args[processed].bits);
        }
    } roots{runtime, args};
    roots.retain_all();
    if (args.empty() || args[0].kind != dex::ValueKind::reference)
        fail("BUNDLE_STATE", "Bundle method requires a reference receiver");
    const auto receiver = args[0].bits;
    if (!receiver) runtime.raise("Ljava/lang/NullPointerException;");
    if (!runtime.assignable(receiver, bundle_type))
        fail("BUNDLE_STATE", "Bundle method receiver is not a Bundle");
    runtime.charge_provider_work(1);
    const BundleState *source = nullptr;
    if (name == "<init>" && owner == bundle_type) {
        if (runtime.host_state(receiver))
            fail("BUNDLE_STATE", "Bundle constructor invoked twice");
        if (signature == "()V") {
            publish_bundle_snapshot(runtime, receiver, {}, 0);
            return Value::nothing();
        }
        if (args.size() != 2)
            fail("BUNDLE_STATE", "Bundle copy constructor requires its source");
        source = &state(runtime, args[1].bits);
    } else {
        source = &state(runtime, receiver);
    }
    const auto &current = *source;
    if (name == "size")
        return Value::word(static_cast<std::uint32_t>(current.keys.size()));
    if (name == "isEmpty")
        return Value::word(current.keys.empty());
    if (name == "clear") {
        runtime.charge_provider_work(current.keys.size()); // key destruction
        runtime.shrink_host_state(receiver, [](dex::HostObjectState &raw, void *) noexcept {
            auto &value = static_cast<BundleState &>(raw);
            std::vector<Key>{}.swap(value.keys);
            std::vector<Value>{}.swap(value.entries);
        }, nullptr);
        return Value::nothing();
    }
    const bool copy = name == "<init>";
    std::u16string_view text;
    dex::ObjectId key = 0;
    auto at = current.keys.size();
    if (!copy) {
        if (args.size() < 2 || args[1].kind != dex::ValueKind::reference)
            fail("BUNDLE_STATE", "Bundle key must be a String reference or null");
        key = args[1].bits;
        text = key ? runtime.string(key) : std::u16string_view{};
        // Meter both entry visits and the actual UTF-16 comparison work.
        for (std::size_t n = 0; n < current.keys.size(); ++n) {
            runtime.charge_provider_work(1);
            const auto &existing = current.keys[n];
            if (existing.is_null != !key) continue;
            if (!key) { at = n; break; }
            if (existing.text.size() != text.size()) continue;
            bool equal = true;
            for (std::size_t unit = 0; unit < text.size(); ++unit) {
                runtime.charge_provider_work(1);
                if (existing.text[unit] != text[unit]) { equal = false; break; }
            }
            if (equal) { at = n; break; }
        }
    }
    if (name == "containsKey")
        return Value::word(at != current.keys.size());
    if (name == "remove") {
        if (at != current.keys.size()) {
            // Erase moves existing keys/values without allocating; bytes() scans
            // surviving capacities separately after the mutation.
            runtime.charge_provider_work(current.keys.size() - at);
            runtime.charge_provider_work(current.keys.size() - 1);
            runtime.shrink_host_state(receiver, [](dex::HostObjectState &raw, void *index) noexcept {
                auto &value = static_cast<BundleState &>(raw);
                const auto position = *static_cast<const std::size_t *>(index);
                value.keys.erase(value.keys.begin() + position);
                value.entries.erase(value.entries.begin() + position);
            }, &at);
        }
        return Value::nothing();
    }
    const auto type = copy ? Kind::integer : kind(name);
    if (name.starts_with("get")) {
        if (at != current.keys.size() && current.keys[at].kind == type &&
            (type != Kind::string || current.entries[at].bits))
            return current.entries[at];
        if (args.size() == 3) return args[2];
        if (type == Kind::string || type == Kind::bundle || type == Kind::byte_array)
            return Value::reference(0);
        return type == Kind::wide ? Value::wide(0) : Value::word(0);
    }
    if (!copy && !name.starts_with("put"))
        fail("API_UNSUPPORTED", "Bundle method is not implemented");
    if (!copy && args.size() != 3)
        fail("BUNDLE_STATE", "Bundle write requires a key and value");
    if (!copy && current.keys.size() == std::numeric_limits<std::size_t>::max())
        fail("BUNDLE_LIMIT", "Bundle entry storage size overflows");
    const auto count = current.keys.size() + (copy ? 0 : 1);
    Reservation input_storage{runtime};
    input_storage.add(storage_product(count, sizeof(BundleSnapshotEntry)));
    std::vector<BundleSnapshotEntry> entries;
    entries.reserve(count);
    if (entries.capacity() != count)
        fail("BUNDLE_STORAGE_UNSUPPORTED", "Bundle mutation input changed its admitted capacity");
    for (std::size_t n = 0; n < current.keys.size(); ++n) {
        runtime.charge_provider_work(1);
        entries.push_back({current.keys[n].text, current.keys[n].is_null,
                           current.keys[n].kind, current.entries[n]});
    }
    if (!copy) entries.push_back({text, !key, type, args[2]});
    publish_bundle_snapshot(runtime, receiver, entries, input_storage.bytes);
    return Value::nothing();
}
} // namespace aether::android
