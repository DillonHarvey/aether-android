#include "bundle.hpp"
#include <algorithm>

namespace aether::android {
namespace {
using dex::Value;
enum class Kind { integer, wide, boolean, string, bundle };
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
            total += (key.text.capacity() + 1) * sizeof(char16_t);
        return total;
    }
    std::size_t find(bool is_null, std::u16string_view text) const noexcept {
        for (std::size_t n = 0; n < keys.size(); ++n)
            if (keys[n].is_null == is_null && (is_null || keys[n].text == text))
                return n;
        return keys.size();
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
} // namespace
dex::Value invoke_bundle(dex::ManagedRuntime &runtime, std::string_view owner, std::string_view name,
                         std::string_view signature, std::span<const Value> args) {
    const auto receiver = args[0].bits;
    if (!runtime.assignable(receiver, bundle_type))
        fail("BUNDLE_STATE", "Bundle method receiver is not a Bundle");
    if (name == "<init>" && owner == bundle_type) {
        if (runtime.host_state(receiver))
            fail("BUNDLE_STATE", "Bundle constructor invoked twice");
        auto next = signature == "()V" ? std::make_unique<BundleState>()
                                       : std::make_unique<BundleState>(state(runtime, args[1].bits));
        runtime.set_host_state(receiver, std::move(next));
        return Value::nothing();
    }
    const auto &current = state(runtime, receiver);
    if (name == "size")
        return Value::word(static_cast<std::uint32_t>(current.keys.size()));
    if (name == "isEmpty")
        return Value::word(current.keys.empty());
    if (name == "clear") {
        runtime.set_host_state(receiver, std::make_unique<BundleState>());
        return Value::nothing();
    }
    const auto key = args[1].bits;
    const auto text = key ? runtime.string(key) : std::u16string_view{};
    if (text.size() > bundle_key_units)
        fail("BUNDLE_LIMIT", "Bundle key exceeds 4096 UTF-16 units");
    const auto at = current.find(!key, text);
    if (name == "containsKey")
        return Value::word(at != current.keys.size());
    if (name == "remove") {
        if (at != current.keys.size()) {
            auto next = std::make_unique<BundleState>(current);
            next->keys.erase(next->keys.begin() + at);
            next->entries.erase(next->entries.begin() + at);
            runtime.set_host_state(receiver, std::move(next));
        }
        return Value::nothing();
    }
    const auto type = kind(name);
    if (name.starts_with("get")) {
        if (at != current.keys.size() && current.keys[at].kind == type &&
            (type != Kind::string || current.entries[at].bits))
            return current.entries[at];
        if (args.size() == 3)
            return args[2];
        if (type == Kind::string || type == Kind::bundle)
            return Value::reference(0);
        return type == Kind::wide ? Value::wide(0) : Value::word(0);
    }
    if (name.starts_with("put")) {
        if (at == current.keys.size()) {
            if (current.keys.size() == bundle_entries)
                fail("BUNDLE_LIMIT", "Bundle exceeds 256 entries");
            auto units = text.size();
            for (const auto &existing : current.keys)
                units += existing.text.size();
            if (units > bundle_all_key_units)
                fail("BUNDLE_LIMIT", "Bundle keys exceed 65536 UTF-16 units");
        }
        auto next = std::make_unique<BundleState>(current);
        const auto value = type == Kind::boolean ? Value::word(args[2].bits != 0) : args[2];
        if (at == next->keys.size()) {
            next->keys.push_back({std::u16string(text), !key, type});
            next->entries.push_back(value);
        } else {
            next->keys[at].kind = type;
            next->entries[at] = value;
        }
        runtime.set_host_state(receiver, std::move(next));
        return Value::nothing();
    }
    fail("API_UNSUPPORTED", "Bundle method is not implemented");
}
} // namespace aether::android
