#include "uris.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <optional>

namespace aether::android {
namespace {
using dex::ManagedRuntime;
using dex::ObjectId;
using dex::Value;

// Original Aether implementation. Observable parsing follows Android15 Uri and
// UriCodec at frameworks/base4e43ad12e1b211f15152e9c5b16b0fe88e6b93f3.
// UTF8 replacement follows that release's ICU valid-prefix consumption rules.
enum Slot : std::size_t {
    source, scheme, encoded_ssp, decoded_ssp, encoded_authority, decoded_authority,
    encoded_path, decoded_path, encoded_query, decoded_query, encoded_fragment,
    decoded_fragment, encoded_user_info, decoded_user_info, host, slot_count
};
class UriState final : public dex::HostObjectState {
  public:
    std::array<Value, slot_count> references;
    std::uint32_t ready = 1u;
    std::int32_t port = -2;
    explicit UriState(ObjectId text) {
        references.fill(Value::reference(0));
        references[source] = Value::reference(text);
    }
    std::span<const Value> values() const noexcept override { return references; }
    std::size_t bytes() const noexcept override { return sizeof(*this); }
};
class Root {
    ManagedRuntime &runtime;
    ObjectId id;
  public:
    Root(ManagedRuntime &runtime, ObjectId id) : runtime(runtime), id(id) { runtime.retain(id); }
    ~Root() { runtime.release(id); }
    Root(const Root &) = delete;
    Root &operator=(const Root &) = delete;
};
[[noreturn]] void bad(std::string_view code, std::string_view message) {
    throw dex::DexError("AETHER_ANDROID_" + std::string(code), std::string(message));
}
ObjectId reference(Value value) {
    if (value.kind != dex::ValueKind::reference) bad("URI_ARGUMENT", "Uri requires reference arguments");
    return value.bits;
}
void bounded(std::u16string_view text) {
    if (text.size() > uri_text_units) bad("URI_LIMIT", "Uri text exceeds 4096 UTF-16 units");
}
const UriState &state(ManagedRuntime &runtime, ObjectId id) {
    if (!id) runtime.raise("Ljava/lang/NullPointerException;");
    if (runtime.object_type(id) != string_uri_type)
        bad("API_UNSUPPORTED", "This Uri getter requires the supported actual StringUri representation");
    const auto *current = dynamic_cast<const UriState *>(runtime.host_state(id));
    if (!current) bad("URI_STATE", "StringUri lacks authenticated value state");
    return *current;
}
ObjectId canonical_string(ManagedRuntime &runtime, std::u16string_view text) {
    const auto result = runtime.new_string(text);
    if (!text.empty()) return result;
    Root result_root(runtime, result);
    return reference(runtime.invoke_virtual_named(result, "intern", "()Ljava/lang/String;"));
}
ObjectId allocate(ManagedRuntime &runtime, ObjectId text) {
    Root text_root(runtime, text);
    if (!text) runtime.raise("Ljava/lang/NullPointerException;", u"uriString");
    bounded(runtime.string(text));
    const auto result = runtime.new_object(string_uri_type);
    Root result_root(runtime, result);
    runtime.set_host_state(result, std::make_unique<UriState>(text));
    return result;
}
[[noreturn]] void common_error(const uri::Error &error) {
    bad(error.kind == uri::Error::Kind::limit ? "URI_LIMIT" : "URI_STATE", error.what());
}
std::u16string decode(std::u16string_view encoded) {
    try { return uri::decode(encoded); }
    catch (const uri::Error &error) { common_error(error); }
}
uri::Part encoded_part(Slot slot) {
    switch (slot) {
    case scheme: return uri::Part::scheme;
    case encoded_ssp: return uri::Part::scheme_specific_part;
    case encoded_authority: return uri::Part::authority;
    case encoded_path: return uri::Part::path;
    case encoded_query: return uri::Part::query;
    case encoded_fragment: return uri::Part::fragment;
    case encoded_user_info: return uri::Part::user_info;
    default: bad("URI_STATE", "Unsupported encoded Uri component slot");
    }
}
using Parsed = uri::Parsed;
Parsed parse(std::u16string_view text) {
    try { return Parsed(text); }
    catch (const uri::Error &error) { common_error(error); }
}
ObjectId component(ManagedRuntime &runtime, ObjectId receiver, Slot slot) {
    if (state(runtime, receiver).ready & (1u << slot)) return state(runtime, receiver).references[slot].bits;
    ObjectId result = 0;
    if (slot == decoded_ssp || slot == decoded_authority || slot == decoded_path ||
        slot == decoded_query || slot == decoded_fragment || slot == decoded_user_info) {
        const auto encoded = component(runtime, receiver, static_cast<Slot>(static_cast<std::size_t>(slot) - 1));
        Root encoded_root(runtime, encoded);
        if (encoded) {
            const auto text = std::u16string(runtime.string(encoded));
            result = text.empty() ? encoded : canonical_string(runtime, decode(text));
        }
    } else if (slot == host || slot == encoded_user_info) {
        const auto authority_id = component(runtime, receiver, encoded_authority);
        Root authority_root(runtime, authority_id);
        if (authority_id) {
            const auto authority = std::u16string(runtime.string(authority_id));
            const auto text = std::u16string_view(authority);
            try {
                if (slot == encoded_user_info) {
                    if (const auto user = uri::user_info(text))
                        result = canonical_string(runtime, text.substr(user->first, user->last - user->first));
                } else result = canonical_string(runtime, uri::host(text));
            } catch (const uri::Error &error) { common_error(error); }
        }
    } else {
        const auto source_id = state(runtime, receiver).references[source].bits;
        const auto original = std::u16string(runtime.string(source_id));
        const auto parsed = parse(original);
        if (const auto slice = parsed.part(encoded_part(slot))) {
            const auto text = std::u16string_view(original).substr(slice->first, slice->last - slice->first);
            result = !text.empty() && slice->first == 0 && slice->last == original.size() ?
                source_id : canonical_string(runtime, text);
        }
    }
    Root result_root(runtime, result);
    // A managed allocation may publish another lazy cache. Merge into the live
    // state rather than overwriting it with a pre-allocation state snapshot.
    const auto &current = state(runtime, receiver);
    if (current.ready & (1u << slot)) return current.references[slot].bits;
    auto next = std::make_unique<UriState>(current);
    next->references[slot] = Value::reference(result);
    next->ready |= 1u << slot;
    runtime.set_host_state(receiver, std::move(next));
    return result;
}
std::int32_t port(ManagedRuntime &runtime, ObjectId receiver) {
    if (state(runtime, receiver).port != -2) return state(runtime, receiver).port;
    std::int32_t result = -1;
    const auto authority = component(runtime, receiver, encoded_authority);
    Root authority_root(runtime, authority);
    if (authority) {
        const auto text = std::u16string(runtime.string(authority));
        try { result = uri::port(text); }
        catch (const uri::Error &error) { common_error(error); }
    }
    auto next = std::make_unique<UriState>(state(runtime, receiver));
    next->port = result;
    runtime.set_host_state(receiver, std::move(next));
    return result;
}
std::uint32_t hash(std::u16string_view text) noexcept {
    std::uint32_t result = 0;
    for (const auto unit : text) result = result * 31u + static_cast<std::uint16_t>(unit);
    return result;
}
std::int32_t compare(std::u16string_view left, std::u16string_view right) noexcept {
    for (std::size_t at = 0, count = std::min(left.size(), right.size()); at < count; ++at)
        if (left[at] != right[at]) return static_cast<std::int32_t>(left[at]) - static_cast<std::int32_t>(right[at]);
    return static_cast<std::int32_t>(left.size()) - static_cast<std::int32_t>(right.size());
}
ObjectId representation(ManagedRuntime &runtime, ObjectId uri) {
    Root uri_root(runtime, uri);
    if (!uri) runtime.raise("Ljava/lang/NullPointerException;");
    if (runtime.object_type(uri) == string_uri_type) return state(runtime, uri).references[source].bits;
    if (!runtime.assignable(uri, uri_type)) bad("URI_ARGUMENT", "Value is not a Uri");
    // Preserve genuine virtual behavior for any other admitted representation.
    // Null String results are handled by the calling operation, after its
    // remaining Java argument expressions have been evaluated.
    return reference(runtime.invoke_virtual_named(uri, "toString", "()Ljava/lang/String;"));
}
} // namespace

ObjectId new_uri(ManagedRuntime &runtime, std::u16string_view encoded) {
    bounded(encoded);
    const auto copied = std::u16string(encoded);
    const auto text = runtime.new_string(copied);
    Root text_root(runtime, text);
    return allocate(runtime, text);
}
std::u16string uri_text(ManagedRuntime &runtime, ObjectId uri) {
    Root uri_root(runtime, uri);
    const auto text = representation(runtime, uri);
    Root text_root(runtime, text);
    const auto result = std::u16string(runtime.string(text));
    bounded(result);
    return result;
}
Value invoke_uri(ManagedRuntime &runtime, std::string_view owner, std::string_view name,
                 std::string_view signature, std::span<const Value> args) {
    if (args.empty() || args.size() > 2) bad("URI_ARGUMENT", "Uri call has an unsupported argument count");
    const auto first = reference(args[0]), second = args.size() == 2 ? reference(args[1]) : 0;
    Root first_root(runtime, first), second_root(runtime, second);
    if (owner == uri_type && name == "parse" && signature == "(Ljava/lang/String;)Landroid/net/Uri;" && args.size() == 1)
        return Value::reference(allocate(runtime, first));
    if (owner == uri_type && name == "decode" && signature == "(Ljava/lang/String;)Ljava/lang/String;" && args.size() == 1) {
        if (!first) return Value::reference(0);
        const auto text = std::u16string(runtime.string(first));
        return Value::reference(canonical_string(runtime, decode(text)));
    }
    if (!first) runtime.raise("Ljava/lang/NullPointerException;");
    if (name == "equals" && signature == "(Ljava/lang/Object;)Z" && args.size() == 2) {
        if (!second || !runtime.assignable(second, uri_type)) return Value::word(0);
        const auto left = representation(runtime, first);
        Root left_root(runtime, left);
        const auto right = representation(runtime, second);
        Root right_root(runtime, right);
        const auto left_text = runtime.string(left);
        return Value::word(right && left_text == runtime.string(right));
    }
    if (name == "hashCode" && signature == "()I" && args.size() == 1) return Value::word(hash(uri_text(runtime, first)));
    if (name == "compareTo" && (signature == "(Landroid/net/Uri;)I" || signature == "(Ljava/lang/Object;)I") && args.size() == 2) {
        if (second && !runtime.assignable(second, uri_type)) runtime.raise("Ljava/lang/ClassCastException;");
        const auto left = representation(runtime, first);
        Root left_root(runtime, left);
        const auto right = representation(runtime, second);
        Root right_root(runtime, right);
        return Value::word(std::bit_cast<std::uint32_t>(compare(runtime.string(left), runtime.string(right))));
    }
    if ((name == "isOpaque" || name == "isAbsolute") && signature == "()Z" && args.size() == 1) {
        const auto base = name == "isOpaque" ? "isHierarchical" : "isRelative";
        if (runtime.object_type(first) != string_uri_type)
            return Value::word(runtime.invoke_virtual_named(first, base, "()Z").bits == 0);
        const auto parsed = parse(runtime.string(state(runtime, first).references[source].bits));
        return Value::word(name == "isOpaque" ? !parsed.hierarchical() : parsed.colon != parsed.text.npos);
    }
    if (args.size() != 1) bad("API_UNSUPPORTED", "Uri operation is outside the supported value profile");
    const auto source_id = state(runtime, first).references[source].bits;
    if (name == "toString" && signature == "()Ljava/lang/String;") return Value::reference(source_id);
    if (name == "describeContents" && signature == "()I") return Value::word(0);
    if ((name == "isHierarchical" || name == "isRelative") && signature == "()Z") {
        const auto parsed = parse(runtime.string(source_id));
        return Value::word(name == "isRelative" ? parsed.colon == parsed.text.npos : parsed.hierarchical());
    }
    if (name == "getPort" && signature == "()I") return Value::word(std::bit_cast<std::uint32_t>(port(runtime, first)));
    if (signature == "()Ljava/lang/String;") {
        const std::array<std::pair<std::string_view, Slot>, 14> components{{
            {"getScheme", scheme}, {"getEncodedSchemeSpecificPart", encoded_ssp}, {"getSchemeSpecificPart", decoded_ssp},
            {"getEncodedAuthority", encoded_authority}, {"getAuthority", decoded_authority},
            {"getEncodedPath", encoded_path}, {"getPath", decoded_path}, {"getEncodedQuery", encoded_query},
            {"getQuery", decoded_query}, {"getEncodedFragment", encoded_fragment}, {"getFragment", decoded_fragment},
            {"getEncodedUserInfo", encoded_user_info}, {"getUserInfo", decoded_user_info}, {"getHost", host}}};
        for (const auto &[getter, slot] : components)
            if (name == getter) return Value::reference(component(runtime, first, slot));
    }
    bad("API_UNSUPPORTED", "Uri operation is outside the supported StringUri profile");
}
} // namespace aether::android
