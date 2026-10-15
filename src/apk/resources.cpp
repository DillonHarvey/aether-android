#include "aether/apk/resources.hpp"
#include "aether/apk/bytes.hpp"
#include "aether/apk/package.hpp"
#include "aether/apk/string_pool.hpp"
#include "aether/common/text.hpp"
#include <algorithm>
#include <set>

namespace aether::apk {
namespace {
[[noreturn]] void bad(std::string message, std::string_view kind = "INVALID") {
    throw InspectError("AETHER_RESOURCES_" + std::string(kind), "resources", std::move(message));
}
struct Chunk {
    std::uint16_t type, header;
    std::uint32_t size;
};
Chunk chunk(const View &view, std::size_t at) {
    const Chunk result{view.u16(at), view.u16(at + 2), view.u32(at + 4)};
    if (result.header < 8 || result.size < result.header || ((result.header | result.size) & 3))
        bad("Invalid resource chunk dimensions");
    (void)view.slice(at, result.size);
    return result;
}
std::u16string unicode(std::string_view text) {
    const auto value = utf16(text);
    return {value.begin(), value.end()};
}
bool better(const ResourceEntry &candidate, const ResourceEntry &old, const ResourceConfiguration &target) {
    // anydpi wins, then the smallest sufficient density, then the largest
    // undersized source. Frozen artwork specially prefers nodpi; runtime treats
    // its sentinel as an unscaled source only when it wins density selection.
    const auto rank = [&](std::uint16_t density) {
        if (density == 0xfffe)
            return std::pair{0u, 0u};
        if (density == 0xffff && target.policy == ResourceSelectionPolicy::frozen_artwork)
            return std::pair{1u, 0u};
        const unsigned actual = density ? density : 160u;
        return actual >= target.density ? std::pair{2u, actual - target.density}
                                        : std::pair{3u, target.density - actual};
    };
    const auto a = rank(candidate.density), b = rank(old.density);
    if (a != b)
        return a < b;
    if (candidate.sdk != old.sdk)
        return candidate.sdk > old.sdk;
    // Unqualified and explicit mdpi have equal effective density. Prefer the
    // explicit bucket on an otherwise exact tie, independently of chunk order.
    return target.policy == ResourceSelectionPolicy::neutral_runtime && candidate.density > old.density;
}
} // namespace
ResourceTable ResourceTable::parse(Bytes bytes, std::string_view container,
                                   const ResourceConfiguration *configuration, ResourceParseOptions options) {
    const bool runtime_selection =
        configuration && configuration->policy == ResourceSelectionPolicy::neutral_runtime;
    if (runtime_selection &&
        (!configuration->density || configuration->density >= 0xfffe || !configuration->sdk))
        bad("A neutral runtime target requires an explicit numeric density and resource SDK", "UNSUPPORTED");
    const std::size_t encoded_limit = (options.metadata_preview ? 64u : 16u) * 1024 * 1024;
    if (bytes.size() > encoded_limit)
        bad(options.metadata_preview ? "Preview resource table exceeds 64 MiB limit"
                                     : "Resource table exceeds 16 MiB limit",
            "LIMIT");
    const View document(bytes, "resources");
    const auto top = chunk(document, 0);
    if (top.type != 2 || top.header != 12 || top.size != bytes.size())
        bad("Expected a complete Android resource table");
    const auto package_count = document.u32(8);
    if (!package_count || package_count > (options.metadata_preview ? 256u : 1u))
        bad("Only a single application resource package is supported", "UNSUPPORTED");
    ResourceTable result;
    result.metadata_preview_ = options.metadata_preview;
    if (configuration)
        result.configuration_ = *configuration;
    result.encoded_bytes_ = bytes.size();
    bool have_strings = false, have_package = false;
    std::set<std::uint32_t> package_ids;
    std::size_t chunks = 0;
    for (std::size_t offset = top.header; offset < bytes.size();) {
        if (++chunks > 8192)
            bad("Resource chunk quota exceeded", "LIMIT");
        const auto current = chunk(document, offset);
        const View view(document.slice(offset, current.size), "resource-package");
        if (current.type == 0x200 && options.metadata_preview) {
            if (!have_strings || current.header != 288 || !view.u32(8) || view.u32(8) > 255 ||
                !package_ids.insert(view.u32(8)).second)
                bad("Invalid or duplicate resource package header");
            // Metadata preview needs only the manifest application's fixed 0x7f
            // resources. Other feature packages remain opaque and cannot resolve
            // cross-package/dynamic references or acquire runtime admission.
            if (view.u32(8) != 0x7f) {
                offset += current.size;
                continue;
            }
        }
        if (current.type == 1 && !have_strings && !have_package) {
            result.strings_ = parse_string_pool(document.slice(offset, current.size), "resources",
                                                "RESOURCES", options.metadata_preview);
            for (const auto &text : result.strings_)
                result.decoded_bytes_ += text.size();
            have_strings = true;
        } else if (current.type == 0x200 && have_strings && !have_package) {
            have_package = true;
            if (current.header != 288 || view.u32(8) != 0x7f || view.u32(284))
                bad("Only the standard application package ID with no type offset is supported",
                    "UNSUPPORTED");
            std::wstring name;
            bool ended = false;
            for (std::size_t i = 0; i < 128; ++i) {
                const auto ch = view.u16(12 + i * 2);
                if (!ch)
                    ended = true;
                else if (ended)
                    bad("Resource package name has nonzero padding");
                else
                    name.push_back(static_cast<wchar_t>(ch));
            }
            if (!ended || name.empty())
                bad("Unterminated or empty resource package name");
            try {
                result.package_ = utf8(name);
            } catch (const std::invalid_argument &) {
                bad("Invalid Unicode package name");
            }
            const auto types_at = view.u32(268), keys_at = view.u32(276);
            if (types_at < current.header || keys_at <= types_at)
                bad("Invalid resource name-pool offsets");
            const auto types_chunk = chunk(view, types_at), keys_chunk = chunk(view, keys_at);
            if (types_chunk.type != 1 || keys_chunk.type != 1 || types_at + types_chunk.size > keys_at)
                bad("Resource name pools overlap or have wrong chunk types");
            const auto types = parse_string_pool(view.slice(types_at, types_chunk.size), "resources",
                                                 "RESOURCES", options.metadata_preview);
            const auto keys = parse_string_pool(view.slice(keys_at, keys_chunk.size), "resources",
                                                "RESOURCES", options.metadata_preview);
            if (types.size() > 255)
                bad("Too many resource type names", "LIMIT");
            const auto name_valid = [](const std::string &value, std::size_t maximum,
                                       bool compiled_key = false) {
                return !value.empty() && value.size() <= maximum &&
                       value.find_first_not_of(compiled_key
                                                   ? "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                                     "0123456789_.$"
                                                   : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                                     "0123456789_.") == std::string::npos;
            };
            const bool compiled_names = options.names == ResourceNamePolicy::compiled;
            const auto key_valid = [&](const std::string &value) {
                if (!options.metadata_preview)
                    return name_valid(value, 256, compiled_names);
                // Compiled keys may be Unicode or obfuscator labels such as
                // "(name removed)". They are bounded identities, never paths.
                return !value.empty() && value.size() <= 256 &&
                       value.find_first_of("/\\:") == std::string::npos &&
                       std::none_of(value.begin(), value.end(),
                                    [](unsigned char c) { return c < 32 || c == 127; });
            };
            if (!name_valid(result.package_, 255) ||
                std::any_of(keys.begin(), keys.end(), [&](const auto &value) { return !key_valid(value); }))
                bad("Resource package/type/key names exceed the supported identifier subset", "UNSUPPORTED");
            for (std::size_t i = 0; i < types.size(); ++i) {
                // AAPT2 fills unused type IDs with ?<decimal ID>. These are
                // holes, not names that may define or resolve a resource.
                if (!name_valid(types[i], 64) && !(compiled_names && types[i] == "?" + std::to_string(i + 1)))
                    bad("Resource package/type/key names exceed the supported identifier subset",
                        "UNSUPPORTED");
            }
            std::map<unsigned, std::uint32_t> specs;
            std::map<unsigned, std::uint16_t> declared_configurations, actual_configurations;
            std::set<unsigned> definitions;
            std::set<std::pair<unsigned, std::vector<std::uint8_t>>> configurations;
            std::map<std::uint32_t, std::uint32_t> resource_keys;
            std::size_t entry_count = 0;
            bool saw_types = false, saw_keys = false, saw_libraries = false;
            for (std::size_t at = current.header; at < current.size;) {
                if (++chunks > 8192)
                    bad("Resource chunk quota exceeded", "LIMIT");
                const auto part = chunk(view, at);
                const View item(view.slice(at, part.size), "resource-type");
                if (part.type == 1) {
                    if (at == types_at && !saw_types)
                        saw_types = true;
                    else if (at == keys_at && !saw_keys)
                        saw_keys = true;
                    else
                        bad("Unexpected resource name pool");
                } else if (part.type == 0x202) {
                    if (!saw_types || !saw_keys || part.header != 16 || item.u8(9))
                        bad("Invalid type-specification header");
                    if (!configuration && item.u16(10) > 1)
                        bad("Only one default configuration per resource type is supported", "UNSUPPORTED");
                    const auto id = item.u8(8);
                    const auto count = item.u32(12);
                    if (!id || id > types.size() || count > 65536 ||
                        part.size != 16 + std::uint64_t(count) * 4 || !specs.emplace(id, count).second)
                        bad("Invalid or duplicate type specification");
                    if (compiled_names && types[id - 1].starts_with('?'))
                        bad("A resource type placeholder cannot have a definition");
                    if (runtime_selection)
                        declared_configurations.emplace(id, item.u16(10));
                } else if (part.type == 0x201) {
                    if (part.header < 24)
                        bad("Truncated resource type header");
                    const auto id = item.u8(8), flags = item.u8(9);
                    const auto count = item.u32(12), start = item.u32(16), config_size = item.u32(20);
                    if (item.u16(10) || !specs.contains(id) || config_size < 28 || config_size > 128 ||
                        20ull + config_size != part.header)
                        bad("Resource type disagrees with its specification");
                    if (flags & ~(configuration ? 3u : 2u) || flags == 3)
                        bad("Sparse or unknown resource offset tables are unsupported", "UNSUPPORTED");
                    if ((flags & 1) ? count > specs.at(id) : count != specs.at(id))
                        bad("Resource entry count disagrees with its specification");
                    const auto config = item.slice(24, config_size - 4);
                    if (!configuration &&
                        std::any_of(config.begin(), config.end(), [](auto b) { return b != 0; }))
                        bad("Only default resource configurations are supported", "UNSUPPORTED");
                    auto config_identity = std::vector<std::uint8_t>(config.begin(), config.end());
                    if (runtime_selection) {
                        // Newer encoders append zero-valued configuration fields;
                        // padding cannot turn the same configuration into a new one.
                        while (!config_identity.empty() && config_identity.back() == 0)
                            config_identity.pop_back();
                        ++actual_configurations[id];
                    }
                    if (!configurations.emplace(id, std::move(config_identity)).second)
                        bad("Repeated resource configuration");
                    definitions.insert(id);
                    const auto density = item.u16(34), sdk = item.u16(44);
                    bool eligible = !configuration || sdk <= configuration->sdk;
                    if (configuration) {
                        // Every configuration is structurally checked. Qualifiers
                        // outside the declared neutral policy never silently win.
                        for (std::size_t i = 4; i < config_size; ++i)
                            if (i != 14 && i != 15 && i != 24 && i != 25 && item.u8(20 + i))
                                eligible = false;
                    }
                    const auto width = flags & 2 ? 2u : 4u;
                    if (start < part.header + std::uint64_t(count) * width || start > part.size ||
                        (start & 3))
                        bad("Invalid resource entry-table range");
                    std::map<std::size_t, std::size_t> ranges;
                    std::set<std::uint32_t> entry_keys;
                    std::uint32_t previous_sparse = 0;
                    for (std::uint32_t entry = 0; entry < count; ++entry) {
                        const auto table_at = part.header + std::size_t(entry) * width;
                        const auto entry_id = flags & 1 ? item.u16(table_at) : entry;
                        if ((flags & 1) &&
                            (entry_id >= specs.at(id) || (entry && entry_id <= previous_sparse)))
                            bad("Sparse resource indices must be strictly increasing and in range");
                        previous_sparse = entry_id;
                        auto relative = flags & 1    ? item.u16(table_at + 2)
                                        : width == 2 ? item.u16(table_at)
                                                     : item.u32(table_at);
                        if (++entry_count > (options.metadata_preview ? 8388608u : 262144u))
                            bad("Resource variant quota exceeded", "LIMIT");
                        if (flags & 1)
                            relative *= 4;
                        if (relative == (width == 2 ? 0xffffu : 0xffffffffu))
                            continue;
                        if (width == 2)
                            relative *= 4;
                        if ((relative & 3) || relative >= part.size - start)
                            bad("Invalid resource entry offset");
                        const auto value_at = std::size_t(start) + relative;
                        const auto entry_flags = item.u16(value_at + 2);
                        std::uint32_t key = 0, data = 0;
                        std::uint8_t value_type = 0;
                        std::size_t size = 0;
                        std::optional<Bag> bag;
                        if ((entry_flags & 1) && (configuration || options.retain_bags)) {
                            if ((entry_flags & ~7u) || item.u16(value_at) != 16)
                                bad("Invalid complex resource entry");
                            key = item.u32(value_at + 4);
                            const auto maps = item.u32(value_at + 12);
                            if (maps > 65536)
                                bad("Resource map count exceeds quota", "LIMIT");
                            size = 16 + std::size_t(maps) * 12;
                            (void)item.slice(value_at, size);
                            if (options.retain_bags) {
                                if (maps > 262144 - result.bag_items_)
                                    bad("Resource bag values exceed package quota", "LIMIT");
                                result.bag_items_ += maps;
                                result.metadata_bytes_ +=
                                    sizeof(Bag) + std::size_t(maps) * sizeof(ResourceBagItem);
                                if (result.metadata_bytes_ > 64 * 1024 * 1024)
                                    bad("Resource bag metadata exceeds 64 MiB", "LIMIT");
                                bag.emplace();
                                bag->parent = item.u32(value_at + 8);
                                bag->items.reserve(maps);
                            }
                            for (std::size_t n = 0; n < maps; ++n) {
                                const auto map = value_at + 16 + n * 12;
                                if (item.u16(map + 4) != 8 || item.u8(map + 6) ||
                                    (item.u8(map + 7) == 3 && item.u32(map + 8) >= result.strings_.size()))
                                    bad("Malformed complex resource map value");
                                if (bag)
                                    bag->items.push_back(
                                        {item.u32(map), {item.u32(map + 8), item.u8(map + 7)}});
                            }
                            if (bag) {
                                std::sort(bag->items.begin(), bag->items.end(),
                                          [](const auto &a, const auto &b) { return a.key < b.key; });
                                if (std::adjacent_find(bag->items.begin(), bag->items.end(),
                                                       [](const auto &a, const auto &b) {
                                                           return a.key == b.key;
                                                       }) != bag->items.end())
                                    bad("Duplicate complex resource map key");
                            }
                            // Frozen icon callers retain only identity. Runtime
                            // callers retain actual values in a separate bag table.
                        } else if (entry_flags & 8) {
                            if (entry_flags & 0xf1)
                                bad("Unsupported compact resource entry flags", "UNSUPPORTED");
                            key = item.u16(value_at);
                            value_type = static_cast<std::uint8_t>(entry_flags >> 8);
                            data = item.u32(value_at + 4);
                            size = 8;
                        } else {
                            if (entry_flags & ~6u)
                                bad("Complex or unknown resource entries are unsupported", "UNSUPPORTED");
                            if (item.u16(value_at) != 8 || item.u16(value_at + 8) != 8 ||
                                item.u8(value_at + 10))
                                bad("Invalid scalar resource entry");
                            key = item.u32(value_at + 4);
                            value_type = item.u8(value_at + 11);
                            data = item.u32(value_at + 12);
                            size = 16;
                        }
                        (void)item.slice(value_at, size);
                        const auto next = ranges.lower_bound(value_at);
                        const bool shared = options.metadata_preview && next != ranges.end() &&
                                            next->first == value_at && next->second == value_at + size;
                        if (!shared && ((next != ranges.end() && value_at + size > next->first) ||
                                        (next != ranges.begin() && std::prev(next)->second > value_at)))
                            bad("Resource entries overlap");
                        ranges.emplace(value_at, value_at + size);
                        if (key >= keys.size() ||
                            (!options.metadata_preview && !entry_keys.insert(key).second) ||
                            keys[key].empty() || types[id - 1].empty())
                            bad("Invalid or duplicate resource name");
                        if (value_type == 3 && data >= result.strings_.size())
                            bad("Resource string index is out of bounds");
                        if (result.entries_.size() >= (options.metadata_preview ? 131072u : 65536u))
                            bad("Resource entry quota exceeded", "LIMIT");
                        const auto resource_id = 0x7f000000u | (std::uint32_t(id) << 16) | entry_id;
                        const auto [identity, inserted] = resource_keys.emplace(resource_id, key);
                        if (!inserted && identity->second != key)
                            bad("Resource name changes across configurations");
                        result.metadata_bytes_ += sizeof(ResourceEntry) + types[id - 1].size() +
                                                  keys[key].size() + container.size();
                        if (result.metadata_bytes_ > 64 * 1024 * 1024)
                            bad("Resource identity metadata exceeds 64 MiB", "LIMIT");
                        if (eligible) {
                            ResourceEntry candidate{resource_id,   data,      value_type,
                                                    types[id - 1], keys[key], std::string(container),
                                                    density,       sdk};
                            const auto old = result.entries_.find(resource_id);
                            if (old == result.entries_.end()) {
                                result.entries_.emplace(resource_id, std::move(candidate));
                                if (bag)
                                    result.bags_.emplace(resource_id, std::move(*bag));
                            } else if (configuration && better(candidate, old->second, *configuration)) {
                                old->second = std::move(candidate);
                                if (bag)
                                    result.bags_.insert_or_assign(resource_id, std::move(*bag));
                                else
                                    result.bags_.erase(resource_id);
                            }
                        }
                    }
                } else if (part.type == 0x203 && options.metadata_preview) {
                    if (saw_libraries || part.header != 12 || item.u32(8) > 256 ||
                        part.size != 12ull + std::uint64_t(item.u32(8)) * 260)
                        bad("Invalid resource library metadata");
                    saw_libraries = true;
                    std::set<std::uint32_t> libraries;
                    std::set<std::string> library_names;
                    for (std::uint32_t i = 0; i < item.u32(8); ++i) {
                        const auto position = 12 + std::size_t(i) * 260;
                        const auto library = item.u32(position);
                        if (!library || library > 255 || !libraries.insert(library).second)
                            bad("Invalid or duplicate resource library ID");
                        std::wstring library_name;
                        bool terminated = false;
                        for (std::size_t ch = 0; ch < 128; ++ch) {
                            const auto value = item.u16(position + 4 + ch * 2);
                            if (!value)
                                terminated = true;
                            else if (terminated)
                                bad("Resource library name has nonzero padding");
                            else
                                library_name.push_back(static_cast<wchar_t>(value));
                        }
                        std::string encoded_name;
                        try {
                            encoded_name = utf8(library_name);
                        } catch (const std::invalid_argument &) {
                            bad("Invalid Unicode resource library name");
                        }
                        if (!terminated || !name_valid(encoded_name, 255) ||
                            !library_names.insert(encoded_name).second)
                            bad("Invalid or duplicate resource library name");
                    }
                    // Declaration metadata only. Dynamic references remain
                    // unsupported; no library is loaded or assigned authority.
                } else
                    bad("Unsupported resource package chunk " + std::to_string(part.type), "UNSUPPORTED");
                at += part.size;
            }
            if (!saw_types || !saw_keys || (!options.metadata_preview && specs.size() != definitions.size()))
                bad("Missing resource name pools or type definitions");
            for (const auto &[id, declared] : declared_configurations)
                if (declared && declared != actual_configurations[id])
                    bad("Resource type configuration count disagrees with its specification");
        } else
            bad("Unexpected top-level resource chunk", "UNSUPPORTED");
        offset += current.size;
    }
    if (!have_strings || !have_package)
        bad("Missing resource string pool or package");
    if (options.metadata_preview && package_ids.size() != package_count)
        bad("Resource package count disagrees with table header");
    result.chunks_ = chunks;
    return result;
}
ResourceTable ResourceTable::compose(const PackageView &package, std::string_view package_name,
                                     const ResourceConfiguration *configuration,
                                     ResourceParseOptions options) {
    ResourceTable result;
    result.metadata_preview_ = options.metadata_preview;
    const std::size_t encoded_limit = (options.metadata_preview ? 64u : 16u) * 1024 * 1024;
    if (configuration)
        result.configuration_ = *configuration;
    for (const auto &part : package.parts) {
        const auto &entries = part.archive->entries();
        const auto found = std::find_if(entries.begin(), entries.end(),
                                        [](const auto &entry) { return entry.path == "resources.arsc"; });
        if (found == entries.end())
            continue;
        if (found->directory || found->bytes > encoded_limit - result.encoded_bytes_)
            bad(options.metadata_preview ? "Combined preview resource tables exceed 64 MiB"
                                         : "Combined resource tables exceed 16 MiB",
                "LIMIT");
        auto table = parse(part.archive->read(static_cast<std::size_t>(found - entries.begin())), part.path,
                           configuration, options);
        if (table.package_name() != package_name)
            bad("Resource package identity differs from the signed manifest");
        result.merge(std::move(table));
    }
    return result;
}
void ResourceTable::merge(ResourceTable other) {
    if (metadata_preview_ != other.metadata_preview_)
        bad("Cannot compose preview and runtime resource policies", "UNSUPPORTED");
    const std::size_t encoded_limit = (metadata_preview_ ? 64u : 16u) * 1024 * 1024;
    const std::size_t string_limit = metadata_preview_ ? 262144u : 65536u;
    const bool runtime_selection =
        (configuration_ && configuration_->policy == ResourceSelectionPolicy::neutral_runtime) ||
        (other.configuration_ && other.configuration_->policy == ResourceSelectionPolicy::neutral_runtime);
    if (runtime_selection && (configuration_ || encoded_bytes_) && configuration_ != other.configuration_)
        bad("Cannot compose resource tables selected for different runtime configurations", "UNSUPPORTED");
    if (!package_.empty() && package_ != other.package_)
        bad("Resource packages disagree across APK members");
    if (other.encoded_bytes_ > encoded_limit - encoded_bytes_ ||
        other.decoded_bytes_ > 16 * 1024 * 1024 - decoded_bytes_ || other.chunks_ > 8192 - chunks_ ||
        other.entries_.size() > (metadata_preview_ ? 131072u : 65536u) - entries_.size() ||
        other.strings_.size() > string_limit - strings_.size() ||
        other.metadata_bytes_ > 64 * 1024 * 1024 - metadata_bytes_ || other.bag_items_ > 262144 - bag_items_)
        bad("Combined resource tables exceed package-wide quotas", "LIMIT");
    std::set<std::pair<std::string, std::string>> names;
    if (!metadata_preview_)
        for (const auto &[id, entry] : entries_)
            names.emplace(entry.type, entry.name);
    // Validate every identity before rebasing strings or replacing an existing
    // selection; a later conflicting split must not leave dangling string IDs.
    for (const auto &[id, entry] : other.entries_) {
        const auto found = entries_.find(id);
        if (found != entries_.end() && configuration_ && other.configuration_) {
            const auto &old = found->second;
            if (old.type != entry.type || old.name != entry.name ||
                (old.density == entry.density && old.sdk == entry.sdk))
                bad("Resource identity/configuration is ambiguous across APK members", "UNSUPPORTED");
        } else if (found != entries_.end() ||
                   (!metadata_preview_ && !names.emplace(entry.type, entry.name).second))
            bad("Default resource identity is ambiguous across APK members", "UNSUPPORTED");
    }
    for (auto &[id, entry] : other.entries_) {
        const auto incoming_bag = other.bags_.find(id);
        if (incoming_bag != other.bags_.end())
            for (auto &item : incoming_bag->second.items)
                if (item.value.type == 3)
                    item.value.data += static_cast<std::uint32_t>(strings_.size());
        const auto found = entries_.find(id);
        if (found != entries_.end() && configuration_ && other.configuration_) {
            const auto &old = found->second;
            if (entry.value_type == 3)
                entry.data += static_cast<std::uint32_t>(strings_.size());
            if (better(entry, old, *configuration_)) {
                found->second = entry;
                if (incoming_bag != other.bags_.end())
                    bags_.insert_or_assign(id, std::move(incoming_bag->second));
                else
                    bags_.erase(id);
            }
            if (incoming_bag != other.bags_.end())
                other.bags_.erase(incoming_bag);
            continue;
        }
        if (entry.value_type == 3)
            entry.data += static_cast<std::uint32_t>(strings_.size());
    }
    if (package_.empty())
        package_ = std::move(other.package_);
    if (runtime_selection && !configuration_)
        configuration_ = other.configuration_;
    strings_.insert(strings_.end(), std::make_move_iterator(other.strings_.begin()),
                    std::make_move_iterator(other.strings_.end()));
    entries_.merge(other.entries_);
    bags_.merge(other.bags_);
    bag_items_ += other.bag_items_;
    encoded_bytes_ += other.encoded_bytes_;
    decoded_bytes_ += other.decoded_bytes_;
    chunks_ += other.chunks_;
    metadata_bytes_ += other.metadata_bytes_;
}
std::uint32_t ResourceTable::identifier(std::string_view name, std::string_view type,
                                        std::string_view package) const {
    if (const auto colon = name.find(':'); colon != std::string_view::npos) {
        package = name.substr(0, colon);
        name.remove_prefix(colon + 1);
    }
    if (const auto slash = name.find('/'); slash != std::string_view::npos) {
        type = name.substr(0, slash);
        name.remove_prefix(slash + 1);
    }
    if (package != package_)
        return 0;
    std::uint32_t match = 0;
    for (const auto &[id, entry] : entries_)
        if (entry.type == type && entry.name == name) {
            if (match)
                bad("Symbolic resource name is ambiguous; use its encoded ID", "UNSUPPORTED");
            if (!metadata_preview_)
                return id;
            match = id;
        }
    return match;
}
const ResourceEntry &ResourceTable::resolve(std::uint32_t id) const {
    const auto &entry = value(id);
    if (entry.value_type != 3)
        bad("Resource is not a supported string or reference", "UNSUPPORTED");
    return entry;
}
const ResourceEntry &ResourceTable::value(std::uint32_t id) const {
    std::set<std::uint32_t> visited;
    for (unsigned depth = 0; depth < 32; ++depth) {
        const auto found = entries_.find(id);
        if (found == entries_.end()) {
            if (configuration_ && configuration_->policy == ResourceSelectionPolicy::neutral_runtime)
                bad("Resource ID has no value for neutral runtime density " +
                        std::to_string(configuration_->density) + " / resource SDK " +
                        std::to_string(configuration_->sdk) + ": " + std::to_string(id),
                    "NOT_FOUND");
            bad("Resource ID is not defined: " + std::to_string(id), "NOT_FOUND");
        }
        if (!visited.insert(id).second)
            bad("Cyclic resource reference");
        const auto &value = found->second;
        if (value.value_type != 1)
            return value;
        id = value.data;
    }
    bad("Resource reference depth exceeds 32", "LIMIT");
}
std::string_view ResourceTable::string_value(const ResourceEntry &entry) const {
    if (entry.value_type != 3 || entry.data >= strings_.size())
        bad("Resource is not a string", "UNSUPPORTED");
    return strings_[entry.data];
}
std::u16string ResourceTable::text(std::uint32_t id) const { return unicode(strings_.at(resolve(id).data)); }
std::u16string ResourceTable::text(ResourceValue value) const {
    if (value.type == 1)
        return text(value.data);
    if (value.type != 3 || value.data >= strings_.size())
        bad("Resource bag value is not a supported string or reference", "UNSUPPORTED");
    return unicode(strings_[value.data]);
}
std::vector<ResourceBagItem> ResourceTable::bag(std::uint32_t id) const {
    std::set<std::uint32_t> visited;
    std::map<std::uint32_t, ResourceValue> resolved;
    for (unsigned depth = 0; depth < 32; ++depth) {
        const auto &entry = value(id);
        if (!visited.insert(entry.id).second)
            bad("Cyclic resource bag inheritance");
        const auto found = bags_.find(entry.id);
        if (found == bags_.end())
            bad("Resource is not a retained complex value", "UNSUPPORTED");
        for (const auto &item : found->second.items) {
            // Visit children first: an existing child value overrides its parent.
            resolved.try_emplace(item.key, item.value);
            if (resolved.size() > 65536)
                bad("Resolved resource bag exceeds 65536 values", "LIMIT");
        }
        if (!found->second.parent) {
            std::vector<ResourceBagItem> result;
            result.reserve(resolved.size());
            for (const auto &[key, value] : resolved)
                result.push_back({key, value});
            return result;
        }
        id = found->second.parent;
    }
    bad("Resource bag inheritance exceeds 32 levels", "LIMIT");
}
std::string_view ResourceTable::container(std::uint32_t id) const { return resolve(id).container; }
} // namespace aether::apk
