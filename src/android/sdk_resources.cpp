#include "aether/android/sdk_resources.hpp"
#include <algorithm>
#include <exception>
#include <limits>
#include <string_view>
#include <utility>

namespace aether::android {
namespace {
// A metadata-only ancestor can leave a previously selected child incomplete.
// Only this catalog's own source errors qualify; work-limit/cancellation and
// all other caller callback failures must leave the query unchanged.
struct CatalogFailure final : apk::InspectError {
    using apk::InspectError::InspectError;
};
struct WorkFailure { std::exception_ptr cause; };
[[noreturn]] void bad(std::string_view message, std::string_view kind = "INVALID") {
    throw CatalogFailure("AETHER_SDK_RESOURCES_" + std::string(kind), "sdk-resources", std::string(message));
}
struct Reader {
    apk::Bytes bytes;
    const SdkResourceWork *work = nullptr;
    void charge(std::uint64_t count) const {
        if (!work || !*work || !count) return;
        try { (*work)(count); }
        catch (...) { throw WorkFailure{std::current_exception()}; }
    }
    void range(std::size_t at, std::size_t count) const {
        if (at > bytes.size() || count > bytes.size() - at) bad("Compiled resource range exceeds its container");
    }
    std::uint8_t u8(std::size_t at) const { range(at, 1); charge(1); return bytes[at]; }
    std::uint16_t u16(std::size_t at) const {
        range(at, 2); charge(2); return static_cast<std::uint16_t>(bytes[at] | (std::uint16_t(bytes[at + 1]) << 8));
    }
    std::uint32_t u32(std::size_t at) const {
        range(at, 4); charge(4); return bytes[at] | (std::uint32_t(bytes[at + 1]) << 8) |
            (std::uint32_t(bytes[at + 2]) << 16) | (std::uint32_t(bytes[at + 3]) << 24);
    }
    Reader sub(std::size_t at, std::size_t count) const { range(at, count); return {bytes.subspan(at, count), work}; }
};
struct Chunk { std::uint16_t type, header; std::uint32_t size; };
Chunk chunk(Reader view, std::size_t at) {
    const Chunk result{view.u16(at), view.u16(at + 2), view.u32(at + 4)};
    if (result.header < 8 || result.size < result.header || ((result.header | result.size) & 3))
        bad("Invalid compiled resource chunk dimensions");
    view.range(at, result.size);
    return result;
}
std::uint32_t string_pool(Reader pool) {
    const auto head = chunk(pool, 0);
    if (head.type != 1 || head.header < 28 || head.size != pool.bytes.size()) bad("Invalid string pool header");
    const auto strings = pool.u32(8), styles = pool.u32(12), flags = pool.u32(16);
    const auto start = pool.u32(20), style_start = pool.u32(24);
    const auto table_end = std::uint64_t(head.header) + (std::uint64_t(strings) + styles) * 4;
    if ((flags & ~0x101u) || styles > strings || table_end > head.size || start < table_end ||
        start > head.size || (styles && (!style_start || style_start < start || style_start > head.size)) ||
        (!styles && style_start)) bad("Invalid string pool ranges");
    const auto strings_end = style_start ? style_start : head.size;
    for (std::uint32_t i = 0; i < strings; ++i)
        if (pool.u32(head.header + std::size_t(i) * 4) >= strings_end - start)
            bad("String offset exceeds its pool");
    for (std::uint32_t i = 0; i < styles; ++i) {
        const auto offset = pool.u32(head.header + (std::size_t(strings) + i) * 4);
        if (offset != UINT32_MAX && (offset & 3u || offset >= head.size - style_start))
            bad("String style offset exceeds its pool");
    }
    // Text/style payloads remain opaque: this catalog does not provide strings.
    return strings;
}
bool pool_name(Reader pool, std::uint32_t index, std::string_view expected) {
    const auto header = pool.u16(2);
    if (index >= pool.u32(8)) bad("Resource type name index exceeds its pool");
    std::size_t at = pool.u32(20) + pool.u32(header + std::size_t(index) * 4);
    const auto limit = pool.u32(24) ? pool.u32(24) : static_cast<std::uint32_t>(pool.bytes.size());
    if (pool.u32(16) & 0x100) {
        const auto length = [&]() {
            auto n = std::uint32_t(pool.u8(at++));
            if (n & 0x80) n = ((n & 0x7f) << 8) | pool.u8(at++);
            return n;
        };
        const auto chars = length(), bytes = length();
        if (at > limit || std::uint64_t(bytes) + 1 > limit - at || pool.u8(at + bytes))
            bad("Invalid UTF-8 resource type name range");
        if (chars != expected.size() || bytes != expected.size()) return false;
        for (std::size_t i = 0; i < expected.size(); ++i)
            if (pool.u8(at + i) != static_cast<unsigned char>(expected[i])) return false;
        return true;
    }
    auto chars = std::uint32_t(pool.u16(at)); at += 2;
    if (chars & 0x8000) { chars = ((chars & 0x7fff) << 16) | pool.u16(at); at += 2; }
    if (at > limit || (std::uint64_t(chars) + 1) * 2 > limit - at || pool.u16(at + std::size_t(chars) * 2))
        bad("Invalid UTF-16 resource type name range");
    if (chars != expected.size()) return false;
    for (std::size_t i = 0; i < expected.size(); ++i)
        if (pool.u16(at + i * 2) != static_cast<unsigned char>(expected[i])) return false;
    return true;
}
struct Configuration {
    std::uint16_t density = 0, sdk = 0, smallest = 0, width = 0, height = 0;
    std::uint8_t orientation = 0;
};
void target_valid(const apk::ResourceConfiguration &target) {
    if (!target.density || target.density >= 0xfffe || !target.sdk)
        bad("Resource selection requires a numeric density and SDK", "UNSUPPORTED");
    if (target.policy != apk::ResourceSelectionPolicy::frozen_artwork &&
        target.policy != apk::ResourceSelectionPolicy::neutral_runtime &&
        target.policy != apk::ResourceSelectionPolicy::runtime_display)
        bad("Unknown resource selection policy", "UNSUPPORTED");
    if (target.policy == apk::ResourceSelectionPolicy::runtime_display &&
        ((target.orientation != 1 && target.orientation != 2) || !target.width_dp ||
         !target.height_dp || !target.smallest_width_dp))
        bad("Display resource selection requires actual orientation and dp dimensions", "UNSUPPORTED");
}
bool eligible(Reader type, const apk::ResourceConfiguration &target, Configuration &value) {
    const auto size = type.u32(20);
    const bool display = target.policy == apk::ResourceSelectionPolicy::runtime_display;
    value.density = type.u16(34); value.sdk = type.u16(44);
    if (display) {
        value.orientation = type.u8(32);
        if (size >= 32) value.smallest = type.u16(50);
        if (size >= 36) { value.width = type.u16(52); value.height = type.u16(54); }
    }
    if (value.sdk > target.sdk) return false;
    for (std::uint32_t i = 4; i < size; ++i) {
        type.charge(1);
        const bool supported_display = display && (i == 12 || (i >= 30 && i <= 35));
        if (!supported_display && i != 14 && i != 15 && i != 24 && i != 25 && type.u8(20 + i)) return false;
    }
    return !display || ((!value.orientation || value.orientation == target.orientation) &&
        value.smallest <= target.smallest_width_dp && value.width <= target.width_dp && value.height <= target.height_dp);
}
bool better(const Configuration &candidate, const Configuration &old, const apk::ResourceConfiguration &target) {
    if (target.policy == apk::ResourceSelectionPolicy::runtime_display) {
        if (candidate.smallest != old.smallest) return candidate.smallest > old.smallest;
        const auto a = std::uint32_t(candidate.width) + candidate.height, b = std::uint32_t(old.width) + old.height;
        if (a != b) return a > b;
        if (candidate.orientation != old.orientation) return candidate.orientation > old.orientation;
    }
    const auto rank = [&](std::uint16_t density) {
        if (density == 0xfffe) return std::pair{0u, 0u};
        if (density == 0xffff && target.policy == apk::ResourceSelectionPolicy::frozen_artwork) return std::pair{1u, 0u};
        const unsigned actual = density ? density : 160u;
        return actual >= target.density ? std::pair{2u, actual - target.density} : std::pair{3u, target.density - actual};
    };
    if (rank(candidate.density) != rank(old.density)) return rank(candidate.density) < rank(old.density);
    if (candidate.sdk != old.sdk) return candidate.sdk > old.sdk;
    return target.policy != apk::ResourceSelectionPolicy::frozen_artwork && candidate.density > old.density;
}
} // namespace

SdkResourceCatalog::SdkResourceCatalog(apk::Bytes bytes) : bytes_(bytes) {
    if (bytes.size() > 64u * 1024 * 1024) bad("Compiled SDK resource table exceeds the runtime table bound", "LIMIT");
    const Reader document{bytes};
    const auto top = chunk(document, 0);
    if (top.type != 2 || top.header != 12 || top.size != bytes.size()) bad("Expected one complete resource table");
    const auto packages = document.u32(8);
    if (!packages || packages > 256) bad("Invalid resource package count");
    std::size_t chunks = 1, package_count = 0;
    std::uint64_t variants = 0;
    bool have_strings = false;
    for (std::uint32_t offset = top.header; offset < top.size;) {
        if (++chunks > maximum_chunks) bad("Resource chunk quota exceeded", "LIMIT");
        const auto part = chunk(document, offset);
        const auto view = document.sub(offset, part.size);
        if (part.type == 1 && !have_strings && !package_count) {
            strings_ = string_pool(view); strings_offset_ = offset; strings_size_ = part.size; have_strings = true;
        } else if (part.type == 0x200 && have_strings) {
            ++package_count;
            if ((part.header != 284 && part.header != 288) || !view.u32(8) || view.u32(8) > 255)
                bad("Unsupported resource package header", "UNSUPPORTED");
            const auto package_id = view.u32(8), type_offset = part.header == 288 ? view.u32(284) : 0;
            if (type_offset > 254) bad("Invalid resource type-ID offset");
            bool terminated = false, named = false;
            for (std::size_t i = 0; i < 128; ++i) {
                const auto character = view.u16(12 + i * 2);
                if (!character) terminated = true;
                else if (terminated) bad("Nonzero package-name padding");
                else named = true;
            }
            if (!terminated || !named) bad("Unterminated or empty resource package name");
            const auto types_at = view.u32(268), keys_at = view.u32(276);
            if (types_at < part.header || keys_at <= types_at) bad("Invalid package name-pool offsets");
            const auto type_pool_chunk = chunk(view, types_at), key_pool_chunk = chunk(view, keys_at);
            if (type_pool_chunk.type != 1 || key_pool_chunk.type != 1 ||
                std::uint64_t(types_at) + type_pool_chunk.size > keys_at) bad("Overlapping or invalid name pools");
            const auto type_pool = view.sub(types_at, type_pool_chunk.size);
            const auto type_names = string_pool(type_pool), keys = string_pool(view.sub(keys_at, key_pool_chunk.size));
            if (type_names > 255) bad("Resource type-name count exceeds the ID namespace");
            std::size_t current = maximum_chunks;
            std::uint32_t expected_configs = 0, actual_configs = 0;
            bool saw_types = false, saw_keys = false, saw_aliases = false;
            const auto close = [&](std::uint32_t end) {
                if (current == maximum_chunks) return;
                types_[current].end = offset + end;
                if (expected_configs && expected_configs != actual_configs) bad("Type configuration count disagrees with its specification");
                current = maximum_chunks;
            };
            for (std::uint32_t at = part.header; at < part.size;) {
                if (++chunks > maximum_chunks) bad("Resource chunk quota exceeded", "LIMIT");
                const auto item = chunk(view, at);
                const auto item_view = view.sub(at, item.size);
                if (item.type != 0x201) close(at);
                if (item.type == 1) {
                    if (at == types_at && !saw_types) saw_types = true;
                    else if (at == keys_at && !saw_keys) saw_keys = true;
                    else bad("Unexpected package name pool");
                } else if (item.type == 0x202) {
                    const auto raw_id = item_view.u8(8);
                    const auto count = item_view.u32(12);
                    if (!saw_types || !saw_keys || item.header != 16 || !raw_id || raw_id > type_names ||
                        item_view.u8(9) || count > 65536 || item.size != 16ull + std::uint64_t(count) * 4 ||
                        std::uint32_t(raw_id) + type_offset > 255) bad("Invalid type specification");
                    if (type_count_ == types_.size()) bad("Type directory exceeds the structural chunk bound", "LIMIT");
                    const auto effective_id = static_cast<std::uint8_t>(raw_id + type_offset);
                    for (std::size_t i = 0; i < type_count_; ++i)
                        if (types_[i].package == package_id && types_[i].type == effective_id)
                            bad("Overlapping package/type fragments require an explicit package-merge consumer", "UNSUPPORTED");
                    current = type_count_++;
                    types_[current] = {offset + at + item.size, offset + at + item.size, count, keys,
                        static_cast<std::uint8_t>(package_id), effective_id, pool_name(type_pool, raw_id - 1, "style")};
                    types_[current].spec_flags_offset = offset + at + 16;
                    expected_configs = item_view.u16(10); actual_configs = 0;
                } else if (item.type == 0x201) {
                    if (current == maximum_chunks || item.header < 48) bad("Type chunk has no preceding specification");
                    const auto &record = types_[current];
                    const auto flags = item_view.u8(9);
                    const auto count = item_view.u32(12), start = item_view.u32(16), config = item_view.u32(20);
                    if (item_view.u16(10) || item_view.u8(8) + type_offset != record.type ||
                        (flags & ~3u) || flags == 3 || config < 28 || config > 128 || item.header != 20 + config ||
                        ((flags & 1) ? count > record.entries : count != record.entries) ||
                        start < item.header + std::uint64_t(count) * (flags & 2 ? 2 : 4) || start > item.size || (start & 3))
                        bad("Invalid type offset table or configuration");
                    ++actual_configs;
                    std::uint32_t previous = 0;
                    for (std::uint32_t i = 0; i < count; ++i) {
                        if (++variants > 8388608) bad("Resource variant quota exceeded", "LIMIT");
                        const auto id = flags & 1 ? item_view.u16(item.header + std::size_t(i) * 4) : i;
                        if ((flags & 1) && (id >= record.entries || (i && id <= previous))) bad("Invalid sparse entry ordering");
                        previous = id;
                        const auto entry = read_entry(record, offset + at, id);
                        if (entry.status == SdkResourceStatus::absent) continue;
                        if (entry.key >= record.keys) bad("Resource key index exceeds its name pool");
                        if (entry.complex)
                            for (std::uint32_t map = 0; map < entry.maps; ++map) {
                                const auto position = entry.map_offset + std::size_t(map) * 12;
                                if (document.u16(position + 4) != 8 || document.u8(position + 6) ||
                                    (document.u8(position + 7) == 3 && document.u32(position + 8) >= strings_))
                                    bad("Invalid complex resource map value");
                            }
                    }
                } else if (item.type == 0x206) {
                    const auto count = item_view.u32(8);
                    if (saw_aliases || item.header != 12 || item.size != 12ull + std::uint64_t(count) * 8 || alias_count_ == aliases_.size())
                        bad("Invalid staged-alias table");
                    saw_aliases = true;
                    for (std::uint32_t i = 0; i < count; ++i) {
                        const auto from = item_view.u32(12 + std::size_t(i) * 8), to = item_view.u32(16 + std::size_t(i) * 8);
                        if (!(from >> 24) || !(from & 0xff0000) || !(to >> 24) || !(to & 0xff0000) ||
                            (i && from <= item_view.u32(4 + std::size_t(i) * 8))) bad("Invalid staged-alias identity or ordering");
                    }
                    aliases_[alias_count_++] = {offset + at + 12, count};
                } else if (item.type == 0x203) {
                    if (item.header != 12 || item_view.u32(8) > 256 || item.size != 12ull + std::uint64_t(item_view.u32(8)) * 260)
                        bad("Invalid resource library metadata");
                    // Declaration only: dynamic references remain unsupported.
                } else bad("Unsupported SDK package chunk", "UNSUPPORTED");
                at += item.size;
            }
            close(part.size);
            if (!saw_types || !saw_keys) bad("Package name pools are missing");
        } else bad("Unexpected top-level SDK resource chunk", "UNSUPPORTED");
        offset += part.size;
    }
    if (!have_strings || package_count != packages) bad("Resource package count disagrees with the table header");
}

std::uint32_t SdkResourceCatalog::identifier(std::string_view type, std::string_view name,
                                           const SdkResourceWork &work) const try {
    const Reader document{bytes_, &work};
    if (type.empty() || name.empty()) return 0;
    const std::string_view components[]{type, name};
    for (const auto part : components) {
        for (const char character : part) {
            document.charge(1);
            if (static_cast<unsigned char>(character) >= 0x80)
                bad("Non-ASCII SDK resource identifiers are not implemented", "UNSUPPORTED");
        }
    }
    std::uint32_t result = 0;
    const auto table = chunk(document, 0);
    for (auto offset = std::uint32_t(table.header); offset < table.size;) {
        document.charge(1);
        const auto package_chunk = chunk(document, offset);
        if (package_chunk.type == 0x200) {
            const auto package = document.sub(offset, package_chunk.size);
            const auto package_id = package.u32(8);
            const auto type_offset = package_chunk.header == 288 ? package.u32(284) : 0;
            const auto types_at = package.u32(268), keys_at = package.u32(276);
            const auto types_chunk = chunk(package, types_at), keys_chunk = chunk(package, keys_at);
            const auto type_pool = package.sub(types_at, types_chunk.size);
            const auto key_pool = package.sub(keys_at, keys_chunk.size);
            const auto type_names = type_pool.u32(8);
            for (std::uint32_t type_index = 0; type_index < type_names; ++type_index) {
                document.charge(1);
                if (!pool_name(type_pool, type_index, type)) continue;
                const auto effective_type = type_index + 1 + type_offset;
                for (std::size_t record_index = 0; record_index < type_count_; ++record_index) {
                    document.charge(1);
                    const auto &record = types_[record_index];
                    if (record.package != package_id || record.type != effective_type ||
                        record.begin < offset + package_chunk.header ||
                        record.end > offset + package_chunk.size) continue;
                    for (auto at = record.begin; at < record.end;) {
                        document.charge(1);
                        const auto head = chunk(document, at);
                        const auto view = document.sub(at, head.size);
                        const auto flags = view.u8(9);
                        const auto count = view.u32(12);
                        for (std::uint32_t slot = 0; slot < count; ++slot) {
                            document.charge(1);
                            const auto entry_id = flags & 1
                                ? std::uint32_t(view.u16(head.header + std::size_t(slot) * 4)) : slot;
                            const auto entry = read_entry(record, at, entry_id, work);
                            if (entry.status == SdkResourceStatus::absent ||
                                !pool_name(key_pool, entry.key, name)) continue;
                            const auto candidate = remap(entry.resource_id, work);
                            if (result && result != candidate)
                                bad("SDK resource name has conflicting declared identities", "UNSUPPORTED");
                            result = candidate;
                        }
                        at += head.size;
                    }
                }
            }
        }
        offset += package_chunk.size;
    }
    return result;
} catch (const WorkFailure &failure) {
    std::rethrow_exception(failure.cause);
}

std::uint32_t SdkResourceCatalog::remap(std::uint32_t id, const SdkResourceWork &work) const {
    const Reader document{bytes_, &work};
    std::array<std::uint32_t, 32> visited;
    for (std::size_t depth = 0; depth < visited.size(); ++depth) {
        document.charge(1);
        for (std::size_t previous = 0; previous < depth; ++previous) {
            document.charge(1);
            if (visited[previous] == id) bad("Cyclic staged resource alias");
        }
        visited[depth] = id;
        std::uint32_t replacement = id;
        bool matched = false;
        for (std::size_t i = 0; i < alias_count_; ++i) {
            document.charge(1);
            const auto &aliases = aliases_[i];
            if (!aliases.count || id < document.u32(aliases.offset) ||
                id > document.u32(aliases.offset + std::size_t(aliases.count - 1) * 8)) continue;
            std::uint32_t first = 0, last = aliases.count;
            while (first < last) {
                document.charge(1);
                const auto middle = first + (last - first) / 2;
                if (document.u32(aliases.offset + std::size_t(middle) * 8) < id) first = middle + 1;
                else last = middle;
            }
            if (first < aliases.count && document.u32(aliases.offset + std::size_t(first) * 8) == id) {
                const auto target = document.u32(aliases.offset + std::size_t(first) * 8 + 4);
                if (matched && replacement != target) bad("Conflicting staged resource aliases", "UNSUPPORTED");
                matched = true; replacement = target;
            }
        }
        if (replacement == id) return id;
        id = replacement;
    }
    bad("Staged aliases exceed 32 levels", "LIMIT");
}

SdkResourceCatalog::Entry SdkResourceCatalog::read_entry(const TypeRecord &record, std::uint32_t chunk_offset,
                                                        std::uint32_t entry_id, const SdkResourceWork &work) const {
    const Reader document{bytes_, &work};
    const auto head = chunk(document, chunk_offset);
    const auto view = document.sub(chunk_offset, head.size);
    const auto flags = view.u8(9);
    const auto count = view.u32(12), start = view.u32(16);
    std::uint32_t slot = entry_id, relative = 0;
    if (flags & 1) {
        std::uint32_t first = 0, last = count;
        while (first < last) {
            document.charge(1);
            const auto middle = first + (last - first) / 2;
            if (view.u16(head.header + std::size_t(middle) * 4) < entry_id) first = middle + 1;
            else last = middle;
        }
        if (first == count || view.u16(head.header + std::size_t(first) * 4) != entry_id) return {};
        slot = first; relative = view.u16(head.header + std::size_t(slot) * 4 + 2) * 4u;
    } else {
        if (slot >= count) return {};
        relative = flags & 2 ? view.u16(head.header + std::size_t(slot) * 2) : view.u32(head.header + std::size_t(slot) * 4);
        if (relative == (flags & 2 ? 0xffffu : UINT32_MAX)) return {};
        if (flags & 2) relative *= 4;
    }
    if ((relative & 3) || relative >= head.size - start) bad("Resource entry offset exceeds its type chunk");
    const auto at = std::size_t(start) + relative;
    const auto entry_flags = view.u16(at + 2);
    Entry result;
    result.status = SdkResourceStatus::found;
    result.resource_id = (std::uint32_t(record.package) << 24) | (std::uint32_t(record.type) << 16) | entry_id;
    result.style = record.style;
    result.native_flags = document.u32(record.spec_flags_offset + std::size_t(entry_id) * 4);
    if (entry_flags & 1) {
        if ((entry_flags & ~7u) || view.u16(at) != 16) bad("Invalid complex resource entry");
        result.complex = true; result.key = view.u32(at + 4); result.parent = view.u32(at + 8); result.maps = view.u32(at + 12);
        if (result.maps > 65536) bad("Resource bag exceeds the map bound", "LIMIT");
        view.range(at, 16 + std::size_t(result.maps) * 12);
        result.map_offset = chunk_offset + static_cast<std::uint32_t>(at) + 16;
    } else if (entry_flags & 8) {
        if (entry_flags & 0xf1) bad("Unsupported compact entry flags", "UNSUPPORTED");
        result.key = view.u16(at); result.value = {view.u32(at + 4), static_cast<std::uint8_t>(entry_flags >> 8)};
    } else {
        if ((entry_flags & ~6u) || view.u16(at) != 8 || view.u16(at + 8) != 8 || view.u8(at + 10))
            bad("Invalid scalar resource entry");
        result.key = view.u32(at + 4); result.value = {view.u32(at + 12), view.u8(at + 11)};
    }
    if (result.value.type == 3 && result.value.data >= strings_) bad("Resource string index exceeds the global pool");
    result.source_data = result.value.data;
    return result;
}

SdkResourceCatalog::Entry SdkResourceCatalog::lookup(std::uint32_t id, const apk::ResourceConfiguration &target,
                                                    const SdkResourceWork &work) const {
    target_valid(target);
    id = remap(id, work);
    const auto package = static_cast<std::uint8_t>(id >> 24), type = static_cast<std::uint8_t>(id >> 16);
    const auto entry_id = id & 0xffffu;
    const Reader document{bytes_, &work};
    Entry selected;
    Configuration selected_config;
    bool present = false, have_selected = false, ambiguous = false;
    for (std::size_t i = 0; i < type_count_; ++i) {
        document.charge(1);
        const auto &record = types_[i];
        if (record.package != package || record.type != type || entry_id >= record.entries) continue;
        for (auto at = record.begin; at < record.end;) {
            document.charge(1);
            const auto head = chunk(document, at);
            const auto value = read_entry(record, at, entry_id, work);
            if (value.status != SdkResourceStatus::absent) {
                present = true;
                Configuration candidate;
                if (eligible(document.sub(at, head.size), target, candidate)) {
                    if (!have_selected || better(candidate, selected_config, target)) {
                        selected = value; selected.density = candidate.density;
                        selected_config = candidate; have_selected = true; ambiguous = false;
                    } else if (!better(selected_config, candidate, target) &&
                        (selected.value.type != value.value.type || selected.value.data != value.value.data ||
                         selected.complex != value.complex || selected.parent != value.parent ||
                         selected.maps != value.maps || selected.map_offset != value.map_offset)) {
                        ambiguous = true; // No chunk-order guess for unsupported equal-rank choices.
                    }
                }
            }
            at += head.size;
        }
    }
    if ((!have_selected && present) || ambiguous) selected.status = SdkResourceStatus::unresolved;
    selected.resource_id = id;
    return selected;
}

SdkScalarResult SdkResourceCatalog::scalar(std::uint32_t id, const apk::ResourceConfiguration &target,
                                          const SdkResourceWork &work) const try {
    const auto entry = lookup(id, target, work);
    SdkScalarResult result{entry.status, entry.value, entry.complex, entry.resource_id,
                           entry.density, entry.native_flags, entry.source_data};
    if (entry.status != SdkResourceStatus::found || entry.complex) return result;
    if (entry.value.type == 3) { result.status = SdkResourceStatus::unsupported; result.value.data = 0; }
    else if (entry.value.type > 6 && (entry.value.type < 0x10 || entry.value.type > 0x1f)) result.status = SdkResourceStatus::unsupported;
    return result;
} catch (const WorkFailure &failure) {
    std::rethrow_exception(failure.cause);
}

std::u16string SdkResourceCatalog::pooled_string(std::uint32_t index, std::size_t maximum_code_units,
                                              const SdkResourceWork &work) const try {
    const auto pool = Reader{bytes_, &work}.sub(strings_offset_, strings_size_);
    if (index >= strings_) bad("Requested string index exceeds the actual global pool");
    const auto header = pool.u16(2);
    const auto style_start = pool.u32(24);
    const auto styles = pool.u32(12);
    if (index < styles) {
        const auto relative = pool.u32(header + (std::size_t(strings_) + index) * 4);
        if (relative != UINT32_MAX) {
            if ((relative & 3) || !style_start || relative >= pool.bytes.size() - style_start)
                bad("Selected style span exceeds the pool");
            if (pool.u32(std::size_t(style_start) + relative) != UINT32_MAX)
                bad("Styled pooled CharSequence spans require an actual span representation", "UNSUPPORTED");
        }
    }
    const auto string_end = style_start ? style_start : strings_size_;
    const auto text = pool.sub(0, string_end);
    std::size_t cursor = std::size_t(pool.u32(20)) + pool.u32(header + std::size_t(index) * 4);
    std::uint32_t length = 0, encoded_bytes = 0;
    const bool utf8 = (pool.u32(16) & 0x100) != 0;
    if (utf8) {
        const auto read_length = [&]() {
            auto value = std::uint32_t(text.u8(cursor++));
            if (value & 0x80) value = ((value & 0x7f) << 8) | text.u8(cursor++);
            return value;
        };
        length = read_length(); encoded_bytes = read_length();
        text.range(cursor, std::size_t(encoded_bytes) + 1);
        if (text.u8(cursor + encoded_bytes)) bad("Selected UTF-8 pool string has no terminator");
    } else {
        if (cursor & 1) bad("Selected UTF-16 pool string is not code-unit aligned");
        length = text.u16(cursor); cursor += 2;
        if (length & 0x8000) { length = ((length & 0x7fff) << 16) | text.u16(cursor); cursor += 2; }
        const auto extent = (std::uint64_t(length) + 1) * 2;
        if (extent > std::numeric_limits<std::size_t>::max()) bad("Selected string extent is not representable", "LIMIT");
        text.range(cursor, static_cast<std::size_t>(extent));
        if (text.u16(cursor + std::size_t(length) * 2)) bad("Selected UTF-16 pool string has no terminator");
    }
    if (length > maximum_code_units) bad("Selected string exceeds its caller's admitted code-unit budget", "LIMIT");
    pool.charge(length); // Actual destination code-unit initialization.
    std::u16string result(length, u'\0');
    if (utf8) {
        const auto end = cursor + encoded_bytes;
        std::size_t output = 0;
        const auto append = [&](std::uint32_t unit) {
            if (output >= result.size()) bad("UTF-8 content exceeds its declared UTF-16 length");
            pool.charge(1);
            result[output++] = static_cast<char16_t>(unit);
        };
        while (cursor < end) {
            const auto first = text.u8(cursor++);
            std::uint32_t scalar = first, minimum = 0;
            unsigned continuation = 0;
            if (first >= 0xc2 && first <= 0xdf) { scalar = first & 0x1fu; continuation = 1; minimum = 0x80; }
            else if (first >= 0xe0 && first <= 0xef) { scalar = first & 0x0fu; continuation = 2; minimum = 0x800; }
            else if (first >= 0xf0 && first <= 0xf4) { scalar = first & 7u; continuation = 3; minimum = 0x10000; }
            else if (first >= 0x80) bad("Invalid selected UTF-8 leading byte");
            if (continuation > end - cursor) bad("Truncated selected UTF-8 sequence");
            for (unsigned i = 0; i < continuation; ++i) {
                const auto next = text.u8(cursor++);
                if ((next & 0xc0) != 0x80) bad("Invalid selected UTF-8 continuation");
                scalar = (scalar << 6) | (next & 0x3fu);
            }
            if (scalar < minimum || scalar > 0x10ffff) bad("Invalid selected UTF-8 scalar");
            // AAPT may encode supplementary text either as standard UTF-8 or
            // paired CESU-8 surrogate units. Validate the final UTF16 below.
            if (scalar <= 0xffff) append(scalar);
            else {
                scalar -= 0x10000;
                append(0xd800u + (scalar >> 10)); append(0xdc00u + (scalar & 0x3ffu));
            }
        }
        if (output != result.size()) bad("Selected UTF-8 and UTF-16 lengths disagree");
    } else {
        for (std::size_t i = 0; i < result.size(); ++i) {
            pool.charge(1);
            result[i] = static_cast<char16_t>(text.u16(cursor + i * 2));
        }
    }
    for (std::size_t i = 0; i < result.size(); ++i) {
        pool.charge(1);
        const auto unit = static_cast<std::uint16_t>(result[i]);
        if (unit >= 0xd800 && unit <= 0xdbff) {
            pool.charge(1);
            if (++i == result.size() || result[i] < 0xdc00 || result[i] > 0xdfff)
                bad("Unpaired high surrogate in selected pool string");
        } else if (unit >= 0xdc00 && unit <= 0xdfff) bad("Unpaired low surrogate in selected pool string");
    }
    return result;
} catch (const WorkFailure &failure) {
    std::rethrow_exception(failure.cause);
}

apk::StyleAttributeResult SdkResourceCatalog::style_attribute(std::uint32_t style, std::uint32_t attribute,
                                                            const apk::ResourceConfiguration &target,
                                                            const SdkResourceWork &work) const {
    return style_attribute_impl(style, attribute, target, work, false);
}
apk::StyleAttributeResult SdkResourceCatalog::style_ancestry_flags(std::uint32_t style,
                                                                 const apk::ResourceConfiguration &target,
                                                                 const SdkResourceWork &work) const {
    return style_attribute_impl(style, 0, target, work, true);
}
apk::StyleAttributeResult SdkResourceCatalog::style_attribute_impl(std::uint32_t style, std::uint32_t attribute,
                                                                 const apk::ResourceConfiguration &target,
                                                                 const SdkResourceWork &work,
                                                                 bool ancestry_only) const try {
    const Reader document{bytes_, &work};
    std::array<std::uint32_t, 32> visited;
    apk::StyleAttributeResult result;
    if (!ancestry_only) attribute = remap(attribute, work);
    for (std::size_t depth = 0; depth < visited.size(); ++depth) {
        document.charge(1);
        Entry entry;
        try {
            style = remap(style, work);
        } catch (const CatalogFailure &) {
            if (!ancestry_only && result.status != apk::StyleAttributeStatus::found) throw;
            if (result.status != apk::StyleAttributeStatus::found) result.status = apk::StyleAttributeStatus::unresolved;
            result.unresolved_style = style;
            return result;
        }
        if (!style) {
            result.provenance_complete = true;
            return result;
        }
        for (std::size_t previous = 0; previous < depth; ++previous) {
            document.charge(1);
            if (visited[previous] == style) {
                if (ancestry_only || result.status == apk::StyleAttributeStatus::found) {
                    if (result.status != apk::StyleAttributeStatus::found) result.status = apk::StyleAttributeStatus::unresolved;
                    result.unresolved_style = style;
                    return result;
                }
                bad("Cyclic style inheritance or alias");
            }
        }
        visited[depth] = style;
        try {
            entry = lookup(style, target, work);
        } catch (const CatalogFailure &) {
            if (!ancestry_only && result.status != apk::StyleAttributeStatus::found) throw;
            if (result.status != apk::StyleAttributeStatus::found) result.status = apk::StyleAttributeStatus::unresolved;
            result.unresolved_style = style;
            return result;
        }
        result.native_flags |= entry.native_flags;
        const auto unresolved = [&]() {
            // A selected child's value remains conclusive even when an older
            // ancestor cannot establish complete configuration provenance.
            if (result.status != apk::StyleAttributeStatus::found)
                result.status = apk::StyleAttributeStatus::unresolved;
            result.unresolved_style = style;
            return result;
        };
        if (entry.status != SdkResourceStatus::found || !entry.style) return unresolved();
        if (!entry.complex) {
            if (entry.value.type == 1 && entry.value.data) { style = entry.value.data; continue; }
            return unresolved();
        }
        if (!ancestry_only && result.status != apk::StyleAttributeStatus::found) {
            bool found = false;
            apk::ResourceValue value;
            for (std::uint32_t i = 0; i < entry.maps; ++i) {
                document.charge(1);
                const auto at = entry.map_offset + std::size_t(i) * 12;
                if (remap(document.u32(at), work) != attribute) continue;
                if (found) return unresolved(); // No guessed precedence for duplicate canonical keys.
                found = true; value = {document.u32(at + 8), document.u8(at + 7)};
            }
            if (found) {
                result.status = apk::StyleAttributeStatus::found;
                result.value = value;
                result.source_data = value.data;
                result.source_style = entry.resource_id;
                result.source_id = 0; // The explicit SDK origin selects its actual single pool.
                result.sdk_source = true;
                result.density = entry.density;
                // Preserve the frozen scalar consumer contract. Rich consumers
                // decode the actual pool via source_data and sdk_source instead.
                if (result.value.type == 3) result.value.data = 0;
            }
        }
        style = entry.parent;
        if (!style) {
            result.provenance_complete = true;
            return result;
        }
    }
    if (ancestry_only || result.status == apk::StyleAttributeStatus::found) {
        if (result.status != apk::StyleAttributeStatus::found) result.status = apk::StyleAttributeStatus::unresolved;
        result.unresolved_style = style;
        return result;
    }
    bad("Style ancestry exceeds 32 levels", "LIMIT");
} catch (const WorkFailure &failure) {
    std::rethrow_exception(failure.cause);
}
} // namespace aether::android
