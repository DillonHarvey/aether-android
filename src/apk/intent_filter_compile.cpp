#include "aether/apk/intent_filter.hpp"
#include "aether/common/java_char.hpp"
#include "aether/common/text.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <limits>
#include <set>

namespace aether::apk {
namespace {
constexpr std::string_view android_ns = "http://schemas.android.com/apk/res/android";
constexpr auto exceeded = manifest_activity_bytes + 1;
[[noreturn]] void invalid(std::string_view message) {
    throw InspectError("AETHER_INTENT_FILTER_INVALID", "intent-filter", std::string(message));
}
[[noreturn]] void limit(std::string_view message) {
    throw InspectError("AETHER_INTENT_FILTER_LIMIT", "intent-filter", std::string(message));
}
struct Account {
    std::size_t bytes = 0;
    void add(std::size_t count, std::size_t width = 1) noexcept {
        if (bytes > manifest_activity_bytes || count > (manifest_activity_bytes - bytes) / width) bytes = exceeded;
        else bytes += count * width;
    }
    void text(const std::u16string &value) noexcept {
        if (value.capacity() == std::numeric_limits<std::size_t>::max()) bytes = exceeded;
        else add(value.capacity() + 1, sizeof(char16_t));
    }
};
void issue(CompiledIntentFilter &filter, IntentFilterIssue value) noexcept {
    if (filter.issue == IntentFilterIssue::none) filter.issue = value;
}
std::u16string unicode(std::string_view value) {
    try {
        const auto wide = utf16(value);
        return {wide.begin(), wide.end()};
    } catch (const std::invalid_argument &) { invalid("Filter metadata is not valid UTF-8"); }
}
const DisplayValue *attribute(const ManifestFilterNode &node, std::string_view name) {
    for (const auto &entry : node.attributes)
        if (entry.ns == android_ns && entry.name == name) return &entry.value;
    return nullptr;
}
bool resource(const DisplayValue &value) noexcept {
    return value.type == 1 || value.type == 2 || value.type == 7 || value.type == 8;
}
std::string hex(std::uint32_t value) {
    std::array<char, 8> buffer{};
    const auto converted = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value, 16);
    return {buffer.data(), converted.ptr};
}
std::optional<std::u16string> string_attribute(CompiledIntentFilter &filter, const DisplayValue *value,
                                             bool raw_name = false) {
    if (!value) return {};
    if (value->type == 0) {
        if (raw_name) issue(filter, IntentFilterIssue::typed_value);
        return {};
    }
    if (resource(*value)) { issue(filter, IntentFilterIssue::resource); return {}; }
    if (value->type == 3) return unicode(value->literal);
    // Action/category names come from XmlResourceParser.getAttributeValue,
    // rather than TypedArray's resource-resolving string accessor. The retained
    // representation does not preserve non-String raw lexemes; do not invent one.
    if (raw_name) { issue(filter, IntentFilterIssue::typed_value); return {}; }
    if (value->type >= 0x10 && value->type <= 0x1f) {
        if (value->type == 0x11) return unicode("0x" + hex(value->reference));
        if (value->type == 0x12) return value->reference ? u"true" : u"false";
        if (value->type >= 0x1c) return unicode("#" + hex(value->reference));
        return unicode(std::to_string(std::bit_cast<std::int32_t>(value->reference)));
    }
    issue(filter, IntentFilterIssue::typed_value);
    return {};
}
std::optional<std::int32_t> parse_radix(std::u16string_view value, unsigned radix) {
    if (radix == 10) return java_char::parse_int32(value);
    if (value.empty()) return {};
    const bool negative = value.front() == u'-';
    auto at = negative || value.front() == u'+' ? std::size_t{1} : std::size_t{0};
    if (at == value.size()) return {};
    const auto maximum = negative ? std::uint64_t{0x80000000u} : std::uint64_t{0x7fffffffu};
    std::uint64_t magnitude = 0;
    for (; at < value.size(); ++at) {
        const auto unit = value[at];
        unsigned digit = radix;
        if (unit >= u'A' && unit <= u'Z') digit = static_cast<unsigned>(unit - u'A') + 10;
        else if (unit >= u'a' && unit <= u'z') digit = static_cast<unsigned>(unit - u'a') + 10;
        else if (unit >= u'\uff21' && unit <= u'\uff3a') digit = static_cast<unsigned>(unit - u'\uff21') + 10;
        else if (unit >= u'\uff41' && unit <= u'\uff5a') digit = static_cast<unsigned>(unit - u'\uff41') + 10;
        else if (const auto decimal = java_char::parse_int32(std::u16string_view(&unit, 1)); decimal && *decimal >= 0)
            digit = static_cast<unsigned>(*decimal);
        if (digit >= radix || magnitude > (maximum - digit) / radix) return {};
        magnitude = magnitude * radix + digit;
    }
    auto bits = static_cast<std::uint32_t>(magnitude);
    if (negative) bits = std::uint32_t{0} - bits;
    return std::bit_cast<std::int32_t>(bits);
}
std::int32_t xml_integer(std::u16string_view value, std::int32_t fallback) {
    if (value.empty()) return fallback;
    const bool negate = value.front() == u'-';
    auto at = negate ? std::size_t{1} : std::size_t{0};
    if (at == value.size()) invalid("Filter numeric attribute has no digits");
    unsigned radix = 10;
    if (value[at] == u'0') {
        if (at + 1 == value.size()) return 0;
        if (value[at + 1] == u'x' || value[at + 1] == u'X') { at += 2; radix = 16; }
        else { ++at; radix = 8; }
    } else if (value[at] == u'#') { ++at; radix = 16; }
    const auto parsed = parse_radix(value.substr(at), radix);
    if (!parsed) invalid("Filter numeric attribute is not an Android XmlUtils integer");
    auto bits = std::bit_cast<std::uint32_t>(*parsed);
    if (negate) bits = std::uint32_t{0} - bits;
    return std::bit_cast<std::int32_t>(bits);
}
std::int32_t integer_attribute(CompiledIntentFilter &filter, const DisplayValue *value, std::int32_t fallback) {
    if (!value || value->type == 0) return fallback;
    if (resource(*value)) { issue(filter, IntentFilterIssue::resource); return fallback; }
    if (value->type >= 0x10 && value->type <= 0x1f) return std::bit_cast<std::int32_t>(value->reference);
    if (value->type == 3) return xml_integer(unicode(value->literal), fallback);
    issue(filter, IntentFilterIssue::typed_value);
    return fallback;
}
bool boolean_attribute(CompiledIntentFilter &filter, const DisplayValue *value, bool fallback) {
    if (!value || value->type == 0) return fallback;
    if (resource(*value)) { issue(filter, IntentFilterIssue::resource); return fallback; }
    if (value->type >= 0x10 && value->type <= 0x1f) return value->reference != 0;
    const auto text = string_attribute(filter, value);
    if (!text || text->empty()) return fallback;
    return *text == u"1" || *text == u"true" || *text == u"TRUE";
}
void known_attributes(CompiledIntentFilter &filter, const ManifestFilterNode &node,
                       std::span<const std::string_view> names) {
    for (const auto &entry : node.attributes)
        if (entry.ns != android_ns || std::find(names.begin(), names.end(), entry.name) == names.end())
            issue(filter, IntentFilterIssue::extension);
}
void validate_tree(const ManifestIntentFilter &filter) {
    if (filter.nodes.empty() || filter.nodes[0].parent || filter.nodes[0].name != "intent-filter" || !filter.nodes[0].ns.empty())
        invalid("Filter inventory requires one unqualified intent-filter root with no parent");
    Account raw;
    raw.add(manifest_filter_record_bytes);
    std::vector<std::size_t> ancestry;
    for (std::size_t index = 0; index < filter.nodes.size(); ++index) {
        const auto &node = filter.nodes[index];
        if (index) {
            if (!node.parent || *node.parent >= index) invalid("Filter node parent is absent, forward or out of range");
            while (!ancestry.empty() && ancestry.back() != *node.parent) ancestry.pop_back();
            if (ancestry.empty()) invalid("Filter nodes are not in original subtree order");
        }
        ancestry.push_back(index);
        if (ancestry.size() > 128 || node.attributes.size() > 256) invalid("Filter inventory exceeds original XML structural bounds");
        raw.add(manifest_filter_node_bytes);
        raw.add(node.ns.size()); raw.add(node.name.size());
        std::set<std::pair<std::string_view, std::string_view>> identities;
        for (const auto &entry : node.attributes) {
            if (entry.value.type > 0xff || !identities.emplace(entry.ns, entry.name).second)
                invalid("Filter attribute has an invalid encoded type or duplicate namespace/name");
            raw.add(manifest_filter_attribute_bytes);
            raw.add(entry.ns.size()); raw.add(entry.name.size()); raw.add(entry.value.literal.size());
        }
        if (raw.bytes > manifest_activity_bytes) limit("Raw filter exceeds the existing 4 MiB manifest metadata bound");
    }
}
void unique(std::vector<std::u16string> &values, std::u16string value) {
    if (std::find(values.begin(), values.end(), value) == values.end()) values.push_back(std::move(value));
}
struct PatternAttribute { std::string_view name; IntentPatternType type; };
constexpr std::array patterns{
    PatternAttribute{"", IntentPatternType::literal}, PatternAttribute{"Prefix", IntentPatternType::prefix},
    PatternAttribute{"Pattern", IntentPatternType::simple_glob}, PatternAttribute{"AdvancedPattern", IntentPatternType::advanced_glob},
    PatternAttribute{"Suffix", IntentPatternType::suffix}};
void ordinary_data(CompiledIntentFilter &result, const ManifestFilterNode &node) {
    if (auto mime = string_attribute(result, attribute(node, "mimeType"))) {
        const auto slash = mime->find(u'/');
        if (slash == mime->npos || slash == 0 || mime->size() < slash + 2) invalid("Filter MIME type has no nonempty type/subtype");
        const bool partial = mime->size() == slash + 2 && mime->back() == u'*';
        if (partial) mime->resize(slash);
        if (std::find(result.types.begin(), result.types.end(), *mime) == result.types.end()) {
            result.types.push_back(std::move(*mime));
            result.partial_types = result.partial_types || partial;
        }
    }
    if (string_attribute(result, attribute(node, "mimeGroup"))) issue(result, IntentFilterIssue::mime_group);
    if (auto scheme = string_attribute(result, attribute(node, "scheme"))) unique(result.schemes, std::move(*scheme));
    for (const auto &pattern : patterns) {
        const auto name = "ssp" + std::string(pattern.name);
        if (auto value = string_attribute(result, attribute(node, name))) result.scheme_specific_parts.emplace_back(*value, pattern.type);
    }
    auto host = string_attribute(result, attribute(node, "host"));
    auto port = string_attribute(result, attribute(node, "port"));
    if (host) {
        IntentAuthority authority;
        authority.wildcard = !host->empty() && host->front() == u'*';
        if (authority.wildcard) host->erase(0, 1);
        authority.host = std::move(*host);
        if (port) {
            const auto parsed = java_char::parse_int32(*port);
            if (!parsed) invalid("Filter authority port is not a signed Java int");
            authority.port = *parsed;
        }
        result.authorities.push_back(std::move(authority));
    }
    for (const auto &pattern : patterns) {
        const auto name = "path" + std::string(pattern.name);
        if (auto value = string_attribute(result, attribute(node, name))) result.paths.emplace_back(*value, pattern.type);
    }
    static constexpr std::array<std::string_view, 15> names{
        "mimeType", "mimeGroup", "scheme", "ssp", "sspPrefix", "sspPattern", "sspAdvancedPattern", "sspSuffix",
        "host", "port", "path", "pathPrefix", "pathPattern", "pathAdvancedPattern", "pathSuffix"};
    known_attributes(result, node, names);
}
void relative_data(CompiledIntentFilter &result, IntentRelativeGroup &group, const ManifestFilterNode &node) {
    static constexpr std::array<std::pair<std::string_view, IntentRelativePart>, 3> parts{{
        {"path", IntentRelativePart::path}, {"fragment", IntentRelativePart::fragment}, {"query", IntentRelativePart::query}}};
    for (const auto &[part_name, part] : parts)
        for (const auto &pattern : patterns) {
            const auto name = std::string(part_name) + std::string(pattern.name);
            if (auto value = string_attribute(result, attribute(node, name)))
                group.conditions.push_back({part, IntentPattern(*value, pattern.type)});
        }
    for (const auto &entry : node.attributes) {
        bool known = false;
        if (entry.ns == android_ns)
            for (const auto &[part_name, part] : parts) {
                (void)part;
                for (const auto &pattern : patterns)
                    if (entry.name == std::string(part_name) + std::string(pattern.name)) known = true;
            }
        if (!known) issue(result, IntentFilterIssue::extension);
    }
}
} // namespace

std::size_t CompiledIntentFilter::accounted_bytes() const noexcept {
    Account total;
    total.add(sizeof(*this));
    for (const auto *values : {&actions, &categories, &types, &schemes}) {
        total.add(values->capacity(), sizeof(std::u16string));
        for (const auto &value : *values) total.text(value);
    }
    total.add(authorities.capacity(), sizeof(IntentAuthority));
    for (const auto &authority : authorities) total.text(authority.host);
    const auto patterns_account = [&](const std::vector<IntentPattern> &values) {
        total.add(values.capacity(), sizeof(IntentPattern));
        for (const auto &pattern : values) {
            const auto bytes = pattern.accounted_bytes();
            if (bytes < sizeof(IntentPattern)) total.bytes = exceeded;
            else total.add(bytes - sizeof(IntentPattern));
        }
    };
    patterns_account(scheme_specific_parts); patterns_account(paths);
    total.add(relative_groups.capacity(), sizeof(IntentRelativeGroup));
    for (const auto &group : relative_groups) {
        total.add(group.conditions.capacity(), sizeof(IntentRelativeCondition));
        for (const auto &condition : group.conditions) {
            const auto bytes = condition.pattern.accounted_bytes();
            if (bytes < sizeof(IntentPattern)) total.bytes = exceeded;
            else total.add(bytes - sizeof(IntentPattern));
        }
    }
    return total.bytes;
}
CompiledIntentFilter compile_intent_filter(const ManifestIntentFilter &filter, const IntentFilterPolicy &policy) {
    validate_tree(filter);
    CompiledIntentFilter result;
    result.relative_reference_groups = policy.relative_reference_groups.value_or(false);
    std::vector<bool> skipped(filter.nodes.size());
    std::vector<std::optional<std::size_t>> group_indices(filter.nodes.size());
    for (std::size_t index = 0; index < filter.nodes.size(); ++index) {
        const auto &node = filter.nodes[index];
        if (index && skipped[*node.parent]) { skipped[index] = true; continue; }
        if (!node.ns.empty()) {
            issue(result, IntentFilterIssue::extension);
            skipped[index] = true;
            continue;
        }
        if (attribute(node, "featureFlag")) {
            issue(result, IntentFilterIssue::feature_policy);
            skipped[index] = true;
            continue;
        }
        if (index == 0) {
            result.priority = integer_attribute(result, attribute(node, "priority"), 0);
            result.order = integer_attribute(result, attribute(node, "order"), 0);
            result.auto_verify = boolean_attribute(result, attribute(node, "autoVerify"), false);
            static constexpr std::array<std::string_view, 6> names{"priority", "order", "autoVerify", "label", "icon", "roundIcon"};
            known_attributes(result, node, names);
        } else if (*node.parent == 0 && (node.name == "action" || node.name == "category")) {
            const auto value = attribute(node, "name");
            if (!value) invalid("Filter action/category requires android:name");
            if (auto name = string_attribute(result, value, true)) {
                if (name->empty() && policy.target_sdk >= 30) invalid("Target SDK30 or later rejects empty filter action/category names");
                unique(node.name == "action" ? result.actions : result.categories, std::move(*name));
            }
            static constexpr std::array<std::string_view, 1> names{"name"};
            known_attributes(result, node, names);
        } else if (*node.parent == 0 && node.name == "data") ordinary_data(result, node);
        else if (*node.parent == 0 && node.name == "uri-relative-filter-group") {
            if (!policy.relative_reference_groups) {
                issue(result, IntentFilterIssue::feature_policy);
                skipped[index] = true;
                continue;
            }
            if (!*policy.relative_reference_groups) { skipped[index] = true; continue; }
            IntentRelativeGroup group;
            group.allow = boolean_attribute(result, attribute(node, "allow"), true);
            static constexpr std::array<std::string_view, 1> names{"allow"};
            known_attributes(result, node, names);
            group_indices[index] = result.relative_groups.size();
            result.relative_groups.push_back(std::move(group));
        } else if (node.name == "data" && group_indices[*node.parent])
            relative_data(result, result.relative_groups[*group_indices[*node.parent]], node);
        else {
            issue(result, IntentFilterIssue::extension);
            skipped[index] = true;
        }
        if (result.accounted_bytes() > manifest_activity_bytes) limit("Compiled filter exceeds the existing 4 MiB metadata bound");
    }
    std::erase_if(result.relative_groups, [](const auto &group) { return group.conditions.empty(); });
    if (result.accounted_bytes() > manifest_activity_bytes) limit("Compiled filter exceeds the existing 4 MiB metadata bound");
    return result;
}
std::string_view intent_filter_issue_name(IntentFilterIssue value) noexcept {
    switch (value) {
    case IntentFilterIssue::none: return "none";
    case IntentFilterIssue::resource: return "resource";
    case IntentFilterIssue::typed_value: return "typed-value";
    case IntentFilterIssue::feature_policy: return "feature-policy";
    case IntentFilterIssue::extension: return "extension";
    case IntentFilterIssue::mime_group: return "mime-group";
    }
    return "invalid";
}
} // namespace aether::apk
