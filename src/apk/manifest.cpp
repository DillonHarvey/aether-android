#include "aether/apk/xml.hpp"
#include "aether/common/text.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <map>
#include <set>

namespace aether::apk {
namespace {
constexpr std::string_view android_ns = "http://schemas.android.com/apk/res/android";
[[noreturn]] void bad(std::string message) {
    throw InspectError("AETHER_AXML_INVALID", "manifest", std::move(message));
}
using Value = XmlValue;
using Attributes = XmlAttributes;
const Value *attribute(const Attributes &attrs, std::string name, bool android = true) {
    const auto it = attrs.find({android ? std::string(android_ns) : "", std::move(name)});
    return it == attrs.end() ? nullptr : &it->second;
}
std::string string_value(const Value *value, bool required = false) {
    if (!value) {
        if (required)
            bad("Required manifest attribute is missing");
        return {};
    }
    if (value->type != 3)
        throw InspectError("AETHER_AXML_UNSUPPORTED_VALUE", "manifest",
                           "Required manifest metadata is not a literal string");
    if (required && value->text.empty())
        bad("Required manifest string is empty");
    if (value->text.size() > 4096)
        bad("Manifest metadata string length limit exceeded");
    return value->text;
}
std::optional<std::uint32_t> integer_value(const Value *value) {
    if (!value)
        return {};
    if (value->type != 0x10 && value->type != 0x11)
        throw InspectError("AETHER_AXML_UNSUPPORTED_VALUE", "manifest",
                           "SDK or version value is not a literal integer");
    return value->data;
}
DisplayValue display_value(const Value *value) {
    if (!value)
        return {};
    if (value->text.size() > 4096)
        bad("Presentation metadata string length limit exceeded");
    return {value->type, value->data, value->text};
}
ManifestBoolean boolean_value(const Value *value) {
    return value ? ManifestBoolean{value->type, value->data} : ManifestBoolean{};
}
ManifestInteger orientation_value(const Value *value) {
    if (!value)
        return {};
    if (value->type == 3) {
        constexpr std::array<std::string_view, 16> names{
            "unspecified", "landscape", "portrait", "user", "behind", "sensor", "nosensor",
            "sensorLandscape", "sensorPortrait", "reverseLandscape", "reversePortrait",
            "fullSensor", "userLandscape", "userPortrait", "fullUser", "locked"};
        const auto found = std::find(names.begin(), names.end(), value->text);
        if (found == names.end())
            throw InspectError("AETHER_AXML_UNSUPPORTED_VALUE", "manifest",
                               "Activity screenOrientation is not a recognized Android enum name");
        const auto orientation = static_cast<std::int32_t>(found - names.begin()) - 1;
        return {0x10, std::bit_cast<std::uint32_t>(orientation)};
    }
    if (value->type == 0x10 || value->type == 0x11) {
        const auto orientation = std::bit_cast<std::int32_t>(value->data);
        if (orientation < -1 || orientation > 14)
            throw InspectError("AETHER_AXML_UNSUPPORTED_VALUE", "manifest",
                               "Activity screenOrientation integer is outside Android's -1 through 14 enum range");
    }
    return {value->type, value->data};
}
ManifestInteger config_changes_value(const Value *value) {
    if (!value)
        return {};
    if (value->type == 3) {
        struct Flag { std::string_view name; std::uint32_t value; };
        constexpr std::array flags{
            Flag{"mcc", 0x0001}, Flag{"mnc", 0x0002}, Flag{"locale", 0x0004},
            Flag{"touchscreen", 0x0008}, Flag{"keyboard", 0x0010}, Flag{"keyboardHidden", 0x0020},
            Flag{"navigation", 0x0040}, Flag{"orientation", 0x0080}, Flag{"screenLayout", 0x0100},
            Flag{"uiMode", 0x0200}, Flag{"screenSize", 0x0400}, Flag{"smallestScreenSize", 0x0800},
            Flag{"density", 0x1000}, Flag{"layoutDirection", 0x2000}, Flag{"colorMode", 0x4000},
            Flag{"grammaticalGender", 0x8000}, Flag{"fontWeightAdjustment", 0x10000000},
            Flag{"fontScale", 0x40000000}};
        if (value->text.size() > 4096)
            bad("Activity configChanges string length limit exceeded");
        std::string_view remaining = value->text;
        std::uint32_t mask = 0;
        for (;;) {
            const auto separator = remaining.find('|');
            auto name = remaining.substr(0, separator);
            const auto first = name.find_first_not_of(" \t\r\n");
            if (first != std::string_view::npos)
                name = name.substr(first, name.find_last_not_of(" \t\r\n") - first + 1);
            const auto found = std::find_if(flags.begin(), flags.end(),
                                            [&](const auto &flag) { return flag.name == name; });
            if (found == flags.end())
                throw InspectError("AETHER_AXML_UNSUPPORTED_VALUE", "manifest",
                                   "Activity configChanges contains an empty or unknown Android flag name");
            mask |= found->value;
            if (separator == std::string_view::npos)
                return {0x11, mask};
            remaining.remove_prefix(separator + 1);
        }
    }
    if ((value->type == 0x10 || value->type == 0x11) && (value->data & ~manifest_config_changes_mask))
        throw InspectError("AETHER_AXML_UNSUPPORTED_VALUE", "manifest",
                           "Activity configChanges integer contains unsupported Android flag bits");
    return {value->type, value->data};
}
DisplayValue permission_value(const Value *value) {
    return value ? display_value(value) : DisplayValue{manifest_absent_type, 0, {}};
}
std::string qualify(std::string name, const std::string &package) {
    if (name.empty())
        return name;
    if (name.front() == '.')
        return package + name;
    return name.find('.') == std::string::npos ? package + '.' + name : name;
}
struct Element {
    std::string ns;
    std::string name;
    std::optional<std::size_t> activity;
    bool main = false;
    bool launcher = false;
    bool extension = false;
    bool application = false;
    bool filter = false;
    std::optional<std::size_t> inventory_activity, inventory_filter, inventory_node;
};
} // namespace

std::size_t activity_meta_data_storage_size(
    const std::vector<std::vector<ManifestMetaDataEntry>> &rows) noexcept {
    constexpr auto exceeded = manifest_activity_bytes + 1;
    std::size_t total = 0;
    const auto charge = [&](std::size_t bytes) {
        if (bytes > manifest_activity_bytes - total) return false;
        total += bytes;
        return true;
    };
    using Row = std::vector<ManifestMetaDataEntry>;
    if (rows.capacity() > manifest_activity_bytes / sizeof(Row) ||
        !charge(rows.capacity() * sizeof(Row))) return exceeded;
    for (const auto &row : rows) {
        if (row.capacity() > manifest_activity_bytes / sizeof(ManifestMetaDataEntry) ||
            !charge(row.capacity() * sizeof(ManifestMetaDataEntry))) return exceeded;
        for (const auto &entry : row) {
            for (const auto *field : {&entry.name, &entry.value, &entry.resource}) {
                if (field->literal.capacity() >= manifest_activity_bytes ||
                    !charge(field->literal.capacity() + 1)) return exceeded;
            }
        }
    }
    return total;
}

std::size_t activity_metadata_size(const ManifestInfo &manifest) noexcept {
    constexpr auto exceeded = manifest_activity_bytes + 1;
    if (manifest.activities.size() > manifest_activity_count ||
        (!manifest.activity_config_changes.empty() &&
         manifest.activity_config_changes.size() != manifest.activities.size()) ||
        (!manifest.activity_recreate_on_config_changes.empty() &&
         manifest.activity_recreate_on_config_changes.size() != manifest.activities.size()) ||
        (!manifest.activity_native_entries.empty() &&
         manifest.activity_native_entries.size() != manifest.activities.size()) ||
        (!manifest.activity_intent_filters.empty() &&
         manifest.activity_intent_filters.size() != manifest.activities.size()) ||
        ((!manifest.activity_meta_data.empty() || manifest.activity_meta_data_bound) &&
         manifest.activity_meta_data.size() != manifest.activities.size()))
        return exceeded;
    std::size_t total = 0;
    const auto charge = [&](std::size_t amount) {
        if (amount > manifest_activity_bytes - total) return false;
        total += amount;
        return true;
    };
    if (manifest.declared_services.capacity() > manifest_activity_bytes / sizeof(std::string) ||
        !charge(manifest.declared_services.capacity() * sizeof(std::string)))
        return exceeded;
    for (const auto &service : manifest.declared_services)
        if (service.capacity() >= manifest_activity_bytes || !charge(service.capacity() + 1))
            return exceeded;
    const auto meta_data_bytes = activity_meta_data_storage_size(manifest.activity_meta_data);
    if (meta_data_bytes > manifest_activity_bytes || !charge(meta_data_bytes)) return exceeded;
    for (std::size_t index = 0; index < manifest.activities.size(); ++index) {
        const auto &activity = manifest.activities[index];
        if (!charge(manifest_activity_record_bytes + 2 * manifest_activity_config_bytes +
                    manifest_activity_native_bytes + manifest_activity_filters_bytes) ||
            !charge(activity.name.size()) || !charge(activity.target.size()) ||
            !charge(activity.label.literal.size()) || !charge(activity.icon.literal.size()) ||
            !charge(activity.permission.literal.size()))
            return exceeded;
        if (!manifest.activity_native_entries.empty()) {
            const auto &entry = manifest.activity_native_entries[index];
            if (!charge(entry.lib_name.value.literal.size()) || !charge(entry.func_name.value.literal.size()))
                return exceeded;
        }
        if (manifest.activity_intent_filters.empty()) continue;
        for (const auto &filter : manifest.activity_intent_filters[index]) {
            if (!charge(manifest_filter_record_bytes)) return exceeded;
            for (const auto &node : filter.nodes) {
                if (!charge(manifest_filter_node_bytes) || !charge(node.ns.size()) || !charge(node.name.size()))
                    return exceeded;
                for (const auto &attribute : node.attributes)
                    if (!charge(manifest_filter_attribute_bytes) || !charge(attribute.ns.size()) ||
                        !charge(attribute.name.size()) || !charge(attribute.value.literal.size()))
                        return exceeded;
            }
        }
    }
    return total;
}

ManifestInfo parse_manifest(Bytes bytes) {
    ManifestInfo result;
    result.service_inventory_bound = true;
    result.activity_meta_data_bound = true;
    bool have_root = false, have_app = false, have_sdk = false;
    std::vector<Element> stack;
    std::size_t activity_bytes = 0;
    const auto charge = [&](std::size_t amount) {
        if (amount > manifest_activity_bytes - activity_bytes)
            bad("Activity/filter inventory exceeds 4 MiB of accounted metadata");
        activity_bytes += amount;
    };
    // Grow only the new raw inventory on demand, charging actual capacities.
    // Old storage remains admitted while a replacement reserve is allocated.
    const auto reserve_meta = [&]<class T>(std::vector<T> &values) {
        if (values.size() < values.capacity()) return;
        const auto remaining = manifest_activity_bytes - activity_bytes;
        const auto admitted = remaining / sizeof(T);
        const auto previous = values.capacity();
        const auto desired = previous > manifest_activity_bytes / sizeof(T) / 2
            ? manifest_activity_bytes / sizeof(T) : std::max<std::size_t>(1, previous * 2);
        const auto requested = std::min(desired, admitted);
        if (requested <= values.size()) bad("Raw Activity metadata replacement exceeds manifest admission");
        values.reserve(requested);
        if (values.capacity() > admitted) bad("Actual raw metadata capacity exceeds simultaneous manifest admission");
        charge((values.capacity() - previous) * sizeof(T));
    };
    const auto retain_meta_field = [&](DisplayValue &target, const Value *source) {
        if (!source) return;
        const auto remaining = manifest_activity_bytes - activity_bytes;
        if (source->text.size() > target.literal.capacity() && source->text.size() >= remaining)
            bad("Raw metadata string replacement exceeds manifest admission");
        const auto previous = target.literal.capacity();
        target.literal.assign(source->text);
        if (target.literal.capacity() > previous) {
            if (target.literal.capacity() >= remaining)
                bad("Actual metadata string replacement exceeds simultaneous manifest admission");
            charge(target.literal.capacity() - previous);
        } else activity_bytes -= previous - target.literal.capacity();
        target.type = source->type;
        target.reference = source->data;
    };
    walk_binary_xml(bytes, [&](const XmlElement &node, bool start) {
        if (start) {
            Element element{node.ns, node.name, {}, false, false};
            element.extension = !element.ns.empty() || (!stack.empty() && stack.back().extension);
            // Unknown namespace/extension component forms must not become
            // proven absent metadata in the runtime's component inventory.
            if (element.extension && (element.name == "activity" || element.name == "activity-alias" ||
                                      element.name == "meta-data"))
                result.activity_meta_data_bound = false;
            const auto &attrs = node.attributes;
            const auto parent = stack.empty() ? std::string{} : stack.back().name;
            if (stack.empty()) {
                if (have_root || element.name != "manifest" || !element.ns.empty())
                    bad("Expected one manifest root");
                have_root = true;
                result.package_id = string_value(attribute(attrs, "package", false), true);
                if (result.package_id.find('.') == std::string::npos || result.package_id.front() == '.' ||
                    result.package_id.back() == '.' || result.package_id.find("..") != std::string::npos ||
                    !std::all_of(result.package_id.begin(), result.package_id.end(), [](char c) {
                        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                               c == '_' || c == '.';
                    }))
                    bad("Invalid package identifier");
                result.version_code = integer_value(attribute(attrs, "versionCode"));
                result.version_code_major = integer_value(attribute(attrs, "versionCodeMajor"));
                if (const auto *version = attribute(attrs, "versionName")) {
                    result.version_name_present = true;
                    if (version->type == 1) result.version_name_resource = version->data;
                    result.version_name = version->type == 1 ? "@resource:" + std::to_string(version->data)
                                                             : string_value(version);
                }
                result.split = string_value(attribute(attrs, "split", false));
                result.config_for_split = string_value(attribute(attrs, "configForSplit", false));
                result.required_split_types = string_value(attribute(attrs, "requiredSplitTypes"));
                result.split_types = string_value(attribute(attrs, "splitTypes"));
                result.feature_split = boolean_value(attribute(attrs, "isFeatureSplit"));
                result.isolated_splits = boolean_value(attribute(attrs, "isolatedSplits"));
                result.split_required = boolean_value(attribute(attrs, "isSplitRequired"));
            } else if (!element.extension) {
                if (element.name == "uses-sdk" && stack.size() == 1) {
                    if (have_sdk)
                        bad("Duplicate uses-sdk element");
                    have_sdk = true;
                    result.min_sdk = integer_value(attribute(attrs, "minSdkVersion"));
                    result.target_sdk = integer_value(attribute(attrs, "targetSdkVersion"));
                } else if ((element.name == "uses-permission" || element.name == "uses-permission-sdk-23") &&
                           stack.size() == 1) {
                    if (result.permissions.size() >= 1024)
                        bad("Permission count limit exceeded");
                    result.permissions.push_back(string_value(attribute(attrs, "name"), true));
                } else if (element.name == "uses-split" && stack.size() == 1) {
                    if (result.required_splits.size() >= 1024)
                        bad("Split count limit exceeded");
                    result.required_splits.push_back(string_value(attribute(attrs, "name"), true));
                } else if (element.name == "application" && stack.size() == 1) {
                    if (have_app)
                        bad("Duplicate application element");
                    have_app = true;
                    element.application = true;
                    if (const auto *value = attribute(attrs, "name")) {
                        if (value->type != 3)
                            throw InspectError("AETHER_AXML_UNSUPPORTED_VALUE", "manifest",
                                               "Application android:name is not a literal string");
                        result.application_name = qualify(string_value(value, true), result.package_id);
                    }
                    if (const auto *value = attribute(attrs, "appComponentFactory")) {
                        if (value->type != 3)
                            throw InspectError("AETHER_AXML_UNSUPPORTED_VALUE", "manifest",
                                               "Application android:appComponentFactory is not a literal string");
                        result.app_component_factory_name = qualify(string_value(value, true), result.package_id);
                    }
                    if (const auto *theme = attribute(attrs, "theme"))
                        result.application_theme = {theme->type, theme->data};
                    result.label = display_value(attribute(attrs, "label"));
                    result.icon = display_value(attribute(attrs, "icon"));
                    result.round_icon = display_value(attribute(attrs, "roundIcon"));
                    result.enabled = boolean_value(attribute(attrs, "enabled"));
                    result.has_code = boolean_value(attribute(attrs, "hasCode"));
                    result.supports_rtl = boolean_value(attribute(attrs, "supportsRtl"));
                    result.permission = permission_value(attribute(attrs, "permission"));
                    if (const auto *value = attribute(attrs, "extractNativeLibs")) {
                        if (value->type != 0x12)
                            bad("extractNativeLibs must be a boolean");
                        result.extract_native_libs = value->data != 0;
                    }
                } else if (element.name == "service" && stack.back().application) {
                    const auto *name = attribute(attrs, "name");
                    if (!name || name->type != 3 || name->text.empty() || name->text.size() > 4096) {
                        // Do not turn a declaration we cannot identify into a
                        // proven absent component or reject unrelated old paths.
                        result.service_inventory_bound = false;
                    } else {
                        const auto extra = name->text.front() == '.' ? result.package_id.size()
                            : name->text.find('.') == std::string::npos ? result.package_id.size() + 1 : 0;
                        if (extra > manifest_activity_bytes - activity_bytes ||
                            name->text.size() + 1 > manifest_activity_bytes - activity_bytes - extra)
                            bad("Service name exceeds the existing manifest metadata admission");
                        auto qualified = qualify(name->text, result.package_id);
                        charge(qualified.capacity() + 1);
                        auto &names = result.declared_services;
                        if (names.size() == names.capacity()) {
                            const auto previous = names.capacity();
                            const auto available = (manifest_activity_bytes - activity_bytes) / sizeof(std::string);
                            const auto minimum = names.size() + 1;
                            auto next = previous ? previous * 2 : std::size_t{1};
                            if (next > available) next = minimum;
                            // Reserve the full replacement while the old array
                            // is still live, then retain its actual new capacity.
                            if (next > available)
                                bad("Service inventory exceeds the existing manifest metadata admission");
                            names.reserve(next);
                            charge((names.capacity() - previous) * sizeof(std::string));
                        }
                        names.push_back(std::move(qualified));
                    }
                } else if ((element.name == "activity" || element.name == "activity-alias") &&
                           stack.back().application) {
                    if (result.activities.size() >= manifest_activity_count)
                        bad("Activity inventory exceeds 8192 declarations");
                    Activity activity;
                    activity.label = display_value(attribute(attrs, "label"));
                    activity.icon = display_value(attribute(attrs, "icon"));
                    activity.enabled = boolean_value(attribute(attrs, "enabled"));
                    activity.exported = boolean_value(attribute(attrs, "exported"));
                    if (element.name == "activity") {
                        activity.screen_orientation = orientation_value(attribute(attrs, "screenOrientation"));
                        if (const auto *theme = attribute(attrs, "theme"))
                            activity.theme = {theme->type, theme->data};
                    }
                    const auto config_changes = element.name == "activity"
                        ? config_changes_value(attribute(attrs, "configChanges")) : ManifestInteger{};
                    const auto recreate_changes = element.name == "activity"
                        ? config_changes_value(attribute(attrs, "recreateOnConfigChanges")) : ManifestInteger{};
                    activity.permission = permission_value(attribute(attrs, "permission"));
                    activity.name = qualify(string_value(attribute(attrs, "name"), true), result.package_id);
                    if (element.name == "activity-alias")
                        activity.target = qualify(string_value(attribute(attrs, "targetActivity"), true),
                                                  result.package_id);
                    charge(manifest_activity_record_bytes + 2 * manifest_activity_config_bytes +
                           manifest_activity_native_bytes + manifest_activity_filters_bytes);
                    charge(activity.name.size());
                    charge(activity.target.size());
                    charge(activity.label.literal.size());
                    charge(activity.icon.literal.size());
                    charge(activity.permission.literal.size());
                    result.activities.push_back(std::move(activity));
                    result.activity_config_changes.push_back(config_changes);
                    result.activity_recreate_on_config_changes.push_back(recreate_changes);
                    reserve_meta(result.activity_meta_data);
                    result.activity_meta_data.emplace_back();
                    result.activity_native_entries.emplace_back();
                    result.activity_intent_filters.emplace_back();
                    element.activity = result.activities.size() - 1;
                } else if (element.name == "meta-data" &&
                           (parent == "activity" || parent == "activity-alias") && stack.back().activity) {
                    auto &raw = result.activity_meta_data[*stack.back().activity];
                    reserve_meta(raw);
                    raw.emplace_back();
                    auto &retained_raw = raw.back();
                    for (const auto *field : {&retained_raw.name, &retained_raw.value, &retained_raw.resource})
                        charge(field->literal.capacity() + 1);
                    retain_meta_field(retained_raw.name, attribute(attrs, "name"));
                    retain_meta_field(retained_raw.value, attribute(attrs, "value"));
                    retain_meta_field(retained_raw.resource, attribute(attrs, "resource"));
                    const auto *name = attribute(attrs, "name");
                    auto &entry = result.activity_native_entries[*stack.back().activity];
                    if (!name || name->type != 3) {
                        entry.unresolved_name = true;
                    } else if (name->text == "android.app.lib_name" || name->text == "android.app.func_name") {
                        auto &retained = name->text == "android.app.lib_name" ? entry.lib_name : entry.func_name;
                        const auto *resource = attribute(attrs, "resource");
                        const auto *value = resource ? resource : attribute(attrs, "value");
                        // A supplied key without a value is not an absent key.
                        // Android's Bundle replacement semantics retain the last
                        // declaration, without accumulating discarded strings.
                        auto replacement = ManifestNativeValue{value ? display_value(value) : DisplayValue{},
                                                               resource != nullptr};
                        activity_bytes -= retained.value.literal.size();
                        charge(replacement.value.literal.size());
                        retained = std::move(replacement);
                    }
                } else if (element.name == "intent-filter" &&
                           (parent == "activity" || parent == "activity-alias") && stack.back().activity) {
                    element.activity = stack.back().activity;
                    element.filter = true;
                    result.activities[*element.activity].intent_filter = true;
                } else if (stack.back().filter) {
                    const auto name = string_value(attribute(attrs, "name"));
                    if (element.name == "action" && name == "android.intent.action.MAIN")
                        stack.back().main = true;
                    if (element.name == "category" && name == "android.intent.category.LAUNCHER")
                        stack.back().launcher = true;
                }
            }

            if (element.filter) {
                const auto activity = *element.activity;
                auto &filters = result.activity_intent_filters[activity];
                charge(manifest_filter_record_bytes);
                filters.emplace_back();
                element.inventory_activity = activity;
                element.inventory_filter = filters.size() - 1;
            } else if (!stack.empty() && stack.back().inventory_filter) {
                element.inventory_activity = stack.back().inventory_activity;
                element.inventory_filter = stack.back().inventory_filter;
            }
            if (element.inventory_filter) {
                auto &filter = result.activity_intent_filters[*element.inventory_activity][*element.inventory_filter];
                charge(manifest_filter_node_bytes);
                charge(node.ns.size());
                charge(node.name.size());
                ManifestFilterNode retained;
                retained.ns = node.ns;
                retained.name = node.name;
                if (!element.filter) retained.parent = stack.back().inventory_node;
                for (const auto &[identity, value] : attrs) {
                    charge(manifest_filter_attribute_bytes);
                    charge(identity.first.size());
                    charge(identity.second.size());
                    charge(value.text.size());
                    retained.attributes.push_back({identity.first, identity.second,
                                                   {value.type, value.data, value.text}});
                }
                filter.nodes.push_back(std::move(retained));
                element.inventory_node = filter.nodes.size() - 1;
            }
            stack.push_back(std::move(element));
        } else {
            const auto &element = stack.back();
            if (element.filter && element.activity && element.main && element.launcher)
                result.activities[*element.activity].launcher = true;
            stack.pop_back();
        }
    });
    if (activity_metadata_size(result) != activity_bytes)
        bad("Activity/filter metadata accounting is inconsistent");
    return result;
}
} // namespace aether::apk
