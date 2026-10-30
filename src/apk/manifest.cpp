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

std::size_t activity_metadata_size(const ManifestInfo &manifest) noexcept {
    constexpr auto exceeded = manifest_activity_bytes + 1;
    if (manifest.activities.size() > manifest_activity_count ||
        (!manifest.activity_config_changes.empty() &&
         manifest.activity_config_changes.size() != manifest.activities.size()) ||
        (!manifest.activity_intent_filters.empty() &&
         manifest.activity_intent_filters.size() != manifest.activities.size()))
        return exceeded;
    std::size_t total = 0;
    const auto charge = [&](std::size_t amount) {
        if (amount > manifest_activity_bytes - total) return false;
        total += amount;
        return true;
    };
    for (std::size_t index = 0; index < manifest.activities.size(); ++index) {
        const auto &activity = manifest.activities[index];
        if (!charge(manifest_activity_record_bytes + manifest_activity_config_bytes + manifest_activity_filters_bytes) ||
            !charge(activity.name.size()) || !charge(activity.target.size()) ||
            !charge(activity.label.literal.size()) || !charge(activity.icon.literal.size()) ||
            !charge(activity.permission.literal.size()))
            return exceeded;
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
    bool have_root = false, have_app = false, have_sdk = false;
    std::vector<Element> stack;
    std::size_t activity_bytes = 0;
    const auto charge = [&](std::size_t amount) {
        if (amount > manifest_activity_bytes - activity_bytes)
            bad("Activity/filter inventory exceeds 4 MiB of accounted metadata");
        activity_bytes += amount;
    };
    walk_binary_xml(bytes, [&](const XmlElement &node, bool start) {
        if (start) {
            Element element{node.ns, node.name, {}, false, false};
            element.extension = !element.ns.empty() || (!stack.empty() && stack.back().extension);
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
                    result.label = display_value(attribute(attrs, "label"));
                    result.icon = display_value(attribute(attrs, "icon"));
                    result.round_icon = display_value(attribute(attrs, "roundIcon"));
                    result.enabled = boolean_value(attribute(attrs, "enabled"));
                    result.has_code = boolean_value(attribute(attrs, "hasCode"));
                    result.permission = permission_value(attribute(attrs, "permission"));
                    if (const auto *value = attribute(attrs, "extractNativeLibs")) {
                        if (value->type != 0x12)
                            bad("extractNativeLibs must be a boolean");
                        result.extract_native_libs = value->data != 0;
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
                    if (element.name == "activity")
                        activity.screen_orientation = orientation_value(attribute(attrs, "screenOrientation"));
                    const auto config_changes = element.name == "activity"
                        ? config_changes_value(attribute(attrs, "configChanges")) : ManifestInteger{};
                    activity.permission = permission_value(attribute(attrs, "permission"));
                    activity.name = qualify(string_value(attribute(attrs, "name"), true), result.package_id);
                    if (element.name == "activity-alias")
                        activity.target = qualify(string_value(attribute(attrs, "targetActivity"), true),
                                                  result.package_id);
                    charge(manifest_activity_record_bytes + manifest_activity_config_bytes + manifest_activity_filters_bytes);
                    charge(activity.name.size());
                    charge(activity.target.size());
                    charge(activity.label.literal.size());
                    charge(activity.icon.literal.size());
                    charge(activity.permission.literal.size());
                    result.activities.push_back(std::move(activity));
                    result.activity_config_changes.push_back(config_changes);
                    result.activity_intent_filters.emplace_back();
                    element.activity = result.activities.size() - 1;
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
