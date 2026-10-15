#include "aether/apk/xml.hpp"
#include "aether/common/text.hpp"
#include <algorithm>
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
};
} // namespace

ManifestInfo parse_manifest(Bytes bytes) {
    ManifestInfo result;
    bool have_root = false, have_app = false, have_sdk = false;
    std::vector<Element> stack;
    std::size_t activity_bytes = 0;
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
                    activity.permission = permission_value(attribute(attrs, "permission"));
                    activity.name = qualify(string_value(attribute(attrs, "name"), true), result.package_id);
                    if (element.name == "activity-alias")
                        activity.target = qualify(string_value(attribute(attrs, "targetActivity"), true),
                                                  result.package_id);
                    const auto charge = manifest_activity_record_bytes + activity.name.size() +
                                        activity.target.size() + activity.label.literal.size() +
                                        activity.icon.literal.size() + activity.permission.literal.size();
                    if (charge > manifest_activity_bytes - activity_bytes)
                        bad("Activity inventory exceeds 4 MiB of accounted metadata");
                    activity_bytes += charge;
                    result.activities.push_back(std::move(activity));
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

            stack.push_back(std::move(element));
        } else {
            const auto &element = stack.back();
            if (element.filter && element.activity && element.main && element.launcher)
                result.activities[*element.activity].launcher = true;
            stack.pop_back();
        }
    });
    return result;
}
} // namespace aether::apk
