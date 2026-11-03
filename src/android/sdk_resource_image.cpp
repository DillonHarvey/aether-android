#include "aether/android/sdk_resource_image.hpp"
#include "aether/android/sdk_resources.hpp"
#include <Windows.h>

namespace aether::android {
namespace {
apk::Bytes resource_image(const wchar_t *name, std::uint32_t expected_size) {
    const auto module = GetModuleHandleW(nullptr);
    const auto resource = FindResourceW(module, name, RT_RCDATA);
    if (!resource)
        throw apk::InspectError("AETHER_SDK_RESOURCES_UNAVAILABLE", "sdk-resources",
                                "This executable has no authenticated SDK35 resource image");
    const auto size = SizeofResource(module, resource);
    const auto loaded = LoadResource(module, resource);
    const auto *bytes = static_cast<const std::uint8_t *>(LockResource(loaded));
    if (!bytes || size != expected_size)
        throw apk::InspectError("AETHER_SDK_RESOURCES_INVALID", "sdk-resources",
                                "The embedded SDK35 resource image has an invalid extent");
    return {bytes, size};
}
struct ResourceFile {
    std::string_view path;
    const wchar_t *image_name;
    std::uint32_t bytes;
};
// These are authenticated build-input identities, not guest resource IDs or
// application-specific layout substitutes. The original binary XML is intact.
constexpr ResourceFile resource_files[]{
    {"res/layout/screen_simple.xml", L"AETHER_SDK35_LAYOUT_SCREEN_SIMPLE", 956u},
    {"res/layout/screen_simple_overlay_action_mode.xml", L"AETHER_SDK35_LAYOUT_SCREEN_SIMPLE_OVERLAY", 896u},
    {"res/layout/action_mode_bar.xml", L"AETHER_SDK35_LAYOUT_ACTION_MODE_BAR", 432u},
};
} // namespace
apk::Bytes embedded_sdk_resource_bytes() {
    return resource_image(L"AETHER_SDK35_TABLE", 17237428u);
}
std::optional<apk::Bytes> embedded_sdk_resource_file(
    std::string_view path, const std::function<void(std::uint64_t)> &charge_work) {
    if (!charge_work)
        throw apk::InspectError("AETHER_SDK_RESOURCES_STATE", "sdk-resources",
                                "Runtime SDK member access requires its existing work ledger");
    for (const auto &file : resource_files) {
        charge_work(1);
        if (path.size() != file.path.size()) continue;
        charge_work(path.size());
        if (path == file.path) return resource_image(file.image_name, file.bytes);
    }
    return std::nullopt;
}
const SdkResourceCatalog &embedded_sdk_resources() {
    static const SdkResourceCatalog catalog(embedded_sdk_resource_bytes());
    return catalog;
}
} // namespace aether::android
