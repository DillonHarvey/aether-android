#pragma once
#include "aether/dex/runtime.hpp"

namespace aether::android {
inline constexpr std::string_view bundle_type = "Landroid/os/Bundle;";
inline constexpr std::string_view base_bundle_type = "Landroid/os/BaseBundle;";
inline constexpr std::size_t bundle_entries = 256, bundle_key_units = 4096, bundle_all_key_units = 65536;
dex::Value invoke_bundle(dex::ManagedRuntime &runtime, std::string_view owner, std::string_view name,
                         std::string_view signature, std::span<const dex::Value> arguments);
} // namespace aether::android
