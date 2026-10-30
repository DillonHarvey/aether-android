#pragma once
#include "aether/dex/runtime.hpp"
#include <utility>

namespace aether::android {
inline constexpr std::string_view component_type = "Landroid/content/ComponentName;";
inline constexpr std::size_t component_name_units = 4096;

// Value-object construction does not resolve, launch or authorize a component.
dex::ObjectId new_component(dex::ManagedRuntime &runtime, std::u16string_view package,
                            std::u16string_view class_name);
// Own the returned text across later metadata callbacks or managed allocations.
std::pair<std::u16string, std::u16string> component_parts(dex::ManagedRuntime &runtime,
                                                       dex::ObjectId component);
// Instance arguments include the receiver; static arguments do not.
dex::Value invoke_component(dex::ManagedRuntime &runtime, std::string_view name,
                            std::string_view signature, std::span<const dex::Value> arguments);
} // namespace aether::android
