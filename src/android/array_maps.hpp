#pragma once
#include "aether/dex/runtime.hpp"
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace aether::android {
inline constexpr std::string_view array_map_type="Landroid/util/ArrayMap;";
inline constexpr std::string_view android_empty_array_type="Landroid/util/EmptyArray;";
// Native backend metadata, not a fabricated SDK class or SDK allocation count.
inline constexpr std::string_view array_map_class_space_type="Laether/internal/android/ArrayMapClassSpace;";
struct ArrayMapContext {
    dex::ManagedRuntime &runtime;
    const void *session_seal;
    // One fixed retained Session root. The Session releases it once at teardown;
    // every nonzero value must have been installed by this module in this Runtime.
    dex::ObjectId &class_space_root;
};
std::optional<dex::HostClass> array_map_class(std::string_view descriptor);
// Called only by the Runtime-owned hosted initialization lifecycle. Same-owner
// recursion, completion and erroneous-class behavior remain Runtime authority.
void initialize_array_map_class(ArrayMapContext &,std::string_view descriptor);
// Creates a distinct actual ArrayMap; initialization precedes receiver allocation.
dex::ObjectId new_array_map(ArrayMapContext &,std::int32_t capacity=0,bool identity_hash=false);
// Arguments include the receiver. Only actual supported constructor bodies are
// implemented; other map operations remain explicitly unsupported.
dex::Value invoke_array_map(ArrayMapContext &,std::string_view owner,std::string_view name,
                           std::string_view signature,std::span<const dex::Value> arguments);
std::optional<dex::Value> array_map_static_field(ArrayMapContext &,std::string_view owner,
                                               std::string_view name,std::string_view type);
} // namespace aether::android
