#pragma once
#include "aether/dex/runtime.hpp"

namespace aether::android {
inline constexpr std::string_view intent_categories_type = "Landroid/util/ArraySet;";
inline constexpr std::string_view intent_categories_iterator_type = "Landroid/util/MapCollections$ArrayIterator;";
inline constexpr std::size_t intent_category_limit = 65536;

// Original bounded ArraySet profile for real Intent categories. String/null
// keys only; generic keys and unlisted bulk methods remain unsupported.
dex::ObjectId new_intent_categories(dex::ManagedRuntime &runtime);
dex::ObjectId copy_intent_categories(dex::ManagedRuntime &runtime, dex::ObjectId source);
dex::Value invoke_intent_categories(dex::ManagedRuntime &runtime, std::string_view owner,
                                   std::string_view name, std::string_view signature,
                                   std::span<const dex::Value> arguments);
} // namespace aether::android
