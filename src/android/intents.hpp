#pragma once
#include "aether/apk/intent_value.hpp"
#include "aether/dex/runtime.hpp"

namespace aether::android {
inline constexpr std::string_view intent_type = "Landroid/content/Intent;";
inline constexpr std::size_t intent_text_units = 4096;

// Original action/component/category/raw-Uri/MIME/identifier value profile.
// No normalization, resolution, routing, extras or host authority is implied.
// Instance arguments include the receiver. Unlisted signatures are unsupported.
dex::Value intent_api(dex::ManagedRuntime &runtime, std::string_view name,
                      std::string_view signature, std::span<const dex::Value> arguments);
// Actual external launcher-root metadata: MAIN, LAUNCHER, NEW_TASK and the
// selected explicit component. Retain the result before another allocation.
dex::ObjectId make_launch_intent(dex::ManagedRuntime &runtime, std::u16string_view package,
                                std::u16string_view class_name);
// Capture only authenticated supported value storage. No guest getters,
// content-provider resolution or host authority is invoked or inferred.
apk::IntentValue capture_intent(dex::ManagedRuntime &runtime, dex::ObjectId intent);
// Validate before allocating and recreate the exact admitted values. Retain
// the returned object before another managed allocation.
dex::ObjectId materialize_intent(dex::ManagedRuntime &runtime, const apk::IntentValue &value);
// Genuine stored ComponentName identity, or null. Does not resolve a target.
dex::ObjectId intent_component(dex::ManagedRuntime &runtime, dex::ObjectId intent);
} // namespace aether::android
