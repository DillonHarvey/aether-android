#pragma once
#include "aether/common/uri.hpp"
#include "aether/dex/runtime.hpp"

namespace aether::android {
inline constexpr std::string_view uri_type = "Landroid/net/Uri;";
inline constexpr std::string_view abstract_uri_type = "Landroid/net/Uri$AbstractHierarchicalUri;";
inline constexpr std::string_view string_uri_type = "Landroid/net/Uri$StringUri;";
inline constexpr std::size_t uri_text_units = uri::text_units;

// Lenient value parsing only; no resolution, host path interpretation or I/O.
dex::ObjectId new_uri(dex::ManagedRuntime &runtime, std::u16string_view encoded);
// Own the returned text across managed allocation or metadata callbacks.
std::u16string uri_text(dex::ManagedRuntime &runtime, dex::ObjectId uri);
// Instance arguments include the receiver; static arguments do not.
dex::Value invoke_uri(dex::ManagedRuntime &runtime, std::string_view owner, std::string_view name,
                      std::string_view signature, std::span<const dex::Value> arguments);
} // namespace aether::android
