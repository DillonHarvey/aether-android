#pragma once
#include "aether/dex/runtime.hpp"

namespace aether::android {
inline constexpr std::string_view bundle_type = "Landroid/os/Bundle;";
inline constexpr std::string_view base_bundle_type = "Landroid/os/BaseBundle;";
// Historical test constants only; live Bundle admission uses actual storage
// under the existing runtime heap budget rather than fixed shape allowances.
inline constexpr std::size_t bundle_entries = 256, bundle_key_units = 4096, bundle_all_key_units = 65536;
enum class BundleValueKind { integer, wide, boolean, floating, string, bundle, byte_array };
struct BundleSnapshotEntry {
    std::u16string_view key;
    bool null_key = false;
    BundleValueKind kind = BundleValueKind::integer;
    dex::Value value;
};
// Input views and references must remain rooted/stable across allocation/GC.
// actual_native_input_bytes is covered by a caller-held provider reservation;
// this function neither consumes nor releases that input reservation.
dex::ObjectId new_bundle_snapshot(dex::ManagedRuntime &runtime,
    std::span<const BundleSnapshotEntry> entries, std::size_t actual_native_input_bytes);

dex::Value invoke_bundle(dex::ManagedRuntime &runtime, std::string_view owner, std::string_view name,
                         std::string_view signature, std::span<const dex::Value> arguments);
} // namespace aether::android
