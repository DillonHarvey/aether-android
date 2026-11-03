#pragma once
#include "aether/dex/runtime.hpp"
#include <optional>

namespace aether::android {
struct ManagedLogRecord {
    std::int32_t buffer_id = 0, priority = 3; // SDK MAIN, DEBUG.
    std::optional<std::u16string_view> tag;
    std::u16string_view message;
};
struct ManagedLogSink {
    void *owner = nullptr;
    // Trusted, synchronous, nonallocating transport only: no guest reentry,
    // managed allocation/collection, or retained record/views. A configured
    // adapter must preserve JNI modified-UTF8/default-tag semantics and charge
    // its actual payload processing to the existing provider ledger. Ordinary
    // transport errors return false; hard-budget/cancellation failures propagate.
    bool (*write)(void *, const ManagedLogRecord &) = nullptr;
};
struct ManagedLogResult {
    std::int32_t return_value = 1;
    bool transport_dropped = true;
};

// Static Log.d(String,String) arguments, without a receiver. The caller roots
// both original Strings through this call. Null tag is distinct from empty;
// null message throws before tag access. The current virtual property profile
// has no log.tag overrides: SDK VERBOSE fallback admits DEBUG. An unavailable
// sink is a real transport drop, not evidence of message delivery. Android's
// accepted-attempt return does not report the logger transport's outcome.
ManagedLogResult write_managed_debug_log(dex::ManagedRuntime &,
    std::span<const dex::Value> arguments, ManagedLogSink sink = {});
} // namespace aether::android
