#include "aether/android/managed_log.hpp"

namespace aether::android {
ManagedLogResult write_managed_debug_log(dex::ManagedRuntime &runtime,
    std::span<const dex::Value> arguments, ManagedLogSink sink) {
    if (arguments.size() != 2)
        runtime.raise("Ljava/lang/IllegalArgumentException;", u"Log.d requires tag and message Strings");
    for (const auto value : arguments)
        if (value.kind != dex::ValueKind::reference &&
            !(value.kind == dex::ValueKind::word && !value.bits))
            runtime.raise("Ljava/lang/IllegalArgumentException;", u"Log.d requires nullable reference arguments");
    if (!arguments[1].bits)
        runtime.raise("Ljava/lang/NullPointerException;", u"println needs a message");

    ManagedLogRecord record;
    record.message = runtime.string(arguments[1].bits);
    if (arguments[0].bits) record.tag = runtime.string(arguments[0].bits);
    runtime.charge_provider_work(1);
    bool delivered = false;
    if (sink.write) {
        delivered = sink.write(sink.owner, record);
    }
    // SDK35 liblog calls the selected logger and returns 1 for a loggable
    // request, independently of a failed/unavailable transport. No text is
    // retained here. The caller records the actual dropped-transport outcome.
    return {1, !delivered};
}
} // namespace aether::android
