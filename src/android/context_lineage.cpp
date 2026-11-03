#include "aether/android/context_lineage.hpp"
#include "aether/apk/inspect.hpp"

namespace aether::android {
namespace {
[[noreturn]] void reject(const char *code, const char *message) {
    throw apk::InspectError(code, "context-lineage", message);
}
} // namespace
void require_context_lineage(dex::ObjectId entry, dex::ObjectId anchor, ContextLineageAccess access) {
    if (!entry || !anchor)
        reject("AETHER_CONTEXT_LINEAGE_NULL", "Context lineage requires actual nonnull entry and anchor");
    if (!access.parent || !access.charge)
        reject("AETHER_CONTEXT_LINEAGE_OWNER", "Context lineage requires authenticated edges and the existing work owner");
    const auto next = [&](dex::ObjectId object) {
        if (object == anchor) return anchor;
        access.charge(access.owner, 1);
        const auto parent = access.parent(access.owner, object);
        if (!parent)
            reject("AETHER_CONTEXT_LINEAGE_UNSUPPORTED", "Context has no authenticated base or creation-provenance edge");
        if (!*parent)
            reject("AETHER_CONTEXT_LINEAGE_NULL", "Context lineage reaches an actual null base before its anchor");
        return *parent;
    };
    auto slow = entry, fast = entry;
    while (slow != anchor) {
        slow = next(slow);
        if (slow == anchor) return;
        fast = next(fast);
        if (fast == anchor) return;
        fast = next(fast);
        if (fast == anchor) return;
        if (slow == fast)
            reject("AETHER_CONTEXT_LINEAGE_CYCLE", "Context base/provenance chain contains a cycle");
    }
}
} // namespace aether::android
