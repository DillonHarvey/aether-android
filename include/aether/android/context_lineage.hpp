#pragma once
#include "aether/dex/runtime.hpp"
#include <optional>

namespace aether::android {
struct ContextLineageAccess {
    void *owner = nullptr;
    // Return only an authenticated stored-base/creation-provenance edge.
    // nullopt is unsupported provenance; an engaged zero is an actual null
    // base. No guest override or package-name equality can supply this proof.
    std::optional<dex::ObjectId> (*parent)(void *, dex::ObjectId) = nullptr;
    void (*charge)(void *, std::uint64_t) = nullptr;
};
// Caller roots entry/anchor and their traced chain throughout this operation.
// Edges must remain unchanged; callbacks do not invoke guests or mutate them.
// Every actual edge inspection is charged to the existing work owner. Budget
// and reader exceptions propagate unchanged; no allowance or heap is created.
// Success proves only the supplied authenticated lineage, not Activity/native
// admission or an implemented Context API. Cycles use constant-space detection.
void require_context_lineage(dex::ObjectId entry, dex::ObjectId anchor, ContextLineageAccess);
} // namespace aether::android
