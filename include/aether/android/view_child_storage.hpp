#pragma once
#include "aether/dex/runtime.hpp"
#include <cstddef>
#include <vector>

namespace aether::android {
// Trusted native storage only: the caller authenticates the parent/child and
// normalizes the SDK index. ObjectId values (including zero) remain opaque.
// The vector's address/lifetime must survive admission's possible GC; callers
// root its managed owner and children as needed. Every nonzero capacity must
// already belong to this adapter's live provider-storage reservation, with
// zeroed spare cells. Do not mutate/reallocate the vector outside this adapter.
void insert_view_child(dex::ManagedRuntime &runtime, std::vector<dex::ObjectId> &children,
                       std::size_t index, dex::ObjectId child);
dex::ObjectId erase_view_child(dex::ManagedRuntime &runtime, std::vector<dex::ObjectId> &children,
                               std::size_t index);
// Frees the actual buffer before refunding its live capacity. The runtime and
// its owner thread must still be valid; accounting/owner violations terminate.
void release_view_child_storage(dex::ManagedRuntime &runtime,
                                std::vector<dex::ObjectId> &children) noexcept;
} // namespace aether::android
