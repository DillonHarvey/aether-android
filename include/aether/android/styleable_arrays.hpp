#pragma once
#include "aether/android/sdk_resources.hpp"
#include "aether/dex/runtime.hpp"
#include <span>
#include <string_view>

namespace aether::android {
struct StyleableArrays {
    dex::ObjectId ids = 0;
    dex::ObjectId ordinals = 0;
};
// Creates real managed int[] values: unsigned-sorted SDK attribute IDs and a
// parallel mapping to the supplied declaration-name ordinals. No native vector,
// guest callback, cache or new work allowance. Names must remain immutable and
// alive independently of managed GC; work is the caller's nonreentrant ledger.
// Both arrays are rooted internally until return. The caller must immediately
// root both before another allocation, then publish only the complete pair.
// Keep the ordinal map private; the IDs retain their genuine mutable identity
// when passed to an original Context override.
StyleableArrays create_styleable_arrays(dex::ManagedRuntime &runtime,
    std::span<const std::string_view> names, const SdkResourceWork &work);
} // namespace aether::android
