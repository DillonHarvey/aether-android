#include "aether/android/styleable_arrays.hpp"
#include "aether/android/sdk_resource_image.hpp"
#include <limits>

namespace aether::android {
namespace {
class ArrayRoot final {
    dex::ManagedRuntime &runtime_;
    dex::ObjectId object_;
  public:
    ArrayRoot(dex::ManagedRuntime &runtime, dex::ObjectId object) : runtime_(runtime), object_(object) {
        runtime_.retain(object_);
    }
    ~ArrayRoot() { runtime_.release(object_); }
    ArrayRoot(const ArrayRoot &) = delete;
    ArrayRoot &operator=(const ArrayRoot &) = delete;
};
} // namespace
StyleableArrays create_styleable_arrays(dex::ManagedRuntime &runtime,
    std::span<const std::string_view> names, const SdkResourceWork &work) {
    if (!work)
        throw apk::InspectError("AETHER_STYLEABLE_WORK", "styleable-arrays",
                                "Styleable construction requires the existing provider work ledger");
    if (names.size() > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()))
        throw apk::InspectError("AETHER_STYLEABLE_LIMIT", "styleable-arrays",
                                "Styleable names exceed a managed array's length representation");
    const auto count = static_cast<std::int32_t>(names.size());
    // Admit each allocation/zero-initialization stage before asking the VM to
    // create it. The VM separately admits and charges actual managed storage.
    work(static_cast<std::uint64_t>(names.size()) + 1);
    const auto ids = runtime.new_array("[I", count);
    ArrayRoot ids_root(runtime, ids);
    work(static_cast<std::uint64_t>(names.size()) + 1);
    const auto ordinals = runtime.new_array("[I", count);
    ArrayRoot ordinals_root(runtime, ordinals);
    for (std::int32_t index = 0; index < count; ++index) {
        work(1);
        const auto id = embedded_sdk_resources().identifier("attr", names[static_cast<std::size_t>(index)], work);
        if (!id)
            throw apk::InspectError("AETHER_STYLEABLE_ATTRIBUTE", "styleable-arrays",
                                    "An expected styleable attribute is absent from the authenticated SDK catalog");
        auto position = index;
        // Stable in-place sorting retains exact declaration ordinals without
        // an uncharged native array. Neither managed array escapes this call.
        while (position > 0) {
            work(2);
            const auto previous = static_cast<std::uint32_t>(runtime.array_get(ids, position - 1).bits);
            if (previous == id)
                throw apk::InspectError("AETHER_STYLEABLE_ATTRIBUTE", "styleable-arrays",
                                        "Styleable declarations resolve to duplicate SDK attribute identities");
            if (previous < id) break;
            work(3);
            const auto ordinal = runtime.array_get(ordinals, position - 1);
            runtime.array_set(ids, position, dex::Value::word(previous));
            runtime.array_set(ordinals, position, ordinal);
            --position;
        }
        work(2);
        runtime.array_set(ids, position, dex::Value::word(id));
        runtime.array_set(ordinals, position, dex::Value::word(static_cast<std::uint32_t>(index)));
    }
    return {ids, ordinals};
}
} // namespace aether::android
