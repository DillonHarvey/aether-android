#pragma once
#include "aether/dex/runtime.hpp"

namespace aether::android {
enum class InflaterFactorySlot { factory, factory2, private_factory };

inline constexpr std::string_view inflater_factory_merger_type =
    "Landroid/view/LayoutInflater$FactoryMerger;";

// The framework supplies the genuine Factory2 class identity and routes its two
// onCreateView bodies here. No public constructor or guest initialization is
// introduced. All four original factory fields are traced, including nulls.
// Root the returned carrier before another managed allocation or callback.
dex::ObjectId new_inflater_factory_merger(dex::ManagedRuntime &, dex::ObjectId f1,
    dex::ObjectId f12, dex::ObjectId f2, dex::ObjectId f22);

// Arguments exclude the receiver: name/context/attributes, or
// parent/name/context/attributes. Nulls are forwarded to the original factory;
// they are not replaced or rejected before its callback. Exceptions propagate.
dex::ObjectId invoke_inflater_factory_merger(dex::ManagedRuntime &, dex::ObjectId receiver,
    std::span<const dex::Value> arguments, bool parent_aware);

// Read current owner-authenticated, charged and traced inflater state. The
// reader must not invoke guest code or retain references into mutable state.
struct InflaterFactoryAccess {
    void *owner = nullptr;
    dex::ObjectId (*read)(void *, dex::ObjectId, InflaterFactorySlot) = nullptr;
};

// Applies the actual factory chain after the caller selects the tag's themed
// Context. Context and attributes may be null and are forwarded unchanged.
// A null result requires normal construction; exceptions retain their
// real cause for the outer inflater's InflateException boundary. The caller
// must root a returned View before another allocation or guest callback.
// Access is copied so replacing managed owner state during a callback cannot
// invalidate the reader descriptor itself.
dex::ObjectId invoke_inflater_factories(dex::ManagedRuntime &, dex::ObjectId inflater,
                                       dex::ObjectId parent, dex::ObjectId name,
                                       dex::ObjectId context, dex::ObjectId attributes,
                                       InflaterFactoryAccess);
} // namespace aether::android
