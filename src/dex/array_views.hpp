#pragma once
#include "aether/dex/runtime.hpp"
#include <functional>

namespace aether::dex {
inline constexpr std::string_view arrays_type = "Ljava/util/Arrays;";
inline constexpr std::string_view array_list_type = "Ljava/util/Arrays$ArrayList;";
inline constexpr std::string_view array_iterator_type = "Laether/internal/ArrayListIterator;";
std::optional<HostClass> array_view_class(std::string_view type);
std::optional<Value> invoke_array_view(ManagedRuntime &runtime, ObjectId array, std::string_view name,
                                       std::string_view signature, std::span<const Value> args,
                                       const std::function<bool(ObjectId, ObjectId)> &equal);
// Factory-owned state: backing array reference, cursor, last-returned index.
std::optional<Value> invoke_array_iterator(ManagedRuntime &runtime, std::span<Value> state,
                                           std::string_view name, std::string_view signature,
                                           std::span<const Value> args);
} // namespace aether::dex
