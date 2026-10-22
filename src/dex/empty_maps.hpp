#pragma once
#include "aether/dex/runtime.hpp"
#include <functional>
namespace aether::dex {
inline constexpr std::string_view empty_map_type="Ljava/util/Collections$EmptyMap;";
inline constexpr std::string_view empty_set_type="Ljava/util/Collections$EmptySet;";
inline constexpr std::string_view empty_map_iterator_type="Ljava/util/Collections$EmptyIterator;";
std::optional<HostClass> empty_map_class(std::string_view type);
bool empty_map_method(std::string_view type,std::string_view name,std::string_view signature) noexcept;
using EmptyFactory=std::function<ObjectId(std::string_view)>;
std::optional<Value> invoke_empty_map(ManagedRuntime &,std::string_view type,std::string_view name,
    std::string_view signature,std::span<const Value> args,const EmptyFactory &factory);
} // namespace aether::dex
