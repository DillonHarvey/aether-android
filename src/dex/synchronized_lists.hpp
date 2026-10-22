#pragma once
#include "aether/dex/runtime.hpp"

namespace aether::dex {
inline constexpr std::string_view synchronized_list_type="Ljava/util/Collections$SynchronizedList;";
inline constexpr std::string_view synchronized_random_list_type="Ljava/util/Collections$SynchronizedRandomAccessList;";
bool synchronized_list_class(std::string_view) noexcept;
std::optional<HostClass> synchronized_list_metadata(std::string_view);
bool synchronized_list_owner_method(std::string_view,std::string_view,std::string_view) noexcept;
}
