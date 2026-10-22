#pragma once
#include "aether/dex/runtime.hpp"

namespace aether::dex {
inline constexpr std::string_view unmodifiable_collection_type="Ljava/util/Collections$UnmodifiableCollection;";
inline constexpr std::string_view unmodifiable_list_type="Ljava/util/Collections$UnmodifiableList;";
inline constexpr std::string_view unmodifiable_random_list_type="Ljava/util/Collections$UnmodifiableRandomAccessList;";
inline constexpr std::string_view unmodifiable_iterator_type="Laether/internal/UnmodifiableIterator;";
inline constexpr std::string_view unmodifiable_list_iterator_type="Laether/internal/UnmodifiableListIterator;";
std::optional<HostClass> unmodifiable_class(std::string_view);
bool unmodifiable_list_class(std::string_view) noexcept;
bool unmodifiable_iterator_class(std::string_view) noexcept;
bool unmodifiable_mutator(std::string_view,std::string_view) noexcept;
bool unmodifiable_list_method(std::string_view,std::string_view) noexcept;
bool unmodifiable_iterator_method(std::string_view,std::string_view,bool) noexcept;
bool unmodifiable_owner_method(std::string_view,std::string_view,std::string_view) noexcept;
}
