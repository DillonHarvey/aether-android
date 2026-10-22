#include "synchronized_lists.hpp"
#include "unmodifiable_lists.hpp"
#include "sets.hpp"
#include <array>

namespace aether::dex {
bool synchronized_list_class(std::string_view type) noexcept {
    return type==synchronized_list_type || type==synchronized_random_list_type;
}
std::optional<HostClass> synchronized_list_metadata(std::string_view type) {
    static constexpr std::array<std::string_view,1> list{"Ljava/util/List;"},random{"Ljava/util/RandomAccess;"};
    if(type==synchronized_list_type)return HostClass{synchronized_collection_type,list};
    if(type==synchronized_random_list_type)return HostClass{synchronized_list_type,random};
    return {};
}
bool synchronized_list_owner_method(std::string_view owner,std::string_view name,std::string_view signature) noexcept {
    if(synchronized_list_class(owner))return unmodifiable_list_method(name,signature);
    if(owner==synchronized_collection_type)owner="Ljava/util/Collection;";
    return unmodifiable_owner_method(owner,name,signature);
}
}
