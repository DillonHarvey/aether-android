#include "unmodifiable_lists.hpp"
#include <array>

namespace aether::dex {
bool unmodifiable_list_class(std::string_view type) noexcept {
    return type==unmodifiable_list_type || type==unmodifiable_random_list_type;
}
bool unmodifiable_iterator_class(std::string_view type) noexcept {
    return type==unmodifiable_iterator_type || type==unmodifiable_list_iterator_type;
}
std::optional<HostClass> unmodifiable_class(std::string_view type) {
    static constexpr std::array<std::string_view,2> collection{"Ljava/util/Collection;","Ljava/io/Serializable;"};
    static constexpr std::array<std::string_view,1> list{"Ljava/util/List;"},random{"Ljava/util/RandomAccess;"},
        iterator{"Ljava/util/Iterator;"},list_iterator{"Ljava/util/ListIterator;"};
    if(type==unmodifiable_collection_type)return HostClass{"Ljava/lang/Object;",collection};
    if(type==unmodifiable_list_type)return HostClass{unmodifiable_collection_type,list};
    if(type==unmodifiable_random_list_type)return HostClass{unmodifiable_list_type,random};
    if(type==unmodifiable_iterator_type)return HostClass{"Ljava/lang/Object;",iterator};
    if(type==unmodifiable_list_iterator_type)return HostClass{"Ljava/lang/Object;",list_iterator};
    return {};
}
bool unmodifiable_mutator(std::string_view name,std::string_view signature) noexcept {
    return (name=="add" && (signature=="(Ljava/lang/Object;)Z" || signature=="(ILjava/lang/Object;)V")) ||
        (name=="set" && signature=="(ILjava/lang/Object;)Ljava/lang/Object;") ||
        (name=="remove" && (signature=="(Ljava/lang/Object;)Z" || signature=="(I)Ljava/lang/Object;")) ||
        (name=="clear" && signature=="()V") ||
        (name=="addAll" && (signature=="(Ljava/util/Collection;)Z" || signature=="(ILjava/util/Collection;)Z")) ||
        ((name=="removeAll" || name=="retainAll") && signature=="(Ljava/util/Collection;)Z") ||
        (name=="removeIf" && signature=="(Ljava/util/function/Predicate;)Z") ||
        (name=="replaceAll" && signature=="(Ljava/util/function/UnaryOperator;)V") ||
        (name=="sort" && signature=="(Ljava/util/Comparator;)V");
}
bool unmodifiable_list_method(std::string_view name,std::string_view signature) noexcept {
    return unmodifiable_mutator(name,signature) ||
        ((name=="size" || name=="hashCode") && signature=="()I") ||
        (name=="isEmpty" && signature=="()Z") ||
        ((name=="contains" || name=="equals") && signature=="(Ljava/lang/Object;)Z") ||
        (name=="containsAll" && signature=="(Ljava/util/Collection;)Z") ||
        (name=="get" && signature=="(I)Ljava/lang/Object;") ||
        ((name=="indexOf" || name=="lastIndexOf") && signature=="(Ljava/lang/Object;)I") ||
        (name=="toArray" && (signature=="()[Ljava/lang/Object;" || signature=="([Ljava/lang/Object;)[Ljava/lang/Object;")) ||
        (name=="toString" && signature=="()Ljava/lang/String;") ||
        (name=="iterator" && signature=="()Ljava/util/Iterator;") ||
        (name=="listIterator" && (signature=="()Ljava/util/ListIterator;" || signature=="(I)Ljava/util/ListIterator;")) ||
        (name=="subList" && signature=="(II)Ljava/util/List;");
}
bool unmodifiable_iterator_method(std::string_view name,std::string_view signature,bool list) noexcept {
    return (name=="hasNext" && signature=="()Z") ||
        (name=="next" && signature=="()Ljava/lang/Object;") ||
        (name=="remove" && signature=="()V") ||
        (list && ((name=="hasPrevious" && signature=="()Z") ||
        (name=="previous" && signature=="()Ljava/lang/Object;") ||
        ((name=="nextIndex" || name=="previousIndex") && signature=="()I") ||
        ((name=="set" || name=="add") && signature=="(Ljava/lang/Object;)V")));
}
bool unmodifiable_owner_method(std::string_view owner,std::string_view name,std::string_view signature) noexcept {
    if(owner=="Ljava/lang/Object;")return (name=="equals" && signature=="(Ljava/lang/Object;)Z") ||
        (name=="hashCode" && signature=="()I") || (name=="toString" && signature=="()Ljava/lang/String;");
    if(owner=="Ljava/util/Iterator;" || owner==unmodifiable_iterator_type)
        return unmodifiable_iterator_method(name,signature,false);
    if(owner=="Ljava/util/ListIterator;" || owner==unmodifiable_list_iterator_type)
        return unmodifiable_iterator_method(name,signature,true);
    if(owner=="Ljava/lang/Iterable;")return name=="iterator" && signature=="()Ljava/util/Iterator;";
    if(owner=="Ljava/util/List;" || unmodifiable_list_class(owner))return unmodifiable_list_method(name,signature);
    if(owner!="Ljava/util/Collection;" && owner!=unmodifiable_collection_type)return false;
    if(!unmodifiable_list_method(name,signature))return false;
    return name!="get" && name!="set" && name!="indexOf" && name!="lastIndexOf" && name!="listIterator" &&
        name!="subList" && name!="replaceAll" && name!="sort" && signature!="(ILjava/lang/Object;)V" &&
        signature!="(I)Ljava/lang/Object;" && signature!="(ILjava/util/Collection;)Z";
}
}
