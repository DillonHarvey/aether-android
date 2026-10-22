#include "empty_maps.hpp"
#include <array>
namespace aether::dex {
std::optional<HostClass> empty_map_class(std::string_view type) {
    static constexpr std::array<std::string_view,1> serial{"Ljava/io/Serializable;"},iterator{"Ljava/util/Iterator;"};
    if(type==empty_map_type)return HostClass{"Ljava/util/AbstractMap;",serial};
    if(type==empty_set_type)return HostClass{"Ljava/util/AbstractSet;",serial};
    if(type==empty_map_iterator_type)return HostClass{"Ljava/lang/Object;",iterator};
    if(type=="Ljava/util/function/Function;" || type=="Ljava/util/function/BiFunction;" ||
        type=="Ljava/util/function/Consumer;" || type=="Ljava/util/function/BiConsumer;" || type=="Ljava/util/function/Predicate;")
        return HostClass{"Ljava/lang/Object;",{},true,true};
    return {};
}
bool empty_map_method(std::string_view type,std::string_view name,std::string_view signature) noexcept {
    const bool map=type==empty_map_type,set=type==empty_set_type,it=type==empty_map_iterator_type;
    if(it)return (name=="hasNext" && signature=="()Z") || (name=="next" && signature=="()Ljava/lang/Object;") ||
        (name=="remove" && signature=="()V") || (name=="forEachRemaining" && signature=="(Ljava/util/function/Consumer;)V");
    if(!map && !set)return false;
    if((name=="size" || name=="hashCode") && signature=="()I")return true;
    if((name=="isEmpty" && signature=="()Z") || (name=="clear" && signature=="()V") ||
        (name=="toString" && signature=="()Ljava/lang/String;") || (name=="equals" && signature=="(Ljava/lang/Object;)Z"))return true;
    if(map)return ((name=="containsKey" || name=="containsValue") && signature=="(Ljava/lang/Object;)Z") ||
        ((name=="get" || name=="remove") && signature=="(Ljava/lang/Object;)Ljava/lang/Object;") ||
        (name=="getOrDefault" && signature=="(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;") ||
        ((name=="keySet" || name=="entrySet") && signature=="()Ljava/util/Set;") || (name=="values" && signature=="()Ljava/util/Collection;") ||
        (name=="putAll" && signature=="(Ljava/util/Map;)V") || (name=="forEach" && signature=="(Ljava/util/function/BiConsumer;)V") ||
        (name=="replaceAll" && signature=="(Ljava/util/function/BiFunction;)V") ||
        ((name=="put" || name=="putIfAbsent" || name=="replace") && signature=="(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;") ||
        (name=="remove" && signature=="(Ljava/lang/Object;Ljava/lang/Object;)Z") ||
        (name=="replace" && signature=="(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z") ||
        (name=="computeIfAbsent" && signature=="(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;") ||
        ((name=="computeIfPresent" || name=="compute") && signature=="(Ljava/lang/Object;Ljava/util/function/BiFunction;)Ljava/lang/Object;") ||
        (name=="merge" && signature=="(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/function/BiFunction;)Ljava/lang/Object;");
    return ((name=="contains" || name=="remove" || name=="add") && signature=="(Ljava/lang/Object;)Z") ||
        (name=="iterator" && signature=="()Ljava/util/Iterator;") ||
        ((name=="containsAll" || name=="removeAll" || name=="retainAll" || name=="addAll") && signature=="(Ljava/util/Collection;)Z") ||
        (name=="forEach" && signature=="(Ljava/util/function/Consumer;)V") || (name=="removeIf" && signature=="(Ljava/util/function/Predicate;)Z") ||
        (name=="toArray" && (signature=="()[Ljava/lang/Object;" || signature=="([Ljava/lang/Object;)[Ljava/lang/Object;"));
}
namespace {
struct Pins {
    ManagedRuntime &runtime;std::array<ObjectId,6> ids{};std::size_t count=0;
    void add(ObjectId id){runtime.retain(id);ids[count++]=id;}
    ~Pins(){while(count)runtime.release(ids[--count]);}
};
void nonnull(ManagedRuntime &runtime,ObjectId id){if(!id)runtime.raise("Ljava/lang/NullPointerException;");}
void first_item(ManagedRuntime &runtime,ObjectId source,bool map) {
    nonnull(runtime,source);Pins pins{runtime};
    const auto collection=map?runtime.invoke_virtual_named(source,"entrySet","()Ljava/util/Set;").bits:source;
    pins.add(collection);
    const auto iterator=runtime.invoke_virtual_named(collection,"iterator","()Ljava/util/Iterator;").bits;pins.add(iterator);
    if(!runtime.invoke_virtual_named(iterator,"hasNext","()Z").bits)return;
    const auto entry=runtime.invoke_virtual_named(iterator,"next","()Ljava/lang/Object;").bits;pins.add(entry);
    if(map) {
        const auto key=runtime.invoke_virtual_named(entry,"getKey","()Ljava/lang/Object;").bits;pins.add(key);
        const auto value=runtime.invoke_virtual_named(entry,"getValue","()Ljava/lang/Object;").bits;pins.add(value);
    }
    runtime.raise("Ljava/lang/UnsupportedOperationException;");
}
}
std::optional<Value> invoke_empty_map(ManagedRuntime &runtime,std::string_view type,std::string_view name,
    std::string_view signature,std::span<const Value> args,const EmptyFactory &factory) {
    if(type==empty_map_iterator_type) {
        if(name=="hasNext" && signature=="()Z")return Value::word(0);
        if(name=="next" && signature=="()Ljava/lang/Object;")runtime.raise("Ljava/util/NoSuchElementException;");
        if(name=="remove" && signature=="()V")runtime.raise("Ljava/lang/IllegalStateException;");
        if(name=="forEachRemaining" && signature=="(Ljava/util/function/Consumer;)V") {
            nonnull(runtime,args[1].bits);return Value::nothing();
        }
        return {};
    }
    const bool map=type==empty_map_type;
    if(!map && type!=empty_set_type)return {};
    if(name=="size" && signature=="()I")return Value::word(0);
    if(name=="isEmpty" && signature=="()Z")return Value::word(1);
    if(name=="hashCode" && signature=="()I")return Value::word(0);
    if(name=="toString" && signature=="()Ljava/lang/String;")return Value::reference(runtime.new_string(map?u"{}":u"[]"));
    if(name=="clear" && signature=="()V")return Value::nothing();
    if(name=="equals" && signature=="(Ljava/lang/Object;)Z") {
        const auto other=args[1].bits;
        if(other==args[0].bits)return Value::word(1);
        if(!other || !runtime.assignable(other,map?"Ljava/util/Map;":"Ljava/util/Set;"))return Value::word(0);
        if(!map && runtime.invoke_virtual_named(other,"size","()I").bits)return Value::word(0);
        try {return runtime.invoke_virtual_named(other,"isEmpty","()Z");}
        catch(const JavaException &error) {
            Pins pins{runtime};pins.add(error.object);
            if(!map && (runtime.assignable(error.object,"Ljava/lang/ClassCastException;") || runtime.assignable(error.object,"Ljava/lang/NullPointerException;")))return Value::word(0);
            throw;
        }
    }
    if(map) {
        if((name=="containsKey" || name=="containsValue") && signature=="(Ljava/lang/Object;)Z")return Value::word(0);
        if((name=="get" || name=="remove") && signature=="(Ljava/lang/Object;)Ljava/lang/Object;")return Value::reference(0);
        if(name=="getOrDefault" && signature=="(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;")return args[2];
        if((name=="keySet" || name=="entrySet") && signature=="()Ljava/util/Set;")return Value::reference(factory(empty_set_type));
        if(name=="values" && signature=="()Ljava/util/Collection;")return Value::reference(factory(empty_set_type));
        if(name=="putAll" && signature=="(Ljava/util/Map;)V") {first_item(runtime,args[1].bits,true);return Value::nothing();}
        if((name=="forEach" && signature=="(Ljava/util/function/BiConsumer;)V") ||
            (name=="replaceAll" && signature=="(Ljava/util/function/BiFunction;)V")) {
            nonnull(runtime,args[1].bits);return Value::nothing();
        }
        if(((name=="put" || name=="putIfAbsent" || name=="replace") && signature=="(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;") ||
            (name=="remove" && signature=="(Ljava/lang/Object;Ljava/lang/Object;)Z") ||
            (name=="replace" && signature=="(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z") ||
            (name=="computeIfAbsent" && signature=="(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;") ||
            ((name=="computeIfPresent" || name=="compute") && signature=="(Ljava/lang/Object;Ljava/util/function/BiFunction;)Ljava/lang/Object;") ||
            (name=="merge" && signature=="(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/function/BiFunction;)Ljava/lang/Object;"))
            runtime.raise("Ljava/lang/UnsupportedOperationException;");
    } else {
        if((name=="contains" || name=="remove") && signature=="(Ljava/lang/Object;)Z")return Value::word(0);
        if(name=="iterator" && signature=="()Ljava/util/Iterator;")return Value::reference(factory(empty_map_iterator_type));
        if(name=="containsAll" && signature=="(Ljava/util/Collection;)Z")return runtime.invoke_virtual_named(args[1].bits,"isEmpty","()Z");
        if(name=="removeAll" && signature=="(Ljava/util/Collection;)Z") {
            const auto size=runtime.invoke_virtual_named(args[1].bits,"size","()I");
            if(static_cast<std::int32_t>(size.bits)<0)throw DexError("AETHER_DEX_COLLECTION_STATE","Collection reported a negative size");
            return Value::word(0);
        }
        if(name=="retainAll" && signature=="(Ljava/util/Collection;)Z") {nonnull(runtime,args[1].bits);return Value::word(0);}
        if(name=="addAll" && signature=="(Ljava/util/Collection;)Z") {first_item(runtime,args[1].bits,false);return Value::word(0);}
        if(name=="add" && signature=="(Ljava/lang/Object;)Z")runtime.raise("Ljava/lang/UnsupportedOperationException;");
        if((name=="forEach" && signature=="(Ljava/util/function/Consumer;)V") ||
            (name=="removeIf" && signature=="(Ljava/util/function/Predicate;)Z")) {
            nonnull(runtime,args[1].bits);return name=="removeIf"?Value::word(0):Value::nothing();
        }
        if(name=="toArray" && signature=="()[Ljava/lang/Object;")return Value::reference(runtime.new_array("[Ljava/lang/Object;",0));
        if(name=="toArray" && signature=="([Ljava/lang/Object;)[Ljava/lang/Object;") {
            if(runtime.array_length(args[1].bits))runtime.array_set(args[1].bits,0,Value::reference(0));
            return args[1];
        }
    }
    return {};
}
} // namespace aether::dex
