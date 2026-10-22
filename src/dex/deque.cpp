#include "deque.hpp"
#include <algorithm>
#include <array>
namespace aether::dex {
std::optional<HostClass> deque_class(std::string_view type) {
    static constexpr std::array<std::string_view,3> interfaces{"Ljava/util/Deque;","Ljava/lang/Cloneable;","Ljava/io/Serializable;"};
    static constexpr std::array<std::string_view,1> iter{"Ljava/util/Iterator;"};
    if(type==array_deque_type)return HostClass{"Ljava/util/AbstractCollection;",interfaces};
    if(type=="Ljava/util/Deque;")return HostClass{"Ljava/util/Queue;",{},true,true};
    if(type==deque_iterator_type)return HostClass{"Ljava/lang/Object;",iter};
    return {};
}
void ManagedDeque::grow(CollectionBudget budget) {
    if(values_.size()>=budget.maximum_elements)throw DexError("AETHER_DEX_COLLECTION_LIMIT","Deque exceeds managed element bound");
    if(values_.size()<values_.capacity())return;
    const auto count=std::min(budget.maximum_elements,std::max<std::size_t>(1,values_.size()*2));
    const auto before=bytes();
    if(count*sizeof(Value)-before>budget.heap_limit-budget.heap_bytes)throw DexError("AETHER_DEX_HEAP_LIMIT","Deque exceeds managed heap bound");
    std::vector<Value> next;next.reserve(count);
    const auto after=next.capacity()*sizeof(Value);
    if(next.capacity()>budget.maximum_elements||after-before>budget.heap_limit-budget.heap_bytes)
        throw DexError("AETHER_DEX_HEAP_LIMIT","Deque allocation exceeds managed heap bound");
    next.insert(next.end(),values_.begin(),values_.end());values_.swap(next);
    budget.object_bytes+=after-before;budget.heap_bytes+=after-before;
}
std::optional<Value> ManagedDeque::invoke(ManagedRuntime &r,std::string_view name,std::string_view sig,
    std::span<const Value> args,CollectionBudget budget,const std::function<bool(ObjectId,ObjectId)> &equal) {
    if(name=="<init>"&&sig=="()V") {
        if(initialized_)throw DexError("AETHER_DEX_STATE","Deque initialized twice");
        initialized_=true;return Value::nothing();
    }
    if(!initialized_)throw DexError("AETHER_DEX_STATE","Deque must be initialized before use");
    if(name=="size"&&sig=="()I")return Value::word(static_cast<std::uint32_t>(values_.size()));
    if(name=="isEmpty"&&sig=="()Z")return Value::word(values_.empty());
    if(name=="clear"&&sig=="()V") {if(!values_.empty()){values_.clear();++revision_;}return Value::nothing();}
    const bool front=name=="addFirst"||name=="offerFirst"||name=="push";
    const bool insertion=front||name=="addLast"||name=="offerLast"||name=="add"||name=="offer";
    const bool void_insert=name=="addFirst"||name=="addLast"||name=="push";
    if(insertion&&sig==(void_insert?"(Ljava/lang/Object;)V":"(Ljava/lang/Object;)Z")) {
        if(!args[1].bits)r.raise("Ljava/lang/NullPointerException;");
        grow(budget);if(front)values_.insert(values_.begin(),args[1]);else values_.push_back(args[1]);
        ++revision_;return void_insert?Value::nothing():Value::word(1);
    }
    const bool back=name=="pollLast"||name=="peekLast"||name=="removeLast"||name=="getLast";
    const bool remove=name=="poll"||name=="pollFirst"||name=="pollLast"||name=="remove"||name=="removeFirst"||name=="removeLast"||name=="pop";
    const bool access=back||remove||name=="peek"||name=="peekFirst"||name=="element"||name=="getFirst";
    if(access&&sig=="()Ljava/lang/Object;") {
        if(values_.empty()) {
            if(name.starts_with("remove")||name.starts_with("get")||name=="element"||name=="pop")r.raise("Ljava/util/NoSuchElementException;");
            return Value::reference(0);
        }
        const auto value=back?values_.back():values_.front();
        if(remove){values_.erase(back?values_.end()-1:values_.begin());++revision_;}return value;
    }
    if((name=="contains"||name=="remove"||name=="removeFirstOccurrence"||name=="removeLastOccurrence")&&sig=="(Ljava/lang/Object;)Z") {
        const auto query=args[1].bits,revision=revision_;if(!query)return Value::word(0);
        for(std::size_t n=0;n<values_.size();++n) {
            const auto at=name=="removeLastOccurrence"?values_.size()-n-1:n;
            const auto candidate=values_[at].bits;const bool match=query==candidate||equal(query,candidate);
            if(revision!=revision_)throw DexError("AETHER_DEX_COLLECTION_REENTRANCY","Equality callback changed deque");
            if(match){if(name!="contains"){values_.erase(values_.begin()+at);++revision_;}return Value::word(1);}
        }
        return Value::word(0);
    }
    if(name=="toArray"&&(sig=="()[Ljava/lang/Object;"||sig=="([Ljava/lang/Object;)[Ljava/lang/Object;")) {
        const bool typed=sig[1]=='[';auto array=typed?args[1].bits:0;const auto length=typed?r.array_length(array):0;
        if(!typed||length<values_.size())array=r.new_array(typed?std::string(r.object_type(array)):"[Ljava/lang/Object;",static_cast<std::int32_t>(values_.size()));
        for(std::size_t n=0;n<values_.size();++n)r.array_set(array,static_cast<std::int32_t>(n),values_[n]);
        if(typed&&length>values_.size())r.array_set(array,static_cast<std::int32_t>(values_.size()),Value::reference(0));
        return Value::reference(array);
    }
    return {};
}
std::optional<Value> ManagedDeque::iterate(ManagedRuntime &r,DequeIterator &it,std::string_view name,std::string_view sig) {
    if(name=="hasNext"&&sig=="()Z")return Value::word(it.reverse?it.cursor!=0:it.cursor<values_.size());
    if(name=="next"&&sig=="()Ljava/lang/Object;") {
        if(it.revision!=revision_)r.raise("Ljava/util/ConcurrentModificationException;");
        if(it.reverse?it.cursor==0:it.cursor>=values_.size())r.raise("Ljava/util/NoSuchElementException;");
        const auto at=it.reverse?--it.cursor:it.cursor++;it.last=at;return values_[at];
    }
    if(name=="remove"&&sig=="()V") {
        if(!it.last)r.raise("Ljava/lang/IllegalStateException;");
        if(it.revision!=revision_)r.raise("Ljava/util/ConcurrentModificationException;");
        values_.erase(values_.begin()+*it.last);++revision_;it.revision=revision_;
        if(!it.reverse)--it.cursor;it.last.reset();return Value::nothing();
    }
    return {};
}
}
