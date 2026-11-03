#include "array_maps.hpp"
#include <array>
#include <bit>
#include <memory>

namespace aether::android {
namespace {
using dex::ObjectId;
using dex::Value;
using dex::ValueKind;
// Original native translation of declaration/constructor facts checked against
// AOSP android-15.0.0_r1 android/util/{ArrayMap,EmptyArray}.java. These fixed
// field slots describe the SDK, never an app-dependent admission allowance.
enum StaticSlot : std::size_t { immutable_ints,empty_map,base_cache,twice_cache,
    base_lock,twice_lock,empty_boolean,empty_byte,empty_char,empty_double,
    empty_float,empty_int,empty_long,empty_object,empty_string,static_slots };
enum InstanceSlot : std::size_t { class_space,hashes,pairs,collections,instance_slots };
class ClassSpaceState final : public dex::HostObjectState {
  public:
    explicit ClassSpaceState(const void *seal):owner(seal) {}
    const void *const owner;
    mutable std::array<Value,static_slots> references{
        Value::reference(0),Value::reference(0),Value::reference(0),
        Value::reference(0),Value::reference(0),Value::reference(0),
        Value::reference(0),Value::reference(0),Value::reference(0),
        Value::reference(0),Value::reference(0),Value::reference(0),
        Value::reference(0),Value::reference(0),Value::reference(0)};
    mutable std::int32_t base_cache_size=0,twice_cache_size=0;
    std::span<const Value> values() const noexcept override {return references;}
    std::size_t bytes() const noexcept override {return sizeof(*this);}
};
class ArrayMapState final : public dex::HostObjectState {
  public:
    ArrayMapState(const void *seal,ObjectId storage):owner(seal),references{
        Value::reference(storage),Value::reference(0),Value::reference(0),Value::reference(0)} {}
    const void *const owner;
    mutable std::array<Value,instance_slots> references;
    mutable std::int32_t size=0;
    mutable bool identity_hash=false;
    // The immutable marker is the actual references[hashes] identity, not a
    // second independently mutable boolean that could disagree with it.
    std::span<const Value> values() const noexcept override {return references;}
    std::size_t bytes() const noexcept override {return sizeof(*this);}
};
struct EmptyField {std::string_view name,type;StaticSlot slot;};
constexpr std::array<EmptyField,9> empty_fields{{
    {"BOOLEAN","[Z",empty_boolean},{"BYTE","[B",empty_byte},{"CHAR","[C",empty_char},
    {"DOUBLE","[D",empty_double},{"FLOAT","[F",empty_float},{"INT","[I",empty_int},
    {"LONG","[J",empty_long},{"OBJECT","[Ljava/lang/Object;",empty_object},
    {"STRING","[Ljava/lang/String;",empty_string}
}};
[[noreturn]] void fail(const char *code,const char *message) {throw dex::DexError(code,message);}
struct Root {
    dex::ManagedRuntime &runtime;ObjectId object;
    Root(dex::ManagedRuntime &owner,ObjectId id):runtime(owner),object(id) {runtime.retain(object);}
    ~Root() {runtime.release(object);}
    Root(const Root &)=delete;Root &operator=(const Root &)=delete;
};
struct Reservation {
    dex::ManagedRuntime &runtime;std::size_t bytes;
    Reservation(dex::ManagedRuntime &owner,std::size_t amount):runtime(owner),bytes(amount) {
        runtime.reserve_provider_storage(bytes);
    }
    ~Reservation() {runtime.release_provider_storage(bytes);}
    Reservation(const Reservation &)=delete;Reservation &operator=(const Reservation &)=delete;
};
void validate_context(const ArrayMapContext &context) {
    if(!context.session_seal)
        fail("AETHER_ANDROID_ARRAY_MAP_STATE","ArrayMap requires its actual live session owner");
}
const ClassSpaceState &class_state(ArrayMapContext &context) {
    validate_context(context);
    auto &runtime=context.runtime;
    if(!context.class_space_root) {
        // An explicitly native-origin carrier, not a purported SDK object. It
        // accounts for backend metadata while the SDK references start null.
        const auto object=runtime.new_object(array_map_class_space_type);
        Root object_root(runtime,object);
        Reservation storage(runtime,sizeof(ClassSpaceState));
        runtime.charge_provider_work(static_slots+3); // References, owner and two count fields.
        auto state=std::make_unique<ClassSpaceState>(context.session_seal);
        runtime.charge_provider_work(static_slots); // Actual traced-field validation.
        runtime.set_host_state_with_storage(object,std::move(state),storage.bytes);
        runtime.charge_provider_work(1);
        runtime.retain(object);
        context.class_space_root=object;
    }
    const auto *state=dynamic_cast<const ClassSpaceState *>(runtime.host_state(context.class_space_root));
    if(!state || state->owner!=context.session_seal ||
       runtime.object_type(context.class_space_root)!=array_map_class_space_type)
        fail("AETHER_ANDROID_ARRAY_MAP_STATE","ArrayMap class storage has another native origin or owner");
    return *state;
}
const ArrayMapState &map_state(ArrayMapContext &context,ObjectId object) {
    const auto &storage=class_state(context);
    (void)storage;
    const auto *state=dynamic_cast<const ArrayMapState *>(context.runtime.host_state(object));
    if(!state || state->owner!=context.session_seal ||
       context.runtime.object_type(object)!=array_map_type ||
       state->references[class_space].bits!=context.class_space_root)
        fail("AETHER_ANDROID_ARRAY_MAP_STATE","ArrayMap fields have another receiver, class space or native origin");
    return *state;
}
void store(dex::ManagedRuntime &runtime,Value &field,ObjectId object) {
    runtime.charge_provider_work(1);
    field=Value::reference(object);
}
ObjectId reference(Value value) {
    if(value.kind!=ValueKind::reference)
        fail("AETHER_ANDROID_ARRAY_MAP_ARGUMENT","ArrayMap requires an actual managed reference");
    return value.bits;
}
std::int32_t word(Value value) {
    if(value.kind!=ValueKind::word)
        fail("AETHER_ANDROID_ARRAY_MAP_ARGUMENT","ArrayMap requires its actual int or boolean argument");
    return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value.bits));
}
ObjectId empty_reference(ArrayMapContext &context,std::string_view name,std::string_view type) {
    const auto field=array_map_static_field(context,android_empty_array_type,name,type);
    if(!field)
        fail("AETHER_ANDROID_ARRAY_MAP_STATIC_STATE","Expected android.util.EmptyArray source field is unavailable");
    return reference(*field);
}
ObjectId cached_reference(dex::ManagedRuntime &runtime,ObjectId array,std::int32_t index) {
    runtime.charge_provider_work(1);
    return reference(runtime.array_get(array,index));
}
struct CacheRequest {
    ArrayMapContext &context;
    const ClassSpaceState &storage;
    const ArrayMapState &target;
    std::int32_t capacity;
    bool twice,reused=false;
};
void take_cached_arrays(CacheRequest &request) {
    auto &runtime=request.context.runtime;
    auto &head=request.storage.references[request.twice?twice_cache:base_cache];
    auto &count=request.twice?request.storage.twice_cache_size:request.storage.base_cache_size;
    runtime.charge_provider_work(1);
    const auto array=head.bits;
    if(!array)return;
    Root array_root(runtime,array);
    // Private cache heads have no mutable Java frontend here. Unexpected
    // corruption needs the original diagnostic path, never a forged hit.
    runtime.charge_provider_work(1);
    if(runtime.object_type(array)!="[Ljava/lang/Object;" ||
       runtime.array_length(array)!=static_cast<std::size_t>(request.capacity)*2 || count<=0)
        fail("AETHER_ANDROID_ARRAY_MAP_CACHE_UNSUPPORTED","ArrayMap cache requires its original well-formed source producer");
    store(runtime,request.target.references[pairs],array);
    const auto next=cached_reference(runtime,array,0);
    if(next && runtime.object_type(next)!="[Ljava/lang/Object;")
        fail("AETHER_ANDROID_ARRAY_MAP_CACHE_UNSUPPORTED","ArrayMap cache next link requires the original corruption diagnostic");
    store(runtime,head,next);
    const auto hash_array=cached_reference(runtime,array,1);
    if(!hash_array || runtime.object_type(hash_array)!="[I" ||
       runtime.array_length(hash_array)!=static_cast<std::size_t>(request.capacity))
        fail("AETHER_ANDROID_ARRAY_MAP_CACHE_UNSUPPORTED","ArrayMap cached hashes require the original corruption diagnostic");
    store(runtime,request.target.references[hashes],hash_array);
    runtime.charge_provider_work(2);
    runtime.array_set(array,1,Value::reference(0));
    runtime.array_set(array,0,Value::reference(0));
    runtime.charge_provider_work(1);
    --count;
    request.reused=true;
}
void allocate_arrays(ArrayMapContext &context,const ArrayMapState &target,std::int32_t capacity) {
    auto &runtime=context.runtime;
    const auto &storage=class_state(context);
    runtime.charge_provider_work(1);
    if(target.references[hashes].bits==storage.references[immutable_ints].bits)
        fail("AETHER_ANDROID_ARRAY_MAP_IMMUTABLE","Immutable ArrayMap storage cannot be expanded");
    if(capacity==4 || capacity==8) {
        const bool twice=capacity==8;
        const auto lock=storage.references[twice?twice_lock:base_lock].bits;
        Root lock_root(runtime,lock);
        // The small closure is one stack-context pointer. Runtime owns the real
        // logical monitor/frame, including guaranteed release during unwinding.
        CacheRequest request{context,storage,target,capacity,twice};
        runtime.run_host_monitor(lock,[&request] {take_cached_arrays(request);});
        if(request.reused)return;
    }
    const auto hash_array=runtime.new_array("[I",capacity);
    Root hashes_root(runtime,hash_array);
    store(runtime,target.references[hashes],hash_array);
    // Preserve Java int shift semantics and source allocation/publication order:
    // a bad pair length fails AFTER the int[] allocation and mHashes write.
    const auto pair_length=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(capacity)<<1);
    const auto array=runtime.new_array("[Ljava/lang/Object;",pair_length);
    Root array_root(runtime,array);
    store(runtime,target.references[pairs],array);
}
void construct(ArrayMapContext &context,ObjectId receiver,std::int32_t capacity,bool identity_hash) {
    auto &runtime=context.runtime;
    Root receiver_root(runtime,receiver);
    if(!receiver)runtime.raise("Ljava/lang/NullPointerException;");
    const auto &storage=class_state(context);
    if(runtime.object_type(receiver)!=array_map_type || runtime.host_state(receiver))
        fail("AETHER_ANDROID_ARRAY_MAP_CONSTRUCTOR_STATE","ArrayMap constructor requires its actual fresh final-class receiver");
    // Object's direct constructor has no own field/callback/allocation body.
    // The Runtime's ordinary Object allocation already supplies those defaults.
    Reservation state_storage(runtime,sizeof(ArrayMapState));
    runtime.charge_provider_work(instance_slots+3); // References, owner, size and mode.
    auto state=std::make_unique<ArrayMapState>(context.session_seal,context.class_space_root);
    runtime.charge_provider_work(instance_slots);
    runtime.set_host_state_with_storage(receiver,std::move(state),state_storage.bytes);
    const auto &target=map_state(context,receiver);
    runtime.charge_provider_work(1);
    target.identity_hash=identity_hash;
    if(capacity<0) {
        runtime.charge_provider_work(1);
        store(runtime,target.references[hashes],storage.references[immutable_ints].bits);
        const auto array=empty_reference(context,"OBJECT","[Ljava/lang/Object;");
        store(runtime,target.references[pairs],array);
    } else if(capacity==0) {
        const auto ints=empty_reference(context,"INT","[I");
        store(runtime,target.references[hashes],ints);
        const auto objects=empty_reference(context,"OBJECT","[Ljava/lang/Object;");
        store(runtime,target.references[pairs],objects);
    } else allocate_arrays(context,target,capacity);
    runtime.charge_provider_work(1);
    target.size=0;
}
} // namespace

std::optional<dex::HostClass> array_map_class(std::string_view descriptor) {
    static constexpr std::array<std::string_view,1> interfaces{"Ljava/util/Map;"};
    if(descriptor!=array_map_type && descriptor!=android_empty_array_type && descriptor!=array_map_class_space_type)return {};
    dex::HostClass result{"Ljava/lang/Object;",descriptor==array_map_type?std::span<const std::string_view>(interfaces):std::span<const std::string_view>{}};
    result.bootstrap_class=true;
    result.has_class_initializer=true;
    result.identity_object_methods=descriptor!=array_map_type;
    return result;
}
void initialize_array_map_class(ArrayMapContext &context,std::string_view descriptor) {
    validate_context(context);
    auto &runtime=context.runtime;
    if(descriptor==array_map_class_space_type)return; // Explicit Aether-private empty own body.
    if(descriptor==array_map_type) {
        // Map declares default methods but has no allocation-bearing own static
        // work. Its existing core initialization remains the core's authority.
        runtime.initialize("Ljava/util/Map;");
        const auto &storage=class_state(context);
        runtime.charge_provider_work(1);
        if(storage.references[immutable_ints].bits)
            fail("AETHER_ANDROID_ARRAY_MAP_STATIC_STATE","ArrayMap own class initializer cannot be replayed");
        const auto marker=runtime.new_array("[I",0);
        Root marker_root(runtime,marker);
        store(runtime,storage.references[immutable_ints],marker);
        // Same-owner recursive ArrayMap initialization is handled by Runtime.
        // Its negative constructor triggers EmptyArray only at OBJECT's read.
        const auto singleton=new_array_map(context,-1,false);
        Root singleton_root(runtime,singleton);
        store(runtime,storage.references[empty_map],singleton);
        const auto first=runtime.new_object("Ljava/lang/Object;");
        Root first_root(runtime,first);
        store(runtime,storage.references[base_lock],first);
        const auto second=runtime.new_object("Ljava/lang/Object;");
        Root second_root(runtime,second);
        store(runtime,storage.references[twice_lock],second);
        return;
    }
    if(descriptor==android_empty_array_type) {
        const auto &storage=class_state(context);
        runtime.charge_provider_work(1);
        if(storage.references[empty_boolean].bits)
            fail("AETHER_ANDROID_ARRAY_MAP_STATIC_STATE","android.util.EmptyArray own initializer cannot be replayed");
        for(const auto &field:empty_fields) {
            runtime.charge_provider_work(1);
            const auto array=runtime.new_array(field.type,0);
            Root array_root(runtime,array);
            store(runtime,storage.references[field.slot],array);
        }
        return;
    }
    fail("AETHER_ANDROID_ARRAY_MAP_CLASS_INITIALIZATION_UNSUPPORTED","No ArrayMap module initializer exists for this actual declaring class");
}
ObjectId new_array_map(ArrayMapContext &context,std::int32_t capacity,bool identity_hash) {
    validate_context(context);
    const auto object=context.runtime.new_object(array_map_type);
    Root object_root(context.runtime,object);
    construct(context,object,capacity,identity_hash);
    return object;
}
Value invoke_array_map(ArrayMapContext &context,std::string_view owner,std::string_view name,
                       std::string_view signature,std::span<const Value> arguments) {
    validate_context(context);
    if(owner!=array_map_type || name!="<init>")
        fail("AETHER_ANDROID_ARRAY_MAP_OPERATION_UNSUPPORTED","This ArrayMap operation has no implemented source body");
    const bool noarg=signature=="()V",one=signature=="(I)V",two=signature=="(IZ)V";
    if((!noarg && !one && !two) || arguments.size()!=(noarg?1U:one?2U:3U))
        fail("AETHER_ANDROID_ARRAY_MAP_CONSTRUCTOR_UNSUPPORTED","Only the actual zero/int/int-identity ArrayMap constructors are implemented");
    const auto receiver=reference(arguments[0]);
    const auto capacity=noarg?0:word(arguments[1]);
    const bool identity=two && word(arguments[2])!=0;
    construct(context,receiver,capacity,identity);
    return Value::nothing();
}
std::optional<Value> array_map_static_field(ArrayMapContext &context,std::string_view owner,
                                           std::string_view name,std::string_view type) {
    validate_context(context);
    std::optional<StaticSlot> slot;
    bool base_count=false,twice_count=false;
    if(owner==android_empty_array_type) {
        for(const auto &field:empty_fields) {
            context.runtime.charge_provider_work(1);
            if(name==field.name && type==field.type) {slot=field.slot;break;}
        }
    } else if(owner==array_map_type) {
        if(name=="EMPTY_IMMUTABLE_INTS" && type=="[I")slot=immutable_ints;
        else if(name=="EMPTY" && type==array_map_type)slot=empty_map;
        else if(name=="mBaseCache" && type=="[Ljava/lang/Object;")slot=base_cache;
        else if(name=="mTwiceBaseCache" && type=="[Ljava/lang/Object;")slot=twice_cache;
        else if(name=="sBaseCacheLock" && type=="Ljava/lang/Object;")slot=base_lock;
        else if(name=="sTwiceBaseCacheLock" && type=="Ljava/lang/Object;")slot=twice_lock;
        else if(name=="mBaseCacheSize" && type=="I")base_count=true;
        else if(name=="mTwiceBaseCacheSize" && type=="I")twice_count=true;
    }
    if(!slot && !base_count && !twice_count)return {};
    // Actual declaring-owner initialization also covers direct trusted native
    // reads; recursive source reads retain Runtime's partially published state.
    context.runtime.initialize(owner);
    const auto &storage=class_state(context);
    context.runtime.charge_provider_work(1);
    if(slot)return storage.references[*slot];
    return Value::word(static_cast<std::uint32_t>(base_count?storage.base_cache_size:storage.twice_cache_size));
}
} // namespace aether::android
