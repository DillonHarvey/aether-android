#include "preferences.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <iterator>
#include <exception>
#include <vector>
namespace aether::android {
using dex::ObjectId;using dex::Value;
namespace {
constexpr std::size_t journal_limit=65536,transaction_limit=16384,pending_limit=8,native_entries_limit=128*1024,scratch_reservation=1024*1024;
constexpr std::string_view journal_name="aether_preferences_v1.log";
constexpr std::array<std::uint8_t,8> magic{'A','E','T','H','P','R','F',1};
[[noreturn]] void bad(std::string_view code,std::string_view message){throw dex::DexError("AETHER_ANDROID_"+std::string(code),std::string(message));}
enum class Kind:std::uint8_t {integer=1,long_integer=2,floating=3,boolean=4,string=5,removed=6,string_set=7};
struct Entry {std::u16string key,text;Kind kind=Kind::removed;std::uint64_t bits=0;std::vector<std::optional<std::u16string>> strings;};
using Entries=std::vector<Entry>;
std::size_t entry_bytes(const Entries &entries) noexcept {
    std::size_t bytes=entries.capacity()*sizeof(Entry);
    for(const auto &entry:entries)bytes+=(entry.key.capacity()+entry.text.capacity()+2)*sizeof(char16_t);
    for(const auto &entry:entries){bytes+=entry.strings.capacity()*sizeof(std::optional<std::u16string>);for(const auto &value:entry.strings)if(value)bytes+=(value->capacity()+1)*sizeof(char16_t);}
    return bytes;
}
void entry_profile(const Entries &entries) {
    if(entry_bytes(entries)>native_entries_limit)bad("PREFS_LIMIT","Preference native entry storage exceeds 128 KiB");
}
void merge(Entries &entries,const Entries &delta,bool clear) {
    if(clear)entries.clear();
    for(const auto &change:delta) {
        const auto found=std::find_if(entries.begin(),entries.end(),[&](const Entry &entry){return entry.key==change.key;});
        if(change.kind==Kind::removed){if(found!=entries.end())entries.erase(found);}
        else if(found!=entries.end())*found=change;
        else {if(entries.size()==128)bad("PREFS_LIMIT","Preference store exceeds 128 entries");entries.push_back(change);}
    }
}
std::uint32_t crc(std::span<const std::uint8_t> bytes) noexcept {
    std::uint32_t value=0xffffffffU;
    for(const auto byte:bytes){value^=byte;for(unsigned n=0;n<8;++n)value=(value>>1)^((value&1)?0xedb88320U:0U);}
    return ~value;
}
void number(std::vector<std::uint8_t> &out,std::uint64_t value,unsigned bytes){for(unsigned n=0;n<bytes;++n)out.push_back(static_cast<std::uint8_t>(value>>(n*8)));}
void text(std::vector<std::uint8_t> &out,std::u16string_view value){number(out,value.size(),2);for(const auto unit:value)number(out,unit,2);}
void patch(std::span<std::uint8_t> out,std::size_t at,std::uint64_t value,unsigned bytes){for(unsigned n=0;n<bytes;++n)out[at+n]=static_cast<std::uint8_t>(value>>(n*8));}
std::vector<std::uint8_t> encode(std::u16string_view name,const Entries &changes,bool clear) {
    std::vector<std::uint8_t> out;out.reserve(transaction_limit);number(out,0,4);number(out,0,8);text(out,name);number(out,clear,1);number(out,changes.size(),2);
    for(const auto &entry:changes) {
        text(out,entry.key);number(out,static_cast<unsigned>(entry.kind),1);
        if(entry.kind==Kind::string_set) {
            number(out,entry.strings.size(),2);
            for(const auto &value:entry.strings){number(out,value.has_value(),1);if(value)text(out,*value);if(out.size()>transaction_limit-4)bad("PREFS_LIMIT","Preference transaction exceeds 16 KiB");}
        }
        else if(entry.kind==Kind::string)text(out,entry.text);
        else if(entry.kind==Kind::boolean)number(out,entry.bits,1);
        else if(entry.kind==Kind::long_integer)number(out,entry.bits,8);
        else if(entry.kind!=Kind::removed)number(out,entry.bits,4);
        if(out.size()>transaction_limit-4)bad("PREFS_LIMIT","Preference transaction exceeds 16 KiB");
    }
    number(out,0,4);patch(out,0,out.size(),4);return out;
}
struct Parser {
    std::span<const std::uint8_t> bytes;std::size_t at=0;
    std::uint64_t number(unsigned count) {
        if(count>bytes.size()-at)bad("PREFS_CORRUPT","Preference journal has a truncated field");
        std::uint64_t value=0;for(unsigned n=0;n<count;++n)value|=static_cast<std::uint64_t>(bytes[at++])<<(n*8);return value;
    }
    std::u16string text(std::size_t limit) {
        const auto count=number(2);if(count>limit)bad("PREFS_CORRUPT","Preference journal string exceeds its bound");
        std::u16string value;value.reserve(static_cast<std::size_t>(count));for(std::uint64_t n=0;n<count;++n)value.push_back(static_cast<char16_t>(number(2)));return value;
    }
};
struct NamedStore {std::u16string name;Entries entries;};
struct Catalog {std::vector<NamedStore> stores;std::uint64_t sequence=0;};
Catalog parse(std::span<const std::uint8_t> bytes) {
    if(bytes.size()<=magic.size() || !std::equal(magic.begin(),magic.end(),bytes.begin()))bad("PREFS_CORRUPT","Preference journal has no complete versioned transaction");
    Catalog result;std::size_t at=magic.size();
    while(at<bytes.size()) {
        Parser size{bytes.subspan(at)};const auto length=size.number(4);
        if(length<21 || length>transaction_limit || length>bytes.size()-at)bad("PREFS_CORRUPT","Preference journal transaction length is invalid");
        const auto frame=bytes.subspan(at,static_cast<std::size_t>(length));Parser footer{frame.last(4)};
        if(footer.number(4)!=crc(frame.first(frame.size()-4)))bad("PREFS_CORRUPT","Preference journal transaction checksum differs");
        Parser body{frame.first(frame.size()-4)};(void)body.number(4);
        const auto sequence=body.number(8);if(sequence!=result.sequence+1)bad("PREFS_CORRUPT","Preference journal sequence is not contiguous");
        auto name=body.text(256);const auto clear=body.number(1),count=body.number(2);
        if(clear>1 || count>128)bad("PREFS_CORRUPT","Preference transaction flags or entry count are invalid");
        Entries changes;changes.reserve(static_cast<std::size_t>(count));
        for(std::uint64_t n=0;n<count;++n) {
            Entry entry;entry.key=body.text(256);const auto kind=body.number(1);
            if(kind<1 || kind>7)bad("PREFS_CORRUPT","Preference journal value type is invalid");entry.kind=static_cast<Kind>(kind);
            if(entry.kind==Kind::string_set) {
                const auto members=body.number(2);if(members>128)bad("PREFS_CORRUPT","Preference string set exceeds 128 members");
                for(std::uint64_t member=0;member<members;++member) {
                    const auto present=body.number(1);if(present>1)bad("PREFS_CORRUPT","Preference set member tag is invalid");
                    std::optional<std::u16string> value;if(present)value=body.text(4096);
                    if(std::find(entry.strings.begin(),entry.strings.end(),value)!=entry.strings.end())bad("PREFS_CORRUPT","Preference string set repeats a member");
                    entry.strings.push_back(std::move(value));
                }
            }
            else if(entry.kind==Kind::string)entry.text=body.text(4096);
            else if(entry.kind==Kind::boolean){entry.bits=body.number(1);if(entry.bits>1)bad("PREFS_CORRUPT","Preference boolean is not normalized");}
            else if(entry.kind==Kind::long_integer)entry.bits=body.number(8);
            else if(entry.kind!=Kind::removed)entry.bits=body.number(4);
            if(std::any_of(changes.begin(),changes.end(),[&](const Entry &other){return other.key==entry.key;}))bad("PREFS_CORRUPT","Preference transaction repeats a key");
            changes.push_back(std::move(entry));
        }
        if(body.at!=body.bytes.size())bad("PREFS_CORRUPT","Preference transaction has trailing data");
        auto store=std::find_if(result.stores.begin(),result.stores.end(),[&](const NamedStore &value){return value.name==name;});
        if(store==result.stores.end()){if(result.stores.size()==16)bad("PREFS_CORRUPT","Preference journal exceeds sixteen stores");result.stores.push_back({std::move(name),{}});store=std::prev(result.stores.end());}
        try {merge(store->entries,changes,clear!=0);entry_profile(store->entries);}catch(const dex::DexError &){bad("PREFS_CORRUPT","Preference journal store exceeds its entry bound");}
        result.sequence=sequence;at+=static_cast<std::size_t>(length);
    }
    return result;
}
struct Transaction {std::array<std::uint8_t,transaction_limit> bytes{};std::size_t length=0;};
struct Lease {
    host::FileService *files=nullptr;bool active=true,poison=false,known=false,api_busy=false,io_busy=false;
    std::uint64_t denied=0,sequence=0;std::size_t disk_size=0;std::uint32_t head_crc=0;
    std::array<std::uint8_t,journal_limit> disk{};
    std::array<Transaction,pending_limit> pending{};std::size_t head=0,count=0;
    std::array<Value,16> roots{};std::size_t stores=0;
    dex::ManagedRuntime::TaskId worker=0;
    Lease(){roots.fill(Value::reference(0));}
};
struct Anchor final:dex::HostObjectState {
    std::shared_ptr<Lease> lease;std::array<Value,16> roots;
    Anchor(std::shared_ptr<Lease> value,std::array<Value,16> roots):lease(std::move(value)),roots(roots){}
    std::span<const Value> values() const noexcept override{return roots;}
    // Fixed parser/serialization scratch reservation bounds temporary replay of
    // all 16*128 entries under the 64KiB journal and 128KiB native Store/Editor
    // aggregate caps, including copy-on-write rollback states. This is a policy
    // charge, not a hidden unbounded cache.
    std::size_t bytes() const noexcept override{return sizeof(Anchor)+sizeof(Lease)+scratch_reservation+256;}
};
struct StoreState final:dex::HostObjectState {
    std::weak_ptr<Lease> lease;std::u16string name;Entries entries;std::array<Value,1> roots{};
    std::span<const Value> values() const noexcept override{return roots;}
    std::size_t bytes() const noexcept override{return sizeof(StoreState)+(name.capacity()+1)*2+entry_bytes(entries);}
};
struct EditorState final:dex::HostObjectState {
    std::weak_ptr<Lease> lease;Entries changes;bool clear=false;std::array<Value,1> roots{};
    std::span<const Value> values() const noexcept override{return roots;}
    std::size_t bytes() const noexcept override{return sizeof(EditorState)+entry_bytes(changes);}
};
struct Root {dex::ManagedRuntime &runtime;ObjectId id;Root(dex::ManagedRuntime &runtime,ObjectId id):runtime(runtime),id(id){runtime.retain(id);}~Root(){runtime.release(id);}};
struct Descriptor {
    host::FileService &files;int id;bool closed=false;
    ~Descriptor(){if(!closed)(void)files.close(id);}
    bool close() noexcept {closed=true;const auto result=files.close(id);return result.error==host::FileError::none && result.value==0;}
};
struct ReadResult {Catalog catalog;int descriptor=-1;bool missing=false,created=false;};
ReadResult read_disk(Lease &lease,bool create) {
    if(!lease.files)bad("PREFS_UNAVAILABLE","Private preference storage is unavailable");
    const auto root=lease.files->private_root();
    if(root.error==host::FileError::denied){++lease.denied;bad("PREFS_DENIED","Private preference storage is denied");}
    if(root.error!=host::FileError::none || root.value!=0)bad("PREFS_UNAVAILABLE","Private preference root is unavailable");
    auto opened=lease.files->open(journal_name,{true,true});bool created=false;
    if(opened.error==host::FileError::missing) {
        if(lease.known && (lease.sequence || lease.disk_size))bad("PREFS_CONFLICT","Known preference journal disappeared");
        if(!create)return {{},-1,true,false};
        opened=lease.files->open(journal_name,{true,true,true,true});created=true;
    }
    if(opened.error==host::FileError::denied){++lease.denied;bad("PREFS_DENIED","Private preference journal is denied");}
    if(opened.error!=host::FileError::none)bad("PREFS_UNAVAILABLE","Preference journal could not be opened");
    if(opened.value<3 || opened.value>std::numeric_limits<int>::max()) {
        if(opened.value>=0 && opened.value<=std::numeric_limits<int>::max())(void)lease.files->close(static_cast<int>(opened.value));
        bad("PREFS_UNAVAILABLE","Preference journal returned an invalid descriptor");
    }
    const auto descriptor=static_cast<int>(opened.value);Descriptor held{*lease.files,descriptor};std::size_t total=0;
    for(;;) {
        std::uint8_t extra=0;
        const auto room=std::min<std::size_t>(4080,journal_limit-total);
        const auto result=lease.files->read(descriptor,room?std::span(lease.disk).subspan(total,room):std::span<std::uint8_t>(&extra,1));
        if(result.error==host::FileError::denied){++lease.denied;bad("PREFS_DENIED","Preference journal read is denied");}
        if(result.error!=host::FileError::none || result.value<0 || static_cast<std::uint64_t>(result.value)>(room?room:1))bad("PREFS_UNAVAILABLE","Preference journal read failed");
        if(!result.value)break;
        if(!room)bad("PREFS_CORRUPT","Preference journal exceeds 64 KiB");total+=static_cast<std::size_t>(result.value);
    }
    Catalog catalog;if(!created)catalog=parse(std::span(lease.disk).first(total));
    else if(total)bad("PREFS_CORRUPT","New preference journal unexpectedly contains data");
    const auto checksum=total?crc(std::span(lease.disk).first(total)):0;
    if(lease.known && (lease.sequence!=catalog.sequence || lease.disk_size!=total || lease.head_crc!=checksum))bad("PREFS_CONFLICT","Preference journal changed outside this service");
    if(!lease.known){lease.known=true;lease.sequence=catalog.sequence;lease.disk_size=total;lease.head_crc=checksum;}
    held.closed=true;return {std::move(catalog),descriptor,false,created};
}
bool persist(Lease &lease,Transaction &transaction) noexcept {
    if(lease.poison || !lease.active)return false;
    lease.io_busy=true;struct End {bool &busy;~End(){busy=false;}} end{lease.io_busy};
    try {
        auto loaded=read_disk(lease,true);Descriptor descriptor{*lease.files,loaded.descriptor};
        patch(transaction.bytes,4,lease.sequence+1,8);patch(transaction.bytes,transaction.length-4,crc(std::span(transaction.bytes).first(transaction.length-4)),4);
        const auto prefix=loaded.created?magic.size():0;
        if(transaction.length+prefix>journal_limit-lease.disk_size)bad("PREFS_LIMIT","Preference journal is full");
        // Validate the proposed complete head before making any write.
        if(prefix)std::copy(magic.begin(),magic.end(),lease.disk.begin());
        std::copy_n(transaction.bytes.begin(),transaction.length,lease.disk.begin()+static_cast<std::ptrdiff_t>(lease.disk_size+prefix));
        const auto size=lease.disk_size+prefix+transaction.length;(void)parse(std::span(lease.disk).first(size));
        auto write=[&](std::span<const std::uint8_t> bytes) {
            while(!bytes.empty()) {
                const auto chunk=bytes.first(std::min<std::size_t>(4080,bytes.size()));const auto result=lease.files->write(descriptor.id,chunk);
                if(result.error==host::FileError::denied)++lease.denied;
                if(result.error!=host::FileError::none || result.value!=static_cast<std::int64_t>(chunk.size()))bad("PREFS_PERSISTENCE","Preference journal write was incomplete");
                bytes=bytes.subspan(chunk.size());
            }
        };
        if(prefix)write(magic);write(std::span(transaction.bytes).first(transaction.length));
        const auto flushed=lease.files->flush(descriptor.id);if(flushed.error==host::FileError::denied)++lease.denied;
        if(flushed.error!=host::FileError::none || flushed.value!=0)bad("PREFS_PERSISTENCE","Preference journal durability flush failed");
        if(!descriptor.close())bad("PREFS_PERSISTENCE","Preference journal close failed");
        lease.sequence+=1;lease.disk_size=size;lease.head_crc=crc(std::span(lease.disk).first(size));return true;
    } catch(...) {lease.poison=true;return false;}
}
bool drain_one(Lease &lease) noexcept {
    if(!lease.count)return !lease.poison;
    auto &transaction=lease.pending[lease.head];lease.head=(lease.head+1)%pending_limit;--lease.count;
    const auto result=persist(lease,transaction);transaction.length=0;return result;
}
bool drain(Lease &lease) noexcept {bool okay=!lease.poison;while(lease.count)okay=drain_one(lease)&&okay;return okay;}
struct Writer final:dex::ManagedWorkerEntry {
    std::shared_ptr<Lease> lease;std::array<Value,1> roots;
    Writer(std::shared_ptr<Lease> lease,ObjectId anchor):lease(std::move(lease)),roots{Value::reference(anchor)}{}
    std::span<const Value> values() const noexcept override{return roots;}
    // A retained worker may outlive the service anchor during teardown. Keep
    // its shared lease and bounded replay scratch independently charged.
    std::size_t bytes() const noexcept override{return sizeof(Writer)+sizeof(Lease)+scratch_reservation+256;}
    void run(dex::ManagedRuntime &runtime) override {
        try {
            while(lease->active) {
                while(lease->active && lease->count){(void)drain_one(*lease);runtime.worker_checkpoint();}
                if(lease->active)runtime.park_worker();
            }
        } catch(const std::exception &) {lease->poison=true;throw;}
    }
};
ObjectId reference(dex::ManagedRuntime &runtime,Value value){if(value.kind!=dex::ValueKind::reference && !(value.kind==dex::ValueKind::word && !value.bits))bad("PREFS_ARGUMENT","Preference API requires a reference");if(value.bits)(void)runtime.object_type(value.bits);return value.bits;}
std::u16string key(dex::ManagedRuntime &runtime,Value value){const auto id=reference(runtime,value);if(!id)runtime.raise("Ljava/lang/NullPointerException;");auto result=std::u16string(runtime.string(id));if(result.size()>256)bad("PREFS_LIMIT","Preference key exceeds 256 UTF16 units");return result;}
std::uint64_t scalar(Value value,bool wide){if(value.kind!=(wide?dex::ValueKind::wide:dex::ValueKind::word))bad("PREFS_ARGUMENT","Preference scalar has the wrong value kind");return wide?value.bits:static_cast<std::uint32_t>(value.bits);}
}
std::string_view preferences_owner(std::string_view type) noexcept {return type==preferences_store_impl?preferences_type:type==preferences_editor_impl?preferences_editor_type:type;}
std::optional<dex::HostClass> preferences_class(std::string_view type) {
    static constexpr std::array<std::string_view,1> store{preferences_type},editor{preferences_editor_type};
    if(type==preferences_type || type==preferences_editor_type)return dex::HostClass{"Ljava/lang/Object;",{},true,true};
    if(type==preferences_store_impl)return dex::HostClass{"Ljava/lang/Object;",store};
    if(type==preferences_editor_impl)return dex::HostClass{"Ljava/lang/Object;",editor};
    if(type==preferences_lease_impl)return dex::HostClass{"Ljava/lang/Object;"};
    return {};
}
struct PreferencesService::Impl {
    dex::ManagedRuntime &runtime;host::FileService *files;std::shared_ptr<Lease> lease;ObjectId anchor=0;bool closed=false;std::uint64_t closed_denials=0;
    Impl(dex::ManagedRuntime &runtime,host::FileService *files):runtime(runtime),files(files){}
    void ensure_anchor() {
        if(anchor)return;
        if(!lease){lease=std::make_shared<Lease>();lease->files=files;}
        const auto id=runtime.new_object(preferences_lease_impl);Root root(runtime,id);
        runtime.set_host_state(id,std::make_unique<Anchor>(lease,lease->roots));runtime.retain(id);anchor=id;
    }
    void check() {if(closed || (lease && !lease->active))bad("PREFS_CLOSED","Preference service is closed");if(lease && (lease->api_busy || lease->io_busy))bad("PREFS_REENTRANT","Preference service cannot reenter an active operation");}
    void require_access() {
        if(!lease->files)bad("PREFS_UNAVAILABLE","Private preference storage is unavailable");
        const auto access=lease->files->private_root();
        if(access.error==host::FileError::denied){++lease->denied;runtime.raise("Ljava/lang/SecurityException;",u"Private preference permission is denied");}
        if(access.error!=host::FileError::none || access.value!=0)bad("PREFS_UNAVAILABLE","Private preference root is unavailable");
    }
    const StoreState &store(ObjectId id) {
        const auto *state=dynamic_cast<const StoreState*>(runtime.host_state(id));
        if(!state || state->lease.lock()!=lease)bad("PREFS_RECEIVER","Preference store is not authenticated by this service");return *state;
    }
    const EditorState &editor(ObjectId id) {
        const auto *state=dynamic_cast<const EditorState*>(runtime.host_state(id));
        if(!state || state->lease.lock()!=lease)bad("PREFS_RECEIVER","Preference editor is not authenticated by this service");return *state;
    }
    bool publish(ObjectId receiver,const EditorState &editor_state,bool async) {
        const auto store_id=editor_state.roots[0].bits;const auto &current=store(store_id);
        entry_profile(current.entries);entry_profile(editor_state.changes);
        // Validate the serialized delta before copying potentially large edits.
        auto encoded=encode(current.name,editor_state.changes,editor_state.clear);Transaction transaction;transaction.length=encoded.size();std::copy(encoded.begin(),encoded.end(),transaction.bytes.begin());
        auto previous_store=std::make_unique<StoreState>(current);
        auto previous_editor=std::make_unique<EditorState>(editor_state);
        auto next=std::make_unique<StoreState>(current);merge(next->entries,editor_state.changes,editor_state.clear);entry_profile(next->entries);
        auto empty=std::make_unique<EditorState>();empty->lease=lease;empty->roots=editor_state.roots;
        if(async) {
            if(lease->poison)bad("PREFS_PERSISTENCE","Preference persistence is poisoned");
            if(lease->count==pending_limit)bad("PREFS_LIMIT","Preference apply FIFO is full");
            std::size_t projected=lease->disk_size?lease->disk_size:magic.size();for(std::size_t n=0;n<lease->count;++n)projected+=lease->pending[(lease->head+n)%pending_limit].length;
            if(transaction.length>journal_limit-projected)bad("PREFS_LIMIT","Pending preference journal exceeds 64 KiB");
        }
        runtime.set_host_state(store_id,std::move(next));runtime.set_host_state(receiver,std::move(empty));
        if(async) {
            if(!lease->worker) {
                try {lease->worker=runtime.schedule_worker(std::make_unique<Writer>(lease,anchor));}
                catch(...) {
                    const auto failure=std::current_exception();
                    try {runtime.set_host_state(store_id,std::move(previous_store));runtime.set_host_state(receiver,std::move(previous_editor));}
                    catch(...) {lease->poison=true;}
                    std::rethrow_exception(failure);
                }
            }
            lease->pending[(lease->head+lease->count)%pending_limit]=transaction;++lease->count;runtime.unpark_worker(lease->worker);return true;
        }
        const auto preceding=drain(*lease);return persist(*lease,transaction)&&preceding;
    }
};
PreferencesService::PreferencesService(dex::ManagedRuntime &runtime,host::FileService *files):impl_(std::make_unique<Impl>(runtime,files)){}
PreferencesService::~PreferencesService() {
    // Explicit close owns IO. Destruction never retries writes or flushes.
    if(!impl_ || impl_->closed || !impl_->lease)return;
    auto &p=*impl_;p.closed=true;p.lease->active=false;p.lease->files=nullptr;
    try {if(p.lease->worker)p.runtime.cancel_task(p.lease->worker);}catch(...){}
    if(p.anchor) {
        p.lease->roots.fill(Value::reference(0));
        try {p.runtime.set_host_state(p.anchor,nullptr);}catch(...){}
        try {p.runtime.release(p.anchor);}catch(...){}
    }
}
ObjectId PreferencesService::open(ObjectId context,std::u16string_view name,std::int32_t mode) {
    auto &p=*impl_;p.check();if(mode)bad("PREFS_MODE","Only private preference mode zero is supported");
    if(name.size()>256)bad("PREFS_LIMIT","Preference name exceeds 256 UTF16 units");(void)p.runtime.object_type(context);
    p.ensure_anchor();p.lease->api_busy=true;struct End {bool &busy;~End(){busy=false;}} end{p.lease->api_busy};p.require_access();
    for(std::size_t n=0;n<p.lease->stores;++n){const auto id=p.lease->roots[n].bits;if(p.store(id).name==name)return id;}
    if(p.lease->stores==16)bad("PREFS_LIMIT","Preference service exceeds sixteen stores");
    if(p.lease->poison)bad("PREFS_PERSISTENCE","Preference persistence is poisoned");
    ReadResult loaded;
    try {loaded=read_disk(*p.lease,false);}catch(const dex::DexError &error){if(error.code=="AETHER_ANDROID_PREFS_DENIED")p.runtime.raise("Ljava/lang/SecurityException;",u"Private preference permission is denied");throw;}
    if(!loaded.missing){Descriptor descriptor{*p.lease->files,loaded.descriptor};if(!descriptor.close()){p.lease->poison=true;bad("PREFS_UNAVAILABLE","Preference journal close failed");}}
    else {if(p.lease->known && p.lease->sequence)bad("PREFS_CONFLICT","Preference journal disappeared");p.lease->known=true;}
    auto state=std::make_unique<StoreState>();state->lease=p.lease;state->name=name;state->roots[0]=Value::reference(context);
    const auto found=std::find_if(loaded.catalog.stores.begin(),loaded.catalog.stores.end(),[&](const NamedStore &store){return store.name==name;});
    if(found!=loaded.catalog.stores.end())state->entries=found->entries;
    else if(loaded.catalog.stores.size()==16)bad("PREFS_LIMIT","Preference journal already contains sixteen stores");
    const auto id=p.runtime.new_object(preferences_store_impl);Root root(p.runtime,id);p.runtime.set_host_state(id,std::move(state));
    auto roots=p.lease->roots;roots[p.lease->stores]=Value::reference(id);p.runtime.set_host_state(p.anchor,std::make_unique<Anchor>(p.lease,roots));
    p.lease->roots=roots;++p.lease->stores;return id;
}
std::optional<Value> PreferencesService::invoke(dex::Index method,std::span<const Value> args) {
    const auto &image=impl_->runtime.image();if(method>=image.methods.size())bad("PREFS_ARGUMENT","Preference method index is invalid");
    const auto &declaration=image.methods[method];return invoke(image.types.at(declaration.owner),declaration.name,image.prototypes.at(declaration.prototype).descriptor,args);
}
std::optional<Value> PreferencesService::invoke(std::string_view owner,std::string_view name,std::string_view signature,std::span<const Value> args) {
    owner=preferences_owner(owner);if(owner!=preferences_type && owner!=preferences_editor_type)return {};
    auto &p=*impl_;p.check();if(!p.lease)bad("PREFS_RECEIVER","Preference receiver has no initialized service");if(args.empty())bad("PREFS_ARGUMENT","Preference receiver is absent");const auto receiver=reference(p.runtime,args[0]);
    p.lease->api_busy=true;struct End {bool &busy;~End(){busy=false;}} end{p.lease->api_busy};p.require_access();
    const auto arity=[&](std::size_t count){if(args.size()!=count)bad("PREFS_ARGUMENT","Preference method argument count differs");};
    if(owner==preferences_type) {
        const auto &state=p.store(receiver);
        if(name=="edit" && signature=="()Landroid/content/SharedPreferences$Editor;") {
            arity(1);auto editor=std::make_unique<EditorState>();editor->lease=p.lease;editor->roots[0]=Value::reference(receiver);
            const auto id=p.runtime.new_object(preferences_editor_impl);Root root(p.runtime,id);p.runtime.set_host_state(id,std::move(editor));return Value::reference(id);
        }
        if(name=="contains" && signature=="(Ljava/lang/String;)Z") {arity(2);const auto query=key(p.runtime,args[1]);return Value::word(std::any_of(state.entries.begin(),state.entries.end(),[&](const Entry &entry){return entry.key==query;}));}
        Kind kind;bool getter=true;
        if(name=="getInt" && signature=="(Ljava/lang/String;I)I")kind=Kind::integer;
        else if(name=="getLong" && signature=="(Ljava/lang/String;J)J")kind=Kind::long_integer;
        else if(name=="getFloat" && signature=="(Ljava/lang/String;F)F")kind=Kind::floating;
        else if(name=="getBoolean" && signature=="(Ljava/lang/String;Z)Z")kind=Kind::boolean;
        else if(name=="getString" && signature=="(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;")kind=Kind::string;
        else if(name=="getStringSet" && signature=="(Ljava/lang/String;Ljava/util/Set;)Ljava/util/Set;")kind=Kind::string_set;
        else {getter=false;kind=Kind::removed;}
        if(getter) {
            arity(3);const auto query=key(p.runtime,args[1]);
            if(kind==Kind::string){const auto fallback=reference(p.runtime,args[2]);if(fallback)(void)p.runtime.string(fallback);}
            else if(kind==Kind::string_set){const auto fallback=reference(p.runtime,args[2]);if(fallback && !p.runtime.assignable(fallback,"Ljava/util/Set;"))bad("PREFS_ARGUMENT","Preference default must be a Set");}
            else (void)scalar(args[2],kind==Kind::long_integer);
            const auto found=std::find_if(state.entries.begin(),state.entries.end(),[&](const Entry &entry){return entry.key==query;});
            if(found==state.entries.end())return args[2];if(found->kind!=kind)p.runtime.raise("Ljava/lang/ClassCastException;");
            if(kind==Kind::string_set)return Value::reference(p.runtime.new_string_set(found->strings));
            if(kind==Kind::string)return Value::reference(p.runtime.new_string(found->text));
            return kind==Kind::long_integer?Value::wide(found->bits):Value::word(static_cast<std::uint32_t>(found->bits));
        }
    } else {
        const auto &state=p.editor(receiver);
        if((name=="commit" && signature=="()Z") || (name=="apply" && signature=="()V")){arity(1);const auto result=p.publish(receiver,state,name=="apply");return name=="apply"?Value::nothing():Value::word(result);}
        const bool clear=name=="clear" && signature=="()Landroid/content/SharedPreferences$Editor;";
        const bool remove=name=="remove" && signature=="(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;";
        Kind kind=Kind::removed;bool put=true;
        if(name=="putInt" && signature=="(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;")kind=Kind::integer;
        else if(name=="putLong" && signature=="(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;")kind=Kind::long_integer;
        else if(name=="putFloat" && signature=="(Ljava/lang/String;F)Landroid/content/SharedPreferences$Editor;")kind=Kind::floating;
        else if(name=="putBoolean" && signature=="(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;")kind=Kind::boolean;
        else if(name=="putString" && signature=="(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;")kind=Kind::string;
        else if(name=="putStringSet" && signature=="(Ljava/lang/String;Ljava/util/Set;)Landroid/content/SharedPreferences$Editor;")kind=Kind::string_set;
        else put=false;
        if(clear || remove || put) {
            arity(clear?1:remove?2:3);entry_profile(state.changes);auto next=std::make_unique<EditorState>(state);
            if(clear)next->clear=true;
            else {
                Entry entry;entry.key=key(p.runtime,args[1]);entry.kind=kind;
                if(put && kind==Kind::string){const auto id=reference(p.runtime,args[2]);if(!id)entry.kind=Kind::removed;else {entry.text=p.runtime.string(id);if(entry.text.size()>4096)bad("PREFS_LIMIT","Preference string exceeds 4096 UTF16 units");}}
                else if(put && kind==Kind::string_set) {
                    const auto source=reference(p.runtime,args[2]);
                    if(!source)entry.kind=Kind::removed;
                    else {
                        if(!p.runtime.assignable(source,"Ljava/util/Set;"))bad("PREFS_ARGUMENT","Preference value must be a Set");
                        const auto iterator=reference(p.runtime,p.runtime.invoke_virtual_named(source,"iterator","()Ljava/util/Iterator;"));Root held(p.runtime,iterator);
                        std::size_t traversed=0;
                        while(p.runtime.invoke_virtual_named(iterator,"hasNext","()Z").bits) {
                            if(++traversed>128)bad("PREFS_LIMIT","Preference string set exceeds 128 traversed members");
                            const auto element=reference(p.runtime,p.runtime.invoke_virtual_named(iterator,"next","()Ljava/lang/Object;"));Root item(p.runtime,element);
                            if(element && !p.runtime.assignable(element,"Ljava/lang/String;"))p.runtime.raise("Ljava/lang/ClassCastException;");
                            std::optional<std::u16string> value;if(element)value=std::u16string(p.runtime.string(element));if(value && value->size()>4096)bad("PREFS_LIMIT","Preference string exceeds 4096 UTF16 units");
                            if(std::find(entry.strings.begin(),entry.strings.end(),value)==entry.strings.end())entry.strings.push_back(std::move(value));
                            Entries candidate{entry};entry_profile(candidate);
                        }
                    }
                }
                else if(put){entry.bits=scalar(args[2],kind==Kind::long_integer);if(kind==Kind::boolean)entry.bits=entry.bits!=0;}
                const auto found=std::find_if(next->changes.begin(),next->changes.end(),[&](const Entry &value){return value.key==entry.key;});
                if(found!=next->changes.end())*found=std::move(entry);else {if(next->changes.size()==128)bad("PREFS_LIMIT","Preference editor exceeds 128 modified keys");next->changes.push_back(std::move(entry));}
            }
            entry_profile(next->changes);p.runtime.set_host_state(receiver,std::move(next));return Value::reference(receiver);
        }
    }
    bad("API_UNSUPPORTED","SharedPreferences method is not implemented");
}
void PreferencesService::close() {
    auto &p=*impl_;if(p.closed)return;p.check();p.closed=true;if(!p.lease)return;const auto lease=p.lease;
    const bool terminated=p.runtime.process_state()->exit_status().has_value();
    const auto okay=terminated?true:drain(*lease);
    if(terminated){for(auto &transaction:lease->pending)transaction.length=0;lease->count=lease->head=0;}
    lease->active=false;lease->files=nullptr;p.closed_denials=lease->denied;
    std::exception_ptr cleanup_failure;
    if(lease->worker) {
        try {
            const auto state=p.runtime.task_state(lease->worker);
            if(state==dex::Scheduler::State::completed || state==dex::Scheduler::State::failed || state==dex::Scheduler::State::cancelled)p.runtime.release_task(lease->worker);
            else p.runtime.cancel_task(lease->worker);
        } catch(...) {cleanup_failure=std::current_exception();}
    }
    if(p.anchor) {
        lease->roots.fill(Value::reference(0));
        // Clearing existing state is loader/provider-independent teardown.
        try {p.runtime.set_host_state(p.anchor,nullptr);}
        catch(...) {if(!cleanup_failure)cleanup_failure=std::current_exception();}
        try {p.runtime.release(p.anchor);}catch(...) {if(!cleanup_failure)cleanup_failure=std::current_exception();}
        p.anchor=0;
    }
    p.lease.reset();if(!okay)bad("PREFS_PERSISTENCE","Preference persistence failed before close");
    if(cleanup_failure)std::rethrow_exception(cleanup_failure);
}
std::uint64_t PreferencesService::denials() const noexcept{return impl_->lease?impl_->lease->denied:impl_->closed_denials;}
}
