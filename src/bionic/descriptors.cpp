#include "descriptors.hpp"
#include "aether/a64/guest_memory.hpp"
#include "aether/host/entropy.hpp"
#include <algorithm>
#include <cstddef>
#include <limits>
#include <utility>
namespace aether::bionic {
namespace {
using host::FileResult;using host::FileError;constexpr FileResult bad{-1,FileError::bad_descriptor};
// Android NDK r30 aarch64 asm/fcntl.h and asm-generic/fcntl.h constants.
constexpr std::uint32_t access_mode=3,nonblocking=0x800,persistent_open=3|0x4000|0x8000;
}
struct NativeDescriptors::PipeChannel {
    std::array<std::uint8_t,pipe_capacity> bytes{};
    std::size_t head=0,size=0;
    std::uint64_t identity=0;
    std::weak_ptr<Description> reader,writer;
};
struct NativeDescriptors::Description {
    host::FileService *provider;
    int fd=-1;
    host::FileAccessScope scope=host::FileAccessScope::files_leaf;
    bool directory=false,event=false,semaphore=false,unlinked=false,entropy=false;
    std::uint32_t status_flags=0; // Actual access plus accepted immutable flags and shared O_NONBLOCK.
    unsigned standard=0; // 1: closed input, 2: diagnostic stdout, 3: diagnostic stderr.
    std::shared_ptr<StandardWrite> standard_write;
    std::shared_ptr<PipeChannel> pipe;
    std::shared_ptr<const PollSource> poll_source;
    bool pipe_reader=false;
    std::uint64_t counter=0;
    std::string name;
    explicit Description(host::FileService *value):provider(value){}
    FileResult close_once() noexcept {
        if(standard || event || pipe || poll_source || entropy || (directory && fd<0))return {0,FileError::none};
        if(fd<0)return bad;
        const auto old=std::exchange(fd,-1);
        const auto result=provider->close(old);
        return result.error==FileError::none && result.value!=0?FileResult{-1,FileError::io}:result;
    }
    ~Description(){if(fd>=0)(void)close_once();}
};
NativeDescriptors::~NativeDescriptors()=default;
void NativeDescriptors::initialize_standard_streams(StandardWrite sink) {
    if(standard_initialized_ || soft_limit_<3 || get(0) || get(1) || get(2))
        throw a64::GuestError("AETHER_GUEST_STDIO","Standard descriptors require unused initial slots");
    // Allocate all ownership state before installing any of the three aliases.
    const auto writer=std::make_shared<StandardWrite>(std::move(sink));
    std::array<std::shared_ptr<Description>,3> descriptions;
    for(unsigned i=0;i<descriptions.size();++i){
        descriptions[i]=std::make_shared<Description>(nullptr);
        descriptions[i]->standard=i+1;
        descriptions[i]->status_flags=i?1u:0u; // O_WRONLY output; O_RDONLY closed input.
        descriptions[i]->standard_write=writer;
    }
    for(unsigned i=0;i<descriptions.size();++i){entries_[i].description=std::move(descriptions[i]);entries_[i].close_on_exec=false;}
    standard_initialized_=true;
}
NativeDescriptors::Description *NativeDescriptors::get(int fd) const noexcept {
    return fd>=0 && static_cast<std::size_t>(fd)<entries_.size()?entries_[static_cast<std::size_t>(fd)].description.get():nullptr;
}
FileResult NativeDescriptors::private_root() noexcept {return provider_?provider_->private_root():FileResult{-1,FileError::denied};}
FileResult NativeDescriptors::observe_data_file(std::string_view name){return provider_?provider_->observe_data_file(name):FileResult{-1,FileError::denied};}
FileResult NativeDescriptors::list_directory(std::vector<host::DirectoryEntry> &output){return provider_?provider_->list_directory(output):FileResult{-1,FileError::denied};}
FileResult NativeDescriptors::access(host::FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept {return provider_?provider_->access(scope,name,mode):FileResult{-1,FileError::denied};}
FileResult NativeDescriptors::access_path(host::FileAccessScope scope,std::string_view name,std::uint32_t mode,bool directory_required) noexcept {
    if(!provider_)return {-1,FileError::denied};
    if(name.empty() && (scope==host::FileAccessScope::files_root || scope==host::FileAccessScope::data_root))return provider_->access(scope,name,mode);
    return provider_->access_path(scope,name,mode,directory_required);
}
FileResult NativeDescriptors::open(std::string_view name,host::FileOpen options){return open_scoped(host::FileAccessScope::files_leaf,name,options);}
FileResult NativeDescriptors::open_scoped(host::FileAccessScope scope,std::string_view name,host::FileOpen options){
    return open_owned(scope,name,options,false);
}
FileResult NativeDescriptors::open_directory(host::FileAccessScope scope,std::string_view name) {
    return open_owned(scope,name,{},true);
}
FileResult NativeDescriptors::open_owned(host::FileAccessScope scope,std::string_view name,host::FileOpen options,bool directory,int parent,std::string_view display) {
    if(!directory && !options.read && !options.write)return {-1,FileError::invalid};
    if(!host::valid_file_access(scope,display.empty()?name:display,0))return {-1,FileError::invalid};
    if(!provider_)return {-1,FileError::denied};
    const bool root=scope==host::FileAccessScope::files_root || scope==host::FileAccessScope::data_root;
    if(root && !directory)return {-1,FileError::is_directory};
    const auto end=entries_.begin()+static_cast<std::ptrdiff_t>(soft_limit_);
    const auto slot=std::find_if(entries_.begin(),end,[](const auto &entry){return !entry.description;});
    if(slot==end)return {-1,FileError::descriptor_limit};
    auto description=std::make_shared<Description>(provider_);
    description->name=display.empty()?name:display;description->scope=scope;description->directory=directory;
    description->status_flags=directory?0u:options.read?(options.write?2u:0u):1u;
    if(root && parent<0){
        // Preserve the existing provider-observed immutable logical-root aliases.
        const auto observed=provider_->access(scope,"",4);
        if(observed.error!=FileError::none)return observed;
        if(observed.value!=0)return {-1,FileError::io};
    }else{
        const auto opened=directory?(parent>=0?provider_->open_directory_relative(parent,name):provider_->open_directory(scope,name)):
            parent>=0?provider_->open_relative(parent,name,options):scope==host::FileAccessScope::files_leaf?provider_->open(name,options):provider_->open_scoped(scope,name,options);
        if(opened.error!=FileError::none)return opened;
        if(opened.value<0 || opened.value>std::numeric_limits<int>::max())return {-1,FileError::io};
        description->fd=static_cast<int>(opened.value);
    }
    slot->description=std::move(description);slot->close_on_exec=false;
    return {slot-entries_.begin(),FileError::none};
}
FileResult NativeDescriptors::relative_target(int fd,std::string_view path,host::FileAccessScope &scope,std::string &name,int &parent) const {
    const auto d=get(fd);if(!d)return bad;if(!d->directory)return {-1,FileError::not_directory};
    scope=d->scope;parent=d->fd;
    if(parent>=0){
        name=d->name;if(!path.empty()){if(!name.empty())name+='/';name+=path;}
    }else{
        name=path;
        if(scope==host::FileAccessScope::data_root){
            if(name=="files"){scope=host::FileAccessScope::files_root;name.clear();}
            else if(name.starts_with("files/")){scope=host::FileAccessScope::files_root;name.erase(0,6);}
        }
        if(!name.empty())scope=scope==host::FileAccessScope::files_root?host::FileAccessScope::files_leaf:host::FileAccessScope::data_leaf;
    }
    return host::valid_file_access(scope,name,0)?FileResult{0,FileError::none}:FileResult{-1,FileError::unsupported};
}
FileResult NativeDescriptors::open_at(int directory,std::string_view path,host::FileOpen options) {
    host::FileAccessScope scope;std::string name;int parent=-1;
    const auto resolved=relative_target(directory,path,scope,name,parent);if(resolved.error!=FileError::none)return resolved;
    return open_owned(scope,parent<0?std::string_view(name):path,options,false,parent,name);
}
FileResult NativeDescriptors::open_directory_at(int directory,std::string_view path) {
    host::FileAccessScope scope;std::string name;int parent=-1;
    const auto resolved=relative_target(directory,path,scope,name,parent);if(resolved.error!=FileError::none)return resolved;
    return open_owned(scope,parent<0?std::string_view(name):path,{},true,parent,name);
}
FileResult NativeDescriptors::make_directory(host::FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept {
    return provider_?provider_->make_directory(scope,name,mode):FileResult{-1,FileError::denied};
}
FileResult NativeDescriptors::make_directory_at(int directory,std::string_view path,std::uint32_t mode) noexcept {
    try{host::FileAccessScope scope;std::string name;int parent=-1;
        const auto resolved=relative_target(directory,path,scope,name,parent);if(resolved.error!=FileError::none)return resolved;
        return parent<0?make_directory(scope,name,mode):provider_->make_directory_relative(parent,path,mode);
    }catch(...){return {-1,FileError::io};}
}
FileResult NativeDescriptors::access_at(int directory,std::string_view path,std::uint32_t mode,bool directory_required) noexcept {
    try{host::FileAccessScope scope;std::string name;int parent=-1;
        const auto resolved=relative_target(directory,path,scope,name,parent);if(resolved.error!=FileError::none)return resolved;
        return parent<0?access_path(scope,name,mode,directory_required):provider_->access_relative_path(parent,path,mode,directory_required);
    }catch(...){return {-1,FileError::io};}
}
FileResult NativeDescriptors::remove_at(int directory,std::string_view path,host::FileRemoveMode mode,bool directory_required) noexcept {
    try{host::FileAccessScope scope;std::string name;int parent=-1;
        const auto resolved=relative_target(directory,path,scope,name,parent);if(resolved.error!=FileError::none)return resolved;
        return remove_owned(scope,name,mode,directory_required,parent,path);
    }catch(...){return {-1,FileError::io};}
}
FileResult NativeDescriptors::directory_scope(int fd) const noexcept {
    const auto d=get(fd);if(!d)return bad;
    return d->directory?FileResult{static_cast<std::int64_t>(d->scope),FileError::none}:FileResult{-1,FileError::not_directory};
}
FileResult NativeDescriptors::rename_path(const host::FilePathRef &source,const host::FilePathRef &destination,host::FileRenameInfo &output) noexcept {
    if(!provider_)return {-1,FileError::denied};
    try {
        std::array<host::FilePathRef,2> endpoints{source,destination};
        std::array<std::string,2> displays;
        for(std::size_t i=0;i<endpoints.size();++i){
            auto &endpoint=endpoints[i];
            if(endpoint.directory>=0){
                host::FileAccessScope scope;int parent=-1;
                const auto resolved=relative_target(endpoint.directory,endpoint.name,scope,displays[i],parent);
                if(resolved.error!=FileError::none)return resolved;
                endpoint.scope=scope;endpoint.directory=parent;
                if(parent<0)endpoint.name=displays[i];
            }
            if(!host::valid_file_path(endpoint.name) || static_cast<unsigned>(endpoint.scope)<2 || static_cast<unsigned>(endpoint.scope)>3)return {-1,FileError::denied};
        }
        // Allocate all possible display storage before the sole provider mutation.
        std::array<Description*,256> descriptions{};std::size_t count=0;
        for(const auto &entry:entries_){
            const auto d=entry.description.get();if(!d || d->standard || d->event || d->pipe || d->poll_source || d->fd<0)continue;
            if(std::find(descriptions.begin(),descriptions.begin()+static_cast<std::ptrdiff_t>(count),d)!=descriptions.begin()+static_cast<std::ptrdiff_t>(count))continue;
            d->name.reserve(host::private_path_limit);descriptions[count++]=d;
        }
        host::FileRenameInfo changed;
        const auto result=provider_->rename_path(endpoints[0],endpoints[1],changed);
        if(result.error!=FileError::none)return result;
        if(result.value!=0 || !changed.source_identity || changed.source_identity>4096 || changed.replaced_identity>4096 ||
            changed.source_identity==changed.replaced_identity || changed.relocation_count>changed.relocations.size() ||
            (changed.unchanged && (changed.replaced_identity || changed.relocation_count)))return {-1,FileError::io};
        // Validate every row before publishing any display or deleted-state change.
        for(std::size_t i=0;i<changed.relocation_count;++i){const auto &row=changed.relocations[i];
            if(row.descriptor<0 || !row.identity || row.identity>4096 || row.name_length>host::private_path_limit ||
                !host::valid_file_path(std::string_view(row.name.data(),row.name_length)) ||
                (row.scope!=host::FileAccessScope::files_leaf && row.scope!=host::FileAccessScope::data_leaf) ||
                (row.unlinked && row.identity!=changed.replaced_identity))return {-1,FileError::io};
            for(std::size_t prior=0;prior<i;++prior)if(changed.relocations[prior].descriptor==row.descriptor)return {-1,FileError::io};
            for(std::size_t n=0;n<count;++n)if(descriptions[n]->fd==row.descriptor && descriptions[n]->directory!=row.directory)return {-1,FileError::io};
        }
        for(std::size_t i=0;i<changed.relocation_count;++i){const auto &row=changed.relocations[i];
            for(std::size_t n=0;n<count;++n){const auto d=descriptions[n];if(d->fd!=row.descriptor)continue;
                d->scope=row.scope;d->name.assign(row.name.data(),row.name_length);d->unlinked=row.unlinked;
            }
        }
        output=changed;return result;
    }catch(...){return {-1,FileError::io};}
}
FileResult NativeDescriptors::event(std::uint32_t initial,std::uint32_t flags) {
    if(flags&~std::uint32_t{1|0x800|0x80000})return {-1,FileError::invalid};
    const auto end=entries_.begin()+static_cast<std::ptrdiff_t>(soft_limit_);
    const auto slot=std::find_if(entries_.begin(),end,[](const auto &entry){return !entry.description;});
    if(slot==end)return {-1,FileError::descriptor_limit};
    auto description=std::make_shared<Description>(nullptr);
    description->event=true;description->counter=initial;description->semaphore=flags&1;
    description->status_flags=2u|(flags&nonblocking); // eventfd is always O_RDWR.
    slot->description=std::move(description);slot->close_on_exec=flags&0x80000;
    return {slot-entries_.begin(),FileError::none};
}
bool NativeDescriptors::is_event(int fd) const noexcept {const auto d=get(fd);return d && d->event;}
FileResult NativeDescriptors::entropy_device(std::uint32_t flags) {
    constexpr std::uint32_t cloexec=0x80000,nofollow=0x8000,noctty=0x100,directory=0x4000;
    if(flags&directory)return {-1,FileError::not_directory};
    if((flags&access_mode) || (flags&~(nonblocking|cloexec|nofollow|noctty)))return {-1,FileError::unsupported};
    const auto end=entries_.begin()+static_cast<std::ptrdiff_t>(soft_limit_);
    const auto slot=std::find_if(entries_.begin(),end,[](const auto &entry){return !entry.description;});
    if(slot==end)return {-1,FileError::descriptor_limit};
    auto description=std::make_shared<Description>(nullptr);
    description->entropy=true;description->status_flags=flags&(nonblocking|nofollow);
    slot->description=std::move(description);slot->close_on_exec=(flags&cloexec)!=0;
    return {slot-entries_.begin(),FileError::none};
}
bool NativeDescriptors::is_entropy(int fd) const noexcept {const auto d=get(fd);return d && d->entropy;}
FileResult NativeDescriptors::poll_source(std::shared_ptr<const PollSource> source) {
    if(!source)return {-1,FileError::invalid};
    const auto end=entries_.begin()+static_cast<std::ptrdiff_t>(soft_limit_);
    const auto slot=std::find_if(entries_.begin(),end,[](const auto &entry){return !entry.description;});
    if(slot==end)return {-1,FileError::descriptor_limit};
    auto description=std::make_shared<Description>(nullptr);
    description->poll_source=std::move(source);description->status_flags=nonblocking;
    slot->description=std::move(description);slot->close_on_exec=true;
    return {slot-entries_.begin(),FileError::none};
}
FileResult NativeDescriptors::pipe(std::uint32_t flags,std::array<int,2> &output) {
    constexpr std::uint32_t close_on_exec=0x80000;
    if(flags&~(nonblocking|close_on_exec))return {-1,FileError::invalid};
    std::array<std::size_t,2> slots{};std::size_t count=0;
    for(std::size_t index=0;index<soft_limit_ && count<slots.size();++index)
        if(!entries_[index].description)slots[count++]=index;
    if(count!=slots.size())return {-1,FileError::descriptor_limit};
    const auto charged=std::find_if(pipes_.begin(),pipes_.end(),[](const auto &channel){return channel.expired();});
    if(charged==pipes_.end() || next_pipe_identity_==std::numeric_limits<std::uint64_t>::max())
        return {-1,FileError::quota};
    // No guest callback or other owner can observe either slot during admission.
    // Construct everything that can allocate before publishing the pair.
    auto channel=std::make_shared<PipeChannel>();
    auto reader=std::make_shared<Description>(nullptr),writer=std::make_shared<Description>(nullptr);
    channel->identity=next_pipe_identity_;
    reader->pipe=writer->pipe=channel;reader->pipe_reader=true;
    reader->status_flags=flags&nonblocking;writer->status_flags=1u|(flags&nonblocking);
    channel->reader=reader;channel->writer=writer;
    *charged=channel;
    entries_[slots[0]]={std::move(reader),(flags&close_on_exec)!=0};
    entries_[slots[1]]={std::move(writer),(flags&close_on_exec)!=0};
    ++next_pipe_identity_;
    output={static_cast<int>(slots[0]),static_cast<int>(slots[1])};
    return {0,FileError::none};
}
bool NativeDescriptors::is_pipe(int fd) const noexcept {const auto d=get(fd);return d && d->pipe;}
std::shared_ptr<const void> NativeDescriptors::event_identity(int fd) const noexcept {
    const auto description = get(fd);
    if (!description || !description->event) return {};
    return entries_[static_cast<std::size_t>(fd)].description;
}
std::shared_ptr<const void> NativeDescriptors::poll_identity(int fd) const noexcept {
    const auto description=get(fd);
    if(!description || (!description->event && !description->pipe && !description->poll_source))return {};
    return entries_[static_cast<std::size_t>(fd)].description;
}
std::shared_ptr<const void> NativeDescriptors::descriptor_identity(int fd) const noexcept {
    if(!get(fd))return {};
    return entries_[static_cast<std::size_t>(fd)].description;
}
NativeDescriptors::PinnedIo::PinnedIo(std::shared_ptr<Description> description,IoDirection direction,std::size_t size) noexcept
    :description_(std::move(description)),direction_(direction),original_size_(size) {}
std::optional<NativeDescriptors::PinnedIo> NativeDescriptors::pin_io(int fd,IoDirection direction,std::size_t size) const noexcept {
    const auto description=get(fd);
    if(!description || (!description->event && !description->pipe))return {};
    return PinnedIo(entries_[static_cast<std::size_t>(fd)].description,direction,size);
}
NativeDescriptors::IoStep NativeDescriptors::PinnedIo::read_step(std::span<std::uint8_t> output) const noexcept {
    if(!description_ || direction_!=IoDirection::read)return {bad};
    if(output.size()!=original_size_)return {{-1,FileError::invalid}};
    auto &description=*description_;
    if(description.pipe){
        if(!description.pipe_reader)return {bad};
        if(output.empty())return {{0,FileError::none}};
        auto &channel=*description.pipe;
        if(!channel.size){
            if(channel.writer.expired())return {{0,FileError::none}};
            return {{-1,FileError::would_block},false,(description.status_flags&nonblocking)==0};
        }
        const auto count=std::min(output.size(),channel.size);
        for(std::size_t index=0;index<count;++index)output[index]=channel.bytes[(channel.head+index)%pipe_capacity];
        channel.head=(channel.head+count)%pipe_capacity;channel.size-=count;
        return {{static_cast<std::int64_t>(count),FileError::none}};
    }
    if(output.size()<8)return {{-1,FileError::invalid}};
    if(!description.counter)
        return {{-1,FileError::would_block},false,(description.status_flags&nonblocking)==0};
    const auto value=description.semaphore?1:description.counter;
    for(unsigned index=0;index<8;++index)output[index]=static_cast<std::uint8_t>(value>>(8*index));
    description.counter-=value;
    return {{8,FileError::none}};
}
NativeDescriptors::IoStep NativeDescriptors::PinnedIo::write_step(std::span<const std::uint8_t> input) const noexcept {
    if(!description_ || direction_!=IoDirection::write)return {bad};
    if(input.size()>original_size_)return {{-1,FileError::invalid}};
    auto &description=*description_;
    if(description.pipe){
        if(description.pipe_reader)return {bad};
        const bool atomic=original_size_<=pipe_atomic_limit;
        if(atomic && input.size()!=original_size_)return {{-1,FileError::invalid}};
        if(input.empty())return {{0,FileError::none}};
        auto &channel=*description.pipe;
        if(channel.reader.expired())return {{-1,FileError::unsupported},true};
        const auto space=pipe_capacity-channel.size;
        if(!space || (atomic && space<input.size()))
            return {{-1,FileError::would_block},false,(description.status_flags&nonblocking)==0};
        const auto count=std::min(space,input.size());
        for(std::size_t index=0;index<count;++index)
            channel.bytes[(channel.head+channel.size+index)%pipe_capacity]=input[index];
        channel.size+=count;
        return {{static_cast<std::int64_t>(count),FileError::none},false,
                count<input.size() && (description.status_flags&nonblocking)==0};
    }
    if(original_size_!=8 || input.size()!=8)return {{-1,FileError::invalid}};
    std::uint64_t value=0;
    for(unsigned index=0;index<8;++index)value|=std::uint64_t{input[index]}<<(8*index);
    constexpr auto maximum=UINT64_MAX-1;
    if(value>maximum)return {{-1,FileError::invalid}};
    if(value>maximum-description.counter)
        return {{-1,FileError::would_block},false,(description.status_flags&nonblocking)==0};
    description.counter+=value;
    return {{8,FileError::none}};
}
bool NativeDescriptors::PinnedIo::read_ready() const noexcept {
    if(!description_ || direction_!=IoDirection::read)return true;
    const auto &description=*description_;
    if(description.pipe)
        return !description.pipe_reader || !original_size_ || description.pipe->size ||
            description.pipe->writer.expired() || (description.status_flags&nonblocking);
    return original_size_<8 || description.counter || (description.status_flags&nonblocking);
}
bool NativeDescriptors::PinnedIo::write_ready(std::span<const std::uint8_t> input) const noexcept {
    if(!description_ || direction_!=IoDirection::write || input.size()>original_size_)return true;
    const auto &description=*description_;
    if(description.pipe){
        const bool atomic=original_size_<=pipe_atomic_limit;
        if(description.pipe_reader || (atomic && input.size()!=original_size_) || input.empty() ||
           description.pipe->reader.expired() || (description.status_flags&nonblocking))return true;
        const auto space=pipe_capacity-description.pipe->size;
        return atomic?space>=input.size():space!=0;
    }
    if(original_size_!=8 || input.size()!=8 || (description.status_flags&nonblocking))return true;
    std::uint64_t value=0;
    for(unsigned index=0;index<8;++index)value|=std::uint64_t{input[index]}<<(8*index);
    constexpr auto maximum=UINT64_MAX-1;
    return value>maximum || value<=maximum-description.counter;
}
std::uint16_t NativeDescriptors::readiness(int fd,std::uint16_t events) const noexcept {
    if(fd<0)return 0;
    const auto description=get(fd);if(!description)return 0x20; // POLLNVAL, even without requested events.
    if(description->poll_source){
        const auto ready=description->poll_source->readiness();
        constexpr std::uint16_t allowed=0x01|0x40|0x08|0x10|0x20;
        if(ready&~allowed)return 0x20;
        return static_cast<std::uint16_t>((ready&events)|(ready&(0x08|0x10|0x20)));
    }
    if(description->pipe){
        const auto &channel=*description->pipe;
        unsigned ready=0;
        if(description->pipe_reader){
            if(channel.size)ready|=0x41; // POLLIN|POLLRDNORM may coexist with HUP.
            if(channel.writer.expired())ready|=0x10;
        }else{
            if(channel.size<pipe_capacity)ready|=0x104; // POLLOUT|POLLWRNORM, including a possible short write.
            if(channel.reader.expired())ready|=0x08;
        }
        return static_cast<std::uint16_t>((ready&events)|(ready&(0x08|0x10)));
    }
    unsigned ready=0x145; // Regular files: POLLIN|POLLOUT|POLLRDNORM|POLLWRNORM.
    if(description->entropy)ready=0x41; // An owned secure-random read never waits for another guest.
    if(description->standard)ready=description->standard==1?0x41U:0x104U;
    if(description->event)ready=(description->counter?1U:0U)|(description->counter<UINT64_MAX-1?4U:0U);
    return static_cast<std::uint16_t>(ready&events);
}
FileResult NativeDescriptors::read(int fd,std::span<std::uint8_t> output) noexcept {
    try{return read_wait(fd,output,{});}catch(...){return {-1,FileError::io};}
}
FileResult NativeDescriptors::write(int fd,std::span<const std::uint8_t> input) noexcept {
    try{return write_wait(fd,input,{});}catch(...){return {-1,FileError::io};}
}
FileResult NativeDescriptors::read_wait(int fd,std::span<std::uint8_t> output,const Progress &progress) {
    if(!get(fd))return bad;
    // Pin the open description across nested work, including close/dup2/reuse of fd.
    const auto description=entries_[static_cast<std::size_t>(fd)].description;
    if(description->poll_source)return {-1,FileError::unsupported};
    if(description->entropy){
        if(output.size()>host::private_file_size_limit)return {-1,FileError::invalid};
        std::array<std::uint8_t,4096> bytes{};
        std::size_t completed=0;
        while(completed<output.size()){
            const auto count=std::min(bytes.size(),output.size()-completed);
            const auto chunk=std::span(bytes).first(count);
            if(!host::secure_random(chunk))return completed?FileResult{static_cast<std::int64_t>(completed),FileError::none}:FileResult{-1,FileError::io};
            std::copy_n(bytes.data(),count,output.data()+completed);completed+=count;
        }
        return {static_cast<std::int64_t>(completed),FileError::none};
    }
    if(description->standard)return description->standard==1?FileResult{0,FileError::none}:bad;
    if(description->directory)return {-1,FileError::is_directory};
    if(description->pipe){
        if(!description->pipe_reader)return bad;
        if(output.empty())return {0,FileError::none};
        auto &channel=*description->pipe;
        while(!channel.size){
            if(channel.writer.expired())return {0,FileError::none};
            if(description->status_flags&nonblocking)return {-1,FileError::would_block};
            if(!progress || !progress())return {-1,FileError::unsupported};
        }
        const auto count=std::min(output.size(),channel.size);
        for(std::size_t index=0;index<count;++index)output[index]=channel.bytes[(channel.head+index)%pipe_capacity];
        channel.head=(channel.head+count)%pipe_capacity;channel.size-=count;
        return {static_cast<std::int64_t>(count),FileError::none};
    }
    if(description->event) {
        if(output.size()<8)return {-1,FileError::invalid};
        while(!description->counter) {
            if(description->status_flags&nonblocking)return {-1,FileError::would_block};
            if(!progress || !progress())return {-1,FileError::unsupported};
        }
        const auto value=description->semaphore?1:description->counter;
        for(unsigned i=0;i<8;++i)output[i]=static_cast<std::uint8_t>(value>>(8*i));
        description->counter-=value;return {8,FileError::none};
    }
    const auto result=description->provider->read(description->fd,output);
    if(result.error==FileError::none && (result.value<0 || static_cast<std::uint64_t>(result.value)>output.size()))return {-1,FileError::io};
    return result;
}
FileResult NativeDescriptors::write_wait(int fd,std::span<const std::uint8_t> input,const Progress &progress) {
    // Generic FileService/stdio callers cannot carry the required SIGPIPE
    // outcome. Refuse before publishing bytes rather than dropping the signal.
    if(const auto description=get(fd);description && description->pipe)
        return description->pipe_reader?bad:FileResult{-1,FileError::unsupported};
    return write_wait_outcome(fd,input,progress).result;
}
NativeDescriptors::WriteOutcome NativeDescriptors::write_wait_outcome(int fd,std::span<const std::uint8_t> input,const Progress &progress) {
    const auto write_ordinary=[&]() -> FileResult {
    if(!get(fd))return bad;
    const auto description=entries_[static_cast<std::size_t>(fd)].description;
    if(description->poll_source)return {-1,FileError::unsupported};
    if(description->entropy)return bad;
    if(description->pipe){
        if(description->pipe_reader)return bad;
        // Handled separately below, preserving the pinned endpoint identity.
        return {-1,FileError::unsupported};
    }
    if(description->standard){
        if(description->standard==1)return bad;
        if(input.size()>host::private_file_size_limit)return {-1,FileError::unsupported};
        if(input.empty())return {0,FileError::none};
        try{
            if(!description->standard_write || !*description->standard_write ||
               !(*description->standard_write)(static_cast<int>(description->standard-1),input))return {-1,FileError::io};
        }catch(...){return {-1,FileError::io};}
        return {static_cast<std::int64_t>(input.size()),FileError::none};
    }
    if(description->directory)return bad; // Root descriptions are opened read-only.
    if(description->event) {
        if(input.size()!=8)return {-1,FileError::invalid};
        std::uint64_t value=0;for(unsigned i=0;i<8;++i)value|=std::uint64_t{input[i]}<<(8*i);
        constexpr auto maximum=std::numeric_limits<std::uint64_t>::max()-1;
        if(value>maximum)return {-1,FileError::invalid};
        while(value>maximum-description->counter) {
            if(description->status_flags&nonblocking)return {-1,FileError::would_block};
            if(!progress || !progress())return {-1,FileError::unsupported};
        }
        description->counter+=value;return {8,FileError::none};
    }
    const auto result=description->provider->write(description->fd,input);
    if(result.error==FileError::none && (result.value<0 || static_cast<std::uint64_t>(result.value)>input.size()))return {-1,FileError::io};
    return result;
    };
    if(!is_pipe(fd))return {write_ordinary(),false};
    const auto description=entries_[static_cast<std::size_t>(fd)].description;
    if(description->pipe_reader)return {bad,false};
    if(input.empty())return {{0,FileError::none},false};
    auto &channel=*description->pipe;
    std::size_t written=0;
    const bool atomic=input.size()<=pipe_atomic_limit;
    while(written<input.size()){
        if(channel.reader.expired())
            return {{written?static_cast<std::int64_t>(written):-1,written?FileError::none:FileError::unsupported},true};
        const auto space=pipe_capacity-channel.size;
        if(!space || (atomic && space<input.size())){
            if(description->status_flags&nonblocking)
                return {{written?static_cast<std::int64_t>(written):-1,written?FileError::none:FileError::would_block},false};
            if(!progress || !progress())
                return {{written?static_cast<std::int64_t>(written):-1,FileError::unsupported},false};
            continue;
        }
        const auto count=std::min(space,input.size()-written);
        for(std::size_t index=0;index<count;++index)
            channel.bytes[(channel.head+channel.size+index)%pipe_capacity]=input[written+index];
        channel.size+=count;written+=count;
        if((description->status_flags&nonblocking) && !atomic)break;
    }
    return {{static_cast<std::int64_t>(written),FileError::none},false};
}
FileResult NativeDescriptors::close(int fd) noexcept {
    if(!get(fd))return bad;
    auto &entry=entries_[static_cast<std::size_t>(fd)];const bool last=entry.description.use_count()==1;
    auto description=std::move(entry.description);entry.close_on_exec=false;
    return last?description->close_once():FileResult{0,FileError::none};
}
FileResult NativeDescriptors::flush(int fd) noexcept {
    const auto description=get(fd);if(!description)return bad;
    if(description->poll_source)return {-1,FileError::unsupported};
    if(description->standard)return description->standard==1?FileResult{-1,FileError::invalid}:FileResult{0,FileError::none};
    return (description->event || description->pipe || description->poll_source || description->directory || description->entropy)?FileResult{-1,FileError::invalid}:description->provider->flush(description->fd);
}
FileResult NativeDescriptors::lock(int fd,std::uint32_t operation) noexcept {
    const auto description=get(fd);if(!description)return bad;
    if(!host::valid_file_lock(operation))return {-1,FileError::invalid};
    return (description->standard || description->event || description->pipe || description->poll_source || description->directory || description->entropy)?FileResult{-1,FileError::unsupported}:description->provider->lock(description->fd,operation);
}
bool NativeDescriptors::set_descriptor_limits(std::uint64_t soft,std::uint64_t hard) noexcept {
    if(soft>hard || hard>hard_limit_ || hard>entries_.size())return false;
    soft_limit_=soft;hard_limit_=hard;return true;
}
FileResult NativeDescriptors::duplicate_to(int old_fd,int new_fd) noexcept {
    if(!get(old_fd) || new_fd<0 || static_cast<std::size_t>(new_fd)>=entries_.size())return bad;
    if(old_fd==new_fd)return {new_fd,FileError::none};
    if(static_cast<std::uint64_t>(new_fd)>=soft_limit_)return bad;
    auto source=entries_[static_cast<std::size_t>(old_fd)].description;
    auto &target=entries_[static_cast<std::size_t>(new_fd)];
    // A shared_ptr assignment is allocation-free. No guest thread can observe a closed gap.
    auto displaced=std::move(target.description);target.description=std::move(source);target.close_on_exec=false;
    // Last displaced close is best effort, exactly once; dup2 does not report its close error.
    displaced.reset();return {new_fd,FileError::none};
}
void NativeDescriptors::set_close_on_exec(int fd,bool value) noexcept {if(get(fd))entries_[static_cast<std::size_t>(fd)].close_on_exec=value;}
void NativeDescriptors::record_open_status(int fd,std::uint32_t original_flags) noexcept {
    const auto description=get(fd);
    if(!description || description->standard || description->event || description->pipe || description->poll_source || description->entropy)return;
    // Access was established by the successful provider open. Request metadata
    // must agree with it, including read-only directory fallback, never widen it.
    if((original_flags&access_mode)!=(description->status_flags&access_mode))return;
    description->status_flags=(description->status_flags&nonblocking)|(original_flags&persistent_open);
}
FileResult NativeDescriptors::control(int fd,int command,std::uint64_t argument) noexcept {
    const auto description=get(fd);if(!description)return bad;
    auto &entry=entries_[static_cast<std::size_t>(fd)];
    // These commands take an int argument in the Android ABI. Upper register
    // bits are not part of that value (and GET commands ignore the argument).
    const auto flags=static_cast<std::uint32_t>(argument);
    switch(command){
    case 0:case 1030:{ // F_DUPFD / F_DUPFD_CLOEXEC: lowest free descriptor >= arg.
        if(flags>=soft_limit_)return {-1,FileError::invalid};
        const auto begin=entries_.begin()+static_cast<std::ptrdiff_t>(flags);
        const auto end=entries_.begin()+static_cast<std::ptrdiff_t>(soft_limit_);
        const auto slot=std::find_if(begin,end,[](const auto &candidate){return !candidate.description;});
        if(slot==end)return {-1,FileError::descriptor_limit};
        // Allocation-free alias publication preserves the provider handle and
        // offset, counter, status flags and pending wait's pinned description.
        slot->description=entry.description;slot->close_on_exec=command==1030;
        return {slot-entries_.begin(),FileError::none};
    }
    case 1:return {entry.close_on_exec?1:0,FileError::none}; // F_GETFD.
    case 2: // F_SETFD; this flag belongs only to the selected alias.
        if(flags&~1u)return {-1,FileError::invalid};
        entry.close_on_exec=(flags&1u)!=0;return {0,FileError::none};
    case 3:return {description->status_flags,FileError::none}; // F_GETFL.
    case 4:{ // F_SETFL: only nonblocking has an implemented mutable behavior.
        if(description->poll_source)return {-1,FileError::unsupported};
        constexpr std::uint32_t unavailable=0x400|0x1000|0x2000|0x10000|0x40000|0x100000|0x200000|0x400000;
        // Access/creation/path-selection bits are immutable here. They do not
        // reopen, truncate, change authority, or alter per-alias close-on-exec.
        constexpr std::uint32_t ignored=access_mode|0x40|0x80|0x100|0x200|0x4000|0x8000|0x20000|0x80000;
        if(flags&~(ignored|nonblocking|unavailable))return {-1,FileError::invalid};
        if(flags&unavailable)return {-1,FileError::unsupported};
        description->status_flags=(description->status_flags&~nonblocking)|(flags&nonblocking);
        return {0,FileError::none};
    }
    // Known Android commands whose behavior is unavailable. In particular,
    // record locks and async ownership are not silently reported as successful.
    case 5:case 6:case 7:case 8:case 9:case 10:case 11:
    case 15:case 16:case 17:case 36:case 37:case 38:
    case 1024:case 1025:case 1026:case 1027:case 1028:case 1029:
    case 1031:case 1032:case 1033:case 1034:case 1035:case 1036:
    case 1037:case 1038:case 1039:case 1040:
        return {-1,FileError::unsupported};
    default:return {-1,FileError::invalid};
    }
}
FileResult NativeDescriptors::metadata(int fd,host::FileMetadata &output) noexcept {
    const auto description=get(fd);if(!description)return bad;
    if(description->standard || description->event || description->pipe || description->poll_source || description->directory || description->entropy)return {-1,FileError::unsupported};
    return description->provider->metadata(description->fd,output);
}
FileResult NativeDescriptors::truncate(int fd,std::uint64_t size) noexcept {
    const auto d=get(fd);if(!d)return bad;
    if(d->standard || d->event || d->pipe || d->poll_source || d->directory || d->entropy)return {-1,FileError::invalid};
    return d->provider->truncate(d->fd,size);
}
FileResult NativeDescriptors::read_at(int fd,std::uint64_t offset,std::span<std::uint8_t> output) noexcept {
    const auto d=get(fd);if(!d)return bad;
    if(d->pipe || d->standard || d->entropy)return {-1,FileError::not_seekable};
    if(d->event || d->poll_source)return {-1,FileError::unsupported};
    if(d->directory)return {-1,FileError::is_directory};
    return d->provider->read_at(d->fd,offset,output);
}
FileResult NativeDescriptors::write_at(int fd,std::uint64_t offset,std::span<const std::uint8_t> input) noexcept {
    const auto d=get(fd);if(!d)return bad;
    if(d->pipe || d->standard || d->entropy)return {-1,FileError::not_seekable};
    if(d->event || d->poll_source)return {-1,FileError::unsupported};
    if(d->directory)return {-1,FileError::is_directory};
    return d->provider->write_at(d->fd,offset,input);
}
FileResult NativeDescriptors::metadata_path(const host::FilePathRef &path,host::FilePathMetadata &output) noexcept {
    try {
        if(!provider_)return {-1,FileError::denied};
        if(path.directory < -1)return bad;
        if(path.directory < 0){
            if(!host::valid_file_access(path.scope,path.name,0))return {-1,FileError::invalid};
            return provider_->metadata_path(path,output);
        }
        const auto description=get(path.directory);if(!description)return bad;
        if(!description->directory)return {-1,FileError::not_directory};
        if(description->unlinked)return {-1,FileError::missing};
        host::FileAccessScope scope;std::string name;int parent=-1;
        const auto resolved=relative_target(path.directory,path.name,scope,name,parent);
        if(resolved.error!=FileError::none)return resolved;
        const host::FilePathRef selected{scope,parent,parent<0?std::string_view(name):path.name,path.directory_required};
        return description->provider->metadata_path(selected,output);
    }catch(...){return {-1,FileError::io};}
}
FileResult NativeDescriptors::seek(int fd,std::int64_t offset,unsigned whence) noexcept {
    const auto description=get(fd);if(!description)return bad;
    if(whence>2)return {-1,FileError::invalid};
    if(description->standard)return {-1,FileError::not_seekable};
    if(description->pipe || description->entropy)return {-1,FileError::not_seekable};
    if(description->poll_source)return {-1,FileError::unsupported};
    if(description->directory)return {-1,FileError::unsupported};
    return description->event?FileResult{0,FileError::none}:description->provider->seek(description->fd,offset,whence);
}
FileResult NativeDescriptors::remove(host::FileAccessScope scope,std::string_view name,host::FileRemoveMode mode,bool directory_required) noexcept {
    return remove_owned(scope,name,mode,directory_required);
}
FileResult NativeDescriptors::remove_owned(host::FileAccessScope scope,std::string_view name,host::FileRemoveMode mode,bool directory_required,int parent,std::string_view relative) noexcept {
    if(!provider_)return {-1,FileError::denied};
    // Snapshot candidate identities before the mutation. A same-name replacement
    // must not mark a different held object as deleted. All staging is bounded.
    std::array<std::pair<Description*,std::uint64_t>,256> candidates{};std::size_t count=0;
    if(scope==host::FileAccessScope::files_leaf || scope==host::FileAccessScope::data_leaf){
        for(const auto &entry:entries_){
            const auto d=entry.description.get();if(!d || d->standard || d->event || d->pipe || d->poll_source || d->directory || d->entropy || d->scope!=scope || d->unlinked || d->name!=name)continue;
            bool seen=false;for(std::size_t i=0;i<count;++i)if(candidates[i].first==d){seen=true;break;}
            if(seen)continue;
            host::FileMetadata info;const auto observed=d->provider->metadata(d->fd,info);
            if(observed.error!=FileError::none)return observed;
            if(observed.value!=0 || !host::valid_file_metadata(info))return {-1,FileError::io};
            candidates[count++]={d,info.identity};
        }
    }
    const auto result=parent<0?provider_->remove(scope,name,mode,directory_required):provider_->remove_relative(parent,relative,mode,directory_required); // Exactly one mutation attempt.
    if(result.error==FileError::none){
        if(result.value<=0)return {-1,FileError::io};
        for(std::size_t i=0;i<count;++i)if(candidates[i].second==static_cast<std::uint64_t>(result.value))candidates[i].first->unlinked=true;
    }
    return result;
}
FileResult NativeDescriptors::link_target(int fd,std::string_view package,std::string &output) const {
    const auto description=get(fd);if(!description)return {-1,FileError::missing};
    if(description->poll_source)return {-1,FileError::unsupported};
    if(description->standard)return {-1,FileError::unsupported};
    if(description->entropy)return {-1,FileError::unsupported};
    std::string target;
    if(description->event)target="anon_inode:[eventfd]";
    else if(description->pipe)target="pipe:["+std::to_string(description->pipe->identity)+"]";
    else {
        if(package.empty() || (!description->directory && description->name.empty()))return {-1,FileError::unsupported};
        target="/data/user/0/"+std::string(package);
        if(description->scope==host::FileAccessScope::files_root || description->scope==host::FileAccessScope::files_leaf)target+="/files";
        if(!description->name.empty())target+="/"+description->name;
        bool deleted=description->unlinked;
        if(description->directory && description->fd>=0){
            const auto observed=description->provider->directory_valid(description->fd);
            if(observed.error==FileError::missing)deleted=true;
            else if(observed.error!=FileError::none)return observed;
            else if(observed.value!=0)return {-1,FileError::io};
        }
        if(deleted)target+=" (deleted)";
    }
    output.swap(target);return {static_cast<std::int64_t>(output.size()),FileError::none};
}
}
