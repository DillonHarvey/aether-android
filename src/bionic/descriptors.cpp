#include "descriptors.hpp"
#include "aether/a64/guest_memory.hpp"
#include <algorithm>
#include <cstddef>
#include <limits>
#include <utility>
namespace aether::bionic {
namespace {using host::FileResult;using host::FileError;constexpr FileResult bad{-1,FileError::bad_descriptor};}
struct NativeDescriptors::Description {
    host::FileService *provider;
    int fd=-1;
    host::FileAccessScope scope=host::FileAccessScope::files_leaf;
    bool directory=false,event=false,semaphore=false,nonblocking=false,unlinked=false;
    unsigned standard=0; // 1: closed input, 2: diagnostic stdout, 3: diagnostic stderr.
    std::shared_ptr<StandardWrite> standard_write;
    std::uint64_t counter=0;
    std::string name;
    explicit Description(host::FileService *value):provider(value){}
    FileResult close_once() noexcept {
        if(standard || event || (directory && fd<0))return {0,FileError::none};
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
    if(!host::valid_file_access(scope,display.empty()?name:display,0))return {-1,FileError::invalid};
    if(!provider_)return {-1,FileError::denied};
    const bool root=scope==host::FileAccessScope::files_root || scope==host::FileAccessScope::data_root;
    if(root && !directory)return {-1,FileError::is_directory};
    const auto end=entries_.begin()+static_cast<std::ptrdiff_t>(soft_limit_);
    const auto slot=std::find_if(entries_.begin(),end,[](const auto &entry){return !entry.description;});
    if(slot==end)return {-1,FileError::descriptor_limit};
    auto description=std::make_shared<Description>(provider_);
    description->name=display.empty()?name:display;description->scope=scope;description->directory=directory;
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
            const auto d=entry.description.get();if(!d || d->standard || d->event || d->fd<0)continue;
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
    description->event=true;description->counter=initial;description->semaphore=flags&1;description->nonblocking=flags&0x800;
    slot->description=std::move(description);slot->close_on_exec=flags&0x80000;
    return {slot-entries_.begin(),FileError::none};
}
bool NativeDescriptors::is_event(int fd) const noexcept {const auto d=get(fd);return d && d->event;}
std::uint16_t NativeDescriptors::readiness(int fd,std::uint16_t events) const noexcept {
    if(fd<0)return 0;
    const auto description=get(fd);if(!description)return 0x20; // POLLNVAL, even without requested events.
    unsigned ready=0x145; // Regular files: POLLIN|POLLOUT|POLLRDNORM|POLLWRNORM.
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
    if(description->standard)return description->standard==1?FileResult{0,FileError::none}:bad;
    if(description->directory)return {-1,FileError::is_directory};
    if(description->event) {
        if(output.size()<8)return {-1,FileError::invalid};
        while(!description->counter) {
            if(description->nonblocking)return {-1,FileError::would_block};
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
    if(!get(fd))return bad;
    const auto description=entries_[static_cast<std::size_t>(fd)].description;
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
            if(description->nonblocking)return {-1,FileError::would_block};
            if(!progress || !progress())return {-1,FileError::unsupported};
        }
        description->counter+=value;return {8,FileError::none};
    }
    const auto result=description->provider->write(description->fd,input);
    if(result.error==FileError::none && (result.value<0 || static_cast<std::uint64_t>(result.value)>input.size()))return {-1,FileError::io};
    return result;
}
FileResult NativeDescriptors::close(int fd) noexcept {
    if(!get(fd))return bad;
    auto &entry=entries_[static_cast<std::size_t>(fd)];const bool last=entry.description.use_count()==1;
    auto description=std::move(entry.description);entry.close_on_exec=false;
    return last?description->close_once():FileResult{0,FileError::none};
}
FileResult NativeDescriptors::flush(int fd) noexcept {
    const auto description=get(fd);if(!description)return bad;
    if(description->standard)return description->standard==1?FileResult{-1,FileError::invalid}:FileResult{0,FileError::none};
    return (description->event || description->directory)?FileResult{-1,FileError::invalid}:description->provider->flush(description->fd);
}
FileResult NativeDescriptors::lock(int fd,std::uint32_t operation) noexcept {
    const auto description=get(fd);if(!description)return bad;
    if(!host::valid_file_lock(operation))return {-1,FileError::invalid};
    return (description->standard || description->event || description->directory)?FileResult{-1,FileError::unsupported}:description->provider->lock(description->fd,operation);
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
FileResult NativeDescriptors::metadata(int fd,host::FileMetadata &output) noexcept {
    const auto description=get(fd);if(!description)return bad;
    if(description->standard || description->event || description->directory)return {-1,FileError::unsupported};
    return description->provider->metadata(description->fd,output);
}
FileResult NativeDescriptors::seek(int fd,std::int64_t offset,unsigned whence) noexcept {
    const auto description=get(fd);if(!description)return bad;
    if(whence>2)return {-1,FileError::invalid};
    if(description->standard)return {-1,FileError::not_seekable};
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
            const auto d=entry.description.get();if(!d || d->standard || d->event || d->directory || d->scope!=scope || d->unlinked || d->name!=name)continue;
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
    if(description->standard)return {-1,FileError::unsupported};
    std::string target;
    if(description->event)target="anon_inode:[eventfd]";
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
