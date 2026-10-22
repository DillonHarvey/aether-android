#include "descriptors.hpp"
#include <algorithm>
#include <limits>
#include <utility>
namespace aether::bionic {
namespace {using host::FileResult;using host::FileError;constexpr FileResult bad{-1,FileError::bad_descriptor};}
struct NativeDescriptors::Description {
    host::FileService *provider;
    int fd=-1;
    bool event=false,semaphore=false,nonblocking=false;
    std::uint64_t counter=0;
    explicit Description(host::FileService *value):provider(value){}
    FileResult close_once() noexcept {
        if(event)return {0,FileError::none};
        if(fd<0)return bad;
        const auto old=std::exchange(fd,-1);
        const auto result=provider->close(old);
        return result.error==FileError::none && result.value!=0?FileResult{-1,FileError::io}:result;
    }
    ~Description(){if(fd>=0)(void)close_once();}
};
NativeDescriptors::~NativeDescriptors()=default;
NativeDescriptors::Description *NativeDescriptors::get(int fd) const noexcept {
    return fd>=0 && static_cast<std::size_t>(fd)<entries_.size()?entries_[static_cast<std::size_t>(fd)].description.get():nullptr;
}
FileResult NativeDescriptors::private_root() noexcept {return provider_?provider_->private_root():FileResult{-1,FileError::denied};}
FileResult NativeDescriptors::observe_data_file(std::string_view name){return provider_?provider_->observe_data_file(name):FileResult{-1,FileError::denied};}
FileResult NativeDescriptors::list_directory(std::vector<host::DirectoryEntry> &output){return provider_?provider_->list_directory(output):FileResult{-1,FileError::denied};}
FileResult NativeDescriptors::access(host::FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept {return provider_?provider_->access(scope,name,mode):FileResult{-1,FileError::denied};}
FileResult NativeDescriptors::open(std::string_view name,host::FileOpen options){
    if(!provider_)return {-1,FileError::denied};
    const auto slot=std::find_if(entries_.begin(),entries_.end(),[](const auto &entry){return !entry.description;});
    if(slot==entries_.end())return {-1,FileError::descriptor_limit};
    // Allocate before opening/truncating. Publishing into this fixed table cannot allocate.
    auto description=std::make_shared<Description>(provider_);
    const auto opened=provider_->open(name,options);
    if(opened.error!=FileError::none)return opened;
    if(opened.value<0 || opened.value>std::numeric_limits<int>::max())return {-1,FileError::io};
    description->fd=static_cast<int>(opened.value);
    slot->description=std::move(description);slot->close_on_exec=false;
    return {slot-entries_.begin(),FileError::none};
}
FileResult NativeDescriptors::event(std::uint32_t initial,std::uint32_t flags) {
    if(flags&~std::uint32_t{1|0x800|0x80000})return {-1,FileError::invalid};
    const auto slot=std::find_if(entries_.begin(),entries_.end(),[](const auto &entry){return !entry.description;});
    if(slot==entries_.end())return {-1,FileError::descriptor_limit};
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
FileResult NativeDescriptors::flush(int fd) noexcept {const auto description=get(fd);return !description?bad:description->event?FileResult{-1,FileError::invalid}:description->provider->flush(description->fd);}
FileResult NativeDescriptors::lock(int fd,std::uint32_t operation) noexcept {
    const auto description=get(fd);if(!description)return bad;
    if(!host::valid_file_lock(operation))return {-1,FileError::invalid};
    return description->event?FileResult{-1,FileError::unsupported}:description->provider->lock(description->fd,operation);
}
FileResult NativeDescriptors::duplicate_to(int old_fd,int new_fd) noexcept {
    if(!get(old_fd) || new_fd<0 || static_cast<std::size_t>(new_fd)>=entries_.size())return bad;
    if(old_fd==new_fd)return {new_fd,FileError::none};
    auto source=entries_[static_cast<std::size_t>(old_fd)].description;
    auto &target=entries_[static_cast<std::size_t>(new_fd)];
    // A shared_ptr assignment is allocation-free. No guest thread can observe a closed gap.
    auto displaced=std::move(target.description);target.description=std::move(source);target.close_on_exec=false;
    // Last displaced close is best effort, exactly once; dup2 does not report its close error.
    displaced.reset();return {new_fd,FileError::none};
}
void NativeDescriptors::set_close_on_exec(int fd,bool value) noexcept {if(get(fd))entries_[static_cast<std::size_t>(fd)].close_on_exec=value;}
}
