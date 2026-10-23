#include "opening.hpp"
#include <array>
namespace aether::bionic {
namespace {
using host::FileError;using host::FileAccessScope;
unsigned code(FileError error) {
    switch(error){
    case FileError::none:return 0;case FileError::missing:return 2;case FileError::denied:return 13;
    case FileError::exists:return 17;case FileError::bad_descriptor:return 9;case FileError::invalid:return 22;
    case FileError::unsupported:return 95;case FileError::descriptor_limit:return 24;case FileError::quota:return 28;
    case FileError::would_block:return 11;case FileError::is_directory:return 21;case FileError::not_directory:return 20;
    case FileError::not_empty:return 39;case FileError::io:return 5;case FileError::not_seekable:return 29;
    }return 5;
}
}
a64::Fault NativeOpening::invoke(OpeningOperation operation,a64::Address error,std::array<std::uint64_t,31> &r) noexcept {
    rejection_={};
    const auto fail=[&](unsigned value){std::array<std::uint8_t,4> bytes{};for(unsigned i=0;i<4;++i)bytes[i]=static_cast<std::uint8_t>(value>>(8*i));if(!memory_.write(error,bytes))return a64::Fault::write;r[0]=UINT64_MAX;return a64::Fault::none;};
    try {
        const bool at=operation!=OpeningOperation::open,access=operation==OpeningOperation::access_at;
        const auto flags=static_cast<std::uint32_t>(r[at?2:1]);
        // Bionic's aarch64 asm/fcntl.h overrides asm-generic O_DIRECTORY.
        constexpr unsigned directory=0x4000,nofollow=0x8000,cloexec=0x80000,tmpfile=0x404000;
        if(operation==OpeningOperation::checked_open_at && ((flags&64) || (flags&tmpfile)==tmpfile)){
            rejection_="__openat_2: fortify violation, O_CREAT/O_TMPFILE requires a mode argument";
            return a64::Fault::unsupported_service;
        }
        if(access){if((flags&~7U) || (static_cast<std::uint32_t>(r[3])&~0x300U))return fail(22);}
        const auto pointer=r[at?1:0];std::string path;
        for(std::size_t i=0;i<1024;++i){
            std::array<std::uint8_t,1> byte{};
            if(!pointer || pointer>=a64::GuestMemory::address_limit || i>=a64::GuestMemory::address_limit-pointer || !memory_.read(pointer+i,byte))return fail(14);
            if(!byte[0])break;path+=static_cast<char>(byte[0]);
        }
        if(path.size()==1024)return fail(36);if(path.empty())return fail(2);
        if(!access && ((flags&~unsigned{3|64|128|512|directory|nofollow|cloexec}) || (flags&3)==3))return fail(95);
        if(!access && (flags&64) && static_cast<std::uint32_t>(r[at?3:2])!=0600)return fail(95);
        // Collapse slash and dot components, but never resolve a parent traversal.
        const bool absolute=path.front()=='/';
        bool directory_required=path.back()=='/';std::string clean=absolute?"/":"";
        for(std::size_t start=absolute?1:0;start<=path.size();){
            const auto end=path.find('/',start);const auto part=std::string_view(path).substr(start,(end==std::string::npos?path.size():end)-start);
            if(part=="..")return fail(13);
            if(part=="." && end==std::string::npos)directory_required=true;
            if(!part.empty() && part!="."){if(!clean.empty() && clean.back()!='/')clean+='/';clean+=part;}
            if(end==std::string::npos)break;start=end+1;
        }
        // Unbound legacy first-party bridges retain their original flat ordinary-open
        // denial contract; installed packages use the authenticated nested namespace.
        if(operation==OpeningOperation::open && package_.empty() && !absolute && clean.find('/')!=std::string::npos)return fail(13);
        // A real directory fd is an object capability. Pass its provider token
        // through NativeDescriptors; never reopen a saved pathname as authority.
        if(at && !absolute && static_cast<std::int32_t>(r[0])!=-100){
            const auto fd=static_cast<std::int32_t>(r[0]);host::FileResult selected;
            const auto checked=descriptors_.directory_scope(fd);if(checked.error!=FileError::none)return fail(code(checked.error));
            if(access){
                selected=descriptors_.access_at(fd,clean,flags,directory_required);
                if(selected.error!=FileError::none)return fail(code(selected.error));
                if(selected.value!=0)return fail(5);
                r[0]=0;return a64::Fault::none;
            }
            if((flags&directory) || directory_required){
                selected=descriptors_.open_directory_at(fd,clean);
                if(selected.error==FileError::none && ((flags&3) || (flags&(64|512)))){(void)descriptors_.close(static_cast<int>(selected.value));return fail(21);}
            }else{
                selected=descriptors_.open_at(fd,clean,{(flags&3)!=1,(flags&3)!=0,(flags&64)!=0,(flags&128)!=0,(flags&512)!=0});
                if(selected.error==FileError::is_directory && !(flags&(3|64|512)))selected=descriptors_.open_directory_at(fd,clean);
            }
            if(selected.error!=FileError::none)return fail(code(selected.error));
            if(selected.value<0 || selected.value>=256)return fail(5);
            descriptors_.set_close_on_exec(static_cast<int>(selected.value),(flags&cloexec)!=0);r[0]=static_cast<std::uint64_t>(selected.value);return a64::Fault::none;
        }
        FileAccessScope base=FileAccessScope::files_root;std::string_view name=clean;
        if(absolute){
            if(package_.empty())return fail(operation==OpeningOperation::open?13:95);
            const std::array roots{"/data/user/0/"+package_,"/data/data/"+package_};bool found=false;
            for(const auto &root:roots){
                if(clean==root){base=FileAccessScope::data_root;name={};found=true;break;}
                if(clean.starts_with(root+"/")){base=FileAccessScope::data_root;name=std::string_view(clean).substr(root.size()+1);found=true;break;}
            }
            if(!found)return fail(13);
        }
        if(base==FileAccessScope::data_root){
            if(name=="files"){base=FileAccessScope::files_root;name={};}
            else if(name.starts_with("files/")){base=FileAccessScope::files_root;name.remove_prefix(6);}
        }
        const auto scope=name.empty()?base:base==FileAccessScope::files_root?FileAccessScope::files_leaf:FileAccessScope::data_leaf;
        if(!host::valid_file_access(scope,name,access?flags:0))return fail(operation==OpeningOperation::open?13:95); // Preserve the existing ordinary-open flat-name policy.
        const bool root=scope==FileAccessScope::files_root || scope==FileAccessScope::data_root;
        if(access){
            const auto result=descriptors_.access_path(scope,name,flags,directory_required);
            if(result.error!=FileError::none)return fail(code(result.error));
            if(result.value!=0)return fail(5);
            r[0]=0;return a64::Fault::none;
        }
        if(root && ((flags&3) || (flags&(64|512)))){
            const auto observed=descriptors_.access(scope,"",0);
            if(observed.error!=FileError::none)return fail(code(observed.error));
            return fail(observed.value==0?21:5);
        }
        auto result=(root || (flags&directory) || directory_required)?descriptors_.open_directory(scope,name):descriptors_.open_scoped(scope,name,{(flags&3)!=1,(flags&3)!=0,(flags&64)!=0,(flags&128)!=0,(flags&512)!=0});
        if(result.error==FileError::is_directory && !(flags&(3|64|512)))result=descriptors_.open_directory(scope,name);
        if(result.error!=FileError::none)return fail(code(result.error));
        if(!root && ((flags&directory) || directory_required) && ((flags&3) || (flags&(64|512)))){(void)descriptors_.close(static_cast<int>(result.value));return fail(21);}
        if(result.value<0 || result.value>=256)return fail(5);
        descriptors_.set_close_on_exec(static_cast<int>(result.value),(flags&cloexec)!=0);
        r[0]=static_cast<std::uint64_t>(result.value);return a64::Fault::none;
    }catch(...){rejection_="native openat: host marshalling failed";return a64::Fault::unsupported_service;}
}
}
