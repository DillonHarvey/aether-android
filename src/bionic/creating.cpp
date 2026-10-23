#include "creating.hpp"
#include <bit>
namespace aether::bionic {
namespace {
unsigned code(host::FileError error){
    using host::FileError;
    switch(error){case FileError::none:return 0;case FileError::missing:return 2;case FileError::denied:return 13;
    case FileError::exists:return 17;case FileError::bad_descriptor:return 9;case FileError::invalid:return 22;
    case FileError::unsupported:return 95;case FileError::descriptor_limit:return 24;case FileError::quota:return 28;
    case FileError::not_directory:return 20;case FileError::not_empty:return 39;default:return 5;}
}
}
a64::Fault NativeCreating::invoke(bool at,a64::Address error,std::array<std::uint64_t,31> &r) noexcept {
    const auto fail=[&](unsigned value){std::array<std::uint8_t,4> bytes{};for(unsigned i=0;i<4;++i)bytes[i]=static_cast<std::uint8_t>(value>>(8*i));if(!memory_.write(error,bytes))return a64::Fault::write;r[0]=UINT64_MAX;return a64::Fault::none;};
    try{
        const auto pointer=r[at?1:0];const auto mode=static_cast<std::uint32_t>(r[at?2:1]);std::string path;
        for(std::size_t i=0;i<1024;++i){std::array<std::uint8_t,1> byte{};
            if(!pointer || pointer>=a64::GuestMemory::address_limit || i>=a64::GuestMemory::address_limit-pointer || !memory_.read(pointer+i,byte))return fail(14);
            if(!byte[0])break;path+=static_cast<char>(byte[0]);
        }
        if(path.size()==1024)return fail(36);if(path.empty())return fail(2);
        if(mode!=0700)return fail(95); // Current app-private permissions, no ignored authority bits.
        const bool absolute=path.front()=='/';bool final_dot=false;std::string clean=absolute?"/":"";
        for(std::size_t start=absolute?1:0;start<=path.size();){
            const auto end=path.find('/',start);const auto part=std::string_view(path).substr(start,(end==std::string::npos?path.size():end)-start);
            if(part=="..")return fail(13);
            if(!part.empty())final_dot=part==".";
            if(!part.empty() && part!="."){if(!clean.empty() && clean.back()!='/')clean+='/';clean+=part;}
            if(end==std::string::npos)break;start=end+1;
        }
        host::FileResult result;
        if(at && !absolute && std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[0]))!=-100){
            const auto fd=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[0]));
            if(final_dot || clean.empty()){
                const auto observed=descriptors_.access_at(fd,clean,0,!clean.empty());
                if(observed.error!=host::FileError::none)return fail(code(observed.error));
                return fail(observed.value==0?17:5);
            }
            result=descriptors_.make_directory_at(fd,clean,mode);
        }else{
            auto base=host::FileAccessScope::files_root;std::string_view name=clean;
            if(absolute){
                if(package_.empty())return fail(13);bool found=false;
                const std::array roots{"/data/user/0/"+package_,"/data/data/"+package_};
                for(const auto &root:roots){
                    if(clean==root){base=host::FileAccessScope::data_root;name={};found=true;break;}
                    if(clean.starts_with(root+"/")){base=host::FileAccessScope::data_root;name=std::string_view(clean).substr(root.size()+1);found=true;break;}
                }
                if(!found)return fail(13);
            }
            if(base==host::FileAccessScope::data_root){
                if(name=="files"){base=host::FileAccessScope::files_root;name={};}
                else if(name.starts_with("files/")){base=host::FileAccessScope::files_root;name.remove_prefix(6);}
            }
            const auto scope=name.empty()?base:base==host::FileAccessScope::files_root?host::FileAccessScope::files_leaf:host::FileAccessScope::data_leaf;
            if(!host::valid_file_access(scope,name,0))return fail(95);
            if(name.empty() || final_dot){
                const auto observed=name.empty()?descriptors_.access(scope,name,0):descriptors_.access_path(scope,name,0,true);
                if(observed.error!=host::FileError::none)return fail(code(observed.error));
                return fail(observed.value==0?17:5);
            }
            result=descriptors_.make_directory(scope,name,mode);
        }
        if(result.error!=host::FileError::none)return fail(code(result.error));
        if(result.value!=0)return fail(5);r[0]=0;return a64::Fault::none;
    }catch(...){return a64::Fault::windows_service;}
}
}
