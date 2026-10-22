#include "access.hpp"
#include <array>
namespace aether::bionic {
NativeAccess::NativeAccess(a64::GuestMemory &memory,host::FileService *files,std::string_view package):memory_(memory),files_(files),package_(package) {
    if(package_.size()>255 || package_.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.")!=std::string::npos)throw a64::GuestError("AETHER_GUEST_NAMESPACE","Invalid logical package identity");
}
a64::Fault NativeAccess::invoke(a64::Address error,std::array<std::uint64_t,31> &r) noexcept {
    const auto fail=[&](std::uint32_t value){std::array<std::uint8_t,4> bytes{};for(unsigned i=0;i<4;++i)bytes[i]=static_cast<std::uint8_t>(value>>(i*8));if(!memory_.write(error,bytes))return a64::Fault::write;r[0]=UINT64_MAX;return a64::Fault::none;};
    try {
        const auto mode=static_cast<std::uint32_t>(r[1]);if(mode&~7U)return fail(22);
        std::string path;
        for(std::size_t i=0;i<1024;++i){std::array<std::uint8_t,1> byte{};if(!r[0] || r[0]>=a64::GuestMemory::address_limit || i>=a64::GuestMemory::address_limit-r[0] || !memory_.read(r[0]+i,byte))return fail(14);if(!byte[0])break;path.push_back(static_cast<char>(byte[0]));}
        if(path.size()==1024)return fail(36);if(path.empty())return fail(2);
        std::string clean;for(const auto c:path)if(c!='/' || clean.empty() || clean.back()!='/')clean+=c;path=std::move(clean);
        while(path.starts_with("./"))path.erase(0,2);
        if(path.empty())path=".";
        if(path==".." || path.starts_with("../") || path.ends_with("/..") || path.find("/../")!=std::string::npos)return fail(13);
        bool directory_required=path.size()>1 && path.back()=='/';if(directory_required)path.pop_back();
        while(path.ends_with("/.")){directory_required=true;path.resize(path.size()-2);}
        auto scope=host::FileAccessScope::files_leaf;std::string_view name=path;
        if(path=="."){scope=host::FileAccessScope::files_root;name={};}
        else if(path.starts_with('/')) {
            if(package_.empty())return fail(95);
            const std::array<std::string,2> roots{"/data/user/0/"+package_,"/data/data/"+package_};bool matched=false;
            for(const auto &root:roots) {
                if(path==root){scope=host::FileAccessScope::data_root;name={};matched=true;break;}
                if(path==root+"/files"){scope=host::FileAccessScope::files_root;name={};matched=true;break;}
                if(path.starts_with(root+"/files/")){scope=host::FileAccessScope::files_leaf;name=std::string_view(path).substr(root.size()+7);matched=true;break;}
                if(path.starts_with(root+"/")){scope=host::FileAccessScope::data_leaf;name=std::string_view(path).substr(root.size()+1);matched=true;break;}
            }
            if(!matched)return fail(13);
        }
        const bool leaf=scope==host::FileAccessScope::files_leaf || scope==host::FileAccessScope::data_leaf;
        if((directory_required && leaf) || !host::valid_file_access(scope,name,mode))return fail(95);
        if(!files_)return fail(13);
        const auto result=files_->access(scope,name,mode);
        if(result.error==host::FileError::none){if(result.value!=0)return fail(5);r[0]=0;return a64::Fault::none;}
        switch(result.error){case host::FileError::missing:return fail(2);case host::FileError::denied:return fail(13);case host::FileError::invalid:return fail(22);case host::FileError::unsupported:return fail(95);default:return fail(5);}
    }catch(...){return a64::Fault::windows_service;}
}
}
