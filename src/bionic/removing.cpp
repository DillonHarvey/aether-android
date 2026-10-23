#include "removing.hpp"
#include "descriptors.hpp"
#include <bit>
namespace aether::bionic {
namespace {
struct Failure {unsigned code;};
int descriptor(std::uint64_t value){return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value));}
std::string text(a64::GuestMemory &memory,a64::Address address) {
    std::string value;
    for(unsigned i=0;i<1024;++i){
        std::array<std::uint8_t,1> byte{};
        if(!address || address>=a64::GuestMemory::address_limit || i>=a64::GuestMemory::address_limit-address || !memory.read(address+i,byte))throw Failure{14};
        if(!byte[0])return value;value.push_back(static_cast<char>(byte[0]));
    }
    throw Failure{36};
}
unsigned file_error(host::FileError error){
    switch(error){
    case host::FileError::missing:return 2;
    case host::FileError::denied:return 13;
    case host::FileError::bad_descriptor:return 9;
    case host::FileError::invalid:return 22;
    case host::FileError::quota:return 28;
    case host::FileError::is_directory:return 21;
    case host::FileError::not_directory:return 20;
    case host::FileError::not_empty:return 39;
    default:return 5;
    }
}
}
NativeRemoving::NativeRemoving(a64::GuestMemory &memory,NativeDescriptors &descriptors,std::string_view package)
    :memory_(memory),descriptors_(descriptors),package_(package){}
a64::Fault NativeRemoving::invoke(RemovingOperation operation,a64::Address error,std::array<std::uint64_t,31> &r) noexcept {
    rejection_={};
    const auto fail=[&](unsigned code){std::array<std::uint8_t,4> bytes{};for(unsigned i=0;i<4;++i)bytes[i]=static_cast<std::uint8_t>(code>>(8*i));if(!memory_.write(error,bytes))return a64::Fault::write;r[0]=UINT64_MAX;return a64::Fault::none;};
    const auto unsupported=[&](std::string_view reason){rejection_=reason;return a64::Fault::unsupported_service;};
    try {
        const bool at=operation==RemovingOperation::unlink_at;
        auto mode=operation==RemovingOperation::remove?host::FileRemoveMode::either:operation==RemovingOperation::remove_directory?host::FileRemoveMode::directory:host::FileRemoveMode::file;
        if(at){const auto flags=static_cast<std::uint32_t>(r[2]);if(flags!=0 && flags!=0x200)return fail(22);if(flags)mode=host::FileRemoveMode::directory;}
        auto path=text(memory_,at?r[1]:r[0]);if(path.empty())return fail(2);
        std::string clean;for(const auto c:path)if(c!='/' || clean.empty() || clean.back()!='/')clean.push_back(c);path=std::move(clean);
        while(path.starts_with("./"))path.erase(0,2);
        if(path.empty() || path=="." || path=="..")return fail(13);
        if(path.starts_with("../") || path.ends_with("/..") || path.find("/../")!=std::string::npos)return unsupported("remove: parent traversal is outside the private profile");
        const bool directory_required=path.size()>1 && path.back()=='/';if(directory_required)path.pop_back();
        if(path.ends_with("/.") || path.find("/./")!=std::string::npos)return unsupported("remove: internal dot components are unsupported");
        auto scope=host::FileAccessScope::files_leaf;std::string_view name=path;
        if(path.starts_with('/')){
            if(package_.empty())return unsupported("remove: no logical package namespace");
            const std::array<std::string,2> roots{"/data/user/0/"+package_,"/data/data/"+package_};bool matched=false;
            for(const auto &root:roots){
                if(path==root || path==root+"/files")return fail(13);
                if(path.starts_with(root+"/files/")){scope=host::FileAccessScope::files_leaf;name=std::string_view(path).substr(root.size()+7);matched=true;break;}
                if(path.starts_with(root+"/")){scope=host::FileAccessScope::data_leaf;name=std::string_view(path).substr(root.size()+1);matched=true;break;}
            }
            if(!matched)return unsupported("remove: path outside the app-private namespace");
        }
        if(!host::valid_file_access(scope,name,0))return unsupported("remove: path outside the supported private leaf profile");
        const auto result=at && path.front()!='/' && descriptor(r[0])!=-100?
            descriptors_.remove_at(descriptor(r[0]),name,mode,directory_required):descriptors_.remove(scope,name,mode,directory_required);
        if(result.error==host::FileError::unsupported)return unsupported("remove: provider does not support the requested private mutation");
        if(result.error!=host::FileError::none)return fail(file_error(result.error));
        if(result.value<=0)return fail(5);r[0]=0;return a64::Fault::none;
    }catch(const Failure &failure){return fail(failure.code);}
    catch(...){return unsupported("remove: host marshalling failed; no automatic mutation retry");}
}
}
