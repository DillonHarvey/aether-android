#include "file_metadata.hpp"
#include "access.hpp"
#include "descriptors.hpp"
#include "aether/host/process_info.hpp"
#include <algorithm>
#include <bit>
#include <charconv>
#include <limits>

namespace aether::bionic {
namespace {
using a64::Fault;
struct Failure {unsigned code;};
std::string text(a64::GuestMemory &memory,a64::Address address) {
    std::string result;
    for(unsigned i=0;i<1024;++i){
        std::array<std::uint8_t,1> byte{};
        if(!address || address>=a64::GuestMemory::address_limit || i>=a64::GuestMemory::address_limit-address || !memory.read(address+i,byte))throw Failure{14};
        if(!byte[0])return result;result.push_back(static_cast<char>(byte[0]));
    }
    throw Failure{36};
}
unsigned file_error(host::FileError error) {
    switch(error){
    case host::FileError::missing:return 2;
    case host::FileError::denied:return 13;
    case host::FileError::bad_descriptor:return 9;
    case host::FileError::invalid:return 22;
    case host::FileError::quota:return 28;
    case host::FileError::is_directory:return 21;
    case host::FileError::not_directory:return 20;
    case host::FileError::not_empty:return 39;
    case host::FileError::not_seekable:return 29;
    default:return 5;
    }
}
int descriptor(std::uint64_t value){return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value));}
}
NativeFileMetadata::NativeFileMetadata(a64::GuestMemory &memory,const a64::AppContext &app,NativeDescriptors &descriptors,NativeAccess &access,std::string_view package)
    :memory_(memory),descriptors_(descriptors),access_(access),package_(package),self_("/proc/"+std::to_string(host::current_process_id())+"/"),uid_(10000+static_cast<std::uint32_t>(app.instance_id%10000)) {
    const auto image=host::current_process_image_basename();
    if(!image.empty())image_="/aether/runtime/"+image;
}
Fault NativeFileMetadata::invoke(FileMetadataOperation operation,a64::Address error,std::array<std::uint64_t,31> &r) noexcept {
    rejection_={};
    const auto fail=[&](unsigned code){std::array<std::uint8_t,4> bytes{};for(unsigned i=0;i<4;++i)bytes[i]=static_cast<std::uint8_t>(code>>(8*i));if(!memory_.write(error,bytes))return Fault::write;r[0]=UINT64_MAX;return Fault::none;};
    const auto unsupported=[&](std::string_view reason){rejection_=reason;return Fault::unsupported_service;};
    try {
        if(operation==FileMetadataOperation::user_id){r[0]=uid_;return Fault::none;}
        if(operation==FileMetadataOperation::descriptor_seek){
            const auto result=descriptors_.seek(descriptor(r[0]),std::bit_cast<std::int64_t>(r[1]),static_cast<std::uint32_t>(r[2]));
            if(result.error==host::FileError::unsupported)return unsupported("lseek: descriptor does not support seeking in this profile");
            if(result.error!=host::FileError::none)return fail(file_error(result.error));
            if(result.value<0)return fail(5);r[0]=static_cast<std::uint64_t>(result.value);return Fault::none;
        }
        if(operation==FileMetadataOperation::descriptor_stat){
            const auto output=r[1];
            if(!descriptors_.contains(descriptor(r[0])))return fail(9);
            if(!memory_.accessible(output,128,a64::Permission::write))return fail(14);
            host::FileMetadata info;
            const auto result=descriptors_.metadata(descriptor(r[0]),info);
            if(result.error==host::FileError::unsupported)return unsupported("fstat: descriptor metadata is unsupported");
            if(result.error!=host::FileError::none)return fail(file_error(result.error));
            if(result.value!=0 || !host::valid_file_metadata(info))return fail(5);
            std::array<std::uint8_t,128> bytes{};
            const auto word=[&](unsigned offset,std::uint64_t value,unsigned width=8){for(unsigned i=0;i<width;++i)bytes[offset+i]=static_cast<std::uint8_t>(value>>(8*i));};
            word(0,1);word(8,info.identity);word(16,0100400U|(info.readonly?0U:0200U),4);word(20,info.links,4);
            word(24,uid_,4);word(28,uid_,4);word(48,info.size);word(56,4096,4);
            word(64,(info.allocated_bytes+511)/512);
            word(72,std::bit_cast<std::uint64_t>(info.access_seconds));word(80,info.access_nanoseconds);
            word(88,std::bit_cast<std::uint64_t>(info.modified_seconds));word(96,info.modified_nanoseconds);
            word(104,std::bit_cast<std::uint64_t>(info.changed_seconds));word(112,info.changed_nanoseconds);
            if(!memory_.write(output,bytes))return fail(14);r[0]=0;return Fault::none;
        }
        const bool at=operation==FileMetadataOperation::read_link_at;
        const auto supplied=at?r[1]:r[0],output=at?r[2]:r[1];
        // Linux's arm64 readlinkat syscall takes an int bufsiz.
        const auto capacity=descriptor(at?r[3]:r[2]);if(capacity<=0)return fail(22);
        const auto path=text(memory_,supplied);if(path.empty())return fail(2);
        if(at && !path.starts_with('/') && descriptor(r[0])!=-100){
            std::string ignored;const auto current=descriptors_.link_target(descriptor(r[0]),package_,ignored);
            return fail(current.error==host::FileError::missing?9:20);
        }
        std::string target;
        std::string_view suffix;
        if(path.starts_with("/proc/self/"))suffix=std::string_view(path).substr(11);
        else if(path.starts_with(self_))suffix=std::string_view(path).substr(self_.size());
        if(!suffix.empty()){
            if(suffix=="exe"){
                if(image_.empty())return unsupported("readlink: current executable identity unavailable");
                target=image_;
            }else if(suffix.starts_with("fd/")){
                const auto name=suffix.substr(3);int fd=0;
                if(name.empty() || (name.size()>1 && name.front()=='0'))return fail(2);
                const auto parsed=std::from_chars(name.data(),name.data()+name.size(),fd);
                if(parsed.ec!=std::errc{} || parsed.ptr!=name.data()+name.size() || fd<0 || name.front()<'0' || name.front()>'9')return fail(2);
                const auto result=descriptors_.link_target(fd,package_,target);
                if(result.error==host::FileError::unsupported)return unsupported("readlink: descriptor has no supported logical pathname");
                if(result.error!=host::FileError::none)return fail(file_error(result.error));
            }else return unsupported("readlink: unsupported self-process metadata path");
        }else {
            const auto observed=access_.probe_link_path(path);
            if(observed.error==host::FileError::unsupported)return unsupported("readlink: path outside supported logical namespaces");
            if(observed.error!=host::FileError::none)return fail(file_error(observed.error));
            if(observed.value!=0)return fail(5);
            return fail(22); // An observed regular private file/directory is not a link.
        }
        const auto count=std::min<std::size_t>(target.size(),static_cast<unsigned>(capacity));
        if(!memory_.write(output,{reinterpret_cast<const std::uint8_t*>(target.data()),count}))return fail(14);
        r[0]=count;return Fault::none;
    }catch(const Failure &failure){return fail(failure.code);}
    catch(...){return unsupported("native file metadata: host marshalling failed");}
}
}
