#include "renaming.hpp"
#include <bit>
namespace aether::bionic {
namespace {
struct Failure {unsigned code;};
int descriptor(std::uint64_t value){return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value));}
unsigned code(host::FileError error){
    using host::FileError;
    switch(error){case FileError::none:return 0;case FileError::missing:return 2;case FileError::denied:return 13;
    case FileError::exists:return 17;case FileError::bad_descriptor:return 9;case FileError::invalid:return 22;
    case FileError::unsupported:return 95;case FileError::descriptor_limit:return 24;case FileError::quota:return 28;
    case FileError::is_directory:return 21;case FileError::not_directory:return 20;case FileError::not_empty:return 39;
    case FileError::would_block:return 11;default:return 5;}
}
std::string text(a64::GuestMemory &memory,a64::Address pointer){
    std::string path;
    for(std::size_t i=0;i<1024;++i){std::array<std::uint8_t,1> byte{};
        if(!pointer || pointer>=a64::GuestMemory::address_limit || i>=a64::GuestMemory::address_limit-pointer || !memory.read(pointer+i,byte))throw Failure{14};
        if(!byte[0])return path;path+=static_cast<char>(byte[0]);
    }
    throw Failure{36};
}
}
a64::Fault NativeRenaming::invoke(bool at,a64::Address error,std::array<std::uint64_t,31> &r) noexcept {
    const auto fail=[&](unsigned value){std::array<std::uint8_t,4> bytes{};for(unsigned i=0;i<4;++i)bytes[i]=static_cast<std::uint8_t>(value>>(8*i));if(!memory_.write(error,bytes))return a64::Fault::write;r[0]=UINT64_MAX;return a64::Fault::none;};
    try {
        std::array<std::string,2> names;
        std::array<host::FilePathRef,2> refs;
        // Resolve each endpoint independently: an absolute path ignores only its own dirfd.
        for(unsigned index=0;index<2;++index){
            const auto path=text(memory_,r[at?index*2+1:index]);if(path.empty())throw Failure{2};
            const bool absolute=path.front()=='/';bool terminal_dot=false;
            auto &clean=names[index];if(absolute)clean='/';
            for(std::size_t start=absolute?1:0;start<=path.size();){
                const auto end=path.find('/',start);const auto part=std::string_view(path).substr(start,(end==std::string::npos?path.size():end)-start);
                if(part=="..")throw Failure{13};
                if(!part.empty())terminal_dot=part==".";
                if(!part.empty() && part!="."){if(!clean.empty() && clean.back()!='/')clean+='/';clean+=part;}
                if(end==std::string::npos)break;start=end+1;
            }
            if(terminal_dot || clean.empty() || clean=="/")throw Failure{13};
            auto &ref=refs[index];ref.directory_required=path.back()=='/';
            std::string_view name=clean;
            if(absolute){
                if(package_.empty())throw Failure{13};bool found=false;
                const std::array roots{"/data/user/0/"+package_,"/data/data/"+package_};
                for(const auto &root:roots){
                    if(clean==root)throw Failure{13};
                    if(clean.starts_with(root+"/")){ref.scope=host::FileAccessScope::data_leaf;name=std::string_view(clean).substr(root.size()+1);found=true;break;}
                }
                if(!found)throw Failure{13};
                if(name=="files")throw Failure{13};
                if(name.starts_with("files/")){ref.scope=host::FileAccessScope::files_leaf;name.remove_prefix(6);}
            }else if(at && descriptor(r[index*2])!=-100){ref.directory=descriptor(r[index*2]);if(ref.directory<0)throw Failure{9};}
            if(!host::valid_file_path(name))throw Failure{95};
            // The view references the stable per-endpoint string, including a possible root prefix.
            ref.name=name;
        }
        host::FileRenameInfo output;
        const auto result=descriptors_.rename_path(refs[0],refs[1],output); // One call, never replayed.
        if(result.error!=host::FileError::none)return fail(code(result.error));
        if(result.value!=0)return fail(5);r[0]=0;return a64::Fault::none;
    }catch(const Failure &failure){return fail(failure.code);}
    catch(...){return a64::Fault::windows_service;}
}
}
