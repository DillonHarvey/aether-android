#include "stdio.hpp"
#include <algorithm>
#include <limits>
#include <bit>
#include <new>
namespace aether::bionic {
namespace {
constexpr std::size_t transfer_limit=1024*1024;
unsigned code(host::FileError error){using E=host::FileError;switch(error){case E::none:return 0;case E::missing:return 2;case E::denied:return 13;case E::exists:return 17;case E::bad_descriptor:return 9;case E::invalid:return 22;case E::unsupported:return 95;case E::descriptor_limit:return 24;case E::quota:return 28;case E::io:return 5;case E::would_block:return 11;case E::is_directory:return 21;case E::not_directory:return 20;case E::not_empty:return 39;case E::not_seekable:return 29;}return 5;}
}
NativeStdio::~NativeStdio(){for(const auto &[address,stream]:streams_){try{if(files_)files_->close(stream.fd);}catch(...){}try{if(address<standard_base || address>=standard_base+456)memory_.unmap(address);}catch(...){}}if(standard_owned_)try{memory_.unmap(standard_base);}catch(...){}}
void NativeStdio::initialize(){
    memory_.map(standard_base,4096,a64::read_write);standard_owned_=true;
    for(unsigned i=0;i<3;++i){
        streams_.emplace(standard_base+i*152,Stream{static_cast<int>(i),i==0,i!=0});
        std::array<std::uint8_t,8> pointer{};const auto value=standard_base+i*152;
        for(unsigned n=0;n<8;++n)pointer[n]=static_cast<std::uint8_t>(value>>(n*8));
        if(!memory_.write(standard_base+512+i*8,pointer))throw a64::GuestError("AETHER_GUEST_MAPPING","Cannot initialize standard stream pointers");
    }
    if(!sync_standard())throw a64::GuestError("AETHER_GUEST_MAPPING","Cannot initialize standard streams");
}
bool NativeStdio::sync_standard(){
    for(unsigned i=0;i<3;++i){
        const auto address=standard_base+i*152;const auto found=streams_.find(address);
        unsigned flags=0;std::uint32_t fd=~std::uint32_t{0};
        if(found!=streams_.end()){const auto &stream=found->second;flags=(i==0?4U:i==1?8U:10U)|(stream.eof?0x20U:0U)|(stream.error?0x40U:0U);fd=static_cast<std::uint32_t>(stream.fd);}
        std::array<std::uint8_t,8> bytes{};
        for(unsigned n=0;n<4;++n){bytes[n]=static_cast<std::uint8_t>(flags>>(n*8));bytes[n+4]=static_cast<std::uint8_t>(fd>>(n*8));}
        if(!memory_.write(address+16,bytes))return false;
    }
    return true;
}
bool NativeStdio::preflight_standard() const {
    if(standard_owned_)for(unsigned i=0;i<3;++i)
        if(!memory_.accessible(standard_base+i*152+16,8,a64::Permission::write))return false;
    return true;
}
a64::Fault NativeStdio::invoke(unsigned op,a64::Address error,std::array<std::uint64_t,31>&r){
    // Bionic checks the int argument before it inspects even the FILE pointer.
    if(op==14 && static_cast<std::uint32_t>(r[0])==UINT32_MAX){r[0]=UINT64_MAX;return a64::Fault::none;}
    // The public layout carries metadata only. Descriptor authority stays in streams_.
    // Preflight every metadata destination before a provider read or write can occur.
    if(!preflight_standard())return a64::Fault::write;
    const auto fault=operate(op,error,r);
    if(standard_owned_ && !sync_standard())return a64::Fault::write;
    return fault;
}
a64::Fault NativeStdio::prepare_formatted(a64::Address handle,a64::Address error,
                                          std::array<std::uint64_t,31>&r,bool &ready){
    ready=false;
    if(!preflight_standard())return a64::Fault::write;
    auto result=r;
    const auto finish=[&](a64::Fault fault){
        if(standard_owned_ && !sync_standard())return a64::Fault::write;
        if(fault==a64::Fault::none)r[0]=result[0];
        return fault;
    };
    const auto found=streams_.find(handle);
    if(found==streams_.end())return finish(fail(error,result,9,UINT64_MAX));
    auto &stream=found->second;
    // Retain the existing checked update-stream direction profile. A permitted
    // transition prepares the stream even when the eventual format is empty.
    if(!stream.write || (stream.direction==1 && !stream.eof)){
        stream.error=true;
        return finish(fail(error,result,9,UINT64_MAX));
    }
    stream.direction=2;stream.eof=false;
    std::vector<std::uint8_t>{}.swap(stream.pushed);
    const auto fault=finish(a64::Fault::none);
    ready=fault==a64::Fault::none;
    return fault;
}

a64::Fault NativeStdio::write_formatted(a64::Address handle,a64::Address error,
                                        std::span<const std::uint8_t> bytes,
                                        std::array<std::uint64_t,31>&r){
    bool ready=false;
    const auto prepared=prepare_formatted(handle,error,r,ready);
    if(prepared!=a64::Fault::none || !ready)return prepared;
    auto result=r;
    const auto finish=[&](a64::Fault fault){
        if(standard_owned_ && !sync_standard())return a64::Fault::write;
        if(fault==a64::Fault::none)r[0]=result[0];
        return fault;
    };
    auto &stream=streams_.find(handle)->second;
    if(bytes.size()>transfer_limit){
        stream.error=true;return finish(fail(error,result,75,UINT64_MAX));
    }
    std::size_t done=0;
    while(done<bytes.size()){
        const auto remaining=bytes.size()-done;
        const auto written=files_->write(stream.fd,bytes.subspan(done));
        if(written.error!=host::FileError::none || written.value<=0 ||
           static_cast<std::uint64_t>(written.value)>remaining){
            stream.error=true;
            // Accepted prefixes stay committed. A failure never replays them,
            // and an errno fault must not publish a new return value.
            const auto number=written.error==host::FileError::none?5:code(written.error);
            return finish(fail(error,result,number,UINT64_MAX));
        }
        done+=static_cast<std::size_t>(written.value);
    }
    // fprintf preserves an earlier error indicator and returns -1 for it,
    // including an empty current output, without inventing a new errno value.
    result[0]=stream.error?UINT64_MAX:static_cast<std::uint64_t>(done);
    return finish(a64::Fault::none);
}

a64::Fault NativeStdio::fail(a64::Address error,std::array<std::uint64_t,31>&r,unsigned value,std::uint64_t result){std::array<std::uint8_t,4> bytes{};for(unsigned i=0;i<4;++i)bytes[i]=static_cast<std::uint8_t>(value>>(8*i));if(!memory_.write(error,bytes))return a64::Fault::write;r[0]=result;return a64::Fault::none;}
a64::Fault NativeStdio::operate(unsigned op,a64::Address error,std::array<std::uint64_t,31>&r){
    constexpr auto eof=~std::uint64_t{0};
    if(op==0){
        if(!private_files_)return fail(error,r,13,0);
        const auto text=[&](a64::Address address,std::size_t limit,std::string&out){for(std::size_t i=0;i<limit;++i){std::array<std::uint8_t,1>b{};if(address>=a64::GuestMemory::address_limit || i>=a64::GuestMemory::address_limit-address || !memory_.read(address+i,b))return 14U;if(!b[0])return 0U;out.push_back(static_cast<char>(b[0]));}return 36U;};
        std::string name,mode;auto status=text(r[0],128,name);if(status)return fail(error,r,status,0);status=text(r[1],8,mode);if(status)return fail(error,r,status,0);
        if(mode.empty() || (mode[0]!='r' && mode[0]!='w' && mode[0]!='a'))return fail(error,r,22,0);
        if(mode[0]=='a')return fail(error,r,95,0);
        bool plus=false,binary=false,exclusive=false,cloexec=false;
        for(std::size_t i=1;i<mode.size();++i){bool *flag=nullptr;switch(mode[i]){case '+':flag=&plus;break;case 'b':flag=&binary;break;case 'x':flag=&exclusive;break;case 'e':flag=&cloexec;break;default:return fail(error,r,22,0);}if(*flag)return fail(error,r,22,0);*flag=true;}
        if(exclusive && mode[0]!='w')return fail(error,r,22,0);
        if(std::count_if(streams_.begin(),streams_.end(),[](const auto &item){return item.first<standard_base || item.first>=standard_base+456;})>=16 || next_>=0x3b000000)return fail(error,r,24,0);
        const auto address=next_;
        // Allocate ownership records before opening/truncating any provider file.
        const auto [it,inserted]=streams_.emplace(address,Stream{-1,mode[0]=='r'||plus,mode[0]=='w'||plus});
        if(!inserted)return fail(error,r,5,0);
        try{memory_.map(address,4096,a64::read_write);}catch(...){streams_.erase(it);return fail(error,r,12,0);}
        host::FileResult opened;
        try{opened=files_->open(name,{it->second.read,it->second.write,mode[0]=='w',exclusive,mode[0]=='w'});}catch(...){memory_.unmap(address);streams_.erase(it);throw;}
        if(opened.error!=host::FileError::none || opened.value<0 || opened.value>std::numeric_limits<int>::max()){memory_.unmap(address);streams_.erase(it);return fail(error,r,opened.error==host::FileError::none?5:code(opened.error),0);}
        it->second.fd=static_cast<int>(opened.value);files_->set_close_on_exec(it->second.fd,cloexec);next_+=4096;r[0]=address;return a64::Fault::none;
    }
    if(op==10 && !r[0]){for(auto &[address,stream]:streams_){(void)address;if(stream.direction==2)stream.direction=0;}r[0]=0;return a64::Fault::none;}
    const auto handle=(op==2 || op==3)?r[3]:op==5?r[2]:(op==14 || op==15)?r[1]:r[0];
    const auto found=streams_.find(handle);
    const bool pointer_result=op==5;
    if(found==streams_.end()){
        const auto original=r[0];const auto fault=fail(error,r,9,(op==2 || op==3 || pointer_result)?0:eof);
        if(op==11)r[0]=original;return fault;
    }
    auto &stream=found->second;
    if(op==14){
        // Write-only streams reject pushback without setting errno or ferror.
        if(!stream.read){r[0]=eof;return a64::Fault::none;}
        if(stream.pushed.size()==pushback_limit)return fail(error,r,12,eof);
        const auto byte=static_cast<std::uint8_t>(r[0]);
        try{
            // Grow lazily within the same one-MiB profile as stream transfers.
            if(stream.pushed.size()==stream.pushed.capacity())
                stream.pushed.reserve(std::min(pushback_limit,std::max<std::size_t>(3,stream.pushed.capacity()*2)));
            stream.pushed.push_back(byte);
        }catch(const std::bad_alloc &){return fail(error,r,12,eof);}
        // Unbuffered update streams have no pending output to flush. ungetc
        // itself switches writing to reading; it is not a direction error.
        stream.direction=1;stream.eof=false;r[0]=byte;return a64::Fault::none;
    }
    if(op==1){const auto fd=stream.fd;streams_.erase(found);if(handle<standard_base || handle>=standard_base+456)memory_.unmap(handle);const auto result=files_->close(fd);if(result.error!=host::FileError::none || result.value!=0)return fail(error,r,result.error==host::FileError::none?5:code(result.error),eof);r[0]=0;return a64::Fault::none;}
    if(op==6){r[0]=stream.eof;return a64::Fault::none;}
    if(op==7){r[0]=stream.error;return a64::Fault::none;}
    if(op==8){stream.eof=false;stream.error=false;return a64::Fault::none;}
    if(op==9){r[0]=static_cast<std::uint64_t>(stream.fd);return a64::Fault::none;}
    if(op==10){if(!stream.write)return fail(error,r,9,eof);stream.direction=0;r[0]=0;return a64::Fault::none;}
    if(op>=11 && op<=13){
        const bool rewinding=op==11,telling=op==13;
        auto whence=rewinding?0U:telling?1U:static_cast<std::uint32_t>(r[2]);
        auto offset=rewinding||telling?std::int64_t{0}:std::bit_cast<std::int64_t>(r[1]);
        host::FileResult result;
        if(!telling && whence==1 && stream.pushed.size()){
            result=files_->seek(stream.fd,0,1);
            if(result.error==host::FileError::none && result.value>=0){
                const auto current=result.value-static_cast<std::int64_t>(stream.pushed.size());
                // Bionic treats an effective -1 current position as failure,
                // even if it came from pushback rather than a failed seek.
                if(current==-1){r[0]=eof;return a64::Fault::none;}
                if((offset>0 && current>INT64_MAX-offset) || (offset<0 && current<INT64_MIN-offset))
                    return fail(error,r,75,eof);
                offset+=current;whence=0;result=files_->seek(stream.fd,offset,whence);
            }
        } else result=whence>2?host::FileResult{-1,host::FileError::invalid}:files_->seek(stream.fd,offset,whence);
        if(result.error!=host::FileError::none || result.value<0 || (whence==0 && result.value!=offset)){
            const auto original=r[0];const auto fault=fail(error,r,result.error==host::FileError::none?5:code(result.error),eof);
            if(rewinding){r[0]=original;if(fault==a64::Fault::none){stream.eof=false;stream.error=false;}}
            return fault;
        }
        if(!telling){stream.eof=false;stream.direction=0;std::vector<std::uint8_t>{}.swap(stream.pushed);}
        if(rewinding)stream.error=false;
        else r[0]=telling?static_cast<std::uint64_t>(result.value-static_cast<std::int64_t>(stream.pushed.size())):0;
        return a64::Fault::none;
    }
    if(op>10 && op!=15)return a64::Fault::unsupported_service;
    const bool writing=op==3 || op==15;
    std::uint64_t size=1,count=1;auto destination=r[0];
    if(op==2 || op==3){size=r[1];count=r[2];if(!size || !count){r[0]=0;return a64::Fault::none;}if(size>transfer_limit || count>transfer_limit/size){stream.error=true;return fail(error,r,75,0);}}
    if(op==5){const auto length=static_cast<std::int32_t>(r[1]);if(length<=0)return a64::Fault::invalid_call;count=static_cast<std::uint32_t>(length)-1;if(count>=transfer_limit)return fail(error,r,75,0);}

    const auto total=static_cast<std::size_t>(size*count);
    if(op!=4 && op!=15 && !memory_.accessible(destination,total+(op==5?1:0),writing?a64::Permission::read:a64::Permission::write)){stream.error=true;return fail(error,r,14,0);}
    if(op==5 && !total){const std::array<std::uint8_t,1> zero{};if(!memory_.write(destination,zero))return fail(error,r,14,0);r[0]=destination;return a64::Fault::none;}
    if((writing && (!stream.write || (stream.direction==1 && !stream.eof))) || (!writing && (!stream.read || stream.direction==2))){stream.error=true;return fail(error,r,9,(op==4 || op==15)?eof:0);}
    stream.direction=writing?2U:1U;
    std::vector<std::uint8_t> bytes(op==4?1:total);
    if(op==15)bytes[0]=static_cast<std::uint8_t>(r[0]);
    else if(writing && !memory_.read(destination,bytes))return fail(error,r,14,0);
    if(writing){stream.eof=false;std::vector<std::uint8_t>{}.swap(stream.pushed);}
    std::size_t done=0;unsigned failure=0;
    while(done<bytes.size()){
        if(!writing && stream.pushed.size()){
            bytes[done++]=stream.pushed.back();stream.pushed.pop_back();
            if(stream.pushed.empty())std::vector<std::uint8_t>{}.swap(stream.pushed);
            if(op==5 && bytes[done-1]=='\n')break;
            continue;
        }
        const auto request=op==5?std::size_t{1}:bytes.size()-done;
        const auto result=writing?files_->write(stream.fd,std::span<const std::uint8_t>{bytes}.subspan(done,request)):files_->read(stream.fd,std::span<std::uint8_t>{bytes}.subspan(done,request));
        if(result.error!=host::FileError::none){failure=code(result.error);stream.error=true;break;}
        if(result.value<0 || static_cast<std::uint64_t>(result.value)>request){failure=5;stream.error=true;break;}
        if(!result.value){if(writing){failure=5;stream.error=true;}else stream.eof=true;break;}
        done+=static_cast<std::size_t>(result.value);
        if(op==5 && bytes[done-1]=='\n')break;
    }
    if(!writing && op!=4 && done && !memory_.write(destination,std::span<const std::uint8_t>{bytes}.first(done)))return fail(error,r,14,0);
    std::uint64_t value=done/size;
    if(op==4 || op==15)value=done?bytes[0]:eof;
    if(op==5){value=done?destination:0;if(value){const std::array<std::uint8_t,1> zero{};if(!memory_.write(destination+done,zero))return fail(error,r,14,0);}}
    if(failure)return fail(error,r,failure,value);
    r[0]=value;return a64::Fault::none;
}
}
