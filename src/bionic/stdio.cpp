#include "stdio.hpp"
#include <algorithm>
#include <limits>
namespace aether::bionic {
namespace {
constexpr std::size_t transfer_limit=1024*1024;
unsigned code(host::FileError error){using E=host::FileError;switch(error){case E::none:return 0;case E::missing:return 2;case E::denied:return 13;case E::exists:return 17;case E::bad_descriptor:return 9;case E::invalid:return 22;case E::unsupported:return 95;case E::descriptor_limit:return 24;case E::quota:return 28;case E::io:return 5;case E::would_block:return 11;}return 5;}
}
NativeStdio::~NativeStdio(){for(const auto &[address,stream]:streams_){try{if(files_)files_->close(stream.fd);}catch(...){}try{memory_.unmap(address);}catch(...){}}}
a64::Fault NativeStdio::fail(a64::Address error,std::array<std::uint64_t,31>&r,unsigned value,std::uint64_t result){std::array<std::uint8_t,4> bytes{};for(unsigned i=0;i<4;++i)bytes[i]=static_cast<std::uint8_t>(value>>(8*i));if(!memory_.write(error,bytes))return a64::Fault::write;r[0]=result;return a64::Fault::none;}
a64::Fault NativeStdio::invoke(unsigned op,a64::Address error,std::array<std::uint64_t,31>&r){
    constexpr auto eof=~std::uint64_t{0};
    if(op==0){
        if(!files_)return fail(error,r,13,0);
        const auto text=[&](a64::Address address,std::size_t limit,std::string&out){for(std::size_t i=0;i<limit;++i){std::array<std::uint8_t,1>b{};if(address>=a64::GuestMemory::address_limit || i>=a64::GuestMemory::address_limit-address || !memory_.read(address+i,b))return 14U;if(!b[0])return 0U;out.push_back(static_cast<char>(b[0]));}return 36U;};
        std::string name,mode;auto status=text(r[0],128,name);if(status)return fail(error,r,status,0);status=text(r[1],8,mode);if(status)return fail(error,r,status,0);
        if(mode.empty() || (mode[0]!='r' && mode[0]!='w' && mode[0]!='a'))return fail(error,r,22,0);
        if(mode[0]=='a')return fail(error,r,95,0);
        bool plus=false,binary=false,exclusive=false,cloexec=false;
        for(std::size_t i=1;i<mode.size();++i){bool *flag=nullptr;switch(mode[i]){case '+':flag=&plus;break;case 'b':flag=&binary;break;case 'x':flag=&exclusive;break;case 'e':flag=&cloexec;break;default:return fail(error,r,22,0);}if(*flag)return fail(error,r,22,0);*flag=true;}
        if(exclusive && mode[0]!='w')return fail(error,r,22,0);
        if(streams_.size()>=16 || next_>=0x3b000000)return fail(error,r,24,0);
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
    const auto handle=(op==2 || op==3)?r[3]:op==5?r[2]:r[0];
    const auto found=streams_.find(handle);
    const bool pointer_result=op==5;
    if(found==streams_.end())return fail(error,r,9,(op==2 || op==3 || pointer_result)?0:eof);
    auto &stream=found->second;
    if(op==1){const auto fd=stream.fd;streams_.erase(found);memory_.unmap(handle);const auto result=files_->close(fd);if(result.error!=host::FileError::none || result.value!=0)return fail(error,r,result.error==host::FileError::none?5:code(result.error),eof);r[0]=0;return a64::Fault::none;}
    if(op==6){r[0]=stream.eof;return a64::Fault::none;}
    if(op==7){r[0]=stream.error;return a64::Fault::none;}
    if(op==8){stream.eof=false;stream.error=false;return a64::Fault::none;}
    if(op==9){r[0]=static_cast<std::uint64_t>(stream.fd);return a64::Fault::none;}
    if(op==10){if(!stream.write)return fail(error,r,9,eof);stream.direction=0;r[0]=0;return a64::Fault::none;}
    if(op>10)return a64::Fault::unsupported_service;
    const bool writing=op==3;
    std::uint64_t size=1,count=1;auto destination=r[0];
    if(op==2 || op==3){size=r[1];count=r[2];if(!size || !count){r[0]=0;return a64::Fault::none;}if(size>transfer_limit || count>transfer_limit/size){stream.error=true;return fail(error,r,75,0);}}
    if(op==5){const auto length=static_cast<std::int32_t>(r[1]);if(length<=0)return a64::Fault::invalid_call;count=static_cast<std::uint32_t>(length)-1;if(count>=transfer_limit)return fail(error,r,75,0);}

    const auto total=static_cast<std::size_t>(size*count);
    if(op!=4 && !memory_.accessible(destination,total+(op==5?1:0),writing?a64::Permission::read:a64::Permission::write)){stream.error=true;return fail(error,r,14,0);}
    if(op==5 && !total){const std::array<std::uint8_t,1> zero{};if(!memory_.write(destination,zero))return fail(error,r,14,0);r[0]=destination;return a64::Fault::none;}
    if((writing && (!stream.write || (stream.direction==1 && !stream.eof))) || (!writing && (!stream.read || stream.direction==2))){stream.error=true;return fail(error,r,9,(op==4)?eof:0);}
    stream.direction=writing?2U:1U;
    std::vector<std::uint8_t> bytes(op==4?1:total);if(writing && !memory_.read(destination,bytes))return fail(error,r,14,0);
    std::size_t done=0;unsigned failure=0;
    while(done<bytes.size()){
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
    if(op==4)value=done?bytes[0]:eof;
    if(op==5){value=done?destination:0;if(value){const std::array<std::uint8_t,1> zero{};if(!memory_.write(destination+done,zero))return fail(error,r,14,0);}}
    if(failure)return fail(error,r,failure,value);
    r[0]=value;return a64::Fault::none;
}
}
