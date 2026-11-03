#include "stdio.hpp"
#include "locale.hpp"
#include <algorithm>
#include <limits>
#include <bit>
#include <new>
namespace aether::bionic {
namespace {
constexpr std::size_t transfer_limit=1024*1024;
unsigned code(host::FileError error){using E=host::FileError;switch(error){case E::none:return 0;case E::missing:return 2;case E::denied:return 13;case E::exists:return 17;case E::bad_descriptor:return 9;case E::invalid:return 22;case E::unsupported:return 95;case E::descriptor_limit:return 24;case E::quota:return 28;case E::io:return 5;case E::would_block:return 11;case E::is_directory:return 21;case E::not_directory:return 20;case E::not_empty:return 39;case E::not_seekable:return 29;}return 5;}
unsigned text(a64::GuestMemory &memory,a64::Address address,std::size_t limit,std::string &out){
    for(std::size_t i=0;i<limit;++i){
        std::array<std::uint8_t,1> byte{};
        if(address>=a64::GuestMemory::address_limit || i>=a64::GuestMemory::address_limit-address || !memory.read(address+i,byte))return 14;
        if(!byte[0])return 0;
        out.push_back(static_cast<char>(byte[0]));
    }
    return 36;
}
struct Mode {bool read=false,write=false,create=false,truncate=false,exclusive=false,cloexec=false;};
unsigned mode(a64::GuestMemory &memory,a64::Address address,Mode &out){
    std::string value;const auto status=text(memory,address,8,value);if(status)return status;
    if(value.empty() || (value[0]!='r' && value[0]!='w' && value[0]!='a'))return 22;
    if(value[0]=='a')return 95; // No owned atomic-append descriptor profile yet.
    bool plus=false,binary=false;
    for(std::size_t i=1;i<value.size();++i){
        bool *flag=nullptr;
        switch(value[i]){case '+':flag=&plus;break;case 'b':flag=&binary;break;case 'x':flag=&out.exclusive;break;case 'e':flag=&out.cloexec;break;default:return 22;}
        if(*flag)return 22;*flag=true;
    }
    if(out.exclusive && value[0]!='w')return 22;
    out.read=value[0]=='r'||plus;out.write=value[0]=='w'||plus;
    out.create=out.truncate=value[0]=='w';return 0;
}
}
a64::Fault NativeStdio::orient(Stream &stream,bool wide){
    const int requested=wide?1:-1;
    if(stream.orientation && stream.orientation!=requested)return a64::Fault::unsupported_service;
    if(!stream.orientation){
        if(wide){
            if(!locales_)return a64::Fault::unsupported_service;
            std::array<std::uint64_t,31> registers{};
            const auto fault=locales_->invoke(6,registers);
            if(fault!=a64::Fault::none)return fault;
            if(registers[0]!=1 && registers[0]!=4)return a64::Fault::unsupported_service;
            stream.encoding=static_cast<unsigned>(registers[0]);
        }
        stream.orientation=requested;
    }
    return a64::Fault::none;
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
        if(found!=streams_.end()){
            const auto &stream=found->second;
            flags=(stream.read&&stream.write?0x10U|(stream.direction==1?4U:stream.direction==2?8U:0U):stream.read?4U:8U)|
                (i==2?2U:0U)|(stream.eof?0x20U:0U)|(stream.error?0x40U:0U);
            fd=static_cast<std::uint32_t>(stream.fd);
        }
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
    return invoke_impl(op,error,r,nullptr);
}
NativeStdio::WriteCompletion NativeStdio::invoke_output(unsigned op,a64::Address error,std::array<std::uint64_t,31>&r){
    WriteCompletion completion;
    if(op!=3 && op!=15 && op!=16 && op!=17 && op!=22){completion.fault=a64::Fault::unsupported_service;return completion;}
    // EPIPE and partial-write errors must be publishable before pipe bytes can
    // become visible; the trusted errno destination is not guest FILE storage.
    if(!memory_.accessible(error,4,a64::Permission::write)){completion.fault=a64::Fault::write;return completion;}
    completion.fault=invoke_impl(op,error,r,&completion);
    if(completion.fault==a64::Fault::none && completion.continuation_unavailable)
        completion.fault=a64::Fault::unsupported_service;
    return completion;
}
a64::Fault NativeStdio::invoke_impl(unsigned op,a64::Address error,std::array<std::uint64_t,31>&r,WriteCompletion *completion){
    // Bionic checks the int argument before it inspects even the FILE pointer.
    if((op==14 || op==23) && static_cast<std::uint32_t>(r[0])==UINT32_MAX){r[0]=UINT64_MAX;return a64::Fault::none;}
    // The public layout carries metadata only. Descriptor authority stays in streams_.
    // Preflight every metadata destination before a provider read or write can occur.
    if(!preflight_standard())return a64::Fault::write;
    const auto fault=operate(op,error,r,completion);
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
    const auto oriented=orient(stream,false);
    if(oriented!=a64::Fault::none)return finish(oriented);
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
    return write_formatted_impl(handle,error,bytes,r,nullptr);
}
NativeStdio::WriteCompletion NativeStdio::write_formatted_output(a64::Address handle,a64::Address error,
                                                               std::span<const std::uint8_t> bytes,
                                                               std::array<std::uint64_t,31>&r){
    WriteCompletion completion;
    if(!memory_.accessible(error,4,a64::Permission::write)){completion.fault=a64::Fault::write;return completion;}
    completion.fault=write_formatted_impl(handle,error,bytes,r,&completion);
    if(completion.fault==a64::Fault::none && completion.continuation_unavailable)
        completion.fault=a64::Fault::unsupported_service;
    return completion;
}
NativeDescriptors::WriteOutcome NativeStdio::write_output(int fd,std::span<const std::uint8_t> bytes,WriteCompletion *completion){
    if(!completion)return {files_->write(fd,bytes),false};
    // Deliberately no Progress callback: stream map references and metadata stay
    // stable until the caller commits the result and later delivers SIGPIPE.
    const auto outcome=files_->write_wait_outcome(fd,bytes,{});
    if(outcome.result.value>0 && static_cast<std::uint64_t>(outcome.result.value)<=bytes.size())
        completion->committed_bytes+=static_cast<std::uint64_t>(outcome.result.value);
    completion->broken_pipe|=outcome.broken_pipe;
    if(!outcome.broken_pipe && outcome.result.error==host::FileError::unsupported && files_->is_pipe(fd))
        completion->continuation_unavailable=true;
    return outcome;
}
a64::Fault NativeStdio::write_formatted_impl(a64::Address handle,a64::Address error,
                                          std::span<const std::uint8_t> bytes,
                                          std::array<std::uint64_t,31>&r,WriteCompletion *completion){
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
        const auto outcome=write_output(stream.fd,bytes.subspan(done),completion);
        const auto &written=outcome.result;
        if(written.value>0 && static_cast<std::uint64_t>(written.value)<=remaining)
            done+=static_cast<std::size_t>(written.value);
        if(outcome.broken_pipe || written.error!=host::FileError::none || written.value<=0 ||
           static_cast<std::uint64_t>(written.value)>remaining){
            stream.error=true;
            // Accepted prefixes stay committed. A failure never replays them,
            // and an errno fault must not publish a new return value.
            const auto number=outcome.broken_pipe?32:written.error==host::FileError::none?5:code(written.error);
            return finish(fail(error,result,number,UINT64_MAX));
        }
    }
    // fprintf preserves an earlier error indicator and returns -1 for it,
    // including an empty current output, without inventing a new errno value.
    result[0]=stream.error?UINT64_MAX:static_cast<std::uint64_t>(done);
    return finish(a64::Fault::none);
}

a64::Fault NativeStdio::fail(a64::Address error,std::array<std::uint64_t,31>&r,unsigned value,std::uint64_t result){std::array<std::uint8_t,4> bytes{};for(unsigned i=0;i<4;++i)bytes[i]=static_cast<std::uint8_t>(value>>(8*i));if(!memory_.write(error,bytes))return a64::Fault::write;r[0]=result;return a64::Fault::none;}
a64::Fault NativeStdio::operate(unsigned op,a64::Address error,std::array<std::uint64_t,31>&r,WriteCompletion *completion){
    constexpr auto eof=~std::uint64_t{0};
    if(op==0 || op==20 || op==21){
        const bool attaching=op==20,reopening=op==21;
        auto existing=reopening?streams_.find(r[2]):streams_.end();
        if(reopening && existing==streams_.end())return fail(error,r,9,0);
        const auto retire=[&](){
            if(existing==streams_.end())return;
            const auto address=existing->first;const auto fd=existing->second.fd;
            streams_.erase(existing);existing=streams_.end();
            if(address<standard_base || address>=standard_base+456)memory_.unmap(address);
            (void)files_->close(fd);
        };
        Mode selected;const auto status=mode(memory_,r[1],selected);
        if(status){if(reopening)retire();return fail(error,r,status,0);}
        // Reopening a null pathname needs an independent same-object open with
        // new access rights. A pathname reconstructed from a guest fd is not authority.
        if(reopening && !r[0]){retire();return fail(error,r,95,0);}
        if(!attaching && !private_files_){if(reopening)retire();return fail(error,r,13,0);}
        std::string name;
        if(!attaching){const auto path_status=text(memory_,r[0],128,name);if(path_status){if(reopening)retire();return fail(error,r,path_status,0);}}
        int attached_fd=-1;
        if(attaching){
            attached_fd=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[0]));
            const auto flags=files_->control(attached_fd,3,0);
            if(flags.error!=host::FileError::none)return fail(error,r,code(flags.error),0);
            const auto access=static_cast<unsigned>(flags.value)&3U;
            if((selected.read && access==1) || (selected.write && access==0))return fail(error,r,22,0);
            if(access>2)return fail(error,r,22,0);
        }
        if(!reopening && (std::count_if(streams_.begin(),streams_.end(),[](const auto &item){return item.first<standard_base || item.first>=standard_base+456;})>=16 || next_>=0x3b000000))return fail(error,r,24,0);
        const auto address=reopening?existing->first:next_;
        auto it=existing;
        if(!reopening){
            // All FILE ownership allocation precedes fd ownership transfer or
            // provider creation/truncation. fdopen does not duplicate or truncate.
            const auto inserted=streams_.emplace(address,Stream{-1,selected.read,selected.write});
            if(!inserted.second)return fail(error,r,5,0);it=inserted.first;
            try{memory_.map(address,4096,a64::read_write);}catch(...){streams_.erase(it);return fail(error,r,12,0);}
        }
        host::FileResult opened{attached_fd,host::FileError::none};
        try{if(!attaching)opened=files_->open(name,{selected.read,selected.write,selected.create,selected.exclusive,selected.truncate});}
        catch(...){if(reopening)retire();else{memory_.unmap(address);streams_.erase(it);}throw;}
        if(opened.error!=host::FileError::none || opened.value<0 || opened.value>std::numeric_limits<int>::max()){
            if(reopening)retire();else{memory_.unmap(address);streams_.erase(it);}
            return fail(error,r,opened.error==host::FileError::none?5:code(opened.error),0);
        }
        auto fd=static_cast<int>(opened.value);
        if(reopening){
            const auto previous=it->second.fd;
            // Keep the original descriptor number, including stdin/out/err,
            // using the actual alias replacement rather than FILE metadata.
            const auto replaced=files_->duplicate_to(fd,previous);
            if(replaced.error!=host::FileError::none || replaced.value!=previous){
                (void)files_->close(fd);retire();return fail(error,r,replaced.error==host::FileError::none?5:code(replaced.error),0);
            }
            if(fd!=previous)(void)files_->close(fd);fd=previous;
            it->second=Stream{fd,selected.read,selected.write};
        }else it->second.fd=fd;
        if(!attaching || selected.cloexec)files_->set_close_on_exec(fd,selected.cloexec);
        if(!reopening)next_+=4096;r[0]=address;return a64::Fault::none;
    }
    if(op==16 || op==17){
        a64::Address handle=r[1];
        if(op==17){
            std::array<std::uint8_t,8> pointer{};
            if(!memory_.read(standard_base+520,pointer))return a64::Fault::read;
            handle=0;for(unsigned i=0;i<8;++i)handle|=std::uint64_t{pointer[i]}<<(8*i);
        }
        std::string source;const auto status=text(memory_,r[0],transfer_limit,source);
        if(status)return fail(error,r,status,eof);
        if(op==17){if(source.size()==transfer_limit-1)return fail(error,r,75,eof);source.push_back('\n');}
        return write_formatted_impl(handle,error,{reinterpret_cast<const std::uint8_t*>(source.data()),source.size()},r,completion);
    }
    if(op==18 || op==19){
        const auto position=r[1];
        std::array<std::uint8_t,8> value{};
        if(op==18){
            if(!memory_.accessible(position,value.size(),a64::Permission::write))return fail(error,r,14,eof);
            const auto fault=operate(13,error,r,completion);
            if(fault!=a64::Fault::none || r[0]==eof)return fault;
            for(unsigned i=0;i<8;++i)value[i]=static_cast<std::uint8_t>(r[0]>>(8*i));
            if(!memory_.write(position,value))return fail(error,r,14,eof);
            r[0]=0;return a64::Fault::none;
        }
        if(!memory_.read(position,value))return fail(error,r,14,eof);
        std::uint64_t offset=0;for(unsigned i=0;i<8;++i)offset|=std::uint64_t{value[i]}<<(8*i);
        r[1]=offset;r[2]=0;return operate(12,error,r,completion);
    }
    if(op==10 && !r[0]){for(auto &[address,stream]:streams_){(void)address;if(stream.direction==2)stream.direction=0;}r[0]=0;return a64::Fault::none;}
    const auto handle=(op==2 || op==3)?r[3]:op==5?r[2]:(op==14 || op==15 || op==22 || op==23)?r[1]:r[0];
    const auto found=streams_.find(handle);
    const bool pointer_result=op==5;
    if(found==streams_.end()){
        const auto original=r[0];const auto fault=fail(error,r,9,(op==2 || op==3 || pointer_result)?0:eof);
        if(op==11)r[0]=original;return fault;
    }
    auto &stream=found->second;
    if(op>=22 && op<=24){
        const auto oriented=orient(stream,true);if(oriented!=a64::Fault::none)return oriented;
        const auto point=static_cast<std::uint32_t>(r[0]);
        if(op==23){
            if(!stream.read){r[0]=eof;return a64::Fault::none;}
            if(stream.wide_pushed.size()==pushback_limit/sizeof(std::uint32_t))return fail(error,r,12,eof);
            try{stream.wide_pushed.push_back(point);}catch(const std::bad_alloc &){return fail(error,r,12,eof);}
            stream.eof=false;stream.error=false;r[0]=point;return a64::Fault::none;
        }
        const bool writing=op==22;
        if((writing && (!stream.write || (stream.direction==1 && !stream.eof))) ||
           (!writing && (!stream.read || stream.direction==2))){stream.error=true;return fail(error,r,9,eof);}
        stream.direction=writing?2U:1U;
        if(writing){
            std::array<std::uint8_t,4> bytes{};unsigned count=0;
            if(point<0x80){bytes[0]=static_cast<std::uint8_t>(point);count=1;}
            else if(stream.encoding==1 || point>0x10ffff || (point>=0xd800 && point<=0xdfff)){
                stream.error=true;return fail(error,r,84,eof);
            }else{
                count=point<0x800?2:point<0x10000?3:4;
                auto rest=point;
                for(unsigned i=count-1;i>0;--i){bytes[i]=static_cast<std::uint8_t>(0x80|(rest&0x3f));rest>>=6;}
                bytes[0]=static_cast<std::uint8_t>((count==2?0xc0:count==3?0xe0:0xf0)|rest);
            }
            stream.eof=false;stream.wide_pushed.clear();
            std::size_t done=0;
            while(done<count){
                const auto outcome=write_output(stream.fd,std::span<const std::uint8_t>(bytes).subspan(done,count-done),completion);
                const auto &result=outcome.result;
                const bool valid=result.value>=0 && static_cast<std::uint64_t>(result.value)<=count-done;
                if(valid && result.value>0)done+=static_cast<std::size_t>(result.value);
                if(outcome.broken_pipe || result.error!=host::FileError::none || !valid || !result.value){
                    stream.error=true;return fail(error,r,outcome.broken_pipe?32:result.error==host::FileError::none?5:code(result.error),eof);
                }
            }
            r[0]=point;return a64::Fault::none;
        }
        if(!stream.wide_pushed.empty()){r[0]=stream.wide_pushed.back();stream.wide_pushed.pop_back();return a64::Fault::none;}
        for(unsigned step=0;step<4;++step){
            std::array<std::uint8_t,1> byte{};const auto result=files_->read(stream.fd,byte);
            if(result.error!=host::FileError::none){stream.error=true;return fail(error,r,code(result.error),eof);}
            if(result.value==0){stream.eof=true;r[0]=eof;return a64::Fault::none;}
            if(result.value!=1){stream.error=true;return fail(error,r,5,eof);}
            const auto value=byte[0];
            bool invalid=false;
            if(!stream.wide_used){
                if(value<0x80){r[0]=value;return a64::Fault::none;}
                if(stream.encoding==1 || value<0xc2 || value>0xf4)invalid=true;
                else{
                    stream.wide_expected=value<0xe0?2:value<0xf0?3:4;
                    stream.wide_minimum=stream.wide_expected==2?0x80:stream.wide_expected==3?0x800:0x10000;
                    stream.wide_point=value&(stream.wide_expected==2?0x1f:stream.wide_expected==3?0x0f:0x07);
                    stream.wide_used=1;
                }
            }else{
                if((value&0xc0)!=0x80)invalid=true;
                else{
                    stream.wide_point=(stream.wide_point<<6)|(value&0x3f);++stream.wide_used;
                    if(stream.wide_used==stream.wide_expected){
                        const auto decoded=stream.wide_point;
                        invalid=decoded<stream.wide_minimum || decoded>0x10ffff || (decoded>=0xd800 && decoded<=0xdfff);
                        stream.wide_used=stream.wide_expected=0;stream.wide_point=stream.wide_minimum=0;
                        if(!invalid){r[0]=decoded;return a64::Fault::none;}
                    }
                }
            }
            if(invalid){
                stream.wide_used=stream.wide_expected=0;stream.wide_point=stream.wide_minimum=0;
                stream.error=true;return fail(error,r,84,eof);
            }
        }
        return a64::Fault::invalid_call;
    }
    if(op==14){
        const auto oriented=orient(stream,false);if(oriented!=a64::Fault::none)return oriented;
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
        if(!telling){stream.eof=false;stream.direction=0;std::vector<std::uint8_t>{}.swap(stream.pushed);stream.wide_pushed.clear();stream.wide_used=stream.wide_expected=0;stream.wide_point=stream.wide_minimum=0;}
        if(rewinding)stream.error=false;
        else r[0]=telling?static_cast<std::uint64_t>(result.value-static_cast<std::int64_t>(stream.pushed.size())):0;
        return a64::Fault::none;
    }
    if(op>10 && op!=15)return a64::Fault::unsupported_service;
    const auto oriented=orient(stream,false);if(oriented!=a64::Fault::none)return oriented;
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
        const auto outcome=writing?write_output(stream.fd,std::span<const std::uint8_t>{bytes}.subspan(done,request),completion)
            :NativeDescriptors::WriteOutcome{files_->read(stream.fd,std::span<std::uint8_t>{bytes}.subspan(done,request)),false};
        const auto &result=outcome.result;
        // The native typed result can carry an already committed prefix along
        // with an unavailable continuation or broken peer. Count it exactly
        // once before publishing the stdio whole-item result and error.
        if(writing && completion && result.value>0 && static_cast<std::uint64_t>(result.value)<=request)
            done+=static_cast<std::size_t>(result.value);
        if(outcome.broken_pipe || result.error!=host::FileError::none){failure=outcome.broken_pipe?32:code(result.error);stream.error=true;break;}
        if(result.value<0 || static_cast<std::uint64_t>(result.value)>request){failure=5;stream.error=true;break;}
        if(!result.value){if(writing){failure=5;stream.error=true;}else stream.eof=true;break;}
        if(!writing || !completion)done+=static_cast<std::size_t>(result.value);
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
