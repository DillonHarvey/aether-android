#include "phdr.hpp"
#include "threads.hpp"
#include "aether/common/thread_exit.hpp"
#include <algorithm>
#include <bit>
#include <utility>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
constexpr std::size_t phdr_bytes=56,name_bytes=4096,maximum_headers=128;
constexpr std::uint64_t callback_budget=1'000'000;
void word(std::span<std::uint8_t> target,std::size_t offset,std::uint64_t value,unsigned size=8){
    for(unsigned i=0;i<size;++i)target[offset+i]=static_cast<std::uint8_t>(value>>(8*i));
}
}

NativePhdr::~NativePhdr(){
    for(std::size_t i=0;i<cache_.size();++i)if(cache_[i].owned){
        try{memory_.unmap(cache_base+i*slot_bytes);}catch(...){}
    }
}
void NativePhdr::provider(GuestPosixServices::ProgramHeaderLookup value){provider_=std::move(value);}
void NativePhdr::runner(GuestPosixServices::PhdrRunner value){runner_=std::move(value);}

Fault NativePhdr::prepare(std::size_t index,const elf::ProgramHeaderInfo &image){
    const auto reject=[&](std::string_view reason,Fault fault=Fault::unsupported_service){rejection_=reason;return fault;};
    if(image.name.empty() || image.name.size()>=name_bytes || image.name.find('\0')!=std::string::npos ||
       image.load_bias>=a64::GuestMemory::address_limit || image.headers.empty() ||
       image.headers.size()%phdr_bytes || image.headers.size()>maximum_headers*phdr_bytes)
        return reject("dl_iterate_phdr: invalid committed ELF metadata");
    auto &cached=cache_[index];
    const auto address=cache_base+index*slot_bytes;
    if(cached.owned){
        if(cached.name!=image.name || cached.load_bias!=image.load_bias || cached.headers!=image.headers)
            return reject("dl_iterate_phdr: committed ELF identity changed");
        const auto mapping=memory_.mapping(address);
        if(!mapping || mapping->address!=address || mapping->size!=slot_bytes || mapping->permissions!=a64::Permission::read)
            return reject("dl_iterate_phdr: cached ELF metadata mapping changed",Fault::read);
        return Fault::none;
    }
    if(memory_.find_free(address,address+slot_bytes,slot_bytes)!=address)
        return reject("dl_iterate_phdr: private ELF metadata address is occupied");
    // Finish host allocations before acquiring a guest mapping. Publication of
    // the immutable cache follows successful data and protection updates.
    Cache prepared{image.name,image.load_bias,image.headers,false};
    std::vector<std::uint8_t> bytes(slot_bytes);
    std::copy(image.name.begin(),image.name.end(),bytes.begin());
    std::copy(image.headers.begin(),image.headers.end(),bytes.begin()+name_bytes);
    bool mapped=false;
    try{
        memory_.map(address,slot_bytes,a64::read_write);mapped=true;
        if(!memory_.write(address,bytes)){
            memory_.unmap(address);mapped=false;
            return reject("dl_iterate_phdr: ELF metadata publication failed",Fault::write);
        }
        memory_.protect(address,a64::Permission::read);
        prepared.owned=true;cached=std::move(prepared);
        return Fault::none;
    }catch(...){
        if(mapped)try{memory_.unmap(address);}catch(...){}
        throw;
    }
}

Fault NativePhdr::invoke(a64::ServiceState &state,bool full_frame) noexcept {
    const auto reject=[&](std::string_view reason,Fault fault=Fault::unsupported_service){rejection_=reason;return fault;};
    rejection_={};
    try{
        if(!app_.process_state)return reject("dl_iterate_phdr: process state is unavailable");
        if(app_.process_state->exit_status())return reject("dl_iterate_phdr: process has terminated",Fault::process_exit);
        const auto owner=threads_.tid();const auto tls=threads_.tls();
        if(!owner || !tls)return reject("dl_iterate_phdr: current logical thread is unavailable");
        if(threads_.exit_value(tls))return reject("dl_iterate_phdr: logical thread has terminated",Fault::thread_exit);
        if(!full_frame)return reject("dl_iterate_phdr: callbacks require a trusted full guest frame");
        const auto callback=state.registers[0],data=state.registers[1],stack=state.stack_pointer;
        if(callback%4 || !memory_.accessible(callback,4,a64::Permission::execute))
            return reject("dl_iterate_phdr: callback is not aligned executable guest code",Fault::execute);
        if(stack<80 || stack%16 || !state.stack_top || stack>state.stack_top ||
           !memory_.accessible(stack-80,80,a64::Permission::write))
            return reject("dl_iterate_phdr: active guest stack lacks aligned writable callback space",Fault::write);
        if(!provider_)return reject("dl_iterate_phdr: committed ELF provider is unavailable");
        if(!runner_)return reject("dl_iterate_phdr: owned callback runner is unavailable");
        if(depth_==slot_count)return reject("dl_iterate_phdr: callback nesting exceeds 16 enumerations",Fault::nesting_limit);
        // Reentrant callbacks may replace either configured function. This call
        // retains its own function values and no borrowed loader references.
        const auto lookup=provider_;const auto run=runner_;
        ++depth_;
        struct Scope {unsigned &depth;~Scope(){--depth;}} scope{depth_};
        std::uint64_t remaining=callback_budget;
        const Address info=stack-64;
        for(std::size_t index=0;;++index){
            const auto image=lookup(index);
            if(app_.process_state->exit_status())return reject("dl_iterate_phdr: provider terminated the process",Fault::process_exit);
            if(threads_.exit_value(tls))return reject("dl_iterate_phdr: logical thread has terminated",Fault::thread_exit);
            if(threads_.tid()!=owner || threads_.tls()!=tls)return reject("dl_iterate_phdr: provider changed the logical thread binding");
            if(!image){state.registers[0]=0;rejection_={};return Fault::none;}
            if(index==slot_count)return reject("dl_iterate_phdr: committed ELF count exceeds 16");
            const auto prepared=prepare(index,*image);if(prepared!=Fault::none)return prepared;
            if(!remaining)return reject("dl_iterate_phdr: enumeration callback budget exhausted",Fault::budget);
            if(!memory_.accessible(callback,4,a64::Permission::execute))
                return reject("dl_iterate_phdr: callback is no longer executable",Fault::execute);
            if(!memory_.accessible(info-16,80,a64::Permission::write))
                return reject("dl_iterate_phdr: callback stack space is no longer writable",Fault::write);
            std::array<std::uint8_t,64> record{};
            const auto base=cache_base+index*slot_bytes;
            word(record,0,image->load_bias);word(record,8,base);word(record,16,base+name_bytes);
            word(record,24,image->headers.size()/phdr_bytes,2);word(record,32,image->adds);
            // Images are pinned, and PT_TLS is rejected by the ELF loader.
            // Unload count, TLS module ID and current-thread TLS data stay zero.
            if(!memory_.write(info,record))return reject("dl_iterate_phdr: callback info is unwritable",Fault::write);
            const auto execution=run(callback,{info,record.size(),data},info,tls,remaining);
            if(app_.process_state->exit_status())return reject("dl_iterate_phdr: callback terminated the process",Fault::process_exit);
            if(threads_.exit_value(tls))return reject("dl_iterate_phdr: callback terminated its logical thread",Fault::thread_exit);
            if(execution.result.fault!=Fault::none)return reject("dl_iterate_phdr: callback execution failed",execution.result.fault);
            if(!execution.result.returned)return reject("dl_iterate_phdr: callback did not return",Fault::invalid_call);
            if(threads_.tid()!=owner || threads_.tls()!=tls)return reject("dl_iterate_phdr: callback did not restore its logical thread binding");
            if(execution.ticks>remaining)return reject("dl_iterate_phdr: callback exceeded its enumeration budget",Fault::budget);
            remaining-=execution.ticks;
            const auto result=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(execution.result.registers[0]));
            if(result){state.registers[0]=static_cast<std::uint64_t>(static_cast<std::int64_t>(result));rejection_={};return Fault::none;}
            // Query the next committed index after guest reentry, so newly
            // appended pinned images and the current load count are visible.
        }
    }catch(const ThreadExit &exit){
        threads_.request_exit(exit.value);return reject("dl_iterate_phdr: callback exited its logical thread",Fault::thread_exit);
    }catch(const ProcessExit &exit){
        if(app_.process_state){if(exit.signal)app_.process_state->request_signal(exit.signal);else app_.process_state->request_exit(exit.status);}
        return reject("dl_iterate_phdr: callback exited the process",Fault::process_exit);
    }catch(const elf::ElfError &){return reject("dl_iterate_phdr: committed ELF metadata is unavailable");}
    catch(const a64::GuestError &){return reject("dl_iterate_phdr: private metadata mapping failed",Fault::windows_service);}
    catch(...){return reject("dl_iterate_phdr: trusted metadata or callback operation failed",Fault::windows_service);}
}
}
