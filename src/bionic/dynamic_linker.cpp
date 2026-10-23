#include "dynamic_linker.hpp"
#include "threads.hpp"
#include "thread_attributes.hpp"
#include "aether/common/thread_exit.hpp"
#include <algorithm>
#include <atomic>
#include <exception>
#include <limits>
#include <utility>

namespace aether::bionic {
namespace {
constexpr std::uint64_t handle_tag=0xd17a000000000000ULL,maximum_generation=0x0000ffffffffffffULL;
std::atomic<std::uint64_t> next_generation{1};
std::uint64_t handle() noexcept {
    auto value=next_generation.load(std::memory_order_relaxed);
    while(value<=maximum_generation){if(next_generation.compare_exchange_weak(value,value+1,std::memory_order_relaxed))return handle_tag|value;}
    return 0; // Never wrap or reuse a process generation.
}
enum class Read {ok,unreadable,overlong};
template<std::size_t N>
Read text(a64::GuestMemory &memory,a64::Address pointer,std::array<char,N> &buffer,std::size_t &length) noexcept {
    for(length=0;length<N;++length){
        if(!pointer || pointer>=a64::GuestMemory::address_limit || length>=a64::GuestMemory::address_limit-pointer)return Read::unreadable;
        std::array<std::uint8_t,1> byte{};if(!memory.read(pointer+length,byte))return Read::unreadable;
        buffer[length]=static_cast<char>(byte[0]);if(!byte[0])return Read::ok;
    }
    return Read::overlong;
}
bool library(std::string_view name) noexcept {
    if(name.size()<6 || !name.starts_with("lib") || !name.ends_with(".so") || name.find("..")!=std::string_view::npos)return false;
    for(const auto byte:name)if(!((byte>='a' && byte<='z') || (byte>='A' && byte<='Z') ||
        (byte>='0' && byte<='9') || byte=='_' || byte=='-' || byte=='+' || byte=='.'))return false;
    return true;
}
}
NativeDynamicLinker::~NativeDynamicLinker(){if(errors_owned_)try{memory_.unmap_range(errors_base,errors_bytes);}catch(...){}}
void NativeDynamicLinker::callbacks(DynamicLinkCallbacks value){callbacks_=std::move(value);}
NativeDynamicLinker::Module *NativeDynamicLinker::module(std::uint64_t value) noexcept {
    for(auto &entry:modules_)if(entry.phase==Phase::ready && entry.handle==value)return &entry;
    return nullptr;
}
void NativeDynamicLinker::discard_loading(std::uint64_t value) noexcept {
    for(auto &entry:modules_)if(entry.handle==value && entry.phase==Phase::loading){entry={};return;}
}
std::size_t NativeDynamicLinker::error_slot() {
    const auto tls=threads_.tls();const auto tid=threads_.tid();
    for(std::size_t i=0;i<errors_.size();++i)if(errors_[i].tid==tid && errors_[i].tls==tls)return i;
    for(std::size_t i=0;i<errors_.size();++i)if(errors_[i].tid && errors_[i].tls==tls){
        NativeThreadOptions options;a64::Address stack=0;
        if(threads_.query(errors_[i].tid,options,stack)==3){errors_[i]={};errors_[i].tid=tid;errors_[i].tls=tls;return i;}
    }
    for(std::size_t i=0;i<errors_.size();++i)if(!errors_[i].tid){errors_[i].tid=tid;errors_[i].tls=tls;return i;}
    return errors_.size();
}
a64::Fault NativeDynamicLinker::invoke(unsigned operation,std::array<std::uint64_t,31> &r) noexcept {
    using a64::Fault;
    rejection_={};std::uint64_t loading=0;
    if(app_.process_state && app_.process_state->exit_status())return Fault::process_exit;
    if(threads_.exit_value(threads_.tls()))return Fault::thread_exit;
    try{
        const auto slot=error_slot();
        if(slot==errors_.size()){rejection_="dynamic linker: logical thread error capacity exceeded";return Fault::unsupported_service;}
        const auto fail=[&](std::string_view message,std::uint64_t value=0){
            errors_[slot].text={};std::copy_n(message.begin(),std::min(message.size(),errors_[slot].text.size()-1),errors_[slot].text.begin());
            errors_[slot].pending=true;r[0]=value;return Fault::none;
        };
        if(operation==3){
            if(!errors_[slot].pending){r[0]=0;return Fault::none;}
            if(!errors_owned_){
                try{memory_.map(errors_base,errors_bytes,a64::read_write);errors_owned_=true;}
                catch(...){rejection_="dlerror: guest error storage is unavailable";return Fault::unsupported_service;}
            }
            const auto pointer=errors_base+slot*errors_[slot].text.size();
            if(!memory_.write(pointer,{reinterpret_cast<const std::uint8_t*>(errors_[slot].text.data()),errors_[slot].text.size()})){
                rejection_="dlerror: guest error storage is unwritable";return Fault::write;
            }
            errors_[slot].pending=false;r[0]=pointer;return Fault::none;
        }
        if(operation==2){
            auto entry=module(r[0]);if(!entry)return fail("dlclose: invalid or stale app handle",UINT64_MAX);
            if(--entry->references==0)*entry={};r[0]=0;return Fault::none;
        }
        if(operation==0){
            const auto flags=static_cast<std::uint32_t>(r[1]);
            if(flags!=1 && flags!=2)return fail("dlopen: unsupported loading flags");
            if(!r[0])return fail("dlopen: global handles are outside the supported profile");
            std::array<char,128> name{};std::size_t length=0;const auto read=text(memory_,r[0],name,length);
            if(read==Read::unreadable){rejection_="dlopen: unreadable module name";return Fault::read;}
            if(read==Read::overlong || !library({name.data(),length}))return fail("dlopen: invalid private library basename");
            const std::string_view requested{name.data(),length};
            for(auto &entry:modules_)if(entry.phase!=Phase::free && std::string_view(entry.name.data(),entry.length)==requested){
                if(entry.phase==Phase::loading)return fail("dlopen: module initialization is already in progress");
                if(entry.references==std::numeric_limits<std::uint32_t>::max())return fail("dlopen: app handle reference limit exceeded");
                ++entry.references;r[0]=entry.handle;return Fault::none;
            }
            if(!callbacks_.open)return fail("dlopen: authorized module source is unavailable");
            const auto opener=callbacks_.open;
            {
                const auto empty=std::find_if(modules_.begin(),modules_.end(),[](const auto &entry){return entry.phase==Phase::free;});
                if(empty==modules_.end())return fail("dlopen: app handle limit exceeded");
                loading=handle();if(!loading)return fail("dlopen: app handle generations exhausted");
                *empty={name,static_cast<std::uint32_t>(length),1,loading,Phase::loading};
            }
            // Only stack-owned name and callback copies survive constructor reentry.
            opener(requested);
            if(app_.process_state && app_.process_state->exit_status()){discard_loading(loading);return Fault::process_exit;}
            if(threads_.exit_value(threads_.tls())){discard_loading(loading);return Fault::thread_exit;}
            for(auto &entry:modules_)if(entry.handle==loading && entry.phase==Phase::loading){entry.phase=Phase::ready;r[0]=loading;return Fault::none;}
            rejection_="dlopen: pending app handle changed during initialization";return Fault::unsupported_service;
        }
        if(operation==1){
            std::array<char,128> name{};std::uint32_t length=0;
            {const auto entry=module(r[0]);if(!entry)return fail("dlsym: invalid or unsupported app handle");name=entry->name;length=entry->length;}
            std::array<char,256> symbol{};std::size_t symbol_length=0;const auto read=text(memory_,r[1],symbol,symbol_length);
            if(read==Read::unreadable){rejection_="dlsym: unreadable symbol name";return Fault::read;}
            if(read==Read::overlong || !symbol_length)return fail("dlsym: symbol name exceeds the supported profile");
            if(!callbacks_.lookup)return fail("dlsym: authorized module lookup is unavailable");
            const auto lookup=callbacks_.lookup;
            const auto result=lookup({name.data(),length},{symbol.data(),symbol_length});
            if(app_.process_state && app_.process_state->exit_status())return Fault::process_exit;
            if(threads_.exit_value(threads_.tls()))return Fault::thread_exit;
            if(!result)return fail("dlsym: symbol was not found in the selected module");
            r[0]=result->address;return Fault::none;
        }
        rejection_="dynamic linker: unsupported service operation";return Fault::unsupported_service;
    }catch(const ProcessExit &exit){
        discard_loading(loading);if(app_.process_state)app_.process_state->request_exit(exit.status);return Fault::process_exit;
    }catch(const ThreadExit &exit){discard_loading(loading);threads_.request_exit(exit.value);return Fault::thread_exit;
    }catch(const DynamicLinkExecution &execution){
        discard_loading(loading);rejection_="dynamic linker: guest module initialization failed";return execution.fault==Fault::none?Fault::unsupported_service:execution.fault;
    }catch(const DynamicLinkSourceError &source){
        discard_loading(loading);
        try{
            const auto slot=error_slot();if(slot==errors_.size()){rejection_="dynamic linker: logical thread error capacity exceeded";return Fault::unsupported_service;}
            errors_[slot].text={};
            const bool safe=!source.code.empty() && source.code.size()<=80 && std::all_of(source.code.begin(),source.code.end(),[](char byte){return (byte>='A' && byte<='Z') || (byte>='0' && byte<='9') || byte=='_';});
            constexpr std::string_view prefix="dynamic linker: module source rejected: ",generic="dynamic linker: authorized module operation failed";
            if(safe){std::copy(prefix.begin(),prefix.end(),errors_[slot].text.begin());std::copy(source.code.begin(),source.code.end(),errors_[slot].text.begin()+prefix.size());}
            else std::copy(generic.begin(),generic.end(),errors_[slot].text.begin());
            errors_[slot].pending=true;r[0]=0;return Fault::none;
        }catch(...){rejection_="dynamic linker: error state is unavailable";return Fault::unsupported_service;}
    }catch(const std::exception &){
        discard_loading(loading);
        try{
            const auto slot=error_slot();if(slot==errors_.size()){rejection_="dynamic linker: logical thread error capacity exceeded";return Fault::unsupported_service;}
            errors_[slot].text={};constexpr std::string_view message="dynamic linker: authorized module operation failed";
            std::copy(message.begin(),message.end(),errors_[slot].text.begin());errors_[slot].pending=true;r[0]=0;return Fault::none;
        }catch(...){rejection_="dynamic linker: error state is unavailable";return Fault::unsupported_service;}
    }catch(...){discard_loading(loading);rejection_="dynamic linker: unexpected trusted callback failure";return Fault::unsupported_service;}
}
}
