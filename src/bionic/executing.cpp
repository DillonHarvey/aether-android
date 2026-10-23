#include "executing.hpp"
#include "access.hpp"
#include <array>
#include <string>
#include <vector>

namespace aether::bionic {
namespace {
struct Failure {unsigned error;};
std::string text(a64::GuestMemory &memory,a64::Address address,std::size_t limit,unsigned overlong) {
    std::string result;
    for(std::size_t i=0;i<limit;++i){
        std::array<std::uint8_t,1> byte{};
        if(!address || address>=a64::GuestMemory::address_limit || i>=a64::GuestMemory::address_limit-address || !memory.read(address+i,byte))throw Failure{14};
        if(!byte[0])return result;
        result.push_back(static_cast<char>(byte[0]));
    }
    throw Failure{overlong};
}
}
a64::Fault NativeExecuting::invoke(a64::Address error,a64::ServiceState &state,bool full_frame) noexcept {
    using a64::Fault;
    rejection_={};
    const auto fail=[&](unsigned code){
        std::array<std::uint8_t,4> bytes{};for(unsigned i=0;i<4;++i)bytes[i]=static_cast<std::uint8_t>(code>>(8*i));
        if(!memory_.write(error,bytes))return Fault::write;
        state.registers[0]=UINT64_MAX;return Fault::none;
    };
    try {
        // Copy every argument before touching a provider; never use host argv,
        // va_list, environment, PATH or a guest address as a Windows path.
        std::vector<a64::Address> pointers;
        if(state.registers[1])pointers.push_back(state.registers[1]);
        bool terminated=false;
        for(unsigned argument=2;argument<258;++argument){
            std::uint64_t pointer=0;
            if(argument<8)pointer=state.registers[argument];
            else {
                if(!full_frame){rejection_="execlp: stack arguments require a full native frame";return Fault::unsupported_service;}
                const auto offset=std::uint64_t{argument-8}*8;
                if(state.stack_pointer%16 || state.stack_pointer>a64::GuestMemory::address_limit-8 || offset>a64::GuestMemory::address_limit-state.stack_pointer-8)throw Failure{14};
                std::array<std::uint8_t,8> slot{};
                if(!memory_.read(state.stack_pointer+offset,slot))throw Failure{14};
                for(unsigned i=0;i<8;++i)pointer|=std::uint64_t{slot[i]}<<(8*i);
            }
            if(!pointer){terminated=true;break;}
            if(pointers.size()==256)throw Failure{7};
            pointers.push_back(pointer);
        }
        if(!terminated)throw Failure{7};
        if(!state.registers[0])return fail(2);
        const auto target=text(memory_,state.registers[0],1024,36);
        if(target.empty())return fail(2);
        std::vector<std::string> arguments;
        std::size_t bytes=0;
        for(const auto pointer:pointers){
            auto value=text(memory_,pointer,65536-bytes,7);
            bytes+=value.size()+1;arguments.push_back(std::move(value));
        }
        if(target.find('/')==std::string::npos){rejection_="execlp: guest PATH executable resolution is unsupported";return Fault::unsupported_service;}
        const auto result=access_.probe_executable(target);
        switch(result.error){
        case host::FileError::missing:return fail(2);
        case host::FileError::denied:return fail(13);
        case host::FileError::invalid:return fail(22);
        case host::FileError::io:return fail(5);
        case host::FileError::none:rejection_="execlp: guest executable image replacement is unsupported";return Fault::unsupported_service;
        default:rejection_="execlp: target executable namespace or path profile is unsupported";return Fault::unsupported_service;
        }
    }catch(const Failure &failure){return fail(failure.error);}
    catch(...){rejection_="execlp: host argument marshalling failed";return Fault::unsupported_service;}
}
}
