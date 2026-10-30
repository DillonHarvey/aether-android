#include "wide_memory.hpp"
#include <array>
#include <vector>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
constexpr std::size_t maximum_bytes=1024*1024,maximum_units=maximum_bytes/4;
struct Failure {Fault fault;const char *message;};
[[noreturn]] void limit(){throw Failure{Fault::unsupported_service,"wide memory: accessed span exceeds 1 MiB"};}
std::uint32_t read_unit(a64::GuestMemory &memory,Address address,std::size_t index){
    if(index>=maximum_units)limit();
    const auto distance=index*4;
    if(address>=a64::GuestMemory::address_limit || distance>a64::GuestMemory::address_limit-address ||
       4>a64::GuestMemory::address_limit-address-distance)
        throw Failure{Fault::read,"wide memory: source address overflow"};
    std::array<std::uint8_t,4> bytes{};
    if(!memory.read(address+distance,bytes))throw Failure{Fault::read,"wide memory: unreadable source unit"};
    std::uint32_t result=0;
    for(unsigned i=0;i<4;++i)result|=std::uint32_t{bytes[i]}<<(8*i);
    return result;
}
}
a64::Fault NativeWideMemory::invoke(unsigned operation,std::array<std::uint64_t,31> &r) noexcept {
    rejection_={};
    try {
        if(operation>5)throw Failure{Fault::unsupported_service,"wide memory: invalid operation"};
        if(operation==1){
            for(std::size_t index=0;;++index)if(!read_unit(memory_,r[0],index)){r[0]=index;return Fault::none;}
        }
        const auto count=r[2];
        if(operation==3){
            for(std::uint64_t index=0;index<count;++index){
                const auto first=read_unit(memory_,r[0],static_cast<std::size_t>(index));
                const auto second=read_unit(memory_,r[1],static_cast<std::size_t>(index));
                if(first!=second){r[0]=first>second?1U:UINT32_MAX;return Fault::none;}
            }
            r[0]=0;return Fault::none;
        }
        if(operation==4){
            const auto wanted=static_cast<std::uint32_t>(r[1]);
            for(std::uint64_t index=0;index<count;++index){
                if(read_unit(memory_,r[0],static_cast<std::size_t>(index))==wanted){
                    r[0]+=index*4;return Fault::none;
                }
            }
            r[0]=0;return Fault::none;
        }
        // Zero-count bulk operations return their destination without touching
        // either guest span. Check multiplication before allocating host storage.
        if(!count)return Fault::none;
        if(count>maximum_units)limit();
        const auto bytes=static_cast<std::size_t>(count)*4;
        if(!memory_.accessible(r[0],bytes,a64::Permission::write))
            throw Failure{Fault::write,"wide memory: unwritable destination"};
        std::vector<std::uint8_t> snapshot(bytes);
        if(operation==5){
            const auto value=static_cast<std::uint32_t>(r[1]);
            for(std::size_t at=0;at<bytes;at+=4)
                for(unsigned i=0;i<4;++i)snapshot[at+i]=static_cast<std::uint8_t>(value>>(8*i));
        } else if(!memory_.read(r[1],snapshot)){
            throw Failure{Fault::read,"wide memory: unreadable source span"};
        }
        // Snapshot before publication gives memmove its overlapping semantics;
        // GuestMemory preflights the whole write, preserving fault atomicity.
        if(!memory_.write(r[0],snapshot))throw Failure{Fault::write,"wide memory: unwritable destination"};
        return Fault::none;
    }catch(const Failure &failure){rejection_=failure.message;return failure.fault;}
    catch(...){rejection_="wide memory: host allocation or marshalling failed";return Fault::windows_service;}
}
}
