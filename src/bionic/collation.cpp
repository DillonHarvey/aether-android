#include "collation.hpp"
#include <algorithm>
#include <vector>

namespace aether::bionic {
namespace {
struct Failure {a64::Fault fault;const char *message;};
constexpr std::size_t source_limit=1024*1024;
std::uint32_t unit(a64::GuestMemory &memory,a64::Address base,std::size_t index,unsigned width) {
    if(index>=source_limit/width)
        throw Failure{a64::Fault::unsupported_service,"collation: source exceeds 1 MiB profile"};
    const auto distance=index*width;
    if(base>=a64::GuestMemory::address_limit || distance>a64::GuestMemory::address_limit-base ||
       width>a64::GuestMemory::address_limit-base-distance)
        throw Failure{a64::Fault::read,"collation: source address overflow"};
    std::array<std::uint8_t,4> bytes{};
    if(!memory.read(base+distance,std::span{bytes}.first(width)))
        throw Failure{a64::Fault::read,"collation: source is unreadable"};
    std::uint32_t value=0;
    for(unsigned i=0;i<width;++i)value|=std::uint32_t{bytes[i]}<<(8*i);
    return value;
}
}
a64::Fault NativeCollation::invoke(unsigned operation,std::array<std::uint64_t,31> &registers) noexcept {
    rejection_={};
    try {
        if(operation>3)throw Failure{a64::Fault::unsupported_service,"collation: invalid operation"};
        const unsigned width=operation>=2?4:1;
        if((operation&1)==0){
            for(std::size_t index=0;;++index){
                const auto left=unit(memory_,registers[0],index,width);
                const auto right=unit(memory_,registers[1],index,width);
                if(left!=right){
                    // Bionic wcscmp subtracts unsigned 32-bit units then returns
                    // int. Preserve those low32 bits, including raw-unit wrap.
                    registers[0]=std::uint32_t{left-right};return a64::Fault::none;
                }
                if(!left){registers[0]=0;return a64::Fault::none;}
            }
        }
        const auto destination=registers[0],source=registers[1],count=registers[2];
        std::vector<std::uint8_t> bytes;
        std::size_t length=0;
        for(;;++length){
            const auto value=unit(memory_,source,length,width);
            // Cache only units which can actually be copied. A zero-sized
            // destination is never inspected, regardless of its address.
            if(count && length<count)
                for(unsigned i=0;i<width;++i)bytes.push_back(static_cast<std::uint8_t>(value>>(8*i)));
            if(!value)break;
        }
        if(count){
            // strlcpy/wcslcpy always terminate when n>0, even on truncation.
            // They do not pad unused destination units with additional zeros.
            const auto written=static_cast<std::size_t>((std::min)(count,std::uint64_t{length+1}))*width;
            std::fill(bytes.end()-width,bytes.end(),0);
            if(bytes.size()!=written || !memory_.write(destination,bytes))
                throw Failure{a64::Fault::write,"collation: destination is unwritable"};
        }
        registers[0]=length;return a64::Fault::none;
    }catch(const Failure &failure){rejection_=failure.message;return failure.fault;}
    catch(...){rejection_="collation: bounded host storage unavailable";return a64::Fault::windows_service;}
}
}
