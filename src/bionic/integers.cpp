#include "integers.hpp"
#include <limits>
namespace aether::bionic {
namespace {
struct InputFault {a64::Fault fault;};
bool space(unsigned c){return c==' ' || (c>=9 && c<=13);}
unsigned digit(unsigned c){if(c>='0' && c<='9')return c-'0';if(c>='a' && c<='z')return c-'a'+10;if(c>='A' && c<='Z')return c-'A'+10;return 255;}
bool put(a64::GuestMemory&memory,a64::Address address,std::uint64_t value,unsigned length){std::array<std::uint8_t,8> bytes{};for(unsigned i=0;i<length;++i)bytes[i]=static_cast<std::uint8_t>(value>>(8*i));return memory.write(address,std::span{bytes}.first(length));}
}
a64::Fault convert_integer(a64::GuestMemory&memory,a64::Address error,unsigned kind,std::array<std::uint64_t,31>&r){
    const auto source=r[0],end=kind<2?r[1]:0;
    auto base=kind<2?static_cast<std::int32_t>(r[2]):10;
    if(end && !memory.accessible(end,8,a64::Permission::write))return a64::Fault::write;
    if(base<0 || base==1 || base>36){if(end && !put(memory,end,source,8))return a64::Fault::write;if(!put(memory,error,22,4))return a64::Fault::write;r[0]=0;return a64::Fault::none;}
    try {
        const auto read=[&](std::uint64_t offset){
            if(offset>=1024*1024)throw InputFault{a64::Fault::unsupported_service};
            std::array<std::uint8_t,1> byte{};
            if(source>=a64::GuestMemory::address_limit || offset>=a64::GuestMemory::address_limit-source || !memory.read(source+offset,byte))throw InputFault{a64::Fault::read};
            return static_cast<unsigned>(byte[0]);
        };
        std::uint64_t position=0;auto c=read(position);
        while(space(c))c=read(++position);
        const bool negative=c=='-';if(negative || c=='+')c=read(++position);
        if(c=='0' && (base==0 || base==16 || base==2)){
            const auto next=read(position+1);
            if((base==0 || base==16) && (next=='x' || next=='X')){const auto following=read(position+2);if(digit(following)<16){position+=2;c=following;base=16;}}
            else if((base==0 || base==2) && (next=='b' || next=='B')){const auto following=read(position+2);if(following>='0' && following<='9'){position+=2;c=following;base=2;}}
        }
        if(base==0)base=c=='0'?8:10;
        const bool signed_value=kind!=0;
        const auto maximum=signed_value?(negative?(std::uint64_t{1}<<63):(std::uint64_t{1}<<63)-1):std::numeric_limits<std::uint64_t>::max();
        std::uint64_t value=0;bool any=false,overflow=false;
        for(;;){const auto number=digit(c);if(number>=static_cast<unsigned>(base))break;any=true;
            if(!overflow){if(value>maximum/static_cast<unsigned>(base) || (value==maximum/static_cast<unsigned>(base) && number>maximum%static_cast<unsigned>(base)))overflow=true;else value=value*static_cast<unsigned>(base)+number;}
            c=read(++position);
        }
        if(end && !put(memory,end,any?source+position:source,8))return a64::Fault::write;
        if(overflow){value=maximum;if(!put(memory,error,34,4))return a64::Fault::write;}
        if(negative && (!overflow || signed_value))value=0-value;
        r[0]=kind==2?static_cast<std::uint32_t>(value):value;
        return a64::Fault::none;
    }catch(const InputFault&fault){return fault.fault;}
}
}
