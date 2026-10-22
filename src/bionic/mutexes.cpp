#include "mutexes.hpp"
#include <array>
namespace aether::bionic {
namespace {
using a64::Fault;using a64::Address;
template<std::size_t N> std::uint64_t get(const std::array<std::uint8_t,N> &b,std::size_t at=0,unsigned size=8){std::uint64_t n=0;for(unsigned i=0;i<size;++i)n|=std::uint64_t{b[at+i]}<<(8*i);return n;}
template<std::size_t N> void put(std::array<std::uint8_t,N> &b,std::uint64_t n,std::size_t at=0,unsigned size=8){for(unsigned i=0;i<size;++i)b[at+i]=static_cast<std::uint8_t>(n>>(8*i));}
}
Fault NativeMutexes::call(unsigned operation,std::uint32_t tid,std::array<std::uint64_t,31> &r){
    const Address address=r[0];const auto result=[&](unsigned code){r[0]=code;return Fault::none;};
    const auto reject=[&](std::string_view text){rejection_=text;return Fault::unsupported_service;};
    if(operation>=5){
        if(address%8)return reject("pthread mutex attribute is not LP64 aligned");
        std::array<std::uint8_t,8> attr{};
        if(operation!=5 && !memory_.read(address,attr))return Fault::read;
        auto value=get(attr);const auto input=static_cast<std::uint32_t>(r[1]);
        if(operation==8 || operation==10 || operation==12){unsigned out=0;if(operation==8){out=static_cast<unsigned>(value&15);if(out>2)return result(22);}else if(operation==10)out=(value&16)?1:0;else out=(value&32)?1:0;
            std::array<std::uint8_t,4> bytes{};put(bytes,out,0,4);if(!memory_.write(r[1],bytes))return Fault::write;return result(0);}
        if(!memory_.accessible(address,8,a64::Permission::write))return Fault::write;
        if(operation==5)value=0;
        else if(operation==6)value=~std::uint64_t{0};
        else if(operation==7){if(input>2)return result(22);value=(value&~std::uint64_t{15})|input;}
        else if(operation==9){if(input>1)return result(22);value=(value&~std::uint64_t{16})|(std::uint64_t{input}<<4);}
        else if(operation==11){if(input>1)return result(22);value=(value&~std::uint64_t{32})|(std::uint64_t{input}<<5);}
        else return reject("Unknown pthread mutex attribute operation");
        put(attr,value);if(!memory_.write(address,attr))return Fault::write;return result(0);
    }
    if(address%4)return reject("pthread mutex is not 4-byte aligned");
    std::array<std::uint8_t,40> bytes{};
    if(operation!=3 && !memory_.read(address,bytes))return Fault::read;
    if(!memory_.accessible(address,bytes.size(),a64::Permission::write))return Fault::write;
    auto found=held_.find(address);
    if(operation==3){
        if(found!=held_.end())return result(16);
        std::uint64_t attr=0;if(r[1]){if(r[1]%8)return reject("pthread mutex attribute is not LP64 aligned");std::array<std::uint8_t,8> value{};if(!memory_.read(r[1],value))return Fault::read;attr=get(value);}
        if((attr&15)>2)return result(22);
        if(attr&~std::uint64_t{15})return reject("pthread mutex process-shared, priority-inheritance or unknown attributes are unsupported");
        put(bytes,(attr&15)<<14,0,2);if(!memory_.write(address,bytes))return Fault::write;return result(0);
    }
    const auto state=static_cast<unsigned>(get(bytes,0,2)),type=state>>14;
    if(state==0xffff)return reject("pthread mutex was destroyed");
    if((state&0x2000)||type>2)return reject("pthread mutex process-shared or priority-inheritance state is unsupported");
    if(found!=held_.end()){
        const auto &held=found->second;const auto expected=(held.type<<14)|1|((held.type==1?(held.depth-1):0)<<2);
        if(state!=expected || (type && get(bytes,4,4)!=held.owner))return reject("pthread mutex storage changed while owned");
    }else if(state!=(type<<14))return reject("pthread mutex locked or invalid state has no runtime owner");
    if(operation==4){if(found!=held_.end())return result(16);put(bytes,0xffff,0,2);if(!memory_.write(address,bytes))return Fault::write;return result(0);}
    if(operation==2){
        if(found==held_.end() || found->second.owner!=tid){if(type)return result(1);return reject("pthread normal mutex unlock without ownership is undefined and unsupported");}
        auto &held=found->second;if(held.depth>1){--held.depth;put(bytes,(type<<14)|1|((held.depth-1)<<2),0,2);}
        else {put(bytes,type<<14,0,2);if(type)put(bytes,0,4,4);}
        if(!memory_.write(address,bytes))return Fault::write;if(held.depth==1 && static_cast<unsigned>(get(bytes,0,2))==(type<<14))held_.erase(found);return result(0);
    }
    if(found!=held_.end()){
        auto &held=found->second;
        if(held.owner==tid && type==1){if(held.depth==2048)return result(11);++held.depth;put(bytes,(type<<14)|1|((held.depth-1)<<2),0,2);if(!memory_.write(address,bytes))return Fault::write;return result(0);}
        if(operation==1)return result(16);
        if(held.owner==tid && type==2)return result(35);
        return reject("pthread mutex lock requires resumable native contention or deadlock handling");
    }
    if(held_.size()==1024)return reject("pthread held mutex limit reached");
    held_.emplace(address,Held{tid,1,type});put(bytes,(type<<14)|1,0,2);if(type)put(bytes,tid,4,4);
    if(!memory_.write(address,bytes)){held_.erase(address);return Fault::write;}return result(0);
}
a64::Fault NativeMutexes::validate_wait(a64::Address address, std::uint32_t tid) const {
    if (address % 4) return Fault::unsupported_service;
    std::array<std::uint8_t, 40> bytes{};
    if (!memory_.read(address, bytes)) return Fault::read;
    if (!memory_.accessible(address, bytes.size(), a64::Permission::write)) return Fault::write;
    const auto found = held_.find(address);
    if (found == held_.end() || found->second.owner != tid || found->second.depth != 1)
        return Fault::unsupported_service;
    const auto type = found->second.type;
    if (get(bytes, 0, 2) != ((type << 14) | 1) || (type && get(bytes, 4, 4) != tid))
        return Fault::unsupported_service;
    return Fault::none;
}

a64::Fault NativeMutexes::invoke(unsigned operation,std::uint32_t tid,std::array<std::uint64_t,31> &r)noexcept{try{return call(operation,tid,r);}catch(...){rejection_="pthread mutex host state allocation failed";return a64::Fault::unsupported_service;}}
}
