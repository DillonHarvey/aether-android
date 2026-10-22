#include "rwlocks.hpp"
#include <array>
#include <utility>
namespace aether::bionic {
namespace {
using a64::Address;using a64::Fault;
template<std::size_t N> std::uint64_t get(const std::array<std::uint8_t,N>&b,std::size_t at=0,unsigned size=8){std::uint64_t n=0;for(unsigned i=0;i<size;++i)n|=std::uint64_t{b[at+i]}<<(8*i);return n;}
template<std::size_t N> void put(std::array<std::uint8_t,N>&b,std::uint64_t n,std::size_t at=0,unsigned size=8){for(unsigned i=0;i<size;++i)b[at+i]=static_cast<std::uint8_t>(n>>(8*i));}
}
Fault NativeRwLocks::call(unsigned operation,std::uint32_t tid,std::array<std::uint64_t,31>&r){
    const Address address=r[0];const auto done=[&](unsigned code){r[0]=code;return Fault::none;};const auto reject=[&](std::string_view text){rejection_=text;return Fault::unsupported_service;};
    if(operation>=7){
        if(address%8)return reject("pthread rwlock attribute is not LP64 aligned");std::array<std::uint8_t,8> bytes{};
        if(operation!=7 && !memory_.read(address,bytes))return Fault::read;auto value=get(bytes);const auto input=static_cast<std::uint32_t>(r[1]);
        if(operation==10 || operation==12){std::array<std::uint8_t,4> out{};put(out,operation==10?(value&1):((value>>1)&1),0,4);if(!memory_.write(r[1],out))return Fault::write;return done(0);}
        if(!memory_.accessible(address,8,a64::Permission::write))return Fault::write;
        if(operation==7)value=0;else if(operation==8)value=~std::uint64_t{0};
        else if(operation==9){if(input>1)return done(22);value=(value&~std::uint64_t{1})|input;}
        else if(operation==11){if(input>1)return done(22);value=(value&~std::uint64_t{2})|(std::uint64_t{input}<<1);}
        else return reject("Unknown pthread rwlock attribute operation");put(bytes,value);if(!memory_.write(address,bytes))return Fault::write;return done(0);
    }
    if(address%4)return reject("pthread rwlock is not four-byte aligned");std::array<std::uint8_t,56> bytes{};
    if(operation!=5 && !memory_.read(address,bytes))return Fault::read;if(!memory_.accessible(address,bytes.size(),a64::Permission::write))return Fault::write;auto found=held_.find(address);
    if(operation==5){if(found!=held_.end())return done(16);std::uint64_t attr=0;if(r[1]){if(r[1]%8)return reject("pthread rwlock attribute is not LP64 aligned");std::array<std::uint8_t,8> value{};if(!memory_.read(r[1],value))return Fault::read;attr=get(value);}if(attr&~std::uint64_t{3})return done(22);if(attr&1)return reject("pthread process-shared rwlocks are unsupported");bytes[9]=static_cast<std::uint8_t>((attr>>1)&1);if(!memory_.write(address,bytes))return Fault::write;return done(0);}
    if(bytes[8] || bytes[9]>1)return reject("pthread rwlock shared or invalid preference state is unsupported");
    for(unsigned at=12;at<36;at+=4)if(get(bytes,at,4))return reject("pthread rwlock pending waiter state requires resumable native execution");
    const auto state=static_cast<std::uint32_t>(get(bytes,0,4)),writer=static_cast<std::uint32_t>(get(bytes,4,4));
    if(found!=held_.end()){const auto &held=found->second;const auto expected=held.writer?0x80000000U:held.total<<2;if(state!=expected || writer!=held.writer || bytes[9]!=static_cast<unsigned>(held.preference))return reject("pthread rwlock storage changed while owned");}
    else if(state || writer)return reject("pthread rwlock locked state has no runtime owner");
    if(operation==6){if(found!=held_.end())return done(16);return done(0);}
    Held updated;if(found!=held_.end())updated=found->second;else updated.preference=bytes[9]!=0;
    if(operation==4){
        if(updated.writer){if(updated.writer!=tid)return done(1);updated.writer=0;}
        else {const auto owner=updated.readers.find(tid);if(owner==updated.readers.end()){if(!updated.total)return done(1);return reject("pthread rwlock read unlock without ownership is undefined and unsupported");}if(!--owner->second)updated.readers.erase(owner);--updated.total;}
    }else{
        const bool read=operation==0||operation==2,try_lock=operation==2||operation==3;
        if(updated.writer || (!read && updated.total)){if(try_lock)return done(16);if(updated.writer==tid)return done(35);return reject("pthread rwlock contention requires resumable native execution");}
        if(read){if(updated.total==0x1fffffffU)return done(11);if(!updated.readers.contains(tid) && updated.readers.size()==64)return reject("pthread rwlock reader-owner limit reached");++updated.readers[tid];++updated.total;}
        else updated.writer=tid;
    }
    put(bytes,updated.writer?0x80000000U:updated.total<<2,0,4);put(bytes,updated.writer,4,4);
    if(!updated.writer && !updated.total){if(!memory_.write(address,bytes))return Fault::write;if(found!=held_.end())held_.erase(found);return done(0);}
    if(found!=held_.end()){if(!memory_.write(address,bytes))return Fault::write;found->second=std::move(updated);}
    else {if(held_.size()==1024)return reject("pthread held rwlock limit reached");held_.emplace(address,std::move(updated));if(!memory_.write(address,bytes)){held_.erase(address);return Fault::write;}}
    return done(0);
}
a64::Fault NativeRwLocks::invoke(unsigned operation,std::uint32_t tid,std::array<std::uint64_t,31>&r)noexcept{try{return call(operation,tid,r);}catch(...){rejection_="pthread rwlock host state allocation failed";return a64::Fault::unsupported_service;}}
}
