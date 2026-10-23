#include "multibyte.hpp"
#include "threads.hpp"
#include <algorithm>
#include <limits>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
constexpr std::uint64_t maximum_work=1U<<20,illegal=UINT64_MAX,incomplete=UINT64_MAX-1;
constexpr std::uint32_t eof=UINT32_MAX;
struct AccessFailure {Fault fault;};
struct Unsupported {std::string_view reason;};

template<std::size_t N> std::array<std::uint8_t,N> little(std::uint64_t value){
    std::array<std::uint8_t,N> bytes{};
    for(unsigned i=0;i<N;++i)bytes[i]=static_cast<std::uint8_t>(value>>(i*8));
    return bytes;
}
template<std::size_t N> std::uint64_t number(const std::array<std::uint8_t,N> &bytes){
    std::uint64_t value=0;
    for(unsigned i=0;i<N;++i)value|=std::uint64_t{bytes[i]}<<(i*8);
    return value;
}
Address advance(Address base,std::uint64_t count,Fault fault){
    if(count>std::numeric_limits<Address>::max()-base)throw AccessFailure{fault};
    return base+count;
}
void bounded(std::uint64_t offset,std::size_t size){
    if(offset>maximum_work || size>maximum_work-offset)
        throw Unsupported{"multibyte: conversion exceeds 1 MiB consumed input or output profile"};
}

class State {
  public:
    State(a64::GuestMemory &memory,Address guest,std::array<std::uint8_t,4> &owned)
        :memory_(memory),guest_(guest),owned_(owned){}
    std::uint8_t byte(unsigned index) const {
        if(!guest_)return owned_[index];
        std::array<std::uint8_t,1> bytes{};
        if(!memory_.read(advance(guest_,index,Fault::read),bytes))throw AccessFailure{Fault::read};
        return bytes[0];
    }
    bool initial() const {
        if(!guest_)return number(owned_)==0;
        std::array<std::uint8_t,4> bytes{};
        if(!memory_.read(guest_,bytes))throw AccessFailure{Fault::read};
        return number(bytes)==0;
    }
    unsigned used() const {
        if(byte(2))return 3;
        if(byte(1))return 2;
        return byte(0)?1:0;
    }
    void set(unsigned index,std::uint8_t value){
        if(index>=4)throw Unsupported{"multibyte: malformed supplied conversion state"};
        if(!guest_){owned_[index]=value;return;}
        const std::array<std::uint8_t,1> bytes{value};
        if(!memory_.write(advance(guest_,index,Fault::write),bytes))throw AccessFailure{Fault::write};
    }
    void reset(){
        if(!guest_){owned_.fill(0);return;}
        constexpr std::array<std::uint8_t,4> zero{};
        if(!memory_.write(guest_,zero))throw AccessFailure{Fault::write};
    }
  private:
    a64::GuestMemory &memory_;
    Address guest_;
    std::array<std::uint8_t,4> &owned_;
};

struct Encoded {std::array<std::uint8_t,4> bytes{};unsigned size=0;};
struct Decoded {std::uint64_t size;std::uint32_t point=0;};
class Conversion {
  public:
    Conversion(a64::GuestMemory &memory,Address error):memory_(memory),error_(error){}
    std::uint64_t invalid_value(unsigned error=84){
        if(!memory_.write(error_,little<4>(error)))throw AccessFailure{Fault::write};
        return illegal;
    }
    std::uint64_t invalid(State &state,unsigned error=84){
        invalid_value(error);
        state.reset();
        return illegal;
    }
    std::uint8_t source_byte(Address source,std::uint64_t offset){
        bounded(offset,1);
        std::array<std::uint8_t,1> bytes{};
        if(!memory_.read(advance(source,offset,Fault::read),bytes))throw AccessFailure{Fault::read};
        return bytes[0];
    }
    std::uint32_t source_wide(Address source,std::uint64_t offset){
        bounded(offset,4);
        std::array<std::uint8_t,4> bytes{};
        if(!memory_.read(advance(source,offset,Fault::read),bytes))throw AccessFailure{Fault::read};
        return static_cast<std::uint32_t>(number(bytes));
    }
    Address source_pointer(Address at){
        std::array<std::uint8_t,8> bytes{};
        if(!memory_.read(at,bytes))throw AccessFailure{Fault::read};
        return number(bytes);
    }
    void source_pointer(Address at,Address value){
        if(!memory_.write(at,little<8>(value)))throw AccessFailure{Fault::write};
    }
    void output(Address destination,std::uint64_t offset,std::span<const std::uint8_t> bytes){
        bounded(offset,bytes.size());
        if(!memory_.write(advance(destination,offset,Fault::write),bytes))throw AccessFailure{Fault::write};
    }
    Encoded encode(State &state,std::uint32_t point){
        // Callers handle NUL separately because it resets state even if noninitial.
        if(!state.initial()){invalid(state);return {};}
        Encoded result;
        if(point<0x80){result.bytes[0]=static_cast<std::uint8_t>(point);result.size=1;return result;}
        unsigned lead=0;
        if(point<=0x7ff){result.size=2;lead=0xc0;}
        else if(point<=0xffff){result.size=3;lead=0xe0;}
        else if(point<=0x1fffff){result.size=4;lead=0xf0;}
        else {invalid_value();return {};}
        // Bionic's encoder intentionally permits surrogate and >U+10FFFF values.
        for(unsigned i=result.size-1;i>0;--i){result.bytes[i]=static_cast<std::uint8_t>(0x80|(point&0x3f));point>>=6;}
        result.bytes[0]=static_cast<std::uint8_t>(lead|point);
        return result;
    }
    Decoded decode(State &state,Address source,std::uint64_t offset,std::uint64_t count,
                   Address destination=0,std::uint64_t output_offset=0,bool synthetic=false,
                   std::uint8_t synthetic_byte=0){
        // Unlike the reserved LP64 bytes, seq[3] is part of Bionic's validation.
        if(state.byte(3))return {invalid(state,22)};
        if(!count)return {incomplete};
        const auto input=[&](std::uint64_t at){return synthetic?synthetic_byte:source_byte(source,advance(offset,at,Fault::read));};
        if(state.initial()){
            const auto first=input(0);
            if(first<0x80){
                if(destination)output(destination,output_offset,little<4>(first));
                return {first?1U:0U,first};
            }
        }
        const auto used=state.used();
        const auto first=used?state.byte(0):input(0);
        unsigned length=0,mask=0;
        std::uint32_t minimum=0;
        if((first&0xe0)==0xc0){length=2;mask=0x1f;minimum=0x80;}
        else if((first&0xf0)==0xe0){length=3;mask=0x0f;minimum=0x800;}
        else if((first&0xf8)==0xf0){length=4;mask=7;minimum=0x10000;}
        else return {invalid(state)};
        // Such states cannot arise from this decoder. Reject instead of copying
        // Bionic's unsigned underflow or decoding a guest-forged complete prefix.
        if(used>=length)throw Unsupported{"multibyte: supplied state contains a complete or overfull sequence"};
        for(unsigned i=1;i<used;++i)if((state.byte(i)&0xc0)!=0x80)
            throw Unsupported{"multibyte: supplied state contains a sparse or invalid prefix"};
        const auto wanted=length-used;
        const auto taken=static_cast<unsigned>(std::min<std::uint64_t>(wanted,count));
        for(unsigned i=0;i<taken;++i){
            const auto byte=input(i);
            if(!state.initial() && (byte&0xc0)!=0x80)return {invalid(state)};
            state.set(used+i,byte);
        }
        if(taken<wanted)return {incomplete};
        std::uint32_t point=state.byte(0)&mask;
        for(unsigned i=1;i<length;++i)point=(point<<6)|(state.byte(i)&0x3f);
        if(point<minimum || (point>=0xd800 && point<=0xdfff) || point>0x10ffff)return {invalid(state)};
        if(destination)output(destination,output_offset,little<4>(point));
        state.reset();
        return {point?wanted:0U,point};
    }
    std::uint64_t wcrtomb(State &state,Address destination,std::uint32_t point){
        if(!destination){state.reset();return 1;}
        if(!point){output(destination,0,little<1>(0));state.reset();return 1;}
        const auto result=encode(state,point);
        if(!result.size)return illegal;
        output(destination,0,std::span{result.bytes}.first(result.size));
        return result.size;
    }
    std::uint64_t wcs(State &state,Address destination,Address source_slot,std::uint64_t count,std::uint64_t capacity){
        if(!state.initial())return invalid(state);
        Address source=0;
        bool loaded=false;
        const auto input=[&](){if(!loaded){source=source_pointer(source_slot);loaded=true;}return source;};
        std::uint64_t consumed=0,produced=0;
        while(consumed<count && (!destination || produced<capacity)){
            const auto point=source_wide(input(),consumed*4);
            if(point<0x80){
                if(destination)output(destination,produced,little<1>(point));
                if(!point){if(destination)source_pointer(source_slot,0);return produced;}
                ++produced;
            }else{
                const auto result=encode(state,point);
                if(!result.size){if(destination)source_pointer(source_slot,advance(input(),consumed*4,Fault::read));return illegal;}
                if(destination && result.size>capacity-produced)break;
                if(destination)output(destination,produced,std::span{result.bytes}.first(result.size));
                produced+=result.size;
            }
            ++consumed;
        }
        if(destination)source_pointer(source_slot,advance(input(),consumed*4,Fault::read));
        return produced;
    }
    std::uint64_t mbs(State &state,Address destination,Address source_slot,std::uint64_t count,std::uint64_t capacity){
        Address source=0;
        bool loaded=false;
        const auto input=[&](){if(!loaded){source=source_pointer(source_slot);loaded=true;}return source;};
        if(count && state.used() && source_byte(input(),0)<0x80)return invalid(state);
        std::uint64_t consumed=0,produced=0;
        while(consumed<count && (!destination || produced<capacity)){
            const auto first=source_byte(input(),consumed);
            std::uint64_t size=1;
            if(first<0x80){
                if(destination)output(destination,produced*4,little<4>(first));
                if(!first){if(destination)source_pointer(source_slot,0);state.reset();return produced;}
            }else{
                const auto result=decode(state,input(),consumed,count-consumed,destination,produced*4);
                size=result.size;
                if(size==illegal){if(destination)source_pointer(source_slot,advance(input(),consumed,Fault::read));return invalid(state);}
                if(size==incomplete){if(destination)source_pointer(source_slot,advance(input(),count,Fault::read));return invalid(state);}
                if(!size){if(destination)source_pointer(source_slot,0);state.reset();return produced;}
            }
            consumed+=size;
            ++produced;
        }
        if(destination)source_pointer(source_slot,advance(input(),consumed,Fault::read));
        state.reset();
        return produced;
    }
  private:
    a64::GuestMemory &memory_;
    Address error_;
};
}

a64::Fault NativeMultibyte::invoke(MultibyteOperation operation,std::array<std::uint64_t,31> &registers) noexcept {
    try {
        Conversion conversion(memory_,threads_.error_address());
        std::uint64_t result=0;
        switch(operation){
        case MultibyteOperation::wcsnrtombs:{
            State state(memory_,registers[4],private_states_[0]);
            result=conversion.wcs(state,registers[0],registers[1],registers[2],registers[3]);break;
        }
        case MultibyteOperation::wcsrtombs:{
            State state(memory_,registers[3],private_states_[0]);
            result=conversion.wcs(state,registers[0],registers[1],UINT64_MAX,registers[2]);break;
        }
        case MultibyteOperation::wcrtomb:{
            State state(memory_,registers[2],private_states_[1]);
            result=conversion.wcrtomb(state,registers[0],static_cast<std::uint32_t>(registers[1]));break;
        }
        case MultibyteOperation::btowc:{
            const auto byte=static_cast<std::uint32_t>(registers[0]);
            if(byte==eof){result=eof;break;}
            std::array<std::uint8_t,4> local{};State state(memory_,0,local);
            const auto decoded=conversion.decode(state,0,0,1,0,0,true,static_cast<std::uint8_t>(byte));
            result=decoded.size>1?eof:decoded.point;break;
        }
        case MultibyteOperation::wctob:{
            const auto point=static_cast<std::uint32_t>(registers[0]);
            if(point==eof){result=eof;break;}
            std::array<std::uint8_t,4> local{};State state(memory_,0,local);
            const auto encoded=conversion.encode(state,point);
            result=encoded.size==1?encoded.bytes[0]:eof;break;
        }
        case MultibyteOperation::mbrtowc:{
            State state(memory_,registers[3],private_states_[2]);
            result=conversion.decode(state,registers[1],0,registers[1]?registers[2]:1,registers[1]?registers[0]:0,0,!registers[1]).size;break;
        }
        case MultibyteOperation::mbrlen:{
            State state(memory_,registers[2],private_states_[3]);
            result=conversion.decode(state,registers[0],0,registers[0]?registers[1]:1,0,0,!registers[0]).size;break;
        }
        case MultibyteOperation::mbsnrtowcs:{
            State state(memory_,registers[4],private_states_[4]);
            result=conversion.mbs(state,registers[0],registers[1],registers[2],registers[3]);break;
        }
        case MultibyteOperation::mbsrtowcs:{
            State state(memory_,registers[3],private_states_[4]);
            result=conversion.mbs(state,registers[0],registers[1],UINT64_MAX,registers[2]);break;
        }
        case MultibyteOperation::mbsinit:{
            if(!registers[0]){result=1;break;}
            std::array<std::uint8_t,4> local{};State state(memory_,registers[0],local);
            result=state.initial()?1:0;break;
        }
        default:throw Unsupported{"multibyte: unknown operation"};
        }
        registers[0]=result;
        rejection_={};
        return Fault::none;
    }catch(const AccessFailure &failure){
        rejection_=failure.fault==Fault::write?"multibyte: guest destination, source pointer, errno or sequence state is not writable":"multibyte: guest input, source pointer or sequence state is not readable";
        return failure.fault;
    }catch(const Unsupported &failure){rejection_=failure.reason;return Fault::unsupported_service;}
    catch(...){rejection_="multibyte: conversion marshalling raised an exception";return Fault::windows_service;}
}
}
