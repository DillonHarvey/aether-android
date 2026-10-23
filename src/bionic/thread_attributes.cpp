#include "thread_attributes.hpp"
#include "threads.hpp"
#include <array>
namespace aether::bionic {
namespace {
using Bytes=std::array<std::uint8_t,56>;
std::uint64_t field(const Bytes &b,unsigned offset,unsigned width=8){std::uint64_t v=0;for(unsigned i=0;i<width;++i)v|=std::uint64_t{b[offset+i]}<<(8*i);return v;}
void put(Bytes &b,unsigned offset,std::uint64_t value,unsigned width=8){for(unsigned i=0;i<width;++i)b[offset+i]=static_cast<std::uint8_t>(value>>(8*i));}
Bytes encode(const NativeThreadOptions &o,a64::Address base=0){Bytes b{};put(b,0,o.detached?1:0,4);put(b,8,base);put(b,16,o.stack_size);put(b,24,o.guard_size);return b;}
}
unsigned NativeThreadAttributes::read(a64::Address address,NativeThreadOptions &o) const noexcept {
    Bytes b{};if(!memory_.read(address,b))return 14;
    if(field(b,0,4)&~1U || field(b,32,4) || field(b,36,4))return 95;
    if(field(b,8))return 95; // Caller-owned stacks are not silently replaced.
    if(field(b,16)<NativeThreadOptions::minimum_stack_size)return 22;
    o={field(b,16),field(b,24),(field(b,0,4)&1)!=0};return 0;
}
a64::Fault NativeThreadAttributes::invoke(ThreadAttributeOperation op,std::array<std::uint64_t,31> &r,const a64::ServiceState *frame) noexcept {
    using a64::Fault;
    const auto result=[&](unsigned code){r[0]=code;return Fault::none;};
    const auto write=[&](a64::Address address,std::uint64_t value,unsigned width){Bytes b{};put(b,0,value,width);return memory_.write(address,std::span{b}.first(width));};
    if(op==ThreadAttributeOperation::detach)return threads_.detach(r);
    if(op==ThreadAttributeOperation::initialize || op==ThreadAttributeOperation::destroy){
        auto b=encode({});if(op==ThreadAttributeOperation::destroy)b.fill(0x42);
        if(!memory_.write(r[0],b))return Fault::write;return result(0);
    }
    if(op==ThreadAttributeOperation::get_current){
        NativeThreadOptions options;a64::Address base=0;auto error=threads_.query(r[0],options,base);
        if(error==95 && r[0]==threads_.tid() && frame && frame->stack_top){
            const auto region=memory_.mapping(frame->stack_top-1);
            if(region && a64::has(region->permissions,a64::Permission::write) &&
               frame->stack_pointer>=region->address && frame->stack_pointer<=region->address+region->size){
                base=region->address;options={region->size,0,false};error=0;
            }
        }
        if(error)return result(error);
        if(!memory_.write(r[1],encode(options,base)))return Fault::write;return result(0);
    }
    Bytes b{};if(!memory_.read(r[0],b))return Fault::read;
    switch(op){
    case ThreadAttributeOperation::set_detach:
        if(static_cast<std::uint32_t>(r[1])>1)return result(22);
        put(b,0,(field(b,0,4)&~1U)|static_cast<std::uint32_t>(r[1]),4);break;
    case ThreadAttributeOperation::set_stack_size:
        if(r[1]<NativeThreadOptions::minimum_stack_size)return result(22);put(b,16,r[1]);break;
    case ThreadAttributeOperation::set_guard:put(b,24,r[1]);break;
    case ThreadAttributeOperation::get_detach:
        if(!write(r[1],field(b,0,4)&1U,4))return Fault::write;return result(0);
    case ThreadAttributeOperation::get_stack_size:case ThreadAttributeOperation::get_guard:
        if(!write(r[1],field(b,op==ThreadAttributeOperation::get_stack_size?16:24),8))return Fault::write;return result(0);
    case ThreadAttributeOperation::get_stack:
        if(!memory_.accessible(r[1],8,a64::Permission::write) || !memory_.accessible(r[2],8,a64::Permission::write))return Fault::write;
        if(!write(r[1],field(b,8),8) || !write(r[2],field(b,16),8))return Fault::write;return result(0);
    default:return Fault::unsupported_service;
    }
    if(!memory_.write(r[0],b))return Fault::write;return result(0);
}
}
