#include "jumps.hpp"
#include "threads.hpp"
#include "signals.hpp"
#include <array>
namespace aether::bionic {
namespace {
using a64::Fault;
constexpr std::uint64_t magic=0x414554484a4d5031ULL;
using Image=std::array<std::uint8_t,256>;
void put(Image &image,unsigned index,std::uint64_t value){for(unsigned i=0;i<8;++i)image[index*8+i]=static_cast<std::uint8_t>(value>>(8*i));}
std::uint64_t get(const Image &image,unsigned index){std::uint64_t value=0;for(unsigned i=0;i<8;++i)value|=std::uint64_t{image[index*8+i]}<<(8*i);return value;}
std::uint64_t checksum(const Image &image){std::uint64_t value=14695981039346656037ULL;for(unsigned i=0;i<248;++i){value^=image[i];value*=1099511628211ULL;}return value;}
}
Fault NativeJumps::invoke(unsigned operation,a64::ServiceState &state,bool full_frame) {
    if(!full_frame || !state.invocation || !state.stack_top)return Fault::unsupported_service;
    const auto address=state.registers[0];if(address%8)return Fault::invalid_call;
    if(operation<3){
        const auto flag=operation==1?1U:operation==2?0U:static_cast<std::uint32_t>(state.registers[1]);
        if(flag>1)return Fault::invalid_call;
        if(state.stack_pointer<16 || state.stack_pointer%16 || state.stack_pointer>state.stack_top)return Fault::invalid_call;
        if(!memory_.accessible(state.stack_pointer-16,16,a64::Permission::write))return Fault::write;
        const auto lr=state.registers[30];if(lr%4 || !memory_.accessible(lr,4,a64::Permission::execute))return Fault::execute;
        Image image{};put(image,0,magic);put(image,1,state.invocation);put(image,2,threads_.tid());put(image,3,threads_.tls());
        put(image,4,flag);put(image,5,flag?threads_.signal_mask():0);put(image,6,state.stack_pointer);put(image,7,state.registers[18]&0x3fff);
        for(unsigned i=0;i<12;++i)put(image,8+i,state.registers[19+i]);
        for(unsigned i=0;i<8;++i)put(image,20+i,state.vectors[8+i][0]);
        put(image,28,state.stack_top);put(image,31,checksum(image));
        if(!memory_.write(address,image))return Fault::write;
        state.registers[0]=0;return Fault::none;
    }
    if(operation!=3)return Fault::unsupported_service;
    Image image{};if(!memory_.read(address,image))return Fault::read;
    if(get(image,0)!=magic || get(image,31)!=checksum(image) || get(image,1)!=state.invocation ||
       get(image,2)!=threads_.tid() || get(image,3)!=threads_.tls() || get(image,28)!=state.stack_top ||
       get(image,4)>1 || get(image,7)>0x3fff || get(image,29) || get(image,30))return Fault::invalid_call;
    const auto stack=get(image,6),lr=get(image,19);
    if(stack<16 || stack%16 || stack<state.stack_pointer || stack>state.stack_top)return Fault::invalid_call;
    if(!memory_.accessible(stack-16,16,a64::Permission::write))return Fault::write;
    if(lr%4 || !memory_.accessible(lr,4,a64::Permission::execute))return Fault::execute;
    auto value=static_cast<std::uint32_t>(state.registers[1]);if(!value)value=1;
    if(get(image,4)){
        // Match Bionic's SIG_SETMASK policy before restoring registers. Any
        // newly unblocked handler runs on the current stack, not the target one.
        std::array<std::uint64_t,31> args{};args[0]=2;args[1]=address+40;
        if(threads_.change_signal_mask(args))return Fault::invalid_call;
        const auto fault=signals_.deliver_pending(state,true);if(fault!=Fault::none)return fault;
    }
    for(unsigned i=0;i<12;++i)state.registers[19+i]=get(image,8+i);
    for(unsigned i=0;i<8;++i)state.vectors[8+i][0]=get(image,20+i);
    state.registers[18]=(state.registers[18]&~std::uint64_t{0x3fff})|get(image,7);
    state.stack_pointer=stack;state.registers[0]=value;
    // The authenticated service trampoline's RET uses restored x30 to reach
    // the original call site. It does not return to the longjmp caller.
    return Fault::none;
}
}
