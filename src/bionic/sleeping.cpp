#include "sleeping.hpp"
#include "threads.hpp"
#include "signals.hpp"
#include <chrono>
#include <algorithm>
#include <thread>
namespace aether::bionic {
namespace {
std::uint64_t word(std::span<const std::uint8_t> input){std::uint64_t result=0;for(unsigned i=0;i<input.size();++i)result|=std::uint64_t{input[i]}<<(8*i);return result;}
}
void NativeSleepDuration::consume(std::uint64_t elapsed_seconds,std::uint32_t elapsed_nanos) noexcept {
    if(elapsed_seconds>seconds || (elapsed_seconds==seconds && elapsed_nanos>=nanos)){seconds=0;nanos=0;return;}
    seconds-=elapsed_seconds;
    if(elapsed_nanos>nanos){--seconds;nanos=1000000000U+nanos-elapsed_nanos;}
    else nanos-=elapsed_nanos;
}
a64::Fault NativeSleeping::invoke(unsigned operation,a64::Address error,std::array<std::uint64_t,31> &r,bool full_frame,a64::ServiceState *frame) {
    using a64::Fault;using Clock=std::chrono::steady_clock;
    const auto fail=[&](unsigned code){std::array<std::uint8_t,4> output{};for(unsigned i=0;i<4;++i)output[i]=static_cast<std::uint8_t>(code>>(8*i));if(!memory_.write(error,output))return Fault::write;r[0]=UINT64_MAX;return Fault::none;};
    const auto remainder=r[1];
    NativeSleepDuration remaining;auto &[seconds,nanos]=remaining;
    if(operation==0)seconds=static_cast<std::uint32_t>(r[0]);
    else if(operation==1){const auto micros=static_cast<std::uint32_t>(r[0]);seconds=micros/1000000;nanos=(micros%1000000)*1000;}
    else if(operation==2){
        std::array<std::uint8_t,16> input{};if(!memory_.read(r[0],input))return fail(14);
        seconds=word(std::span{input}.first<8>());const auto part=word(std::span{input}.subspan<8,8>());
        if(seconds>INT64_MAX || part>=1000000000)return fail(22);
        nanos=static_cast<std::uint32_t>(part);
        // The optional remainder is unused on successful nanosleep.
    }else return Fault::unsupported_service;
    std::uint64_t budget=1000000;
    while(seconds || nanos){
        // Chunking preserves the entire LP64 timespec without overflowing the
        // host nanosecond duration/deadline for very large valid seconds.
        const auto chunk=seconds>86400?std::uint64_t{86400}:seconds;
        const bool last=chunk==seconds;
        const auto duration=std::chrono::seconds(chunk)+std::chrono::nanoseconds(last?nanos:0);
        const auto start=Clock::now();
        if(duration>Clock::time_point::max()-start)return Fault::unsupported_service;
        const auto deadline=start+duration;
        bool interrupted=false;
        auto interruption=start;
        while(Clock::now()<deadline){
            if(signals_.ready()){
                interruption=Clock::now();
                a64::ServiceState empty;
                const auto deliveries=signals_.delivery_serial();
                const auto fault=signals_.deliver_pending(frame?*frame:empty,frame!=nullptr);
                if(fault!=Fault::none)return fault;
                if(signals_.delivery_serial()!=deliveries){interrupted=true;break;}
            }
            if(full_frame && threads_.has_runnable()){
                if(!budget)return Fault::budget;
                std::uint64_t spent=0;const auto fault=threads_.run_next(budget,spent);budget=spent>=budget?0:budget-spent;
                if(fault!=Fault::none)return fault;
            }else {
                const auto alarm=signals_.alarm_deadline();
                std::this_thread::sleep_until(alarm?std::min(deadline,*alarm):deadline);
            }
        }
        const auto elapsed=(interrupted?interruption:Clock::now())-start;
        const auto elapsed_seconds=std::chrono::duration_cast<std::chrono::seconds>(elapsed);
        remaining.consume(static_cast<std::uint64_t>(elapsed_seconds.count()),static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed-elapsed_seconds).count()));
        if(interrupted){
            if(operation==0){const auto fault=fail(4);if(fault==Fault::none)r[0]=seconds;return fault;}
            if(operation==2 && remainder){
                std::array<std::uint8_t,16> output{};
                for(unsigned i=0;i<8;++i){output[i]=static_cast<std::uint8_t>(seconds>>(8*i));output[8+i]=static_cast<std::uint8_t>(std::uint64_t{nanos}>>(8*i));}
                if(!memory_.write(remainder,output))return fail(14);
            }
            return fail(4);
        }
    }
    r[0]=0;return Fault::none;
}
}
