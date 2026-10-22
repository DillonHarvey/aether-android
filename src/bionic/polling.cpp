#include "polling.hpp"
#include "descriptors.hpp"
#include "threads.hpp"
#include <chrono>
#include <thread>
namespace aether::bionic {
namespace {
template<std::size_t N> std::array<std::uint8_t,N> bytes(std::uint64_t value){std::array<std::uint8_t,N> result{};for(unsigned i=0;i<N;++i)result[i]=static_cast<std::uint8_t>(value>>(8*i));return result;}
std::uint64_t word(std::span<const std::uint8_t> input){std::uint64_t result=0;for(unsigned i=0;i<input.size();++i)result|=std::uint64_t{input[i]}<<(8*i);return result;}
}
a64::Fault NativePolling::invoke(a64::Address error,std::array<std::uint64_t,31> &r,bool full_frame) {
    using a64::Fault;using Clock=std::chrono::steady_clock;
    const auto fail=[&](unsigned code){if(!memory_.write(error,bytes<4>(code)))return Fault::write;r[0]=UINT64_MAX;return Fault::none;};
    const auto address=r[0];const auto count=static_cast<std::uint32_t>(r[1]);const auto timeout=static_cast<std::int32_t>(r[2]);
    if(count>256)return fail(22);
    struct Watch {std::int32_t fd=0;std::uint16_t events=0,revents=0;};
    std::array<Watch,256> watches{};
    for(std::size_t i=0;i<count;++i){
        std::array<std::uint8_t,8> input{};
        if(address>=a64::GuestMemory::address_limit || i*8>=a64::GuestMemory::address_limit-address ||
           !memory_.read(address+i*8,input) || !memory_.accessible(address+i*8+6,2,a64::Permission::write))return fail(14);
        watches[i].fd=static_cast<std::int32_t>(word(std::span{input}.first<4>()));
        watches[i].events=static_cast<std::uint16_t>(word(std::span{input}.subspan<4,2>()));
    }
    const auto deadline=Clock::now()+std::chrono::milliseconds(timeout>0?timeout:0);
    std::uint64_t budget=1000000;
    for(;;){
        unsigned ready=0;
        for(std::size_t i=0;i<count;++i){auto &watch=watches[i];watch.revents=files_.readiness(watch.fd,watch.events);if(watch.revents)++ready;}
        if(ready || timeout==0 || (timeout>0 && Clock::now()>=deadline)){
            // Nested work can free the original table. Validate all outputs before publishing any.
            for(std::size_t i=0;i<count;++i)if(!memory_.accessible(address+i*8+6,2,a64::Permission::write))return fail(14);
            for(std::size_t i=0;i<count;++i)if(!memory_.write(address+i*8+6,bytes<2>(watches[i].revents)))return fail(14);
            r[0]=ready;return Fault::none;
        }
        if(!full_frame)return fail(95);
        if(threads_.has_runnable()){
            if(!budget)return Fault::budget;
            std::uint64_t spent=0;const auto fault=threads_.run_next(budget,spent);budget=spent>=budget?0:budget-spent;
            if(fault!=Fault::none)return fault;
            continue;
        }
        if(timeout<0)return fail(95); // No continuation or external producer exists in this profile.
        // All current descriptor kinds change readiness only via owned queued work;
        // a finite idle timeout is a genuine monotonic Windows-hosted wait.
        std::this_thread::sleep_until(deadline);
    }
}
}
