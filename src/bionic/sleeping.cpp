#include "sleeping.hpp"
#include "threads.hpp"
#include "signals.hpp"
#include "aether/common/thread_exit.hpp"
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
struct NativeSleeping::DeferredSleep final : a64::DeferredService {
    using Clock=std::chrono::steady_clock;
    NativeSleeping &p;unsigned operation;
    a64::Address error,remainder,tls,stack_top;std::uint32_t tid;std::uint64_t invocation;
    std::shared_ptr<a64::ThreadRegisterState> owner;
    const NativeSleepDuration request;
    NativeSleepDuration remaining;
    Clock::time_point sampled;
    std::optional<Clock::time_point> wake;
    DeferredSleep(NativeSleeping &p,unsigned operation,a64::Address error,a64::Address remainder,
                  NativeSleepDuration duration,const a64::ServiceState &frame):
        p(p),operation(operation),error(error),remainder(remainder),tls(frame.trusted_tls),stack_top(frame.stack_top),
        tid(p.threads_.tid()),invocation(frame.invocation),owner(p.threads_.thread_register_state(tls)),
        request(duration),remaining(request),sampled(Clock::now()) {arm();}
    void arm() noexcept {
        const auto chunk=std::min(remaining.seconds,std::uint64_t{86400});
        const auto duration=std::chrono::seconds(chunk)+std::chrono::nanoseconds(chunk==remaining.seconds?remaining.nanos:0);
        if(duration>Clock::time_point::max()-sampled){wake.reset();return;}
        wake=sampled+duration;
    }
    bool ready() const noexcept override {
        if(!p.app_.process_state || p.app_.process_state->exit_status() || !p.threads_.signal_snapshot(tid,owner) || !wake)return true;
        const auto now=Clock::now();
        return now<sampled || now>=*wake || p.signals_.wait_ready(tid,owner);
    }
    std::optional<Clock::time_point> deadline() const noexcept override {
        if(!p.threads_.signal_snapshot(tid,owner))return {};
        auto next=wake;const auto alarm=p.signals_.wait_deadline(tid,owner);
        if(alarm && (!next || *alarm<*next))next=alarm;
        return next;
    }
    a64::Fault fail(a64::ServiceState &frame,unsigned code) const noexcept {
        std::array<std::uint8_t,4> output{};
        for(unsigned index=0;index<4;++index)output[index]=static_cast<std::uint8_t>(code>>(8*index));
        if(!p.memory_.write(error,output))return a64::Fault::write;
        frame.registers[0]=UINT64_MAX;return a64::Fault::none;
    }
    a64::Fault interrupted(a64::ServiceState &frame) const noexcept {
        if(operation==2 && remainder){
            std::array<std::uint8_t,16> output{};
            for(unsigned index=0;index<8;++index){
                output[index]=static_cast<std::uint8_t>(remaining.seconds>>(8*index));
                output[index+8]=static_cast<std::uint8_t>(std::uint64_t{remaining.nanos}>>(8*index));
            }
            // The destination can change while parked. Publish before any
            // handler sees its ucontext; successful sleeps never touch it.
            if(!p.memory_.write(remainder,output))return fail(frame,14);
        }
        const auto fault=fail(frame,4);
        if(fault==a64::Fault::none && operation==0)frame.registers[0]=remaining.seconds;
        return fault;
    }
    a64::DeferredServiceResult resume(a64::ServiceState &frame) noexcept override {
        using a64::Fault;
        try {
            if(!p.app_.process_state)return {Fault::invalid_call,true};
            if(p.app_.process_state->exit_status())return {Fault::process_exit,true};
            if(!owner || p.threads_.tid()!=tid || p.threads_.tls()!=tls || frame.trusted_tls!=tls ||
               frame.invocation!=invocation || frame.stack_top!=stack_top || p.threads_.error_address()!=error ||
               p.threads_.thread_register_state(tls)!=owner)return {Fault::invalid_call,true};
            if(!wake)return {Fault::unsupported_service,true};
            const auto now=Clock::now();
            if(now<sampled)return {Fault::windows_service,true};
            const auto elapsed=now-sampled;
            const auto seconds=std::chrono::duration_cast<std::chrono::seconds>(elapsed);
            const auto nanos=std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed-seconds);
            remaining.consume(static_cast<std::uint64_t>(seconds.count()),static_cast<std::uint32_t>(nanos.count()));
            sampled=now;
            if(!remaining.seconds && !remaining.nanos){frame.registers[0]=0;return {Fault::none,true};}
            if(const auto signal=p.signals_.io_interruption()){
                // Selection commits an expired alarm on this actual owner and
                // skips ignored signals before staging this exact interruption.
                const auto serial=p.signals_.delivery_serial();
                const bool framed=p.signals_.io_frame_ready(*signal,frame);
                if(framed){const auto fault=interrupted(frame);if(fault!=Fault::none)return {fault,true};}
                const auto fault=p.signals_.deliver_pending(frame,true,std::uint64_t{1}<<(signal->signal-1));
                if(fault!=Fault::none)return {fault,true};
                if(frame.resume)return {Fault::none,true};
                if(p.signals_.delivery_serial()!=serial)
                    return {framed?Fault::none:Fault::unsupported_service,true};
            }
            arm();
            return {wake?Fault::none:Fault::unsupported_service,!wake};
        }catch(const ProcessExit &exit){
            if(exit.signal)p.app_.process_state->request_signal(exit.signal);else p.app_.process_state->request_exit(exit.status);
            return {Fault::process_exit,true};
        }catch(const ThreadExit &exit){p.threads_.request_exit(exit.value);return {Fault::thread_exit,true};}
        catch(...){return {Fault::unsupported_service,true};}
    }
};
a64::Fault NativeSleeping::invoke(unsigned operation,a64::Address error,std::array<std::uint64_t,31> &r,bool full_frame,a64::ServiceState *frame,bool allow_deferred) {
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
    if(!seconds && !nanos){r[0]=0;return Fault::none;}
    if(threads_.factory_execution_active()){
        if(!allow_deferred || !full_frame || !frame || &frame->registers!=&r)return Fault::unsupported_service;
        if(!frame->invocation || frame->trusted_tls!=threads_.tls() || !threads_.thread_register_state(frame->trusted_tls))return Fault::invalid_call;
        frame->deferred=std::make_shared<DeferredSleep>(*this,operation,error,remainder,remaining,*frame);
        return Fault::none;
    }
    const auto interrupted_result=[&](const NativeSleepDuration &left){
        if(operation==0){const auto fault=fail(4);if(fault==Fault::none)r[0]=left.seconds;return fault;}
        if(operation==2 && remainder){
            std::array<std::uint8_t,16> output{};
            for(unsigned i=0;i<8;++i){output[i]=static_cast<std::uint8_t>(left.seconds>>(8*i));output[8+i]=static_cast<std::uint8_t>(std::uint64_t{left.nanos}>>(8*i));}
            if(!memory_.write(remainder,output))return fail(14);
        }
        return fail(4);
    };
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
                const auto signal=signals_.io_interruption();
                const bool framed=full_frame && frame && signal && signals_.io_frame_ready(*signal,*frame);
                if(framed){
                    // Publish the interrupted duration before constructing the
                    // frame; no remainder/return writes follow a restored context.
                    auto left=remaining;
                    const auto elapsed=interruption-start;
                    const auto elapsed_seconds=std::chrono::duration_cast<std::chrono::seconds>(elapsed);
                    left.consume(static_cast<std::uint64_t>(elapsed_seconds.count()),static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed-elapsed_seconds).count()));
                    const auto fault=interrupted_result(left);if(fault!=Fault::none)return fault;
                }
                const auto fault=(signal?signals_.deliver_pending(frame?*frame:empty,frame!=nullptr,std::uint64_t{1}<<(signal->signal-1)):Fault::none);
                if(fault!=Fault::none)return fault;
                if(frame && frame->resume)return Fault::none;
                if(signals_.delivery_serial()!=deliveries){if(framed)return Fault::none;interrupted=true;break;}
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
        if(interrupted)return interrupted_result(remaining);
    }
    r[0]=0;return Fault::none;
}
}
