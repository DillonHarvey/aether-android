#include "futex.hpp"
#include "threads.hpp"
#include "signals.hpp"
#include "sleeping.hpp"
#include "aether/common/thread_exit.hpp"
#include <algorithm>
#include <bit>
#include <chrono>
#include <new>
#include <thread>
#include <utility>

namespace aether::bionic {
namespace {
using a64::Address;using a64::Fault;using Clock=std::chrono::steady_clock;
constexpr std::uint32_t private_flag=128,realtime_flag=256,match_any=UINT32_MAX;
std::uint64_t word(std::span<const std::uint8_t> data) noexcept {
    std::uint64_t value=0;for(std::size_t index=0;index<data.size();++index)value|=std::uint64_t{data[index]}<<(index*8);
    return value;
}
template<std::size_t N> std::array<std::uint8_t,N> bytes(std::uint64_t value) noexcept {
    std::array<std::uint8_t,N> output{};
    for(std::size_t index=0;index<N;++index)output[index]=static_cast<std::uint8_t>(value>>(index*8));
    return output;
}
}
Fault NativeFutexes::fail(a64::ServiceState &frame,Address error,unsigned code) noexcept {
    if(!memory_.write(error,bytes<4>(code)))return Fault::write;
    if(errors_!=UINT64_MAX)++errors_;
    frame.registers[0]=UINT64_MAX;return Fault::none;
}
struct NativeFutexes::DeferredWait final : a64::DeferredService {
    NativeFutexes &p;
    Address address,error,tls,stack_top;std::uint32_t tid,expected,mask;
    std::uint64_t invocation,ticket=0;
    std::shared_ptr<a64::ThreadRegisterState> owner;
    a64::GuestMemory::WordIdentity identity;
    bool private_key,full_frame,can_wait,timed,absolute,realtime,queued=false,woken=false;
    std::size_t slot=0;
    NativeSleepDuration remaining;
    std::int64_t seconds;std::uint32_t nanos;
    Clock::time_point sampled;
    std::optional<Clock::time_point> check;
    std::optional<ResumeRestart> restart;
    DeferredWait(NativeFutexes &p,const a64::ServiceState &frame,a64::GuestMemory::WordIdentity identity,
                 bool full_frame,bool can_wait,bool timed,bool absolute,bool realtime,std::int64_t seconds,
                 std::uint32_t nanos,Clock::time_point started,const ResumeRestart *restart):
        p(p),address(frame.registers[0]),error(p.threads_.error_address()),tls(p.threads_.tls()),stack_top(frame.stack_top),
        tid(p.threads_.tid()),expected(static_cast<std::uint32_t>(frame.registers[2])),
        mask((static_cast<std::uint32_t>(frame.registers[1])&~(private_flag|realtime_flag))==9?
             static_cast<std::uint32_t>(frame.registers[5]):match_any),invocation(frame.invocation),
        owner(p.threads_.thread_register_state(tls)),identity(std::move(identity)),
        private_key((frame.registers[1]&private_flag)!=0),full_frame(full_frame),can_wait(can_wait),timed(timed),
        absolute(absolute),realtime(realtime),remaining{static_cast<std::uint64_t>(seconds),nanos},
        seconds(seconds),nanos(nanos),sampled(started),restart(restart?std::optional<ResumeRestart>(*restart):std::nullopt) {}
    ~DeferredWait() override {retire();}
    void retire() noexcept {
        if(!queued)return;
        if(slot<p.waiters_.size() && p.waiters_[slot]==this)p.waiters_[slot]=nullptr;
        queued=false;
    }
    bool mapping_valid() const noexcept {
        const auto current=p.memory_.word_identity(address);
        return current && *current==identity;
    }
    bool same_key(Address other,bool other_private,const a64::GuestMemory::WordIdentity &other_identity) const noexcept {
        return private_key==other_private && (!private_key || address==other) && identity==other_identity;
    }
    Fault refresh_timeout(bool &expired) noexcept {
        expired=false;if(!timed)return Fault::none;
        const auto now=Clock::now();
        if(!absolute){
            if(now<sampled)return Fault::windows_service;
            const auto elapsed=now-sampled;
            const auto whole=std::chrono::duration_cast<std::chrono::seconds>(elapsed);
            remaining.consume(static_cast<std::uint64_t>(whole.count()),
                static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed-whole).count()));
            sampled=now;expired=!remaining.seconds && !remaining.nanos;
            const auto chunk=std::min(remaining.seconds,std::uint64_t{86400});
            const auto duration=std::chrono::seconds(chunk)+std::chrono::nanoseconds(chunk==remaining.seconds?remaining.nanos:0);
            if(duration>Clock::time_point::max()-now)return Fault::unsupported_service;
            check=now+duration;return Fault::none;
        }
        std::int64_t current_seconds=0;std::uint64_t current_nanos=0;
        host::TimeStatus status;
        if(realtime){
            host::EpochTime value;status=p.time_.read_wall_time(value);
            current_seconds=value.seconds;current_nanos=value.nanoseconds;
        }else{
            if(!p.app_.monotonic_time_allowed)return Fault::capability_denied;
            host::MonotonicTime value;status=p.time_.read_monotonic(value);
            if(status==host::TimeStatus::ok && value.seconds>INT64_MAX)return Fault::unsupported_service;
            current_seconds=static_cast<std::int64_t>(value.seconds);current_nanos=value.nanoseconds;
        }
        if(status==host::TimeStatus::denied)return Fault::capability_denied;
        if(status!=host::TimeStatus::ok || current_nanos>=1000000000)return Fault::unsupported_service;
        expired=current_seconds>seconds || (current_seconds==seconds && current_nanos>=nanos);
        auto pause=std::chrono::nanoseconds(10000000);
        if(expired)pause=std::chrono::nanoseconds(0);
        else if(current_seconds==seconds)pause=std::min(pause,std::chrono::nanoseconds(nanos-current_nanos));
        else if(current_seconds==seconds-1 && nanos<current_nanos)
            pause=std::min(pause,std::chrono::nanoseconds(1000000000+std::uint64_t{nanos}-current_nanos));
        if(pause>Clock::time_point::max()-now)return Fault::unsupported_service;
        check=now+pause;return Fault::none;
    }
    bool ready() const noexcept override {
        if(woken || !p.app_.process_state || p.app_.process_state->exit_status() || !p.threads_.signal_snapshot(tid,owner))return true;
        if(!queued || !mapping_valid() || (timed && !check))return true;
        const auto now=Clock::now();
        return (timed && (now<sampled || now>=*check)) || p.signals_.wait_ready(tid,owner);
    }
    std::optional<Clock::time_point> deadline() const noexcept override {
        if(woken || !p.threads_.signal_snapshot(tid,owner))return {};
        auto next=check;const auto alarm=p.signals_.wait_deadline(tid,owner);
        if(alarm && (!next || *alarm<*next))next=alarm;
        return next;
    }
    a64::DeferredServiceResult finish(a64::ServiceState &frame,unsigned code) noexcept {
        retire();return {code?p.fail(frame,error,code):Fault::none,true};
    }
    a64::DeferredServiceResult resume(a64::ServiceState &frame) noexcept override {
        try {
            if(!p.app_.process_state)return {Fault::invalid_call,true};
            if(p.app_.process_state->exit_status())return {Fault::process_exit,true};
            if(!owner || !p.threads_.signal_snapshot(tid,owner) || p.threads_.tid()!=tid || p.threads_.tls()!=tls ||
               p.threads_.thread_register_state(tls)!=owner || p.threads_.error_address()!=error ||
               (full_frame && (frame.trusted_tls!=tls || frame.invocation!=invocation || frame.stack_top!=stack_top)))
                return {Fault::invalid_call,true};
            // A real wake already removed this registration. It wins over any
            // later mapping change, timeout or caught signal, but not process exit.
            if(woken){frame.registers[0]=0;return {Fault::none,true};}
            if(!mapping_valid())return finish(frame,14);
            if(!queued){
                std::array<std::uint8_t,4> value{};
                if(!p.memory_.read(address,value))return finish(frame,14);
                if(word(value)!=expected)return finish(frame,11);
                // Clock reads are host-only: no guest callback or scheduling
                // occurs between this comparison and queue publication below.
                bool expired=false;const auto clock=refresh_timeout(expired);
                if(clock!=Fault::none)return {clock,true};
                if(expired)return finish(frame,110);
                if(!can_wait){p.rejection_="futex: blocking caller has no admitted continuation or main driver";return {Fault::unsupported_service,true};}
                slot=0;while(slot<p.waiters_.size() && p.waiters_[slot])++slot;
                if(slot==p.waiters_.size() || p.next_ticket_==UINT64_MAX){
                    p.rejection_="futex: finite waiter or registration identity limit reached";
                    return {Fault::unsupported_service,true};
                }
                ticket=p.next_ticket_++;p.waiters_[slot]=this;queued=true;
            }else{
                if(slot>=p.waiters_.size() || p.waiters_[slot]!=this || !ticket)return {Fault::invalid_call,true};
                bool expired=false;const auto clock=refresh_timeout(expired);
                if(clock!=Fault::none){retire();return {clock,true};}
                if(expired)return finish(frame,110);
            }
            if(const auto signal=p.signals_.io_interruption()){
                // Linux removes an interrupted waiter before running a handler.
                // Timed waits always expose EINTR to a caught handler. Only an
                // untimed SA_RESTART wait may start a new authenticated SVC.
                retire();
                const bool again=!timed && signal->restart;
                const bool framed=full_frame && p.signals_.io_frame_ready(*signal,frame);
                if(again){
                    if(!restart || !full_frame || frame.pc!=restart->instruction+4 ||
                       !framed){p.rejection_="futex: untimed restart needs the authenticated original SVC and signal frame";return {Fault::unsupported_service,true};}
                    frame.registers=restart->registers;frame.pc=restart->instruction;
                }else if(framed){
                    const auto fault=p.fail(frame,error,4);if(fault!=Fault::none)return {fault,true};
                }
                const auto fault=p.signals_.deliver_pending(frame,full_frame,std::uint64_t{1}<<(signal->signal-1));
                if(fault!=Fault::none)return {fault,true};
                if(again && !frame.resume)return {Fault::unsupported_service,true};
                return {framed?Fault::none:Fault::unsupported_service,true}; // No post-handler writes or queue replay.
            }
            return {Fault::none,false};
        }catch(const ProcessExit &exit){
            if(exit.signal)p.app_.process_state->request_signal(exit.signal);else p.app_.process_state->request_exit(exit.status);
            retire();return {Fault::process_exit,true};
        }catch(const ThreadExit &exit){p.threads_.request_exit(exit.value);retire();return {Fault::thread_exit,true};}
        catch(...){retire();return {Fault::unsupported_service,true};}
    }
};
Fault NativeFutexes::invoke(a64::ServiceState &frame,bool full_frame,bool allow_deferred,const ResumeRestart *restart) {
    rejection_={};auto &r=frame.registers;const auto error=threads_.error_address();
    const auto operation=static_cast<std::uint32_t>(r[1]);
    const auto command=operation&~(private_flag|realtime_flag);
    const bool waiting=command==0 || command==9;
    if(!waiting && command!=1 && command!=10){rejection_="futex: PI, requeue, wake-op and unknown commands are unsupported";return fail(frame,error,38);}
    bool timed=waiting && r[3];std::int64_t seconds=0;std::uint32_t nanos=0;
    if(timed){
        std::array<std::uint8_t,16> input{};
        if(!memory_.read(r[3],input))return fail(frame,error,14);
        const auto whole=word(std::span<const std::uint8_t>(input).first<8>());
        const auto part=word(std::span<const std::uint8_t>(input).subspan<8,8>());
        if(whole>INT64_MAX || part>=1000000000)return fail(frame,error,22);
        seconds=static_cast<std::int64_t>(whole);nanos=static_cast<std::uint32_t>(part);
    }
    const auto started=Clock::now(); // Relative timeout starts before key/admission setup.
    if((operation&realtime_flag) && command!=9)return fail(frame,error,38);
    const auto mask=command==9 || command==10?static_cast<std::uint32_t>(r[5]):match_any;
    if(!mask)return fail(frame,error,22);
    const Address address=r[0];if(address%4)return fail(frame,error,22);
    const auto identity=memory_.word_identity(address);if(!identity)return fail(frame,error,14);
    if(!waiting){
        // Linux6.12 legacy futex wakes before comparing the count, so a zero
        // or negative signed count wakes ONE eligible waiter. futex2 differs.
        const auto count=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[2]));
        const auto limit=count>0?static_cast<std::uint32_t>(count):1U;
        std::uint32_t woke=0;
        for(auto *waiter:waiters_)if(waiter && waiter->queued){
            if(!threads_.signal_snapshot(waiter->tid,waiter->owner)){waiter->retire();continue;}
            if((waiter->mask&mask) && waiter->same_key(address,(operation&private_flag)!=0,*identity)){
                waiter->retire();waiter->woken=true;
                if(++woke>=limit)break;
            }
        }
        r[0]=woke;return Fault::none;
    }
    const bool child=threads_.factory_execution_active();
    const bool parent=full_frame && threads_.main_identity(threads_.tid());
    const bool admitted=child && full_frame && allow_deferred;
    if(full_frame && (!frame.invocation || frame.trusted_tls!=threads_.tls() || frame.resume || frame.deferred))return Fault::invalid_call;
    std::shared_ptr<DeferredWait> operation_state;
    try{
        operation_state=std::make_shared<DeferredWait>(*this,frame,*identity,full_frame,admitted||parent,timed,
            command==9,(operation&realtime_flag)!=0,seconds,nanos,started,restart);
    }catch(const std::bad_alloc &){return fail(frame,error,12);}
    if(admitted){
        frame.deferred=std::move(operation_state);return Fault::none;
    }
    std::uint64_t budget=full_frame?frame.operation_allowance(1'000'000):0;
    std::size_t slices=0;
    for(;;){
        const auto step=operation_state->resume(frame);
        if(step.completed || step.fault!=Fault::none)return step.fault;
        if(!parent){rejection_="futex: blocking requires an admitted native continuation or main frame";return Fault::unsupported_service;}
        // A peer may consume the parent Runtime allowance through Java.
        // Preserve a committed wake above, but never sleep or admit another
        // peer with the original, now stale, main-frame headroom.
        budget=frame.operation_allowance(budget);
        if(!budget){rejection_="futex: main progress allowance exhausted";return Fault::budget;}
        if(threads_.has_runnable()){
            if(!budget || slices++==1024){rejection_="futex: main progress instruction or slice bound exhausted";return Fault::budget;}
            std::uint64_t spent=0;const auto fault=threads_.run_next(budget,spent);
            if(fault!=Fault::none)return fault;
            if(spent>budget)return Fault::budget;budget-=spent;
            continue;
        }
        const auto deadline=operation_state->deadline();
        if(!deadline){rejection_="futex: indefinite main wait has no supported producer";return Fault::unsupported_service;}
        if(Clock::now()<*deadline)std::this_thread::sleep_until(*deadline);
    }
}
}
