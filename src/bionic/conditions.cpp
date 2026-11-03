#include "conditions.hpp"
#include "threads.hpp"
#include "mutexes.hpp"
#include "signals.hpp"
#include <bit>
#include <chrono>
#include <thread>
#include <algorithm>
#include <utility>

namespace aether::bionic {
namespace {
using a64::Fault;
template<std::size_t N> std::array<std::uint8_t,N> bytes(std::uint64_t value) {
    std::array<std::uint8_t,N> result{};
    for (unsigned i=0;i<N;++i) result[i]=static_cast<std::uint8_t>(value>>(8*i));
    return result;
}
std::uint64_t word(std::span<const std::uint8_t> data, unsigned offset=0, unsigned size=8) {
    std::uint64_t result=0;
    for (unsigned i=0;i<size;++i) result|=std::uint64_t{data[offset+i]}<<(8*i);
    return result;
}
}
struct NativeConditions::DeferredWait final : a64::DeferredService {
    using Clock=std::chrono::steady_clock;
    enum class Phase {initial,waiting,reacquiring,complete};
    NativeConditions &p;
    a64::Address condition,mutex,tls,stack_top;std::uint32_t tid,initial_state;
    std::uint64_t invocation,ticket=0;std::shared_ptr<a64::ThreadRegisterState> owner;
    bool timed,enrolled=false;std::int64_t seconds;std::uint64_t nanos;
    std::size_t slot=0;Phase phase=Phase::initial;Fault pending_fault=Fault::none;unsigned status=0;
    std::optional<Clock::time_point> clock_check;
    std::optional<a64::ArchitecturalState> saved_resume;
    DeferredWait(NativeConditions &p,a64::Address condition,a64::Address mutex,std::uint32_t state,
                 bool timed,std::int64_t seconds,std::uint64_t nanos,const a64::ServiceState &frame):
        p(p),condition(condition),mutex(mutex),tls(frame.trusted_tls),stack_top(frame.stack_top),tid(p.threads_.tid()),
        initial_state(state),invocation(frame.invocation),owner(p.threads_.thread_register_state(tls)),
        timed(timed),seconds(seconds),nanos(nanos) {}
    ~DeferredWait() override {try{(void)retire();}catch(...){} } // Cancellation never calls guest code or invents mutex ownership.
    bool owns_slot() const noexcept {
        if(!enrolled || slot>=p.waiters_.size())return false;
        const auto &w=p.waiters_[slot];
        return w.tid==tid && w.condition==condition && w.mutex==mutex && w.ticket==ticket &&
            w.continuation_owned && w.owner==owner;
    }
    Fault validate_enrollment() const {
        if(!owns_slot())return Fault::invalid_call;
        std::array<std::uint8_t,8> current{};
        if(!p.memory_.read(condition,current))return Fault::read;
        if(!p.memory_.accessible(condition,8,a64::Permission::write))return Fault::write;
        const auto count=static_cast<unsigned>(std::count_if(p.waiters_.begin(),p.waiters_.end(),[&](const auto &w){return w.tid && w.condition==condition;}));
        return word(current,0,4)==p.waiters_[slot].state && word(current,4,4)==count?Fault::none:Fault::unsupported_service;
    }
    Fault retire() {
        if(!enrolled)return Fault::none;
        if(!owns_slot()){enrolled=false;return Fault::invalid_call;}
        auto fault=validate_enrollment();
        if(fault==Fault::none){
            const auto count=static_cast<unsigned>(std::count_if(p.waiters_.begin(),p.waiters_.end(),[&](const auto &w){return w.tid && w.condition==condition;}));
            if(!count)fault=Fault::invalid_call;
            else if(!p.memory_.write(condition+4,bytes<4>(count-1)))fault=Fault::write;
        }
        p.waiters_[slot]={};enrolled=false;
        return fault;
    }
    // A steady hint only requests a fresh selected-owner clock read; it never
    // turns a wall-clock adjustment into a fabricated timeout.
    bool refresh_clock(bool &expired) {
        expired=false;if(!timed)return true;
        std::int64_t now_seconds=0;std::uint64_t now_nanos=0;
        if(initial_state&2U){
            host::MonotonicTime now;
            if(p.time_.read_monotonic(now)!=host::TimeStatus::ok || now.seconds>INT64_MAX || now.nanoseconds>=1000000000)return false;
            now_seconds=static_cast<std::int64_t>(now.seconds);now_nanos=now.nanoseconds;
        }else{
            host::EpochTime now;
            if(p.time_.read_wall_time(now)!=host::TimeStatus::ok || now.nanoseconds>=1000000000)return false;
            now_seconds=now.seconds;now_nanos=now.nanoseconds;
        }
        expired=now_seconds>seconds || (now_seconds==seconds && now_nanos>=nanos);
        auto pause=std::chrono::nanoseconds(10000000);
        if(expired)pause=std::chrono::nanoseconds(0);
        else if(now_seconds==seconds)pause=std::min(pause,std::chrono::nanoseconds(nanos-now_nanos));
        else if(now_seconds==seconds-1 && nanos<now_nanos)pause=std::min(pause,std::chrono::nanoseconds(1000000000+nanos-now_nanos));
        clock_check=Clock::now()+pause;return true;
    }
    bool ready() const noexcept override {
        if(p.app_.process_state->exit_status() || phase==Phase::initial || phase==Phase::complete)return true;
        if(!p.threads_.signal_snapshot(tid,owner))return true; // Resume reports a stale incarnation without observing its mutex.
        if(phase==Phase::reacquiring)return p.mutexes_.lock_ready(mutex,tid);
        try{if(validate_enrollment()!=Fault::none)return true;}catch(...){return true;}
        return p.waiters_[slot].notified || p.signals_.wait_ready(tid,owner) || (clock_check && Clock::now()>=*clock_check);
    }
    std::optional<Clock::time_point> deadline() const noexcept override {
        if(phase!=Phase::waiting)return {};
        auto next=clock_check;const auto alarm=p.signals_.wait_deadline(tid,owner);
        if(alarm && (!next || *alarm<*next))next=alarm;
        return next;
    }
    a64::DeferredServiceResult resume(a64::ServiceState &frame) noexcept override {
        try{
            if(p.app_.process_state->exit_status())return {Fault::process_exit,true};
            if(!owner || p.threads_.tid()!=tid || p.threads_.tls()!=tls || frame.trusted_tls!=tls || frame.invocation!=invocation ||
               frame.stack_top!=stack_top || p.threads_.thread_register_state(tls)!=owner)return {Fault::invalid_call,true};
            if(phase==Phase::initial){
                std::array<std::uint8_t,8> current{};
                if(!p.memory_.read(condition,current))return {Fault::read,true};
                if(!p.memory_.accessible(condition,8,a64::Permission::write))return {Fault::write,true};
                const auto count=static_cast<unsigned>(std::count_if(p.waiters_.begin(),p.waiters_.end(),[&](const auto &w){return w.tid && w.condition==condition;}));
                const auto current_state=static_cast<std::uint32_t>(word(current,0,4));
                // Earlier enrolled waiters may signal/retire before this first
                // effect. Use their current validated sequence/count, retaining
                // the originally selected clock mode and no notification token.
                if(current_state==0xdeadc04d || (current_state&1U) || (current_state&3U)!=(initial_state&3U) ||
                   word(current,4,4)!=count)return {Fault::unsupported_service,true};
                for(const auto &w:p.waiters_)if(w.tid && w.condition==condition && (w.state!=current_state || w.mutex!=mutex))return {Fault::unsupported_service,true};
                const auto valid=p.mutexes_.validate_wait(mutex,tid);if(valid!=Fault::none)return {valid,true};
                bool expired=false;if(!refresh_clock(expired))return {Fault::unsupported_service,true};
                slot=0;while(slot<p.waiters_.size() && p.waiters_[slot].tid)++slot;
                if(slot==p.waiters_.size() || p.next_ticket_==UINT64_MAX)return {Fault::unsupported_service,true};
                ticket=p.next_ticket_++;p.waiters_[slot]={condition,mutex,tid,current_state,false,ticket,true,owner};enrolled=true;
                if(!p.memory_.write(condition+4,bytes<4>(count+1))){p.waiters_[slot]={};enrolled=false;return {Fault::write,true};}
                std::array<std::uint64_t,31> args{};args[0]=mutex;
                const auto unlocked=p.mutexes_.invoke(2,tid,args);
                if(unlocked!=Fault::none || args[0]){(void)retire();return {unlocked!=Fault::none?unlocked:Fault::invalid_call,true};}
                phase=Phase::waiting;
            }
            if(phase==Phase::waiting){
                pending_fault=validate_enrollment();
                bool finish=pending_fault!=Fault::none;
                if(!finish && p.waiters_[slot].notified)finish=true;
                if(!finish){
                    bool expired=false;
                    if(!refresh_clock(expired)){pending_fault=Fault::unsupported_service;finish=true;}
                    else if(expired){status=110;finish=true;}
                }
                if(!finish && p.signals_.wait_ready(tid,owner)){
                    std::array<std::uint8_t,4> saved_errno{};
                    const auto error=p.threads_.error_address();
                    if(!p.memory_.read(error,saved_errno))pending_fault=Fault::read;
                    else{
                        const auto serial=p.signals_.delivery_serial();
                        const auto signal=p.signals_.io_interruption();
                        if(signal && p.signals_.io_frame_ready(*signal,frame))frame.registers[0]=0;
                        pending_fault=(signal?p.signals_.deliver_pending(frame,true,std::uint64_t{1}<<(signal->signal-1)):Fault::none);
                        const bool delivered=frame.resume.has_value() || p.signals_.delivery_serial()!=serial;
                        if(delivered && !p.memory_.write(error,saved_errno))pending_fault=Fault::write;
                        if(frame.resume){saved_resume=std::move(frame.resume);frame.resume.reset();}
                        finish=delivered;
                    }
                    finish=finish || pending_fault!=Fault::none;
                }
                if(!finish)return {Fault::none,false};
                const auto retired=retire();if(pending_fault==Fault::none)pending_fault=retired;
                phase=Phase::reacquiring;
            }
            if(phase==Phase::reacquiring){
                std::array<std::uint64_t,31> args{};args[0]=mutex;
                const auto locked=p.mutexes_.invoke(1,tid,args);
                if(locked!=Fault::none){saved_resume.reset();return {locked,true};}
                if(args[0]==16){
                    if(pending_fault!=Fault::none){saved_resume.reset();return {pending_fault,true};}
                    return {Fault::none,false};
                }
                if(args[0]){saved_resume.reset();return {Fault::invalid_call,true};}
                phase=Phase::complete;
                if(pending_fault!=Fault::none){saved_resume.reset();return {pending_fault,true};}
                frame.registers[0]=status;
                if(saved_resume){frame.resume=std::move(saved_resume);saved_resume.reset();}
                return {Fault::none,true};
            }
            return {Fault::invalid_call,true};
        }catch(...){try{(void)retire();}catch(...){}saved_resume.reset();return {Fault::unsupported_service,true};}
    }
};
bool NativeConditions::switch_safe() const noexcept {
    for(const auto &waiter:waiters_)if(waiter.tid && !threads_.main_identity(waiter.tid) &&
        (!waiter.continuation_owned || !waiter.owner || !threads_.signal_snapshot(waiter.tid,waiter.owner)))return false;
    return true; // Only root records or explicitly owned continuations may survive a switch.
}
Fault NativeConditions::invoke(unsigned operation, std::array<std::uint64_t,31> &r, bool full_frame, a64::ServiceState *frame,bool allow_deferred) {
    const bool timed=operation==11;
    if(timed)operation=0;
    const auto address=r[0];
    const auto result=[&](unsigned value){r[0]=value;return Fault::none;};
    if (operation>=5) {
        if (address%8) return Fault::unsupported_service;
        std::array<std::uint8_t,8> input{};
        if (operation!=5 && !memory_.read(address,input)) return Fault::read;
        auto value=word(input);
        if (operation==7 || operation==9) {
            const auto output=operation==7 ? value&1 : (value>>1)&1;
            if (!memory_.write(r[1],bytes<4>(output))) return Fault::write;
            return result(0);
        }
        const auto argument=static_cast<std::uint32_t>(r[1]);
        if ((operation==8 || operation==10) && argument>1) return result(22);
        if (operation==5) value=0;
        else if (operation==6) value=0xdeada11d;
        else if (operation==8) value|=argument; // Bionic attr setter preserves prior shared bit.
        else if (operation==10) value|=std::uint64_t{argument}<<1;
        else return Fault::unsupported_service;
        if (!memory_.write(address,bytes<8>(value))) return Fault::write;
        return result(0);
    }
    if (address%4) return Fault::unsupported_service;
    std::array<std::uint8_t,8> input{};
    if (operation!=3 && !memory_.read(address,input)) return Fault::read;
    if (!memory_.accessible(address,8,a64::Permission::write)) return Fault::write;
    const auto state=static_cast<std::uint32_t>(word(input,0,4));
    const auto count=static_cast<unsigned>(std::count_if(waiters_.begin(),waiters_.end(),[&](const auto &w){return w.condition==address && w.tid;}));
    if (operation==3) {
        if (count) return result(16);
        std::uint64_t attr=0;
        if (r[1]) {std::array<std::uint8_t,8> a{};if (!memory_.read(r[1],a))return Fault::read;attr=word(a);}
        if (attr&1) return Fault::unsupported_service;
        if (!memory_.write(address,bytes<8>(attr&2))) return Fault::write;
        return result(0);
    }
    if (state==0xdeadc04d || (state&1)) return Fault::unsupported_service;
    if (word(input,4,4)!=count) return Fault::unsupported_service;
    for (const auto &w:waiters_) if (w.tid && w.condition==address && w.state!=state) return Fault::unsupported_service;
    if (operation==4) {
        if (count) return result(16);
        if (!memory_.write(address,bytes<4>(0xdeadc04d))) return Fault::write;
        return result(0);
    }
    if (operation==1 || operation==2) {
        if (!count) return result(0); // Signals without waiters are not retained as tokens.
        const auto next=state+4U;
        if (!memory_.write(address,bytes<4>(next))) return Fault::write;
        bool chosen=false;
        for (auto &w:waiters_) if (w.tid && w.condition==address) {
            w.state=next;
            if (!w.notified && (!chosen || operation==2)) {w.notified=true;chosen=true;}
        }
        return result(0);
    }
    if (operation!=0 || !full_frame) return Fault::unsupported_service;
    const bool deferred=threads_.factory_execution_active() && allow_deferred;
    if(threads_.factory_execution_active() && !deferred)return Fault::unsupported_service;
    // Copy the absolute LP64 timespec before enrollment/unlock. NULL is the
    // Bionic indefinite-wait extension; pthread errors never write guest errno.
    bool deadline=false;std::int64_t seconds=0;std::uint64_t nanos=0;
    if(timed && r[2]) {
        std::array<std::uint8_t,16> input_time{};
        if(!memory_.read(r[2],input_time))return Fault::read;
        seconds=std::bit_cast<std::int64_t>(word(input_time));nanos=word(input_time,8);
        if(nanos>=1000000000)return result(22);
        if(seconds<0)return result(110);
        deadline=true;
    }
    std::int64_t now_seconds=0;std::uint64_t now_nanos=0;
    const auto read_clock=[&]() {
        if(state&2U) {
            host::MonotonicTime now;
            if(time_.read_monotonic(now)!=host::TimeStatus::ok || now.seconds>INT64_MAX || now.nanoseconds>=1000000000)return false;
            now_seconds=static_cast<std::int64_t>(now.seconds);now_nanos=now.nanoseconds;
        } else {
            host::EpochTime now;
            if(time_.read_wall_time(now)!=host::TimeStatus::ok || now.nanoseconds>=1000000000)return false;
            now_seconds=now.seconds;now_nanos=now.nanoseconds;
        }
        return true;
    };
    // Provider authorization/availability is checked without releasing the lock.
    if(deadline && (state&2U) && !app_.monotonic_time_allowed)return Fault::unsupported_service;
    if(deadline && !read_clock())return Fault::unsupported_service;
    const auto mutex=r[1];const auto tid=threads_.tid();
    if (address<mutex+40 && mutex<address+48) return Fault::unsupported_service;
    const auto valid=mutexes_.validate_wait(mutex,tid);if (valid!=Fault::none) return valid;
    for (const auto &w:waiters_) if (w.tid && w.condition==address && w.mutex!=mutex) return Fault::unsupported_service;
    if(deferred){
        if(!frame || &frame->registers!=&r || !frame->invocation || frame->trusted_tls!=threads_.tls() ||
           !threads_.thread_register_state(frame->trusted_tls))return Fault::invalid_call;
        frame->deferred=std::make_shared<DeferredWait>(*this,address,mutex,state,deadline,seconds,nanos,*frame);
        return Fault::none;
    }
    auto slot=std::find_if(waiters_.begin(),waiters_.end(),[](const auto &w){return !w.tid;});
    if (slot==waiters_.end() || (!deadline && !threads_.has_runnable() && !(timed && (signals_.alarm_deadline() || signals_.ready())))) return Fault::unsupported_service;
    *slot={address,mutex,tid,state,false};
    if (!memory_.write(address+4,bytes<4>(count+1))) {*slot={};return Fault::write;}
    // Enrollment and unlock are one service action: no guest thread can run between them.
    std::array<std::uint64_t,31> args{};args[0]=mutex;
    auto fault=mutexes_.invoke(2,tid,args);
    bool released=fault==Fault::none && args[0]==0;
    if (fault==Fault::none && !released) fault=Fault::invalid_call;
    std::uint64_t budget=1000000;unsigned status=0;std::size_t progress_slices=0;
    const auto progress=[&]() -> Fault {
        if(!budget || progress_slices==1024)return Fault::budget;
        if(!threads_.has_runnable())return Fault::unsupported_service;
        ++progress_slices;std::uint64_t spent=0;
        const auto advanced=threads_.run_next(budget,spent);
        budget=spent>=budget?0:budget-spent;
        return advanced;
    };
    try {
        while (fault==Fault::none && !slot->notified) {
            if(deadline) {
                if(!read_clock()){fault=Fault::unsupported_service;break;}
                if(now_seconds>seconds || (now_seconds==seconds && now_nanos>=nanos)){status=110;break;}
            }
            if(timed && signals_.ready()) {
                std::array<std::uint8_t,4> saved_errno{};
                if(!memory_.read(threads_.error_address(),saved_errno)){fault=Fault::read;break;}
                const auto serial=signals_.delivery_serial();
                a64::ServiceState empty;
                const auto signal=signals_.io_interruption();
                if(frame && signal && signals_.io_frame_ready(*signal,*frame))r[0]=0;
                try{fault=(signal?signals_.deliver_pending(frame?*frame:empty,frame!=nullptr,std::uint64_t{1}<<(signal->signal-1)):Fault::none);}
                catch(...){fault=Fault::windows_service;}
                if((frame && frame->resume) || signals_.delivery_serial()!=serial) {
                    if(!memory_.write(threads_.error_address(),saved_errno))fault=Fault::write;
                    // A genuinely delivered caught signal permits a spurious wake,
                    // with the mutex reacquired; pthread waits never report EINTR.
                    break;
                }
                if(fault!=Fault::none)break;
            }
            if(threads_.has_runnable()) {
                fault=progress();
                continue;
            }
            const auto alarm=timed?signals_.alarm_deadline():std::nullopt;
            if(!deadline && !alarm){fault=Fault::unsupported_service;break;}
            // Re-read the selected absolute clock at most 10ms later, so realtime
            // adjustments remain visible. No LP64 seconds-to-host-duration overflow.
            auto pause=std::chrono::nanoseconds(10000000);
            if(deadline && now_seconds==seconds)pause=std::min(pause,std::chrono::nanoseconds(nanos-now_nanos));
            else if(deadline && now_seconds==seconds-1 && nanos<now_nanos)
                pause=std::min(pause,std::chrono::nanoseconds(1000000000+nanos-now_nanos));
            const auto until=std::chrono::steady_clock::now()+pause;
            std::this_thread::sleep_until(alarm?std::min(until,*alarm):until);
        }
    } catch (...) {fault=Fault::windows_service;}
    // Remove this waiter even when nested guest work failed. Re-read/validate the
    // state so malformed guest changes are not silently overwritten.
    std::array<std::uint8_t,8> current{};
    if (!memory_.read(address,current)) fault=Fault::read;
    else {
        const auto enrolled=static_cast<unsigned>(std::count_if(waiters_.begin(),waiters_.end(),[&](const auto &w){return w.tid && w.condition==address;}));
        if(!enrolled || word(current,0,4)!=slot->state || word(current,4,4)!=enrolled)fault=Fault::unsupported_service;
        else if(!memory_.write(address+4,bytes<4>(enrolled-1)))fault=Fault::write;
    }
    *slot={};
    if (released) {
        for(;;){
            args={};args[0]=mutex;
            const auto lock_fault=mutexes_.invoke(1,tid,args); // Fresh lookup; no held_ iterator crosses progress.
            if(lock_fault!=Fault::none)return lock_fault;
            if(!args[0])break;
            if(args[0]!=16)return Fault::invalid_call;
            Fault advanced=Fault::none;
            try{advanced=progress();}catch(...){return Fault::windows_service;}
            if(advanced!=Fault::none)return advanced;
        }
    }
    if (fault!=Fault::none) return fault;
    // Enrollment removal and relocking above precede the explicit transfer.
    if(frame && frame->resume)return Fault::none;
    return result(status);
}
}
