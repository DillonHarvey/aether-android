#include "conditions.hpp"
#include "threads.hpp"
#include "mutexes.hpp"
#include "signals.hpp"
#include <bit>
#include <chrono>
#include <thread>
#include <algorithm>

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
Fault NativeConditions::invoke(unsigned operation, std::array<std::uint64_t,31> &r, bool full_frame, a64::ServiceState *frame) {
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
    auto slot=std::find_if(waiters_.begin(),waiters_.end(),[](const auto &w){return !w.tid;});
    if (slot==waiters_.end() || (!deadline && !threads_.has_runnable() && !(timed && (signals_.alarm_deadline() || signals_.ready())))) return Fault::unsupported_service;
    *slot={address,mutex,tid,state,false};
    if (!memory_.write(address+4,bytes<4>(count+1))) {*slot={};return Fault::write;}
    // Enrollment and unlock are one service action: no guest thread can run between them.
    std::array<std::uint64_t,31> args{};args[0]=mutex;
    auto fault=mutexes_.invoke(2,tid,args);
    bool released=fault==Fault::none && args[0]==0;
    if (fault==Fault::none && !released) fault=Fault::invalid_call;
    std::uint64_t budget=1000000;unsigned status=0;
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
                try{fault=signals_.deliver_pending(frame?*frame:empty,frame!=nullptr);}
                catch(...){fault=Fault::windows_service;}
                if(signals_.delivery_serial()!=serial) {
                    if(!memory_.write(threads_.error_address(),saved_errno))fault=Fault::write;
                    // A genuinely delivered caught signal permits a spurious wake,
                    // with the mutex reacquired; pthread waits never report EINTR.
                    break;
                }
                if(fault!=Fault::none)break;
            }
            if(threads_.has_runnable()) {
                if (!budget) {fault=Fault::budget;break;}
                std::uint64_t spent=0;fault=threads_.run_next(budget,spent);
                budget=spent>=budget?0:budget-spent;
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
    else if (word(current,0,4)!=slot->state || word(current,4,4)!=count+1) fault=Fault::unsupported_service;
    else if (!memory_.write(address+4,bytes<4>(count))) fault=Fault::write;
    *slot={};
    if (released) {
        args={};args[0]=mutex;
        const auto lock_fault=mutexes_.invoke(0,tid,args);
        if (lock_fault!=Fault::none) return lock_fault;
        if (args[0]) return Fault::invalid_call;
    }
    if (fault!=Fault::none) return fault;
    return result(status);
}
}
