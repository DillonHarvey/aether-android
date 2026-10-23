#include "thread_specific.hpp"
#include <limits>

namespace aether::bionic {
namespace {
using Execution=GuestPosixServices::ThreadExecution;
Execution fault(a64::Fault value,std::uint64_t ticks=0){Execution result;result.result.fault=value;result.ticks=ticks;return result;}
}
std::size_t NativeThreadSpecific::key(std::uint64_t value) noexcept {
    const auto narrowed=static_cast<std::uint32_t>(value);
    return (narrowed&0xffffff80U)==0x80000000U?static_cast<std::size_t>(narrowed&127U):key_count;
}
std::size_t NativeThreadSpecific::owner(std::uint32_t tid,a64::Address tls) noexcept {
    for(std::size_t i=0;i<owners_.size();++i)
        if(owners_[i].occupied && owners_[i].tid==tid && owners_[i].tls==tls)return i;
    for(const auto &entry:owners_)if(entry.occupied && entry.tls==tls){
        rejection_="pthread keys: logical TLS reuse requires explicit retirement";return owner_count;
    }
    for(std::size_t i=0;i<owners_.size();++i)if(!owners_[i].occupied){
        owners_[i]={};owners_[i].tid=tid;owners_[i].tls=tls;owners_[i].occupied=true;return i;
    }
    rejection_="pthread keys: logical owner capacity exceeded";return owner_count;
}
a64::Fault NativeThreadSpecific::invoke(unsigned operation,std::uint32_t tid,a64::Address tls,
                                      std::array<std::uint64_t,31> &r) noexcept {
    using a64::Fault;rejection_={};
    if(operation==0){
        if(!memory_.accessible(r[0],4,a64::Permission::write))return Fault::write;
        for(std::size_t i=0;i<keys_.size();++i)if(!keys_[i].live && keys_[i].generation!=UINT64_MAX){
            const auto value=0x80000000U|static_cast<std::uint32_t>(i);
            std::array<std::uint8_t,4> output{};
            for(unsigned n=0;n<4;++n)output[n]=static_cast<std::uint8_t>(value>>(n*8));
            if(!memory_.write(r[0],output))return Fault::write;
            ++keys_[i].generation;keys_[i].destructor=r[1];keys_[i].live=true;r[0]=0;return Fault::none;
        }
        r[0]=11;return Fault::none;
    }
    if(operation>3){rejection_="pthread keys: unknown operation";return Fault::unsupported_service;}
    const auto at=key(r[0]);
    if(at==key_count || !keys_[at].live){r[0]=operation==2?0:22;return Fault::none;}
    if(operation==1){keys_[at].live=false;keys_[at].destructor=0;r[0]=0;return Fault::none;}
    const auto selected=owner(tid,tls);if(selected==owner_count)return Fault::unsupported_service;
    if(owners_[selected].phase==Phase::terminal){rejection_="pthread keys: logical thread has terminated";return Fault::invalid_call;}
    if(operation==2){
        auto &value=owners_[selected].values[at];
        if(value.generation!=keys_[at].generation)value={};
        r[0]=value.data;return Fault::none;
    }
    owners_[selected].values[at]={keys_[at].generation,r[1]};r[0]=0;return Fault::none;
}
void NativeThreadSpecific::discard(std::uint32_t tid,a64::Address tls) noexcept {
    for(auto &entry:owners_)if(entry.occupied && entry.tid==tid && entry.tls==tls){
        // A callback cannot invalidate its own live finalizer's bookkeeping.
        if(entry.phase!=Phase::finalizing)entry={};return;
    }
}
GuestPosixServices::ThreadExecution NativeThreadSpecific::finalize(std::uint32_t tid,a64::Address tls,
                                                                 const Runner &runner,std::uint64_t budget){
    using a64::Fault;rejection_={};const auto selected=owner(tid,tls);
    if(selected==owner_count)return fault(Fault::unsupported_service);
    if(owners_[selected].phase==Phase::terminal)return {owners_[selected].terminal,0};
    if(owners_[selected].phase==Phase::finalizing){rejection_="pthread keys: recursive finalization";return fault(Fault::invalid_call);}
    owners_[selected].phase=Phase::finalizing;
    std::uint64_t spent=0;
    const auto finish=[&](a64::ExecutionResult result){
        owners_[selected].values={};owners_[selected].terminal=result;owners_[selected].phase=Phase::terminal;
        return Execution{result,spent};
    };
    try {
        // The trusted caller may replace its callback during guest reentry.
        const auto execute=runner;
        for(unsigned pass=0;pass<4;++pass){
            bool called=false;
            for(std::size_t i=0;i<key_count;++i){
                a64::Address destructor=0,data=0;
                {
                    const auto &definition=keys_[i];const auto &value=owners_[selected].values[i];
                    if(!definition.live || definition.generation!=value.generation || !definition.destructor || !value.data)continue;
                    destructor=definition.destructor;data=value.data;
                }
                if(spent>=budget){rejection_="pthread keys: destructor budget exhausted";return finish(fault(Fault::budget).result);}
                if(!execute){rejection_="pthread keys: destructor runner unavailable";return finish(fault(Fault::unsupported_service).result);}
                // No key/owner/value references survive arbitrary guest callbacks.
                owners_[selected].values[i].data=0;called=true;
                const auto execution=execute(destructor,data,budget-spent);
                const auto remaining=budget-spent;
                const bool overflow=execution.ticks>UINT64_MAX-spent;
                spent=overflow?UINT64_MAX:spent+execution.ticks;
                if(execution.result.fault!=Fault::none)return finish(execution.result);
                if(!execution.result.returned){rejection_="pthread keys: destructor did not return";return finish(fault(Fault::invalid_call).result);}
                if(overflow || execution.ticks>remaining){rejection_="pthread keys: destructor exceeded remaining budget";return finish(fault(Fault::budget).result);}
            }
            if(!called)break;
        }
        a64::ExecutionResult result;result.returned=true;return finish(result);
    } catch(...) {
        (void)finish(fault(Fault::invalid_call).result);throw;
    }
}
}
