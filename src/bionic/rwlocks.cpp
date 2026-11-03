#include "rwlocks.hpp"
#include "threads.hpp"
#include <array>
#include <utility>
namespace aether::bionic {
namespace {
using a64::Address;using a64::Fault;
template<std::size_t N> std::uint64_t get(const std::array<std::uint8_t,N>&b,std::size_t at=0,unsigned size=8){std::uint64_t n=0;for(unsigned i=0;i<size;++i)n|=std::uint64_t{b[at+i]}<<(8*i);return n;}
template<std::size_t N> void put(std::array<std::uint8_t,N>&b,std::uint64_t n,std::size_t at=0,unsigned size=8){for(unsigned i=0;i<size;++i)b[at+i]=static_cast<std::uint8_t>(n>>(8*i));}
}
Fault NativeRwLocks::call(unsigned operation,std::uint32_t tid,std::array<std::uint64_t,31>&r){
    const Address address=r[0];const auto done=[&](unsigned code){r[0]=code;return Fault::none;};const auto reject=[&](std::string_view text){rejection_=text;return Fault::unsupported_service;};
    if(operation>=7){
        if(address%8)return reject("pthread rwlock attribute is not LP64 aligned");std::array<std::uint8_t,8> bytes{};
        if(operation!=7 && !memory_.read(address,bytes))return Fault::read;auto value=get(bytes);const auto input=static_cast<std::uint32_t>(r[1]);
        if(operation==10 || operation==12){std::array<std::uint8_t,4> out{};put(out,operation==10?(value&1):((value>>1)&1),0,4);if(!memory_.write(r[1],out))return Fault::write;return done(0);}
        if(!memory_.accessible(address,8,a64::Permission::write))return Fault::write;
        if(operation==7)value=0;else if(operation==8)value=~std::uint64_t{0};
        else if(operation==9){if(input>1)return done(22);value=(value&~std::uint64_t{1})|input;}
        else if(operation==11){if(input>1)return done(22);value=(value&~std::uint64_t{2})|(std::uint64_t{input}<<1);}
        else return reject("Unknown pthread rwlock attribute operation");put(bytes,value);if(!memory_.write(address,bytes))return Fault::write;return done(0);
    }
    if(address%4)return reject("pthread rwlock is not four-byte aligned");std::array<std::uint8_t,56> bytes{};
    if(operation!=5 && !memory_.read(address,bytes))return Fault::read;if(!memory_.accessible(address,bytes.size(),a64::Permission::write))return Fault::write;auto found=held_.find(address);
    if(operation==5){if(found!=held_.end() || waiting_any(address))return done(16);std::uint64_t attr=0;if(r[1]){if(r[1]%8)return reject("pthread rwlock attribute is not LP64 aligned");std::array<std::uint8_t,8> value{};if(!memory_.read(r[1],value))return Fault::read;attr=get(value);}if(attr&~std::uint64_t{3})return done(22);if(attr&1)return reject("pthread process-shared rwlocks are unsupported");bytes[9]=static_cast<std::uint8_t>((attr>>1)&1);if(!memory_.write(address,bytes))return Fault::write;return done(0);}
    if(bytes[8] || bytes[9]>1)return reject("pthread rwlock shared or invalid preference state is unsupported");
    for(unsigned at=12;at<36;at+=4)if(get(bytes,at,4))return reject("pthread rwlock pending waiter state requires resumable native execution");
    const auto state=static_cast<std::uint32_t>(get(bytes,0,4)),writer=static_cast<std::uint32_t>(get(bytes,4,4));
    if(found!=held_.end()){const auto &held=found->second;const auto expected=held.writer?0x80000000U:held.total<<2;if(state!=expected || writer!=held.writer || bytes[9]!=static_cast<unsigned>(held.preference))return reject("pthread rwlock storage changed while owned");}
    else if(state || writer)return reject("pthread rwlock locked state has no runtime owner");
    if(!waiter_state_matches(address,bytes[9]!=0))return reject("pthread rwlock preference changed while a caller was waiting");
    if(operation==6){if(found!=held_.end() || waiting_any(address))return done(16);return done(0);}
    Held updated;if(found!=held_.end())updated=found->second;else updated.preference=bytes[9]!=0;
    if(operation==4){
        if(updated.writer){if(updated.writer!=tid)return done(1);updated.writer=0;}
        else {const auto owner=updated.readers.find(tid);if(owner==updated.readers.end()){if(!updated.total)return done(1);return reject("pthread rwlock read unlock without ownership is undefined and unsupported");}if(!--owner->second)updated.readers.erase(owner);--updated.total;}
    }else{
        const bool read=operation==0||operation==2,try_lock=operation==2||operation==3;
        if(updated.writer || (!read && updated.total) || (read && updated.preference && waiting_writer(address))){if(try_lock)return done(16);if(updated.writer==tid)return done(35);return reject("pthread rwlock contention requires resumable native execution");}
        if(read){if(updated.total==0x1fffffffU)return done(11);if(!updated.readers.contains(tid) && updated.readers.size()==64)return reject("pthread rwlock reader-owner limit reached");++updated.readers[tid];++updated.total;}
        else updated.writer=tid;
    }
    put(bytes,updated.writer?0x80000000U:updated.total<<2,0,4);put(bytes,updated.writer,4,4);
    if(!updated.writer && !updated.total){if(!memory_.write(address,bytes))return Fault::write;if(found!=held_.end())held_.erase(found);return done(0);}
    if(found!=held_.end()){if(!memory_.write(address,bytes))return Fault::write;found->second=std::move(updated);}
    else {if(held_.size()==1024)return reject("pthread held rwlock limit reached");held_.emplace(address,std::move(updated));if(!memory_.write(address,bytes)){held_.erase(address);return Fault::write;}}
    return done(0);
}
bool NativeRwLocks::waiting_any(Address address) const noexcept {
    for(const auto &waiter:waiters_)if(waiter.operation && waiter.address==address)return true;
    return false;
}
bool NativeRwLocks::waiting_writer(Address address) const noexcept {
    for(const auto &waiter:waiters_)if(waiter.operation && waiter.address==address && !waiter.read)return true;
    return false;
}
bool NativeRwLocks::waiter_state_matches(Address address,bool preference) const noexcept {
    for(const auto &waiter:waiters_)if(waiter.operation && waiter.address==address && waiter.preference!=preference)return false;
    return true;
}
bool NativeRwLocks::lock_ready(Address address,std::uint32_t tid,bool read) const noexcept {
    if(address%4)return true;
    std::array<std::uint8_t,56> bytes{};
    if(!memory_.read(address,bytes) || !memory_.accessible(address,bytes.size(),a64::Permission::write))return true;
    if(bytes[8] || bytes[9]>1 || !waiter_state_matches(address,bytes[9]!=0))return true;
    for(unsigned at=12;at<36;at+=4)if(get(bytes,at,4))return true;
    const auto state=static_cast<std::uint32_t>(get(bytes,0,4)),writer=static_cast<std::uint32_t>(get(bytes,4,4));
    const auto found=held_.find(address);
    if(found!=held_.end()){
        const auto &held=found->second;const auto expected=held.writer?0x80000000U:held.total<<2;
        if(state!=expected || writer!=held.writer || bytes[9]!=static_cast<unsigned>(held.preference))return true;
        if(held.writer)return held.writer==tid; // Immediate blocking EDEADLK for its own writer.
        if(!read && held.total)return false; // Includes an actual read-to-write self-deadlock.
    }else if(state || writer)return true;
    // NONRECURSIVE preference blocks even an existing reader once a writer waits.
    return !read || !bytes[9] || !waiting_writer(address);
}
struct NativeRwLocks::DeferredLock final : a64::DeferredService {
    NativeRwLocks &p;NativeThreads &threads;std::shared_ptr<ProcessState> process;
    Address address,tls,stack_top;std::uint32_t tid;std::uint64_t invocation;bool read;
    std::shared_ptr<a64::ThreadRegisterState> owner;
    std::size_t claim=waiter_limit;
    DeferredLock(NativeRwLocks &p,NativeThreads &threads,unsigned mode,const a64::ServiceState &frame,std::shared_ptr<ProcessState> process):
        p(p),threads(threads),process(std::move(process)),address(frame.registers[0]),tls(frame.trusted_tls),
        stack_top(frame.stack_top),tid(threads.tid()),invocation(frame.invocation),read(mode==0),owner(threads.thread_register_state(tls)){}
    ~DeferredLock() override {clear();}
    bool owns() const noexcept {
        if(claim>=p.waiters_.size())return false;
        const auto &waiter=p.waiters_[claim];
        return waiter.address==address && waiter.tid==tid && waiter.operation==this && waiter.owner==owner.get() && waiter.read==read;
    }
    void clear() noexcept {if(owns())p.waiters_[claim]={};claim=p.waiters_.size();}
    bool ready() const noexcept override {
        if(process->exit_status() || !threads.signal_snapshot(tid,owner) || (claim<p.waiters_.size() && !owns()))return true;
        return p.lock_ready(address,tid,read);
    }
    std::optional<std::chrono::steady_clock::time_point> deadline() const noexcept override {return {};}
    a64::DeferredServiceResult resume(a64::ServiceState &frame) noexcept override {
        const auto finish=[&](Fault fault,std::uint64_t code=0){clear();if(fault==Fault::none)frame.registers[0]=code;return a64::DeferredServiceResult{fault,true};};
        if(process->exit_status())return finish(Fault::process_exit);
        if(!owner || threads.tid()!=tid || threads.tls()!=tls || frame.trusted_tls!=tls || frame.invocation!=invocation ||
           frame.stack_top!=stack_top || threads.thread_register_state(tls)!=owner || !threads.signal_snapshot(tid,owner) ||
           (claim<p.waiters_.size() && !owns()))return finish(Fault::invalid_call);
        std::array<std::uint64_t,31> args{};args[0]=address;
        const auto fault=p.invoke(read?2:3,tid,args);
        if(fault!=Fault::none)return finish(fault);
        if(args[0]!=16)return finish(Fault::none,args[0]);
        const auto found=p.held_.find(address);
        if(found!=p.held_.end() && found->second.writer==tid)return finish(Fault::none,35);
        if(claim==p.waiters_.size()){
            // Readers can also wait solely behind a preferred pending writer
            // after the last holder has unlocked. Retain their lifetime claim.
            if(!read && found==p.held_.end())return finish(Fault::invalid_call);
            std::array<std::uint8_t,56> bytes{};
            if(!p.memory_.read(address,bytes))return finish(Fault::read);
            const bool preference=bytes[9]!=0;
            std::size_t slot=0;while(slot<p.waiters_.size() && p.waiters_[slot].operation)++slot;
            if(slot==p.waiters_.size()){
                p.rejection_="pthread waiting rwlock limit reached";return finish(Fault::unsupported_service);
            }
            p.waiters_[slot]={address,tid,this,owner.get(),preference,read};claim=slot;
        }
        // No iterator or borrowed storage is retained. Parking belongs to the
        // regular CPU boundary; cancellation retires only this waiter claim.
        return {Fault::none,false};
    }
};
Fault NativeRwLocks::invoke_lock(unsigned mode,a64::ServiceState &frame,NativeThreads &threads,bool allow_deferred,
                                std::shared_ptr<ProcessState> process) noexcept {
    if(mode>1 || !process)return Fault::invalid_call;
    if(!threads.factory_execution_active() || !allow_deferred)return invoke(mode,threads.tid(),frame.registers);
    if(!frame.invocation || frame.trusted_tls!=threads.tls() || frame.resume || frame.deferred ||
       !threads.signal_snapshot(threads.tid(),threads.thread_register_state(frame.trusted_tls)))return Fault::invalid_call;
    try {
        frame.deferred=std::make_shared<DeferredLock>(*this,threads,mode,frame,std::move(process));return Fault::none;
    }catch(...){rejection_="pthread rwlock continuation allocation failed";return Fault::unsupported_service;}
}
a64::Fault NativeRwLocks::invoke(unsigned operation,std::uint32_t tid,std::array<std::uint64_t,31>&r)noexcept{try{return call(operation,tid,r);}catch(...){rejection_="pthread rwlock host state allocation failed";return a64::Fault::unsupported_service;}}
}
