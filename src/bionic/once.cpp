#include "once.hpp"
#include "threads.hpp"
#include "aether/common/thread_exit.hpp"
#include <utility>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
std::uint32_t control_value(const std::array<std::uint8_t,4> &bytes) noexcept {
    std::uint32_t value=0;
    for(unsigned i=0;i<bytes.size();++i)value|=std::uint32_t{bytes[i]}<<(8*i);
    return value;
}
constexpr std::array<std::uint8_t,4> underway{1,0,0,0},complete{2,0,0,0};
}

void NativeOnce::runner(GuestPosixServices::OnceRunner value){runner_=std::move(value);}

Fault NativeOnce::invoke(a64::ServiceState &state,bool full_frame) noexcept {
    Record *claimed=nullptr;
    const auto reject=[&](std::string_view reason,Fault fault=Fault::unsupported_service){
        rejection_=reason;
        if(claimed)claimed->failure=reason;
        return fault;
    };
    try {
        const Address control=state.registers[0],initializer=state.registers[1];
        if(!app_.process_state)return reject("pthread_once: process state is unavailable");
        if(app_.process_state->exit_status())return reject("pthread_once: process has terminated",Fault::process_exit);
        if(control%4)return reject("pthread_once: control is not 4-byte aligned");
        // Runtime ownership wins over a guest-forged completed control word.
        for(const auto &record:records_)if(record.occupied && record.control==control){
            if(!record.running)return reject(record.failure.empty()?"pthread_once: initializer was abandoned; retry is unsupported":record.failure);
            if(record.owner==threads_.tid() && record.tls==threads_.tls())return reject("pthread_once: recursive initialization would deadlock");
            return reject("pthread_once: initializer belongs to a suspended logical thread; resumable contention is unsupported");
        }
        std::array<std::uint8_t,4> bytes{};
        if(!memory_.read(control,bytes))return reject("pthread_once: control is not readable",Fault::read);
        const auto value=control_value(bytes);
        if(value==2){state.registers[0]=0;rejection_={};return Fault::none;}
        if(value==1)return reject("pthread_once: underway control has no runtime initializer owner");
        if(value!=0)return reject("pthread_once: control has an invalid state");
        if(!memory_.accessible(control,bytes.size(),a64::Permission::write))return reject("pthread_once: control is not writable",Fault::write);
        if(initializer%4 || !memory_.accessible(initializer,4,a64::Permission::execute))return reject("pthread_once: initializer is not aligned executable guest code",Fault::execute);
        if(!full_frame)return reject("pthread_once: initialization requires a trusted full guest frame");
        const auto stack=state.stack_pointer;
        if(stack<16 || stack%16 || !memory_.accessible(stack-16,16,a64::Permission::write))return reject("pthread_once: active guest stack is not aligned and writable",Fault::write);
        if(!runner_)return reject("pthread_once: no owned initializer runner");
        Record *available=nullptr;
        for(auto &record:records_)if(!record.occupied){available=&record;break;}
        if(!available || depth_==records_.size())return reject("pthread_once: active and abandoned initializer limit reached");
        const auto mapping=memory_.mapping(control);
        if(!mapping)return reject("pthread_once: control mapping is unavailable",Fault::read);
        const auto owner=threads_.tid();
        const auto tls=threads_.tls();
        if(threads_.exit_value(tls))return reject("pthread_once: logical thread has terminated",Fault::thread_exit);
        // Copy before publishing state 1; nested callbacks may replace the runner.
        const auto callback=runner_;
        *available={control,tls,mapping->address,mapping->size,mapping->permissions,owner,depth_+1,true,true,{}};
        if(!memory_.write(control,underway)){
            *available={};
            return reject("pthread_once: control write failed before initialization",Fault::write);
        }
        claimed=available;
        ++depth_;
        struct CallbackScope {
            Record &record;unsigned &depth;
            ~CallbackScope(){record.running=false;--depth;}
        } scope{*claimed,depth_};
        const auto result=callback(initializer,stack,tls,1'000'000);
        if(app_.process_state->exit_status())return reject("pthread_once: initializer terminated the process",Fault::process_exit);
        if(threads_.exit_value(tls))return reject("pthread_once: initializer terminated its logical thread",Fault::thread_exit);
        if(result.fault!=Fault::none)return reject("pthread_once: initializer execution failed; completion was not published",result.fault);
        if(!result.returned)return reject("pthread_once: initializer did not return; completion was not published",Fault::invalid_call);
        if(threads_.tid()!=owner || threads_.tls()!=tls)return reject("pthread_once: initializer did not restore its logical thread binding");
        // Mapping metadata has no backing identity: an identical remap restoring
        // state 1 cannot be distinguished from the original live guest mapping.
        const auto after=memory_.mapping(control);
        if(!after)return reject("pthread_once: initializer removed the control mapping",Fault::read);
        if(after->address!=claimed->mapping_base || after->size!=claimed->mapping_size)return reject("pthread_once: initializer changed the control mapping bounds");
        if(!memory_.read(control,bytes))return reject("pthread_once: initializer made its control unreadable",Fault::read);
        if(control_value(bytes)!=1)return reject("pthread_once: initializer modified its underway control");
        if(!memory_.accessible(control,bytes.size(),a64::Permission::write))return reject("pthread_once: initializer made its control unwritable",Fault::write);
        if(after->permissions!=claimed->permissions)return reject("pthread_once: initializer changed the control mapping permissions");
        if(!memory_.write(control,complete))return reject("pthread_once: completion control write failed",Fault::write);
        *claimed={};
        claimed=nullptr;
        state.registers[0]=0;
        rejection_={};
        return Fault::none;
    }catch(const ThreadExit &exit){
        threads_.request_exit(exit.value);
        return reject("pthread_once: initializer exited its logical thread",Fault::thread_exit);
    }catch(const ProcessExit &exit){
        if(app_.process_state){if(exit.signal)app_.process_state->request_signal(exit.signal);else app_.process_state->request_exit(exit.status);}
        return reject("pthread_once: initializer exited the process",Fault::process_exit);
    }catch(...){
        return reject(claimed?"pthread_once: initializer runner raised an exception; completion was not published":"pthread_once: initializer preparation raised an exception",Fault::windows_service);
    }
}
}
