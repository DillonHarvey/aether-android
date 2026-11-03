#include "runtime_services.hpp"
#include "floating_environment.hpp"
#include "threads.hpp"
#include "thread_attributes.hpp"
#include "descriptors.hpp"
#include "aether/host/process_info.hpp"
#include <Windows.h>
#include <algorithm>
#include <bit>
#include <cfenv>
#include <cmath>
#include <cerrno>
#include <cstring>
#if defined(_MSC_VER)
#pragma float_control(precise,on,push)
#pragma fenv_access(on)
#endif
namespace aether::bionic {
namespace {
constexpr a64::Address host_errors_base=0x3f800000;
template<std::size_t N> std::array<std::uint8_t,N> bytes(std::uint64_t value) {
    std::array<std::uint8_t,N> output{};for(unsigned i=0;i<N;++i)output[i]=static_cast<std::uint8_t>(value>>(8*i));return output;
}
std::uint64_t word(std::span<const std::uint8_t> input) {
    std::uint64_t value=0;for(unsigned i=0;i<input.size();++i)value|=std::uint64_t{input[i]}<<(8*i);return value;
}
}
NativeRuntimeServices::NativeRuntimeServices(a64::GuestMemory &m,NativeThreads &t,NativeDescriptors &d,const a64::AppContext &a)
    :memory_(m),threads_(t),descriptors_(d),app_(a){}
NativeRuntimeServices::~NativeRuntimeServices(){if(host_errors_owned_)try{memory_.unmap(host_errors_base);}catch(...){}}
a64::Address NativeRuntimeServices::host_error() {
    const auto tls=threads_.tls();const auto owner=threads_.thread_register_state(tls);
    if(!owner)return 0;
    for(std::size_t i=0;i<host_errors_.size();++i)
        if(host_errors_[i].tls==tls && host_errors_[i].owner.lock()==owner)return host_errors_base+i*4;
    for(std::size_t i=0;i<host_errors_.size();++i)if(host_errors_[i].owner.expired()){
        if(!host_errors_owned_){memory_.map(host_errors_base,4096,a64::read_write);host_errors_owned_=true;}
        if(!memory_.write(host_errors_base+i*4,bytes<4>(0)))return 0;
        host_errors_[i]={owner,tls};return host_errors_base+i*4;
    }
    return 0;
}
a64::Fault NativeRuntimeServices::invoke(RuntimeOperation operation,a64::ServiceState &state,bool full) noexcept {
    using a64::Fault;auto &r=state.registers;rejection_={};
    if(owner_!=std::this_thread::get_id() || !app_id_ || app_.instance_id!=app_id_){rejection_="runtime service: foreign owner";return Fault::invalid_call;}
    const auto fail=[&](unsigned code,bool pointer=false){if(!memory_.write(threads_.error_address(),bytes<4>(code)))return Fault::write;r[0]=pointer?0:UINT64_MAX;return Fault::none;};
    const auto unsupported=[&](std::string_view reason){rejection_=reason;return Fault::unsupported_service;};
    try {
        switch(operation){
        case RuntimeOperation::socket_create:return fail(13);
        case RuntimeOperation::socket_operation:
            return fail(descriptors_.contains(std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[0])))?88:9);
        case RuntimeOperation::address_lookup:case RuntimeOperation::name_lookup:
            // Bionic EAI_SYSTEM is positive 11, unlike the glibc constant.
            if(!memory_.write(threads_.error_address(),bytes<4>(13)))return Fault::write;
            r[0]=11;return Fault::none;
        case RuntimeOperation::host_lookup:{
            const auto address=host_error();if(!address)return unsupported("gethostbyname: owned h_errno storage unavailable");
            if(!memory_.write(address,bytes<4>(3)))return Fault::write; // NO_RECOVERY: resolver capability denied.
            return fail(13,true);
        }
        case RuntimeOperation::host_error:{const auto address=host_error();if(!address)return unsupported("__get_h_errno: owned logical-thread storage unavailable");r[0]=address;return Fault::none;}
        case RuntimeOperation::free_addresses:
            if(!r[0])return Fault::none;
            return unsupported("freeaddrinfo: no owned resolver result exists in the network-denied runtime");
        case RuntimeOperation::ioctl:{
            const auto fd=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[0]));
            if(!descriptors_.contains(fd))return fail(9);
            if(r[1]==0x5421){ // FIONBIO operates on the actual shared open description.
                std::array<std::uint8_t,4> input{};if(!memory_.read(r[2],input))return fail(14);
                const auto old=descriptors_.control(fd,3,0);if(old.error!=host::FileError::none)return fail(25);
                const auto flags=word(input)?static_cast<std::uint64_t>(old.value)|0x800U:static_cast<std::uint64_t>(old.value)&~std::uint64_t{0x800};
                const auto changed=descriptors_.control(fd,4,flags);if(changed.error!=host::FileError::none)return fail(25);
                r[0]=0;return Fault::none;
            }
            return fail(25); // No tty/socket driver owns a private-file ioctl.
        }
        case RuntimeOperation::lock_memory:return fail(95); // No host working-set-lock capability is exposed.
        case RuntimeOperation::advise_memory:return unsupported("madvise: this runtime has no implemented backing advice consumer");
        case RuntimeOperation::query_schedule:{
            NativeThreadOptions options;a64::Address base=0;
            const auto result=threads_.query(r[0],options,base);
            if((result!=0 && result!=95) || !r[0] || r[0]>UINT32_MAX || !threads_.signal_target(static_cast<std::uint32_t>(r[0]))){r[0]=3;return Fault::none;}
            if(!memory_.accessible(r[1],4,a64::Permission::write)||!memory_.accessible(r[2],4,a64::Permission::write)){r[0]=14;return Fault::none;}
            // Owned native logical threads have only SCHED_OTHER/priority zero;
            // the existing nice service is independent of this realtime class.
            if(!memory_.write(r[1],bytes<4>(0))||!memory_.write(r[2],bytes<4>(0)))return Fault::write;
            r[0]=0;return Fault::none;
        }
        case RuntimeOperation::query_affinity:case RuntimeOperation::set_affinity:{
            const auto pid=static_cast<std::uint32_t>(r[0]);
            if(pid && pid!=host::current_process_id() && pid!=threads_.tid())return fail(3);
            if(r[1]<8 || r[1]>128)return fail(22);
            GROUP_AFFINITY affinity{};DWORD_PTR process_mask=0,system_mask=0;
            if(!GetThreadGroupAffinity(GetCurrentThread(),&affinity)||affinity.Group!=0 ||
               !GetProcessAffinityMask(GetCurrentProcess(),&process_mask,&system_mask))return fail(95);
            const auto actual=static_cast<std::uint64_t>(affinity.Mask & process_mask);
            if(!actual)return fail(95);
            std::array<std::uint8_t,128> mask{};
            if(operation==RuntimeOperation::set_affinity){
                if(!memory_.read(r[2],std::span(mask).first(static_cast<std::size_t>(r[1]))))return fail(14);
                if(word(std::span<const std::uint8_t>(mask).first(8))!=actual ||
                   std::any_of(mask.begin()+8,mask.begin()+static_cast<std::size_t>(r[1]),[](auto byte){return byte!=0;}))return fail(95);
            }else{
                const auto value=bytes<8>(actual);std::copy(value.begin(),value.end(),mask.begin());
                if(!memory_.write(r[2],std::span<const std::uint8_t>(mask).first(static_cast<std::size_t>(r[1]))))return fail(14);
            }
            r[0]=0;return Fault::none;
        }
        case RuntimeOperation::clock_ticks:{
            if(!app_.monotonic_time_allowed)return fail(13);
            FILETIME create{},exit{},kernel{},user{};
            if(!GetProcessTimes(GetCurrentProcess(),&create,&exit,&kernel,&user))return fail(5);
            const auto a=(std::uint64_t{kernel.dwHighDateTime}<<32)|kernel.dwLowDateTime;
            const auto b=(std::uint64_t{user.dwHighDateTime}<<32)|user.dwLowDateTime;
            if(b>UINT64_MAX-a || (a+b)/10>INT64_MAX)return fail(75);
            r[0]=(a+b)/10;return Fault::none; // Android CLOCKS_PER_SEC=1,000,000.
        }
        case RuntimeOperation::scale_double:{
            if(!full)return unsupported("ldexp: floating result requires the actual full guest frame");
            if(state.fpcr)return unsupported("ldexp: nondefault guest floating control is unsupported");
            double input=0;std::memcpy(&input,state.vectors[0].data(),8);
            const auto exponent=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[0]));
            HostFloatingEnvironment environment;
            if(!environment.ready())return unsupported("ldexp: host floating environment unavailable");
            const auto output=std::ldexp(input,exponent);const auto raised=fetestexcept(FE_ALL_EXCEPT);const auto range=errno==ERANGE;
            if(!environment.restore())return unsupported("ldexp: floating environment restoration failed");
            if(range && !memory_.write(threads_.error_address(),bytes<4>(34)))return Fault::write;
            std::memcpy(state.vectors[0].data(),&output,8);
            if(raised&FE_INVALID)state.fpsr|=1;if(raised&FE_DIVBYZERO)state.fpsr|=2;
            if(raised&FE_OVERFLOW)state.fpsr|=4;if(raised&FE_UNDERFLOW)state.fpsr|=8;if(raised&FE_INEXACT)state.fpsr|=16;
            return Fault::none;
        }
        case RuntimeOperation::control_message:{
            std::array<std::uint8_t,56> message{};if(!memory_.read(r[0],message))return Fault::read;
            const auto control=word(std::span<const std::uint8_t>(message).subspan(32,8));
            const auto length=word(std::span<const std::uint8_t>(message).subspan(40,8));
            const auto current=r[1];r[0]=0;
            if(length>1024*1024 || control>=a64::GuestMemory::address_limit || length>a64::GuestMemory::address_limit-control ||
               current<control || current-control>length || length-(current-control)<16)return Fault::none;
            std::array<std::uint8_t,8> header{};if(!memory_.read(current,header))return Fault::read;
            const auto size=word(header);if(size<16 || size>UINT64_MAX-7)return Fault::none;
            const auto step=(size+7)&~std::uint64_t{7};if(step>length-(current-control) || length-(current-control)-step<16)return Fault::none;
            const auto next=current+step;if(!memory_.read(next,header))return Fault::read;
            const auto next_size=word(header);if(next_size<16 || next_size>length-(next-control))return Fault::none;
            r[0]=next;return Fault::none;
        }
        case RuntimeOperation::set_times:return unsupported("utimes: actual private-file timestamp mutation is not implemented");
        case RuntimeOperation::filesystem_status:return unsupported("statfs: actual private-volume statistics are not implemented");
        case RuntimeOperation::path_configuration:return unsupported("pathconf: path-bound configuration observation is not implemented");
        case RuntimeOperation::clock_sleep:return unsupported("clock_nanosleep: clock-specific owned wait adapter is not implemented");
        case RuntimeOperation::change_mode:return unsupported("chmod: path-bound private permission mutation is not implemented");
        case RuntimeOperation::directory_fd:return unsupported("dirfd: the directory snapshot does not own a descriptor capability");
        }
    }catch(...){return unsupported("runtime service: bounded host marshalling failed");}
    return unsupported("runtime service: invalid operation");
}
}

#if defined(_MSC_VER)
#pragma float_control(pop)
#endif
