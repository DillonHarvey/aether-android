#include "math_services.hpp"
#include "floating_environment.hpp"
#include "threads.hpp"
#include <array>
#include <bit>
#include <cerrno>
#include <cfenv>
#include <cmath>
#include <xmmintrin.h>

#if defined(_MSC_VER)
#pragma float_control(precise,on,push)
#pragma fenv_access(on)
#endif

namespace aether::bionic {
namespace {
constexpr std::array<std::string_view,35> operation_names{
    "atan2f","sincosf","tanf","fmodf","pow","log10f","powf","log10","modf","frexp",
    "log2","fmod","acos","asin","atan","cos","exp","log","sin","tan","atan2",
    "exp2","sinf","cosf","asinf","acosf","modff","expf","logf","exp2f","cosh",
    "sincos","sinh","tanh","hypotf"
};
// Preserve the host's complete environment, including x64's nonstandard DAZ
// and FTZ controls, independently of the guest's cumulative FPSR bits. CRT
// errno is host TLS and must never leak into or out of the emulated call.
template<std::size_t N> std::array<std::uint8_t,N> little(std::uint64_t value){
    std::array<std::uint8_t,N> output{};
    for(unsigned i=0;i<N;++i)output[i]=static_cast<std::uint8_t>(value>>(8*i));
    return output;
}
std::uint32_t status_flags(int flags) noexcept{
    return ((flags&FE_INVALID)?1U:0U)|((flags&FE_DIVBYZERO)?2U:0U)|
        ((flags&FE_OVERFLOW)?4U:0U)|((flags&FE_UNDERFLOW)?8U:0U)|((flags&FE_INEXACT)?16U:0U);
}
}
std::span<const std::string_view> NativeMathServices::names() noexcept{return operation_names;}
a64::Fault NativeMathServices::invoke(unsigned operation,a64::ServiceState &state,bool full) noexcept{
    using a64::Fault;
    rejection_={};
    if(!full){rejection_="libm: full authenticated FP register frame required";return Fault::unsupported_service;}
    if(operation>=operation_names.size()){rejection_="libm: unknown math operation";return Fault::unsupported_service;}
    // UCRT does not establish directed-rounding accuracy for all admitted
    // transcendental functions. Do not substitute nearest results for those
    // modes, or approximate ARM's flush/default-NaN/trap behavior.
    if(state.fpcr){rejection_="libm: only nearest rounding with gradual underflow, payload NaNs and masked FP exceptions is supported";return Fault::unsupported_service;}
    try{
        const bool single=operation==0 || operation==1 || operation==2 || operation==3 || operation==5 || operation==6 ||
            (operation>=22 && operation<=29) || operation==34;
        const bool pair=operation==1 || operation==31;
        const bool integral=operation==8 || operation==26;
        const bool exponent=operation==9;
        const auto width=single?4U:8U;
        const auto first=state.registers[0],second=state.registers[1];
        // Prove the entire output set before invoking math or exposing any
        // fraction, exponent, sin/cos prefix, errno or FP status change.
        if((pair || integral || exponent) && !memory_.accessible(first,exponent?4:width,a64::Permission::write))return Fault::write;
        if(pair && !memory_.accessible(second,width,a64::Permission::write))return Fault::write;
        const auto error=threads_.error_address();
        if(!memory_.accessible(error,4,a64::Permission::write))return Fault::write;
        const auto x=std::bit_cast<double>(state.vectors[0][0]),y=std::bit_cast<double>(state.vectors[1][0]);
        const auto xf=std::bit_cast<float>(static_cast<std::uint32_t>(state.vectors[0][0]));
        const auto yf=std::bit_cast<float>(static_cast<std::uint32_t>(state.vectors[1][0]));
        double result=0,extra=0;float resultf=0,extraf=0;int power=0;
        HostFloatingEnvironment environment;
        if(!environment.ready()){rejection_="libm: host floating-point environment unavailable";return Fault::unsupported_service;}
        switch(operation){
        case 0:resultf=std::atan2(xf,yf);break;
        case 1:resultf=std::sin(xf);extraf=std::cos(xf);break;
        case 2:resultf=std::tan(xf);break;
        case 3:resultf=std::fmod(xf,yf);break;
        case 4:result=std::pow(x,y);break;
        case 5:resultf=std::log10(xf);break;
        case 6:resultf=std::pow(xf,yf);break;
        case 7:result=std::log10(x);break;
        case 8:result=std::modf(x,&extra);break;
        case 9:result=std::frexp(x,&power);break;
        case 10:result=std::log2(x);break;
        case 11:result=std::fmod(x,y);break;
        case 12:result=std::acos(x);break;
        case 13:result=std::asin(x);break;
        case 14:result=std::atan(x);break;
        case 15:result=std::cos(x);break;
        case 16:result=std::exp(x);break;
        case 17:result=std::log(x);break;
        case 18:result=std::sin(x);break;
        case 19:result=std::tan(x);break;
        case 20:result=std::atan2(x,y);break;
        case 21:result=std::exp2(x);break;
        case 22:resultf=std::sin(xf);break;
        case 23:resultf=std::cos(xf);break;
        case 24:resultf=std::asin(xf);break;
        case 25:resultf=std::acos(xf);break;
        case 26:resultf=std::modf(xf,&extraf);break;
        case 27:resultf=std::exp(xf);break;
        case 28:resultf=std::log(xf);break;
        case 29:resultf=std::exp2(xf);break;
        case 30:result=std::cosh(x);break;
        case 31:result=std::sin(x);extra=std::cos(x);break;
        case 32:result=std::sinh(x);break;
        case 33:result=std::tanh(x);break;
        case 34:resultf=std::hypot(xf,yf);break;
        default:return Fault::invalid_call;
        }
        const auto exceptions=std::fetestexcept(FE_ALL_EXCEPT);
        const auto math_error=errno;
        if(!environment.restore()){rejection_="libm: host floating-point environment restoration failed";return Fault::windows_service;}
        const auto result_bits=single?std::uint64_t{std::bit_cast<std::uint32_t>(resultf)}:std::bit_cast<std::uint64_t>(result);
        const auto extra_bits=single?std::uint64_t{std::bit_cast<std::uint32_t>(extraf)}:std::bit_cast<std::uint64_t>(extra);
        if(exponent){if(!memory_.write(first,little<4>(static_cast<std::uint32_t>(power))))return Fault::write;}
        else if(pair || integral){
            const auto bits=pair?result_bits:extra_bits;
            const auto bytes=little<8>(bits);
            if(!memory_.write(first,std::span<const std::uint8_t>(bytes).first(width)))return Fault::write;
        }
        if(pair){const auto bytes=little<8>(extra_bits);if(!memory_.write(second,std::span<const std::uint8_t>(bytes).first(width)))return Fault::write;}
        if(math_error==EDOM || math_error==ERANGE){
            if(!memory_.write(error,little<4>(math_error==EDOM?33:34)))return Fault::write;
        }
        state.fpsr|=status_flags(exceptions);
        // sincos has no FP return; its two actual pointer outputs are the result.
        if(!pair)state.vectors[0]={result_bits,0};
        return Fault::none;
    }catch(...){rejection_="libm: owned math service failed";return Fault::windows_service;}
}
}
#if defined(_MSC_VER)
#pragma float_control(pop)
#endif
