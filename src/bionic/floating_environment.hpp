#pragma once
#include <cstdint>
#include <cerrno>
#include <cfenv>
#include <xmmintrin.h>
namespace aether::bionic {
class HostFloatingEnvironment {
  public:
    HostFloatingEnvironment() noexcept:saved_errno_(errno),saved_mxcsr_(_mm_getcsr()){
        saved_=std::fegetenv(&environment_)==0;
        if(!saved_)return;
        std::fenv_t held{};
        ready_=std::feholdexcept(&held)==0;
        if(!ready_)return;
        _mm_setcsr(_mm_getcsr()&~std::uint32_t{(1U<<15)|(1U<<6)});
        ready_=std::fesetround(FE_TONEAREST)==0;
        if(ready_)errno=0;
    }
    ~HostFloatingEnvironment(){restore();}
    bool ready() const noexcept{return ready_;}
    bool restore() noexcept{
        if(restored_)return restored_ok_;
        restored_=true;
        restored_ok_=!saved_ || std::fesetenv(&environment_)==0;
        _mm_setcsr(saved_mxcsr_);errno=saved_errno_;
        return restored_ok_;
    }
  private:
    std::fenv_t environment_{};
    int saved_errno_;
    unsigned saved_mxcsr_;
    bool saved_=false,ready_=false,restored_=false,restored_ok_=false;
};
}
