#include "aether/host/entropy.hpp"
#include <algorithm>
#include <limits>
#include <windows.h>
#include <bcrypt.h>
namespace aether::host {
bool secure_random(std::span<std::uint8_t> output) noexcept {
    if(output.empty())return true;
    if(output.size()>std::numeric_limits<ULONG>::max()){std::fill(output.begin(),output.end(),std::uint8_t{});return false;}
    const auto status=BCryptGenRandom(nullptr,output.data(),static_cast<ULONG>(output.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if(status!=0){std::fill(output.begin(),output.end(),std::uint8_t{});return false;}
    return true;
}
bool secure_random_128(std::span<std::uint8_t,16> output) noexcept {
    return secure_random(output);
}
} // namespace aether::host
