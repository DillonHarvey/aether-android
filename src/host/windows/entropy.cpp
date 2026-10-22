#include "aether/host/entropy.hpp"
#include <algorithm>
#include <windows.h>
#include <bcrypt.h>
namespace aether::host {
bool secure_random_128(std::span<std::uint8_t,16> output) noexcept {
    const auto status=BCryptGenRandom(nullptr,output.data(),16,BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if(status!=0){std::fill(output.begin(),output.end(),std::uint8_t{});return false;}
    return true;
}
} // namespace aether::host
