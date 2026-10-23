#include "properties.hpp"
#include "aether/android/profile.hpp"
#include <array>
#include <charconv>
#include <string_view>
namespace aether::bionic {
a64::Fault get_system_property(a64::GuestMemory &memory,std::array<std::uint64_t,31> &r) noexcept {
    // Original bounded bridge. No host environment, registry or property service.
    std::array<char,1024> name{};std::size_t length=0;
    for(;length<name.size();++length){
        if(r[0]>=a64::GuestMemory::address_limit || length>=a64::GuestMemory::address_limit-r[0])return a64::Fault::read;
        std::array<std::uint8_t,1> byte{};if(!memory.read(r[0]+length,byte))return a64::Fault::read;
        name[length]=static_cast<char>(byte[0]);if(!byte[0])break;
    }
    if(length==name.size())return a64::Fault::unsupported_service;
    std::array<char,92> value{};std::size_t size=0;
    if(std::string_view(name.data(),length)=="ro.build.version.sdk"){
        const auto result=std::to_chars(value.data(),value.data()+value.size()-1,android::compatibility_sdk);
        if(result.ec!=std::errc{})return a64::Fault::windows_service;
        size=static_cast<std::size_t>(result.ptr-value.data());
    }
    // Missing properties follow Bionic's empty-string/zero-length contract.
    // ro.arch and device identities are absent: no Android hardware is emulated.
    if(!memory.write(r[1],{reinterpret_cast<const std::uint8_t*>(value.data()),size+1}))return a64::Fault::write;
    r[0]=size;return a64::Fault::none;
}
}
