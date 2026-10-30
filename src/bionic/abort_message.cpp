#include "abort_message.hpp"
#include <new>
#include <string>
#include <utility>

namespace aether::bionic {
a64::Fault NativeAbortMessage::invoke(std::array<std::uint64_t,31> &registers) noexcept {
    using a64::Fault;
    rejection_={};
    try {
        const auto process=app_.process_state;
        if(!process){rejection_="android_set_abort_message: app process state is unavailable";return Fault::unsupported_service;}
        if(process->exit_status()){rejection_="android_set_abort_message: app process has terminated";return Fault::process_exit;}
        // The first successful message wins, including an empty string. Do not
        // inspect any later argument or logical errno after that publication.
        if(process->abort_message())return Fault::none;
        const auto pointer=registers[0];
        if(!pointer){process->set_abort_message("(null)");return Fault::none;}
        std::string value;
        constexpr std::size_t limit=4096; // Includes the required terminating NUL.
        for(std::size_t offset=0;offset<limit;++offset){
            if(pointer>=a64::GuestMemory::address_limit || offset>=a64::GuestMemory::address_limit-pointer){
                rejection_="android_set_abort_message: guest string address overflow";return Fault::read;
            }
            std::array<std::uint8_t,1> byte{};
            if(!memory_.read(pointer+offset,byte)){
                rejection_="android_set_abort_message: unreadable guest string";return Fault::read;
            }
            if(!byte[0]){process->set_abort_message(std::move(value));return Fault::none;}
            value.push_back(static_cast<char>(byte[0]));
        }
        rejection_="android_set_abort_message: string exceeds 4096 byte profile including NUL";
        return Fault::unsupported_service;
    }catch(const std::bad_alloc &){
        // Explicit Aether allocation-failure profile: like Bionic's failed
        // backing allocation, leave the message unset so a later call may win.
        // This void setter neither changes guest registers nor logical errno.
        return Fault::none;
    }catch(...){
        rejection_="android_set_abort_message: host message capture failed";
        return Fault::windows_service;
    }
}
}
