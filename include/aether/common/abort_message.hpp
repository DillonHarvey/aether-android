#pragma once
#include "aether/common/process_exit.hpp"
#include <string>

namespace aether {
// Presentation only: guest bytes never become a diagnostic code, format string,
// terminal control sequence, or an unmarked part of the trusted signal reason.
inline std::string guest_signal_diagnostic(const ProcessExit &exit){
    std::string result="AETHER_GUEST_SIGNAL: guest terminated abnormally by signal "+std::to_string(exit.signal);
    if(!exit.abort_message)return result;
    result+=" ; guest abort message (untrusted): \"";
    constexpr char hex[]="0123456789ABCDEF";
    for(const unsigned char byte:*exit.abort_message){
        if(byte=='\\' || byte=='\"'){
            result+='\\';result+=static_cast<char>(byte);
        }else if(byte>=0x20 && byte<=0x7e){
            result+=static_cast<char>(byte);
        }else{
            result+="\\x";result+=hex[byte>>4];result+=hex[byte&15];
        }
    }
    result+='\"';
    return result;
}
}
