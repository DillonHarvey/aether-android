#pragma once
#include "aether/common/process_exit.hpp"
#include <string>

namespace aether {
// Presentation only: guest bytes never become a diagnostic code, format string,
// terminal control sequence, or an unmarked part of the trusted signal reason.
inline std::string guest_signal_diagnostic(const ProcessExit &exit){
    // Worker errors have a 512-byte wire quota. Oversized errors retain their
    // first 128 bytes and a tail, so put actual fault, initializer and abort
    // caller identities before module prefixes and expanded register details.
    std::string result="AETHER_GUEST_SIGNAL: signal="+std::to_string(exit.signal);
    constexpr char hex[]="0123456789ABCDEF";
    constexpr std::array<const char*,9> heap_reasons{"request_limit","object_limit","alignment","commit_limit","placement",
        "host_bad_alloc","mapping_rejected","host_mapping_alloc","mapping_other"};
    const auto hexadecimal=[&](std::uint64_t value){
        result+="0x";bool started=false;
        for(int shift=60;shift>=0;shift-=4){
            const auto digit=static_cast<unsigned>((value>>shift)&15);
            if(digit || started || !shift){result+=hex[digit];started=true;}
        }
    };
    const auto escaped=[&](unsigned char byte){
        if(byte=='\\' || byte=='\"'){result+='\\';result+=static_cast<char>(byte);}
        else if(byte>=0x20 && byte<=0x7e)result+=static_cast<char>(byte);
        else{result+="\\x";result+=hex[byte>>4];result+=hex[byte&15];}
    };
    if(exit.fault){
        const auto &fault=*exit.fault;
        result+=" pc=";hexadecimal(fault.pc);
        result+=" addr=";hexadecimal(fault.has_memory_failure?fault.memory_address:fault.address);
        constexpr std::array<const char*,9> kinds{"read","write","exec","undef","break","align","sp_align","dcache","icache"};
        result+=" kind=";
        if(fault.kind<kinds.size())result+=kinds[fault.kind];else hexadecimal(fault.kind);
    }
    if(exit.initializer){
        const auto &context=*exit.initializer;
        result+=context.finalizer?" fini=":" init=";hexadecimal(context.entry);
    }
    if(exit.abort_context){
        result+=" abort_lr=";hexadecimal(exit.abort_context->lr);
    }
    if(exit.signal==6 && exit.heap_failure){
        const auto reason=static_cast<std::uint32_t>(exit.heap_failure->reason);
        result+=" heap_last=";
        if(reason && reason<=heap_reasons.size())result+=heap_reasons[reason-1];else hexadecimal(reason);
        result+=" n="+std::to_string(exit.heap_failure->requested);
    }
    if(exit.initializer){
        const auto &context=*exit.initializer;
        result+=" mod_prefix=\"";
        std::size_t length=0;
        while(length<48 && context.module[length]){
            const auto byte=static_cast<unsigned char>(context.module[length]);
            const std::size_t width=byte=='\\' || byte=='\"'?2:byte>=0x20 && byte<=0x7e?1:4;
            if(result.size()+width+2>128)break; // Reserve the closing quote and a prefix marker.
            escaped(byte);++length;
        }
        if(length==48 || context.module[length])result+='~';
        result+='\"';
    }
    if(exit.fault){
        const auto &fault=*exit.fault;
        result+=" sync code="+std::to_string(fault.signal_code);
        result+=" sub=";hexadecimal(fault.subtype); // Raw source subtype, never labeled ESR.
        result+=" n="+std::to_string(fault.access_bytes);
        if(fault.has_memory_failure){
            constexpr std::array<const char*,3> failures{"invalid","unmapped","protection"};
            result+=" mem=";
            if(fault.memory_kind<failures.size())result+=failures[fault.memory_kind];else hexadecimal(fault.memory_kind);
            result+=" perm=";hexadecimal(fault.permission);
        }
        result+=" sp=";hexadecimal(fault.sp);
        result+=" lr=";hexadecimal(fault.registers[30]);
        result+=" regs_subset:";
        for(const auto index:std::array<unsigned,7>{0,1,8,9,16,17,19}){
            result+=" x"+std::to_string(index)+"=";hexadecimal(fault.registers[index]);
        }
    }
    if(exit.abort_context){
        const auto &context=*exit.abort_context;
        result+=" abort_service pc=";hexadecimal(context.pc);
        result+=" sp=";hexadecimal(context.sp);
        result+=" regs_subset:";
        constexpr std::array<unsigned,4> indices{0,1,8,19};
        for(std::size_t i=0;i<indices.size();++i){
            result+=" x"+std::to_string(indices[i])+"=";hexadecimal(context.registers[i]);
        }
        if(context.has_errno)result+=" logical_errno="+std::to_string(context.logical_errno);
    }
    if(exit.signal==6 && exit.heap_failure){
        const auto &failure=*exit.heap_failure;
        const auto reason=static_cast<std::uint32_t>(failure.reason);
        result+=" last_owned_heap_failure(observation)=";
        if(reason && reason<=heap_reasons.size())result+=heap_reasons[reason-1];else hexadecimal(reason);
        result+=" stage="+std::to_string(static_cast<std::uint32_t>(failure.stage));
        result+=" request="+std::to_string(failure.requested)+" align="+std::to_string(failure.alignment);
        result+=" live="+std::to_string(failure.live_objects)+" backings="+std::to_string(failure.live_backings);
        result+=" requested_live="+std::to_string(failure.live_requested)+" capacity_live="+std::to_string(failure.live_capacity);
        result+=" commit="+std::to_string(failure.committed)+" mapped="+std::to_string(failure.guest_mapped);
        result+=" new_backing="+std::to_string(failure.new_backing);
    }
    if(!exit.abort_message)return result;
    result+=" ; guest abort message (untrusted): \"";
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
