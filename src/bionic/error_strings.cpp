#include "error_strings.hpp"
#include "threads.hpp"
#include "thread_attributes.hpp"
#include <algorithm>
#include <bit>
#include <charconv>

// Aether's lookup, guest storage and formatting implementation below are original.
// Description data is adapted from Android Bionic's bionic_errdefs.h, BSD-2-Clause:
// https://android.googlesource.com/platform/bionic/+/731631f300090436d7f5df80d50b6275c8c60a93/libc/private/bionic_errdefs.h
// Source SHA-256: 20adad662c5df1b785d28396b96b7509e1179a45d4c8957c5211682fb077e050
// The numeric ARM64 ABI is asm-generic errno-base.h/errno.h; 41 and 58 are holes.
/*
 * Copyright (C) 2023 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
namespace aether::bionic {
namespace {
constexpr std::array<std::string_view,134> descriptions{
    "Success", "Operation not permitted", "No such file or directory", "No such process",
    "Interrupted system call", "I/O error", "No such device or address", "Argument list too long",
    "Exec format error", "Bad file descriptor", "No child processes", "Try again", "Out of memory",
    "Permission denied", "Bad address", "Block device required", "Device or resource busy", "File exists",
    "Cross-device link", "No such device", "Not a directory", "Is a directory", "Invalid argument",
    "File table overflow", "Too many open files", "Inappropriate ioctl for device", "Text file busy",
    "File too large", "No space left on device", "Illegal seek", "Read-only file system", "Too many links",
    "Broken pipe", "Math argument out of domain of func", "Math result not representable",
    "Resource deadlock would occur", "File name too long", "No record locks available",
    "Function not implemented", "Directory not empty", "Too many symbolic links encountered", {},
    "No message of desired type", "Identifier removed", "Channel number out of range",
    "Level 2 not synchronized", "Level 3 halted", "Level 3 reset", "Link number out of range",
    "Protocol driver not attached", "No CSI structure available", "Level 2 halted", "Invalid exchange",
    "Invalid request descriptor", "Exchange full", "No anode", "Invalid request code", "Invalid slot", {},
    "Bad font file format", "Device not a stream", "No data available", "Timer expired",
    "Out of streams resources", "Machine is not on the network", "Package not installed", "Object is remote",
    "Link has been severed", "Advertise error", "Srmount error", "Communication error on send",
    "Protocol error", "Multihop attempted", "RFS specific error", "Not a data message",
    "Value too large for defined data type", "Name not unique on network", "File descriptor in bad state",
    "Remote address changed", "Can not access a needed shared library", "Accessing a corrupted shared library",
    ".lib section in a.out corrupted", "Attempting to link in too many shared libraries",
    "Cannot exec a shared library directly", "Illegal byte sequence", "Interrupted system call should be restarted",
    "Streams pipe error", "Too many users", "Socket operation on non-socket", "Destination address required",
    "Message too long", "Protocol wrong type for socket", "Protocol not available", "Protocol not supported",
    "Socket type not supported", "Operation not supported on transport endpoint", "Protocol family not supported",
    "Address family not supported by protocol", "Address already in use", "Cannot assign requested address",
    "Network is down", "Network is unreachable", "Network dropped connection because of reset",
    "Software caused connection abort", "Connection reset by peer", "No buffer space available",
    "Transport endpoint is already connected", "Transport endpoint is not connected",
    "Cannot send after transport endpoint shutdown", "Too many references: cannot splice", "Connection timed out",
    "Connection refused", "Host is down", "No route to host", "Operation already in progress",
    "Operation now in progress", "Stale NFS file handle", "Structure needs cleaning", "Not a XENIX named type file",
    "No XENIX semaphores available", "Is a named type file", "Remote I/O error", "Quota exceeded",
    "No medium found", "Wrong medium type", "Operation Canceled", "Required key not available", "Key has expired",
    "Key has been revoked", "Key was rejected by service", "Owner died", "State not recoverable",
    "Operation not possible due to RF-kill", "Memory page has hardware error"
};
constexpr auto offsets=[] {
    std::array<std::size_t,descriptions.size()> result{};std::size_t next=0;
    for(std::size_t i=0;i<descriptions.size();++i)if(!descriptions[i].empty()){result[i]=next;next+=descriptions[i].size()+1;}
    return result;
}();
static_assert(offsets.back()+descriptions.back().size()+1<=8192);
}
std::string native_error_description(std::int32_t number) {
    if(number>=0 && static_cast<std::size_t>(number)<descriptions.size() && !descriptions[number].empty())
        return std::string{descriptions[number]};
    return "Unknown error "+std::to_string(number);
}
NativeErrorStrings::~NativeErrorStrings() {
    if(constants_owned_)try{memory_.unmap_range(constants_base,constants_size);}catch(...){}
    if(unknown_owned_)try{memory_.unmap(unknown_base);}catch(...){}
}
a64::Fault NativeErrorStrings::initialize_constants() noexcept {
    if(constants_owned_)return a64::Fault::none;
    try{
        memory_.map(constants_base,constants_size,a64::read_write);constants_owned_=true;
        std::array<std::uint8_t,constants_size> bytes{};
        for(std::size_t i=0;i<descriptions.size();++i)std::copy(descriptions[i].begin(),descriptions[i].end(),bytes.begin()+offsets[i]);
        if(!memory_.write(constants_base,bytes))throw a64::GuestError("AETHER_STRERROR_STORAGE","Cannot initialize error descriptions");
        memory_.protect_range(constants_base,constants_size,a64::Permission::read);return a64::Fault::none;
    }catch(...){
        if(constants_owned_){try{memory_.unmap_range(constants_base,constants_size);}catch(...){}constants_owned_=false;}
        rejection_="strerror: readonly description storage is unavailable";return a64::Fault::unsupported_service;
    }
}
a64::Fault NativeErrorStrings::invoke(std::array<std::uint64_t,31> &r) noexcept {
    rejection_={};
    const auto number=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[0]));
    if(number>=0 && static_cast<std::size_t>(number)<descriptions.size() && !descriptions[number].empty()){
        const auto fault=initialize_constants();if(fault!=a64::Fault::none)return fault;
        const auto address=constants_base+offsets[number];
        if(!memory_.accessible(address,descriptions[number].size()+1,a64::Permission::read)){
            rejection_="strerror: description storage is unreadable";return a64::Fault::read;
        }
        r[0]=address;return a64::Fault::none;
    }
    try{
        const auto tls=threads_.tls();const auto tid=threads_.tid();
        auto slot=std::find_if(slots_.begin(),slots_.end(),[&](const auto &value){return value.tls==tls && value.tid==tid;});
        if(slot==slots_.end())slot=std::find_if(slots_.begin(),slots_.end(),[&](const auto &value){
            if(value.tls!=tls || !value.tid)return false;
            NativeThreadOptions options;a64::Address stack=0;return threads_.query(value.tid,options,stack)==3;
        });
        if(slot==slots_.end())slot=std::find_if(slots_.begin(),slots_.end(),[](const auto &value){return !value.tid;});
        if(slot==slots_.end()){rejection_="strerror: logical thread buffer limit exceeded";return a64::Fault::unsupported_service;}
        if(!unknown_owned_){memory_.map(unknown_base,4096,a64::read_write);unknown_owned_=true;}
        std::array<char,unknown_size> bytes{};constexpr std::string_view prefix="Unknown error ";
        std::copy(prefix.begin(),prefix.end(),bytes.begin());
        const auto formatted=std::to_chars(bytes.data()+prefix.size(),bytes.data()+bytes.size()-1,number);
        if(formatted.ec!=std::errc{}){rejection_="strerror: signed error formatting failed";return a64::Fault::windows_service;}
        const auto address=unknown_base+static_cast<a64::Address>(slot-slots_.begin())*unknown_size;
        if(!memory_.write(address,{reinterpret_cast<const std::uint8_t*>(bytes.data()),bytes.size()})){
            rejection_="strerror: thread error buffer is unwritable";return a64::Fault::write;
        }
        *slot={tls,tid};r[0]=address;return a64::Fault::none;
    }catch(...){rejection_="strerror: logical thread storage is unavailable";return a64::Fault::unsupported_service;}
}

a64::Fault NativeErrorStrings::invoke_r(bool gnu,std::array<std::uint64_t,31> &r) noexcept {
    rejection_={};
    const auto buffer=r[1],capacity=r[2];
    // Both Bionic variants preserve errno. A zero-capacity call has no caller
    // output, so it needs neither storage setup nor message formatting.
    if(!capacity){r[0]=gnu?buffer:34;return a64::Fault::none;}
    try {
        const auto number=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[0]));
        auto description=native_error_description(number);
        const auto length=description.size();
        const auto copied=static_cast<std::size_t>(std::min<std::uint64_t>(length,capacity-1));
        description.resize(copied);description.push_back('\0');
        // Native ErrnoRestorer restores errno after copying, including when the
        // caller buffer aliases that object. With no callbacks or concurrent
        // owner, merge those final bytes before the one atomic output write.
        // Subtractive comparisons avoid forming an overflowing buffer end.
        const auto error=threads_.error_address();
        const bool overlaps=buffer<=error?error-buffer<description.size():buffer-error<4;
        if(overlaps){
            std::array<std::uint8_t,4> saved{};
            if(!memory_.read(error,saved)){
                rejection_="strerror_r: overlapping logical errno is not readable";return a64::Fault::read;
            }
            if(buffer<=error){
                const auto start=static_cast<std::size_t>(error-buffer);
                const auto count=std::min(saved.size(),description.size()-start);
                for(std::size_t i=0;i<count;++i)description[start+i]=static_cast<char>(saved[i]);
            }else{
                const auto start=static_cast<std::size_t>(buffer-error);
                const auto count=std::min(description.size(),saved.size()-start);
                for(std::size_t i=0;i<count;++i)description[i]=static_cast<char>(saved[start+i]);
            }
        }
        // Inspect only the bytes actually written, not the declared capacity.
        // GuestMemory validates the complete span before publishing any byte.
        if(!buffer || !memory_.write(buffer,{reinterpret_cast<const std::uint8_t*>(description.data()),description.size()})){
            rejection_="strerror_r: caller buffer is not writable";return a64::Fault::write;
        }
        r[0]=gnu?buffer:length>=capacity?34:0;
        return a64::Fault::none;
    }catch(...){
        rejection_="strerror_r: host message formatting failed";return a64::Fault::windows_service;
    }
}
}
