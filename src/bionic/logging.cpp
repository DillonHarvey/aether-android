#include "logging.hpp"
#include "error_strings.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cstdio>
#include <limits>
#include <locale.h>
#include <vector>
#include <windows.h>
namespace aether::bionic {
namespace {
using a64::Fault;
struct Failure {Fault fault;const char *message;};
[[noreturn]] void unsupported(const char *message){throw Failure{Fault::unsupported_service,message};}
unsigned descriptor_error(host::FileError error){
    // Keep the guest ABI mapping identical to NativeStdio's descriptor errors.
    using E=host::FileError;
    switch(error){case E::none:return 0;case E::missing:return 2;case E::denied:return 13;
    case E::exists:return 17;case E::bad_descriptor:return 9;case E::invalid:return 22;
    case E::unsupported:return 95;case E::descriptor_limit:return 24;case E::quota:return 28;
    case E::io:return 5;case E::would_block:return 11;case E::is_directory:return 21;
    case E::not_directory:return 20;case E::not_empty:return 39;case E::not_seekable:return 29;}
    return 5;
}
std::uint64_t read_word(a64::GuestMemory &memory,std::uint64_t address) {
    std::array<std::uint8_t,8> bytes{};if(!memory.read(address,bytes))throw Failure{Fault::read,"liblog: unreadable argument slot"};
    std::uint64_t value=0;for(unsigned n=0;n<8;++n)value|=static_cast<std::uint64_t>(bytes[n])<<(n*8);return value;
}
std::string text(a64::GuestMemory &memory,std::uint64_t address,std::size_t limit,bool terminated=true) {
    if(!address)return "(null)";
    std::string result;
    for(std::size_t n=0;n<limit;++n) {
        if(address>=a64::GuestMemory::address_limit || n>=a64::GuestMemory::address_limit-address)throw Failure{Fault::read,"liblog: string address overflow"};
        std::array<std::uint8_t,1> byte{};if(!memory.read(address+n,byte))throw Failure{Fault::read,"liblog: unreadable guest string"};
        if(!byte[0])return result;result.push_back(static_cast<char>(byte[0]));
    }
    if(terminated)unsupported("liblog: string exceeds bounded profile");return result;
}
struct Arguments {
    a64::GuestMemory &memory;a64::ServiceState &state;bool full;unsigned gp,fp=0;std::uint64_t stack;
    std::uint64_t take(bool floating=false) {
        if(floating){if(!full)unsupported("liblog: floating arguments require full service frame");if(fp<8)return state.vectors[fp++][0];}
        else if(gp<8)return state.registers[gp++];
        if(!full)unsupported("liblog: stack arguments require full service frame");
        if(stack> a64::GuestMemory::address_limit-8)throw Failure{Fault::read,"liblog: argument stack overflow"};
        const auto value=read_word(memory,stack);stack+=8;return value;
    }
};
// AAPCS64 va_list is passed indirectly. Copy its cursor; never use a host va_list.
struct VaArguments {
    a64::GuestMemory &memory;std::uint64_t stack,gr_top,vr_top;std::int32_t gr_offs,vr_offs;
    VaArguments(a64::GuestMemory &m,std::uint64_t pointer):memory(m) {
        std::array<std::uint8_t,32> image{};
        if(!pointer || !memory.read(pointer,image))throw Failure{Fault::read,"printf: unreadable va_list"};
        const auto word=[&](unsigned at,unsigned size){std::uint64_t n=0;for(unsigned i=0;i<size;++i)n|=std::uint64_t{image[at+i]}<<(8*i);return n;};
        stack=word(0,8);gr_top=word(8,8);vr_top=word(16,8);
        gr_offs=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(word(24,4)));
        vr_offs=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(word(28,4)));
        if((gr_offs<0 && (gr_offs < -64 || gr_offs%8)) || (vr_offs<0 && (vr_offs < -128 || vr_offs%16)))unsupported("printf: invalid va_list register offset");
    }
    std::uint64_t take(bool floating=false) {
        auto &offset=floating?vr_offs:gr_offs;const auto top=floating?vr_top:gr_top;
        if(offset<0) {
            const auto distance=static_cast<std::uint64_t>(-offset);
            if(top<distance || (top-distance)% (floating?16:8))throw Failure{Fault::read,"printf: invalid register-save address"};
            const auto address=top-distance;offset+=floating?16:8;return read_word(memory,address);
        }
        // Positive offsets also denote an exhausted bank (e.g. prior aggregate overflow).
        if(stack%8 || stack>a64::GuestMemory::address_limit-8)throw Failure{Fault::read,"printf: invalid va_list stack"};
        const auto value=read_word(memory,stack);stack+=8;return value;
    }
};
_locale_t c_locale() {
    struct Locale { _locale_t value=_create_locale(LC_ALL,"C");~Locale(){if(value)_free_locale(value);} };
    static const Locale locale;if(!locale.value)throw Failure{Fault::windows_service,"printf: C locale unavailable"};return locale.value;
}
template<class Reader>
std::string format_source(a64::GuestMemory &memory,std::string_view source,Reader &arguments,a64::Address error=0) {
    std::string result;unsigned conversions=0;
    const auto append=[&](std::string_view value){result.append(value);};
    for(std::size_t at=0;at<source.size();) {
        if(source[at]!='%'){append(std::string_view(source).substr(at++,1));continue;}
        ++at;if(at<source.size() && source[at]=='%'){append("%");++at;continue;}
        if(++conversions>64)unsupported("liblog: conversion limit exceeded");
        std::string flags;while(at<source.size() && std::string_view("-+ #0").find(source[at])!=std::string_view::npos){if(flags.size()==5)unsupported("liblog: excessive format flags");flags.push_back(source[at++]);}
        const auto number=[&](bool precision){
            int value=0;
            if(at<source.size() && source[at]=='*'){++at;value=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(arguments.take()));}
            else while(at<source.size() && source[at]>='0' && source[at]<='9'){if(value>512)unsupported("liblog: format width exceeds profile");value=value*10+source[at++]-'0';}
            if(value < -512 || value>512)unsupported("liblog: format width exceeds profile");
            if(!precision && value<0){if(flags.find('-')==std::string::npos)flags.push_back('-');value=-value;}return value;
        };
        const int width=number(false);int precision=-1;
        if(at<source.size() && source[at]=='.'){++at;precision=number(true);}
        std::string length;
        if(at<source.size() && std::string_view("hljztL").find(source[at])!=std::string_view::npos){length.push_back(source[at++]);if(at<source.size() && (length=="h" || length=="l") && source[at]==length[0])length.push_back(source[at++]);}
        if(at==source.size())unsupported("liblog: incomplete conversion");
        const char conversion=source[at++];
        if(conversion=='m') {
            if(!error || !length.empty() || flags.find('#')!=std::string::npos)
                unsupported("syslog: unsupported errno conversion profile");
            std::array<std::uint8_t,4> bytes{};
            if(!memory.read(error,bytes))throw Failure{Fault::read,"syslog: unreadable logical errno"};
            std::uint32_t value=0;for(unsigned i=0;i<4;++i)value|=std::uint32_t{bytes[i]}<<(8*i);
            auto description=native_error_description(std::bit_cast<std::int32_t>(value));
            if(precision>=0 && description.size()>static_cast<std::size_t>(precision))description.resize(precision);
            const auto padding=width>static_cast<int>(description.size())?static_cast<std::size_t>(width)-description.size():0;
            if(flags.find('-')!=std::string::npos)description.append(padding,' ');else description.insert(0,padding,' ');
            append(description);continue;
        }
        if(std::string_view("diuoxXcspfFeEgGaA").find(conversion)==std::string_view::npos || length=="L")unsupported("liblog: unsupported printf conversion");
        const bool floating=std::string_view("fFeEgGaA").find(conversion)!=std::string_view::npos;
        if((floating && !length.empty() && length!="l") || ((conversion=='s' || conversion=='c' || conversion=='p') && !length.empty()))unsupported("liblog: wide or invalid conversion is unsupported");
        std::string spec="%"+flags;if(width)spec+=std::to_string(width);if(precision>=0)spec+="."+std::to_string(precision);
        std::array<char,8192> output{};int count=0;
        if(floating) {
            const auto bits=arguments.take(true);const bool nonfinite=(bits&0x7ff0000000000000ULL)==0x7ff0000000000000ULL;
            const bool hex=conversion=='a' || conversion=='A';
            std::string rendered;
            if(nonfinite) {
                const bool nan=(bits&0xfffffffffffffULL)!=0,upper=conversion>='A' && conversion<='Z';
                if(bits>>63)rendered+='-';else if(flags.find('+')!=std::string::npos)rendered+='+';else if(flags.find(' ')!=std::string::npos)rendered+=' ';
                rendered+=nan?(upper?"NAN":"nan"):(upper?"INF":"inf");
            } else {
                // Render the core first: CRT default hex precision/padding differs from Bionic.
                std::string core="%"+flags;if(precision>=0)core+="."+std::to_string(precision);core+=conversion;
                auto working_bits=bits;int hex_adjustment=0;
                const auto fraction=bits&0xfffffffffffffULL;
                if(hex && !(bits&0x7ff0000000000000ULL) && fraction) {
                    // Bionic normalizes subnormal hex mantissas; UCRT uses 0.x p-1022.
                    const auto shift=std::countl_zero(fraction)-11;
                    working_bits=(bits&0x8000000000000000ULL)|0x3ff0000000000000ULL|((fraction<<shift)&0xfffffffffffffULL);
                    hex_adjustment=-1022-shift;
                }
                count=_snprintf_s_l(output.data(),output.size(),_TRUNCATE,core.c_str(),c_locale(),std::bit_cast<double>(working_bits));
                if(count<0 || static_cast<std::size_t>(count)>=output.size())unsupported("printf: floating conversion exceeds profile");
                rendered.assign(output.data(),static_cast<std::size_t>(count));
                if(hex_adjustment) {
                    const auto exponent=rendered.find_first_of("pP");
                    if(exponent==std::string::npos)unsupported("printf: malformed host hex exponent");
                    const auto adjusted=std::stoi(rendered.substr(exponent+1))+hex_adjustment;
                    rendered.resize(exponent+1);if(adjusted>=0)rendered+='+';rendered+=std::to_string(adjusted);
                }
                if(hex && precision<0) {
                    const auto exponent=rendered.find_first_of("pP"),point=rendered.find('.');
                    if(exponent==std::string::npos)unsupported("printf: malformed host hex conversion");
                    if(point!=std::string::npos && point<exponent) {
                        auto end=exponent;while(end>point+1 && rendered[end-1]=='0')--end;
                        if(end==point+1 && flags.find('#')==std::string::npos)--end;
                        rendered.erase(end,exponent-end);
                    }
                }
            }
            const auto padding=width>static_cast<int>(rendered.size())?static_cast<std::size_t>(width)-rendered.size():0;
            if(flags.find('-')!=std::string::npos)rendered.append(padding,' ');
            else if(!nonfinite && flags.find('0')!=std::string::npos) {
                std::size_t prefix=!rendered.empty() && (rendered[0]=='-' || rendered[0]=='+' || rendered[0]==' ')?1:0;
                if(hex)prefix+=2;rendered.insert(prefix,padding,'0');
            } else rendered.insert(0,padding,' ');
            append(rendered);continue;
        }
        else if(conversion=='s') {
            auto value=text(memory,arguments.take(),precision<0?4096:static_cast<std::size_t>(precision),precision<0);spec+='s';count=_snprintf_s_l(output.data(),output.size(),_TRUNCATE,spec.c_str(),c_locale(),value.c_str());
        } else if(conversion=='c'){spec+='c';count=_snprintf_s_l(output.data(),output.size(),_TRUNCATE,spec.c_str(),c_locale(),static_cast<int>(arguments.take()&255));}
        else if(conversion=='p') {
            const auto value=arguments.take();std::array<char,32> buffer{};
            std::snprintf(buffer.data(),buffer.size(),"%llx",static_cast<unsigned long long>(value));
            std::string digits=precision==0 && !value?std::string{}:std::string(buffer.data());
            if(precision>static_cast<int>(digits.size()))digits.insert(0,static_cast<std::size_t>(precision)-digits.size(),'0');
            const bool left=flags.find('-')!=std::string::npos;
            const auto padding=width>static_cast<int>(digits.size()+2)?static_cast<std::size_t>(width)-digits.size()-2:0;
            const bool zero=precision<0 && !left && flags.find('0')!=std::string::npos;
            std::string rendered;
            if(!left && !zero)rendered.append(padding,' ');
            rendered+="0x";if(zero)rendered.append(padding,'0');rendered+=digits;
            if(left)rendered.append(padding,' ');append(rendered);continue;
        } else {
            auto bits=arguments.take();const bool wide=length=="l" || length=="ll" || length=="j" || length=="z" || length=="t";
            if(conversion=='d' || conversion=='i') {
                std::int64_t value=std::bit_cast<std::int64_t>(bits);
                if(length=="hh")value=std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(bits));else if(length=="h")value=std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(bits));else if(!wide)value=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(bits));
                spec+="ll";spec+=conversion;count=_snprintf_s_l(output.data(),output.size(),_TRUNCATE,spec.c_str(),c_locale(),static_cast<long long>(value));
            } else {
                if(length=="hh")bits=static_cast<std::uint8_t>(bits);else if(length=="h")bits=static_cast<std::uint16_t>(bits);else if(!wide)bits=static_cast<std::uint32_t>(bits);
                spec+="ll";spec+=conversion;count=_snprintf_s_l(output.data(),output.size(),_TRUNCATE,spec.c_str(),c_locale(),static_cast<unsigned long long>(bits));
            }
        }
        if(count<0 || static_cast<std::size_t>(count)>=output.size())unsupported("printf: conversion exceeds bounded profile");append(std::string_view(output.data(),static_cast<std::size_t>(count)));
    }
    return result;
}
template<class Reader>
std::string format(a64::GuestMemory &memory,std::uint64_t pointer,Reader &arguments,a64::Address error=0) {
    if(!pointer)unsupported("liblog: null format");
    return format_source(memory,text(memory,pointer,1024),arguments,error);
}
struct WideError {unsigned value;};
constexpr std::size_t wide_render_limit=1024*1024/4-1;
bool scalar(std::uint32_t value){return value<=0x10ffff && (value<0xd800 || value>0xdfff);}
// Bionic's wide encoder accepts this larger domain; final conversion back to
// wchar_t uses the strict decoder. Keep those two stages distinct.
bool wide_encodable(std::uint32_t value){return value<=0x1fffff;}
std::uint32_t wide_unit(a64::GuestMemory &memory,a64::Address pointer,std::size_t index){
    if(pointer>a64::GuestMemory::address_limit-4 || index>(a64::GuestMemory::address_limit-4-pointer)/4)
        throw Failure{Fault::read,"swprintf: wide source address overflow"};
    std::array<std::uint8_t,4> bytes{};
    if(!pointer || !memory.read(pointer+index*4,bytes))throw Failure{Fault::read,"swprintf: unreadable wide source"};
    std::uint32_t value=0;for(unsigned i=0;i<4;++i)value|=std::uint32_t{bytes[i]}<<(8*i);return value;
}
std::uint32_t utf8_unit(a64::GuestMemory &memory,a64::Address pointer,std::size_t &offset){
    const auto byte=[&](){
        if(pointer>=a64::GuestMemory::address_limit || offset>=a64::GuestMemory::address_limit-pointer)
            throw Failure{Fault::read,"swprintf: UTF-8 source address overflow"};
        std::array<std::uint8_t,1> data{};
        if(!pointer || !memory.read(pointer+offset,data))throw Failure{Fault::read,"swprintf: unreadable UTF-8 source"};
        ++offset;return data[0];
    };
    const auto first=byte();if(first<0x80)return first;
    unsigned extra=0;std::uint32_t value=0,minimum=0;
    if(first>=0xc2 && first<=0xdf){extra=1;value=first&31;minimum=0x80;}
    else if(first>=0xe0 && first<=0xef){extra=2;value=first&15;minimum=0x800;}
    else if(first>=0xf0 && first<=0xf4){extra=3;value=first&7;minimum=0x10000;}
    else throw WideError{84};
    for(unsigned i=0;i<extra;++i){const auto next=byte();if((next&0xc0)!=0x80)throw WideError{84};value=(value<<6)|(next&63);}
    if(value<minimum || !scalar(value))throw WideError{84};return value;
}
void wide_append(std::vector<std::uint32_t> &output,std::span<const std::uint32_t> value){
    for(const auto unit:value)if(!wide_encodable(unit))throw WideError{84};
    if(value.size()>wide_render_limit-output.size())unsupported("swprintf: render exceeds 262143 wchar profile");
    output.insert(output.end(),value.begin(),value.end());
}
void wide_append(std::vector<std::uint32_t> &output,std::uint32_t value){
    if(!wide_encodable(value))throw WideError{84};
    if(output.size()==wide_render_limit)unsupported("swprintf: render exceeds 262143 wchar profile");
    output.push_back(value);
}
template<class Reader>
std::vector<std::uint32_t> wide_format(a64::GuestMemory &memory,a64::Address pointer,Reader &arguments,a64::Address error){
    // Independent ceilings: 1024 format units including NUL, 4096 source
    // characters including NUL, 64 conversions, width/precision <=512.
    // UTF-32 is never passed to a host wchar/locale/varargs implementation.
    std::vector<std::uint32_t> source,output;
    for(std::size_t i=0;;++i){
        if(i==1024)unsupported("swprintf: format exceeds 1024 wchar profile");
        const auto value=wide_unit(memory,pointer,i);if(!value)break;
        source.push_back(value);
    }
    unsigned conversions=0;bool have_error=false;std::string error_description;
    for(std::size_t at=0;at<source.size();){
        if(source[at]!='%'){wide_append(output,source[at++]);continue;}
        ++at;if(at<source.size() && source[at]=='%'){wide_append(output,'%');++at;continue;}
        if(++conversions>64)unsupported("swprintf: conversion limit 64 exceeded");
        std::string flags;
        while(at<source.size() && source[at]<128 && std::string_view("-+ #0").find(static_cast<char>(source[at]))!=std::string_view::npos){
            if(flags.size()==5)unsupported("swprintf: excessive format flags");flags.push_back(static_cast<char>(source[at++]));
        }
        const auto number=[&](bool precision){
            int value=0;
            if(at<source.size() && source[at]=='*'){++at;value=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(arguments.take()));}
            else while(at<source.size() && source[at]>='0' && source[at]<='9'){
                if(value>512)unsupported("swprintf: width/precision exceeds 512 profile");value=value*10+static_cast<int>(source[at++]-'0');
            }
            if(value < -512 || value>512)unsupported("swprintf: width/precision exceeds 512 profile");
            if(!precision && value<0){if(flags.find('-')==std::string::npos)flags.push_back('-');value=-value;}return value;
        };
        const auto width=number(false);int precision=-1;
        if(at<source.size() && source[at]=='.'){++at;precision=number(true);}
        std::string length;
        if(at<source.size() && source[at]<128 && std::string_view("hljztL").find(static_cast<char>(source[at]))!=std::string_view::npos){
            length.push_back(static_cast<char>(source[at++]));
            if(at<source.size() && (length=="h" || length=="l") && source[at]==static_cast<unsigned char>(length[0]))length.push_back(static_cast<char>(source[at++]));
        }
        if(at==source.size() || source[at]>=128)unsupported("swprintf: incomplete or unsupported conversion");
        const auto conversion=static_cast<char>(source[at++]);
        std::vector<std::uint32_t> value;
        if(conversion=='s' || conversion=='S'){
            if((conversion=='s' && !length.empty() && length!="l") || (conversion=='S' && !length.empty()))unsupported("swprintf: invalid string conversion length");
            const auto address=arguments.take();const bool wide=conversion=='S' || length=="l";
            if(!address){
                constexpr std::string_view null="(null)";
                for(std::size_t i=0;i<null.size() && (precision<0 || i<static_cast<std::size_t>(precision));++i)value.push_back(null[i]);
            }else{
                std::size_t offset=0;
                for(std::size_t i=0;precision<0 || i<static_cast<std::size_t>(precision);++i){
                    if(i==4096)unsupported("swprintf: string exceeds 4096 character profile");
                    const auto unit=wide?wide_unit(memory,address,i):utf8_unit(memory,address,offset);
                    if(!unit)break;if(!wide_encodable(unit))throw WideError{84};value.push_back(unit);
                }
            }
        }else if(conversion=='c' || conversion=='C'){
            if((conversion=='c' && !length.empty() && length!="l") || (conversion=='C' && !length.empty()))unsupported("swprintf: invalid character conversion length");
            auto unit=static_cast<std::uint32_t>(arguments.take());
            if(conversion=='c' && length.empty()){
                if(unit==UINT32_MAX)throw WideError{84};unit=static_cast<std::uint8_t>(unit);if(unit>=128)throw WideError{84};
            }
            if(!wide_encodable(unit))throw WideError{84};value.push_back(unit);
        }else if(conversion=='m'){
            if(!length.empty() || flags.find('#')!=std::string::npos)unsupported("swprintf: unsupported errno conversion profile");
            if(!have_error){
                std::array<std::uint8_t,4> bytes{};if(!memory.read(error,bytes))throw Failure{Fault::read,"swprintf: unreadable logical errno"};
                std::uint32_t error_number=0;for(unsigned i=0;i<4;++i)error_number|=std::uint32_t{bytes[i]}<<(8*i);
                error_description=native_error_description(std::bit_cast<std::int32_t>(error_number));have_error=true;
            }
            for(std::size_t i=0;i<error_description.size() && (precision<0 || i<static_cast<std::size_t>(precision));++i)value.push_back(static_cast<unsigned char>(error_description[i]));
        }else{
            if(std::string_view("diuoxXpfFeEgGaA").find(conversion)==std::string_view::npos)unsupported("swprintf: unsupported conversion profile");
            std::string spec="%"+flags;if(width)spec+=std::to_string(width);if(precision>=0)spec+="."+std::to_string(precision);spec+=length;spec+=conversion;
            // A single normalized ASCII numeric conversion shares all integer,
            // pointer and floating behavior, and the original GP/FP cursor.
            const auto rendered=format_source(memory,spec,arguments);
            for(const unsigned char byte:rendered)wide_append(output,byte);
            continue;
        }
        const auto padding=width>static_cast<int>(value.size())?static_cast<std::size_t>(width)-value.size():0;
        if(padding>wide_render_limit-output.size() || value.size()>wide_render_limit-output.size()-padding)unsupported("swprintf: render exceeds 262143 wchar profile");
        if(flags.find('-')==std::string::npos)output.insert(output.end(),padding,' ');
        wide_append(output,value);
        if(flags.find('-')!=std::string::npos)output.insert(output.end(),padding,' ');
    }
    return output;
}
void wide_error(a64::GuestMemory &memory,a64::Address error,a64::ServiceState &state,unsigned value){
    std::array<std::uint8_t,4> bytes{};for(unsigned i=0;i<4;++i)bytes[i]=static_cast<std::uint8_t>(value>>(i*8));
    if(!memory.write(error,bytes))throw Failure{Fault::write,"swprintf: unwritable logical errno"};
    state.registers[0]=UINT64_MAX;
}
class WindowsLog final:public host::NativeLogSink {
    bool write(const host::NativeLogMessage &message) noexcept override {
        try {
            std::string rendered="[Aether native "+std::to_string(message.priority)+"] ";
            const auto escape=[&](std::string_view value){constexpr char hex[]="0123456789abcdef";for(const unsigned char byte:value){if(byte>=32 && byte<127 && byte!='\\')rendered.push_back(static_cast<char>(byte));else{rendered+="\\x";rendered.push_back(hex[byte>>4]);rendered.push_back(hex[byte&15]);}}};
            escape(message.tag);rendered+=": ";escape(message.text);rendered+='\n';OutputDebugStringA(rendered.c_str());
            if(message.assertion){const auto handle=GetStdHandle(STD_ERROR_HANDLE);if(handle && handle!=INVALID_HANDLE_VALUE){DWORD written=0;(void)WriteFile(handle,rendered.data(),static_cast<DWORD>(rendered.size()),&written,nullptr);}}
            return true;
        }catch(...){return false;}
    }
};
WindowsLog default_sink;
}
bool native_log_symbol(std::string_view name) noexcept {return name=="__android_log_write" || name=="__android_log_print" || name=="__android_log_assert";}
NativeLogging::NativeLogging(a64::GuestMemory &memory,host::NativeLogSink *sink,std::string_view program_tag)
    :memory_(memory),sink_(sink?sink:&default_sink),syslog_default_(program_tag.empty()?"Aether":program_tag){}
bool NativeLogging::write_stream(int fd,std::span<const std::uint8_t> bytes) noexcept {
    if((fd!=1 && fd!=2) || bytes.size()>1024*1024)return false;
    const std::string_view message{reinterpret_cast<const char*>(bytes.data()),bytes.size()};
    const auto accepted=sink_->write({fd==2?6:4,fd==2?"stderr":"stdout",message,false});
    if(accepted)++messages_;return accepted;
}
a64::Fault NativeLogging::invoke(std::string_view name,a64::ServiceState &state,bool full) noexcept {
    try {
        auto &r=state.registers;const bool assertion=name=="__android_log_assert";const auto priority=assertion?7:std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[0]));
        if(!assertion && (priority<4 || priority>=8)){r[0]=~std::uint64_t{0};return Fault::none;}
        const auto tag=r[1]?text(memory_,r[1],128):std::string("Aether");std::string message;
        if(name=="__android_log_write")message=text(memory_,r[2],4096);
        else if(assertion && !r[2])message=r[0]?"Assertion failed: "+text(memory_,r[0],1024):"Unspecified assertion failed";
        else {Arguments args{memory_,state,full,3,0,state.stack_pointer};message=format(memory_,r[2],args);}
        if(message.size()>1023)message.resize(1023);
        const auto written=sink_->write({priority,tag,message,assertion});if(written)++messages_;
        if(assertion){rejection_="Android assertion failed ["+tag+"]: "+message;rejection_view_=rejection_;return Fault::invalid_call;}
        r[0]=written?1:static_cast<std::uint64_t>(-std::int64_t{5});return Fault::none;
    }catch(const Failure &failure){rejection_view_=failure.message;return failure.fault;}
    catch(...){rejection_view_="liblog: host formatting or logging failure";return Fault::windows_service;}
}
a64::Fault NativeLogging::invoke_syslog(unsigned operation,a64::ServiceState &state,bool full,
                                      a64::Address error,host::FileService &descriptors) noexcept {
    try {
        auto &r=state.registers;
        if(operation>4)unsupported("syslog: invalid operation");
        if(operation==2){syslog_tag_=r[0];syslog_options_=static_cast<std::uint32_t>(r[1]);return Fault::none;}
        if(operation==3){syslog_tag_=0;syslog_options_=0;return Fault::none;}
        if(operation==4){const auto previous=syslog_mask_;const auto next=static_cast<std::uint32_t>(r[0]);if(next)syslog_mask_=next;r[0]=previous;return Fault::none;}
        const auto priority=static_cast<std::uint32_t>(r[0])&7;
        // Bionic's mask test precedes every tag/format/argument access.
        if(!(syslog_mask_&(std::uint32_t{1}<<priority)))return Fault::none;
        const auto tag=syslog_tag_?text(memory_,syslog_tag_,128):syslog_default_;
        std::string rendered;
        if(operation==1){VaArguments arguments{memory_,r[2]};rendered=format(memory_,r[1],arguments,error);}
        else {Arguments arguments{memory_,state,full,2,0,state.stack_pointer};rendered=format(memory_,r[1],arguments,error);}
        const auto count=rendered.size();
        const bool have_newline=count>0 && count<1024 && rendered[count-1]=='\n';
        if(rendered.size()>1023)rendered.resize(1023);
        // The Bionic logcat and stderr paths print the snprintf buffer with %s.
        if(const auto nul=rendered.find('\0');nul!=std::string::npos)rendered.resize(nul);
        const int android_priority=priority<=3?6:priority==4?5:priority<=6?4:3;
        if(sink_->write({android_priority,tag,rendered,false}))++messages_;
        if(syslog_options_&0x20){
            auto stderr_text=tag+": "+rendered;if(!have_newline)stderr_text+='\n';
            // Use only this app's logical descriptor; no host standard handle.
            std::size_t written=0;
            while(written<stderr_text.size()){
                const auto remaining=stderr_text.size()-written;
                const auto result=descriptors.write(2,{reinterpret_cast<const std::uint8_t*>(stderr_text.data()+written),remaining});
                if(result.error!=host::FileError::none || result.value<=0 ||
                   static_cast<std::uint64_t>(result.value)>remaining){
                    const auto value=result.error==host::FileError::none?5:descriptor_error(result.error);
                    std::array<std::uint8_t,4> bytes{};for(unsigned i=0;i<4;++i)bytes[i]=static_cast<std::uint8_t>(value>>(8*i));
                    // Failure occurs after already accepted output. Never
                    // preflight, roll back, or replay either observable output.
                    if(!memory_.write(error,bytes))throw Failure{Fault::write,"syslog: failed stderr write and unwritable logical errno"};
                    break;
                }
                // Only positive progress permits another write, of the suffix.
                // At most one call per output byte; failed writes never retry.
                written+=static_cast<std::size_t>(result.value);
            }
        }
        return Fault::none;
    }catch(const Failure &failure){rejection_view_=failure.message;return failure.fault;}
    catch(...){rejection_view_="syslog: host formatting or logging failure";return Fault::windows_service;}
}
a64::Fault NativeFormatting::render_allocated(bool variadic_list,a64::Address error,a64::ServiceState &state,
                                             bool full,std::string &output,bool &allocation_failed) noexcept {
    rejection_={};allocation_failed=false;
    try {
        std::string rendered;
        if(variadic_list){
            VaArguments arguments{memory_,state.registers[2]};
            rendered=format(memory_,state.registers[1],arguments,error);
        }else{
            Arguments arguments{memory_,state,full,2,0,state.stack_pointer};
            rendered=format(memory_,state.registers[1],arguments,error);
        }
        // Preserve embedded NULs and the complete count. The allocator adapter
        // adds the final terminator and owns all guest publication and cleanup.
        output.swap(rendered);
        return Fault::none;
    }catch(const Failure &failure){rejection_=failure.message;return failure.fault;}
    catch(const std::bad_alloc &){
        rejection_="asprintf: host rendering allocation failed";allocation_failed=true;return Fault::none;
    }catch(...){rejection_="asprintf: host formatting failure";return Fault::windows_service;}
}

a64::Fault NativeFormatting::render_stream(bool variadic_list,bool standard,a64::Address error,
                                          a64::ServiceState &state,bool full,std::string &output,
                                          bool &allocation_failed) noexcept {
    rejection_={};allocation_failed=false;
    try {
        const unsigned first=standard?1U:2U;
        std::string rendered;
        if(variadic_list){
            VaArguments arguments{memory_,state.registers[first]};
            rendered=format(memory_,state.registers[first-1],arguments,error);
        }else{
            Arguments arguments{memory_,state,full,first,0,state.stack_pointer};
            rendered=format(memory_,state.registers[first-1],arguments,error);
        }
        // The stream owner writes the complete byte sequence, including any
        // embedded NULs, after its own FILE permission and direction checks.
        output.swap(rendered);
        return Fault::none;
    }catch(const Failure &failure){rejection_=failure.message;return failure.fault;}
    catch(const std::bad_alloc &){
        rejection_="printf: host rendering allocation failed";allocation_failed=true;return Fault::none;
    }catch(...){rejection_="printf: host formatting failure";return Fault::windows_service;}
}

a64::Fault NativeFormatting::invoke(unsigned operation,a64::ServiceState &state,bool full) noexcept {
    try {
        auto &r=state.registers;const bool sprintf_checked=operation==4;
        const bool checked=operation>=2,variadic_list=(operation%2)==0;
        const auto destination=r[0],size=r[sprintf_checked?2:1],pointer=r[sprintf_checked?3:checked?4:2];
        if(checked && !sprintf_checked && size>r[3])throw Failure{Fault::invalid_call,"printf: destination size exceeds compiler object size"};
        if(size>static_cast<std::uint64_t>(INT64_MAX) && !(sprintf_checked && size==UINT64_MAX))throw Failure{Fault::invalid_call,"printf: size exceeds SSIZE_MAX"};
        std::string rendered;
        if(variadic_list){VaArguments args{memory_,r[sprintf_checked?4:checked?5:3]};rendered=format(memory_,pointer,args);}
        else {Arguments args{memory_,state,full,checked?5U:3U,0,state.stack_pointer};rendered=format(memory_,pointer,args);}
        const auto full_count=rendered.size();
        if(sprintf_checked && full_count>=size)throw Failure{Fault::invalid_call,"vsprintf: rendered output exceeds compiler object size"};
        if(size) {
            const auto count=static_cast<std::size_t>(std::min<std::uint64_t>(rendered.size(),size-1));
            // Format and validate everything before publishing a single guest write.
            rendered.resize(count);rendered.push_back('\0');
            if(!destination || !memory_.write(destination,{reinterpret_cast<const std::uint8_t*>(rendered.data()),rendered.size()}))throw Failure{Fault::write,"printf: unwritable destination"};
        }
        // The return is the full byte count, including embedded %c NULs but excluding the terminator.
        r[0]=full_count;return Fault::none;
    }catch(const Failure &failure){rejection_=failure.message;return failure.fault;}
    catch(...){rejection_="printf: host formatting failure";return Fault::windows_service;}
}

a64::Fault NativeFormatting::invoke_wide(bool variadic_list,a64::Address error,a64::ServiceState &state,bool full) noexcept {
    try {
        try {
            auto &r=state.registers;const auto destination=r[0],capacity=r[1],pointer=r[2];
            // Bionic rejects zero capacity before touching any caller input.
            if(!capacity)throw WideError{22};
            std::vector<std::uint32_t> rendered;
            if(variadic_list){VaArguments arguments{memory_,r[3]};rendered=wide_format(memory_,pointer,arguments,error);}
            else {Arguments arguments{memory_,state,full,3,0,state.stack_pointer};rendered=wide_format(memory_,pointer,arguments,error);}
            const auto full_count=rendered.size();
            std::size_t prefix=0;
            while(prefix<rendered.size() && prefix<capacity && rendered[prefix] && scalar(rendered[prefix]))++prefix;
            const bool truncated=prefix>=capacity;
            const bool decoding_error=!truncated && prefix<rendered.size() && rendered[prefix] && !scalar(rendered[prefix]);
            const auto copied=truncated?prefix-1:prefix;
            // All emitted units passed the encoder first. Final decoding can
            // stop at capacity or NUL before reaching an encodable non-scalar.
            // A decoding error publishes its valid prefix without a terminator.
            const auto written=copied+(decoding_error?0U:1U);
            std::vector<std::uint8_t> bytes(written*4);
            for(std::size_t i=0;i<copied;++i)for(unsigned b=0;b<4;++b)bytes[i*4+b]=static_cast<std::uint8_t>(rendered[i]>>(b*8));
            // Only the actual write span is inspected, never capacity*4. A huge
            // declared capacity with a short output remains a bounded operation.
            if(written && (!destination || !memory_.write(destination,bytes)))throw Failure{Fault::write,"swprintf: unwritable destination"};
            if(decoding_error)wide_error(memory_,error,state,84);
            else if(truncated)wide_error(memory_,error,state,75);
            else r[0]=full_count;
            return Fault::none;
        }catch(const WideError &failure){wide_error(memory_,error,state,failure.value);return Fault::none;}
        catch(const std::bad_alloc &){wide_error(memory_,error,state,12);return Fault::none;}
    }catch(const Failure &failure){rejection_=failure.message;return failure.fault;}
    catch(...){rejection_="swprintf: host formatting failure";return Fault::windows_service;}
}

}
