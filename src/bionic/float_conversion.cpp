#include "float_conversion.hpp"
#include "floating.hpp"
#include "unicode.hpp"
#include <string>

namespace aether::bionic {
namespace {
struct InputFault {a64::Fault fault;};
constexpr std::size_t limit=1024*1024;
bool ascii_space(unsigned c){return c==32 || (c>=9 && c<=13);}
bool digit(unsigned c){return c>='0' && c<='9';}
bool hex(unsigned c){return digit(c)||(c>='a'&&c<='f')||(c>='A'&&c<='F');}
unsigned lower(unsigned c){return c>='A'&&c<='Z'?c+32:c;}
bool alnum(unsigned c){return digit(c)||(lower(c)>='a' && lower(c)<='z');}
void trim_wide_nan(std::string &text){
    const std::size_t first=!text.empty() && (text[0]=='+' || text[0]=='-')?1:0;
    if(text.size()<first+4 || lower(text[first])!='n' || lower(text[first+1])!='a' ||
       lower(text[first+2])!='n' || text[first+3]!='(')return;
    // Bionic first applies its scanf subject grammar to wide conversions.
    // A malformed payload rolls back to plain NaN before gdtoa sees it.
    for(std::size_t at=first+4;at<text.size();++at){
        const auto c=static_cast<unsigned char>(text[at]);
        if(c==')')return;
        if(!alnum(c) && c!='_'){text.resize(first+3);return;}
    }
    text.resize(first+3);
}
bool put(a64::GuestMemory &m,a64::Address at,std::uint64_t value,unsigned width){
    std::array<std::uint8_t,8> bytes{};for(unsigned i=0;i<width;++i)bytes[i]=static_cast<std::uint8_t>(value>>(8*i));
    return m.write(at,std::span{bytes}.first(width));
}
}
a64::Fault convert_floating(a64::GuestMemory &memory,a64::Address error,unsigned kind,a64::ServiceState &frame){
    if(kind>6)return a64::Fault::unsupported_service;
    const auto source=frame.registers[0],end=kind==6?0:frame.registers[1];
    const bool wide=kind>=3 && kind<6;const unsigned width=wide?4:1;
    const unsigned format=kind==6?64:kind%3==0?32:kind%3==1?64:128;
    try {
        const auto read=[&](std::size_t offset){
            if(offset>=limit/width)throw InputFault{a64::Fault::unsupported_service};
            const auto distance=offset*width;
            if(source>=a64::GuestMemory::address_limit || distance>a64::GuestMemory::address_limit-source || width>a64::GuestMemory::address_limit-source-distance)throw InputFault{a64::Fault::read};
            std::array<std::uint8_t,4> bytes{};if(!memory.read(source+distance,std::span{bytes}.first(width)))throw InputFault{a64::Fault::read};
            unsigned c=0;for(unsigned i=0;i<width;++i)c|=unsigned{bytes[i]}<<(8*i);return c;
        };
        std::size_t start=0;
        while(wide?native_unicode(UnicodeOperation::space,read(start))!=0:ascii_space(read(start)))++start;
        std::string text;
        if(wide){
            // Match Bionic's wchar wrapper candidate span, including its
            // deliberately restricted hexadecimal/NaN payload alphabet.
            constexpr std::string_view alphabet="-+0123456789.xXeEpP()nNaAiIfFtTyY";
            for(auto position=start;;++position){const auto c=read(position);if(c>127 || alphabet.find(static_cast<char>(c))==std::string_view::npos)break;text.push_back(static_cast<char>(c));}
            trim_wide_nan(text);
        } else {
            // Lex only the relevant subject sequence; don't read an unrelated suffix.
            auto position=start;
            auto take=[&](){text.push_back(static_cast<char>(read(position++)));};
            if(read(position)=='+' || read(position)=='-')take();
            const auto first=lower(read(position));
            if(first=='i' || first=='n'){
                const auto word=first=='i'?std::string_view{"infinity"}:std::string_view{"nan"};
                unsigned matched=0;while(matched<word.size() && lower(read(position))==static_cast<unsigned>(word[matched])){take();++matched;}
                if(first=='n' && matched==3 && read(position)=='('){take();while(read(position)!=0 && read(position)!=')')take();if(read(position)==')')take();}
            } else {
                bool hexadecimal=false;
                if(read(position)=='0'){take();if(lower(read(position))=='x'){take();hexadecimal=true;}}
                const auto is_digit=[&](unsigned c){return hexadecimal?hex(c):digit(c);};
                while(is_digit(read(position)))take();
                if(read(position)=='.'){take();while(is_digit(read(position)))take();}
                if(lower(read(position))==static_cast<unsigned>(hexadecimal?'p':'e')){take();if(read(position)=='+' || read(position)=='-')take();while(digit(read(position)))take();}
            }
        }
        const auto result=native_floating_parse(text,format);
        // Commit in Bionic order. An inaccessible end pointer must not hide
        // an ERANGE already produced by numeric conversion.
        if(result.range_error && !put(memory,error,34,4))return a64::Fault::write;
        const auto consumed=result.consumed?start+result.consumed:0;
        if(end && !put(memory,end,source+consumed*width,8))return a64::Fault::write;
        frame.vectors[0]=result.bits;
        return a64::Fault::none;
    }catch(const InputFault &fault){return fault.fault;}
}
}
