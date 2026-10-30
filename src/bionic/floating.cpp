#include "floating.hpp"
#include <boost/multiprecision/cpp_int.hpp>
#include <algorithm>
#include <stdexcept>
#include <string>

namespace aether::bionic {
namespace {
using boost::multiprecision::cpp_int;
constexpr std::size_t input_limit=1024*1024,digit_limit=16384;
bool space(unsigned char c){return c==' ' || (c>=9 && c<=13);}
int digit(unsigned char c){if(c>='0' && c<='9')return c-'0';if(c>='a' && c<='f')return c-'a'+10;if(c>='A' && c<='F')return c-'A'+10;return -1;}
bool match(std::string_view input,std::size_t at,std::string_view word){
    if(word.size()>input.size()-at)return false;
    for(std::size_t i=0;i<word.size();++i){auto c=static_cast<unsigned char>(input[at+i]);if(c>='A' && c<='Z')c+=32;if(c!=static_cast<unsigned char>(word[i]))return false;}
    return true;
}
struct Format{unsigned width,precision,fraction;int bias,minimum,maximum;};
Format format(unsigned width){
    if(width==32)return {32,24,23,127,-126,127};
    if(width==64)return {64,53,52,1023,-1022,1023};
    if(width==128)return {128,113,112,16383,-16382,16383};
    throw std::invalid_argument("floating: unsupported IEEE width");
}
cpp_int power10(unsigned exponent){cpp_int result=1,base=10;while(exponent){if(exponent&1)result*=base;exponent>>=1;if(exponent)base*=base;}return result;}
FloatingResult pack(cpp_int bits,std::size_t consumed,bool range_error,const Format &f,bool negative){
    if(negative)bits|=cpp_int{1}<<(f.width-1);
    const cpp_int mask=(cpp_int{1}<<64)-1;
    return {{{(bits&mask).convert_to<std::uint64_t>(),(bits>>64).convert_to<std::uint64_t>()}},consumed,range_error};
}
cpp_int infinity(const Format &f){return cpp_int{2*f.bias+1}<<f.fraction;}
int exponent(std::string_view input,std::size_t &at,bool hexadecimal){
    const auto original=at;auto p=at+1;bool negative=false;
    if(p<input.size() && (input[p]=='+' || input[p]=='-'))negative=input[p++]=='-';
    const auto first=p;int value=0;
    // Bionic gdtoa clamps decimal exponents at 19999. Hexadecimal saturation
    // exceeds every scale adjustment possible within our bounded input.
    const int maximum=hexadecimal?8000000:19999;
    while(p<input.size() && input[p]>='0' && input[p]<='9'){value=std::min(maximum,value*10+(input[p]-'0'));++p;}
    if(p==first){at=original;return 0;}at=p;return negative?-value:value;
}
FloatingResult finite(cpp_int numerator,cpp_int denominator,std::size_t consumed,const Format &f,bool negative,bool hexadecimal){
    int binary=static_cast<int>(boost::multiprecision::msb(numerator))-static_cast<int>(boost::multiprecision::msb(denominator));
    if(binary>=0){if(numerator<(denominator<<binary))--binary;}
    else if((numerator<<-binary)<denominator)--binary;
    if(binary>f.maximum)return pack(infinity(f),consumed,true,f,negative);
    const auto quantum=std::max(binary,f.minimum)-static_cast<int>(f.fraction);
    if(quantum<0)numerator<<=-quantum;else denominator<<=quantum;
    cpp_int rounded=numerator/denominator;
    const cpp_int remainder=numerator%denominator;
    const cpp_int twice=remainder<<1;
    if(twice>denominator || (twice==denominator && static_cast<bool>(rounded&1)))++rounded;
    // Bionic's hexadecimal path reports range only below the smallest
    // subnormal binade; its ordinary inexact subnormals preserve errno.
    // Its separate decimal double implementation reports even exact tiny
    // results, whereas decimal float/quad require discarded nonzero bits.
    const bool underflow=hexadecimal?binary<f.minimum-static_cast<int>(f.fraction):
        binary<f.minimum && (remainder!=0 || f.width==64);
    if(rounded==0)return pack(0,consumed,true,f,negative);
    const cpp_int hidden=cpp_int{1}<<f.fraction;
    if(binary<f.minimum){
        // Bionic decimal parsing detects tininess after rounding.
        return pack(rounded,consumed,underflow && rounded<hidden,f,negative);
    }
    if(rounded==(hidden<<1)){rounded>>=1;++binary;}
    if(binary>f.maximum)return pack(infinity(f),consumed,true,f,negative);
    return pack((cpp_int{binary+f.bias}<<f.fraction)|(rounded-hidden),consumed,false,f,negative);
}
// Bionic gdtoa accepts hexadecimal NaN words. Each separated group begins a
// fresh 32-bit word; overlong payloads retain the first available words.
cpp_int nan_payload(std::string_view input,std::size_t &at,const Format &f){
    const auto canonical=cpp_int{1}<<(f.fraction-1);
    if(at==input.size() || input[at]!='(')return canonical;
    const auto open=at;std::size_t p=at+1;const unsigned capacity=(f.precision+31)/32;
    std::array<std::uint32_t,4> words{};unsigned count=0,nibbles=0,group_start=0;bool any=false,valid=true;
    auto finish_group=[&](){if(count>group_start+1 && nibbles<8){const auto shift=(8-nibbles)*4;for(unsigned i=count-1;i>group_start;--i)words[i]=(i==count-1?words[i]:(words[i]>>shift))|(words[i-1]<<(32-shift));words[group_start]>>=shift;}group_start=count;nibbles=0;};
    // Once the payload words are exhausted, another 0x is ordinary input:
    // its x invalidates the payload rather than starting a discarded group.
    auto begin_group=[&](){while(p<input.size() && static_cast<unsigned char>(input[p])<=32 && input[p]!=0)++p;if(count<capacity && p+2<input.size() && input[p]=='0' && (input[p+1]=='x' || input[p+1]=='X') && static_cast<unsigned char>(input[p+2])>32)p+=2;};
    begin_group();
    while(p<input.size() && input[p]!=0 && input[p]!=')'){
        const auto c=static_cast<unsigned char>(input[p]);const auto d=digit(c);
        if(d>=0){any=true;if(!nibbles || nibbles==8){if(count<capacity){++count;nibbles=0;}else {++p;continue;}}words[count-1]=(words[count-1]<<4)|static_cast<unsigned>(d);++nibbles;++p;continue;}
        if(c<=32){++p;if(nibbles)finish_group();begin_group();continue;}
        valid=false;while(p<input.size() && input[p]!=0 && input[p]!=')')++p;break;
    }
    if(p<input.size() && input[p]==')')at=p+1;else at=open;
    if(!valid || !any)return canonical;
    if(nibbles)finish_group();
    cpp_int value=0;for(unsigned i=0;i<count;++i){value<<=32;value|=words[i];}
    const auto payload_width=f.width==64?f.fraction:f.precision;
    value&=(cpp_int{1}<<payload_width)-1;
    if(value==0)value=1;
    // Float/quad payload conversion clears the parsed implicit leading bit.
    // A payload containing only that bit therefore produces infinity in Bionic.
    return value&((cpp_int{1}<<f.fraction)-1);
}
}
FloatingResult native_floating_parse(std::string_view input,unsigned width){
    const auto f=format(width);if(input.size()>input_limit)throw std::length_error("floating: input exceeds 1 MiB");
    std::size_t at=0;while(at<input.size() && space(static_cast<unsigned char>(input[at])))++at;
    bool negative=false;if(at<input.size() && (input[at]=='+' || input[at]=='-'))negative=input[at++]=='-';
    if(match(input,at,"inf")){at+=3;if(match(input,at,"inity"))at+=5;return pack(infinity(f),at,false,f,negative);}
    if(match(input,at,"nan")){at+=3;const auto bits=nan_payload(input,at,f);return pack(infinity(f)|bits,at,false,f,negative);}
    bool hex=false;
    if(at+2<=input.size() && input[at]=='0' && (input[at+1]=='x' || input[at+1]=='X')){
        auto p=at+2;if(p<input.size() && input[p]=='.')++p;
        if(p<input.size() && digit(static_cast<unsigned char>(input[p]))>=0){hex=true;at+=2;}
    }
    std::string digits;std::size_t fractional=0;bool dot=false,any=false;
    while(at<input.size()){
        const auto c=static_cast<unsigned char>(input[at]);const auto d=digit(c);
        if(d>=0 && (hex || d<10)){digits.push_back(static_cast<char>(d));any=true;if(dot)++fractional;++at;}
        else if(c=='.' && !dot){dot=true;++at;}
        else break;
    }
    if(!any)return {};
    int scale=-static_cast<int>(fractional)*(hex?4:1);
    if(at<input.size() && (hex?(input[at]=='p' || input[at]=='P'):(input[at]=='e' || input[at]=='E')))scale+=exponent(input,at,hex);
    const auto first=digits.find_first_not_of(char{0});
    if(first==std::string::npos)return pack(0,at,false,f,negative);
    digits.erase(0,first);
    while(digits.back()==0){digits.pop_back();scale+=hex?4:1;}
    const auto order=scale+static_cast<int>(digits.size())*(hex?4:1);
    if(order>(hex?17000:5200))return pack(infinity(f),at,true,f,negative);
    if(order<(hex?-17000:-5200))return pack(0,at,true,f,negative);
    if(digits.size()>digit_limit)throw std::length_error("floating: significant digits exceed 16384");
    cpp_int numerator=0,denominator=1;
    for(const auto d:digits){numerator*=hex?16:10;numerator+=static_cast<unsigned char>(d);}
    if(hex){if(scale>=0)numerator<<=scale;else denominator<<=-scale;}
    else if(scale>=0)numerator*=power10(static_cast<unsigned>(scale));else denominator=power10(static_cast<unsigned>(-scale));
    return finite(std::move(numerator),std::move(denominator),at,f,negative,hex);
}
}
