#include "calendar.hpp"
#include <bit>
#include <string>
#include <vector>

namespace aether::bionic {
namespace {
using a64::Fault;
struct FormatFault { Fault value; };
constexpr std::size_t output_limit=1024*1024;
std::uint64_t load(std::span<const std::uint8_t> b) {
    std::uint64_t n=0;for(std::size_t i=0;i<b.size();++i)n|=std::uint64_t{b[i]}<<(8*i);return n;
}
std::uint8_t byte(a64::GuestMemory &m,a64::Address p,std::size_t offset) {
    std::array<std::uint8_t,1> b{};
    if(p>=a64::GuestMemory::address_limit || offset>=a64::GuestMemory::address_limit-p || !m.read(p+offset,b))throw FormatFault{Fault::read};
    return b[0];
}
std::string text(a64::GuestMemory &m,a64::Address p,std::size_t bound) {
    std::string s;for(std::size_t i=0;i<bound;++i){const auto c=byte(m,p,i);if(!c)return s;s.push_back(static_cast<char>(c));}
    throw FormatFault{Fault::unsupported_service};
}
bool leap(std::int64_t y){return y%4==0 && (y%100!=0 || y%400==0);}
struct Formatter {
    a64::GuestMemory &memory;
    std::array<std::int64_t,9> f;
    std::int64_t offset;
    a64::Address zone;
    std::string output;
    void append(std::string_view s){if(s.size()>output_limit-output.size())throw FormatFault{Fault::unsupported_service};output.append(s);}
    std::int64_t field(unsigned i,std::int64_t lo,std::int64_t hi)const{if(f[i]<lo || f[i]>hi)throw FormatFault{Fault::unsupported_service};return f[i];}
    void number(std::int64_t n,unsigned width,char pad='0'){
        auto s=std::to_string(n);if(s.size()<width){if(n<0 && pad=='0')s="-"+std::string(width-s.size(),pad)+s.substr(1);else s.insert(0,width-s.size(),pad);}append(s);
    }
    std::int64_t year()const{return f[5]+1900;}
    std::pair<std::int64_t,int> iso()const{
        const auto w=field(6,0,6),d=field(7,0,365);auto y=year();const auto iw=w? w:7;
        auto week=static_cast<int>((d+11-iw)/7);
        auto jan=(w-d%7+7)%7;
        const auto weeks=[](std::int64_t yr,std::int64_t j){return j==4 || (j==3 && leap(yr))?53:52;};
        if(week==0){--y;jan=(jan-(leap(y)?2:1)+7)%7;week=weeks(y,jan);}
        else if(week>weeks(y,jan)){++y;week=1;}
        return {y,week};
    }
    void format(std::string_view s,unsigned depth=0){
        if(depth>4)throw FormatFault{Fault::unsupported_service};
        static constexpr std::array<std::string_view,7> days{"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"};
        static constexpr std::array<std::string_view,12> months{"January","February","March","April","May","June","July","August","September","October","November","December"};
        for(std::size_t i=0;i<s.size();++i){
            if(s[i]!='%'){append(s.substr(i,1));continue;}
            if(++i==s.size())throw FormatFault{Fault::unsupported_service};
            if(s[i]=='E'||s[i]=='O'){if(++i==s.size())throw FormatFault{Fault::unsupported_service};}
            switch(s[i]){
            case '%':append("%");break;
            case 'a':append(days[static_cast<std::size_t>(field(6,0,6))].substr(0,3));break;
            case 'A':append(days[static_cast<std::size_t>(field(6,0,6))]);break;
            case 'h':case 'b':append(months[static_cast<std::size_t>(field(4,0,11))].substr(0,3));break;
            case 'B':append(months[static_cast<std::size_t>(field(4,0,11))]);break;
            case 'c':format("%a %b %e %T %Y",depth+1);break;
            case 'C':if(year()<0 && year()>-100)append("-0");else number(year()/100,2);break;
            case 'd':number(field(3,1,31),2);break;
            case 'e':number(field(3,1,31),2,' ');break;
            case 'D':case 'x':format("%m/%d/%y",depth+1);break;
            case 'F':format("%Y-%m-%d",depth+1);break;
            case 'g':{auto y=iso().first;number(y<0?-(y%100):y%100,2);break;}
            case 'G':number(iso().first,4);break;
            case 'H':number(field(2,0,23),2);break;
            case 'I':{auto h=field(2,0,23)%12;number(h?h:12,2);break;}
            case 'j':number(field(7,0,365)+1,3);break;
            case 'k':number(field(2,0,23),2,' ');break;
            case 'l':{auto h=field(2,0,23)%12;number(h?h:12,2,' ');break;}
            case 'm':number(field(4,0,11)+1,2);break;
            case 'M':number(field(1,0,59),2);break;
            case 'n':append("\n");break;
            case 'p':append(field(2,0,23)<12?"AM":"PM");break;
            case 'P':append(field(2,0,23)<12?"am":"pm");break;
            case 'r':format("%I:%M:%S %p",depth+1);break;
            case 'R':format("%H:%M",depth+1);break;
            case 'S':number(field(0,0,60),2);break;
            case 't':append("\t");break;
            case 'T':case 'X':format("%H:%M:%S",depth+1);break;
            case 'u':{auto w=field(6,0,6);number(w?w:7,1);break;}
            case 'U':number((field(7,0,365)+7-field(6,0,6))/7,2);break;
            case 'V':number(iso().second,2);break;
            case 'w':number(field(6,0,6),1);break;
            case 'W':number((field(7,0,365)+7-(field(6,0,6)+6)%7)/7,2);break;
            case 'y':number(year()<0?-(year()%100):year()%100,2);break;
            case 'Y':number(year(),4);break;
            case 'z':{
                const bool minus=offset<0 || (offset==0 && zone && byte(memory,zone,0)=='-');
                const auto magnitude=offset<0?std::uint64_t{0}-static_cast<std::uint64_t>(offset):static_cast<std::uint64_t>(offset);
                // Offsets outside one day are not representable in this guest profile.
                if(magnitude>86400)throw FormatFault{Fault::unsupported_service};
                append(minus?"-":"+");number(static_cast<std::int64_t>((magnitude/3600)*100+(magnitude/60)%60),4);break;
            }
            case 'Z':if(zone)append(text(memory,zone,256));break;
            case 'v':format("%e-%b-%Y",depth+1);break;
            case '+':format("%a %b %e %T %Z %Y",depth+1);break;
            default:throw FormatFault{Fault::unsupported_service};
            }
        }
    }
};
}
a64::Fault NativeCalendar::strftime(std::array<std::uint64_t,31> &r,a64::Address error){
    const auto range=[&](){const std::array<std::uint8_t,4> b{34,0,0,0};if(!memory_.write(error,b))return Fault::write;r[0]=0;return Fault::none;};
    if(!r[1])return range();
    try{
        const auto pattern=text(memory_,r[2],4096);
        std::array<std::uint8_t,56> raw{};if(!memory_.read(r[3],raw))return Fault::read;
        Formatter formatter{memory_,{},std::bit_cast<std::int64_t>(load(std::span{raw}.subspan(40,8))),load(std::span{raw}.subspan(48,8)),{}};
        for(unsigned i=0;i<9;++i)formatter.f[i]=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(load(std::span{raw}.subspan(i*4,4))));
        formatter.format(pattern);
        if(formatter.output.size()>=r[1])return range();
        std::vector<std::uint8_t> result(formatter.output.begin(),formatter.output.end());result.push_back(0);
        if(!memory_.write(r[0],result))return Fault::write;
        r[0]=result.size()-1;return Fault::none;
    }catch(const FormatFault &e){return e.value;}
}
}
