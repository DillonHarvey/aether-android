#include "calendar.hpp"
#include "locale.hpp"
#include <bit>
#include <chrono>
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
struct ParseMismatch {};
bool space(char c){return c==' ' || c=='\t' || c=='\n' || c=='\r' || c=='\f' || c=='\v';}
char lower(char c){return c>='A' && c<='Z'?static_cast<char>(c+('a'-'A')):c;}
struct Parser {
    std::string_view input;
    std::size_t position=0;
    std::array<std::int32_t,9> fields;
    std::optional<int> century,short_year,hour12,pm;
    bool year_set=false,month_set=false,day_set=false,yearday_set=false,utc_zone=false;
    std::optional<std::int64_t> offset;
    void whitespace(){while(position<input.size() && space(input[position]))++position;}
    int number(unsigned maximum,int low,int high){
        unsigned count=0;int value=0;
        while(count<maximum && position<input.size() && input[position]>='0' && input[position]<='9'){
            value=value*10+input[position++]-'0';++count;
        }
        if(!count || value<low || value>high)throw ParseMismatch{};return value;
    }
    bool match(std::string_view expected){
        if(expected.size()>input.size()-position)return false;
        for(std::size_t i=0;i<expected.size();++i)if(lower(input[position+i])!=lower(expected[i]))return false;
        position+=expected.size();return true;
    }
    template<std::size_t N> int name(const std::array<std::string_view,N> &names){
        for(std::size_t i=0;i<N;++i)if(match(names[i]))return static_cast<int>(i);
        for(std::size_t i=0;i<N;++i)if(match(names[i].substr(0,3)))return static_cast<int>(i);
        throw ParseMismatch{};
    }
    void parse(std::string_view format,unsigned depth=0){
        if(depth>4)throw FormatFault{Fault::unsupported_service};
        constexpr std::array<std::string_view,7> days{"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"};
        constexpr std::array<std::string_view,12> months{"January","February","March","April","May","June","July","August","September","October","November","December"};
        for(std::size_t i=0;i<format.size();++i){
            if(space(format[i])){whitespace();continue;}
            if(format[i]!='%'){
                if(position==input.size() || input[position++]!=format[i])throw ParseMismatch{};continue;
            }
            if(++i==format.size())throw FormatFault{Fault::unsupported_service};
            if(format[i]=='E' || format[i]=='O')if(++i==format.size())throw FormatFault{Fault::unsupported_service};
            switch(format[i]){
            case '%':if(position==input.size() || input[position++]!='%')throw ParseMismatch{};break;
            case 'a':case 'A':fields[6]=name(days);break;
            case 'b':case 'B':case 'h':fields[4]=name(months);month_set=true;break;
            case 'c':parse("%a %b %e %T %Y",depth+1);break;
            case 'C':century=number(2,0,99);break;
            case 'd':case 'e':whitespace();fields[3]=number(2,1,31);day_set=true;break;
            case 'D':case 'x':parse("%m/%d/%y",depth+1);break;
            case 'F':parse("%Y-%m-%d",depth+1);break;
            case 'H':case 'k':whitespace();fields[2]=number(2,0,23);break;
            case 'I':case 'l':whitespace();hour12=number(2,1,12);fields[2]=*hour12%12;break;
            case 'j':fields[7]=number(3,1,366)-1;yearday_set=true;break;
            case 'm':fields[4]=number(2,1,12)-1;month_set=true;break;
            case 'M':fields[1]=number(2,0,59);break;
            case 'n':case 't':whitespace();break;
            case 'p':case 'P':if(match("AM"))pm=0;else if(match("PM"))pm=1;else throw ParseMismatch{};break;
            case 'r':parse("%I:%M:%S %p",depth+1);break;
            case 'R':parse("%H:%M",depth+1);break;
            case 'S':fields[0]=number(2,0,60);break;
            case 'T':case 'X':parse("%H:%M:%S",depth+1);break;
            case 'u':fields[6]=number(1,1,7)%7;break;
            case 'w':fields[6]=number(1,0,6);break;
            case 'y':short_year=number(2,0,99);break;
            case 'Y':fields[5]=number(4,0,9999)-1900;year_set=true;break;
            case 'z':{
                if(match("Z")){offset=0;break;}
                if(position==input.size() || (input[position]!='+' && input[position]!='-'))throw ParseMismatch{};
                const bool minus=input[position++]=='-';auto start=position;const auto hours=number(2,0,23);
                if(position-start!=2)throw ParseMismatch{};
                if(position<input.size() && input[position]==':')++position;
                start=position;const auto minutes=number(2,0,59);if(position-start!=2)throw ParseMismatch{};
                offset=(hours*3600+minutes*60)*(minus?-1:1);break;
            }
            case 'Z':if(!match("UTC") && !match("GMT"))throw FormatFault{Fault::unsupported_service};utc_zone=true;offset=0;fields[8]=0;break;
            default:throw FormatFault{Fault::unsupported_service};
            }
        }
    }
    void finish(){
        if(year_set){
            const auto year=fields[5]+1900;
            if((short_year && year%100!=*short_year) || (century && year/100!=*century))throw ParseMismatch{};
        }else if(short_year){fields[5]=(century?*century*100:(*short_year>=69?1900:2000))+*short_year-1900;year_set=true;}
        else if(century){
            // A century alone does not establish the missing year digits.
            throw FormatFault{Fault::unsupported_service};
        }
        if(hour12 && pm)fields[2]=*hour12%12+12*(*pm);
        if(!year_set)return;
        const auto year=std::chrono::year{fields[5]+1900};
        if(yearday_set && (!month_set || !day_set)){
            if(fields[7]==365 && !year.is_leap())throw ParseMismatch{};
            const auto date=std::chrono::year_month_day{std::chrono::sys_days{year/1/1}+std::chrono::days{fields[7]}};
            if(!month_set)fields[4]=static_cast<int>(static_cast<unsigned>(date.month()))-1;
            if(!day_set)fields[3]=static_cast<int>(static_cast<unsigned>(date.day()));
            month_set=day_set=true;
        }
        if(month_set && day_set){
            const auto date=year/std::chrono::month{static_cast<unsigned>(fields[4]+1)}/std::chrono::day{static_cast<unsigned>(fields[3])};
            if(!date.ok())throw ParseMismatch{};
            const auto day=std::chrono::sys_days{date};
            fields[6]=static_cast<std::int32_t>(std::chrono::weekday{day}.c_encoding());
            fields[7]=static_cast<std::int32_t>((day-std::chrono::sys_days{year/1/1}).count());
        }
    }
};
}
a64::Fault NativeCalendar::strftime(std::array<std::uint64_t,31> &r,a64::Address error){
    rejection_={};
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
    }catch(const FormatFault &e){if(e.value==Fault::unsupported_service)rejection_="strftime: directive, field or format bound is unsupported";return e.value;}
}
a64::Fault NativeCalendar::strftime_l(std::array<std::uint64_t,31> &r,a64::Address error,const NativeLocale &locale){
    if(!locale.valid_time_locale(r[4])){
        rejection_="strftime_l: explicit locale is not a live owned C/C.UTF-8 locale";
        return Fault::unsupported_service;
    }
    return strftime(r,error);
}
a64::Fault NativeCalendar::strptime(std::array<std::uint64_t,31> &r,a64::Address error){
    rejection_={};
    try{
        const auto input=text(memory_,r[0],4096),format=text(memory_,r[1],4096);
        std::array<std::uint8_t,56> raw{};if(!memory_.read(r[2],raw))return Fault::read;
        Parser parser{input,0,{}};
        for(unsigned i=0;i<9;++i)parser.fields[i]=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(load(std::span{raw}.subspan(i*4,4))));
        parser.parse(format);parser.finish();
        if(!memory_.accessible(r[2],56,a64::Permission::write))return Fault::write;
        const auto store=[&](unsigned at,std::uint64_t value,unsigned count){for(unsigned i=0;i<count;++i)raw[at+i]=static_cast<std::uint8_t>(value>>(i*8));};
        for(unsigned i=0;i<9;++i)store(i*4,static_cast<std::uint32_t>(parser.fields[i]),4);
        if(parser.offset)store(40,static_cast<std::uint64_t>(*parser.offset),8);
        if(parser.utc_zone)store(48,zone_name("UTC"),8);
        if(!memory_.write(r[2],raw))return Fault::write;r[0]+=parser.position;return Fault::none;
    }catch(const ParseMismatch &){r[0]=0;return Fault::none;}
    catch(const FormatFault &e){if(e.value==Fault::unsupported_service)rejection_="strptime: directive, timezone, partial century or 4096-byte parse bound is unsupported";return e.value;}
    catch(const std::bad_alloc &){return fail(r,error,12);}
    catch(const a64::GuestError &){rejection_="strptime: owned timezone storage unavailable";return Fault::unsupported_service;}
}
}
