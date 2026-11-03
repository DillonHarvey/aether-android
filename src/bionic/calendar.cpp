#include "calendar.hpp"
#include "floating_environment.hpp"
#include "aether/host/local_time_validation.hpp"
#include <algorithm>
#include <bit>
#include <limits>
#include <vector>

#if defined(_MSC_VER)
#pragma float_control(precise,on,push)
#pragma fenv_access(on)
#endif
namespace aether::bionic {
namespace {
using a64::Fault;
using Registers=std::array<std::uint64_t,31>;
template<std::size_t N> std::array<std::uint8_t,N> bytes(std::uint64_t value){
    std::array<std::uint8_t,N> result{};
    for(unsigned i=0;i<N;++i)result[i]=static_cast<std::uint8_t>(value>>(i*8));
    return result;
}
std::uint64_t load(std::span<const std::uint8_t> input){
    std::uint64_t value=0;for(std::size_t i=0;i<input.size();++i)value|=std::uint64_t{input[i]}<<(i*8);return value;
}
std::int64_t floor_div(std::int64_t value,std::int64_t divisor){
    auto q=value/divisor;if(value%divisor<0)--q;return q;
}
bool leap(std::int64_t year){return year%4==0 && (year%100!=0 || year%400==0);}
std::int64_t before_year(std::int64_t year){return 365*year+floor_div(year-1,4)-floor_div(year-1,100)+floor_div(year-1,400);}
constexpr std::array<unsigned,12> month_days{31,28,31,30,31,30,31,31,30,31,30,31};
std::int64_t calendar_seconds(std::int64_t year,unsigned month,std::int64_t day,std::int64_t hour,std::int64_t minute,std::int64_t second){
    auto days=before_year(year)-before_year(1970)+day-1;
    for(unsigned m=0;m<month;++m)days+=month_days[m]+(m==1 && leap(year));
    return days*86400+hour*3600+minute*60+second;
}
bool utc_time(std::int64_t epoch,host::LocalTime &out){
    const auto days=floor_div(epoch,86400),absolute=days+before_year(1970);
    constexpr auto first=std::int64_t{INT32_MIN}+1900,last=std::int64_t{INT32_MAX}+1900;
    if(absolute<before_year(first) || absolute>=before_year(last+1))return false;
    auto lo=first,hi=last+1;
    while(lo+1<hi){const auto middle=lo+(hi-lo)/2;if(before_year(middle)<=absolute)lo=middle;else hi=middle;}
    auto day=absolute-before_year(lo);const auto yearday=day;unsigned month=0;
    while(month<11){const auto count=month_days[month]+(month==1 && leap(lo));if(day<count)break;day-=count;++month;}
    const auto remainder=epoch%86400<0?epoch%86400+86400:epoch%86400;
    out.second=static_cast<std::int32_t>(remainder%60);out.minute=static_cast<std::int32_t>((remainder/60)%60);
    out.hour=static_cast<std::int32_t>(remainder/3600);out.day=static_cast<std::int32_t>(day+1);out.month=month;
    out.year=static_cast<std::int32_t>(lo-1900);out.yearday=static_cast<std::int32_t>(yearday);
    out.weekday=static_cast<std::int32_t>((days%7+11)%7);out.is_dst=0;out.utc_offset=0;out.zone="UTC";return true;
}
unsigned time_error(host::TimeStatus status){return status==host::TimeStatus::denied?13:status==host::TimeStatus::out_of_range?75:5;}
}
NativeCalendar::~NativeCalendar(){
    for(const auto &[name,address]:zones_){(void)name;try{memory_.unmap(address);}catch(...){}}
    if(scratch_owned_)try{memory_.unmap(scratch_base);}catch(...){}
}
Fault NativeCalendar::fail(Registers &r,a64::Address error,unsigned code,std::uint64_t result){
    if(!memory_.write(error,bytes<4>(code)))return Fault::write;r[0]=result;return Fault::none;
}
void NativeCalendar::ensure_scratch(){
    if(scratch_owned_)return;
    memory_.map(scratch_base,a64::GuestMemory::page_size,a64::read_write);scratch_owned_=true;
}
a64::Address NativeCalendar::zone_name(std::string_view zone){
    auto found=zones_.find(std::string(zone));if(found!=zones_.end())return found->second;
    if(zones_.size()==32)throw a64::GuestError("AETHER_GUEST_CALENDAR_LIMIT","Timezone name bound reached");
    const auto address=0x39000000ULL+zones_.size()*4096;bool owned=false;
    try{
        memory_.map(address,4096,a64::read_write);owned=true;
        std::vector<std::uint8_t> name(zone.begin(),zone.end());name.push_back(0);
        if(!memory_.write(address,name))throw a64::GuestError("AETHER_GUEST_TIME","Cannot initialize guest timezone name");
        memory_.protect(address,a64::Permission::read);zones_.emplace(zone,address);return address;
    }catch(...){if(owned)try{memory_.unmap(address);}catch(...){}throw;}
}
Fault NativeCalendar::store_tm(const host::LocalTime &value,a64::Address target){
    if(!memory_.accessible(target,56,a64::Permission::write))return Fault::write;
    const auto zone=zone_name(value.zone);std::array<std::uint8_t,56> output{};
    const std::array fields{value.second,value.minute,value.hour,value.day,value.month,value.year,value.weekday,value.yearday,value.is_dst};
    for(unsigned i=0;i<fields.size();++i){const auto field=bytes<4>(static_cast<std::uint32_t>(fields[i]));std::copy(field.begin(),field.end(),output.begin()+i*4);}
    const auto offset=bytes<8>(static_cast<std::uint64_t>(value.utc_offset)),pointer=bytes<8>(zone);
    std::copy(offset.begin(),offset.end(),output.begin()+40);std::copy(pointer.begin(),pointer.end(),output.begin()+48);
    return memory_.write(target,output)?Fault::none:Fault::write;
}
Fault NativeCalendar::convert(Registers &r,a64::Address error,bool utc,bool reentrant){
    rejection_={};std::array<std::uint8_t,8> input{};if(!memory_.read(r[0],input))return Fault::read;
    const auto epoch=std::bit_cast<std::int64_t>(load(input));host::LocalTime value;
    if(utc){if(!utc_time(epoch,value))return fail(r,error,75);}
    else{
        const auto status=time_.convert_local_time(epoch,value);if(status!=host::TimeStatus::ok)return fail(r,error,time_error(status));
        if(!host::local_time_matches_epoch(value,epoch))return fail(r,error,5);
    }
    try{
        if(!reentrant)ensure_scratch();const auto target=reentrant?r[1]:scratch_base;
        const auto fault=store_tm(value,target);if(fault!=Fault::none)return fault;r[0]=target;return Fault::none;
    }catch(const std::bad_alloc &){return fail(r,error,12);}
    catch(const a64::GuestError &e){rejection_=e.code=="AETHER_GUEST_CALENDAR_LIMIT"?"calendar: 32 timezone names exhausted":"calendar: owned guest storage unavailable";return Fault::unsupported_service;}
}
Fault NativeCalendar::localtime(Registers &r,a64::Address error){return convert(r,error,false,true);}
Fault NativeCalendar::localtime_static(Registers &r,a64::Address error){return convert(r,error,false,false);}
Fault NativeCalendar::gmtime(Registers &r,a64::Address error){return convert(r,error,true,false);}
Fault NativeCalendar::gmtime_r(Registers &r,a64::Address error){return convert(r,error,true,true);}
Fault NativeCalendar::ctime(Registers &r,a64::Address error){
    auto converted=r;const auto fault=convert(converted,error,false,false);
    if(fault!=Fault::none)return fault;if(!converted[0]){r[0]=0;return Fault::none;}
    std::array<std::uint8_t,56> raw{};if(!memory_.read(scratch_base,raw))return Fault::read;
    const auto field=[&](unsigned index){return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(load(std::span{raw}.subspan(index*4,4))));};
    const auto year=std::int64_t{field(5)}+1900;if(year<0 || year>9999)return fail(r,error,75);
    constexpr std::array<std::string_view,7> days{"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
    constexpr std::array<std::string_view,12> months{"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
    const auto two=[](int value,char pad='0'){std::string text=std::to_string(value);if(text.size()<2)text.insert(text.begin(),pad);return text;};
    auto text=std::string(days[field(6)])+" "+std::string(months[field(4)])+" "+two(field(3),' ')+" "+two(field(2))+":"+two(field(1))+":"+two(field(0))+" ";
    auto y=std::to_string(year);y.insert(0,4-y.size(),'0');text+=y;text+='\n';text+='\0';
    if(!memory_.write(scratch_base+128,{reinterpret_cast<const std::uint8_t*>(text.data()),text.size()}))return Fault::write;
    r[0]=scratch_base+128;return Fault::none;
}
Fault NativeCalendar::difftime(a64::ServiceState &state) noexcept {
    rejection_={};
    if(state.fpcr){rejection_="difftime: nondefault guest floating control is unsupported";return Fault::unsupported_service;}
    HostFloatingEnvironment environment;
    if(!environment.ready()){rejection_="difftime: host floating environment unavailable";return Fault::unsupported_service;}

    const auto end=std::bit_cast<std::int64_t>(state.registers[0]),begin=std::bit_cast<std::int64_t>(state.registers[1]);
    const bool negative=end<begin;
    const auto magnitude=negative?static_cast<std::uint64_t>(begin)-static_cast<std::uint64_t>(end):static_cast<std::uint64_t>(end)-static_cast<std::uint64_t>(begin);
    const auto value=static_cast<double>(magnitude)*(negative?-1.0:1.0);
    const auto raised=std::fetestexcept(FE_ALL_EXCEPT);
    if(!environment.restore()){rejection_="difftime: host floating environment restoration failed";return Fault::windows_service;}
    if(raised&FE_INEXACT)state.fpsr|=16;
    state.vectors[0]={std::bit_cast<std::uint64_t>(value),0};return Fault::none;
}
Fault NativeCalendar::tzset(Registers &r,a64::Address error){
    rejection_={};host::LocalTime observed;const auto status=time_.convert_local_time(0,observed);
    if(status!=host::TimeStatus::ok)return fail(r,error,time_error(status));
    if(!host::local_time_matches_epoch(observed,0))return fail(r,error,5);
    // The provider consults current real host timezone policy on every call;
    // there is no guest TZ environment override or stale timezone rule cache.
    return Fault::none;
}
Fault NativeCalendar::mktime(Registers &r,a64::Address error){
    rejection_={};const auto target=r[0];std::array<std::uint8_t,56> raw{};
    if(!memory_.read(target,raw))return Fault::read;if(!memory_.accessible(target,56,a64::Permission::write))return Fault::write;
    const auto field=[&](unsigned index){return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(load(std::span{raw}.subspan(index*4,4))));};
    const auto month=std::int64_t{field(4)},year=std::int64_t{field(5)}+1900+floor_div(month,12);
    const auto normalized_month=static_cast<unsigned>(month-floor_div(month,12)*12);
    const auto wall=calendar_seconds(year,normalized_month,field(3),field(2),field(1),field(0));
    host::LocalTime wanted;if(!utc_time(wall,wanted) || wanted.year< -299 || wanted.year>8099)return fail(r,error,75,UINT64_MAX);
    const auto preference=field(8);struct Offset {std::int64_t seconds;};std::array<Offset,16> offsets{};std::size_t count=0;
    unsigned failure=0;
    const auto observe=[&](std::int64_t epoch,host::LocalTime &value){
        const auto status=time_.convert_local_time(epoch,value);
        if(status!=host::TimeStatus::ok){if(status!=host::TimeStatus::out_of_range)failure=time_error(status);return false;}
        if(!host::local_time_matches_epoch(value,epoch)){failure=5;return false;}
        if(std::none_of(offsets.begin(),offsets.begin()+count,[&](const auto &offset){return offset.seconds==value.utc_offset;})){
            if(count==offsets.size()){failure=5;return false;}offsets[count++]={value.utc_offset};
        }
        return true;
    };
    // Offsets come exclusively from actual provider conversions around the
    // normalized wall date. Never assume UTC or a one-hour DST adjustment.
    for(const auto delta:std::array<std::int64_t,5>{0,-172800,172800,-15811200,15811200}){
        host::LocalTime value;(void)observe(wall+delta,value);if(failure)return fail(r,error,failure,UINT64_MAX);
    }
    if(!count)return fail(r,error,75,UINT64_MAX);
    std::optional<std::pair<std::int64_t,host::LocalTime>> selected;
    bool converted_candidate=false;
    for(std::size_t i=0;i<count;++i){
        const auto epoch=wall-offsets[i].seconds;host::LocalTime actual;
        if(!observe(epoch,actual)){if(failure)return fail(r,error,failure,UINT64_MAX);continue;}
        converted_candidate=true;
        if(actual.year!=wanted.year || actual.month!=wanted.month || actual.day!=wanted.day || actual.hour!=wanted.hour || actual.minute!=wanted.minute || actual.second!=wanted.second)continue;
        if(preference>=0 && actual.is_dst!=(preference>0))continue;
        if(!selected || epoch<selected->first)selected=std::pair{epoch,std::move(actual)};
    }
    if(!selected){
        if(!converted_candidate)return fail(r,error,75,UINT64_MAX);
        rejection_="mktime: nonexistent local time or forced DST requires an inverse timezone provider; no UTC/offset guess is used";
        return Fault::unsupported_service;
    }
    try{
        const auto fault=store_tm(selected->second,target);if(fault!=Fault::none)return fault;
        r[0]=static_cast<std::uint64_t>(selected->first);return Fault::none;
    }catch(const std::bad_alloc &){return fail(r,error,12,UINT64_MAX);}
    catch(const a64::GuestError &){rejection_="mktime: owned timezone storage unavailable";return Fault::unsupported_service;}
}
}

#if defined(_MSC_VER)
#pragma float_control(pop)
#endif
