#include "calendar.hpp"
#include "aether/host/local_time_validation.hpp"
#include <bit>
#include <algorithm>
#include <vector>
namespace aether::bionic {
namespace {
template<std::size_t N> std::array<std::uint8_t,N> bytes(std::uint64_t value){std::array<std::uint8_t,N> result{};for(unsigned i=0;i<N;++i)result[i]=static_cast<std::uint8_t>(value>>(8*i));return result;}
}
NativeCalendar::~NativeCalendar(){for(const auto &[name,address]:zones_){(void)name;try{memory_.unmap(address);}catch(...){}}}
a64::Fault NativeCalendar::localtime(std::array<std::uint64_t,31> &r,a64::Address error) {
    using a64::Fault;
    const auto fail=[&](unsigned code){if(!memory_.write(error,bytes<4>(code)))return Fault::write;r[0]=0;return Fault::none;};
    std::array<std::uint8_t,8> input{};if(!memory_.read(r[0],input))return Fault::read;
    std::uint64_t bits=0;for(unsigned i=0;i<8;++i)bits|=std::uint64_t{input[i]}<<(8*i);
    host::LocalTime value;const auto status=time_.convert_local_time(std::bit_cast<std::int64_t>(bits),value);
    if(status!=host::TimeStatus::ok)return fail(status==host::TimeStatus::denied?13:status==host::TimeStatus::out_of_range?75:5);
    if(!host::local_time_matches_epoch(value,std::bit_cast<std::int64_t>(bits)))return fail(5);
    if(!memory_.accessible(r[1],56,a64::Permission::write))return Fault::write;
    auto found=zones_.find(value.zone);
    if(found==zones_.end()){
        if(zones_.size()==32)return Fault::unsupported_service;
        const auto address=0x39000000ULL+zones_.size()*4096;bool owned=false;
        try{
            memory_.map(address,4096,a64::read_write);owned=true;
            std::vector<std::uint8_t> name(value.zone.begin(),value.zone.end());name.push_back(0);
            if(!memory_.write(address,name))throw a64::GuestError("AETHER_GUEST_TIME","Cannot initialize guest timezone name");
            memory_.protect(address,a64::Permission::read);found=zones_.emplace(value.zone,address).first;
        }catch(...){if(owned)try{memory_.unmap(address);}catch(...){}throw;}
    }
    std::array<std::uint8_t,56> output{};
    const std::array fields{value.second,value.minute,value.hour,value.day,value.month,value.year,value.weekday,value.yearday,value.is_dst};
    for(unsigned i=0;i<fields.size();++i){const auto field=bytes<4>(static_cast<std::uint32_t>(fields[i]));std::copy(field.begin(),field.end(),output.begin()+i*4);}
    const auto offset=bytes<8>(static_cast<std::uint64_t>(value.utc_offset)),zone=bytes<8>(found->second);
    std::copy(offset.begin(),offset.end(),output.begin()+40);std::copy(zone.begin(),zone.end(),output.begin()+48);
    if(!memory_.write(r[1],output))return Fault::write;r[0]=r[1];return Fault::none;
}
}
