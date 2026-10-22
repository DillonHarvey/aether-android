#pragma once
#include "aether/security/protocol.hpp"
#include "aether/host/local_time_validation.hpp"
#include <bit>
namespace aether::security {
inline void append_local_calendar(std::vector<std::uint8_t> &payload,const host::LocalTime &value) {
    if(!host::valid_local_time(value))throw ProtocolError("AETHER_IPC_TIME: invalid local calendar");
    const std::array fields{value.second,value.minute,value.hour,value.day,value.month,value.year,value.weekday,value.yearday,value.is_dst};
    for(const auto field:fields)append_u64(payload,std::bit_cast<std::uint64_t>(std::int64_t{field}));
    append_u64(payload,std::bit_cast<std::uint64_t>(value.utc_offset));append_text(payload,value.zone);
}
inline host::LocalTime read_local_calendar(std::span<const std::uint8_t> payload) {
    if(payload.size()<89 || payload.size()>344)throw ProtocolError("AETHER_IPC_TIME: invalid local calendar size");
    host::LocalTime value;
    const std::array fields{&value.second,&value.minute,&value.hour,&value.day,&value.month,&value.year,&value.weekday,&value.yearday,&value.is_dst};
    std::size_t offset=0;
    for(const auto field:fields){const auto input=std::bit_cast<std::int64_t>(read_u64(payload,offset));offset+=8;if(input<INT32_MIN || input>INT32_MAX)throw ProtocolError("AETHER_IPC_TIME: local calendar integer overflow");*field=static_cast<std::int32_t>(input);}
    value.utc_offset=std::bit_cast<std::int64_t>(read_u64(payload,offset));offset+=8;
    value.zone=read_text(payload,offset,256);
    if(offset!=payload.size() || !host::valid_local_time(value))throw ProtocolError("AETHER_IPC_TIME: invalid local calendar values");
    return value;
}
}
