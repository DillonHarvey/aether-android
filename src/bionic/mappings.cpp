#include "mappings.hpp"
#include <algorithm>
#include <limits>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
constexpr std::uint64_t page=a64::GuestMemory::page_size;
bool rounded(std::uint64_t value,std::uint64_t &result) {
    if(value>UINT64_MAX-(page-1))return false;
    result=(value+page-1)&~(page-1);return true;
}
}
NativeMappings::~NativeMappings() {
    for(const auto &[address,size]:owned_)try{memory_.unmap_range(address,static_cast<std::size_t>(size));}catch(...){}
}
Fault NativeMappings::error(Address address,std::array<std::uint64_t,31> &r,unsigned value) {
    ++errors;std::array<std::uint8_t,4> bytes{};
    for(unsigned i=0;i<4;++i)bytes[i]=static_cast<std::uint8_t>(value>>(i*8));
    if(!memory_.write(address,bytes)){rejection_="mapping: invalid guest errno storage";return Fault::write;}
    r[0]=UINT64_MAX;return Fault::none;
}
Fault NativeMappings::reject(std::string_view message) {rejection_=message;return Fault::unsupported_service;}
bool NativeMappings::covered(Address begin,Address end) const noexcept {
    auto cursor=begin;
    for(const auto &[address,size]:owned_){
        if(address+size<=cursor)continue;
        if(address>cursor)return false;
        cursor=std::max(cursor,std::min(end,address+size));if(cursor==end)return true;
    }
    return cursor==end;
}
bool NativeMappings::foreign(Address begin,Address end) const {
    auto cursor=begin;
    for(const auto &[address,size]:owned_){
        if(address+size<=cursor)continue;
        if(address>=end)break;
        if(address>cursor){const auto gap=std::min(address,end);if(memory_.find_free(cursor,gap,static_cast<std::size_t>(gap-cursor))!=cursor)return true;}
        cursor=std::max(cursor,std::min(end,address+size));if(cursor==end)return false;
    }
    return cursor<end && memory_.find_free(cursor,end,static_cast<std::size_t>(end-cursor))!=cursor;
}
Fault NativeMappings::invoke(MappingOperation operation,Address errno_address,std::array<std::uint64_t,31> &r) {
    rejection_={};
    const auto fail=[&](unsigned code){return error(errno_address,r,code);};
    try {
        const auto address=r[0],length=r[1];std::uint64_t size=0;
        // ARM64's mmap wrapper rejects byte-offset misalignment before do_mmap.
        if(operation==MappingOperation::map && (r[5]&(page-1)))return fail(22);
        if(operation!=MappingOperation::map && address%page)return fail(22);
        // A zero-length mprotect changes nothing, even with unsupported prot bits.
        if(operation==MappingOperation::protect && !length){r[0]=0;return Fault::none;}

        const auto protection=operation==MappingOperation::unmap?0U:static_cast<std::uint32_t>(r[2]);
        if(operation!=MappingOperation::unmap && (protection&~7U))return fail(22);
        if((protection&6U)==6U)return fail(1); // No writable/executable guest mappings.
        if(protection==4)return reject("mapping: execute-only guest pages are unsupported");
        const auto permission=protection==0?a64::Permission::none:
            (protection&2U)?a64::read_write:(protection&4U)?a64::read_execute:a64::Permission::read;
        if(operation==MappingOperation::map){
            if(!length)return fail(22);
            if(!rounded(length,size) || size>a64::GuestMemory::maximum_bytes)return fail(12);
            const auto flags=static_cast<std::uint32_t>(r[3]);
            constexpr unsigned no_replace=0x100000;
            if((flags&3U)==0 || (flags&3U)==3U)return fail(22);
            if((flags&3U)!=2U || !(flags&0x20U))return reject("mmap: file-backed/shared mappings are unsupported");
            if(flags&~(0x22U|no_replace))return reject("mmap: fixed replacement or additional flags are unsupported");
            std::optional<Address> target;
            if(flags&no_replace){
                if(address%page)return fail(22);
                if(address<first || address>=limit || size>limit-address)return reject("mmap: fixed address is outside owned mapping arena");
                target=memory_.find_free(address,address+size,static_cast<std::size_t>(size));
                if(!target)return fail(17);
            } else {
                const auto hint=address&~(page-1);
                if(hint>=first && hint<limit && size<=limit-hint)target=memory_.find_free(hint,hint+size,static_cast<std::size_t>(size));
                if(!target)target=memory_.find_free(first,limit,static_cast<std::size_t>(size));
                if(!target)return fail(12);
            }
            if(owned_.size()>=4096)return fail(12);
            auto next=owned_;next.emplace(*target,size); // Allocate all ownership metadata before mapping.
            memory_.map(*target,static_cast<std::size_t>(size),permission);
            owned_.swap(next);r[0]=*target;return Fault::none;
        }
        if(!length)return fail(22);
        if(!rounded(length,size) || size>a64::GuestMemory::address_limit || address>=a64::GuestMemory::address_limit || size>a64::GuestMemory::address_limit-address)
            return fail(operation==MappingOperation::unmap?22:12);
        if(address<first || address>=limit || size>limit-address)return reject("mapping: range is outside owned mapping arena");
        const auto end=address+size;
        if(foreign(address,end))return reject("mapping: range includes a foreign guest allocation");
        if(operation==MappingOperation::protect){
            if(!covered(address,end))return fail(12);
            memory_.protect_range(address,static_cast<std::size_t>(size),permission);r[0]=0;return Fault::none;
        }
        std::map<Address,std::uint64_t> next;
        for(const auto &[start,bytes]:owned_){
            const auto finish=start+bytes;
            if(finish<=address || start>=end){next.emplace(start,bytes);continue;}
            if(start<address)next.emplace(start,address-start);
            if(finish>end)next.emplace(end,finish-end);
        }
        if(next.size()>4096)return fail(12);
        memory_.unmap_range(address,static_cast<std::size_t>(size));
        owned_.swap(next);r[0]=0;return Fault::none;
    } catch(const std::bad_alloc &) {return fail(12);}
    catch(const a64::GuestError &e){
        if(e.code=="AETHER_GUEST_PROTECTION"){rejection_="mprotect: host protection update failed; actual completed changes retained";return Fault::windows_service;}
        return fail(12);
    }
}
}
