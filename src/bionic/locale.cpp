#include "locale.hpp"
#include "threads.hpp"
#include <algorithm>
#include <bit>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
struct ReadFault {};
struct NameLimit {};
template<std::size_t N> std::array<std::uint8_t,N> bytes(std::uint64_t value){
    std::array<std::uint8_t,N> result{};
    for(unsigned i=0;i<N;++i)result[i]=static_cast<std::uint8_t>(value>>(i*8));
    return result;
}
unsigned name_mode(a64::GuestMemory &memory,Address pointer){
    std::array<char,128> name{};
    for(std::size_t i=0;i<name.size();++i){
        std::array<std::uint8_t,1> byte{};
        if(pointer>=a64::GuestMemory::address_limit || i>=a64::GuestMemory::address_limit-pointer ||
           !memory.read(pointer+i,byte))throw ReadFault{};
        if(!byte[0]){
            const std::string_view value{name.data(),i};
            if(value=="C" || value=="POSIX")return 1;
            if(value.empty() || value=="C.UTF-8" || value=="en_US.UTF-8")return 4;
            return 0;
        }
        name[i]=static_cast<char>(byte[0]);
    }
    throw NameLimit{};
}
}
NativeLocale::~NativeLocale(){
    for(const auto &entry:objects_)if(entry.address)try{memory_.unmap(entry.address);}catch(...){}
    if(constants_owned_)try{memory_.unmap(constants_base);}catch(...){}
}
void NativeLocale::initialize(){
    if(initialized_)return;
    std::array<std::uint8_t,4096> page{};
    const auto pointer=[&](unsigned at,Address address){const auto value=bytes<8>(address);std::copy(value.begin(),value.end(),page.begin()+at);};
    for(unsigned i=0;i<10;++i)pointer(i*8,constants_base+(i?0x122:0x120));
    std::fill(page.begin()+80,page.begin()+94,std::uint8_t{255}); // AAPCS64 plain char is unsigned.
    page[0x100]='C';
    constexpr std::string_view utf8="C.UTF-8";
    std::copy(utf8.begin(),utf8.end(),page.begin()+0x110);
    page[0x120]='.';
    try{
        memory_.map(constants_base,page.size(),a64::read_write);constants_owned_=true;
        if(!memory_.write(constants_base,page))throw a64::GuestError("AETHER_GUEST_LOCALE","Cannot initialize guest locale data");
        memory_.protect(constants_base,a64::Permission::read);initialized_=true;
    }catch(...){
        if(constants_owned_)try{memory_.unmap(constants_base);constants_owned_=false;}catch(...){}
        throw;
    }
}
NativeLocale::Object *NativeLocale::object(Address address) noexcept {
    for(auto &entry:objects_)if(entry.address && entry.address==address)return &entry;
    return nullptr;
}
Fault NativeLocale::fail(std::array<std::uint64_t,31> &r,unsigned error) noexcept {
    if(!memory_.write(threads_.error_address(),bytes<4>(error))){
        rejection_="locale: current logical errno is outside writable guest memory";return Fault::write;
    }
    r[0]=0;return Fault::none;
}
Fault NativeLocale::allocate(std::array<std::uint64_t,31> &r,unsigned mode){
    auto slot=std::find_if(objects_.begin(),objects_.end(),[](const auto &entry){return !entry.address;});
    if(slot==objects_.end() || next_>=objects_limit)return fail(r,12);
    const auto address=next_;bool owned=false;
    try{
        memory_.map(address,4096,a64::read_write);owned=true;
        if(!memory_.write(address,bytes<8>(mode)))throw a64::GuestError("AETHER_GUEST_LOCALE","Cannot initialize owned locale");
    }catch(...){
        if(owned)try{memory_.unmap(address);}catch(...){}
        return fail(r,12);
    }
    *slot={address,mode};next_+=4096;r[0]=address;return Fault::none;
}
Fault NativeLocale::invoke(unsigned operation,std::array<std::uint64_t,31> &r) noexcept {
    rejection_={};
    if(!initialized_){rejection_="locale service is not initialized";return Fault::unsupported_service;}
    try{
        if(operation==0){
            constexpr std::uint32_t all_mask=0x1fbf;
            if((static_cast<std::uint32_t>(r[0])&~all_mask) || !r[1])return fail(r,22);
            const auto mode=name_mode(memory_,r[1]);
            if(!mode)return fail(r,2);
            // Bionic ignores base and category differences; objects encode C versus UTF-8.
            return allocate(r,mode);
        }
        if(operation==1){
            if(r[0]==global_locale)return allocate(r,global_mode_);
            const auto found=object(r[0]);
            if(!found){rejection_="duplocale: handle is not an owned live locale";return Fault::unsupported_service;}
            return allocate(r,found->mode);
        }
        if(operation==2){
            if(!r[0])return Fault::none;
            const auto found=object(r[0]);
            if(!found){rejection_="freelocale: handle is not an owned live locale";return Fault::unsupported_service;}
            memory_.unmap(found->address);*found={};return Fault::none;
        }
        if(operation==3){
            const auto selection=r[0];
            if(selection && selection!=global_locale && !object(selection)){
                rejection_="uselocale: handle is not an owned live locale";return Fault::unsupported_service;
            }
            auto &current=threads_.current_locale();const auto previous=current;
            if(!selection && previous!=global_locale && !object(previous)){
                rejection_="uselocale: selected locale has been freed";return Fault::unsupported_service;
            }
            if(selection)current=selection;
            r[0]=previous;return Fault::none;
        }
        if(operation==4){
            const auto category=std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(r[0]));
            if(category<0 || category>12)return fail(r,22);
            if(r[1]){
                const auto mode=name_mode(memory_,r[1]);
                if(!mode)return fail(r,2);
                global_mode_=mode;
            }
            r[0]=global_mode_==4?utf8_name_address:c_name_address;return Fault::none;
        }
        if(operation==5){r[0]=lconv_address;return Fault::none;}
        if(operation==6){
            const auto selected=threads_.current_locale();
            if(selected==global_locale){r[0]=global_mode_;return Fault::none;}
            const auto found=object(selected);
            if(!found){rejection_="MB_CUR_MAX: selected locale has been freed";return Fault::unsupported_service;}
            r[0]=found->mode;return Fault::none;
        }
        rejection_="unknown native locale operation";return Fault::unsupported_service;
    }catch(const ReadFault &){rejection_="locale name is outside readable guest memory";return Fault::read;}
    catch(const NameLimit &){rejection_="locale name exceeds the 128-byte profile";return Fault::unsupported_service;}
    catch(...){rejection_="native locale allocation or internal operation failed";return Fault::unsupported_service;}
}
}
