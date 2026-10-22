#include "zlib.hpp"
#include <zlib.h>
#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>

namespace aether::bionic {
namespace {
using a64::Address;using a64::Fault;
using Record=std::array<std::uint8_t,112>;
constexpr std::size_t transfer_limit=1024*1024;
constexpr Address messages=0x28000000,first_state=0x28010000,state_limit=0x29000000;
std::uint64_t get(const Record &b,std::size_t at,std::size_t size=8){std::uint64_t n=0;for(std::size_t i=0;i<size;++i)n|=std::uint64_t{b[at+i]}<<(i*8);return n;}
void put(Record &b,std::size_t at,std::uint64_t n,std::size_t size=8){for(std::size_t i=0;i<size;++i)b[at+i]=static_cast<std::uint8_t>(n>>(i*8));}
void status(std::array<std::uint64_t,31> &r,int n){r[0]=static_cast<std::uint32_t>(n);}
bool overlap(Address a,std::size_t n,Address b,std::size_t m){return n && m && a<b+m && b<a+n;}
struct State {
    z_stream stream{};Address guest=0,token=0;std::size_t allocated=0;
    struct alignas(std::max_align_t) Allocation {std::size_t bytes;};
    static voidpf allocate(voidpf opaque,uInt count,uInt size){auto &s=*static_cast<State*>(opaque);const auto bytes=std::uint64_t{count}*size;if(bytes>transfer_limit-s.allocated)return nullptr;auto *p=static_cast<Allocation*>(std::calloc(1,sizeof(Allocation)+static_cast<std::size_t>(bytes)));if(!p)return nullptr;p->bytes=static_cast<std::size_t>(bytes);s.allocated+=p->bytes;return p+1;}
    static void release(voidpf opaque,voidpf address){if(!address)return;auto &s=*static_cast<State*>(opaque);auto *p=static_cast<Allocation*>(address)-1;s.allocated-=p->bytes;std::free(p);}
    State(){stream.zalloc=allocate;stream.zfree=release;stream.opaque=this;}
    ~State(){if(stream.state)::inflateEnd(&stream);}
};
}
struct NativeZlib::Impl {
    a64::GuestMemory &memory;Address allocate,release,next=first_state;
    std::map<Address,std::unique_ptr<State>> streams;
    std::array<std::array<std::uint8_t,256>,32> texts{};std::size_t text_count=0;bool messages_owned=false;
    std::string_view error;
    Impl(a64::GuestMemory &m,Address a,Address f):memory(m),allocate(a),release(f){}
    ~Impl(){for(const auto &[address,s]:streams){(void)address;try{memory.unmap(s->token);}catch(...){}}if(messages_owned)try{memory.unmap(messages);}catch(...){}}
    Fault reject(std::string_view message){error=message;return Fault::unsupported_service;}
    bool defaults(const Record &b)const{return (!get(b,64)||get(b,64)==allocate)&&(!get(b,72)||get(b,72)==release);}
    void ensure_messages(){if(messages_owned)return;memory.map(messages,8192,a64::read_write);messages_owned=true;memory.protect(messages,a64::Permission::read);}
    Address message(const char *text){if(!text)return 0;std::array<std::uint8_t,256> bytes{};const auto count=(std::min)(std::strlen(text),std::size_t{255});std::copy_n(reinterpret_cast<const std::uint8_t*>(text),count,bytes.begin());for(std::size_t i=0;i<text_count;++i)if(texts[i]==bytes)return messages+i*256;if(text_count==texts.size())return 0;memory.protect(messages,a64::read_write);const auto at=messages+text_count*256;const bool ok=memory.write(at,bytes);memory.protect(messages,a64::Permission::read);if(!ok)throw a64::GuestError("AETHER_ZLIB_MAPPING","Cannot publish zlib diagnostic");texts[text_count++]=bytes;return at;}
    void sync(Record &b,const State &s){put(b,48,message(s.stream.msg));put(b,88,static_cast<std::uint32_t>(s.stream.data_type),4);put(b,96,static_cast<std::uint32_t>(s.stream.adler));}
    Fault call(unsigned operation,std::array<std::uint64_t,31> &r){
        if(operation==0){const auto count=static_cast<std::uint32_t>(r[2]);if(!r[1]){r[0]=1;return Fault::none;}if(count>transfer_limit)return reject("adler32: transfer exceeds 1 MiB");std::vector<std::uint8_t> bytes((std::max)(std::size_t{1},std::size_t{count}));if(count && !memory.read(r[1],std::span{bytes}.first(count)))return Fault::read;r[0]=::adler32(static_cast<uLong>(r[0]),bytes.data(),count);return Fault::none;}
        if(operation==1){
            if(!r[1] || static_cast<std::uint32_t>(r[2])!=112){status(r,Z_VERSION_ERROR);return Fault::none;}
            std::array<std::uint8_t,1> version{};if(!memory.read(r[1],version))return Fault::read;if(version[0]!=ZLIB_VERSION[0]){status(r,Z_VERSION_ERROR);return Fault::none;}
        }
        const Address address=r[0];if(!address){status(r,Z_STREAM_ERROR);return Fault::none;}
        Record b{};if(!memory.read(address,b))return Fault::read;if(!memory.accessible(address,b.size(),a64::Permission::write))return Fault::write;
        if(operation==1){
            if(streams.contains(address)){status(r,Z_STREAM_ERROR);return Fault::none;}
            if(!defaults(b))return reject("inflateInit_: custom guest allocation callbacks are unsupported");
            if(streams.size()==16){status(r,Z_MEM_ERROR);return Fault::none;}
            if(next==state_limit)return reject("inflateInit_: lifetime stream identity limit reached");
            auto s=std::make_unique<State>();const int code=::inflateInit_(&s->stream,ZLIB_VERSION,sizeof(z_stream));if(code!=Z_OK){status(r,code);return Fault::none;}
            ensure_messages();memory.map(next,4096,a64::Permission::read);s->guest=address;s->token=next;
            try {streams.emplace(address,std::move(s));}catch(...){memory.unmap(next);throw;}
            const auto &stored=*streams.at(address);next+=4096;
            if(!get(b,64))put(b,80,0);put(b,64,allocate);put(b,72,release);put(b,16,0);put(b,40,0);put(b,56,stored.token);sync(b,stored);
            if(!memory.write(address,b))return Fault::write;status(r,Z_OK);return Fault::none;
        }
        const auto found=streams.find(address);if(found==streams.end() || get(b,56)!=found->second->token){status(r,Z_STREAM_ERROR);return Fault::none;}
        auto &s=*found->second;if(get(b,64)!=allocate || get(b,72)!=release)return reject("inflate: changed guest allocation callbacks are unsupported");
        if(operation==3){const int code=::inflateEnd(&s.stream);if(code==Z_OK){put(b,56,0);if(!memory.write(address,b))return Fault::write;memory.unmap(s.token);streams.erase(found);}status(r,code);return Fault::none;}
        const auto input=get(b,0),output=get(b,24);const auto in_count=static_cast<std::uint32_t>(get(b,8,4)),out_count=static_cast<std::uint32_t>(get(b,32,4));
        if(!output || (!input && in_count)){status(r,Z_STREAM_ERROR);return Fault::none;}
        if(in_count>transfer_limit || out_count>transfer_limit)return reject("inflate: per-call transfer exceeds 1 MiB");
        if(!memory.accessible(input,in_count,a64::Permission::read) && in_count)return Fault::read;
        if(!memory.accessible(output,out_count,a64::Permission::write) && out_count)return Fault::write;
        if(overlap(output,out_count,address,b.size()) || overlap(input,in_count,output,out_count))return reject("inflate: overlapping guest stream/input/output ranges are unsupported");
        std::vector<std::uint8_t> in((std::max)(std::size_t{1},std::size_t{in_count})),out((std::max)(std::size_t{1},std::size_t{out_count}));if(in_count && !memory.read(input,std::span{in}.first(in_count)))return Fault::read;
        s.stream.next_in=input?in.data():nullptr;s.stream.avail_in=in_count;s.stream.next_out=out.data();s.stream.avail_out=out_count;
        const auto prior_in=s.stream.total_in,prior_out=s.stream.total_out;
        const int code=::inflate(&s.stream,static_cast<int>(static_cast<std::int32_t>(r[1])));
        const auto counted_in=static_cast<uLong>(s.stream.total_in-prior_in),counted_out=static_cast<uLong>(s.stream.total_out-prior_out);
        const auto consumed=in_count-s.stream.avail_in,produced=out_count-s.stream.avail_out;
        put(b,0,input+consumed);put(b,8,s.stream.avail_in,4);put(b,16,get(b,16)+counted_in);put(b,24,output+produced);put(b,32,s.stream.avail_out,4);put(b,40,get(b,40)+counted_out);sync(b,s);
        s.stream.next_in=nullptr;s.stream.next_out=nullptr;
        if(produced && !memory.write(output,std::span{out}.first(produced)))return Fault::write;
        if(!memory.write(address,b))return Fault::write;status(r,code);return Fault::none;
    }
};
NativeZlib::NativeZlib(a64::GuestMemory &memory,Address allocate,Address release):impl_(std::make_unique<Impl>(memory,allocate,release)){}
NativeZlib::~NativeZlib()=default;
a64::Fault NativeZlib::invoke(unsigned operation,std::array<std::uint64_t,31> &r)noexcept{try{return impl_->call(operation,r);}catch(const std::bad_alloc &){status(r,Z_MEM_ERROR);return Fault::none;}catch(...){return impl_->reject("zlib: host marshalling or mapping failure");}}
std::string_view NativeZlib::rejection()const noexcept{return impl_->error;}
}
