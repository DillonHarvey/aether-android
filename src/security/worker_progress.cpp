#include "aether/security/worker_progress.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace aether::security {
namespace {
constexpr std::size_t mapping_bytes=4096,record_count=16;
constexpr std::uint64_t magic=0x3152474f52505457ULL;
struct Header {
    std::uint64_t signature;
    std::uint32_t version,header_bytes,record_bytes,capacity;
    std::array<std::uint8_t,40> reserved;
};
struct alignas(8) Record {
    volatile LONG64 commit;
    std::uint32_t stage,method,pc,owner_length,name_length,label_length;
    std::uint64_t instructions;
    std::array<char,80> owner,name;
    std::array<char,32> label;
    std::uint32_t kind,reserved;
};
struct alignas(8) NativeFault {
    volatile LONG64 commit;
    std::uint32_t code,thread;
    std::uint64_t rip,rsp,address,stack_base,stack_limit,allocation_base,image_base;
    std::array<std::uint8_t,120> reserved;
};
struct Layout {Header header;std::array<Record,record_count> records;NativeFault fault;};
static_assert(sizeof(NativeFault)==192 && offsetof(Layout,fault)==3904);
void *volatile active_fault_writer=nullptr;
static_assert(sizeof(Header)==64 && sizeof(Record)==240 && sizeof(Layout)<=mapping_bytes);
bool valid_header(const Header &header) noexcept {
    return header.signature==magic && header.version==1 && header.header_bytes==sizeof(Header) &&
        header.record_bytes==sizeof(Record) && header.capacity==record_count &&
        std::all_of(header.reserved.begin(),header.reserved.end(),[](auto byte){return byte==0;});
}
std::uint32_t copy_label(std::string_view source,std::span<char> output) noexcept {
    const auto count=std::min(source.size(),output.size());
    for(std::size_t n=0;n<count;++n){const auto byte=static_cast<unsigned char>(source[n]);output[n]=byte>=32 && byte<=126?static_cast<char>(byte):'?';}
    return static_cast<std::uint32_t>(count);
}
bool printable(std::span<const char> text) noexcept {
    return std::all_of(text.begin(),text.end(),[](char value){return value>=32 && value<=126;});
}
}
WorkerProgress::WorkerProgress():mapping_(CreateFileMappingW(INVALID_HANDLE_VALUE,nullptr,PAGE_READWRITE,0,static_cast<DWORD>(mapping_bytes),nullptr)) {
    if(!mapping_)throw std::runtime_error("AETHER_WORKER_PROGRESS: anonymous mapping creation failed");
    view_=MapViewOfFile(mapping_.get(),FILE_MAP_READ|FILE_MAP_WRITE,0,0,mapping_bytes);
    if(!view_)throw std::runtime_error("AETHER_WORKER_PROGRESS: parent mapping failed");
    std::memset(view_,0,mapping_bytes);
    static_cast<Layout *>(view_)->header={magic,1,sizeof(Header),sizeof(Record),record_count,{}};
}
WorkerProgress::~WorkerProgress(){if(view_)UnmapViewOfFile(view_);}
WorkerProgressWriter::WorkerProgressWriter(HANDLE owned_duplicated_handle):mapping_(owned_duplicated_handle) {
    if(!mapping_)throw std::runtime_error("AETHER_WORKER_PROGRESS: invalid section handle");
    // PAGE_READWRITE sections must never admit executable views, even when the
    // parent accidentally passed a section handle with broader access rights.
    if(void *executable=MapViewOfFile(mapping_.get(),FILE_MAP_READ|FILE_MAP_EXECUTE,0,0,mapping_bytes)) {
        UnmapViewOfFile(executable);throw std::runtime_error("AETHER_WORKER_PROGRESS: executable section refused");
    }
    view_=MapViewOfFile(mapping_.get(),FILE_MAP_READ|FILE_MAP_WRITE,0,0,mapping_bytes);
    if(!view_)throw std::runtime_error("AETHER_WORKER_PROGRESS: worker mapping failed");
    if(!valid_header(static_cast<Layout *>(view_)->header)) {
        UnmapViewOfFile(view_);view_=nullptr;throw std::runtime_error("AETHER_WORKER_PROGRESS: invalid section schema");
    }
    for(const auto &record:static_cast<Layout *>(view_)->records) {
        const auto commit=record.commit;
        if(commit>0 && !(commit&1))sequence_=std::max(sequence_,static_cast<std::uint64_t>(commit)/2);
    }
}
WorkerProgressWriter::~WorkerProgressWriter(){if(view_)UnmapViewOfFile(view_);}
void WorkerProgressWriter::write(std::uint32_t kind,std::uint32_t stage_value,std::uint32_t method,std::uint32_t pc,
                                 std::uint64_t instructions,std::string_view owner,std::string_view name,std::string_view label) noexcept {
    if(!view_ || !valid_header(static_cast<Layout *>(view_)->header) || sequence_>=static_cast<std::uint64_t>(std::numeric_limits<LONG64>::max())/2)return;
    const auto sequence=++sequence_;auto &record=static_cast<Layout *>(view_)->records[(sequence-1)%record_count];
    const auto committed=static_cast<LONG64>(sequence*2);
    InterlockedExchange64(&record.commit,committed-1);MemoryBarrier();
    record.stage=stage_value;record.method=method;record.pc=pc;record.instructions=instructions;
    record.owner_length=copy_label(owner,record.owner);record.name_length=copy_label(name,record.name);record.label_length=copy_label(label,record.label);
    record.kind=kind;record.reserved=0;
    MemoryBarrier();InterlockedExchange64(&record.commit,committed);
}
void WorkerProgressWriter::refresh_native_stack() noexcept {
    if(!fault_owner_ || GetCurrentThreadId()!=fault_owner_)return;
    const auto *tib=reinterpret_cast<const NT_TIB *>(NtCurrentTeb());
    const auto base=reinterpret_cast<std::uint64_t>(tib->StackBase);
    if(base==cached_stack_base_)return;
    cached_stack_base_=0;cached_allocation_base_=0;
    MEMORY_BASIC_INFORMATION info{};
    if(VirtualQuery(tib->StackLimit,&info,sizeof(info))==sizeof(info)) {
        cached_allocation_base_=reinterpret_cast<std::uint64_t>(info.AllocationBase);
        cached_stack_base_=base;
    }
}
bool WorkerProgressWriter::prepare_native_stack() noexcept {
    if(!fault_owner_)return true;
    if(GetCurrentThreadId()!=fault_owner_)return false;
    ULONG guarantee=32*1024;
    if(!SetThreadStackGuarantee(&guarantee))return false;
    refresh_native_stack();return true;
}
void WorkerProgressWriter::capture_native_fault(EXCEPTION_POINTERS *error) noexcept {
    if(!view_ || !error || !error->ExceptionRecord || !error->ContextRecord ||
       error->ExceptionRecord->ExceptionCode!=EXCEPTION_STACK_OVERFLOW || GetCurrentThreadId()!=fault_owner_)return;
    auto &fault=static_cast<Layout *>(view_)->fault;
    if(InterlockedCompareExchange64(&fault.commit,1,0)!=0)return;
    const auto *tib=reinterpret_cast<const NT_TIB *>(NtCurrentTeb());
    fault.code=EXCEPTION_STACK_OVERFLOW;fault.thread=fault_owner_;
    fault.rip=error->ContextRecord->Rip;fault.rsp=error->ContextRecord->Rsp;
    fault.address=reinterpret_cast<std::uint64_t>(error->ExceptionRecord->ExceptionAddress);
    fault.stack_base=reinterpret_cast<std::uint64_t>(tib->StackBase);
    fault.stack_limit=reinterpret_cast<std::uint64_t>(tib->StackLimit);
    fault.allocation_base=fault.stack_base==cached_stack_base_?cached_allocation_base_:0;
    fault.image_base=image_base_;
    MemoryBarrier();InterlockedExchange64(&fault.commit,2);
}
LONG CALLBACK ScopedWorkerFaultCapture::handle(EXCEPTION_POINTERS *error) noexcept {
    auto *writer=static_cast<WorkerProgressWriter *>(InterlockedCompareExchangePointer(&active_fault_writer,nullptr,nullptr));
    if(writer)writer->capture_native_fault(error);
    return EXCEPTION_CONTINUE_SEARCH;
}
ScopedWorkerFaultCapture::ScopedWorkerFaultCapture(WorkerProgressWriter &writer):writer_(writer) {
    if(InterlockedCompareExchangePointer(&active_fault_writer,&writer_,nullptr))
        throw std::runtime_error("AETHER_WORKER_PROGRESS: native fault capture already installed");
    writer_.fault_owner_=GetCurrentThreadId();
    writer_.image_base_=reinterpret_cast<std::uint64_t>(GetModuleHandleW(nullptr));
    if(!writer_.prepare_native_stack()) {
        writer_.fault_owner_=0;InterlockedExchangePointer(&active_fault_writer,nullptr);
        throw std::runtime_error("AETHER_WORKER_PROGRESS: emergency stack guarantee failed");
    }
    handler_=AddVectoredExceptionHandler(1,&handle);
    if(!handler_) {
        writer_.fault_owner_=0;InterlockedExchangePointer(&active_fault_writer,nullptr);
        throw std::runtime_error("AETHER_WORKER_PROGRESS: native fault handler installation failed");
    }
}
ScopedWorkerFaultCapture::~ScopedWorkerFaultCapture() {
    if(GetCurrentThreadId()!=writer_.fault_owner_)std::terminate();
    if(handler_ && !RemoveVectoredExceptionHandler(handler_))std::terminate();
    InterlockedExchangePointer(&active_fault_writer,nullptr);writer_.fault_owner_=0;
}
void WorkerProgressWriter::report(const dex::RuntimeProgress &progress) noexcept {
    refresh_native_stack();
    const auto stage_value=static_cast<std::uint32_t>(progress.stage);
    if(stage_value>static_cast<std::uint32_t>(dex::RuntimeProgressStage::native_exit))return;
    write(1,stage_value,progress.method,progress.pc,progress.instructions,progress.owner,progress.name,{});
}
void WorkerProgressWriter::stage(std::uint32_t numeric,std::string_view label) noexcept {
    refresh_native_stack();
    write(2,numeric,0,0,0,{},{},label);
}
std::string WorkerProgress::summary_after_exit() const {
    if(!view_ || !valid_header(static_cast<const Layout *>(view_)->header))return {};
    struct Snapshot {std::uint64_t sequence;Record record;};
    std::array<Snapshot,record_count> records{};std::size_t count=0;
    const auto &layout=*static_cast<const Layout *>(view_);
    for(std::size_t slot=0;slot<record_count;++slot) {
        Record record{};std::memcpy(&record,&layout.records[slot],sizeof(record));
        if(record.commit<=0 || (record.commit&1) || record.reserved || (record.kind!=1 && record.kind!=2))continue;
        const auto sequence=static_cast<std::uint64_t>(record.commit)/2;
        if((sequence-1)%record_count!=slot || record.owner_length>record.owner.size() || record.name_length>record.name.size() || record.label_length>record.label.size())continue;
        if(record.kind==1 && (record.stage>static_cast<std::uint32_t>(dex::RuntimeProgressStage::native_exit) || record.label_length))continue;
        if(record.kind==2 && (record.owner_length || record.name_length || record.method || record.pc || record.instructions))continue;
        if(!printable(std::span(record.owner).first(record.owner_length)) || !printable(std::span(record.name).first(record.name_length)) || !printable(std::span(record.label).first(record.label_length)))continue;
        records[count++]={sequence,record};
    }
    std::sort(records.begin(),records.begin()+count,[](const auto &left,const auto &right){return left.sequence<right.sequence;});
    std::string output;output.reserve(mapping_bytes);
    for(std::size_t n=0;n<count;++n) {
        const auto &record=records[n].record;std::array<char,384> line{};std::size_t used=0;
        auto text=[&](std::string_view value){const auto size=std::min(value.size(),line.size()-used);std::memcpy(line.data()+used,value.data(),size);used+=size;};
        auto number=[&](std::uint64_t value){const auto result=std::to_chars(line.data()+used,line.data()+line.size(),value);if(result.ec==std::errc{})used=static_cast<std::size_t>(result.ptr-line.data());};
        text("#");number(records[n].sequence);text(" stage=");number(record.stage);
        if(record.kind==2){text(" ");text({record.label.data(),record.label_length});}
        else {text(" method=");number(record.method);text(" pc=");number(record.pc);text(" instructions=");number(record.instructions);text(" ");text({record.owner.data(),record.owner_length});text(".");text({record.name.data(),record.name_length});}
        text("\n");if(used>mapping_bytes-output.size())break;output.append(line.data(),used);
    }
    NativeFault fault{};std::memcpy(&fault,&layout.fault,sizeof(fault));
    if(fault.commit==2 && fault.code==EXCEPTION_STACK_OVERFLOW && fault.thread && fault.rip && fault.rsp &&
       fault.address && fault.stack_base && fault.stack_limit && fault.stack_limit<fault.stack_base &&
       (!fault.allocation_base || fault.allocation_base<=fault.stack_limit) && fault.image_base &&
       std::all_of(fault.reserved.begin(),fault.reserved.end(),[](auto byte){return byte==0;})) {
        std::array<char,384> line{};std::size_t used=0;
        const auto text=[&](std::string_view value){for(const auto c:value)if(used<line.size())line[used++]=c;};
        const auto number=[&](std::uint64_t value){const auto result=std::to_chars(line.data()+used,line.data()+line.size(),value,16);if(result.ec==std::errc{})used=static_cast<std::size_t>(result.ptr-line.data());};
        text("native_fault code=0x");number(fault.code);text(" thread=0x");number(fault.thread);text(" rip=0x");number(fault.rip);
        text(" rsp=0x");number(fault.rsp);text(" address=0x");number(fault.address);
        text(" stackBase=0x");number(fault.stack_base);text(" stackLimit=0x");number(fault.stack_limit);
        text(" allocationBase=0x");number(fault.allocation_base);text(" imageBase=0x");number(fault.image_base);text("\n");
        while(used>mapping_bytes-output.size()) {
            const auto newline=output.find('\n');
            if(newline==std::string::npos){output.clear();break;}
            output.erase(0,newline+1);
        }
        output.append(line.data(),used);
    }
    return output;
}
} // namespace aether::security
