#include "aether/bionic/guest_posix.hpp"
#include "logging.hpp"
#include "threads.hpp"
#include "zlib.hpp"
#include "mutexes.hpp"
#include "rwlocks.hpp"
#include "stdio.hpp"
#include "integers.hpp"
#include "scanning.hpp"
#include "signals.hpp"
#include "conditions.hpp"
#include "calendar.hpp"
#include "descriptors.hpp"
#include "polling.hpp"
#include "sleeping.hpp"
#include "jumps.hpp"
#include "access.hpp"
#include "aether/host/process_info.hpp"
#include <algorithm>
#include <array>
#include <map>

namespace aether::bionic {
namespace {
using a64::Address;
using a64::Fault;
enum class Operation {
    finalize,
    atexit,
    atfork,
    clock,
    error,
    length,
    copy,
    move,
    fill,
    allocate,
    release,
    tid,
    open,
    read,
    write,
    close,
    create_thread,join_thread,self_thread,stack_failure,
    mutex_lock,mutex_trylock,mutex_unlock,mutex_init,mutex_destroy,attr_init,attr_destroy,attr_settype,attr_gettype,attr_setshared,attr_getshared,attr_setprotocol,attr_getprotocol,
    rw_read,rw_write,rw_tryread,rw_trywrite,rw_unlock,rw_init,rw_destroy,rw_attr_init,rw_attr_destroy,rw_attr_setshared,rw_attr_getshared,rw_attr_setkind,rw_attr_getkind,process_id,process_probe,resource_limit,duplicate,bounded_duplicate,string_copy,string_cat,checked_string_copy,checked_string_cat,system_call,directory_open,directory_read,directory_close,directory_rewind,stdio_open,stdio_close,stdio_read,stdio_write,stdio_getc,stdio_gets,stdio_eof,stdio_error,stdio_clear,stdio_fd,stdio_flush,integer_unsigned,integer_signed,integer_atoi,integer_atol,scan,sig_empty,sig_fill,sig_add,sig_del,sig_member,pthread_mask,process_mask,signal_handler,signal_action,signal_raise,signal_pending,signal_wait,cond_wait,cond_signal,cond_broadcast,cond_init,cond_destroy,cond_attr_init,cond_attr_destroy,cond_attr_getshared,cond_attr_setshared,cond_attr_getclock,cond_attr_setclock,epoch_time,local_time,epoch_timeval,descriptor_dup,jump_save,jump_set,jump_plain,jump_restore,format_list,format_direct,format_checked_list,format_checked_direct,file_lock,file_access,realtime_min,realtime_max,priority_set,priority_get,event_create,poll_descriptors,sleep_seconds,sleep_micros,sleep_nanos,process_exit,thread_exit
};
struct Entry {
    std::string_view name;
    Operation operation;
};
constexpr std::array entries{Entry{"__cxa_finalize", Operation::finalize},
                             Entry{"__cxa_atexit", Operation::atexit},
                             Entry{"__register_atfork", Operation::atfork},
                             Entry{"clock_gettime", Operation::clock},
                             Entry{"__errno", Operation::error},
                             Entry{"strlen", Operation::length},
                             Entry{"memcpy", Operation::copy},
                             Entry{"memmove", Operation::move},
                             Entry{"memset", Operation::fill},
                             Entry{"malloc", Operation::allocate},
                             Entry{"free", Operation::release},
                             Entry{"gettid", Operation::tid},
                             Entry{"open", Operation::open},
                             Entry{"read", Operation::read},
                             Entry{"write", Operation::write},
                             Entry{"close", Operation::close},
                             Entry{"pthread_create", Operation::create_thread},Entry{"pthread_join",Operation::join_thread},
                             Entry{"pthread_self",Operation::self_thread},Entry{"__stack_chk_fail",Operation::stack_failure},
                             Entry{"pthread_mutex_lock",Operation::mutex_lock},Entry{"pthread_mutex_trylock",Operation::mutex_trylock},Entry{"pthread_mutex_unlock",Operation::mutex_unlock},Entry{"pthread_mutex_init",Operation::mutex_init},Entry{"pthread_mutex_destroy",Operation::mutex_destroy},
                             Entry{"pthread_mutexattr_init",Operation::attr_init},Entry{"pthread_mutexattr_destroy",Operation::attr_destroy},Entry{"pthread_mutexattr_settype",Operation::attr_settype},Entry{"pthread_mutexattr_gettype",Operation::attr_gettype},Entry{"pthread_mutexattr_setpshared",Operation::attr_setshared},Entry{"pthread_mutexattr_getpshared",Operation::attr_getshared},Entry{"pthread_mutexattr_setprotocol",Operation::attr_setprotocol},Entry{"pthread_mutexattr_getprotocol",Operation::attr_getprotocol},
                             Entry{"pthread_rwlock_rdlock",Operation::rw_read},Entry{"pthread_rwlock_wrlock",Operation::rw_write},Entry{"pthread_rwlock_tryrdlock",Operation::rw_tryread},Entry{"pthread_rwlock_trywrlock",Operation::rw_trywrite},Entry{"pthread_rwlock_unlock",Operation::rw_unlock},Entry{"pthread_rwlock_init",Operation::rw_init},Entry{"pthread_rwlock_destroy",Operation::rw_destroy},Entry{"pthread_rwlockattr_init",Operation::rw_attr_init},Entry{"pthread_rwlockattr_destroy",Operation::rw_attr_destroy},Entry{"pthread_rwlockattr_setpshared",Operation::rw_attr_setshared},Entry{"pthread_rwlockattr_getpshared",Operation::rw_attr_getshared},Entry{"pthread_rwlockattr_setkind_np",Operation::rw_attr_setkind},Entry{"pthread_rwlockattr_getkind_np",Operation::rw_attr_getkind},Entry{"getpid",Operation::process_id},Entry{"kill",Operation::process_probe},Entry{"getrlimit",Operation::resource_limit},Entry{"getrlimit64",Operation::resource_limit},Entry{"strdup",Operation::duplicate},Entry{"strndup",Operation::bounded_duplicate},Entry{"strcpy",Operation::string_copy},Entry{"strcat",Operation::string_cat},Entry{"__strcpy_chk",Operation::checked_string_copy},Entry{"__strcat_chk",Operation::checked_string_cat},Entry{"syscall",Operation::system_call},Entry{"opendir",Operation::directory_open},Entry{"readdir",Operation::directory_read},Entry{"readdir64",Operation::directory_read},Entry{"closedir",Operation::directory_close},Entry{"rewinddir",Operation::directory_rewind},Entry{"fopen",Operation::stdio_open},Entry{"fclose",Operation::stdio_close},Entry{"fread",Operation::stdio_read},Entry{"fwrite",Operation::stdio_write},Entry{"fgetc",Operation::stdio_getc},Entry{"fgets",Operation::stdio_gets},Entry{"feof",Operation::stdio_eof},Entry{"ferror",Operation::stdio_error},Entry{"clearerr",Operation::stdio_clear},Entry{"fileno",Operation::stdio_fd},Entry{"fflush",Operation::stdio_flush},Entry{"strtoul",Operation::integer_unsigned},Entry{"strtoull",Operation::integer_unsigned},Entry{"strtoumax",Operation::integer_unsigned},Entry{"strtol",Operation::integer_signed},Entry{"strtoll",Operation::integer_signed},Entry{"strtoimax",Operation::integer_signed},Entry{"atoi",Operation::integer_atoi},Entry{"atol",Operation::integer_atol},Entry{"atoll",Operation::integer_atol},Entry{"sscanf",Operation::scan},Entry{"sigemptyset",Operation::sig_empty},Entry{"sigfillset",Operation::sig_fill},Entry{"sigaddset",Operation::sig_add},Entry{"sigdelset",Operation::sig_del},Entry{"sigismember",Operation::sig_member},Entry{"pthread_sigmask",Operation::pthread_mask},Entry{"sigprocmask",Operation::process_mask},Entry{"signal",Operation::signal_handler},Entry{"sigaction",Operation::signal_action},Entry{"raise",Operation::signal_raise},Entry{"sigpending",Operation::signal_pending},Entry{"sigwait",Operation::signal_wait},Entry{"pthread_cond_wait",Operation::cond_wait},Entry{"pthread_cond_signal",Operation::cond_signal},Entry{"pthread_cond_broadcast",Operation::cond_broadcast},Entry{"pthread_cond_init",Operation::cond_init},Entry{"pthread_cond_destroy",Operation::cond_destroy},Entry{"pthread_condattr_init",Operation::cond_attr_init},Entry{"pthread_condattr_destroy",Operation::cond_attr_destroy},Entry{"pthread_condattr_getpshared",Operation::cond_attr_getshared},Entry{"pthread_condattr_setpshared",Operation::cond_attr_setshared},Entry{"pthread_condattr_getclock",Operation::cond_attr_getclock},Entry{"pthread_condattr_setclock",Operation::cond_attr_setclock},Entry{"time",Operation::epoch_time},Entry{"localtime_r",Operation::local_time},Entry{"gettimeofday",Operation::epoch_timeval},Entry{"dup2",Operation::descriptor_dup},Entry{"sigsetjmp",Operation::jump_save},Entry{"setjmp",Operation::jump_set},Entry{"_setjmp",Operation::jump_plain},Entry{"siglongjmp",Operation::jump_restore},Entry{"longjmp",Operation::jump_restore},Entry{"_longjmp",Operation::jump_restore},Entry{"vsnprintf",Operation::format_list},Entry{"snprintf",Operation::format_direct},Entry{"__vsnprintf_chk",Operation::format_checked_list},Entry{"__snprintf_chk",Operation::format_checked_direct},Entry{"flock",Operation::file_lock},Entry{"access",Operation::file_access},Entry{"__libc_current_sigrtmin",Operation::realtime_min},Entry{"__libc_current_sigrtmax",Operation::realtime_max},Entry{"setpriority",Operation::priority_set},Entry{"getpriority",Operation::priority_get},Entry{"eventfd",Operation::event_create},Entry{"poll",Operation::poll_descriptors}};
constexpr std::array<std::string_view,3> log_entries{"__android_log_write","__android_log_print","__android_log_assert"};
constexpr std::uint32_t log_service=0x180;
constexpr a64::Address log_trampoline=GuestPosixServices::trampoline_base+0x800;
enum class CxxOperation {allocate,nothrow_allocate,release,pure};
struct CxxEntry {std::string_view name;CxxOperation operation;};
constexpr std::array cxx_entries{
    CxxEntry{"_Znwm",CxxOperation::allocate},CxxEntry{"_Znam",CxxOperation::allocate},
    CxxEntry{"_ZnwmRKSt9nothrow_t",CxxOperation::nothrow_allocate},CxxEntry{"_ZnamRKSt9nothrow_t",CxxOperation::nothrow_allocate},
    CxxEntry{"_ZdlPv",CxxOperation::release},CxxEntry{"_ZdaPv",CxxOperation::release},
    CxxEntry{"_ZdlPvRKSt9nothrow_t",CxxOperation::release},CxxEntry{"_ZdaPvRKSt9nothrow_t",CxxOperation::release},
    CxxEntry{"__cxa_pure_virtual",CxxOperation::pure}};
constexpr std::uint32_t cxx_service=0x1a0;
constexpr a64::Address cxx_trampoline=GuestPosixServices::trampoline_base+0xa00,
                       nothrow_address=GuestPosixServices::trampoline_base+0xf00;
constexpr std::array<std::string_view,4> zlib_entries{"adler32","inflateInit_","inflate","inflateEnd"};
constexpr std::uint32_t zlib_service=0x1c0;
constexpr Address zlib_trampoline=GuestPosixServices::trampoline_base+0xc00;
constexpr std::uint32_t first_service = 0x100;
static_assert(entries.size()<=log_service-first_service);
constexpr std::array extended_entries{Entry{"sleep",Operation::sleep_seconds},Entry{"usleep",Operation::sleep_micros},Entry{"nanosleep",Operation::sleep_nanos},Entry{"_exit",Operation::process_exit},Entry{"_Exit",Operation::process_exit},Entry{"pthread_exit",Operation::thread_exit}};
constexpr std::uint32_t extended_service=0x200,extended_capacity=512;
constexpr Address extended_trampoline=GuestPosixServices::trampoline_base+4096;
static_assert(extended_entries.size()<=extended_capacity);
static_assert(extended_service>=zlib_service+6 && extended_service+extended_capacity<=0x800);
static_assert(extended_capacity*8==4096 && extended_trampoline+4096<=GuestPosixServices::errno_address);
std::optional<Operation> registered_operation(std::uint32_t service,Address instruction) {
    if(service>=first_service && service-first_service<entries.size() && instruction==GuestPosixServices::trampoline_base+(service-first_service)*8)return entries[service-first_service].operation;
    if(service>=extended_service && service-extended_service<extended_entries.size() && instruction==extended_trampoline+(service-extended_service)*8)return extended_entries[service-extended_service].operation;
    return {};
}

constexpr std::size_t maximum_transfer = 1024 * 1024, maximum_heap = 16 * 1024 * 1024;
constexpr std::uint32_t guest_eio = 5, guest_enomem = 12, guest_eacces = 13, guest_efault = 14,
                        guest_einval = 22;
template <std::size_t N> std::array<std::uint8_t, N> little(std::uint64_t value) {
    static_assert(N <= 8);
    std::array<std::uint8_t, N> bytes{};
    for (std::size_t i = 0; i < N; ++i)
        bytes[i] = static_cast<std::uint8_t>(value >> (i * 8));
    return bytes;
}
} // namespace
struct GuestPosixServices::Impl {
    a64::GuestMemory &memory;
    const a64::AppContext &app;
    const host::TimeService &time;
    NativeDescriptors descriptors;
    host::FileService *files;
    NativeLogging logging;
    NativeAccess access;
    NativeFormatting formatting;
    NativeThreads threads;
    NativePolling polling;
    NativeSleeping sleeping;
    NativeSignals signals;
    NativeJumps jumps;
    NativeZlib compression;
    NativeMutexes mutexes;
    NativeConditions conditions;
    NativeCalendar calendar;
    NativeRwLocks rwlocks;
    NativeStdio stdio;
    const std::uint32_t tid;
    ServiceMetrics stats;
    std::string_view rejection;
    std::map<Address, std::size_t> allocations;
    struct Directory {std::vector<host::DirectoryEntry> entries;std::size_t position=0;};
    std::map<Address,Directory> directories;
    Address next_directory=0x38000000;
    Address next_heap = 0x40000000;
    bool trampoline_owned = false, extended_owned=false, errno_owned = false;
    Impl(a64::GuestMemory &m, const a64::AppContext &a, const host::TimeService &t, std::uint32_t id,
         host::FileService *f,host::NativeLogSink *logs,std::string_view package)
        : memory(m), app(a), time(t), descriptors(f), files(f?&descriptors:nullptr), logging(m,logs), access(m,files,package), formatting(m), threads(m,id,GuestPosixServices::errno_address), polling(m,descriptors,threads), sleeping(m,threads), signals(m,threads), jumps(m,threads,signals), compression(m,zlib_trampoline+32,zlib_trampoline+40), mutexes(m), conditions(m,threads,mutexes), calendar(m,t), rwlocks(m), stdio(m,f?&descriptors:nullptr), tid(id) {}
    ~Impl() {
        for(const auto &[address,directory]:directories){(void)directory;unmap(address);}
        for (const auto &[address, size] : allocations) {
            (void)size;
            unmap(address);
        }
        if (extended_owned)unmap(extended_trampoline);
        if (trampoline_owned)
            unmap(trampoline_base);
        if (errno_owned)
            unmap(errno_address);
    }
    void unmap(Address address) noexcept {
        try {
            memory.unmap(address);
        } catch (...) {
        }
    }
    Fault error(std::array<std::uint64_t, 31> &r, std::uint32_t value, bool null_return = false) {
        ++stats.errors;
        if (!memory.write(threads.error_address(), little<4>(value)))
            return Fault::write;
        r[0] = null_return ? 0 : ~std::uint64_t{0};
        return Fault::none;
    }
    Fault dispatch_cxx(CxxOperation operation,std::array<std::uint64_t,31> &r) {
        if(operation==CxxOperation::pure){rejection="__cxa_pure_virtual: guest pure virtual call";++stats.rejected_operations;return Fault::invalid_call;}
        if(operation==CxxOperation::release)return dispatch(Operation::release,r);
        const auto fault=dispatch(Operation::allocate,r);
        if(fault==Fault::none && !r[0] && operation==CxxOperation::allocate) {
            rejection="operator new: guest allocation failure is fatal";++stats.rejected_operations;return Fault::invalid_call;
        }
        return fault;
    }
    Fault scanning(a64::ServiceState &state,bool full) {
        const auto fault=scan_text(memory,state,full,threads.error_address());
        if(fault!=Fault::none){rejection="sscanf: unsupported format/limit or invalid guest access";++stats.rejected_operations;}
        return fault;
    }
    Fault mask_operation(Operation operation,a64::ServiceState &state,bool full) {
        auto &r=state.registers;std::array<std::uint8_t,4> saved_errno{};
        if(operation==Operation::pthread_mask && !memory.read(threads.error_address(),saved_errno))return Fault::read;
        const auto result=threads.change_signal_mask(r);
        if(operation==Operation::pthread_mask)r[0]=result;
        else if(result)return error(r,result);else r[0]=0;
        if(result)return Fault::none;
        const auto fault=signals.deliver_pending(state,full);
        if(operation==Operation::pthread_mask && !memory.write(threads.error_address(),saved_errno))return Fault::write;
        if(fault!=Fault::none){rejection="signal: pending delivery failed or unsupported";++stats.rejected_operations;}
        return fault;
    }
    Fault signal_operation(Operation operation,a64::ServiceState &state,bool full) {
        const auto fault=signals.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::signal_handler),state,full);
        if(fault!=Fault::none){rejection="signal: unsupported action/delivery or invalid guest access";++stats.rejected_operations;}
        return fault;
    }
    Fault format_operation(Operation operation,a64::ServiceState &state,bool full) {
        const auto fault=formatting.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::format_list),state,full);
        if(fault!=Fault::none){rejection=formatting.rejection();++stats.rejected_operations;}return fault;
    }
    Fault jump_operation(Operation operation,a64::ServiceState &state,bool full) {
        const auto fault=jumps.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::jump_save),state,full);
        if(fault!=Fault::none){rejection="setjmp/longjmp: invalid or stale context, cross-invocation jump, or unsupported frame";++stats.rejected_operations;}
        return fault;
    }
    Fault condition_operation(Operation operation,std::array<std::uint64_t,31> &r,bool full) {
        const auto fault=conditions.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::cond_wait),r,full);
        stats.threads_created=threads.created;stats.threads_started=threads.started;stats.threads_joined=threads.joined;
        if(fault!=Fault::none){rejection="pthread condition: unsupported wait/scheduling/state or invalid guest access";++stats.rejected_operations;}
        return fault;
    }
    Fault dispatch(Operation operation, std::array<std::uint64_t, 31> &r,bool full_frame=false) {
        if(operation>=Operation::format_list && operation<=Operation::format_checked_direct){a64::ServiceState state;state.registers=r;const auto fault=format_operation(operation,state,false);r=state.registers;return fault;}
        if(operation>=Operation::jump_save && operation<=Operation::jump_restore){a64::ServiceState state;state.registers=r;const auto fault=jump_operation(operation,state,false);r=state.registers;return fault;}
        if(operation>=Operation::cond_wait && operation<=Operation::cond_attr_setclock)return condition_operation(operation,r,false);
        if(operation>=Operation::rw_read && operation<=Operation::rw_attr_getkind){const auto fault=rwlocks.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::rw_read),threads.tid(),r);if(fault!=Fault::none){rejection=rwlocks.rejection();++stats.rejected_operations;}return fault;}
        if(operation>=Operation::mutex_lock && operation<=Operation::attr_getprotocol){const auto fault=mutexes.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::mutex_lock),threads.tid(),r);if(fault!=Fault::none){rejection=mutexes.rejection();++stats.rejected_operations;}return fault;}
        if(operation>=Operation::stdio_open && operation<=Operation::stdio_flush)return stdio.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::stdio_open),threads.error_address(),r);
        if(operation>=Operation::integer_unsigned && operation<=Operation::integer_atol){const auto fault=convert_integer(memory,threads.error_address(),static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::integer_unsigned),r);if(fault!=Fault::none){rejection="integer conversion: guest input/output fault or 1 MiB scan limit";++stats.rejected_operations;}return fault;}
        switch (operation) {
        case Operation::thread_exit:threads.request_exit(r[0]);return Fault::thread_exit;
        case Operation::process_exit:app.process_state->request_exit(static_cast<std::uint32_t>(r[0]));return Fault::process_exit;
        case Operation::sleep_seconds:case Operation::sleep_micros:case Operation::sleep_nanos:{const auto fault=sleeping.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::sleep_seconds),threads.error_address(),r,full_frame);stats.threads_created=threads.created;stats.threads_started=threads.started;stats.threads_joined=threads.joined;if(fault!=Fault::none){rejection="native sleep: nested work failed or monotonic chunk unavailable";++stats.rejected_operations;}else if(r[0]==UINT64_MAX)++stats.errors;return fault;}
        case Operation::poll_descriptors:{const auto fault=polling.invoke(threads.error_address(),r,full_frame);stats.threads_created=threads.created;stats.threads_started=threads.started;stats.threads_joined=threads.joined;if(fault!=Fault::none){rejection="poll: nested native work failed";++stats.rejected_operations;}else if(r[0]==UINT64_MAX)++stats.errors;return fault;}
        case Operation::priority_set:case Operation::priority_get:{
            const auto result=threads.priority(static_cast<std::int32_t>(r[0]),static_cast<std::uint32_t>(r[1]),operation==Operation::priority_set?std::optional<std::int32_t>{static_cast<std::int32_t>(r[2])}:std::nullopt);
            if(result.error)return error(r,result.error);r[0]=operation==Operation::priority_set?0:static_cast<std::uint64_t>(static_cast<std::int64_t>(result.nice));return Fault::none;
        }
        case Operation::realtime_min:r[0]=native_sigrtmin;return Fault::none;
        case Operation::realtime_max:r[0]=native_sigrtmax;return Fault::none;
        case Operation::file_access:{++stats.file_operations;const auto fault=access.invoke(threads.error_address(),r);if(fault==Fault::none && r[0]==UINT64_MAX)++stats.errors;return fault;}
        case Operation::pthread_mask:case Operation::process_mask: {
            a64::ServiceState state;state.registers=r;const auto fault=mask_operation(operation,state,false);r=state.registers;return fault;
        }
        case Operation::signal_handler:case Operation::signal_action:case Operation::signal_raise:case Operation::signal_pending:case Operation::signal_wait:{a64::ServiceState state;state.registers=r;const auto fault=signal_operation(operation,state,false);r=state.registers;return fault;}
        case Operation::sig_empty:case Operation::sig_fill:case Operation::sig_add:case Operation::sig_del:case Operation::sig_member: {
            const bool bit_operation=operation==Operation::sig_add || operation==Operation::sig_del || operation==Operation::sig_member;
            const auto signal=static_cast<std::int32_t>(r[1]);
            if(!r[0] || (bit_operation && (signal<1 || signal>64)))return error(r,guest_einval);
            std::uint64_t bits=operation==Operation::sig_fill?~std::uint64_t{0}:0;
            if(bit_operation){std::array<std::uint8_t,8> bytes{};if(!memory.read(r[0],bytes))return Fault::read;for(unsigned i=0;i<8;++i)bits|=std::uint64_t{bytes[i]}<<(8*i);const auto mask=std::uint64_t{1}<<(signal-1);if(operation==Operation::sig_member){r[0]=(bits&mask)?1:0;return Fault::none;}if(operation==Operation::sig_add)bits|=mask;else bits&=~mask;}
            if(!memory.write(r[0],little<8>(bits)))return Fault::write;
            r[0]=0;return Fault::none;
        }
        case Operation::scan:{a64::ServiceState state;state.registers=r;const auto fault=scanning(state,false);r=state.registers;return fault;}
        case Operation::integer_unsigned:case Operation::integer_signed:case Operation::integer_atoi:case Operation::integer_atol:return Fault::unsupported_service;
        case Operation::stdio_open:case Operation::stdio_close:case Operation::stdio_read:case Operation::stdio_write:case Operation::stdio_getc:case Operation::stdio_gets:case Operation::stdio_eof:case Operation::stdio_error:case Operation::stdio_clear:case Operation::stdio_fd:case Operation::stdio_flush:return Fault::unsupported_service;
        case Operation::rw_read:case Operation::rw_write:case Operation::rw_tryread:case Operation::rw_trywrite:case Operation::rw_unlock:case Operation::rw_init:case Operation::rw_destroy:case Operation::rw_attr_init:case Operation::rw_attr_destroy:case Operation::rw_attr_setshared:case Operation::rw_attr_getshared:case Operation::rw_attr_setkind:case Operation::rw_attr_getkind:return Fault::unsupported_service;
        case Operation::mutex_lock:case Operation::mutex_trylock:case Operation::mutex_unlock:case Operation::mutex_init:case Operation::mutex_destroy:
        case Operation::attr_init:case Operation::attr_destroy:case Operation::attr_settype:case Operation::attr_gettype:case Operation::attr_setshared:case Operation::attr_getshared:case Operation::attr_setprotocol:case Operation::attr_getprotocol:return Fault::unsupported_service;
        case Operation::directory_open: {
            if(!files)return error(r,guest_eacces,true);
            std::string path;
            bool terminated=false;
            for(unsigned i=0;i<128;++i){std::array<std::uint8_t,1> c{};if(r[0]>=a64::GuestMemory::address_limit || i>=a64::GuestMemory::address_limit-r[0] || !memory.read(r[0]+i,c))return error(r,guest_efault,true);if(!c[0]){terminated=true;break;}path.push_back(static_cast<char>(c[0]));}
            if(!terminated)return error(r,36,true);
            if(path.empty())return error(r,2,true);
            // Relative file operations already use this provider-owned private root as cwd.
            if(path!="." && path!="./")return error(r,95,true);
            if(directories.size()>=16 || next_directory>=0x39000000)return error(r,24,true);
            Directory directory;
            const auto result=files->list_directory(directory.entries);
            if(result.error!=host::FileError::none){const auto code=result.error==host::FileError::denied?13U:result.error==host::FileError::unsupported?95U:result.error==host::FileError::quota?75U:result.error==host::FileError::missing?2U:5U;return error(r,code,true);}
            if(result.value!=static_cast<std::int64_t>(directory.entries.size()) || directory.entries.size()>12)return error(r,guest_eio,true);
            for(const auto &entry:directory.entries)if(!host::valid_directory_entry(entry))return error(r,guest_eio,true);
            const auto address=next_directory;
            const auto [it,inserted]=directories.emplace(address,std::move(directory));
            if(!inserted)return error(r,guest_eio,true);
            try{memory.map(address,4096,a64::read_write);}catch(...){directories.erase(it);return error(r,guest_enomem,true);}
            next_directory+=4096;r[0]=address;return Fault::none;
        }
        case Operation::directory_read:case Operation::directory_close:case Operation::directory_rewind: {
            const auto it=directories.find(r[0]);
            if(it==directories.end())return error(r,9,operation==Operation::directory_read);
            if(operation==Operation::directory_close){memory.unmap(it->first);directories.erase(it);r[0]=0;return Fault::none;}
            if(operation==Operation::directory_rewind){
                std::vector<host::DirectoryEntry> refreshed;
                const auto result=files->list_directory(refreshed);
                if(result.error!=host::FileError::none)return error(r,result.error==host::FileError::denied?13U:result.error==host::FileError::quota?75U:result.error==host::FileError::unsupported?95U:5U);
                if(result.value!=static_cast<std::int64_t>(refreshed.size()) || refreshed.size()>host::directory_entry_limit)return error(r,guest_eio);
                for(const auto &entry:refreshed)if(!host::valid_directory_entry(entry))return error(r,guest_eio);
                it->second.entries.swap(refreshed);it->second.position=0;return Fault::none;
            }
            auto &directory=it->second;
            if(directory.position==directory.entries.size()){r[0]=0;return Fault::none;}
            const auto &entry=directory.entries[directory.position];
            std::array<std::uint8_t,280> bytes{};
            const auto inode=little<8>(entry.inode),offset=little<8>(directory.position+1);
            std::copy(inode.begin(),inode.end(),bytes.begin());std::copy(offset.begin(),offset.end(),bytes.begin()+8);
            const auto length=little<2>((19+entry.name.size()+1+7)&~std::size_t{7});
            std::copy(length.begin(),length.end(),bytes.begin()+16);bytes[18]=entry.type;
            std::copy(entry.name.begin(),entry.name.end(),bytes.begin()+19);
            const auto address=it->first+64;
            if(!memory.write(address,bytes))return error(r,guest_efault,true);
            ++directory.position;r[0]=address;return Fault::none;
        }
        case Operation::system_call: {
            Operation target;
            // Android arm64 asm-generic syscall numbers, using the existing guest providers.
            switch(r[0]){
            case 94:target=Operation::process_exit;break;
            case 101:target=Operation::sleep_nanos;break;
            case 19:target=Operation::event_create;break;
            case 172:target=Operation::process_id;break;
            case 178:target=Operation::tid;break;
            case 129:target=Operation::process_probe;break;
            case 113:target=Operation::clock;break;
            case 63:target=Operation::read;break;
            case 64:target=Operation::write;break;
            case 57:target=Operation::close;break;
            default:return error(r,38);
            }
            // libc syscall(number,...) places the six kernel arguments in x1..x6.
            for(unsigned i=0;i<6;++i)r[i]=r[i+1];
            return dispatch(target,r,full_frame);
        }
        case Operation::string_copy:case Operation::string_cat:
        case Operation::checked_string_copy:case Operation::checked_string_cat: {
            const auto destination=r[0],source=r[1];
            const bool checked=operation==Operation::checked_string_copy || operation==Operation::checked_string_cat;
            const bool append=operation==Operation::string_cat || operation==Operation::checked_string_cat;
            const auto capacity=checked?r[2]:~std::uint64_t{0};
            const auto overflow=[&](){rejection="checked string: destination object size exceeded";++stats.rejected_operations;return Fault::invalid_call;};
            const auto capped=[&](){rejection="string: exceeds 1 MiB service limit";++stats.rejected_operations;return Fault::unsupported_service;};
            const auto read_byte=[&](Address address,std::uint64_t offset,std::array<std::uint8_t,1>& byte){return address<a64::GuestMemory::address_limit && offset<a64::GuestMemory::address_limit-address && memory.read(address+offset,byte);};
            std::uint64_t prefix=0;
            if(append)for(;;++prefix){
                if(prefix>=capacity)return overflow();
                if(prefix>=maximum_transfer)return capped();
                std::array<std::uint8_t,1> byte{};if(!read_byte(destination,prefix,byte))return Fault::read;
                if(!byte[0])break;
            }
            std::vector<std::uint8_t> bytes;
            for(std::uint64_t i=0;;++i){
                if(prefix>=capacity || i>=capacity-prefix)return overflow();
                if(i>=maximum_transfer-prefix)return capped();
                std::array<std::uint8_t,1> byte{};if(!read_byte(source,i,byte))return Fault::read;
                bytes.push_back(byte[0]);if(!byte[0])break;
            }
            if(destination>=a64::GuestMemory::address_limit || prefix>=a64::GuestMemory::address_limit-destination)return Fault::write;
            const auto start=destination+prefix;
            if(!memory.accessible(start,bytes.size(),a64::Permission::write))return Fault::write;
            // Overlapping source/destination has undefined C semantics; do not invent memmove behavior.
            if(source<start+bytes.size() && destination<source+bytes.size()){rejection="string: overlapping source and destination unsupported";++stats.rejected_operations;return Fault::unsupported_service;}
            return memory.write(start,bytes)?Fault::none:Fault::write;
        }
        case Operation::duplicate:
        case Operation::bounded_duplicate: {
            const auto source=r[0];
            const auto bound=operation==Operation::duplicate?std::uint64_t{maximum_transfer}:r[1];
            std::vector<std::uint8_t> bytes;
            for(std::uint64_t i=0;i<bound;++i){
                if(i>=maximum_transfer){rejection="strdup: string exceeds 1 MiB service limit";++stats.rejected_operations;return Fault::unsupported_service;}
                std::array<std::uint8_t,1> byte{};
                if(source>=a64::GuestMemory::address_limit || i>=a64::GuestMemory::address_limit-source || !memory.read(source+i,byte))return Fault::read;
                if(!byte[0])break;
                bytes.push_back(byte[0]);
            }
            if(operation==Operation::duplicate && bytes.size()==maximum_transfer){rejection="strdup: unterminated string exceeds service limit";++stats.rejected_operations;return Fault::unsupported_service;}
            bytes.push_back(0);r[0]=bytes.size();
            const auto fault=dispatch(Operation::allocate,r);
            if(fault!=Fault::none || !r[0])return fault;
            if(!memory.write(r[0],bytes))return Fault::write;
            return Fault::none;
        }
        case Operation::resource_limit: {
            const auto resource=static_cast<std::int32_t>(r[0]);
            if(resource<0 || resource>=16)return error(r,guest_einval);
            // The guest runtime has no core-file producer. Its enforced core limit is zero.
            // Do not present Windows limits or invented Linux defaults as guest limits.
            if(resource!=4)return error(r,38); // ENOSYS: this resource accounting is not implemented.
            if(!memory.accessible(r[1],16,a64::Permission::write))return error(r,guest_efault);
            const std::array<std::uint8_t,16> limit{};
            if(!memory.write(r[1],limit))return error(r,guest_efault);
            r[0]=0;return Fault::none;
        }
        case Operation::process_id:
            r[0]=host::current_process_id();return Fault::none;
        case Operation::process_probe: {
            const auto pid=static_cast<std::int32_t>(r[0]);
            const auto signal=static_cast<std::int32_t>(r[1]);
            if(signal<0 || signal>64)return error(r,guest_einval);
            if(pid<=0){rejection="kill: guest process-group selection is unsupported";++stats.rejected_operations;return Fault::unsupported_service;}
            // Only the owned application process exists in the guest process namespace.
            // Never forward guest signal requests to Windows or unrelated host processes.
            if(static_cast<std::uint32_t>(pid)!=host::current_process_id())return error(r,3);
            if(signal==0){r[0]=0;return Fault::none;}
            rejection="kill: nonzero guest signal delivery is unsupported";
            ++stats.rejected_operations;return Fault::unsupported_service;
        }
        case Operation::finalize:
            // No callback registration can succeed in this subset. An empty list is therefore exact.
            return Fault::none;
        case Operation::atexit:
            rejection = "__cxa_atexit: guest destructor callback registration is unsupported";
            ++stats.rejected_operations;
            return Fault::unsupported_service;
        case Operation::atfork:
            rejection = "__register_atfork: guest fork handlers are unsupported";
            ++stats.rejected_operations;
            return Fault::unsupported_service;
        case Operation::create_thread:
        case Operation::join_thread: {
            const auto fault=operation==Operation::create_thread?threads.create(r):threads.join(r);
            stats.threads_created=threads.created;stats.threads_started=threads.started;stats.threads_joined=threads.joined;
            if(fault!=Fault::none){rejection=threads.rejection();++stats.rejected_operations;}return fault;
        }
        case Operation::self_thread:r[0]=threads.tid();return Fault::none;
        case Operation::stack_failure:rejection="__stack_chk_fail: guest stack canary mismatch";++stats.rejected_operations;return Fault::invalid_call;
        case Operation::error:
            r[0] = threads.error_address();
            return Fault::none;
        case Operation::tid:
            r[0] = threads.tid();
            return Fault::none;
        case Operation::epoch_timeval: {
            if(r[1]){rejection="gettimeofday: obsolete nonnull kernel timezone argument unsupported";++stats.rejected_operations;return Fault::unsupported_service;}
            if(!r[0]){r[0]=0;return Fault::none;}
            if(!memory.accessible(r[0],16,a64::Permission::write))return error(r,guest_efault);
            host::EpochTime now;const auto status=time.read_wall_time(now);
            if(status!=host::TimeStatus::ok)return error(r,status==host::TimeStatus::denied?guest_eacces:guest_eio);
            if(now.nanoseconds>=1000000000)return error(r,guest_eio);
            std::array<std::uint8_t,16> output{};const auto seconds=little<8>(static_cast<std::uint64_t>(now.seconds)),micros=little<8>(now.nanoseconds/1000);
            std::copy(seconds.begin(),seconds.end(),output.begin());std::copy(micros.begin(),micros.end(),output.begin()+8);
            if(!memory.write(r[0],output))return error(r,guest_efault);
            ++stats.clock_reads;r[0]=0;return Fault::none;
        }
        case Operation::local_time:return calendar.localtime(r,threads.error_address());
        case Operation::epoch_time: {
            host::EpochTime now;
            const auto status=time.read_wall_time(now);
            if(status!=host::TimeStatus::ok)return error(r,status==host::TimeStatus::denied?guest_eacces:guest_eio);
            if(now.nanoseconds>=1000000000)return error(r,guest_eio);
            const auto seconds=static_cast<std::uint64_t>(now.seconds);
            if(r[0] && !memory.write(r[0],little<8>(seconds)))return Fault::write;
            ++stats.clock_reads;r[0]=seconds;return Fault::none;
        }
        case Operation::clock: {
            if (!app.monotonic_time_allowed)
                return error(r, guest_eacces);
            // Android clockid_t is signed 32-bit; upper argument bits are not part of the value.
            if (static_cast<std::uint32_t>(r[0]) != 1)
                return error(r, guest_einval);
            if (!memory.accessible(r[1], 16, a64::Permission::write))
                return error(r, guest_efault);
            host::MonotonicTime now;
            const auto status = time.read_monotonic(now);
            if (status != host::TimeStatus::ok)
                return error(r, status == host::TimeStatus::denied ? guest_eacces : guest_eio);
            std::array<std::uint8_t, 16> bytes{};
            const auto seconds = little<8>(now.seconds), nanos = little<8>(now.nanoseconds);
            std::copy(seconds.begin(), seconds.end(), bytes.begin());
            std::copy(nanos.begin(), nanos.end(), bytes.begin() + 8);
            if (!memory.write(r[1], bytes))
                return error(r, guest_efault);
            ++stats.clock_reads;
            r[0] = 0;
            return Fault::none;
        }
        case Operation::length: {
            for (std::size_t n = 0; n < maximum_transfer; ++n) {
                if (r[0] >= a64::GuestMemory::address_limit || n >= a64::GuestMemory::address_limit - r[0])
                    return Fault::read;
                std::array<std::uint8_t, 1> byte{};
                if (!memory.read(r[0] + n, byte))
                    return Fault::read;
                if (!byte[0]) {
                    r[0] = n;
                    return Fault::none;
                }
            }
            rejection = "strlen: string exceeds 1 MiB service limit";
            ++stats.rejected_operations;
            return Fault::unsupported_service;
        }
        case Operation::copy:
        case Operation::move:
        case Operation::fill: {
            if (r[2] > maximum_transfer) {
                rejection = "memory operation exceeds 1 MiB service limit";
                ++stats.rejected_operations;
                return Fault::unsupported_service;
            }
            const auto size = static_cast<std::size_t>(r[2]);
            if (!size)
                return Fault::none;
            if (!memory.accessible(r[0], size, a64::Permission::write))
                return Fault::write;
            if (operation != Operation::fill && !memory.accessible(r[1], size, a64::Permission::read))
                return Fault::read;
            if (operation == Operation::copy && r[0] < r[1] + size && r[1] < r[0] + size) {
                rejection = "memcpy: overlapping ranges violate the guest API contract";
                ++stats.rejected_operations;
                return Fault::unsupported_service;
            }
            std::vector<std::uint8_t> bytes(size, static_cast<std::uint8_t>(r[1]));
            if (operation != Operation::fill && !memory.read(r[1], bytes))
                return Fault::read;
            return memory.write(r[0], bytes) ? Fault::none : Fault::write;
        }
        case Operation::allocate: {
            if (r[0] > maximum_heap || allocations.size() >= 4096)
                return error(r, guest_enomem, true);
            const auto size =
                (std::max<std::size_t>(static_cast<std::size_t>(r[0]), 1) + 4095) & ~std::size_t{4095};
            if (size > maximum_heap - stats.allocated_bytes || next_heap + size > 0x50000000)
                return error(r, guest_enomem, true);
            const auto address = next_heap;
            const auto [it, inserted] = allocations.emplace(address, size);
            if (!inserted)
                return error(r, guest_enomem, true);
            try {
                memory.map(address, size, a64::read_write);
            } catch (const a64::GuestError &) {
                allocations.erase(it);
                return error(r, guest_enomem, true);
            }
            next_heap +=
                size + 4096; // Unmapped page between allocations; addresses are not immediately reused.
            stats.allocated_bytes += size;
            ++stats.allocations;
            r[0] = address;
            return Fault::none;
        }
        case Operation::release: {
            if (!r[0])
                return Fault::none;
            const auto it = allocations.find(r[0]);
            if (it == allocations.end()) {
                rejection = "free: address is not a live allocation";
                ++stats.rejected_operations;
                return Fault::invalid_call;
            }
            memory.unmap(it->first);
            stats.allocated_bytes -= it->second;
            allocations.erase(it);
            ++stats.frees;
            return Fault::none;
        }
        case Operation::event_create:
        case Operation::open:
        case Operation::read:
        case Operation::write:
        case Operation::descriptor_dup:
        case Operation::file_lock:
        case Operation::close: {
            if (!files && operation==Operation::open)
                return error(r, guest_eacces);
            host::FileResult result;
            if(operation==Operation::event_create){
                result=descriptors.event(static_cast<std::uint32_t>(r[0]),static_cast<std::uint32_t>(r[1]));
            } else if(operation==Operation::descriptor_dup){
                result=descriptors.duplicate_to(static_cast<std::int32_t>(r[0]),static_cast<std::int32_t>(r[1]));
            } else if(operation==Operation::file_lock){
                result=descriptors.lock(static_cast<std::int32_t>(r[0]),static_cast<std::uint32_t>(r[1]));
            } else if (operation == Operation::open) {
                std::string name;
                for (std::size_t i = 0; i < 128; ++i) {
                    std::array<std::uint8_t, 1> c{};
                    if (r[0] >= a64::GuestMemory::address_limit ||
                        i >= a64::GuestMemory::address_limit - r[0] || !memory.read(r[0] + i, c))
                        return error(r, guest_efault);
                    if (!c[0])
                        break;
                    name.push_back(static_cast<char>(c[0]));
                }
                const auto flags = static_cast<std::uint32_t>(r[1]);
                // Android O_ACCMODE, O_CREAT, O_EXCL, O_TRUNC, O_CLOEXEC. No guest exec exists.
                if ((flags & ~std::uint32_t{3 | 64 | 128 | 512 | 0x80000}) || (flags & 3) == 3)
                    return error(r, 95); // EOPNOTSUPP: unsupported flags are never silently ignored.
                if ((flags & 64) && static_cast<std::uint32_t>(r[2]) != 0600)
                    return error(r,
                                 95); // One guest identity per scope; host ACL isolation is a Phase 7 gate.
                result = files->open(name, {(flags & 3) != 1, (flags & 3) != 0, (flags & 64) != 0,
                                            (flags & 128) != 0, (flags & 512) != 0});
                if(result.error==host::FileError::none)descriptors.set_close_on_exec(static_cast<int>(result.value),(flags&0x80000)!=0);
            } else if (operation == Operation::close) {
                result = descriptors.close(static_cast<std::int32_t>(r[0]));
            } else {
                const auto fd=static_cast<std::int32_t>(r[0]);
                const bool event=descriptors.is_event(fd),reading=operation==Operation::read;
                if(r[2]>INT64_MAX)return error(r,guest_einval);
                if(event && (r[2]<8 || (!reading && r[2]!=8)))return error(r,guest_einval);
                if(!event && r[2]>maximum_transfer)return error(r,guest_einval);
                // An event read transfers exactly eight bytes, even for a larger count.
                const auto count=event?std::size_t{8}:static_cast<std::size_t>(r[2]);
                const auto permission=reading?a64::Permission::write:a64::Permission::read;
                if(count && !memory.accessible(r[1],count,permission))return error(r,guest_efault);
                std::vector<std::uint8_t> buffer(count);
                if(!reading && count && !memory.read(r[1],buffer))return error(r,guest_efault);
                Fault child_fault=Fault::none;bool invalid_output=false;std::uint64_t budget=1000000;
                const NativeDescriptors::Progress progress=[&]{
                    if(!full_frame || !threads.has_runnable())return false;
                    if(!budget){child_fault=Fault::budget;return false;}
                    std::uint64_t spent=0;child_fault=threads.run_next(budget,spent);budget=spent>=budget?0:budget-spent;
                    if(child_fault!=Fault::none)return false;
                    // Nested work may free the original output. Validate before consuming.
                    if(reading && !memory.accessible(r[1],count,permission)){invalid_output=true;return false;}
                    return true;
                };
                result=reading?descriptors.read_wait(fd,buffer,progress):descriptors.write_wait(fd,buffer,progress);
                stats.threads_created=threads.created;stats.threads_started=threads.started;stats.threads_joined=threads.joined;
                if(child_fault!=Fault::none){rejection="eventfd: nested native work failed";++stats.rejected_operations;return child_fault;}
                if(invalid_output)return error(r,guest_efault);
                if(reading && result.error==host::FileError::none && result.value>0 &&
                   !memory.write(r[1],std::span{buffer}.first(static_cast<std::size_t>(result.value))))return error(r,guest_efault);
            }
            ++stats.file_operations;
            switch (result.error) {
            case host::FileError::none:
                r[0] = static_cast<std::uint64_t>(result.value);
                return Fault::none;
            case host::FileError::missing:
                return error(r, 2);
            case host::FileError::denied:
                return error(r, guest_eacces);
            case host::FileError::exists:
                return error(r, 17);
            case host::FileError::bad_descriptor:
                return error(r, 9);
            case host::FileError::invalid:
                return error(r, guest_einval);
            case host::FileError::unsupported:
                return error(r, 95);
            case host::FileError::descriptor_limit:
                return error(r, 24);
            case host::FileError::quota:
                return error(r, 28);
            case host::FileError::would_block:
                return error(r,11);
            case host::FileError::io:
                return error(r, guest_eio);
            }
        }
        }
        return Fault::unsupported_service;
    }
};
GuestPosixServices::GuestPosixServices(a64::GuestMemory &memory, const a64::AppContext &app,
                                       const host::TimeService &time, std::uint32_t logical_thread,
                                       host::FileService *files,host::NativeLogSink *logs,std::string_view package)
    : impl_(std::make_unique<Impl>(memory, app, time, logical_thread, files,logs,package)) {
    if(!app.process_state)throw a64::GuestError("AETHER_GUEST_CONTEXT","Guest process state is required");
    if (!logical_thread || logical_thread >= 0x40000000U)
        throw a64::GuestError("AETHER_GUEST_THREAD_ID", "Main native thread ID must be positive and below the managed reserved range");
    memory.map(trampoline_base, 4096, a64::read_write);
    impl_->trampoline_owned = true;
    memory.map(extended_trampoline,4096,a64::read_write);impl_->extended_owned=true;
    for(std::size_t i=0;i<extended_entries.size();++i){
        const auto svc=little<4>(0xd4000001u|((extended_service+static_cast<std::uint32_t>(i))<<5));
        constexpr std::array<std::uint8_t,4> ret{0xc0,0x03,0x5f,0xd6};
        if(!memory.write(extended_trampoline+i*8,svc) || !memory.write(extended_trampoline+i*8+4,ret))throw a64::GuestError("AETHER_GUEST_MAPPING","Cannot initialize extended libc trampolines");
    }
    memory.protect(extended_trampoline,a64::read_execute);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto svc = little<4>(0xd4000001u | ((first_service + static_cast<std::uint32_t>(i)) << 5));
        constexpr auto ret = std::array<std::uint8_t, 4>{0xc0, 0x03, 0x5f, 0xd6};
        if (!memory.write(trampoline_base + i * 8, svc) || !memory.write(trampoline_base + i * 8 + 4, ret))
            throw a64::GuestError("AETHER_GUEST_MAPPING", "Could not initialize service trampolines");
    }
    for(std::size_t i=0;i<log_entries.size();++i) {
        const auto svc=little<4>(0xd4000001u|((log_service+static_cast<std::uint32_t>(i))<<5));
        constexpr auto ret=std::array<std::uint8_t,4>{0xc0,0x03,0x5f,0xd6};
        if(!memory.write(log_trampoline+i*8,svc) || !memory.write(log_trampoline+i*8+4,ret))
            throw a64::GuestError("AETHER_GUEST_MAPPING","Could not initialize logging trampolines");
    }
    for(std::size_t i=0;i<cxx_entries.size();++i) {
        const auto svc=little<4>(0xd4000001u|((cxx_service+static_cast<std::uint32_t>(i))<<5));
        constexpr auto ret=std::array<std::uint8_t,4>{0xc0,0x03,0x5f,0xd6};
        if(!memory.write(cxx_trampoline+i*8,svc) || !memory.write(cxx_trampoline+i*8+4,ret))
            throw a64::GuestError("AETHER_GUEST_MAPPING","Could not initialize C++ ABI trampolines");
    }
    for(unsigned i=0;i<6;++i){const auto svc=little<4>(0xd4000001u|((zlib_service+i)<<5));constexpr std::array<std::uint8_t,4> ret{0xc0,0x03,0x5f,0xd6};if(!memory.write(zlib_trampoline+i*8,svc)||!memory.write(zlib_trampoline+i*8+4,ret))throw a64::GuestError("AETHER_GUEST_MAPPING","Cannot initialize zlib trampolines");}
    if(!memory.write(nothrow_address,little<1>(0)))throw a64::GuestError("AETHER_GUEST_MAPPING","Could not initialize guest nothrow tag");
    memory.protect(trampoline_base, a64::read_execute);
    memory.map(errno_address, 4096, a64::read_write);
    impl_->errno_owned = true;
    impl_->threads.initialize();
}
GuestPosixServices::~GuestPosixServices() = default;
bool GuestPosixServices::has_library(std::string_view library) const noexcept {
    return library == "libz.so" || library == "libc.so" || library == "libm.so" || library == "libdl.so" || library == "liblog.so" || library == "libstdc++.so";
}
std::optional<elf::GuestSymbol> GuestPosixServices::resolve(std::string_view library, std::string_view name,
                                                            std::string_view version) const {
    if(library=="libz.so"){if(!version.empty())return std::nullopt;for(std::size_t i=0;i<zlib_entries.size();++i)if(zlib_entries[i]==name)return elf::GuestSymbol{std::string(name),"libz.so",{},zlib_trampoline+i*8,8,2};return std::nullopt;}
    if(library=="libstdc++.so" && (version.empty() || version=="LIBC_O")) {
        if(name=="_ZSt7nothrow")return elf::GuestSymbol{std::string(name),"libstdc++.so","LIBC_O",nothrow_address,1,1};
        for(std::size_t i=0;i<cxx_entries.size();++i)if(cxx_entries[i].name==name)
            return elf::GuestSymbol{std::string(name),"libstdc++.so","LIBC_O",cxx_trampoline+i*8,8,2};
        return std::nullopt;
    }
    if(library=="liblog.so" && (version.empty() || version=="LIBLOG")) {
        for(std::size_t i=0;i<log_entries.size();++i)if(log_entries[i]==name)
            return elf::GuestSymbol{std::string(name),"liblog.so","LIBLOG",log_trampoline+i*8,8,2};
        return std::nullopt;
    }
    if (library != "libc.so" || (!version.empty() && version != "LIBC"))
        return std::nullopt;
    for (std::size_t i = 0; i < entries.size(); ++i)
        if (entries[i].name == name)
            return elf::GuestSymbol{std::string(name), "libc.so", "LIBC", trampoline_base + i * 8, 8, 2};
    for(std::size_t i=0;i<extended_entries.size();++i)
        if(extended_entries[i].name==name)return elf::GuestSymbol{std::string(name),"libc.so","LIBC",extended_trampoline+i*8,8,2};
    return std::nullopt;
}
a64::Fault GuestPosixServices::invoke(std::uint32_t service, Address instruction,
                                      std::array<std::uint64_t, 31> &registers) noexcept {
    auto &p = *impl_;
    if(p.app.process_state->exit_status())return Fault::process_exit;
    if(p.signals.terminated())return Fault::invalid_call;
    if(service>=zlib_service && service-zlib_service<6 && instruction==zlib_trampoline+(service-zlib_service)*8){
        ++p.stats.calls;const auto operation=service-zlib_service;
        if(operation>=4){try{if(operation==4){registers[0]=std::uint64_t{static_cast<std::uint32_t>(registers[1])}*static_cast<std::uint32_t>(registers[2]);return p.dispatch(Operation::allocate,registers);}registers[0]=registers[1];return p.dispatch(Operation::release,registers);}catch(...){p.rejection="zlib guest allocator marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}}
        const auto fault=p.compression.invoke(operation,registers);if(fault!=Fault::none){p.rejection=p.compression.rejection();++p.stats.rejected_operations;}return fault;
    }
    if(service>=cxx_service && service-cxx_service<cxx_entries.size() && instruction==cxx_trampoline+(service-cxx_service)*8) {
        ++p.stats.calls;
        try{return p.dispatch_cxx(cxx_entries[service-cxx_service].operation,registers);}
        catch(...){p.rejection="C++ ABI service raised a host exception";++p.stats.rejected_operations;return Fault::unsupported_service;}
    }
    if(service>=log_service && service-log_service<log_entries.size() && instruction==log_trampoline+(service-log_service)*8) {
        a64::ServiceState state;state.registers=registers;++p.stats.calls;
        const auto fault=p.logging.invoke(log_entries[service-log_service],state,false);registers=state.registers;
        p.stats.log_messages=p.logging.messages();if(fault!=Fault::none){p.rejection=p.logging.rejection();++p.stats.rejected_operations;}return fault;
    }
    const auto operation=registered_operation(service,instruction);
    if (!operation) {
        p.rejection = "service trap is not at its registered guest call site";
        ++p.stats.rejected_operations;
        return Fault::unsupported_service;
    }
    ++p.stats.calls;
    try {
        return p.dispatch(*operation, registers);
    } catch (const std::bad_alloc &) {
        p.rejection = "host allocation failed while marshalling a service";
    } catch (...) {
        p.rejection = "host service raised an exception";
    }
    ++p.stats.rejected_operations;
    return Fault::unsupported_service;
}
a64::Fault GuestPosixServices::invoke_frame(std::uint32_t service,Address instruction,a64::ServiceState &state) noexcept {
    auto &p=*impl_;
    if(p.app.process_state->exit_status())return Fault::process_exit;
    if(p.signals.terminated())return Fault::invalid_call;
    if(const auto selected=registered_operation(service,instruction)){
        const auto operation=*selected;
        if(operation==Operation::read || operation==Operation::write || operation==Operation::system_call || operation==Operation::poll_descriptors || (operation>=Operation::sleep_seconds && operation<=Operation::sleep_nanos)){
            ++p.stats.calls;try{return p.dispatch(operation,state.registers,true);}catch(...){p.rejection="descriptor: host marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}
        }
        if(operation>=Operation::format_list && operation<=Operation::format_checked_direct){++p.stats.calls;return p.format_operation(operation,state,true);}
        if(operation>=Operation::jump_save && operation<=Operation::jump_restore){
            ++p.stats.calls;try{return p.jump_operation(operation,state,true);}catch(...){p.rejection="setjmp/longjmp: host marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}
        }
        if(operation==Operation::cond_wait){
            ++p.stats.calls;try{return p.condition_operation(operation,state.registers,true);}catch(...){p.rejection="pthread condition: host marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}
        }
        if(operation==Operation::pthread_mask || operation==Operation::process_mask || (operation>=Operation::signal_handler && operation<=Operation::signal_wait)){
            ++p.stats.calls;try{return operation==Operation::pthread_mask || operation==Operation::process_mask?p.mask_operation(operation,state,true):p.signal_operation(operation,state,true);}catch(...){p.rejection="signal: host marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}
        }
    }
    if(service>=log_service && service-log_service<log_entries.size() && instruction==log_trampoline+(service-log_service)*8) {
        ++p.stats.calls;const auto fault=p.logging.invoke(log_entries[service-log_service],state,true);
        p.stats.log_messages=p.logging.messages();if(fault!=Fault::none){p.rejection=p.logging.rejection();++p.stats.rejected_operations;}return fault;
    }
    if(const auto operation=registered_operation(service,instruction);operation && *operation==Operation::scan){
        ++p.stats.calls;try{return p.scanning(state,true);}catch(...){p.rejection="sscanf: host marshalling failure";++p.stats.rejected_operations;return Fault::unsupported_service;}
    }
    return invoke(service,instruction,state.registers);
}
std::optional<GuestPosixServices::ThreadBinding> GuestPosixServices::exchange_thread_binding(std::optional<ThreadBinding> value){return impl_->threads.exchange_binding(value);}
std::uint64_t GuestPosixServices::signal_mask(){return impl_->threads.signal_mask();}
std::uint64_t GuestPosixServices::binding_signal_mask(const ThreadBinding &binding){return impl_->threads.binding_signal_mask(binding);}
void GuestPosixServices::set_signal_runner(SignalRunner runner){impl_->signals.runner(std::move(runner));}
void GuestPosixServices::set_managed_priority_service(int baseline,host::PriorityService service){impl_->threads.managed_priority(baseline,std::move(service));}
host::PriorityResult GuestPosixServices::current_thread_priority(std::optional<std::int32_t> nice){return impl_->threads.priority(0,0,nice);}
std::optional<std::uint64_t> GuestPosixServices::thread_exit_value(Address tls) const noexcept {return impl_->threads.exit_value(tls);}
void GuestPosixServices::request_thread_exit(std::uint64_t value) noexcept {impl_->threads.request_exit(value);}
void GuestPosixServices::set_thread_runner(ThreadRunner runner){impl_->threads.runner(std::move(runner));}
a64::Address GuestPosixServices::thread_pointer()const noexcept{return impl_->threads.tls();}
bool GuestPosixServices::is_main_native_thread()const noexcept{return impl_->threads.tid()==impl_->tid;}
a64::Fault GuestPosixServices::run_pending_threads(std::uint64_t budget) noexcept {
    auto &p=*impl_;if(p.app.process_state->exit_status())return Fault::process_exit;try {
        const auto fault=p.threads.pump(budget);p.stats.threads_created=p.threads.created;p.stats.threads_started=p.threads.started;p.stats.threads_joined=p.threads.joined;
        if(fault!=Fault::none){p.rejection=p.threads.rejection();++p.stats.rejected_operations;}return fault;
    }catch(...){p.rejection="Native thread pump failed";return a64::Fault::windows_service;}
}
const ServiceMetrics &GuestPosixServices::metrics() const noexcept { return impl_->stats; }
std::string_view GuestPosixServices::last_rejection() const noexcept { return impl_->rejection; }
} // namespace aether::bionic
