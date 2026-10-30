#include "aether/bionic/guest_posix.hpp"
#include "aether/a64/capabilities.hpp"
#include "aether/common/thread_exit.hpp"
#include "logging.hpp"
#include "threads.hpp"
#include "thread_specific.hpp"
#include "thread_attributes.hpp"
#include "zlib.hpp"
#include "mutexes.hpp"
#include "rwlocks.hpp"
#include "stdio.hpp"
#include "integers.hpp"
#include "float_conversion.hpp"
#include "collation.hpp"
#include "wide_memory.hpp"
#include "scanning.hpp"
#include "signals.hpp"
#include "conditions.hpp"
#include "calendar.hpp"
#include "locale.hpp"
#include "ctype.hpp"
#include "unicode.hpp"
#include "once.hpp"
#include "phdr.hpp"
#include "cxa_destructors.hpp"
#include "abort_message.hpp"
#include "multibyte.hpp"
#include "descriptors.hpp"
#include "polling.hpp"
#include "sleeping.hpp"
#include "jumps.hpp"
#include "access.hpp"
#include "executing.hpp"
#include "string_memory.hpp"
#include "file_metadata.hpp"
#include "removing.hpp"
#include "opening.hpp"
#include "creating.hpp"
#include "renaming.hpp"
#include "error_strings.hpp"
#include "dynamic_linker.hpp"
#include "properties.hpp"
#include "mappings.hpp"
#include "aether/host/process_info.hpp"
#include <algorithm>
#include <array>
#include <bit>
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
    rw_read,rw_write,rw_tryread,rw_trywrite,rw_unlock,rw_init,rw_destroy,rw_attr_init,rw_attr_destroy,rw_attr_setshared,rw_attr_getshared,rw_attr_setkind,rw_attr_getkind,process_id,process_probe,resource_limit,duplicate,bounded_duplicate,string_copy,string_cat,checked_string_copy,checked_string_cat,system_call,directory_open,directory_read,directory_close,directory_rewind,stdio_open,stdio_close,stdio_read,stdio_write,stdio_getc,stdio_gets,stdio_eof,stdio_error,stdio_clear,stdio_fd,stdio_flush,integer_unsigned,integer_signed,integer_atoi,integer_atol,scan,sig_empty,sig_fill,sig_add,sig_del,sig_member,pthread_mask,process_mask,signal_handler,signal_action,signal_raise,signal_pending,signal_wait,cond_wait,cond_signal,cond_broadcast,cond_init,cond_destroy,cond_attr_init,cond_attr_destroy,cond_attr_getshared,cond_attr_setshared,cond_attr_getclock,cond_attr_setclock,epoch_time,local_time,epoch_timeval,descriptor_dup,jump_save,jump_set,jump_plain,jump_restore,format_list,format_direct,format_checked_list,format_checked_direct,file_lock,file_access,realtime_min,realtime_max,priority_set,priority_get,event_create,poll_descriptors,sleep_seconds,sleep_micros,sleep_nanos,process_exit,thread_exit,alarm_timer,execute_list_path,allocate_zero,resize_allocation,string_compare,string_compare_n,string_copy_n,string_find_char,string_find_last_char,string_find_text,string_compare_bytes,string_find_byte,string_find_bytes,string_checked_length,string_checked_find_char,string_checked_find_last_char,string_checked_copy_n,string_checked_copy_n_source,string_checked_move,heap_information,file_read_link,file_read_link_at,file_descriptor_stat,file_descriptor_seek,file_user_id,file_remove,file_unlink,file_unlink_at,file_remove_directory,checked_open,checked_read,checked_write,checked_read_link,checked_read_link_at,resource_set_limit,open_at,checked_open_at,access_at,thread_attr_init,thread_attr_destroy,thread_attr_setdetach,thread_attr_getdetach,thread_attr_setstacksize,thread_attr_getstacksize,thread_attr_setguard,thread_attr_getguard,thread_attr_getstack,thread_getattr,thread_detach,signal_stack,page_size,address_info,system_configuration,memory_map,memory_unmap,memory_protect,cond_timedwait,directory_create,directory_create_at,file_rename,file_rename_at,process_control,error_description,system_property,process_fork,thread_set_name,thread_get_name,system_information,format_checked_unbounded_list,dynamic_open,dynamic_symbol,dynamic_close,dynamic_error,auxiliary_value,key_create,key_delete,key_get,key_set,process_abort,string_copy_sized,process_trace,process_wait,calendar_format,string_tokenize,string_tokenize_reentrant,stdio_rewind,stdio_seek,stdio_tell,string_checked_copy_bytes,string_checked_copy_end,string_checked_fill,string_length_n,thread_signal,scan_list,locale_new,locale_duplicate,locale_free,locale_use,locale_set,locale_conventions,locale_width,character_wide_control,character_alnum,character_alpha,character_blank,character_control,character_digit,character_graph,character_lower,character_print,character_punct,character_space,character_upper,character_xdigit,character_to_lower,character_to_upper,thread_once,multibyte_wcsnrtombs,multibyte_wcsrtombs,multibyte_wcrtomb,multibyte_btowc,multibyte_wctob,multibyte_mbrtowc,multibyte_mbrlen,multibyte_mbsnrtowcs,multibyte_mbsrtowcs,multibyte_mbsinit,unicode_iswalnum,unicode_iswalpha,unicode_iswblank,unicode_iswdigit,unicode_iswgraph,unicode_iswlower,unicode_iswprint,unicode_iswpunct,unicode_iswspace,unicode_iswupper,unicode_iswxdigit,unicode_towlower,unicode_towupper,float_single,float_double,float_long,float_wide_single,float_wide_double,float_wide_long,float_atof,syslog_direct,syslog_list,syslog_open,syslog_close,syslog_mask,allocate_posix_aligned,allocate_memaligned,allocate_aligned,collate_compare,collate_transform,collate_wide_compare,collate_wide_transform,wide_copy,wide_length,wide_move,wide_compare,wide_find,wide_fill,thread_equal,stdio_ungetc,stdio_putc,format_wide_direct,format_wide_list,iterate_phdr,set_abort_message,integer_wide_unsigned,integer_wide_signed,multibyte_mbtowc,multibyte_mblen,multibyte_wctomb,error_description_xsi,error_description_gnu,schedule_yield,format_allocated_list,format_allocated_direct,format_stream_direct,format_stream_list,format_stdout_direct,format_stdout_list,string_copy_end,string_concatenate_n,string_span_accept,string_span_reject,string_find_any
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
constexpr std::array extended_entries{Entry{"sleep",Operation::sleep_seconds},Entry{"usleep",Operation::sleep_micros},Entry{"nanosleep",Operation::sleep_nanos},Entry{"_exit",Operation::process_exit},Entry{"_Exit",Operation::process_exit},Entry{"pthread_exit",Operation::thread_exit},Entry{"alarm",Operation::alarm_timer},Entry{"execlp",Operation::execute_list_path},Entry{"calloc",Operation::allocate_zero},Entry{"realloc",Operation::resize_allocation},Entry{"strcmp",Operation::string_compare},Entry{"strncmp",Operation::string_compare_n},Entry{"strncpy",Operation::string_copy_n},Entry{"strchr",Operation::string_find_char},Entry{"strrchr",Operation::string_find_last_char},Entry{"strstr",Operation::string_find_text},Entry{"memcmp",Operation::string_compare_bytes},Entry{"memchr",Operation::string_find_byte},Entry{"memmem",Operation::string_find_bytes},Entry{"__strlen_chk",Operation::string_checked_length},Entry{"__strchr_chk",Operation::string_checked_find_char},Entry{"__strrchr_chk",Operation::string_checked_find_last_char},Entry{"__strncpy_chk",Operation::string_checked_copy_n},Entry{"__strncpy_chk2",Operation::string_checked_copy_n_source},Entry{"__memmove_chk",Operation::string_checked_move},Entry{"mallinfo",Operation::heap_information},Entry{"readlink",Operation::file_read_link},Entry{"readlinkat",Operation::file_read_link_at},Entry{"fstat",Operation::file_descriptor_stat},Entry{"fstat64",Operation::file_descriptor_stat},Entry{"lseek",Operation::file_descriptor_seek},Entry{"lseek64",Operation::file_descriptor_seek},Entry{"getuid",Operation::file_user_id},Entry{"geteuid",Operation::file_user_id},Entry{"getgid",Operation::file_user_id},Entry{"getegid",Operation::file_user_id},Entry{"remove",Operation::file_remove},Entry{"unlink",Operation::file_unlink},Entry{"unlinkat",Operation::file_unlink_at},Entry{"rmdir",Operation::file_remove_directory},Entry{"__open_2",Operation::checked_open},Entry{"__read_chk",Operation::checked_read},Entry{"__write_chk",Operation::checked_write},Entry{"__readlink_chk",Operation::checked_read_link},Entry{"__readlinkat_chk",Operation::checked_read_link_at},Entry{"setrlimit",Operation::resource_set_limit},Entry{"setrlimit64",Operation::resource_set_limit},Entry{"open64",Operation::open},Entry{"openat",Operation::open_at},Entry{"openat64",Operation::open_at},Entry{"__openat_2",Operation::checked_open_at},Entry{"faccessat",Operation::access_at},Entry{"pthread_attr_init",Operation::thread_attr_init},Entry{"pthread_attr_destroy",Operation::thread_attr_destroy},Entry{"pthread_attr_setdetachstate",Operation::thread_attr_setdetach},Entry{"pthread_attr_getdetachstate",Operation::thread_attr_getdetach},Entry{"pthread_attr_setstacksize",Operation::thread_attr_setstacksize},Entry{"pthread_attr_getstacksize",Operation::thread_attr_getstacksize},Entry{"pthread_attr_setguardsize",Operation::thread_attr_setguard},Entry{"pthread_attr_getguardsize",Operation::thread_attr_getguard},Entry{"pthread_attr_getstack",Operation::thread_attr_getstack},Entry{"pthread_getattr_np",Operation::thread_getattr},Entry{"pthread_detach",Operation::thread_detach},Entry{"sigaltstack",Operation::signal_stack},Entry{"getpagesize",Operation::page_size},Entry{"dladdr",Operation::address_info},Entry{"sysconf",Operation::system_configuration},Entry{"mmap",Operation::memory_map},Entry{"mmap64",Operation::memory_map},Entry{"munmap",Operation::memory_unmap},Entry{"mprotect",Operation::memory_protect},Entry{"pthread_cond_timedwait",Operation::cond_timedwait},Entry{"mkdir",Operation::directory_create},Entry{"mkdirat",Operation::directory_create_at},Entry{"rename",Operation::file_rename},Entry{"renameat",Operation::file_rename_at},Entry{"prctl",Operation::process_control},Entry{"strerror",Operation::error_description},Entry{"__system_property_get",Operation::system_property},Entry{"fork",Operation::process_fork},Entry{"pthread_setname_np",Operation::thread_set_name},Entry{"pthread_getname_np",Operation::thread_get_name},Entry{"sysinfo",Operation::system_information},Entry{"__vsprintf_chk",Operation::format_checked_unbounded_list},Entry{"dlopen",Operation::dynamic_open},Entry{"dlsym",Operation::dynamic_symbol},Entry{"dlclose",Operation::dynamic_close},Entry{"dlerror",Operation::dynamic_error},Entry{"getauxval",Operation::auxiliary_value},Entry{"pthread_key_create",Operation::key_create},Entry{"pthread_key_delete",Operation::key_delete},Entry{"pthread_getspecific",Operation::key_get},Entry{"pthread_setspecific",Operation::key_set},Entry{"abort",Operation::process_abort},Entry{"strlcpy",Operation::string_copy_sized},Entry{"ptrace",Operation::process_trace},Entry{"waitpid",Operation::process_wait},Entry{"wait4",Operation::process_wait},Entry{"strftime",Operation::calendar_format},Entry{"strtok",Operation::string_tokenize},Entry{"strtok_r",Operation::string_tokenize_reentrant},Entry{"rewind",Operation::stdio_rewind},Entry{"fseek",Operation::stdio_seek},Entry{"fseeko",Operation::stdio_seek},Entry{"fseeko64",Operation::stdio_seek},Entry{"ftell",Operation::stdio_tell},Entry{"ftello",Operation::stdio_tell},Entry{"ftello64",Operation::stdio_tell},Entry{"__memcpy_chk",Operation::string_checked_copy_bytes},Entry{"__mempcpy_chk",Operation::string_checked_copy_end},Entry{"__memset_chk",Operation::string_checked_fill},Entry{"strnlen",Operation::string_length_n},Entry{"tgkill",Operation::thread_signal},Entry{"strtoull_l",Operation::integer_unsigned},Entry{"strtoll_l",Operation::integer_signed},Entry{"strtoul_l",Operation::integer_unsigned},Entry{"strtol_l",Operation::integer_signed},Entry{"vsscanf",Operation::scan_list},Entry{"newlocale",Operation::locale_new},Entry{"duplocale",Operation::locale_duplicate},Entry{"freelocale",Operation::locale_free},Entry{"uselocale",Operation::locale_use},Entry{"setlocale",Operation::locale_set},Entry{"localeconv",Operation::locale_conventions},Entry{"__ctype_get_mb_cur_max",Operation::locale_width},Entry{"iswcntrl",Operation::character_wide_control},Entry{"iswcntrl_l",Operation::character_wide_control},Entry{"isalnum",Operation::character_alnum},Entry{"isalpha",Operation::character_alpha},Entry{"isblank",Operation::character_blank},Entry{"iscntrl",Operation::character_control},Entry{"isdigit",Operation::character_digit},Entry{"isgraph",Operation::character_graph},Entry{"islower",Operation::character_lower},Entry{"isprint",Operation::character_print},Entry{"ispunct",Operation::character_punct},Entry{"isspace",Operation::character_space},Entry{"isupper",Operation::character_upper},Entry{"isxdigit",Operation::character_xdigit},Entry{"tolower",Operation::character_to_lower},Entry{"toupper",Operation::character_to_upper},Entry{"isalnum_l",Operation::character_alnum},Entry{"isalpha_l",Operation::character_alpha},Entry{"isblank_l",Operation::character_blank},Entry{"iscntrl_l",Operation::character_control},Entry{"isdigit_l",Operation::character_digit},Entry{"isgraph_l",Operation::character_graph},Entry{"islower_l",Operation::character_lower},Entry{"isprint_l",Operation::character_print},Entry{"ispunct_l",Operation::character_punct},Entry{"isspace_l",Operation::character_space},Entry{"isupper_l",Operation::character_upper},Entry{"isxdigit_l",Operation::character_xdigit},Entry{"tolower_l",Operation::character_to_lower},Entry{"toupper_l",Operation::character_to_upper},Entry{"pthread_once",Operation::thread_once},Entry{"wcsnrtombs",Operation::multibyte_wcsnrtombs},Entry{"wcsrtombs",Operation::multibyte_wcsrtombs},Entry{"wcrtomb",Operation::multibyte_wcrtomb},Entry{"btowc",Operation::multibyte_btowc},Entry{"wctob",Operation::multibyte_wctob},Entry{"mbrtowc",Operation::multibyte_mbrtowc},Entry{"mbrlen",Operation::multibyte_mbrlen},Entry{"mbsnrtowcs",Operation::multibyte_mbsnrtowcs},Entry{"mbsrtowcs",Operation::multibyte_mbsrtowcs},Entry{"mbsinit",Operation::multibyte_mbsinit},Entry{"iswalnum",Operation::unicode_iswalnum},Entry{"iswalpha",Operation::unicode_iswalpha},Entry{"iswblank",Operation::unicode_iswblank},Entry{"iswdigit",Operation::unicode_iswdigit},Entry{"iswgraph",Operation::unicode_iswgraph},Entry{"iswlower",Operation::unicode_iswlower},Entry{"iswprint",Operation::unicode_iswprint},Entry{"iswpunct",Operation::unicode_iswpunct},Entry{"iswspace",Operation::unicode_iswspace},Entry{"iswupper",Operation::unicode_iswupper},Entry{"iswxdigit",Operation::unicode_iswxdigit},Entry{"towlower",Operation::unicode_towlower},Entry{"towupper",Operation::unicode_towupper},Entry{"iswalnum_l",Operation::unicode_iswalnum},Entry{"iswalpha_l",Operation::unicode_iswalpha},Entry{"iswblank_l",Operation::unicode_iswblank},Entry{"iswdigit_l",Operation::unicode_iswdigit},Entry{"iswgraph_l",Operation::unicode_iswgraph},Entry{"iswlower_l",Operation::unicode_iswlower},Entry{"iswprint_l",Operation::unicode_iswprint},Entry{"iswpunct_l",Operation::unicode_iswpunct},Entry{"iswspace_l",Operation::unicode_iswspace},Entry{"iswupper_l",Operation::unicode_iswupper},Entry{"iswxdigit_l",Operation::unicode_iswxdigit},Entry{"towlower_l",Operation::unicode_towlower},Entry{"towupper_l",Operation::unicode_towupper},Entry{"strtof",Operation::float_single},Entry{"strtod",Operation::float_double},Entry{"strtold",Operation::float_long},Entry{"wcstof",Operation::float_wide_single},Entry{"wcstod",Operation::float_wide_double},Entry{"wcstold",Operation::float_wide_long},Entry{"atof",Operation::float_atof},Entry{"strtof_l",Operation::float_single},Entry{"strtod_l",Operation::float_double},Entry{"strtold_l",Operation::float_long},Entry{"wcstof_l",Operation::float_wide_single},Entry{"wcstod_l",Operation::float_wide_double},Entry{"wcstold_l",Operation::float_wide_long},Entry{"syslog",Operation::syslog_direct},Entry{"vsyslog",Operation::syslog_list},Entry{"openlog",Operation::syslog_open},Entry{"closelog",Operation::syslog_close},Entry{"setlogmask",Operation::syslog_mask},Entry{"posix_memalign",Operation::allocate_posix_aligned},Entry{"memalign",Operation::allocate_memaligned},Entry{"aligned_alloc",Operation::allocate_aligned},Entry{"strcoll",Operation::collate_compare},Entry{"strxfrm",Operation::collate_transform},Entry{"wcscoll",Operation::collate_wide_compare},Entry{"wcsxfrm",Operation::collate_wide_transform},Entry{"strcoll_l",Operation::collate_compare},Entry{"strxfrm_l",Operation::collate_transform},Entry{"wcscoll_l",Operation::collate_wide_compare},Entry{"wcsxfrm_l",Operation::collate_wide_transform},Entry{"wmemcpy",Operation::wide_copy},Entry{"wcslen",Operation::wide_length},Entry{"wmemmove",Operation::wide_move},Entry{"wmemcmp",Operation::wide_compare},Entry{"wmemchr",Operation::wide_find},Entry{"wmemset",Operation::wide_fill},Entry{"pthread_equal",Operation::thread_equal},Entry{"ungetc",Operation::stdio_ungetc},Entry{"getc",Operation::stdio_getc},Entry{"fputc",Operation::stdio_putc},Entry{"swprintf",Operation::format_wide_direct},Entry{"vswprintf",Operation::format_wide_list},Entry{"dl_iterate_phdr",Operation::iterate_phdr},Entry{"android_set_abort_message",Operation::set_abort_message},Entry{"wcstol",Operation::integer_wide_signed},Entry{"wcstoul",Operation::integer_wide_unsigned},Entry{"wcstoll",Operation::integer_wide_signed},Entry{"wcstoull",Operation::integer_wide_unsigned},Entry{"wcstoimax",Operation::integer_wide_signed},Entry{"wcstoumax",Operation::integer_wide_unsigned},Entry{"wcstol_l",Operation::integer_wide_signed},Entry{"wcstoul_l",Operation::integer_wide_unsigned},Entry{"wcstoll_l",Operation::integer_wide_signed},Entry{"wcstoull_l",Operation::integer_wide_unsigned},Entry{"mbtowc",Operation::multibyte_mbtowc},Entry{"mblen",Operation::multibyte_mblen},Entry{"wctomb",Operation::multibyte_wctomb},Entry{"strerror_r",Operation::error_description_xsi},Entry{"__gnu_strerror_r",Operation::error_description_gnu},Entry{"sched_yield",Operation::schedule_yield},Entry{"vasprintf",Operation::format_allocated_list},Entry{"asprintf",Operation::format_allocated_direct},Entry{"fprintf",Operation::format_stream_direct},Entry{"vfprintf",Operation::format_stream_list},Entry{"printf",Operation::format_stdout_direct},Entry{"vprintf",Operation::format_stdout_list},Entry{"stpcpy",Operation::string_copy_end},Entry{"strncat",Operation::string_concatenate_n},Entry{"strspn",Operation::string_span_accept},Entry{"strcspn",Operation::string_span_reject},Entry{"strpbrk",Operation::string_find_any}};
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
    NativeFileMetadata metadata;
    NativeRemoving removing;
    NativeOpening opening;
    NativeCreating creating;
    NativeRenaming renaming;
    NativeMappings mappings;
    NativeExecuting executing;
    NativeStringMemory string_memory;
    NativeCollation collation;
    NativeWideMemory wide_memory;
    NativeFormatting formatting;
    NativeThreadSpecific specific;
    NativeThreads threads;
    NativeLocale locales;
    NativeOnce once;
    NativePhdr phdr;
    NativeCxaDestructors cxa;
    NativeAbortMessage abort_message;
    NativeMultibyte multibyte;
    NativeDynamicLinker dynamic_linker;
    NativeErrorStrings error_strings;
    NativeThreadAttributes thread_attributes;
    NativeSignals signals;
    NativePolling polling;
    NativeSleeping sleeping;
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
    struct Allocation {std::size_t mapped,requested;};
    std::map<Address, Allocation> allocations;
    struct Directory {std::vector<host::DirectoryEntry> entries;std::size_t position=0;};
    std::map<Address,Directory> directories;
    AddressLookup address_lookup;
    std::map<std::string,Address,std::less<>> lookup_strings;
    Address next_directory=0x38000000;
    Address next_heap = 0x40000000;
    std::size_t heap_peak=0;
    bool trampoline_owned = false, extended_owned=false, errno_owned = false;
    Impl(a64::GuestMemory &m, const a64::AppContext &a, const host::TimeService &t, std::uint32_t id,
         host::FileService *f,host::NativeLogSink *logs,std::string_view package)
        : memory(m), app(a), time(t), descriptors(f), files(f?&descriptors:nullptr), logging(m,logs,package), access(m,files,package), metadata(m,a,descriptors,access,package), removing(m,descriptors,package), opening(m,descriptors,package), creating(m,descriptors,package), renaming(m,descriptors,package), mappings(m), executing(m,access), string_memory(m), collation(m), wide_memory(m), formatting(m), specific(m), threads(m,id,GuestPosixServices::errno_address,&specific), locales(m,threads), once(m,threads,a), phdr(m,threads,a), cxa(m,threads,a), abort_message(m,a), multibyte(m,threads), dynamic_linker(m,threads,a), error_strings(m,threads), thread_attributes(m,threads), signals(m,threads,a), polling(m,descriptors,threads,signals), sleeping(m,threads,signals), jumps(m,threads,signals), compression(m,zlib_trampoline+32,zlib_trampoline+40), mutexes(m), conditions(m,threads,mutexes,t,signals,a), calendar(m,t), rwlocks(m), stdio(m,descriptors,f!=nullptr), tid(id) {}
    ~Impl() {
        for(const auto &[name,address]:lookup_strings){(void)name;unmap(address);}
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
    struct HeapResult {Address address=0;Fault fault=Fault::none;};
    HeapResult allocate_heap(std::uint64_t requested,Address alignment,
                             std::optional<Address> output={}) {
        constexpr Address heap_end=0x50000000;
        constexpr auto page=a64::GuestMemory::page_size;
        if(requested>maximum_heap || allocations.size()>=4096)return {};
        const auto size=(std::max<std::size_t>(static_cast<std::size_t>(requested),1)+page-1)&~(page-1);
        if(size>maximum_heap-stats.allocated_bytes || next_heap>=heap_end)return {};
        alignment=std::max<Address>(alignment,page);
        // Include the following unmapped page in the placement search. Alignment
        // gaps consume virtual cursor space, never the committed heap quota.
        const auto footprint=size+page;
        const auto initial_remainder=next_heap&(alignment-1);
        const auto initial_padding=initial_remainder?alignment-initial_remainder:0;
        if(initial_padding>heap_end-next_heap)return {};
        Address candidate=next_heap+initial_padding,address=0;
        // Every failed pass now skips at least one new mapping; one final pass
        // finds placement. GuestMemory permits at most 4096 mappings.
        for(unsigned attempt=0;attempt<=4096;++attempt){
            if(candidate>=heap_end || footprint>heap_end-candidate)return {};
            const auto free=memory.find_free(candidate,heap_end,footprint);
            if(!free)return {};
            const auto remainder=*free&(alignment-1);
            const auto padding=remainder?alignment-remainder:0;
            if(padding>heap_end-*free)return {};
            const auto aligned=*free+padding;
            if(aligned==*free){address=aligned;break;}
            candidate=aligned;
        }
        if(!address)return {};
        // Invalid destinations are a guest fault, not an allocation. Preflight
        // only after nonmutating ENOMEM checks, preserving POSIX error ordering.
        if(output && !memory.accessible(*output,8,a64::Permission::write))return {0,Fault::write};
        try {
            const auto [entry,inserted]=allocations.emplace(address,Allocation{size,static_cast<std::size_t>(requested)});
            if(!inserted)return {};
            try {memory.map(address,size,a64::read_write);}
            catch(...){allocations.erase(entry);throw;}
            if(output && !memory.write(*output,little<8>(address))){
                memory.unmap(address);allocations.erase(entry);return {0,Fault::write};
            }
            next_heap=address+footprint;
            stats.allocated_bytes+=size;
            heap_peak=std::max(heap_peak,stats.allocated_bytes);
            ++stats.allocations;
            return {address,Fault::none};
        }catch(const a64::GuestError &){return {};}
        catch(const std::bad_alloc &){return {};}
    }
    void release_owned_heap(Address address) {
        const auto entry=allocations.find(address);
        if(entry==allocations.end())return;
        memory.unmap(address);
        stats.allocated_bytes-=entry->second.mapped;
        allocations.erase(entry);++stats.frees;
    }
    HeapResult resize_owned_heap(Address address,std::size_t requested) {
        const auto old=allocations.find(address);
        if(old==allocations.end())return {0,Fault::invalid_call};
        if(requested>maximum_heap)return {};
        if(requested<=old->second.mapped){old->second.requested=requested;return {address,Fault::none};}
        try {
            std::vector<std::uint8_t> saved(std::min(old->second.requested,requested));
            if(!saved.empty() && !memory.read(address,saved))return {0,Fault::read};
            const auto replacement=allocate_heap(requested,a64::GuestMemory::page_size);
            if(!replacement.address || replacement.fault!=Fault::none)return replacement;
            if(!saved.empty() && !memory.write(replacement.address,saved)){
                release_owned_heap(replacement.address);return {0,Fault::write};
            }
            release_owned_heap(address);return replacement;
        }catch(const std::bad_alloc &){return {};}
    }
    Fault allocated_format_operation(Operation operation,a64::ServiceState &state,bool full) {
        const auto output=state.registers[0];
        Address owned=0;
        const auto cleanup=[&](){if(owned){release_owned_heap(owned);owned=0;}};
        const auto reject=[&](Fault fault,std::string_view reason){cleanup();rejection=reason;++stats.rejected_operations;return fault;};
        const auto exhausted=[&](){
            cleanup();
            if(!memory.write(output,little<8>(0)))return reject(Fault::write,"asprintf: output pointer is not writable");
            return error(state.registers,guest_enomem);
        };
        try {
            const auto initial=allocate_heap(128,a64::GuestMemory::page_size);
            if(initial.fault!=Fault::none)return reject(initial.fault,"asprintf: initial allocation failed");
            if(!initial.address)return exhausted();
            owned=initial.address;
            std::string rendered;bool allocation_failed=false;
            const auto fault=formatting.render_allocated(operation==Operation::format_allocated_list,
                threads.error_address(),state,full,rendered,allocation_failed);
            if(allocation_failed)return exhausted();
            if(fault!=Fault::none)return reject(fault,formatting.rejection());
            const auto resized=resize_owned_heap(owned,rendered.size()+1);
            if(resized.fault!=Fault::none)return reject(resized.fault,"asprintf: owned resize failed");
            if(!resized.address)return exhausted();
            owned=resized.address;
            const auto count=rendered.size();rendered.push_back('\0');
            if(!memory.write(owned,std::span{reinterpret_cast<const std::uint8_t *>(rendered.data()),rendered.size()}))
                return reject(Fault::write,"asprintf: owned output is not writable");
            if(!memory.write(output,little<8>(owned)))return reject(Fault::write,"asprintf: output pointer is not writable");
            owned=0;state.registers[0]=count;return Fault::none;
        }catch(const std::bad_alloc &){return exhausted();}
        catch(...){return reject(Fault::windows_service,"asprintf: owned formatting failed");}
    }
    Fault wait_operation(std::array<std::uint64_t,31> &r,std::uint64_t pid,std::uint64_t options) {
        // Linux wait4 validates int flags before pid; this app has no process children.
        constexpr std::uint32_t allowed=0xe000000bU;
        if(static_cast<std::uint32_t>(options)&~allowed)return error(r,22);
        return error(r,static_cast<std::uint32_t>(pid)==0x80000000U?3U:10U);
    }
    Fault abort_operation(a64::ServiceState &state,bool full) noexcept {
        try {
            const auto fault=signals.abort(state,full,*app.process_state);
            rejection=signals.abort_failure()==Fault::none?std::string_view{"abort: guest SIGABRT termination"}:a64::fault_name(signals.abort_failure());
            return fault;
        }catch(...){app.process_state->request_signal(6);rejection="abort: SIGABRT handler threw; forced fatal termination";return Fault::process_exit;}
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
    Fault once_operation(a64::ServiceState &state,bool full) {
        const auto fault=once.invoke(state,full);
        if(fault!=Fault::none){rejection=once.rejection();++stats.rejected_operations;}return fault;
    }
    Fault scanning(a64::ServiceState &state,bool full,bool list=false) {
        const auto fault=scan_text(memory,state,full,threads.error_address(),list);
        if(fault!=Fault::none){rejection=list?"vsscanf: unsupported format/limit or invalid guest access":"sscanf: unsupported format/limit or invalid guest access";++stats.rejected_operations;}
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
    Fault thread_signal_operation(a64::ServiceState &state,bool full,bool syscall=false) {
        const auto &r=state.registers;const unsigned at=syscall?1U:0U;
        const auto fault=signals.tgkill(r[at],r[at+1],r[at+2],state,full);
        if(fault!=Fault::none){rejection="tgkill: unsupported logical signal delivery or invalid guest access";++stats.rejected_operations;}
        else if(state.registers[0]==UINT64_MAX)++stats.errors;
        return fault;
    }
    Fault execute_operation(a64::ServiceState &state,bool full) {
        const auto fault=executing.invoke(threads.error_address(),state,full);
        if(fault!=Fault::none){rejection=executing.rejection();++stats.rejected_operations;}
        else if(state.registers[0]==UINT64_MAX)++stats.errors;
        return fault;
    }
    Fault format_operation(Operation operation,a64::ServiceState &state,bool full) {
        const auto fault=formatting.invoke(operation==Operation::format_checked_unbounded_list?4U:static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::format_list),state,full);
        if(fault!=Fault::none){rejection=formatting.rejection();++stats.rejected_operations;}return fault;
    }
    Fault stream_format_operation(Operation operation,a64::ServiceState &state,bool full) {
        const bool standard=operation==Operation::format_stdout_direct || operation==Operation::format_stdout_list;
        const bool list=operation==Operation::format_stream_list || operation==Operation::format_stdout_list;
        const auto reject=[&](Fault fault,std::string_view reason){rejection=reason;++stats.rejected_operations;return fault;};
        try {
            auto handle=state.registers[0];
            if(standard){
                std::array<std::uint8_t,8> pointer{};
                if(!memory.read(NativeStdio::standard_base+520,pointer))return reject(Fault::read,"printf: unreadable stdout pointer");
                handle=0;for(unsigned i=0;i<8;++i)handle|=std::uint64_t{pointer[i]}<<(i*8);
            }
            bool ready=false;
            const auto prepared=stdio.prepare_formatted(handle,threads.error_address(),state.registers,ready);
            if(prepared!=Fault::none)return reject(prepared,"fprintf: owned stream preparation failed");
            if(!ready){++stats.errors;return Fault::none;}
            std::string rendered;bool allocation_failed=false;
            const auto formatted=formatting.render_stream(list,standard,threads.error_address(),state,full,rendered,allocation_failed);
            if(allocation_failed)return error(state.registers,guest_enomem);
            if(formatted!=Fault::none)return reject(formatted,formatting.rejection());
            const auto written=stdio.write_formatted(handle,threads.error_address(),
                std::span{reinterpret_cast<const std::uint8_t *>(rendered.data()),rendered.size()},state.registers);
            if(written!=Fault::none)return reject(written,"fprintf: owned stream output failed");
            if(state.registers[0]==UINT64_MAX)++stats.errors;
            return Fault::none;
        }catch(const std::bad_alloc &){return error(state.registers,guest_enomem);}
        catch(...){return reject(Fault::windows_service,"fprintf: owned stream service failed");}
    }
    Fault register_cxa_operation(std::array<std::uint64_t,31> &registers) noexcept {
        const auto fault=cxa.register_callback(registers);
        if(fault!=Fault::none){rejection=cxa.rejection();++stats.rejected_operations;}
        else if(registers[0]==UINT64_MAX)++stats.errors;
        return fault;
    }
    Fault finalize_cxa_operation(a64::ServiceState &state,bool full) noexcept {
        const auto owner=threads.tid();const auto tls=threads.tls();
        auto fault=cxa.finalize(state,full);
        if(app.process_state && app.process_state->exit_status())fault=Fault::process_exit;
        // A cooperative child may terminate inside a nested drain and be joined
        // before this caller resumes. Its campaign failure must not terminate
        // the restored parent or turn an opaque DSO value into its exit value.
        if(fault==Fault::thread_exit &&
           (threads.tid()!=owner || threads.tls()!=tls || !threads.exit_value(tls))){
            rejection="__cxa_finalize: nested callback thread exit is not owned by the finalizing caller";
            ++stats.rejected_operations;return Fault::unsupported_service;
        }
        if(fault!=Fault::none){rejection=cxa.rejection();++stats.rejected_operations;}
        return fault;
    }
    Fault yield_operation(a64::ServiceState &state,bool full) noexcept {
        const auto sync=[&](){stats.threads_created=threads.created;stats.threads_started=threads.started;stats.threads_joined=threads.joined;};
        const auto reject=[&](Fault fault,std::string_view reason){sync();rejection=reason;++stats.rejected_operations;return fault;};
        const auto tls=threads.tls();const auto owner=threads.tid();
        try {
            if(app.process_state->exit_status())return reject(Fault::process_exit,"sched_yield: process has terminated");
            if(threads.exit_value(tls))return reject(Fault::thread_exit,"sched_yield: logical thread has terminated");
            const auto fault=threads.yield(full);sync();
            if(app.process_state->exit_status())return reject(Fault::process_exit,"sched_yield: peer terminated the process");
            if(threads.exit_value(tls))return reject(Fault::thread_exit,"sched_yield: caller terminated its logical thread");
            if(threads.tid()!=owner || threads.tls()!=tls)return reject(Fault::unsupported_service,"sched_yield: logical binding was not restored");
            if(fault!=Fault::none)return reject(fault,threads.rejection());
            state.registers[0]=0;return Fault::none;
        }catch(const ThreadExit &exit){threads.request_exit(exit.value);return reject(Fault::thread_exit,"sched_yield: logical thread exited");}
        catch(const ProcessExit &exit){
            if(exit.signal)app.process_state->request_signal(exit.signal);else app.process_state->request_exit(exit.status);
            return reject(Fault::process_exit,"sched_yield: process exited");
        }catch(...){return reject(Fault::windows_service,"sched_yield: owned scheduling failed");}
    }
    Fault phdr_operation(a64::ServiceState &state,bool full) {
        const auto fault=phdr.invoke(state,full);
        if(fault!=Fault::none){rejection=phdr.rejection();++stats.rejected_operations;}
        return fault;
    }
    Fault wide_format_operation(Operation operation,a64::ServiceState &state,bool full) {
        const auto fault=formatting.invoke_wide(operation==Operation::format_wide_list,threads.error_address(),state,full);
        if(fault!=Fault::none){rejection=formatting.rejection();++stats.rejected_operations;}
        else if(state.registers[0]==UINT64_MAX)++stats.errors;
        return fault;
    }
    Fault syslog_operation(Operation operation,a64::ServiceState &state,bool full) {
        const auto fault=logging.invoke_syslog(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::syslog_direct),
                                               state,full,threads.error_address(),descriptors);
        stats.log_messages=logging.messages();
        if(fault!=Fault::none){rejection=logging.rejection();++stats.rejected_operations;}
        return fault;
    }
    Fault jump_operation(Operation operation,a64::ServiceState &state,bool full) {
        const auto fault=jumps.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::jump_save),state,full);
        if(fault!=Fault::none){rejection="setjmp/longjmp: invalid or stale context, cross-invocation jump, or unsupported frame";++stats.rejected_operations;}
        return fault;
    }
    Fault condition_operation(Operation operation,std::array<std::uint64_t,31> &r,bool full,a64::ServiceState *frame=nullptr) {
        const auto fault=conditions.invoke(operation==Operation::cond_timedwait?11:static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::cond_wait),r,full,frame);
        stats.threads_created=threads.created;stats.threads_started=threads.started;stats.threads_joined=threads.joined;
        if(fault!=Fault::none){rejection="pthread condition: unavailable clock/capability, unsupported wait/scheduling/state, nested failure or invalid guest access";++stats.rejected_operations;}
        return fault;
    }
    Address lookup_string(const std::string &text) {
        if(const auto at=lookup_strings.find(text);at!=lookup_strings.end())return at->second;
        if(text.size()>=a64::GuestMemory::page_size || text.find('\0')!=std::string::npos || lookup_strings.size()>=256)
            throw a64::GuestError("AETHER_DLADDR_LIMIT","dladdr metadata exceeds readonly string profile");
        const Address address=0x3c000000ULL+lookup_strings.size()*a64::GuestMemory::page_size;
        auto [at,inserted]=lookup_strings.emplace(text,address);bool owned=false;
        try {
            memory.map(address,a64::GuestMemory::page_size,a64::read_write);owned=true;
            if(!memory.write(address,{reinterpret_cast<const std::uint8_t *>(text.c_str()),text.size()+1}))
                throw a64::GuestError("AETHER_DLADDR_STRING","dladdr string copy failed");
            memory.protect(address,a64::Permission::read);return address;
        } catch(...) {if(owned)unmap(address);lookup_strings.erase(at);throw;}
    }
    std::optional<elf::AddressInfo> shim_address(Address address) const {
        const auto entry=[&](std::string_view module,std::string_view name,Address base,Address start,std::size_t size)->std::optional<elf::AddressInfo>{
            if(address<start || address-start>=size)return {};
            return elf::AddressInfo{std::string(module),std::string(name),base,start};
        };
        if(auto found=entry("libc.so","__sF",trampoline_base,NativeStdio::standard_base,456))return found;
        constexpr std::array<std::string_view,3> standard_names{"stdin","stdout","stderr"};
        for(unsigned i=0;i<3;++i)if(auto found=entry("libc.so",standard_names[i],trampoline_base,NativeStdio::standard_base+512+i*8,8))return found;
        for(std::size_t i=0;i<entries.size();++i)if(auto found=entry("libc.so",entries[i].name,trampoline_base,trampoline_base+i*8,8))return found;
        for(std::size_t i=0;i<extended_entries.size();++i)if(auto found=entry("libc.so",extended_entries[i].name,trampoline_base,extended_trampoline+i*8,8))return found;
        for(std::size_t i=0;i<log_entries.size();++i)if(auto found=entry("liblog.so",log_entries[i],log_trampoline,log_trampoline+i*8,8))return found;
        for(std::size_t i=0;i<cxx_entries.size();++i)if(auto found=entry("libstdc++.so",cxx_entries[i].name,cxx_trampoline,cxx_trampoline+i*8,8))return found;
        for(std::size_t i=0;i<zlib_entries.size();++i)if(auto found=entry("libz.so",zlib_entries[i],zlib_trampoline,zlib_trampoline+i*8,8))return found;
        return entry("libstdc++.so","_ZSt7nothrow",cxx_trampoline,nothrow_address,1);
    }
    Fault address_operation(std::array<std::uint64_t,31> &r) {
        auto found=shim_address(r[0]);
        if(!found){
            if(!address_lookup){rejection="dladdr: owned guest module lookup is unavailable";++stats.rejected_operations;return Fault::unsupported_service;}
            found=address_lookup(r[0]);
        }
        if(!found){r[0]=0;return Fault::none;}
        if(!memory.accessible(r[1],32,a64::Permission::write)){rejection="dladdr: invalid guest Dl_info output";++stats.rejected_operations;return Fault::write;}
        if(found->module.empty() || !found->base || found->base>=a64::GuestMemory::address_limit || found->symbol_address>=a64::GuestMemory::address_limit){
            rejection="dladdr: invalid owned guest address metadata";++stats.rejected_operations;return Fault::unsupported_service;
        }
        std::array<std::uint8_t,32> output{};
        try {
            const auto name=lookup_string(found->module);
            const auto symbol=found->has_symbol?lookup_string(found->symbol):0;
            const std::array<Address,4> fields{name,found->base,symbol,symbol?found->symbol_address:0};
            for(unsigned i=0;i<4;++i){const auto bytes=little<8>(fields[i]);std::copy(bytes.begin(),bytes.end(),output.begin()+i*8);}
        } catch(...) {rejection="dladdr: readonly guest string storage unavailable or limit exceeded";++stats.rejected_operations;return Fault::unsupported_service;}
        if(!memory.write(r[1],output)){rejection="dladdr: guest output write failed";++stats.rejected_operations;return Fault::write;}
        r[0]=1;return Fault::none;
    }
    Fault dispatch(Operation operation, std::array<std::uint64_t, 31> &r,bool full_frame=false) {
        if(operation>=Operation::memory_map && operation<=Operation::memory_protect){
            const auto before=mappings.errors;
            const auto fault=mappings.invoke(static_cast<MappingOperation>(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::memory_map)),threads.error_address(),r);
            stats.errors+=mappings.errors-before;
            if(fault!=Fault::none){rejection=mappings.rejection();++stats.rejected_operations;}
            return fault;
        }
        if(operation==Operation::address_info)return address_operation(r);
        if(operation==Operation::signal_stack){rejection="sigaltstack: trusted live guest frame required";++stats.rejected_operations;return Fault::unsupported_service;}
        if(operation>=Operation::thread_attr_init && operation<=Operation::thread_detach){
            return thread_attributes.invoke(static_cast<ThreadAttributeOperation>(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::thread_attr_init)),r);
        }
        if(operation>=Operation::checked_read && operation<=Operation::checked_read_link_at){
            const bool at=operation==Operation::checked_read_link_at;
            const auto count=r[at?3:2],capacity=r[at?4:3];
            if(count>INT64_MAX || count>capacity){
                static constexpr std::array count_errors{std::string_view{"__read_chk: fortify count exceeds SSIZE_MAX"},std::string_view{"__write_chk: fortify count exceeds SSIZE_MAX"},std::string_view{"__readlink_chk: fortify count exceeds SSIZE_MAX"},std::string_view{"__readlinkat_chk: fortify count exceeds SSIZE_MAX"}};
                static constexpr std::array object_errors{std::string_view{"__read_chk: fortify transfer exceeds buffer object size"},std::string_view{"__write_chk: fortify transfer exceeds buffer object size"},std::string_view{"__readlink_chk: fortify transfer exceeds buffer object size"},std::string_view{"__readlinkat_chk: fortify transfer exceeds buffer object size"}};
                const auto index=static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::checked_read);
                rejection=count>INT64_MAX?count_errors[index]:object_errors[index];
                ++stats.rejected_operations;return Fault::unsupported_service;
            }
            const auto target=operation==Operation::checked_read?Operation::read:operation==Operation::checked_write?Operation::write:at?Operation::file_read_link_at:Operation::file_read_link;
            return dispatch(target,r,full_frame);
        }
        if(operation==Operation::checked_open){
            const auto flags=static_cast<std::uint32_t>(r[1]);
            if((flags&64U) || (flags&0x404000U)==0x404000U){
                rejection="__open_2: fortify violation, O_CREAT/O_TMPFILE requires a mode argument";
                ++stats.rejected_operations;return Fault::unsupported_service;
            }
            r[2]=0;return dispatch(Operation::open,r,full_frame);
        }
        if(operation==Operation::open || operation==Operation::open_at || operation==Operation::checked_open_at || operation==Operation::access_at){
            if(operation==Operation::open && !files)return error(r,guest_eacces); // Preserve the existing capability-before-pointer open contract.
            ++stats.file_operations;
            const auto selected=operation==Operation::open?OpeningOperation::open:operation==Operation::open_at?OpeningOperation::open_at:operation==Operation::checked_open_at?OpeningOperation::checked_open_at:OpeningOperation::access_at;
            const auto fault=opening.invoke(selected,threads.error_address(),r);
            if(fault!=Fault::none){rejection=opening.rejection();++stats.rejected_operations;}else if(r[0]==UINT64_MAX)++stats.errors;
            return fault;
        }
        if(operation>=Operation::file_remove && operation<=Operation::file_remove_directory){
            ++stats.file_operations;
            const auto fault=removing.invoke(static_cast<RemovingOperation>(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::file_remove)),threads.error_address(),r);
            if(fault!=Fault::none){rejection=removing.rejection();++stats.rejected_operations;}else if(r[0]==UINT64_MAX)++stats.errors;
            return fault;
        }
        if(operation>=Operation::file_read_link && operation<=Operation::file_user_id){
            if(operation!=Operation::file_user_id)++stats.file_operations;
            const auto fault=metadata.invoke(static_cast<FileMetadataOperation>(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::file_read_link)),threads.error_address(),r);
            if(fault!=Fault::none){rejection=metadata.rejection();++stats.rejected_operations;}else if(r[0]==UINT64_MAX)++stats.errors;
            return fault;
        }
        if(operation>=Operation::string_copy_end && operation<=Operation::string_find_any){
            const auto selected=static_cast<StringMemoryOperation>(static_cast<unsigned>(StringMemoryOperation::copy_end)+static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::string_copy_end));
            const auto fault=string_memory.invoke(selected,r);
            if(fault!=Fault::none){rejection=string_memory.rejection();++stats.rejected_operations;}return fault;
        }
        if(operation==Operation::string_length_n){
            const auto fault=string_memory.invoke(StringMemoryOperation::length_n,r);
            if(fault!=Fault::none){rejection=string_memory.rejection();++stats.rejected_operations;}return fault;
        }
        if(operation>=Operation::string_checked_copy_bytes && operation<=Operation::string_checked_fill){
            const auto fault=string_memory.invoke(static_cast<StringMemoryOperation>(static_cast<unsigned>(StringMemoryOperation::checked_copy)+static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::string_checked_copy_bytes)),r);
            if(fault!=Fault::none){rejection=string_memory.rejection();++stats.rejected_operations;}return fault;
        }
        if(operation==Operation::string_tokenize || operation==Operation::string_tokenize_reentrant){
            const auto fault=string_memory.invoke(operation==Operation::string_tokenize?StringMemoryOperation::tokenize:StringMemoryOperation::tokenize_reentrant,r);
            if(fault!=Fault::none){rejection=string_memory.rejection();++stats.rejected_operations;}return fault;
        }
        if((operation>=Operation::string_compare && operation<=Operation::string_checked_move) || operation==Operation::string_copy_sized){
            const auto fault=string_memory.invoke(operation==Operation::string_copy_sized?StringMemoryOperation::copy_sized:static_cast<StringMemoryOperation>(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::string_compare)),r);
            if(fault!=Fault::none){rejection=string_memory.rejection();++stats.rejected_operations;}return fault;
        }
        if((operation>=Operation::format_list && operation<=Operation::format_checked_direct) || operation==Operation::format_checked_unbounded_list){a64::ServiceState state;state.registers=r;const auto fault=format_operation(operation,state,false);r=state.registers;return fault;}
        if(operation>=Operation::format_stream_direct && operation<=Operation::format_stdout_list){a64::ServiceState state;state.registers=r;const auto fault=stream_format_operation(operation,state,false);r=state.registers;return fault;}
        if(operation==Operation::format_allocated_list || operation==Operation::format_allocated_direct){a64::ServiceState state;state.registers=r;const auto fault=allocated_format_operation(operation,state,false);r=state.registers;return fault;}
        if(operation==Operation::format_wide_direct || operation==Operation::format_wide_list){a64::ServiceState state;state.registers=r;const auto fault=wide_format_operation(operation,state,false);r=state.registers;return fault;}
        if(operation==Operation::iterate_phdr){a64::ServiceState state;state.registers=r;const auto fault=phdr_operation(state,false);r=state.registers;return fault;}
        if(operation>=Operation::jump_save && operation<=Operation::jump_restore){a64::ServiceState state;state.registers=r;const auto fault=jump_operation(operation,state,false);r=state.registers;return fault;}
        if(operation==Operation::cond_timedwait || (operation>=Operation::cond_wait && operation<=Operation::cond_attr_setclock))return condition_operation(operation,r,false);
        if(operation>=Operation::rw_read && operation<=Operation::rw_attr_getkind){const auto fault=rwlocks.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::rw_read),threads.tid(),r);if(fault!=Fault::none){rejection=rwlocks.rejection();++stats.rejected_operations;}return fault;}
        if(operation>=Operation::mutex_lock && operation<=Operation::attr_getprotocol){const auto fault=mutexes.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::mutex_lock),threads.tid(),r);if(fault!=Fault::none){rejection=mutexes.rejection();++stats.rejected_operations;}return fault;}
        if(operation==Operation::stdio_ungetc)return stdio.invoke(14,threads.error_address(),r);
        if(operation==Operation::stdio_putc)return stdio.invoke(15,threads.error_address(),r);
        if(operation>=Operation::stdio_rewind && operation<=Operation::stdio_tell)return stdio.invoke(11+static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::stdio_rewind),threads.error_address(),r);
        if(operation>=Operation::stdio_open && operation<=Operation::stdio_flush)return stdio.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::stdio_open),threads.error_address(),r);
        if(operation>=Operation::unicode_iswalnum && operation<=Operation::unicode_towupper){
            r[0]=native_unicode(static_cast<UnicodeOperation>(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::unicode_iswalnum)),static_cast<std::uint32_t>(r[0]));return Fault::none;
        }
        if(operation>=Operation::multibyte_mbtowc && operation<=Operation::multibyte_wctomb){
            const auto kind=static_cast<MultibyteOperation>(10U+static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::multibyte_mbtowc));
            const auto fault=multibyte.invoke(kind,r);
            if(fault!=Fault::none){rejection=multibyte.rejection();++stats.rejected_operations;}
            else if(r[0]==UINT64_MAX)++stats.errors;
            return fault;
        }
        if(operation>=Operation::multibyte_wcsnrtombs && operation<=Operation::multibyte_mbsinit){
            const auto fault=multibyte.invoke(static_cast<MultibyteOperation>(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::multibyte_wcsnrtombs)),r);
            if(fault!=Fault::none){rejection=multibyte.rejection();++stats.rejected_operations;}
            else if(r[0]==UINT64_MAX)++stats.errors;
            return fault;
        }
        if(operation>=Operation::character_wide_control && operation<=Operation::character_to_upper){
            r[0]=native_character(static_cast<CharacterOperation>(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::character_wide_control)),static_cast<std::uint32_t>(r[0]));return Fault::none;
        }
        if(operation>=Operation::locale_new && operation<=Operation::locale_width){
            const auto fault=locales.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::locale_new),r);
            if(fault!=Fault::none){rejection=locales.rejection();++stats.rejected_operations;}return fault;
        }
        if(operation==Operation::integer_wide_unsigned || operation==Operation::integer_wide_signed){
            const auto fault=convert_integer(memory,threads.error_address(),operation==Operation::integer_wide_unsigned?0U:1U,r,true);
            if(fault!=Fault::none){rejection="wide integer conversion: guest input/output fault or 1 MiB read-span limit";++stats.rejected_operations;}
            return fault;
        }
        if(operation>=Operation::integer_unsigned && operation<=Operation::integer_atol){const auto fault=convert_integer(memory,threads.error_address(),static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::integer_unsigned),r);if(fault!=Fault::none){rejection="integer conversion: guest input/output fault or 1 MiB scan limit";++stats.rejected_operations;}return fault;}
        switch (operation) {
        case Operation::file_rename:case Operation::file_rename_at:{++stats.file_operations;const auto fault=renaming.invoke(operation==Operation::file_rename_at,threads.error_address(),r);if(fault!=Fault::none){rejection="rename: private namespace marshalling failed; no automatic mutation retry";++stats.rejected_operations;}else if(r[0]==UINT64_MAX)++stats.errors;return fault;}
        case Operation::directory_create:case Operation::directory_create_at:{++stats.file_operations;const auto fault=creating.invoke(operation==Operation::directory_create_at,threads.error_address(),r);if(fault!=Fault::none){rejection="mkdir: private directory marshalling failed; no automatic mutation retry";++stats.rejected_operations;}else if(r[0]==UINT64_MAX)++stats.errors;return fault;}
        case Operation::execute_list_path:{a64::ServiceState state;state.registers=r;const auto fault=execute_operation(state,false);r=state.registers;return fault;}
        case Operation::alarm_timer:r[0]=signals.alarm(static_cast<std::uint32_t>(r[0]));return Fault::none;
        case Operation::thread_exit:threads.request_exit(r[0]);return Fault::thread_exit;
        case Operation::process_abort:{a64::ServiceState state;state.registers=r;const auto fault=abort_operation(state,false);r=state.registers;return fault;}
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
        case Operation::float_single:case Operation::float_double:case Operation::float_long:case Operation::float_wide_single:case Operation::float_wide_double:case Operation::float_wide_long:case Operation::float_atof:rejection="floating conversion requires full S0/D0/Q0 service frame";++stats.rejected_operations;return Fault::unsupported_service;
        case Operation::unicode_iswalnum:case Operation::unicode_iswalpha:case Operation::unicode_iswblank:case Operation::unicode_iswdigit:case Operation::unicode_iswgraph:case Operation::unicode_iswlower:case Operation::unicode_iswprint:case Operation::unicode_iswpunct:case Operation::unicode_iswspace:case Operation::unicode_iswupper:case Operation::unicode_iswxdigit:case Operation::unicode_towlower:case Operation::unicode_towupper:return Fault::unsupported_service;
        case Operation::multibyte_wcsnrtombs:case Operation::multibyte_wcsrtombs:case Operation::multibyte_wcrtomb:case Operation::multibyte_btowc:case Operation::multibyte_wctob:case Operation::multibyte_mbrtowc:case Operation::multibyte_mbrlen:case Operation::multibyte_mbsnrtowcs:case Operation::multibyte_mbsrtowcs:case Operation::multibyte_mbsinit:case Operation::multibyte_mbtowc:case Operation::multibyte_mblen:case Operation::multibyte_wctomb:return Fault::unsupported_service;
        case Operation::thread_once:{a64::ServiceState state;state.registers=r;const auto fault=once_operation(state,false);r=state.registers;return fault;}
        case Operation::scan:case Operation::scan_list:{a64::ServiceState state;state.registers=r;const auto fault=scanning(state,false,operation==Operation::scan_list);r=state.registers;return fault;}
        case Operation::character_wide_control:case Operation::character_alnum:case Operation::character_alpha:case Operation::character_blank:case Operation::character_control:case Operation::character_digit:case Operation::character_graph:case Operation::character_lower:case Operation::character_print:case Operation::character_punct:case Operation::character_space:case Operation::character_upper:case Operation::character_xdigit:case Operation::character_to_lower:case Operation::character_to_upper:return Fault::unsupported_service;
        case Operation::locale_new:case Operation::locale_duplicate:case Operation::locale_free:case Operation::locale_use:case Operation::locale_set:case Operation::locale_conventions:case Operation::locale_width:return Fault::unsupported_service;
        case Operation::integer_unsigned:case Operation::integer_signed:case Operation::integer_atoi:case Operation::integer_atol:case Operation::integer_wide_unsigned:case Operation::integer_wide_signed:return Fault::unsupported_service;
        case Operation::stdio_open:case Operation::stdio_close:case Operation::stdio_read:case Operation::stdio_write:case Operation::stdio_getc:case Operation::stdio_gets:case Operation::stdio_eof:case Operation::stdio_error:case Operation::stdio_clear:case Operation::stdio_fd:case Operation::stdio_flush:case Operation::stdio_ungetc:case Operation::stdio_putc:case Operation::format_wide_direct:case Operation::format_wide_list:case Operation::iterate_phdr:return Fault::unsupported_service;
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
        case Operation::set_abort_message: {
            const auto fault=abort_message.invoke(r);
            if(fault!=Fault::none){rejection=abort_message.rejection();++stats.rejected_operations;}
            return fault;
        }
        case Operation::dynamic_open:case Operation::dynamic_symbol:case Operation::dynamic_close:case Operation::dynamic_error: {
            const auto fault=dynamic_linker.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::dynamic_open),r);
            if(fault!=Fault::none){rejection=dynamic_linker.rejection();++stats.rejected_operations;}
            return fault;
        }
        case Operation::key_create:case Operation::key_delete:case Operation::key_get:case Operation::key_set: {
            const auto fault=specific.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::key_create),threads.tid(),threads.tls(),r);
            if(fault!=Fault::none){rejection="pthread key: invalid guest access or logical owner state";++stats.rejected_operations;}
            return fault;
        }
        case Operation::auxiliary_value:
            // Full-width unsigned-long key. Present zero is success, not absence.
            if(r[0]==16){r[0]=a64::guest_hwcap;return Fault::none;}
            if(r[0]==26){r[0]=a64::guest_hwcap2;return Fault::none;}
            return error(r,2,true); // ENOENT; no invented Linux process pointers/data.
        case Operation::system_information:
            // No Linux system snapshot provider; never fabricate physical/load/swap data.
            return error(r,38);
        case Operation::process_wait:return wait_operation(r,r[0],r[2]);
        case Operation::process_trace:
            // Guest tracing has no backend, parent trace relationship or stop/wait model.
            // Refuse before interpreting request/pid/pointers; never expose host debugging.
            return error(r,38);
        case Operation::process_fork:
            // No guest process cloning backend; never manufacture a child PID.
            return error(r,38);
        case Operation::system_property: {
            const auto fault=get_system_property(memory,r);
            if(fault!=Fault::none){rejection="system property: bounded name or guest output unavailable";++stats.rejected_operations;}
            return fault;
        }
        case Operation::error_description_xsi:case Operation::error_description_gnu: {
            const auto fault=error_strings.invoke_r(operation==Operation::error_description_gnu,r);
            if(fault!=Fault::none){rejection=error_strings.rejection();++stats.rejected_operations;}
            else if(operation==Operation::error_description_xsi && r[0]!=0)++stats.errors;
            return fault;
        }
        case Operation::error_description: {
            const auto fault=error_strings.invoke(r);
            if(fault!=Fault::none){rejection=error_strings.rejection();++stats.rejected_operations;}
            return fault;
        }
        case Operation::thread_set_name:case Operation::thread_get_name:
            return threads.thread_name(r,operation==Operation::thread_set_name);
        case Operation::process_control:
            if(static_cast<std::uint32_t>(r[0])==15 || static_cast<std::uint32_t>(r[0])==16){
                const bool set=static_cast<std::uint32_t>(r[0])==15;
                const auto fault=threads.thread_name(r,set,true);
                return fault!=Fault::none?fault:r[0]?error(r,static_cast<std::uint32_t>(r[0])):Fault::none;
            }
            // Linux prctl specifies EINVAL for controls unavailable on this system.
            // LPAC/job restrictions are not Linux dumpability, Yama or prctl state.
            // Refuse without reading variadic arguments or changing host authority.
            return error(r,22);
        case Operation::thread_signal: {
            a64::ServiceState state;state.registers=r;const auto fault=thread_signal_operation(state,false);r=state.registers;return fault;
        }
        case Operation::schedule_yield: {
            a64::ServiceState state;state.registers=r;const auto fault=yield_operation(state,false);r=state.registers;return fault;
        }
        case Operation::system_call: {
            if(r[0]==124){a64::ServiceState state;state.registers=r;const auto fault=yield_operation(state,false);r=state.registers;return fault;}
            if(r[0]==131){a64::ServiceState state;state.registers=r;const auto fault=thread_signal_operation(state,false,true);r=state.registers;return fault;}
            if(r[0]==260)return wait_operation(r,r[1],r[3]); // arm64 wait4; no child/output access.
            Operation target;
            // Android arm64 asm-generic syscall numbers, using the existing guest providers.
            switch(r[0]){
            case 34:target=Operation::directory_create_at;break;
            case 35:target=Operation::file_unlink_at;break;
            case 38:target=Operation::file_rename_at;break;
            case 48:target=Operation::access_at;break;
            case 56:target=Operation::open_at;break;
            case 132:target=Operation::signal_stack;break;
            case 222:target=Operation::memory_map;break;
            case 215:target=Operation::memory_unmap;break;
            case 226:target=Operation::memory_protect;break;
            case 163:target=Operation::resource_limit;break;
            case 164:target=Operation::resource_set_limit;break;
            case 167:target=Operation::process_control;break;
            case 179:target=Operation::system_information;break;
            case 62:target=Operation::file_descriptor_seek;break;
            case 78:target=Operation::file_read_link_at;break;
            case 80:target=Operation::file_descriptor_stat;break;
            case 174:case 175:case 176:case 177:target=Operation::file_user_id;break;
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
            const bool kernel_access=r[0]==48;
            for(unsigned i=0;i<6;++i)r[i]=r[i+1];
            if(kernel_access)r[3]=0; // faccessat syscall has three arguments.
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
            const auto resource=static_cast<std::uint32_t>(r[0]);
            if(resource>=16)return error(r,guest_einval);
            if(resource!=4 && resource!=7)return error(r,38);
            if(!memory.accessible(r[1],16,a64::Permission::write))return error(r,guest_efault);
            std::array<std::uint8_t,16> limit{};
            if(resource==7){
                const auto soft=little<8>(descriptors.descriptor_soft_limit()),hard=little<8>(descriptors.descriptor_hard_limit());
                std::copy(soft.begin(),soft.end(),limit.begin());std::copy(hard.begin(),hard.end(),limit.begin()+8);
            }
            // CORE remains zero: this guest runtime has no core-file producer.
            if(!memory.write(r[1],limit))return error(r,guest_efault);
            r[0]=0;return Fault::none;
        }
        case Operation::resource_set_limit: {
            // Linux setrlimit copies the complete user input before resource checks.
            std::array<std::uint8_t,16> limit{};
            if(!memory.read(r[1],limit))return error(r,guest_efault);
            const auto resource=static_cast<std::uint32_t>(r[0]);
            if(resource>=16)return error(r,guest_einval);
            std::uint64_t soft=0,hard=0;
            for(unsigned i=0;i<8;++i){soft|=std::uint64_t{limit[i]}<<(8*i);hard|=std::uint64_t{limit[i+8]}<<(8*i);}
            if(soft>hard)return error(r,guest_einval);
            if(resource==4){if(hard)return error(r,1);r[0]=0;return Fault::none;}
            if(resource!=7)return error(r,38);
            if(hard>descriptors.descriptor_hard_limit())return error(r,1);
            if(!descriptors.set_descriptor_limits(soft,hard))return error(r,guest_einval);
            r[0]=0;return Fault::none;
        }
        case Operation::system_configuration: {
            // Android selector numbers are an ABI, independent of the Windows CRT.
            const auto name=static_cast<std::int32_t>(r[0]);
            switch(name){
            case 0x06: r[0]=100;return Fault::none; // Android USER_HZ accounting unit, not host scheduler frequency.
            case 0x0b: r[0]=descriptors.descriptor_soft_limit();return Fault::none;
            case 0x27: case 0x28: r[0]=a64::GuestMemory::page_size;return Fault::none;
            case 0x4c: r[0]=NativeThreadOptions::minimum_stack_size;return Fault::none;
            default: break;
            }
            const bool legacy=name==0x0f || name==0x21 || (name>=0x2a && name<=0x2d);
            if(legacy || name<0 || (name>0x55 && name<0x60) || name>0x9e)return error(r,guest_einval);
            rejection="sysconf: recognized Android query is not implemented";
            ++stats.rejected_operations;return Fault::unsupported_service;
        }
        case Operation::page_size:
            r[0]=a64::GuestMemory::page_size;return Fault::none;
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
        case Operation::finalize: {
            a64::ServiceState state;state.registers=r;
            const auto fault=finalize_cxa_operation(state,false);r=state.registers;return fault;
        }
        case Operation::atexit:return register_cxa_operation(r);
        case Operation::atfork:
            rejection = "__register_atfork: guest fork handlers are unsupported";
            ++stats.rejected_operations;
            return Fault::unsupported_service;
        case Operation::create_thread:
        case Operation::join_thread: {
            NativeThreadOptions options;
            if(operation==Operation::create_thread && r[1]){
                const auto code=thread_attributes.read(r[1],options);
                if(code==14)return Fault::read;if(code){r[0]=code;return Fault::none;}
            }
            const auto fault=operation==Operation::create_thread?threads.create(r,options):threads.join(r);
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
        case Operation::calendar_format:return calendar.strftime(r,threads.error_address());
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
        case Operation::string_compare:
        case Operation::string_compare_n:
        case Operation::string_copy_n:
        case Operation::string_find_char:
        case Operation::string_find_last_char:
        case Operation::string_find_text:
        case Operation::string_compare_bytes:
        case Operation::string_find_byte:
        case Operation::string_find_bytes:
        case Operation::string_checked_length:
        case Operation::string_checked_find_char:
        case Operation::string_checked_find_last_char:
        case Operation::string_checked_copy_n:
        case Operation::string_checked_copy_n_source:
        case Operation::string_checked_move:
            return Fault::unsupported_service;
        case Operation::checked_read:case Operation::checked_write:case Operation::checked_read_link:case Operation::checked_read_link_at:
        case Operation::thread_attr_init:case Operation::thread_attr_destroy:case Operation::thread_attr_setdetach:case Operation::thread_attr_getdetach:case Operation::thread_attr_setstacksize:case Operation::thread_attr_getstacksize:case Operation::thread_attr_setguard:case Operation::thread_attr_getguard:case Operation::thread_attr_getstack:case Operation::thread_getattr:case Operation::thread_detach:return Fault::unsupported_service;
        case Operation::signal_stack:return Fault::unsupported_service;
        case Operation::checked_open:
        case Operation::open_at:case Operation::checked_open_at:case Operation::access_at:
        case Operation::file_remove:case Operation::file_unlink:case Operation::file_unlink_at:case Operation::file_remove_directory:
        case Operation::file_read_link:case Operation::file_read_link_at:case Operation::file_descriptor_stat:case Operation::file_descriptor_seek:case Operation::file_user_id:return Fault::unsupported_service;
        case Operation::heap_information: {
            // Bionic LP64 returns this 80-byte aggregate indirectly through x8.
            // The page allocator retains no free arenas, bins or trim cache.
            std::array<std::uint8_t,80> output{};
            for(const auto [field,value]:std::array{std::pair{4U,stats.allocated_bytes},std::pair{5U,heap_peak},std::pair{7U,stats.allocated_bytes}}){
                const auto encoded=little<8>(value);std::copy(encoded.begin(),encoded.end(),output.begin()+field*8);
            }
            return memory.write(r[8],output)?Fault::none:Fault::write;
        }
        case Operation::collate_compare:case Operation::collate_transform:case Operation::collate_wide_compare:case Operation::collate_wide_transform: {
            const auto fault=collation.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::collate_compare),r);
            if(fault!=Fault::none){rejection=collation.rejection();++stats.rejected_operations;}
            return fault;
        }
        case Operation::wide_copy:case Operation::wide_length:case Operation::wide_move:case Operation::wide_compare:case Operation::wide_find:case Operation::wide_fill: {
            const auto fault=wide_memory.invoke(static_cast<unsigned>(operation)-static_cast<unsigned>(Operation::wide_copy),r);
            if(fault!=Fault::none){rejection=wide_memory.rejection();++stats.rejected_operations;}
            return fault;
        }
        case Operation::allocate_zero: {
            const auto count=r[0],element=r[1];
            if(element && count>UINT64_MAX/element)return error(r,guest_enomem,true);
            r[0]=count*element;
            // New guarded Windows MEM_COMMIT pages are zero-initialized.
            return dispatch(Operation::allocate,r);
        }
        case Operation::resize_allocation: {
            const auto address=r[0],requested=r[1];
            if(!address){r[0]=requested;return dispatch(Operation::allocate,r);}
            const auto old=allocations.find(address);
            if(old==allocations.end()){
                rejection="realloc: address is not a live allocation";++stats.rejected_operations;return Fault::invalid_call;
            }
            if(!requested){const auto fault=dispatch(Operation::release,r);if(fault==Fault::none)r[0]=0;return fault;}
            if(requested>maximum_heap)return error(r,guest_enomem,true);
            if(requested<=old->second.mapped){old->second.requested=static_cast<std::size_t>(requested);return Fault::none;}
            const auto retained=std::min<std::size_t>(old->second.requested,static_cast<std::size_t>(requested));
            std::vector<std::uint8_t> saved(retained);
            if(retained && !memory.read(address,saved))return Fault::read;
            r[0]=requested;const auto allocated=dispatch(Operation::allocate,r);
            if(allocated!=Fault::none || !r[0])return allocated;
            const auto replacement=r[0];
            if(retained && !memory.write(replacement,saved)){
                (void)dispatch(Operation::release,r);r[0]=address;return Fault::write;
            }
            r[0]=address;const auto released=dispatch(Operation::release,r);
            r[0]=replacement;return released;
        }
        case Operation::thread_equal:r[0]=r[0]==r[1]?1:0;return Fault::none;
        case Operation::allocate_posix_aligned: {
            const auto alignment=r[1];
            if(alignment<8 || !std::has_single_bit(alignment)){++stats.errors;r[0]=guest_einval;return Fault::none;}
            const auto result=allocate_heap(r[2],alignment,r[0]);
            if(result.fault!=Fault::none){rejection="posix_memalign: output pointer is not writable";++stats.rejected_operations;return result.fault;}
            if(!result.address)++stats.errors;
            r[0]=result.address?0:guest_enomem;return Fault::none;
        }
        case Operation::allocate_memaligned:
        case Operation::allocate_aligned: {
            auto alignment=r[0];const auto requested=r[1];
            if(operation==Operation::allocate_aligned){
                if(!std::has_single_bit(alignment) || requested%alignment)return error(r,guest_einval,true);
            } else {
                // Bionic memalign accepts zero and rounds nonpowers upward.
                if(!alignment)alignment=1;
                if(alignment>(Address{1}<<63))return error(r,guest_enomem,true);
                alignment=std::bit_ceil(alignment);
            }
            const auto result=allocate_heap(requested,alignment);
            if(result.fault!=Fault::none)return result.fault;
            if(!result.address)return error(r,guest_enomem,true);
            r[0]=result.address;return Fault::none;
        }
        case Operation::allocate: {
            const auto result=allocate_heap(r[0],a64::GuestMemory::page_size);
            if(result.fault!=Fault::none)return result.fault;
            if(!result.address)return error(r,guest_enomem,true);
            r[0]=result.address;return Fault::none;
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
            release_owned_heap(r[0]);
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
            case host::FileError::is_directory:return error(r,21);
            case host::FileError::not_directory:return error(r,20);
            case host::FileError::not_empty:return error(r,39);
            case host::FileError::not_seekable:return error(r,29);
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
    impl_->locales.initialize();
    impl_->descriptors.initialize_standard_streams([p=impl_.get()](int fd,std::span<const std::uint8_t> bytes){return p->logging.write_stream(fd,bytes);});
    impl_->stdio.initialize();
}
GuestPosixServices::~GuestPosixServices() = default;
void GuestPosixServices::set_address_lookup(AddressLookup lookup){impl_->address_lookup=std::move(lookup);}
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
    if(library=="libdl.so" && (version.empty() || version=="LIBC")){
        if(name=="dladdr")return resolve("libc.so",name,version);
        for(std::size_t i=0;i<extended_entries.size();++i)
            if(((extended_entries[i].operation>=Operation::dynamic_open && extended_entries[i].operation<=Operation::dynamic_error) || extended_entries[i].operation==Operation::iterate_phdr) && extended_entries[i].name==name)
                return elf::GuestSymbol{std::string(name),"libdl.so","LIBC",extended_trampoline+i*8,8,2};
        return std::nullopt;
    }
    if (library != "libc.so" || (!version.empty() && version != "LIBC"))
        return std::nullopt;
    if(name=="__sF")return elf::GuestSymbol{std::string(name),"libc.so","LIBC",NativeStdio::standard_base,456,1};
    constexpr std::array<std::string_view,3> standard_names{"stdin","stdout","stderr"};
    for(unsigned i=0;i<3;++i)if(name==standard_names[i])return elf::GuestSymbol{std::string(name),"libc.so","LIBC",NativeStdio::standard_base+512+i*8,8,1};
    for (std::size_t i = 0; i < entries.size(); ++i)
        if (entries[i].name == name)
            return elf::GuestSymbol{std::string(name), "libc.so", "LIBC", trampoline_base + i * 8, 8, 2};
    for(std::size_t i=0;i<extended_entries.size();++i)
        if(extended_entries[i].name==name && !(extended_entries[i].operation>=Operation::dynamic_open && extended_entries[i].operation<=Operation::dynamic_error))return elf::GuestSymbol{std::string(name),"libc.so","LIBC",extended_trampoline+i*8,8,2};
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
        if(*operation>=Operation::syslog_direct && *operation<=Operation::syslog_mask){
            a64::ServiceState state;state.registers=registers;
            const auto fault=p.syslog_operation(*operation,state,false);registers=state.registers;return fault;
        }
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
    if(const auto operation=registered_operation(service,instruction);operation && *operation==Operation::finalize){
        ++p.stats.calls;return p.finalize_cxa_operation(state,true);
    }
    if(const auto operation=registered_operation(service,instruction);operation && (*operation==Operation::schedule_yield || (*operation==Operation::system_call && state.registers[0]==124))){
        ++p.stats.calls;return p.yield_operation(state,true);
    }
    if(const auto operation=registered_operation(service,instruction);operation && *operation>=Operation::syslog_direct && *operation<=Operation::syslog_mask){
        ++p.stats.calls;return p.syslog_operation(*operation,state,true);
    }
    if(const auto operation=registered_operation(service,instruction);operation && *operation>=Operation::float_single && *operation<=Operation::float_atof){
        ++p.stats.calls;
        try{const auto fault=convert_floating(p.memory,p.threads.error_address(),static_cast<unsigned>(*operation)-static_cast<unsigned>(Operation::float_single),state);
            if(fault!=Fault::none){p.rejection="floating conversion: guest access or bounded input failed";++p.stats.rejected_operations;}return fault;
        }catch(...){p.rejection="floating conversion: numeric work limit or marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}
    }
    if(const auto operation=registered_operation(service,instruction);operation && *operation==Operation::thread_once){
        ++p.stats.calls;
        try{return p.once_operation(state,true);}catch(...){p.rejection="pthread_once: callback marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}
    }
    if(const auto operation=registered_operation(service,instruction);operation && (*operation==Operation::thread_signal || (*operation==Operation::system_call && state.registers[0]==131))){
        ++p.stats.calls;
        try{return p.thread_signal_operation(state,true,*operation==Operation::system_call);}
        catch(...){p.rejection="tgkill: logical signal marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}
    }
    if(const auto operation=registered_operation(service,instruction);operation && (*operation==Operation::signal_stack || (*operation==Operation::system_call && state.registers[0]==132))){
        ++p.stats.calls;
        if(*operation==Operation::system_call)for(unsigned i=0;i<6;++i)state.registers[i]=state.registers[i+1];
        try{const auto fault=p.signals.alternate_stack(state,true);if(fault!=Fault::none){p.rejection="sigaltstack: trusted frame or logical signal stack failed";++p.stats.rejected_operations;}else if(state.registers[0]==UINT64_MAX)++p.stats.errors;return fault;}catch(...){p.rejection="sigaltstack: logical signal stack marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}
    }

    if(const auto selected=registered_operation(service,instruction)){
        const auto operation=*selected;
        if(operation==Operation::process_abort){++p.stats.calls;return p.abort_operation(state,true);}
        if(operation==Operation::execute_list_path){++p.stats.calls;return p.execute_operation(state,true);}
        if(operation==Operation::poll_descriptors){
            ++p.stats.calls;
            try{const auto fault=p.polling.invoke(p.threads.error_address(),state.registers,true,&state);
                p.stats.threads_created=p.threads.created;p.stats.threads_started=p.threads.started;p.stats.threads_joined=p.threads.joined;
                if(fault!=Fault::none){p.rejection="poll: signal delivery or nested native work failed";++p.stats.rejected_operations;}
                else if(state.registers[0]==UINT64_MAX)++p.stats.errors;return fault;}
            catch(...){p.rejection="poll: host marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}
        }
        if((operation>=Operation::sleep_seconds && operation<=Operation::sleep_nanos) || (operation==Operation::system_call && state.registers[0]==101)){
            ++p.stats.calls;
            auto sleep=operation;
            if(operation==Operation::system_call){for(unsigned i=0;i<6;++i)state.registers[i]=state.registers[i+1];sleep=Operation::sleep_nanos;}
            try{const auto fault=p.sleeping.invoke(static_cast<unsigned>(sleep)-static_cast<unsigned>(Operation::sleep_seconds),p.threads.error_address(),state.registers,true,&state);
                p.stats.threads_created=p.threads.created;p.stats.threads_started=p.threads.started;p.stats.threads_joined=p.threads.joined;
                if(fault!=Fault::none){p.rejection="native sleep: signal delivery or nested native work failed";++p.stats.rejected_operations;}
                else if(state.registers[0]==UINT64_MAX)++p.stats.errors;return fault;}
            catch(...){p.rejection="native sleep: host marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}
        }
        if(operation==Operation::read || operation==Operation::write || (operation>=Operation::checked_read && operation<=Operation::checked_read_link_at) || operation==Operation::system_call || operation==Operation::poll_descriptors || (operation>=Operation::sleep_seconds && operation<=Operation::sleep_nanos)){
            ++p.stats.calls;try{return p.dispatch(operation,state.registers,true);}catch(...){p.rejection="descriptor: host marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}
        }
        if((operation>=Operation::format_list && operation<=Operation::format_checked_direct) || operation==Operation::format_checked_unbounded_list){++p.stats.calls;return p.format_operation(operation,state,true);}
        if(operation>=Operation::format_stream_direct && operation<=Operation::format_stdout_list){++p.stats.calls;return p.stream_format_operation(operation,state,true);}
        if(operation==Operation::format_allocated_list || operation==Operation::format_allocated_direct){++p.stats.calls;return p.allocated_format_operation(operation,state,true);}
        if(operation==Operation::format_wide_direct || operation==Operation::format_wide_list){++p.stats.calls;return p.wide_format_operation(operation,state,true);}
        if(operation==Operation::iterate_phdr){++p.stats.calls;return p.phdr_operation(state,true);}
        if(operation>=Operation::jump_save && operation<=Operation::jump_restore){
            ++p.stats.calls;try{return p.jump_operation(operation,state,true);}catch(...){p.rejection="setjmp/longjmp: host marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}
        }
        if(operation==Operation::cond_wait || operation==Operation::cond_timedwait){
            ++p.stats.calls;try{return p.condition_operation(operation,state.registers,true,&state);}catch(...){p.rejection="pthread condition: host marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}
        }
        if(operation==Operation::pthread_mask || operation==Operation::process_mask || (operation>=Operation::signal_handler && operation<=Operation::signal_wait)){
            ++p.stats.calls;try{return operation==Operation::pthread_mask || operation==Operation::process_mask?p.mask_operation(operation,state,true):p.signal_operation(operation,state,true);}catch(...){p.rejection="signal: host marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}
        }
    }
    if(service>=log_service && service-log_service<log_entries.size() && instruction==log_trampoline+(service-log_service)*8) {
        ++p.stats.calls;const auto fault=p.logging.invoke(log_entries[service-log_service],state,true);
        p.stats.log_messages=p.logging.messages();if(fault!=Fault::none){p.rejection=p.logging.rejection();++p.stats.rejected_operations;}return fault;
    }
    if(const auto operation=registered_operation(service,instruction);operation && *operation==Operation::thread_getattr){
        ++p.stats.calls;return p.thread_attributes.invoke(ThreadAttributeOperation::get_current,state.registers,&state);
    }
    if(const auto operation=registered_operation(service,instruction);operation && (*operation==Operation::scan || *operation==Operation::scan_list)){
        ++p.stats.calls;try{return p.scanning(state,true,*operation==Operation::scan_list);}catch(...){p.rejection="scanf: host marshalling failure";++p.stats.rejected_operations;return Fault::unsupported_service;}
    }
    return invoke(service,instruction,state.registers);
}
bool GuestPosixServices::event_pending() noexcept {
    try{return impl_->signals.terminated() || impl_->signals.ready();}catch(...){return true;}
}
a64::Fault GuestPosixServices::checkpoint(a64::ServiceState &state) noexcept {
    auto &p=*impl_;
    if(p.app.process_state->exit_status())return Fault::process_exit;
    try{return p.signals.deliver_pending(state,true);}
    catch(...){p.rejection="signal checkpoint: host marshalling failed";++p.stats.rejected_operations;return Fault::unsupported_service;}
}
std::optional<GuestPosixServices::ThreadBinding> GuestPosixServices::exchange_thread_binding(std::optional<ThreadBinding> value){return impl_->threads.exchange_binding(value);}
std::uint64_t GuestPosixServices::signal_mask(){return impl_->threads.signal_mask();}
std::uint64_t GuestPosixServices::binding_signal_mask(const ThreadBinding &binding){return impl_->threads.binding_signal_mask(binding);}
void GuestPosixServices::set_signal_runner(SignalRunner runner){impl_->signals.runner(std::move(runner));}
void GuestPosixServices::set_once_runner(OnceRunner runner){impl_->once.runner(std::move(runner));}
void GuestPosixServices::set_program_header_lookup(ProgramHeaderLookup lookup){impl_->phdr.provider(std::move(lookup));}
void GuestPosixServices::set_phdr_runner(PhdrRunner runner){impl_->phdr.runner(std::move(runner));}
void GuestPosixServices::set_cxa_runner(CxaRunner runner){impl_->cxa.runner(std::move(runner));}
a64::Fault GuestPosixServices::finalize_cxa(a64::ServiceState &state) noexcept {++impl_->stats.calls;return impl_->finalize_cxa_operation(state,true);}
void GuestPosixServices::set_managed_priority_service(int baseline,host::PriorityService service){impl_->threads.managed_priority(baseline,std::move(service));}
host::PriorityResult GuestPosixServices::current_thread_priority(std::optional<std::int32_t> nice){return impl_->threads.priority(0,0,nice);}
std::optional<std::uint64_t> GuestPosixServices::thread_exit_value(Address tls) const noexcept {return impl_->threads.exit_value(tls);}
void GuestPosixServices::request_thread_exit(std::uint64_t value) noexcept {impl_->threads.request_exit(value);}
GuestPosixServices::ThreadExecution GuestPosixServices::finish_current_thread(const DestructorRunner &runner,std::uint64_t budget) {
    auto &p=*impl_;
    if(const auto status=p.app.process_state->exit_status()){
        ThreadExecution out;out.result.fault=Fault::process_exit;out.result.detail=*status;out.finalization_failed=true;return out;
    }
    p.threads.begin_finalization();
    struct End {NativeThreads &threads;~End(){threads.end_finalization();}} end{p.threads};
    const auto checked=[&](Address entry,Address value,std::uint64_t remaining){
        p.app.process_state->checkpoint();
        return runner(entry,value,remaining);
    };
    try {
        auto out=p.specific.finalize(p.threads.tid(),p.threads.tls(),checked,budget);
        out.finalization_failed=out.result.fault!=Fault::none || !out.result.returned;
        if(out.finalization_failed){p.rejection="pthread key destructor: guest finalization failed";++p.stats.rejected_operations;}
        return out;
    }catch(const ProcessExit &exit){p.app.process_state->request_exit(exit.status);throw;}
    catch(const ThreadExit &exit){p.threads.request_exit(exit.value);throw;}
}
void GuestPosixServices::discard_thread(std::uint32_t id,Address tls) noexcept {impl_->threads.retire(id,tls);}
void GuestPosixServices::set_thread_runner(ThreadRunner runner){impl_->threads.runner(std::move(runner));}
a64::Address GuestPosixServices::thread_pointer()const noexcept{return impl_->threads.tls();}
bool GuestPosixServices::is_main_native_thread()const noexcept{return impl_->threads.tid()==impl_->tid;}
a64::Fault GuestPosixServices::run_pending_threads(std::uint64_t budget) noexcept {
    auto &p=*impl_;if(p.app.process_state->exit_status())return Fault::process_exit;try {
        const auto fault=p.threads.pump(budget);p.stats.threads_created=p.threads.created;p.stats.threads_started=p.threads.started;p.stats.threads_joined=p.threads.joined;
        if(fault!=Fault::none){p.rejection=p.threads.rejection();++p.stats.rejected_operations;}return fault;
    }catch(...){p.rejection="Native thread pump failed";return a64::Fault::windows_service;}
}
const ServiceMetrics &GuestPosixServices::metrics() const noexcept { impl_->stats.log_messages=impl_->logging.messages();return impl_->stats; }
std::string_view GuestPosixServices::last_rejection() const noexcept { return impl_->rejection; }
} // namespace aether::bionic

namespace aether::bionic {
void GuestPosixServices::set_dynamic_linker(DynamicLinkCallbacks callbacks){impl_->dynamic_linker.callbacks(std::move(callbacks));}
}
