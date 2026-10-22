#include "aether/host/regex.hpp"
#include <Windows.h>
#include <icu.h>
#include <algorithm>
#include <atomic>
#include <bit>
#include <chrono>
namespace aether::host {
namespace {
std::atomic_size_t live_patterns=0,live_matchers=0;
struct Api {
    HMODULE module=nullptr;
#define AETHER_ICU(name) decltype(&name) name=nullptr
    AETHER_ICU(u_getVersion);
    AETHER_ICU(uregex_open);AETHER_ICU(uregex_close);AETHER_ICU(uregex_clone);
    AETHER_ICU(uregex_setText);AETHER_ICU(uregex_matches);AETHER_ICU(uregex_find);AETHER_ICU(uregex_findNext);
    AETHER_ICU(uregex_start);AETHER_ICU(uregex_end);AETHER_ICU(uregex_groupCount);
    AETHER_ICU(uregex_setTimeLimit);AETHER_ICU(uregex_setStackLimit);
    AETHER_ICU(uregex_setMatchCallback);AETHER_ICU(uregex_setFindProgressCallback);
#undef AETHER_ICU
    Api() {
        module=LoadLibraryExW(L"icu.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
        if(!module)throw RegexError(RegexError::Kind::backend,"Windows system ICU is unavailable");
        try {
#define AETHER_ICU(name) name=std::bit_cast<decltype(name)>(GetProcAddress(module,#name));if(!name)throw RegexError(RegexError::Kind::backend,"Windows system ICU export is unavailable: " #name)
            AETHER_ICU(u_getVersion);
            AETHER_ICU(uregex_open);AETHER_ICU(uregex_close);AETHER_ICU(uregex_clone);
            AETHER_ICU(uregex_setText);AETHER_ICU(uregex_matches);AETHER_ICU(uregex_find);AETHER_ICU(uregex_findNext);
            AETHER_ICU(uregex_start);AETHER_ICU(uregex_end);AETHER_ICU(uregex_groupCount);
            AETHER_ICU(uregex_setTimeLimit);AETHER_ICU(uregex_setStackLimit);
            AETHER_ICU(uregex_setMatchCallback);AETHER_ICU(uregex_setFindProgressCallback);
#undef AETHER_ICU
        } catch(...) {FreeLibrary(module);module=nullptr;throw;}
    }
    ~Api(){if(module)FreeLibrary(module);}
};
Api &api(){static Api value;return value;}
void check(UErrorCode status) {
    if(U_SUCCESS(status))return;
    if(status==U_REGEX_TIME_OUT || status==U_REGEX_STACK_OVERFLOW || status==U_REGEX_STOPPED_BY_CALLER || status==U_MEMORY_ALLOCATION_ERROR || status==U_REGEX_PATTERN_TOO_BIG)
        throw RegexError(RegexError::Kind::limit,"ICU regex resource limit reached");
    throw RegexError(RegexError::Kind::backend,"ICU regex operation failed: "+std::to_string(static_cast<int>(status)));
}
struct Handle {
    URegularExpression *value=nullptr;
    ~Handle(){if(value)api().uregex_close(value);}
};
struct Deadline {std::chrono::steady_clock::time_point end;};
UBool U_CALLCONV progress(const void *context,int32_t) noexcept {
    return std::chrono::steady_clock::now()<static_cast<const Deadline*>(context)->end;
}
UBool U_CALLCONV find_progress(const void *context,int64_t) noexcept {return progress(context,0);}
void limits(URegularExpression *value) {
    UErrorCode status=U_ZERO_ERROR;api().uregex_setTimeLimit(value,1000,&status);
    api().uregex_setStackLimit(value,256*1024,&status);check(status);
}
struct Operation {
    URegularExpression *handle;Deadline deadline{std::chrono::steady_clock::now()+std::chrono::milliseconds(50)};
    explicit Operation(URegularExpression *value):handle(value) {
        UErrorCode status=U_ZERO_ERROR;api().uregex_setMatchCallback(handle,progress,&deadline,&status);
        api().uregex_setFindProgressCallback(handle,find_progress,&deadline,&status);
        if(U_FAILURE(status)) {clear();check(status);}
    }
    void clear() noexcept {UErrorCode status=U_ZERO_ERROR;api().uregex_setMatchCallback(handle,nullptr,nullptr,&status);status=U_ZERO_ERROR;api().uregex_setFindProgressCallback(handle,nullptr,nullptr,&status);}
    ~Operation(){clear();}
};
}
struct RegexPattern::State {Handle handle;};
struct RegexMatcher::State {
    // Own storage before the handle so closing the ICU borrower precedes release.
    std::unique_ptr<char16_t[]> text;std::size_t length=0;Handle handle;
};
RegexPattern::RegexPattern(std::unique_ptr<State> state):state_(std::move(state)){++live_patterns;}
RegexPattern::~RegexPattern(){--live_patterns;}
RegexMatcher::RegexMatcher(std::unique_ptr<State> state):state_(std::move(state)){++live_matchers;}
RegexMatcher::~RegexMatcher(){--live_matchers;}
std::unique_ptr<RegexPattern> RegexPattern::compile(std::u16string_view pattern,std::uint32_t flags,bool literal) {
    if(pattern.size()>4096)throw RegexError(RegexError::Kind::limit,"Pattern exceeds 4096 UTF16 units");
    // Literal quoting expands at most 4*n+4 units (16388 at the source bound).
    std::u16string quoted;
    if(literal) {
        quoted=u"\\Q";
        for(std::size_t n=0;n<pattern.size();++n) {
            if(pattern[n]==u'\\' && n+1<pattern.size() && pattern[n+1]==u'E'){quoted+=u"\\E\\\\E\\Q";++n;}
            else quoted.push_back(pattern[n]);
        }
        quoted+=u"\\E";pattern=quoted;
    }
    // ICU's C entry point refuses patternLength==0, although an empty Java
    // pattern is a valid zero-width expression. Preserve the managed source
    // and compile an equivalent empty noncapturing group at this boundary.
    if(pattern.empty())pattern=u"(?:)";
    auto state=std::make_unique<State>();UErrorCode status=U_ZERO_ERROR;UParseError parse{};
    state->handle.value=api().uregex_open(pattern.data(),static_cast<int32_t>(pattern.size()),flags,&parse,&status);
    if(U_FAILURE(status)) {
        if(status>U_REGEX_ERROR_START && status<=U_REGEX_INVALID_CAPTURE_GROUP_NAME &&
            status!=U_REGEX_INVALID_STATE && status!=U_REGEX_UNIMPLEMENTED && status!=U_REGEX_INVALID_FLAG &&
            status!=U_REGEX_STACK_OVERFLOW && status!=U_REGEX_TIME_OUT && status!=U_REGEX_STOPPED_BY_CALLER && status!=U_REGEX_PATTERN_TOO_BIG)
            throw RegexError(RegexError::Kind::syntax,"Invalid regular expression (ICU "+std::to_string(static_cast<int>(status))+")",parse.offset);
        check(status);
    }
    if(!state->handle.value)throw RegexError(RegexError::Kind::backend,"ICU returned no compiled expression");
    limits(state->handle.value);
    const auto groups=api().uregex_groupCount(state->handle.value,&status);check(status);
    if(groups>128)throw RegexError(RegexError::Kind::limit,"Regex exceeds 128 capturing groups");
    return std::unique_ptr<RegexPattern>(new RegexPattern(std::move(state)));
}
std::unique_ptr<RegexMatcher> RegexPattern::matcher(std::u16string_view input) const {
    if(input.size()>65536)throw RegexError(RegexError::Kind::limit,"Input exceeds 65536 UTF16 units");
    auto state=std::make_unique<RegexMatcher::State>();
    state->text=std::make_unique<char16_t[]>(input.size()+1);state->length=input.size();std::copy(input.begin(),input.end(),state->text.get());
    UErrorCode status=U_ZERO_ERROR;state->handle.value=api().uregex_clone(state_->handle.value,&status);check(status);
    if(!state->handle.value)throw RegexError(RegexError::Kind::backend,"ICU returned no matcher");
    limits(state->handle.value);api().uregex_setText(state->handle.value,state->text.get(),static_cast<int32_t>(input.size()),&status);check(status);
    return std::unique_ptr<RegexMatcher>(new RegexMatcher(std::move(state)));
}
bool RegexMatcher::matches(){Operation operation(state_->handle.value);UErrorCode status=U_ZERO_ERROR;const auto result=api().uregex_matches(state_->handle.value,-1,&status);check(status);if(std::chrono::steady_clock::now()>=operation.deadline.end)throw RegexError(RegexError::Kind::limit,"Regex operation exceeded its deadline");return result!=0;}
bool RegexMatcher::find(std::int32_t start) {Operation operation(state_->handle.value);UErrorCode status=U_ZERO_ERROR;const auto result=start<0?api().uregex_findNext(state_->handle.value,&status):api().uregex_find(state_->handle.value,start,&status);check(status);if(std::chrono::steady_clock::now()>=operation.deadline.end)throw RegexError(RegexError::Kind::limit,"Regex operation exceeded its deadline");return result!=0;}
std::int32_t RegexMatcher::start(std::int32_t group) const {UErrorCode status=U_ZERO_ERROR;const auto result=api().uregex_start(state_->handle.value,group,&status);check(status);return result;}
std::int32_t RegexMatcher::end(std::int32_t group) const {UErrorCode status=U_ZERO_ERROR;const auto result=api().uregex_end(state_->handle.value,group,&status);check(status);return result;}
std::int32_t RegexMatcher::groups() const {UErrorCode status=U_ZERO_ERROR;const auto result=api().uregex_groupCount(state_->handle.value,&status);check(status);return result;}
void RegexMatcher::reset(std::u16string_view input) {
    if(input.size()>65536)throw RegexError(RegexError::Kind::limit,"Input exceeds 65536 UTF16 units");
    auto next=std::make_unique<State>();next->text=std::make_unique<char16_t[]>(input.size()+1);next->length=input.size();std::copy(input.begin(),input.end(),next->text.get());
    UErrorCode status=U_ZERO_ERROR;next->handle.value=api().uregex_clone(state_->handle.value,&status);check(status);
    if(!next->handle.value)throw RegexError(RegexError::Kind::backend,"ICU returned no reset matcher");
    limits(next->handle.value);api().uregex_setText(next->handle.value,next->text.get(),static_cast<int32_t>(input.size()),&status);check(status);
    state_.swap(next);
}
std::u16string_view RegexMatcher::input() const noexcept{return {state_->text.get(),state_->length};}
std::size_t RegexMatcher::storage_bytes() const noexcept{return (state_->length+1)*sizeof(char16_t);}
RegexBackendInfo regex_backend_info(){RegexBackendInfo result;api().u_getVersion(result.version.data());result.live_patterns=live_patterns.load();result.live_matchers=live_matchers.load();return result;}
}
