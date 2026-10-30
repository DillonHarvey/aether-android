#include "aether/security/worker_progress.hpp"
#include "aether/security/worker.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include <aclapi.h>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <sddl.h>
#include <thread>
#include <userenv.h>

namespace aether::security {
namespace {
using host::UniqueHandle;
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(std::string("AETHER_WORKER: ") + message +
                            "; Windows error=" + std::to_string(GetLastError()));
}
struct LocalOwner {
    void *value = nullptr;
    ~LocalOwner() { LocalFree(value); }
};
struct SidOwner {
    PSID value = nullptr;
    ~SidOwner() {
        if (value)
            FreeSid(value);
    }
};
// Fixed renderer authority, never selected by a caller or a guest capability request.
std::vector<std::uint8_t> graphics_registry_read_sid() {
    struct Arrays {
        PSID *groups = nullptr, *capabilities = nullptr;
        DWORD group_count = 0, capability_count = 0;
        ~Arrays() {
            for (DWORD i = 0; i < group_count; ++i)
                LocalFree(groups[i]);
            for (DWORD i = 0; i < capability_count; ++i)
                LocalFree(capabilities[i]);
            LocalFree(groups);
            LocalFree(capabilities);
        }
    } data;
    require(DeriveCapabilitySidsFromName(L"registryRead", &data.groups, &data.group_count, &data.capabilities,
                                         &data.capability_count) &&
                data.capability_count == 1 && data.capabilities && IsValidSid(data.capabilities[0]),
            "Cannot derive fixed renderer registryRead capability");
    const auto length = GetLengthSid(data.capabilities[0]);
    require(length <= SECURITY_MAX_SID_SIZE, "Renderer capability SID exceeds Windows bound");
    std::vector<std::uint8_t> sid(length);
    require(CopySid(length, sid.data(), data.capabilities[0]), "Cannot retain renderer capability SID");
    return sid;
}
std::vector<std::uint8_t> token_info(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
    DWORD size = 0;
    GetTokenInformation(token, kind, nullptr, 0, &size);
    require(size && size <= 65536, "Cannot size token information");
    std::vector<std::uint8_t> bytes(size);
    require(GetTokenInformation(token, kind, bytes.data(), size, &size) != FALSE,
            "Cannot read token information");
    return bytes;
}
class Attributes final {
  public:
    explicit Attributes(DWORD count) {
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(nullptr, count, 0, &size);
        require(size != 0, "Cannot size process attributes");
        data_.resize(size);
        list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(data_.data());
        require(InitializeProcThreadAttributeList(list, count, 0, &size) != FALSE,
                "Cannot initialize process attributes");
    }
    ~Attributes() { DeleteProcThreadAttributeList(list); }
    void set(DWORD_PTR kind, void *value, SIZE_T size) {
        require(UpdateProcThreadAttribute(list, 0, kind, value, size, nullptr, nullptr) != FALSE,
                "Cannot set process attribute");
    }
    LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr;

  private:
    std::vector<std::uint8_t> data_;
};
void read_exact(HANDLE reader, std::span<std::uint8_t> bytes) {
    while (!bytes.empty()) {
        DWORD count = 0;
        require(ReadFile(reader, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) && count,
                "Worker pipe closed or read failed");
        bytes = bytes.subspan(count);
    }
}
} // namespace
AwakeDeadlineClock::time_point AwakeDeadlineClock::now() noexcept {
    ULONGLONG ticks = 0;
    QueryUnbiasedInterruptTimePrecise(&ticks);
    return time_point{duration{static_cast<rep>(ticks)}};
}
void verify_appcontainer_identity(HANDLE process, PSID expected_sid, std::optional<bool> less_privileged,
                                  std::span<PSID const> expected_capabilities) {
    HANDLE raw = nullptr;
    require(OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &raw) != FALSE,
            "Cannot open worker token");
    UniqueHandle token(raw);
    const auto container = token_info(token.get(), TokenIsAppContainer);
    require(*reinterpret_cast<const DWORD *>(container.data()) == 1, "Worker is not an AppContainer");
    const auto capabilities = token_info(token.get(), TokenCapabilities);
    const auto actual_capabilities = reinterpret_cast<const TOKEN_GROUPS *>(capabilities.data());
    require(expected_capabilities.size() <= 16 &&
                actual_capabilities->GroupCount == expected_capabilities.size(),
            "Worker has unexpected Windows capability count");
    for (std::size_t i = 0; i < expected_capabilities.size(); ++i) {
        require(expected_capabilities[i] && IsValidSid(expected_capabilities[i]),
                "Invalid expected capability identity");
        for (std::size_t j = 0; j < i; ++j)
            require(!EqualSid(expected_capabilities[i], expected_capabilities[j]),
                    "Duplicate expected capability identity");
        unsigned matches = 0;
        for (DWORD j = 0; j < actual_capabilities->GroupCount; ++j) {
            const auto &actual = actual_capabilities->Groups[j];
            require(IsValidSid(actual.Sid) && actual.Attributes == SE_GROUP_ENABLED,
                    "Worker capability attributes differ from launch policy");
            matches += EqualSid(expected_capabilities[i], actual.Sid) ? 1 : 0;
        }
        require(matches == 1, "Worker Windows capability identity differs from launch policy");
    }
    const auto integrity = token_info(token.get(), TokenIntegrityLevel);
    const auto level = reinterpret_cast<const TOKEN_MANDATORY_LABEL *>(integrity.data())->Label.Sid;
    require(IsValidSid(level) && *GetSidSubAuthorityCount(level) > 0 &&
                *GetSidSubAuthority(level, *GetSidSubAuthorityCount(level) - 1) == SECURITY_MANDATORY_LOW_RID,
            "Worker is not low integrity");
    if (expected_sid) {
        const auto identity = token_info(token.get(), TokenAppContainerSid);
        require(
            EqualSid(
                expected_sid,
                reinterpret_cast<const TOKEN_APPCONTAINER_INFORMATION *>(identity.data())->TokenAppContainer),
            "Worker identity differs from parent policy");
    }
    if (less_privileged) {
        // TokenIsLessPrivilegedAppContainer is present in the SDK but GetTokenInformation
        // rejects it on this host. Verify its security consequence with AccessCheck,
        // using an in-memory descriptor granting the user pass and package pass.
        // Merely checking group membership does not model the AppContainer access check.
        LocalOwner descriptor;
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    L"O:SYG:SYD:(A;;FR;;;WD)(A;;FR;;;AC)", SDDL_REVISION_1,
                    reinterpret_cast<PSECURITY_DESCRIPTOR *>(&descriptor.value), nullptr),
                "Cannot create LPAC access-check descriptor");
        HANDLE duplicate_raw = nullptr;
        require(DuplicateTokenEx(token.get(), TOKEN_QUERY, nullptr, SecurityIdentification,
                                 TokenImpersonation, &duplicate_raw),
                "Cannot inspect worker access policy");
        UniqueHandle duplicate(duplicate_raw);
        GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
        PRIVILEGE_SET privileges{};
        DWORD privilege_size = sizeof(privileges), granted = 0;
        BOOL access = FALSE;
        require(AccessCheck(descriptor.value, duplicate.get(), FILE_READ_DATA, &mapping, &privileges,
                            &privilege_size, &granted, &access),
                "Cannot verify worker package access");
        require((access == FALSE) == *less_privileged && (access == FALSE || (granted & FILE_READ_DATA) != 0),
                "Worker LPAC policy differs from parent policy");
    }
}
void verify_isolated_process(HANDLE process, PSID expected_sid, std::optional<bool> less_privileged) {
    verify_appcontainer_identity(process, expected_sid, less_privileged);
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamic{};
    require(GetProcessMitigationPolicy(process, ProcessDynamicCodePolicy, &dynamic, sizeof(dynamic)) &&
                !dynamic.ProhibitDynamicCode && !dynamic.AllowThreadOptOut && !dynamic.AllowRemoteDowngrade,
            "Worker JIT policy differs from parent policy");
}
void verify_graphics_process(HANDLE process, PSID expected_sid) {
    auto registry_read = graphics_registry_read_sid();
    const std::array<PSID, 1> capabilities{registry_read.data()};
    verify_appcontainer_identity(process, expected_sid, true, capabilities);
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamic{};
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensions{};
    require(GetProcessMitigationPolicy(process, ProcessDynamicCodePolicy, &dynamic, sizeof(dynamic)) &&
                dynamic.ProhibitDynamicCode && !dynamic.AllowThreadOptOut && !dynamic.AllowRemoteDowngrade &&
                !dynamic.AuditProhibitDynamicCode &&
                GetProcessMitigationPolicy(process, ProcessExtensionPointDisablePolicy, &extensions,
                                           sizeof(extensions)) &&
                extensions.DisableExtensionPoints,
            "Graphics service mitigation policy differs from parent policy");
}
void verify_metadata_process(HANDLE process, PSID expected_sid) {
    verify_appcontainer_identity(process, expected_sid, true); // No registryRead or other capabilities.
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamic{};
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensions{};
    require(GetProcessMitigationPolicy(process, ProcessDynamicCodePolicy, &dynamic, sizeof(dynamic)) &&
                dynamic.ProhibitDynamicCode && !dynamic.AllowThreadOptOut && !dynamic.AllowRemoteDowngrade &&
                !dynamic.AuditProhibitDynamicCode &&
                GetProcessMitigationPolicy(process, ProcessExtensionPointDisablePolicy, &extensions,
                                           sizeof(extensions)) &&
                extensions.DisableExtensionPoints,
            "Metadata service mitigation policy differs from parent policy");
}
struct PipeFramePoller::Impl {
    HANDLE reader;
    const std::thread::id owner = std::this_thread::get_id();
    const std::chrono::milliseconds timeout;
    std::optional<AwakeDeadlineClock::time_point> deadline;
    bool broken = false;
    Impl(HANDLE handle, std::chrono::milliseconds bound) : reader(handle), timeout(bound) {
        if (!reader || reader == INVALID_HANDLE_VALUE || timeout.count() <= 0 || timeout > std::chrono::seconds(30) ||
            GetFileType(reader) != FILE_TYPE_PIPE || !PeekNamedPipe(reader, nullptr, 0, nullptr, nullptr, nullptr))
            throw ProtocolError("AETHER_IPC_POLL: invalid borrowed pipe reader or timeout");
    }
    void check() const {
        if (std::this_thread::get_id() != owner)
            throw ProtocolError("AETHER_IPC_POLL: pipe belongs to another thread");
        if (broken) throw ProtocolError("AETHER_IPC_POLL: channel is closed");
    }
};
PipeFramePoller::PipeFramePoller(HANDLE reader, std::chrono::milliseconds timeout)
    : impl_(std::make_unique<Impl>(reader, timeout)) {}
PipeFramePoller::~PipeFramePoller() = default;
std::optional<Frame> PipeFramePoller::poll() {
    auto &p = *impl_;p.check();
    try {
        DWORD available = 0, copied = 0;
        std::array<std::uint8_t, header_bytes> prefix{};
        if (!PeekNamedPipe(p.reader, prefix.data(), static_cast<DWORD>(prefix.size()), &copied, &available, nullptr))
            throw ProtocolError("AETHER_IPC_POLL: peer closed or pipe peek failed");
        const auto now = AwakeDeadlineClock::now();
        if (available && !p.deadline) p.deadline = now + p.timeout;
        if (p.deadline && now >= *p.deadline)
            throw ProtocolError("AETHER_IPC_POLL: absolute partial-frame deadline expired");
        if (copied < header_bytes) return {};
        const auto header = decode_header(prefix); // Bounds payload before allocation or consumption.
        if (available < header_bytes + header.payload_size) return {};
        auto result = read_pipe_frame(p.reader);
        if (p.deadline && AwakeDeadlineClock::now() >= *p.deadline)
            throw ProtocolError("AETHER_IPC_POLL: full frame completed after its absolute deadline");
        p.deadline.reset();
        return result;
    } catch (...) { p.broken = true; throw; }
}
void PipeFramePoller::reset() { impl_->check();impl_->deadline.reset(); }
std::optional<AwakeDeadlineClock::time_point> PipeFramePoller::partial_deadline() const {
    impl_->check();return impl_->deadline;
}
Frame read_pipe_frame(HANDLE reader) {
    std::array<std::uint8_t, header_bytes> bytes{};
    read_exact(reader, bytes);
    const auto header = decode_header(bytes); // Bound the allocation first.
    Frame frame{header, std::vector<std::uint8_t>(header.payload_size)};
    read_exact(reader, frame.payload);
    return frame;
}
void write_pipe_frame(HANDLE writer, const Frame &frame) {
    const auto bytes = encode_frame(frame);
    DWORD count = 0;
    require(WriteFile(writer, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) &&
                count == bytes.size(),
            "Worker pipe write failed");
}
bool write_worker_allocation_failure(HANDLE writer, std::uint64_t session) noexcept {
    if(!writer || writer==INVALID_HANDLE_VALUE || !session)return false;
    try {
        constexpr char message[]="AETHER_WORKER_ALLOCATION_FAILED: std::bad_alloc";
        constexpr auto payload_size=sizeof(message)-1;
        const auto header=encode_header({Operation::finished,0,session,
                                         static_cast<std::uint32_t>(payload_size),Status::invalid});
        std::array<std::uint8_t,header_bytes+payload_size> bytes{};
        for(std::size_t i=0;i<header.size();++i)bytes[i]=header[i];
        for(std::size_t i=0;i<payload_size;++i)bytes[header_bytes+i]=static_cast<std::uint8_t>(message[i]);
        std::size_t written=0;
        while(written<bytes.size()){
            const auto remaining=static_cast<DWORD>(bytes.size()-written);
            DWORD count=0;
            if(!WriteFile(writer,bytes.data()+written,remaining,&count,nullptr) || !count || count>remaining)return false;
            // Retry only an accepted positive prefix, never a failed write.
            written+=count;
        }
        return true;
    }catch(...){return false;}
}
struct WorkerProcess::Impl {
    WorkerRole role = WorkerRole::guest;
    UniqueHandle job, process, reader, writer, primary_thread;
    std::unique_ptr<PipeFramePoller> poller;
    std::unique_ptr<WorkerImage> image;
    WorkerImageAccess image_permissions;
    std::jthread watchdog;
    std::atomic<bool> expired = false;
    DWORD pid = 0;
    std::uint64_t start_uptime_ticks = 0;
    std::uint32_t sent = 0, received = 0;
    std::mutex deadline_mutex;
    std::condition_variable deadline_changed;
    AwakeDeadlineClock::time_point deadline;
    std::uint32_t timeout_ms = 0;
    bool exchange_deadlines = false, armed = true, stopping = false;
    void stop_watchdog() {
        {
            std::lock_guard lock(deadline_mutex);
            stopping = true;
        }
        deadline_changed.notify_all();
    }
    void check_exchange() {
        (void)poller->partial_deadline(); // Validate the channel owner before any blocking I/O.
        if (exchange_deadlines) {
            std::lock_guard lock(deadline_mutex);
            require(armed && !stopping && !expired && AwakeDeadlineClock::now() < deadline,
                    "I/O requires an active unexpired trusted exchange");
        }
    }
    ~Impl() {
        if (job)
            TerminateJobObject(job.get(), 1);
        if (process && WaitForSingleObject(process.get(), 5000) != WAIT_OBJECT_0)
            std::fputs("AETHER_WORKER_TERMINATION_FAILED\n", stderr);
        stop_watchdog();
        if (watchdog.joinable())
            watchdog.join();
    }
    void start(const WorkerOptions &options) {
        require(options.role == WorkerRole::guest ||
                    (options.role == WorkerRole::graphics && options.less_privileged &&
                     options.exchange_deadlines) ||
                    (options.role == WorkerRole::metadata && options.less_privileged &&
                     !options.exchange_deadlines),
                "Invalid isolated service role");
        role = options.role;
        require(options.executable.is_absolute() && !options.profile.empty() &&
                    options.profile.size() <= 64 &&
                    options.profile.find_first_not_of(
                        L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.") ==
                        std::wstring::npos &&
                    options.timeout_ms >= 100 && options.timeout_ms <= 30000,
                "Invalid trusted worker startup options");
        image = std::make_unique<WorkerImage>(options.executable);
        SidOwner sid;
        if (options.role == WorkerRole::metadata) {
            require(options.profile == L"Aether.IconMetadata.v2", "Unexpected metadata service identity");
            // Userenv profile creation is not a concurrent read: parallel calls
            // for the same profile returned ERROR_KEY_DELETED in the broker test.
            // Provision once per host, serialized across hosts; later one-shot
            // workers only derive the same fixed zero-capability identity.
            static std::once_flag provisioned;
            std::call_once(provisioned, [&] {
                const auto policy = runtime_directory_sddl();
                const auto owner_end = policy.find(L"G:");
                require(policy.starts_with(L"O:") && owner_end != policy.npos,
                        "Invalid metadata owner policy");
                LocalOwner descriptor;
                require(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                            policy.c_str(), SDDL_REVISION_1,
                            reinterpret_cast<PSECURITY_DESCRIPTOR *>(&descriptor.value), nullptr) != FALSE,
                        "Cannot protect metadata provisioning mutex");
                SECURITY_ATTRIBUTES access{sizeof(SECURITY_ATTRIBUTES), descriptor.value, FALSE};
                const auto name = L"Local\\Aether.IconMetadata.Provision." + policy.substr(2, owner_end - 2);
                UniqueHandle mutex(CreateMutexW(&access, FALSE, name.c_str()));
                require(static_cast<bool>(mutex), "Cannot create metadata provisioning mutex");
                const auto locked = WaitForSingleObject(mutex.get(), 5000);
                require(locked == WAIT_OBJECT_0 || locked == WAIT_ABANDONED, "Metadata provisioning is busy");
                struct Unlock {
                    HANDLE value;
                    ~Unlock() { ReleaseMutex(value); }
                } unlock{mutex.get()};
                SidOwner provision;
                const auto created =
                    CreateAppContainerProfile(options.profile.c_str(), L"Aether package metadata",
                                              L"Read-only metadata and icon service; no Windows capabilities",
                                              nullptr, 0, &provision.value);
                require(SUCCEEDED(created) || created == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS),
                        ("Cannot provision metadata profile; HRESULT=" +
                         std::to_string(static_cast<std::uint32_t>(created)))
                            .c_str());
            });
            require(SUCCEEDED(DeriveAppContainerSidFromAppContainerName(options.profile.c_str(), &sid.value)),
                    "Cannot derive metadata identity");
        } else {
            const auto created = CreateAppContainerProfile(
                options.profile.c_str(), L"Aether isolated fixture worker",
                L"Phase 7 controlled fixtures; explicit per-process capability policy", nullptr, 0,
                &sid.value);
            if (created == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
                require(
                    SUCCEEDED(DeriveAppContainerSidFromAppContainerName(options.profile.c_str(), &sid.value)),
                    "Cannot derive worker identity");
            else
                require(SUCCEEDED(created), "Cannot create worker profile");
        }
        SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
        HANDLE parent_read = nullptr, child_write = nullptr, child_read = nullptr, parent_write = nullptr;
        require(CreatePipe(&parent_read, &child_write, &security, 65536) != FALSE,
                "Cannot create reply pipe");
        reader.reset(parent_read);
        UniqueHandle child_writer(child_write);
        require(CreatePipe(&child_read, &parent_write, &security, 65536) != FALSE,
                "Cannot create command pipe");
        writer.reset(parent_write);
        UniqueHandle child_reader(child_read);
        poller = std::make_unique<PipeFramePoller>(reader.get(), std::chrono::milliseconds(options.timeout_ms));
        require(SetHandleInformation(reader.get(), HANDLE_FLAG_INHERIT, 0) &&
                    SetHandleInformation(writer.get(), HANDLE_FLAG_INHERIT, 0),
                "Cannot restrict pipe inheritance");
        job.reset(CreateJobObjectW(nullptr, nullptr));
        require(static_cast<bool>(job), "Cannot create worker job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
            JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_PROCESS_TIME |
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = 10 * 10'000'000;
        limits.ProcessMemoryLimit = 256 * 1024 * 1024;
        require(
            SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
            "Cannot set worker resource limits");
        JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
        ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_READCLIPBOARD |
                                 JOB_OBJECT_UILIMIT_WRITECLIPBOARD | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
                                 JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | JOB_OBJECT_UILIMIT_GLOBALATOMS |
                                 JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_EXITWINDOWS;
        require(SetInformationJobObject(job.get(), JobObjectBasicUIRestrictions, &ui, sizeof(ui)),
                "Cannot set worker UI restrictions");
        auto registry_read =
            options.role == WorkerRole::graphics ? graphics_registry_read_sid() : std::vector<std::uint8_t>{};
        SID_AND_ATTRIBUTES graphics_capability{registry_read.data(), SE_GROUP_ENABLED};
        SECURITY_CAPABILITIES capabilities{sid.value, registry_read.empty() ? nullptr : &graphics_capability,
                                           registry_read.empty() ? 0u : 1u, 0};
        Attributes attributes(options.less_privileged ? 4 : 3);
        attributes.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities, sizeof(capabilities));
        std::array<HANDLE, 2> inherited{child_reader.get(), child_writer.get()};
        attributes.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(), sizeof(inherited));
        DWORD64 mitigation = PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE |
                             PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON;
        if (options.role != WorkerRole::guest)
            mitigation |= PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
        attributes.set(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigation, sizeof(mitigation));
        DWORD packages = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        if (options.less_privileged)
            attributes.set(PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, &packages,
                           sizeof(packages));
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.lpAttributeList = attributes.list;
        auto command = L"\"" + options.executable.wstring() +
                       (options.role == WorkerRole::graphics   ? L"\" --isolated-graphics "
                        : options.role == WorkerRole::metadata ? L"\" --isolated-metadata "
                                                               : L"\" --isolated ") +
                       std::to_wstring(reinterpret_cast<std::uintptr_t>(child_reader.get())) + L" " +
                       std::to_wstring(reinterpret_cast<std::uintptr_t>(child_writer.get())) + L" " +
                       options.profile + (options.less_privileged ? L" 1" : L" 0");
        std::array<wchar_t, MAX_PATH> system{}, windows{};
        const auto system_size = GetSystemDirectoryW(system.data(), static_cast<UINT>(system.size()));
        const auto windows_size = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
        require(system_size && system_size < system.size() && windows_size && windows_size < windows.size(),
                "Cannot locate Windows directories");
        std::array<wchar_t, 32768> local{};
        const auto local_size =
            GetEnvironmentVariableW(L"LOCALAPPDATA", local.data(), static_cast<DWORD>(local.size()));
        require(local_size && local_size < local.size(), "LOCALAPPDATA is required for worker startup");
        std::wstring environment = L"LOCALAPPDATA=" + std::wstring(local.data());
        environment.push_back(L'\0');
        environment += L"SystemRoot=" + std::wstring(windows.data());
        environment.push_back(L'\0');
        environment += L"windir=" + std::wstring(windows.data());
        environment.append(2, L'\0');
        {
            PROCESS_INFORMATION child{};
            require(CreateProcessW(options.executable.c_str(), command.data(), nullptr, nullptr, TRUE,
                                   EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | DETACHED_PROCESS |
                                       CREATE_UNICODE_ENVIRONMENT,
                                   environment.data(), system.data(), &startup.StartupInfo, &child),
                    "Isolated startup failed; execution refused");
            process.reset(child.hProcess);
            UniqueHandle thread(child.hThread);
            pid = child.dwProcessId;
            // Assign first; if assignment fails, the still-suspended child must be killed directly.
            if (!AssignProcessToJobObject(job.get(), process.get())) {
                TerminateProcess(process.get(), 1);
                throw ProtocolError("AETHER_WORKER: cannot attach suspended child to job");
            }
            if (options.role == WorkerRole::graphics)
                verify_graphics_process(process.get(), sid.value);
            else if (options.role == WorkerRole::metadata)
                verify_metadata_process(process.get(), sid.value);
            else
                verify_isolated_process(process.get(), sid.value, options.less_privileged);
            JOBOBJECT_BASIC_PROCESS_ID_LIST members{};
            require(QueryInformationJobObject(job.get(), JobObjectBasicProcessIdList, &members,
                                              sizeof(members), nullptr) &&
                        members.NumberOfAssignedProcesses == 1 && members.NumberOfProcessIdsInList == 1 &&
                        members.ProcessIdList[0] == pid,
                    "Worker job has unexpected process membership; execution refused");
            image_permissions = image->verify_process(process.get());
            timeout_ms = options.timeout_ms;
            exchange_deadlines = options.exchange_deadlines;
            deadline = AwakeDeadlineClock::now() + std::chrono::milliseconds(timeout_ms);
            watchdog = std::jthread([this] {
                std::unique_lock lock(deadline_mutex);
                while (!stopping) {
                    if (!armed) {
                        deadline_changed.wait(lock, [this] { return stopping || armed; });
                        continue;
                    }
                    const auto observed = deadline;
                    const auto now = AwakeDeadlineClock::now();
                    if (now >= observed) {
                        expired = true;
                        TerminateJobObject(job.get(), 0xAEE00002);
                        break;
                    }
                    // The condition-variable wait is only a wake mechanism.
                    // Recheck awake time after every return; an underlying wait
                    // clock expiring across sleep must not expire this exchange.
                    (void)deadline_changed.wait_for(lock, observed - now, [this, observed] {
                        return stopping || !armed || deadline != observed;
                    });
                }
            });
            // Freeze this worker's execution-start uptime before any worker/app
            // code runs. Use the same sleep-excluding 100ns clock as uptimeMillis.
            ULONGLONG startup_ticks = 0;QueryUnbiasedInterruptTimePrecise(&startup_ticks);
            start_uptime_ticks = startup_ticks;
            require(ResumeThread(thread.get()) != static_cast<DWORD>(-1), "Cannot resume isolated worker");
            primary_thread = std::move(thread);
        }
    }
};
WorkerProcess::WorkerProcess(const WorkerOptions &options) : impl_(std::make_unique<Impl>()) {
    impl_->start(options);
}
WorkerProcess::~WorkerProcess() = default;
std::uint64_t WorkerProcess::duplicate_progress_mapping(const WorkerProgress &progress) {
    const auto source = progress.handle();
    impl_->check_exchange();
    require(impl_->role == WorkerRole::guest && source && source != INVALID_HANDLE_VALUE,
            "Startup diagnostics require the isolated guest process");
    HANDLE target = nullptr;
    require(DuplicateHandle(GetCurrentProcess(), source, impl_->process.get(), &target,
                            SECTION_MAP_READ | SECTION_MAP_WRITE, FALSE, 0),
            "Cannot duplicate the anonymous startup diagnostic mapping");
    return reinterpret_cast<std::uint64_t>(target);
}
std::uint64_t WorkerProcess::duplicate_package_mapping(HANDLE source) {
    impl_->check_exchange();
    require(impl_->role == WorkerRole::guest && source && source != INVALID_HANDLE_VALUE,
            "Package mappings require the isolated guest process");
    HANDLE target = nullptr;
    require(DuplicateHandle(GetCurrentProcess(), source, impl_->process.get(), &target, SECTION_MAP_READ,
                            FALSE, 0),
            "Cannot duplicate the read-only installed package mapping");
    return reinterpret_cast<std::uint64_t>(target);
}
std::uint64_t WorkerProcess::duplicate_graphics_handle(HANDLE source) {
    impl_->check_exchange();
    require(impl_->role == WorkerRole::graphics && source && source != INVALID_HANDLE_VALUE,
            "Explicit texture grants require the dedicated graphics process");
    HANDLE target = nullptr;
    require(DuplicateHandle(GetCurrentProcess(), source, impl_->process.get(), &target, 0, FALSE,
                            DUPLICATE_SAME_ACCESS),
            "Cannot duplicate the explicit graphics resource");
    return reinterpret_cast<std::uint64_t>(target);
}
std::uint64_t WorkerProcess::duplicate_metadata_mapping(HANDLE source) {
    impl_->check_exchange();
    require(impl_->role == WorkerRole::metadata && source && source != INVALID_HANDLE_VALUE,
            "Preview mappings require the metadata-only process");
    HANDLE target = nullptr;
    require(DuplicateHandle(GetCurrentProcess(), source, impl_->process.get(), &target, SECTION_MAP_READ,
                            FALSE, 0),
            "Cannot grant the read-only metadata mapping");
    return reinterpret_cast<std::uint64_t>(target);
}
void WorkerProcess::send(const Frame &frame) {
    impl_->check_exchange();
    if (++impl_->sent > (impl_->exchange_deadlines ? 10000u : 258u))
        throw ProtocolError("AETHER_IPC_QUOTA: outbound frame limit");
    write_pipe_frame(impl_->writer.get(), frame);
    impl_->check_exchange(); // A late write is never reported as successful before the watchdog runs.
}
Frame WorkerProcess::receive() {
    impl_->check_exchange();
    const auto partial = impl_->poller->partial_deadline();
    // Metadata permits bounded permission frames plus a maximum 512 px bitmap.
    if (++impl_->received > (impl_->exchange_deadlines             ? 10000u
                             : impl_->role == WorkerRole::metadata ? 300u
                                                                   : 258u))
        throw ProtocolError("AETHER_IPC_QUOTA: inbound frame limit");
    try {
        auto result = read_pipe_frame(impl_->reader.get());
        require(!partial || AwakeDeadlineClock::now() < *partial,
                "Reply exceeded its absolute partial-frame deadline");
        impl_->check_exchange(); // Check the actual clock, not only the asynchronously set expired flag.
        impl_->poller->reset();
        return result;
    } catch (const std::exception &error) {
        DWORD code = 0;
        GetExitCodeProcess(impl_->process.get(), &code);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        const bool queried = QueryInformationJobObject(impl_->job.get(), JobObjectExtendedLimitInformation,
                                                       &limits, sizeof(limits), nullptr) != FALSE;
        FILETIME created{}, exited{}, kernel{}, user{};
        const bool timed = GetProcessTimes(impl_->process.get(), &created, &exited, &kernel, &user) != FALSE;
        const auto user_ticks = (static_cast<std::uint64_t>(user.dwHighDateTime) << 32) | user.dwLowDateTime;
        throw ProtocolError(
            std::string(error.what()) + "; worker exit=" + std::to_string(code) +
            "; peak commit=" + (queried ? std::to_string(limits.PeakProcessMemoryUsed) : "unknown") +
            "; user CPU 100ns=" + (timed ? std::to_string(user_ticks) : "unknown") +
            "; CPU limit 100ns=" +
            (queried ? std::to_string(limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart)
                     : "unknown"));
    }
}
std::uint32_t WorkerProcess::wait() {
    require(WaitForSingleObject(impl_->process.get(), 31000) == WAIT_OBJECT_0, "Worker did not terminate");
    DWORD code = 0;
    require(GetExitCodeProcess(impl_->process.get(), &code), "Cannot read worker exit status");
    impl_->stop_watchdog();
    return code;
}
std::optional<Frame> WorkerProcess::try_receive_idle() {
    {
        std::lock_guard lock(impl_->deadline_mutex);
        require(impl_->role == WorkerRole::guest && impl_->exchange_deadlines && !impl_->armed &&
                    !impl_->stopping && !impl_->expired, "Idle receive requires an inactive interactive guest exchange");
    }
    const auto partial = impl_->poller->partial_deadline();
    auto frame = impl_->poller->poll();
    if (!frame) return {};
    require(!partial || AwakeDeadlineClock::now() < *partial,
            "Idle reply exceeded its absolute partial-frame deadline");
    begin_exchange();
    if (partial) {
        std::lock_guard lock(impl_->deadline_mutex);
        if (*partial < impl_->deadline) impl_->deadline = *partial;
        impl_->deadline_changed.notify_all();
    }
    impl_->check_exchange();
    impl_->received = 1;
    return frame;
}
void WorkerProcess::begin_exchange() {
    const auto partial = impl_->poller->partial_deadline();
    std::lock_guard lock(impl_->deadline_mutex);
    require(impl_->exchange_deadlines && !impl_->armed && !impl_->stopping && !impl_->expired,
            "Cannot begin this worker exchange");
    const auto now = AwakeDeadlineClock::now();
    require(!partial || now < *partial, "Cannot begin an exchange after its partial-frame deadline");
    impl_->sent = impl_->received = 0;
    impl_->deadline = now + std::chrono::milliseconds(impl_->timeout_ms);
    if (partial && *partial < impl_->deadline) impl_->deadline = *partial;
    impl_->armed = true;
    impl_->deadline_changed.notify_all();
}
AwakeDeadlineClock::time_point WorkerProcess::exchange_deadline() const {
    (void)impl_->poller->partial_deadline(); // Enforce the existing I/O owner.
    std::lock_guard lock(impl_->deadline_mutex);
    require(impl_->exchange_deadlines && impl_->armed && !impl_->stopping && !impl_->expired &&
                AwakeDeadlineClock::now() < impl_->deadline,
            "Cannot inspect an inactive or expired worker exchange");
    return impl_->deadline;
}
void WorkerProcess::end_exchange() {
    (void)impl_->poller->partial_deadline();
    std::lock_guard lock(impl_->deadline_mutex);
    require(impl_->exchange_deadlines && impl_->armed && !impl_->stopping && !impl_->expired &&
                AwakeDeadlineClock::now() < impl_->deadline,
            "Cannot finish an inactive or expired worker exchange");
    impl_->armed = false;
    impl_->deadline_changed.notify_all();
}
void WorkerProcess::terminate() {
    require(TerminateJobObject(impl_->job.get(), 1), "Cannot terminate worker job");
    (void)wait();
}
void WorkerProcess::request_stop() noexcept {
    if (!TerminateJobObject(impl_->job.get(), 1))
        std::fputs("AETHER_WORKER_CANCEL_FAILED\n", stderr);
}
HANDLE WorkerProcess::primary_thread() const noexcept {
    return impl_->role == WorkerRole::guest ? impl_->primary_thread.get() : nullptr;
}
std::uint64_t WorkerProcess::start_uptime_ticks() const noexcept { return impl_->start_uptime_ticks; }
std::uint32_t WorkerProcess::process_id() const noexcept { return impl_->pid; }
WorkerImageAccess WorkerProcess::image_access() const noexcept { return impl_->image_permissions; }
bool WorkerProcess::timed_out() const noexcept { return impl_->expired; }
WorkerAccounting WorkerProcess::accounting() const {
    FILETIME created{}, exited{}, kernel{}, user{};
    require(GetProcessTimes(impl_->process.get(), &created, &exited, &kernel, &user),
            "Cannot read worker process accounting");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION usage{};
    require(QueryInformationJobObject(impl_->job.get(), JobObjectExtendedLimitInformation, &limits,
                                      sizeof(limits), nullptr) &&
                QueryInformationJobObject(impl_->job.get(), JobObjectBasicAccountingInformation, &usage,
                                          sizeof(usage), nullptr),
            "Cannot read worker job accounting");
    const auto ticks = [](FILETIME value) {
        return static_cast<std::uint64_t>(value.dwHighDateTime) << 32 | value.dwLowDateTime;
    };
    WorkerAccounting result{
        ticks(user),
        ticks(kernel),
        limits.PeakProcessMemoryUsed,
        limits.ProcessMemoryLimit,
        static_cast<std::uint64_t>(limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart),
        usage.ActiveProcesses,
        usage.TotalProcesses,
        limits.BasicLimitInformation.ActiveProcessLimit,
        limits.BasicLimitInformation.LimitFlags,
        {}};
    alignas(JOBOBJECT_BASIC_PROCESS_ID_LIST) std::array<std::uint8_t, 256> process_ids{};
    auto *ids = reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST *>(process_ids.data());
    require(QueryInformationJobObject(impl_->job.get(), JobObjectBasicProcessIdList, ids,
                                      static_cast<DWORD>(process_ids.size()), nullptr),
            "Cannot read worker job membership");
    for (DWORD i = 0; i < ids->NumberOfProcessIdsInList; ++i)
        result.active_process_ids.push_back(static_cast<std::uint32_t>(ids->ProcessIdList[i]));
    return result;
}
} // namespace aether::security
