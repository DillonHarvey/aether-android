#include "aether/graphics/shared_window.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/security/graphics_channel.hpp"
#include <crtdbg.h>
#include <cstdlib>
#include <iostream>
#include <userenv.h>

#ifdef AETHER_GRAPHICS_CONTEXT_TESTING
namespace aether::graphics::testing {
void before_context_request(std::uint64_t app_id, const security::Frame &request);
void after_context_reply(security::Frame &reply);
} // namespace aether::graphics::testing
#endif

#ifdef _DEBUG
static int __cdecl stop_report_a(int, char *, int *) { ExitProcess(3); }
static int __cdecl stop_report_w(int, wchar_t *, int *) { ExitProcess(3); }
static int __cdecl initialize_reporting() {
    _CrtSetReportHook(stop_report_a);
    _CrtSetReportHookW2(_CRT_RPTHOOK_INSTALL, stop_report_w);
    return 0;
}
#pragma section(".CRT$XIB", long, read)
extern "C" __declspec(allocate(".CRT$XIB")) int(__cdecl *aether_graphics_reporting)() = initialize_reporting;
#endif

namespace {
using namespace aether::security;
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(std::string("AETHER_GRAPHICS_SERVICE: ") + message);
}
struct Sid {
    PSID value = nullptr;
    ~Sid() {
        if (value)
            FreeSid(value);
    }
};
int run(HANDLE reader, HANDLE writer, std::uint64_t app_id) {
    const auto boot = read_pipe_frame(reader);
    require(boot.header.operation == Operation::boot && boot.header.sequence == 0 && boot.header.session &&
                boot.header.status == Status::ok && boot.payload.size() == 8 &&
                read_u64(boot.payload, 0) == app_id,
            "Invalid startup envelope");
    GraphicsBroker graphics(read_u64(boot.payload, 0)); // Original bounded arena; no guest CPU or APK loader.
    write_pipe_frame(writer, {{Operation::boot, 0, boot.header.session, 0, Status::ok}, {}});
    bool closed = false;
    for (std::uint64_t sequence = 1; sequence < 100000; ++sequence) {
        const auto request = read_pipe_frame(reader);
        require(request.header.session == boot.header.session && request.header.sequence == sequence &&
                    request.header.status == Status::ok,
                "Invalid request identity");
        const auto op = request.header.operation;
#ifdef AETHER_GRAPHICS_CONTEXT_TESTING
        aether::graphics::testing::before_context_request(app_id, request);
#endif
        if (op == Operation::graphics_bind_surface) {
            const auto &bytes = request.payload;
            require(!closed && bytes.size() == 72 && read_u64(bytes, 0) == 1 &&
                        read_u64(bytes, 8) == app_id && read_u64(bytes, 40) <= 1024 &&
                        read_u64(bytes, 48) <= 1024 && read_u64(bytes, 56) <= UINT32_MAX &&
                        read_u64(bytes, 64) <= UINT32_MAX,
                    "Invalid trusted surface grant envelope");
            aether::graphics::SharedWindowGrant grant{read_u64(bytes, 16),
                                                      read_u64(bytes, 24),
                                                      read_u64(bytes, 32),
                                                      static_cast<std::uint32_t>(read_u64(bytes, 40)),
                                                      static_cast<std::uint32_t>(read_u64(bytes, 48)),
                                                      static_cast<std::uint32_t>(read_u64(bytes, 56)),
                                                      static_cast<std::uint32_t>(read_u64(bytes, 64))};
            require(grant.valid(), "Invalid trusted surface grant fields");
            auto result = encode_graphics_reply(graphics.bind_shared_window(grant));
            const auto size = static_cast<std::uint32_t>(result.size());
            require(size <= maximum_payload, "Oversized surface grant acknowledgement");
            Frame reply{{op, sequence, boot.header.session, size, Status::ok}, std::move(result)};
#ifdef AETHER_GRAPHICS_CONTEXT_TESTING
            aether::graphics::testing::after_context_reply(reply);
#endif
            write_pipe_frame(writer, reply);
            continue;
        }
        if (op == Operation::finished) {
            const auto &m = graphics.metrics();
            require(closed && request.payload.empty() && !graphics.retained_transfer_bytes() && !m.contexts &&
                        !m.surfaces && !m.shaders && !m.programs && !m.buffers && !m.buffer_bytes &&
                        !m.window_bindings && !m.window_surfaces && !m.cleanup_failures,
                    "Shutdown before complete graphics cleanup");
            write_pipe_frame(writer, {{op, sequence, boot.header.session, 0, Status::ok}, {}});
            return 0;
        }
        require(op >= Operation::graphics_call && op <= Operation::graphics_close &&
                    (!closed || op == Operation::graphics_result),
                "Unsupported graphics service operation");
        auto reply = graphics.dispatch(request);
#ifdef AETHER_GRAPHICS_CONTEXT_TESTING
        aether::graphics::testing::after_context_reply(reply);
#endif
        if (op == Operation::graphics_close)
            closed = true;
        write_pipe_frame(writer, reply);
    }
    throw ProtocolError("AETHER_GRAPHICS_SERVICE: frame quota reached");
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    _set_error_mode(_OUT_TO_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    try {
        verify_graphics_process(GetCurrentProcess()); // Refuse full-trust entry before parsing handles.
        require(argc == 6 && std::wstring_view(argv[1]) == L"--isolated-graphics" &&
                    std::wstring_view(argv[5]) == L"1",
                "Invalid service arguments");
        const std::wstring profile(argv[4]);
        constexpr std::wstring_view prefix = L"Aether.Development.GraphicsService.";
        require(profile.starts_with(prefix) && profile.size() <= 64, "Invalid service profile");
        const auto app_id = std::stoull(profile.substr(prefix.size()));
        require(app_id && profile == std::wstring(prefix) + std::to_wstring(app_id),
                "Noncanonical service app identity");
        Sid sid;
        require(SUCCEEDED(DeriveAppContainerSidFromAppContainerName(profile.c_str(), &sid.value)),
                "Cannot derive service identity");
        verify_graphics_process(GetCurrentProcess(), sid.value);
        JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        require(QueryInformationJobObject(nullptr, JobObjectBasicUIRestrictions, &ui, sizeof(ui), nullptr) &&
                    ui.UIRestrictionsClass == 255 &&
                    QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation, &limits,
                                              sizeof(limits), nullptr) &&
                    limits.BasicLimitInformation.LimitFlags == 9482 &&
                    limits.BasicLimitInformation.ActiveProcessLimit == 1 &&
                    limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart == 100000000 &&
                    limits.ProcessMemoryLimit == 256 * 1024 * 1024,
                "Unexpected graphics job policy");
        require(SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32), "Cannot restrict DLL lookup");
        aether::host::UniqueHandle reader(reinterpret_cast<HANDLE>(std::stoull(argv[2])));
        aether::host::UniqueHandle writer(reinterpret_cast<HANDLE>(std::stoull(argv[3])));
        require(reader && writer && reader.get() != writer.get() &&
                    GetFileType(reader.get()) == FILE_TYPE_PIPE &&
                    GetFileType(writer.get()) == FILE_TYPE_PIPE,
                "Invalid inherited pipe handles");
        return run(reader.get(), writer.get(), app_id);
    } catch (const std::exception &error) {
        std::cerr << "AETHER_GRAPHICS_SERVICE_FAILED: " << error.what() << '\n';
        return 1;
    }
}
