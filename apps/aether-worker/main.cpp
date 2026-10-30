// Isolated execution: developer probes stay fixture-only; installed Activities use app-scoped admission.
#include "aether/a64/selftest.hpp"
#include "aether/common/text.hpp"
#include "aether/host/audio_stream.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/security/activity_session.hpp"
#include "aether/security/activity_launch.hpp"
#include "aether/security/worker_progress.hpp"
#include "aether/security/apk_session.hpp"
#include "aether/security/audio_session.hpp"
#include "aether/security/graphics_session.hpp"
#include "aether/security/graphics_window_protocol.hpp"
#include "aether/security/worker.hpp"
#include "probes.hpp"
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <array>
#include <crtdbg.h>
#include <cstdlib>
#include <d3d11.h>
#include <dxgi.h>
#include <exception>
#include <iostream>
#include <new>
#include <userenv.h>
#include <wrl/client.h>

// CRT static initialization precedes wmain. An isolated startup failure must never
// open a modal debug window or write text into the binary protocol channel.
#ifdef _DEBUG
static int __cdecl stop_debug_ansi(int, char *, int *) { ExitProcess(3); }
static int __cdecl stop_debug_wide(int, wchar_t *, int *) { ExitProcess(3); }
static int __cdecl initialize_worker_reporting() {
    std::set_terminate([] { ExitProcess(3); });
    _CrtSetReportHook(stop_debug_ansi);
    _CrtSetReportHookW2(_CRT_RPTHOOK_INSTALL, stop_debug_wide);
    return 0;
}
#pragma section(".CRT$XIB", long, read)
extern "C"
    __declspec(allocate(".CRT$XIB")) int(__cdecl *aether_worker_reporting)() = initialize_worker_reporting;
#endif

namespace {
using namespace aether;
using namespace aether::security;
void require(bool value, const char *message) {
    if (!value)
        throw std::runtime_error(message);
}
struct Client final : a64::GuestServices {
    HANDLE reader, writer;
    std::uint64_t session, next = 1;
    std::uint64_t delegated_calls = 0;
    Client(HANDLE input, HANDLE output, std::uint64_t identity)
        : reader(input), writer(output), session(identity) {}
    Frame request(Operation operation, std::vector<std::uint8_t> payload = {}) {
        Frame message{{operation, next++, session, static_cast<std::uint32_t>(payload.size()), Status::ok},
                      std::move(payload)};
        write_pipe_frame(writer, message);
        auto reply = read_pipe_frame(reader);
        require(reply.header.operation == operation && reply.header.sequence == message.header.sequence &&
                    reply.header.session == session,
                "Broker response identity mismatch");
        return reply;
    }
    a64::Fault invoke(std::uint32_t service, a64::Address instruction,
                      std::array<std::uint64_t, 31> &registers) noexcept override {
        try {
            if (service != 0x700 || instruction != 0x20000)
                return a64::Fault::unsupported_service;
            const auto reply = request(Operation::monotonic_time);
            ++delegated_calls;
            if (reply.header.status == Status::denied)
                return a64::Fault::capability_denied;
            if (reply.header.status != Status::ok || reply.payload.size() != 16)
                return a64::Fault::windows_service;
            registers[0] = read_u64(reply.payload, 0);
            registers[1] = read_u64(reply.payload, 8);
            return registers[1] < 1'000'000'000 ? a64::Fault::none : a64::Fault::windows_service;
        } catch (...) {
            return a64::Fault::windows_service;
        }
    }
};
struct Graphics {
    EGLDisplay display = EGL_NO_DISPLAY;
    EGLContext context = EGL_NO_CONTEXT;
    EGLSurface surface = EGL_NO_SURFACE;
    bool initialized = false;
    bool close() noexcept {
        bool ok = true;
        if (initialized) {
            ok = eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT) != EGL_FALSE;
            if (surface != EGL_NO_SURFACE)
                ok = (eglDestroySurface(display, surface) != EGL_FALSE) && ok;
            if (context != EGL_NO_CONTEXT)
                ok = (eglDestroyContext(display, context) != EGL_FALSE) && ok;
            ok = (eglTerminate(display) != EGL_FALSE) && ok;
            initialized = false;
        }
        return (eglReleaseThread() != EGL_FALSE) && ok;
    }
    ~Graphics() { close(); }
};
// Observations, not mandatory successes: do not grant capabilities to make media pass.
void graphics_observation(std::vector<std::uint8_t> &result) {
    std::uint64_t passed = 0, error = 0, vendor = 0, device = 0;
    Graphics graphics;
    try {
        const EGLint attributes[]{EGL_PLATFORM_ANGLE_TYPE_ANGLE, EGL_PLATFORM_ANGLE_TYPE_D3D11_ANGLE,
                                  EGL_PLATFORM_ANGLE_DEVICE_TYPE_ANGLE,
                                  EGL_PLATFORM_ANGLE_DEVICE_TYPE_HARDWARE_ANGLE, EGL_NONE};
        graphics.display =
            eglGetPlatformDisplayEXT(EGL_PLATFORM_ANGLE_ANGLE, EGL_DEFAULT_DISPLAY, attributes);
        require(graphics.display != EGL_NO_DISPLAY, "No isolated EGL display");
        EGLint major = 0, minor = 0;
        require(eglInitialize(graphics.display, &major, &minor), "No isolated hardware D3D11");
        graphics.initialized = true;
        require(eglBindAPI(EGL_OPENGL_ES_API), "Cannot bind isolated ES API");
        const EGLint config_attributes[]{EGL_SURFACE_TYPE,
                                         EGL_PBUFFER_BIT,
                                         EGL_RENDERABLE_TYPE,
                                         EGL_OPENGL_ES2_BIT,
                                         EGL_RED_SIZE,
                                         8,
                                         EGL_GREEN_SIZE,
                                         8,
                                         EGL_BLUE_SIZE,
                                         8,
                                         EGL_ALPHA_SIZE,
                                         8,
                                         EGL_NONE};
        EGLConfig config = nullptr;
        EGLint count = 0;
        require(eglChooseConfig(graphics.display, config_attributes, &config, 1, &count) && count == 1,
                "No isolated RGBA8 config");
        const EGLint context_attributes[]{EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
        graphics.context = eglCreateContext(graphics.display, config, EGL_NO_CONTEXT, context_attributes);
        require(graphics.context != EGL_NO_CONTEXT, "No isolated ES context");
        const EGLint surface_attributes[]{EGL_WIDTH, 4, EGL_HEIGHT, 4, EGL_NONE};
        graphics.surface = eglCreatePbufferSurface(graphics.display, config, surface_attributes);
        require(graphics.surface != EGL_NO_SURFACE &&
                    eglMakeCurrent(graphics.display, graphics.surface, graphics.surface, graphics.context),
                "No isolated pbuffer");
        EGLAttrib egl_device = 0, native_device = 0;
        require(eglQueryDisplayAttribEXT(graphics.display, EGL_DEVICE_EXT, &egl_device) &&
                    eglQueryDeviceAttribEXT(reinterpret_cast<EGLDeviceEXT>(egl_device),
                                            EGL_D3D11_DEVICE_ANGLE, &native_device) &&
                    native_device,
                "No isolated native GPU identity");
        Microsoft::WRL::ComPtr<IDXGIDevice> dxgi;
        Microsoft::WRL::ComPtr<IDXGIAdapter> adapter;
        Microsoft::WRL::ComPtr<IDXGIAdapter1> adapter1;
        require(
            SUCCEEDED(reinterpret_cast<ID3D11Device *>(native_device)->QueryInterface(IID_PPV_ARGS(&dxgi))) &&
                SUCCEEDED(dxgi->GetAdapter(&adapter)) && SUCCEEDED(adapter.As(&adapter1)),
            "Cannot query isolated adapter");
        DXGI_ADAPTER_DESC1 description{};
        require(SUCCEEDED(adapter1->GetDesc1(&description)) &&
                    !(description.Flags & DXGI_ADAPTER_FLAG_SOFTWARE),
                "Isolated renderer is not hardware");
        vendor = description.VendorId;
        device = description.DeviceId;
        glClearColor(1, 0, 0, 1);
        glClear(GL_COLOR_BUFFER_BIT);
        std::array<std::uint8_t, 64> pixels{};
        glReadPixels(0, 0, 4, 4, GL_RGBA, GL_UNSIGNED_BYTE, pixels.data());
        require(glGetError() == GL_NO_ERROR, "Isolated readback failed");
        for (std::size_t i = 0; i < pixels.size(); i += 4)
            require(pixels[i] == 255 && pixels[i + 1] == 0 && pixels[i + 2] == 0 && pixels[i + 3] == 255,
                    "Isolated GPU pixel mismatch");
        // Drop queried native interfaces before ANGLE tears down its device/DLLs.
        adapter1.Reset();
        adapter.Reset();
        dxgi.Reset();
        require(graphics.close(), "Isolated GPU cleanup failed");
        passed = 1;
    } catch (...) {
        error = static_cast<std::uint32_t>(eglGetError());
        if (error == EGL_SUCCESS)
            error = 1; // Operation/readback/cleanup failure without an EGL error.
    }
    for (const auto value : {passed, error, vendor, device})
        append_u64(result, value);
}
void audio_observation(std::vector<std::uint8_t> &result) {
    std::uint64_t passed = 0, error = 0, written = 0, position = 0;
    try {
        host::HostAudioStream stream({48000, 2, true});
        std::array<std::uint8_t, 256> silence{};
        written = stream.write(silence, 0);
        require(written == 64 && stream.info().muted, "Isolated private audio prefill failed");
        stream.start();
        stream.request_stop();
        require(stream.wait_for_change(host::AudioState::stopping, 2'000'000'000) &&
                    stream.state() == host::AudioState::stopped,
                "Isolated playback did not drain");
        position = stream.metrics().clock_position;
        require(position > 0 && !stream.metrics().padding, "Isolated device clock did not advance");
        stream.close();
        require(!stream.metrics().cleanup_failures, "Isolated audio cleanup failed");
        passed = 1;
    } catch (const host::AudioError &failure) {
        error = static_cast<std::uint32_t>(failure.native);
        if (!error)
            error = 1;
    } catch (...) {
        error = 1;
    }
    for (const auto value : {passed, error, written, position})
        append_u64(result, value);
}
int run(HANDLE reader, HANDLE writer, bool lpac, std::uint64_t &session) {
    const auto boot = read_pipe_frame(reader);
    require(boot.header.operation == Operation::boot && boot.header.sequence == 0 &&
                boot.header.status == Status::ok && boot.payload.size() >= 40,
            "Invalid worker boot message");
    session = boot.header.session;
    const auto scenario = read_u64(boot.payload, 0);
    const auto parent = read_u64(boot.payload, 8);
    const auto app_id = read_u64(boot.payload, 16);
    const auto allowed = read_u64(boot.payload, 24);
    const auto path_size = read_u64(boot.payload, 32);
    require(parent > 0 && parent <= MAXDWORD && app_id && allowed <= 1 && path_size <= 2048 &&
                boot.payload.size() >= 40 + path_size,
            "Invalid worker fixture configuration");
    std::array<std::wstring, 3> denied_files{};
    if (scenario == 10) {
        require(lpac, "APK execution requires LPAC");
        std::size_t offset = 32;
        for (auto &path : denied_files)
            path = utf16(read_text(boot.payload, offset, 2048));
        require(offset == boot.payload.size(), "Trailing APK boot configuration");
    } else if (scenario == 20) {
        require(path_size == 0 && (boot.payload.size() == 64 || boot.payload.size() == 72) &&
                    (boot.payload.size() == 64 || read_u64(boot.payload, 64) <= 1),
                "Invalid installed package mapping fields");
    } else if (scenario == installed_intent_scenario) {
        require(path_size == 0 && boot.payload.size() == 80 && read_u64(boot.payload, 64) <= 1 &&
                    read_u64(boot.payload, 72) && read_u64(boot.payload, 72) <= activity_launch_limit,
                "Invalid resolved installed package mapping fields");
    } else if (scenario == 28) {
        require(path_size == 0 && boot.payload.size() == 56, "Invalid compiled native fault fields");
    } else if (scenario == 27) {
        require(path_size == 0 && boot.payload.size() == 56, "Invalid compiled preferences fields");
    } else if (scenario == 25) {
        require(path_size == 0 && boot.payload.size() == 48, "Invalid compiled progress mapping fields");
    } else {
        require(boot.payload.size() == 40 + path_size, "Trailing worker fixture configuration");
    }
    write_pipe_frame(writer, {{Operation::boot, 0, boot.header.session, 0, Status::ok}, {}});
    if (scenario == 32) {
        require(lpac && path_size == 0 && boot.payload.size() == 40 && app_id == 76 && allowed == 1,
                "Invalid compiled allocation failure policy");
        throw std::bad_alloc{};
    }
    if (scenario == 29 || scenario == 30 || scenario == 31) {
        require(lpac && path_size == 0 && boot.payload.size() == 40 && app_id == 76 && allowed == 1,
                "Invalid compiled process exit policy");
        return run_process_exit_probe(writer, session,
                                      static_cast<std::uint8_t>(scenario == 29 ? 0 : scenario == 30 ? 255 : 134));
    }
    if (scenario == 28) {
        require(lpac && path_size == 0 && app_id == 73 && allowed == 0 && read_u64(boot.payload,48) <= 1,
                "Invalid compiled native fault policy");
        run_native_fault_probe(reinterpret_cast<HANDLE>(read_u64(boot.payload,40)),read_u64(boot.payload,48));
        return 0;
    }
    if (scenario == 27) {
        require(lpac && path_size == 0 && app_id == 73 && read_u64(boot.payload,40) <= 2 &&
                (allowed != 0) == (read_u64(boot.payload,40) != 2),
                "Invalid compiled preferences policy");
        run_preferences_probe(reader, writer, session, read_u64(boot.payload,40), read_u64(boot.payload,48));
        return 0;
    }
    if (scenario == 26) {
        require(lpac && path_size == 0 && boot.payload.size() == 40 && app_id == 73,
                "Invalid compiled nanoTime probe policy");
        run_nano_time_probe(reader, writer, session, allowed != 0);
        return 0;
    }
    if (scenario == 25) {
        require(lpac && path_size == 0 && app_id == 73 && allowed == 0,
                "Invalid compiled startup progress policy");
        run_progress_probe(reinterpret_cast<HANDLE>(read_u64(boot.payload, 40)));
        return 0;
    }
    if (scenario == 24) {
        require(lpac && path_size == 0 && boot.payload.size() == 40 && app_id == 73 && allowed == 0,
                "Invalid compiled regex probe policy");
        run_regex_probe(writer, session);
        return 0;
    }
    if (scenario == 23) {
        require(lpac && path_size == 0 && boot.payload.size() == 40 && app_id == 73 && allowed == 0,
                "Invalid compiled UUID probe policy");
        run_uuid_probe(writer, session);
        return 0;
    }
    if (scenario == 22) {
        require(lpac && path_size == 0 && boot.payload.size() == 40 && app_id == 73 && allowed == 0,
                "Invalid compiled stream probe policy");
        run_stream_probe(writer, session);
        return 0;
    }
    if (scenario == 21) {
        require(lpac && path_size == 0 && boot.payload.size() == 40 && app_id == 73 && allowed == 0,
                "Invalid compiled AsyncTask probe policy");
        run_async_task_probe(writer, session);
        return 0;
    }
    if (scenario >= 17 && scenario <= 19) {
        require(lpac && path_size == 0 && app_id == 73 && allowed == 0,
                "Invalid compiled resource probe policy");
        run_resource_probe(reader, writer, session, scenario);
        return 0;
    }
    if (scenario == 15 || scenario == 16) {
        require(lpac && path_size == 0 && app_id == 83 && allowed == 1,
                "Invalid isolated graphics window startup policy");
        run_graphics_window_worker(reader, writer, session, app_id, scenario == 16);
        return 0;
    }
    if (scenario == 14) {
        require(lpac && path_size == 0 && app_id >= 80 && app_id <= 82 && allowed == 1,
                "Invalid isolated graphics startup policy");
        run_graphics_worker(reader, writer, session, app_id);
        return 0;
    }
    if (scenario == 13) {
        require(lpac && path_size == 0 && app_id >= 77 && app_id <= 79 && allowed == 1,
                "Invalid isolated audio startup policy");
        run_audio_worker(reader, writer, session, app_id);
        return 0;
    }
    if (scenario == 11 || scenario == 12) {
        require(lpac && path_size == 0 && app_id == 76 && allowed == 1,
                "Invalid isolated Activity startup policy");
        return run_activity_worker(reader, writer, session, app_id, scenario == 12);
    }
    if (scenario == 20 || scenario == installed_intent_scenario) {
        require(lpac && path_size == 0 && (app_id & (std::uint64_t{1} << 63)) && allowed == 1,
                "Invalid installed Activity startup policy");
        WorkerProgressWriter progress(reinterpret_cast<HANDLE>(read_u64(boot.payload, 56)));
        ScopedWorkerFaultCapture faults(progress);
        progress.stage(100, "installed_package_map");
        const auto size = read_u64(boot.payload, 48);
        host::UniqueHandle mapping(reinterpret_cast<HANDLE>(read_u64(boot.payload, 40)));
        require(mapping && size && size <= SIZE_MAX, "Missing installed package mapping");
        // The parent grants only SECTION_MAP_READ. Verify that the transferred
        // capability cannot acquire writable or executable APK pages.
        for (const auto access : {FILE_MAP_WRITE, FILE_MAP_READ | FILE_MAP_EXECUTE}) {
            const auto forbidden = MapViewOfFile(mapping.get(), access, 0, 0, 1);
            const auto error = GetLastError();
            if (forbidden)
                UnmapViewOfFile(forbidden);
            require(!forbidden && error == ERROR_ACCESS_DENIED, "APK mapping grants excess access");
        }
        const auto unmap = [](void *view) {
            if (view)
                UnmapViewOfFile(view);
        };
        std::unique_ptr<void, decltype(unmap)> view(
            MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, static_cast<SIZE_T>(size)), unmap);
        require(static_cast<bool>(view), "Cannot map the installed package for read access");
        std::optional<ActivityLaunch> launch;
        if (scenario == installed_intent_scenario) {
            const auto expected = static_cast<std::size_t>(read_u64(boot.payload, 72));
            ActivityReassembly receiver(Operation::activity_launch, 0, session, expected);
            while (!receiver.complete())
                receiver.accept(read_pipe_frame(reader));
            const auto encoded = receiver.take();
            require(encoded.size() == expected, "Resolved installed launch size differs from boot configuration");
            launch = ActivityLaunch::decode(encoded);
        }
        return run_activity_worker(reader, writer, session, app_id, false, true,
                            {static_cast<const std::uint8_t *>(view.get()), static_cast<std::size_t>(size)}, &progress,
                            boot.payload.size() >= 72 && read_u64(boot.payload, 64) != 0,
                            launch ? &*launch : nullptr);
    }
    if (scenario == 10) {
        BrokerClient client(reader, writer, session);
        auto result = execute_apk_fixture(client, app_id, allowed != 0, denied_files).encode();
        const auto size = static_cast<std::uint32_t>(result.size());
        write_pipe_frame(writer, {{Operation::finished, client.next_sequence(), session, size, Status::ok},
                                  std::move(result)});
        return 0;
    }
    if (scenario == 1)
        ExitProcess(0xAEE00003);
    if (scenario == 2)
        Sleep(INFINITE); // Parent hard deadline must terminate the entire job.
    Client client(reader, writer, boot.header.session);
    if (scenario == 3 || scenario == 4) {
        auto malformed = encode_header({Operation::monotonic_time, 1, client.session, 0, Status::ok});
        malformed[scenario == 3 ? 0 : 19] = 255;
        DWORD count = 0;
        require(WriteFile(writer, malformed.data(), static_cast<DWORD>(malformed.size()), &count, nullptr) &&
                    count == malformed.size(),
                "Cannot send malformed test header");
        Sleep(INFINITE);
    }
    if (scenario == 5)
        ++client.session;
    if (scenario == 5 || scenario == 6 || scenario == 7) {
        (void)client.request(Operation::monotonic_time);
        if (scenario == 6)
            --client.next;
        for (;;)
            (void)client.request(Operation::monotonic_time);
    }
    if (scenario == 8 || scenario == 9) {
        Frame progress{{Operation::observation, 1, client.session, 8, Status::ok}, {}};
        append_u64(progress.payload, scenario - 7);
        write_pipe_frame(writer, progress);
        std::vector<std::uint8_t> observation;
        if (scenario == 8)
            graphics_observation(observation);
        else
            audio_observation(observation);
        write_pipe_frame(writer,
                         {{Operation::finished, 2, client.session, 32, Status::ok}, std::move(observation)});
        return 0;
    }
    require(scenario == 0, "Unsupported worker fixture scenario");
    const auto jit = a64::translate_selftest();
    require(jit.passed(), "Isolated ARM64 JIT checks failed");
    a64::GuestMemory memory;
    const a64::AppContext app{app_id, false}; // No direct time service; requests must reach the broker.
    constexpr std::array<std::uint8_t, 8> code{0x01, 0xe0, 0x00, 0xd4,
                                               0xc0, 0x03, 0x5f, 0xd6}; // svc #0x700; ret
    memory.map(0x20000, 4096, a64::read_write);
    require(memory.write(0x20000, code), "Cannot map brokered ARM64 fixture");
    memory.protect(0x20000, a64::read_execute);
    memory.map(0x30000, 4096, a64::read_write);
    a64::GuestCpu cpu(memory, app, &client);
    const auto clock = cpu.call(0x20000, {}, 0x31000);
    require(allowed
                ? (clock.returned && clock.fault == a64::Fault::none && clock.registers[1] < 1'000'000'000)
                : (!clock.returned && clock.fault == a64::Fault::capability_denied),
            "Translated capability decision did not match broker policy");
    require(client.delegated_calls == 1, "Translated call did not reach broker");
    std::uint64_t denied = 0;
    for (unsigned operation = 3; operation <= 8; ++operation) {
        const auto reply = client.request(static_cast<Operation>(operation));
        require(reply.header.status == Status::denied && reply.payload.empty(),
                "Sensitive broker operation allowed");
        ++denied;
    }
    const auto invalid = client.request(Operation::monotonic_time, {1});
    const auto unknown = client.request(static_cast<Operation>(65535));
    require(invalid.header.status == Status::invalid && unknown.header.status == Status::unsupported,
            "Broker accepted invalid arguments or an unknown operation");
    const auto path = utf16(std::string(reinterpret_cast<const char *>(boot.payload.data() + 40),
                                        static_cast<std::size_t>(path_size)));
    host::UniqueHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL, nullptr));
    require(!file && GetLastError() == ERROR_ACCESS_DENIED, "Unscoped fixture file was not access-denied");
    host::UniqueHandle write_file(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    const auto write_error = GetLastError();
    require(!write_file && write_error == ERROR_ACCESS_DENIED,
            "Unscoped fixture file write was not access-denied");
    host::UniqueHandle parent_process(OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE,
                                                  FALSE, static_cast<DWORD>(parent)));
    require(!parent_process && GetLastError() == ERROR_ACCESS_DENIED, "Parent process was not access-denied");
    const bool clipboard_open = OpenClipboard(nullptr) != FALSE;
    if (clipboard_open)
        CloseClipboard(); // Never inspect or modify clipboard contents.
    require(!clipboard_open, "Worker can open the clipboard");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    require(QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation, &limits, sizeof(limits),
                                      nullptr) &&
                limits.BasicLimitInformation.ActiveProcessLimit == 1 &&
                limits.ProcessMemoryLimit == 256 * 1024 * 1024,
            "Worker job quotas differ from host policy");
    std::vector<std::uint8_t> result;
    for (const std::uint64_t value :
         {static_cast<std::uint64_t>(lpac), static_cast<std::uint64_t>(jit.checks.size()),
          jit.metrics.compiled_blocks, jit.metrics.rx_checks, jit.metrics.rx_failures, client.delegated_calls,
          allowed, denied, std::uint64_t{1}, std::uint64_t{1}, std::uint64_t{1},
          static_cast<std::uint64_t>(limits.ProcessMemoryLimit), static_cast<std::uint64_t>(write_error)})
        append_u64(result, value);
    for (const auto error : runtime_image_probe())
        append_u64(result, error);
    write_pipe_frame(writer, {{Operation::finished, client.next, client.session,
                               static_cast<std::uint32_t>(result.size()), Status::ok},
                              std::move(result)});
    return 0;
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    _set_error_mode(_OUT_TO_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    host::UniqueHandle reader, writer;
    std::uint64_t session = 0;
    try {
        verify_isolated_process(GetCurrentProcess()); // Before trusting arguments or handles.
        require(argc == 6 && std::wstring_view(argv[1]) == L"--isolated",
                "Worker requires its broker launcher");
        require(std::wstring_view(argv[5]) == L"0" || std::wstring_view(argv[5]) == L"1",
                "Invalid LPAC argument");
        const bool lpac = std::wstring_view(argv[5]) == L"1";
        PSID sid = nullptr;
        require(SUCCEEDED(DeriveAppContainerSidFromAppContainerName(argv[4], &sid)),
                "Cannot derive worker identity");
        struct FreeIdentity {
            PSID value;
            ~FreeIdentity() { FreeSid(value); }
        } identity{sid};
        verify_isolated_process(GetCurrentProcess(), sid, lpac);
        BOOL in_job = FALSE;
        require(IsProcessInJob(GetCurrentProcess(), nullptr, &in_job) && in_job,
                "Worker is not contained in a job");
        require(SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32), "Cannot restrict worker DLL loading");
        reader.reset(reinterpret_cast<HANDLE>(std::stoull(argv[2])));
        writer.reset(reinterpret_cast<HANDLE>(std::stoull(argv[3])));
        require(reader && writer && reader.get() != writer.get() &&
                    GetFileType(reader.get()) == FILE_TYPE_PIPE &&
                    GetFileType(writer.get()) == FILE_TYPE_PIPE,
                "Invalid inherited worker channel");
        return run(reader.get(), writer.get(), lpac, session);
    } catch (const std::bad_alloc &) {
        if (writer && session)
            (void)write_worker_allocation_failure(writer.get(), session);
        return 1;
    } catch (const std::exception &error) {
        if (writer && session) {
            try {
                const auto message = bounded_worker_error(error.what());
                write_pipe_frame(writer.get(), {{Operation::finished, 0, session,
                                                 static_cast<std::uint32_t>(message.size()), Status::invalid},
                                                {message.begin(), message.end()}});
            } catch (...) {
                // The host may already have rejected the channel and terminated the job.
            }
        }
        std::cerr << "AETHER_WORKER_REFUSED: " << error.what() << '\n';
        return 1;
    }
}
