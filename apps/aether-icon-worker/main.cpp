#include "aether/security/metadata_process.hpp"
#include <algorithm>
#include <crtdbg.h>
#include <cstdlib>
#include <iostream>
#include <userenv.h>

#ifdef _DEBUG
static int __cdecl stop_report_a(int, char *, int *) { ExitProcess(3); }
static int __cdecl stop_report_w(int, wchar_t *, int *) { ExitProcess(3); }
static int __cdecl initialize_reporting() {
    _CrtSetReportHook(stop_report_a);
    _CrtSetReportHookW2(_CRT_RPTHOOK_INSTALL, stop_report_w);
    return 0;
}
#pragma section(".CRT$XIB", long, read)
extern "C" __declspec(allocate(".CRT$XIB")) int(__cdecl *aether_icon_reporting)() = initialize_reporting;
#endif

namespace {
using namespace aether::security;
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(std::string("AETHER_ICON_WORKER: ") + message);
}
int run(HANDLE reader, HANDLE writer) {
    const auto grant = read_pipe_frame(reader);
    require(grant.header.operation == Operation::boot && grant.header.sequence == 0 && grant.header.session &&
                grant.header.status == Status::ok && grant.payload.size() == 40 &&
                read_u64(grant.payload, 0) == 3 && read_u64(grant.payload, 8) &&
                read_u64(grant.payload, 16) && read_u64(grant.payload, 24) == 256 &&
                read_u64(grant.payload, 32) == 96,
            "Invalid preview grant");
    aether::host::UniqueHandle mapping(reinterpret_cast<HANDLE>(read_u64(grant.payload, 8)));
    const auto length = read_u64(grant.payload, 16);
    const auto view = MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, static_cast<SIZE_T>(length));
    require(view != nullptr, "Cannot map explicit read-only source grant");
    struct Unmap {
        const void *view;
        ~Unmap() { UnmapViewOfFile(view); }
    } unmap{view};
    const auto preview = aether::apk::preview_package(
        {static_cast<const std::uint8_t *>(view), static_cast<std::size_t>(length)});
    std::uint64_t sequence = 0;
    const auto send = [&](Operation operation, std::vector<std::uint8_t> payload) {
        const auto size = static_cast<std::uint32_t>(payload.size());
        write_pipe_frame(
            writer, {{operation, sequence++, grant.header.session, size, Status::ok}, std::move(payload)});
    };
    send(Operation::icon_result, encode_icon_description(preview));
    std::vector<std::uint8_t> permission_count;
    require(preview.declared_permissions.size() <= 1024, "Too many declared permissions");
    append_u64(permission_count, preview.declared_permissions.size());
    send(Operation::icon_permissions, std::move(permission_count));
    std::size_t permission_bytes = 0;
    std::vector<std::uint8_t> permission_frame;
    for (const auto &permission : preview.declared_permissions) {
        permission_bytes += permission.size();
        require(permission.size() <= 512 && permission_bytes <= 64 * 1024, "Permission metadata limit");
        if (permission_frame.size() + 8 + permission.size() > maximum_payload) {
            send(Operation::icon_permissions, std::move(permission_frame));
            permission_frame.clear();
        }
        append_text(permission_frame, permission);
    }
    if (!permission_frame.empty())
        send(Operation::icon_permissions, std::move(permission_frame));
    const auto &pixels = preview.presentation.bitmap.rgba;
    require(pixels.size() ==
                    std::size_t(preview.presentation.bitmap.width) * preview.presentation.bitmap.height * 4 &&
                pixels.size() <= 512 * 512 * 4,
            "Invalid bounded artwork");
    for (std::size_t offset = 0; offset < pixels.size(); offset += maximum_payload) {
        const auto count = std::min(maximum_payload, pixels.size() - offset);
        send(Operation::icon_pixels, {pixels.begin() + offset, pixels.begin() + offset + count});
    }
    send(Operation::finished, {});
    return 0;
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    _set_error_mode(_OUT_TO_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    try {
        verify_metadata_process(GetCurrentProcess()); // Refuse direct/full-trust entry before handle parsing.
        require(argc == 6 && std::wstring_view(argv[1]) == L"--isolated-metadata" &&
                    std::wstring_view(argv[4]) == metadata_profile && std::wstring_view(argv[5]) == L"1",
                "Invalid service arguments");
        PSID sid = nullptr;
        require(SUCCEEDED(DeriveAppContainerSidFromAppContainerName(metadata_profile, &sid)),
                "Cannot derive metadata identity");
        struct Free {
            PSID sid;
            ~Free() { FreeSid(sid); }
        } free{sid};
        verify_metadata_process(GetCurrentProcess(), sid);
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
                "Unexpected metadata job policy");
        require(SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) != FALSE,
                "Cannot restrict DLL search");
        aether::host::UniqueHandle reader(reinterpret_cast<HANDLE>(std::stoull(argv[2])));
        aether::host::UniqueHandle writer(reinterpret_cast<HANDLE>(std::stoull(argv[3])));
        require(reader && writer && reader.get() != writer.get() &&
                    GetFileType(reader.get()) == FILE_TYPE_PIPE &&
                    GetFileType(writer.get()) == FILE_TYPE_PIPE,
                "Invalid inherited transport");
        return run(reader.get(), writer.get());
    } catch (const std::exception &error) {
        std::cerr << "AETHER_ICON_WORKER_FAILED: " << error.what() << '\n';
        return 1;
    }
}
