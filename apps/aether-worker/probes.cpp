#include "probes.hpp"
#include "aether/common/text.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace aether::security {
std::array<DWORD, 16> runtime_image_probe() {
    std::array<wchar_t, 32768> buffer{};
    const auto size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (!size || size >= buffer.size())
        throw ProtocolError("Cannot locate the running worker image");
    const std::filesystem::path image(std::wstring(buffer.data(), size));
    const auto attempt = [](const std::filesystem::path &path, DWORD access, bool directory) {
        host::UniqueHandle file(CreateFileW(
            path.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0),
            nullptr));
        return file ? ERROR_SUCCESS : GetLastError();
    };
    std::array<DWORD, 16> errors{};
    errors[0] = attempt(image, GENERIC_READ | GENERIC_EXECUTE, false);
    constexpr std::array<DWORD, 8> rights{FILE_WRITE_DATA,       FILE_APPEND_DATA, FILE_WRITE_EA,
                                          FILE_WRITE_ATTRIBUTES, DELETE,           WRITE_DAC,
                                          WRITE_OWNER,           FILE_DELETE_CHILD};
    for (std::size_t i = 0; i < rights.size() - 1; ++i)
        errors[i + 1] = attempt(image, rights[i], false);
    for (std::size_t i = 0; i < rights.size(); ++i)
        errors[i + 8] = attempt(image.parent_path(), rights[i], true);
    if (errors[0] != ERROR_SUCCESS || std::any_of(errors.begin() + 1, errors.end(),
                                                  [](DWORD error) { return error != ERROR_ACCESS_DENIED; }))
        throw ProtocolError("Worker runtime image/directory permission probe failed");
    return errors;
}
namespace {
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(std::string("AETHER_RESOURCE_PROBE: ") + message);
}
void result(HANDLE writer, std::uint64_t session, Operation operation,
            std::initializer_list<std::uint64_t> values) {
    Frame frame{{operation, 2, session, static_cast<std::uint32_t>(values.size() * 8), Status::ok}, {}};
    for (auto value : values)
        append_u64(frame.payload, value);
    write_pipe_frame(writer, frame);
}
DWORD excluded_handle_error(HANDLE handle) {
    // Windows strict-handle policy can raise instead of returning ERROR_INVALID_HANDLE.
    // Catch only that precise expected outcome in this compiled hostile-handle fixture.
    __try {
        DWORD flags = 0;
        return GetHandleInformation(handle, &flags) ? ERROR_SUCCESS : GetLastError();
    } __except (GetExceptionCode() == 0xC0000008u ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return ERROR_INVALID_HANDLE;
    }
}
DWORD child_attempt(const std::wstring &path, DWORD extra_flags) {
    auto command = L"\"" + path + L"\" /d /c exit 0";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    const bool created = CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, FALSE,
                                        CREATE_SUSPENDED | DETACHED_PROCESS | extra_flags, nullptr, nullptr,
                                        &startup, &child) != FALSE;
    const auto error = created ? ERROR_SUCCESS : GetLastError();
    if (created) {
        host::UniqueHandle process(child.hProcess), thread(child.hThread);
        // An unexpected child must never execute, even when the tested restriction fails.
        require(TerminateProcess(process.get(), 1) &&
                    WaitForSingleObject(process.get(), 5000) == WAIT_OBJECT_0,
                "Cannot contain unexpected suspended child");
    }
    if (created || (error != ERROR_ACCESS_DENIED && error != ERROR_NOT_ENOUGH_QUOTA))
        throw ProtocolError("Child creation was not denied: created=" + std::to_string(created) +
                            "; Windows error=" + std::to_string(error));
    return error;
}
int network_attempt(int family, std::uint16_t port) {
    const auto socket_value = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (socket_value == INVALID_SOCKET) {
        const auto error = WSAGetLastError();
        require(error == WSAEACCES, "Unexpected socket creation failure");
        return error;
    }
    struct CloseSocket {
        SOCKET value;
        ~CloseSocket() { closesocket(value); }
    } owned{socket_value};
    u_long nonblocking = 1;
    require(ioctlsocket(socket_value, FIONBIO, &nonblocking) == 0, "Cannot bound socket connection");
    sockaddr_in ipv4{};
    ipv4.sin_family = AF_INET;
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ipv4.sin_port = htons(port);
    sockaddr_in6 ipv6{};
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_addr = in6addr_loopback;
    ipv6.sin6_port = htons(port);
    const auto address = family == AF_INET ? reinterpret_cast<const sockaddr *>(&ipv4)
                                           : reinterpret_cast<const sockaddr *>(&ipv6);
    const auto size = family == AF_INET ? sizeof(ipv4) : sizeof(ipv6);
    const auto connected = connect(socket_value, address, static_cast<int>(size));
    int error = connected == 0 ? 0 : WSAGetLastError();
    if (error == WSAEWOULDBLOCK) {
        fd_set writes{}, failures{};
        FD_ZERO(&writes);
        FD_ZERO(&failures);
        FD_SET(socket_value, &writes);
        FD_SET(socket_value, &failures);
        timeval timeout{3, 0};
        require(select(0, nullptr, &writes, &failures, &timeout) > 0, "Network denial was not explicit");
        int length = sizeof(error);
        require(getsockopt(socket_value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&error), &length) ==
                    0,
                "Cannot observe network result");
    }
    require(error == WSAEACCES, "Loopback connection was not access-denied");
    return error;
}
void resources(HANDLE reader, HANDLE writer, std::uint64_t session) {
    const auto frame = read_pipe_frame(reader);
    require(frame.header.operation == Operation::observation && frame.header.sequence == 1 &&
                frame.header.session == session && frame.header.status == Status::ok &&
                frame.payload.size() >= 32,
            "Invalid resource probe setup");
    const auto inherited = read_u64(frame.payload, 0);
    const auto port4 = read_u64(frame.payload, 8), port6 = read_u64(frame.payload, 16);
    require(inherited && port4 && port4 <= 65535 && port6 && port6 <= 65535,
            "Invalid controlled resource identity");
    std::size_t offset = 24;
    const auto registry = utf16(read_text(frame.payload, offset, 512));
    const auto event = utf16(read_text(frame.payload, offset, 256));
    const auto child = utf16(read_text(frame.payload, offset, 512));
    require(offset == frame.payload.size(), "Trailing resource probe setup");
    const auto checkpoint = [&](std::uint64_t step) {
        Frame progress{{Operation::observation, 1, session, 8, Status::ok}, {}};
        append_u64(progress.payload, step);
        write_pipe_frame(writer, progress);
    };
    checkpoint(0);
    std::array<std::uint64_t, 2> registry_errors{};
    std::size_t index = 0;
    for (const auto access : {KEY_QUERY_VALUE, KEY_SET_VALUE}) {
        HKEY key = nullptr;
        const auto error = RegOpenKeyExW(HKEY_USERS, registry.c_str(), 0, access, &key);
        if (key)
            RegCloseKey(key); // Never read or write after an unexpected open.
        require(error == ERROR_ACCESS_DENIED, "Controlled registry access was not denied");
        registry_errors[index++] = static_cast<std::uint64_t>(error);
    }
    checkpoint(1);
    const auto inherited_error = excluded_handle_error(reinterpret_cast<HANDLE>(inherited));
    require(inherited_error == ERROR_INVALID_HANDLE, "Unlisted parent handle was inherited");
    checkpoint(2);
    host::UniqueHandle named(OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, event.c_str()));
    const auto event_error = named ? ERROR_SUCCESS : GetLastError();
    require(!named && (event_error == ERROR_ACCESS_DENIED || event_error == ERROR_FILE_NOT_FOUND),
            "Host named event was accessible");
    checkpoint(3);
    const auto child_error = child_attempt(child, 0);
    checkpoint(4);
    const auto breakaway_error = child_attempt(child, CREATE_BREAKAWAY_FROM_JOB);
    checkpoint(5);
    WSADATA data{};
    const auto startup_error = WSAStartup(MAKEWORD(2, 2), &data);
    require(startup_error == 0 || startup_error == WSASYSNOTREADY || startup_error == WSASYSCALLFAILURE ||
                startup_error == WSAEACCES,
            "Unexpected Winsock startup failure");
    struct CleanupWinsock {
        bool initialized;
        ~CleanupWinsock() {
            if (initialized)
                WSACleanup();
        }
    } winsock{startup_error == 0};
    checkpoint(6);
    const auto network4 = startup_error ? 0 : network_attempt(AF_INET, static_cast<std::uint16_t>(port4));
    checkpoint(7);
    const auto network6 = startup_error ? 0 : network_attempt(AF_INET6, static_cast<std::uint16_t>(port6));
    checkpoint(8);
    result(writer, session, Operation::finished,
           {registry_errors[0], registry_errors[1], inherited_error, event_error, child_error,
            breakaway_error, static_cast<std::uint64_t>(network4), static_cast<std::uint64_t>(network6),
            static_cast<std::uint64_t>(startup_error), startup_error == 0 ? 2u : 0u});
}
void memory(HANDLE writer, std::uint64_t session) {
    constexpr SIZE_T block_size = 1024 * 1024;
    struct Allocations {
        std::array<void *, 256> blocks{};
        ~Allocations() {
            for (auto block : blocks)
                if (block)
                    VirtualFree(block, 0, MEM_RELEASE);
        }
    } allocations;
    std::uint64_t count = 0;
    DWORD error = 0;
    for (auto &block : allocations.blocks) {
        block = VirtualAlloc(nullptr, block_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!block) {
            error = GetLastError();
            break;
        }
        // Commit and touch each page; this is actual private memory pressure.
        auto bytes = static_cast<volatile std::uint8_t *>(block);
        for (SIZE_T offset = 0; offset < block_size; offset += 4096)
            bytes[offset] = 0xA7;
        ++count;
    }
    require(count >= 32 && count < allocations.blocks.size() &&
                (error == ERROR_NOT_ENOUGH_MEMORY || error == ERROR_COMMITMENT_LIMIT),
            "Allocation did not reach a measured memory ceiling");
    std::uint64_t failures = 1;
    for (unsigned attempt = 0; attempt < 63; ++attempt) {
        auto block = VirtualAlloc(nullptr, block_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        const auto repeat_error = block ? ERROR_SUCCESS : GetLastError();
        if (block)
            VirtualFree(block, 0, MEM_RELEASE);
        require(!block && repeat_error == error, "Memory ceiling did not hold under repeated pressure");
        ++failures;
    }
    for (auto &block : allocations.blocks) {
        if (block) {
            require(VirtualFree(block, 0, MEM_RELEASE), "Cannot release probe allocation");
            block = nullptr;
        }
    }
    auto recovered = VirtualAlloc(nullptr, block_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    require(recovered != nullptr, "Worker memory did not recover after release");
    *static_cast<volatile std::uint8_t *>(recovered) = 0xA7;
    require(VirtualFree(recovered, 0, MEM_RELEASE), "Cannot release recovery allocation");
    result(writer, session, Operation::finished, {count, count * block_size, error, failures, 1});
}
} // namespace
void run_resource_probe(HANDLE reader, HANDLE writer, std::uint64_t session, std::uint64_t scenario) {
    if (scenario == 18 || scenario == 19) {
        const auto permission = read_pipe_frame(reader);
        require(permission.header.operation == Operation::observation && permission.header.sequence == 1 &&
                    permission.header.session == session && permission.header.status == Status::ok &&
                    permission.payload.size() == 8 && read_u64(permission.payload, 0) == scenario,
                "Invalid exhaustion start checkpoint");
    }
    if (scenario == 17)
        resources(reader, writer, session);
    else if (scenario == 18)
        memory(writer, session);
    else if (scenario == 19) {
        result(writer, session, Operation::observation, {19});
        // No voluntary exit and no broker traffic: Windows must enforce cumulative user CPU.
        std::atomic<std::uint64_t> cycles{0};
        for (;;)
            cycles.fetch_add(1, std::memory_order_relaxed);
    } else
        throw ProtocolError("Unsupported compiled resource probe");
}
} // namespace aether::security
