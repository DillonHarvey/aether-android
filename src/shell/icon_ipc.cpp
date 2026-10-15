#include "aether/shell/icon_cache.hpp"
#include "aether/shell/icon_service.hpp"
#include "aether/shell/icons.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <sddl.h>
#include <stdexcept>
#include <vector>

namespace aether::shell {
namespace {
using host::UniqueHandle;
void require(bool condition, const char *message) {
    if (!condition)
        throw std::runtime_error(message);
}
std::vector<std::uint8_t> token_data(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
    DWORD bytes = 0;
    GetTokenInformation(token, kind, nullptr, 0, &bytes);
    require(bytes && bytes <= 65536, "AETHER_ICON_PEER: invalid token data extent");
    std::vector<std::uint8_t> data(bytes);
    require(GetTokenInformation(token, kind, data.data(), bytes, &bytes) != FALSE,
            "AETHER_ICON_PEER: cannot query token");
    return data;
}
UniqueHandle own_token() {
    HANDLE token = nullptr;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) != FALSE,
            "Cannot query icon-service user");
    return UniqueHandle(token);
}
DWORD token_word(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
    const auto data = token_data(token, kind);
    require(data.size() == sizeof(DWORD), "Invalid icon-peer token word");
    DWORD result = 0;
    std::memcpy(&result, data.data(), sizeof(result));
    return result;
}
std::wstring own_sid() {
    const auto token = own_token();
    const auto data = token_data(token.get(), TokenUser);
    LPWSTR raw = nullptr;
    require(ConvertSidToStringSidW(reinterpret_cast<const TOKEN_USER *>(data.data())->User.Sid, &raw) !=
                FALSE,
            "Cannot encode icon-service identity");
    std::wstring result(raw);
    LocalFree(raw);
    return result;
}
void verify_peer(HANDLE token) {
    const auto owner = own_token();
    const auto expected = token_data(owner.get(), TokenUser), actual = token_data(token, TokenUser);
    const auto level = token_data(token, TokenIntegrityLevel);
    const auto sid = reinterpret_cast<const TOKEN_MANDATORY_LABEL *>(level.data())->Label.Sid;
    require(EqualSid(reinterpret_cast<const TOKEN_USER *>(actual.data())->User.Sid,
                     reinterpret_cast<const TOKEN_USER *>(expected.data())->User.Sid) &&
                token_word(token, TokenSessionId) == token_word(owner.get(), TokenSessionId) &&
                token_word(token, TokenIsAppContainer) == 0 && IsValidSid(sid) &&
                *GetSidSubAuthorityCount(sid) > 0 &&
                *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1) >= SECURITY_MANDATORY_MEDIUM_RID,
            "AETHER_ICON_PEER: different user/session, AppContainer or low-integrity caller");
}
UniqueHandle verify_server(HANDLE pipe) {
    ULONG pid = 0;
    require(GetNamedPipeServerProcessId(pipe, &pid) != FALSE, "Cannot identify icon server");
    UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
    HANDLE raw = nullptr;
    require(process && OpenProcessToken(process.get(), TOKEN_QUERY, &raw), "Cannot query icon server");
    UniqueHandle token(raw);
    verify_peer(token.get());
    return process;
}
void verify_client(HANDLE pipe) {
    HANDLE raw = nullptr;
    {
        require(ImpersonateNamedPipeClient(pipe) != FALSE, "Cannot identify icon client");
        struct Revert {
            ~Revert() {
                if (!RevertToSelf())
                    std::terminate();
            }
        } revert;
        require(OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw) != FALSE,
                "Cannot query icon client");
    }
    UniqueHandle token(raw);
    // Only retain the query handle. Identification-level client impersonation
    // cannot be used to open the server's process token or access source files.
    verify_peer(token.get());
}
struct Pending {
    UniqueHandle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    OVERLAPPED overlapped{};
    Pending() {
        require(static_cast<bool>(event), "Cannot create bounded icon IPC event");
        overlapped.hEvent = event.get();
    }
    bool finish(HANDLE pipe, BOOL started, DWORD &count, DWORD timeout = 1000) {
        if (started)
            return true;
        if (GetLastError() != ERROR_IO_PENDING)
            return false;
        const auto ready = WaitForSingleObject(event.get(), timeout);
        if (ready != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &overlapped);
            GetOverlappedResult(pipe, &overlapped, &count, TRUE); // Drain the cancelled local NPFS operation.
            return false;
        }
        return GetOverlappedResult(pipe, &overlapped, &count, FALSE) != FALSE;
    }
};
std::uint32_t word(std::span<const std::uint8_t> bytes, std::size_t at) {
    require(at <= bytes.size() && bytes.size() - at >= 4, "Truncated icon request");
    std::uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i)
        value |= std::uint32_t(bytes[at + i]) << (8 * i);
    return value;
}
void put(std::vector<std::uint8_t> &out, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        out.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
}
} // namespace
std::wstring icon_endpoint(std::wstring_view suffix) {
    require(suffix.size() <= 64 && std::all_of(suffix.begin(), suffix.end(),
                                               [](wchar_t c) {
                                                   return (c >= L'a' && c <= L'z') ||
                                                          (c >= L'0' && c <= L'9') || c == L'.';
                                               }),
            "Invalid icon endpoint suffix");
    const auto sid = own_sid();
    const auto hash =
        icon_digest({reinterpret_cast<const std::uint8_t *>(sid.data()), sid.size() * sizeof(wchar_t)});
    const auto token = own_token();
    return L"\\\\.\\pipe\\Aether.IconCache.v2." + icon_hex(hash) + L"." +
           std::to_wstring(token_word(token.get(), TokenSessionId)) +
           (suffix.empty() ? L"" : L"." + std::wstring(suffix));
}
namespace {
UniqueHandle connect_icon_service(const std::wstring &endpoint) {
    UniqueHandle pipe(CreateFileW(endpoint.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                  FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                                  nullptr));
    if (!pipe && GetLastError() == ERROR_PIPE_BUSY && WaitNamedPipeW(endpoint.c_str(), 200))
        pipe.reset(CreateFileW(endpoint.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                               FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                               nullptr));
    return pipe;
}
bool exchange_icon_message(HANDLE pipe, IconMessage kind, std::wstring_view path) {
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr))
        return false;
    std::vector<std::uint8_t> bytes;
    put(bytes, 0x32504349); // ICP2, protocol version is inseparable from the endpoint and magic.
    put(bytes, static_cast<std::uint32_t>(kind));
    put(bytes, static_cast<std::uint32_t>(path.size()));
    for (auto unit : path) {
        bytes.push_back(static_cast<std::uint8_t>(unit));
        bytes.push_back(static_cast<std::uint8_t>(unit >> 8));
    }
    Pending write;
    DWORD count = 0;
    if (!write.finish(
            pipe, WriteFile(pipe, bytes.data(), static_cast<DWORD>(bytes.size()), &count, &write.overlapped),
            count) ||
        count != bytes.size())
        return false;
    Pending read;
    std::uint8_t acknowledgement = 0;
    if (!read.finish(pipe, ReadFile(pipe, &acknowledgement, 1, &count, &read.overlapped), count) ||
        count != 1 || acknowledgement > 1)
        return false;
    // Confirm receipt before the server disconnects: DisconnectNamedPipe can
    // otherwise discard a buffered acknowledgement. Never use an unbounded
    // server-side FlushFileBuffers to wait on an untrusted client.
    Pending confirm;
    const std::uint8_t received = 0xac;
    return confirm.finish(pipe, WriteFile(pipe, &received, 1, &count, &confirm.overlapped), count) &&
           count == 1 && acknowledgement == 1;
}
} // namespace
bool send_icon_message(const std::wstring &endpoint, IconMessage kind, std::wstring_view path) {
    try {
        if (path.size() > 32760 || (kind == IconMessage::enqueue && icon_input_path(path).empty()) ||
            (kind != IconMessage::enqueue && !path.empty()))
            return false;
        auto pipe = connect_icon_service(endpoint);
        if (!pipe)
            return false;
        const auto server = verify_server(pipe.get());
        return exchange_icon_message(pipe.get(), kind, path);
    } catch (...) {
        return false;
    }
}
IconStopResult stop_icon_service(const std::wstring &endpoint, const std::filesystem::path &executable) {
    try {
        if (!executable.is_absolute())
            return IconStopResult::unavailable;
        // Serialize with the DLL's background startup. Once registration is
        // removed, a waiting old DLL rechecks it before launching a new broker.
        PSECURITY_DESCRIPTOR raw = nullptr;
        const auto policy = L"D:P(A;;GA;;;SY)(A;;GA;;;" + own_sid() + L")";
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(policy.c_str(), SDDL_REVISION_1, &raw,
                                                                     nullptr) != FALSE,
                "Cannot create private icon startup policy");
        struct Release {
            PSECURITY_DESCRIPTOR value;
            ~Release() { LocalFree(value); }
        } release{raw};
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), raw, FALSE};
        const auto name = L"Local\\" + endpoint.substr(9) + L".Startup";
        UniqueHandle startup(CreateMutexW(&attributes, FALSE, name.c_str()));
        if (!startup)
            return IconStopResult::unavailable;
        const auto waited = WaitForSingleObject(startup.get(), 5000);
        if (waited != WAIT_OBJECT_0 && waited != WAIT_ABANDONED)
            return IconStopResult::unavailable;
        struct Unlock {
            HANDLE value;
            ~Unlock() { ReleaseMutex(value); }
        } unlock{startup.get()};
        auto pipe = connect_icon_service(endpoint);
        if (!pipe) {
            const auto error = GetLastError();
            return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND
                       ? IconStopResult::not_running
                       : IconStopResult::unavailable;
        }
        const auto process = verify_server(pipe.get());
        std::array<wchar_t, 32768> image{};
        DWORD size = static_cast<DWORD>(image.size());
        if (!QueryFullProcessImageNameW(process.get(), 0, image.data(), &size))
            return IconStopResult::unavailable;
        if (CompareStringOrdinal(image.data(), static_cast<int>(size), executable.c_str(), -1, TRUE) !=
            CSTR_EQUAL) {
            // Complete the harmless request so the other service is not left
            // waiting on an abandoned connection. It remains available.
            (void)exchange_icon_message(pipe.get(), IconMessage::ping, {});
            return IconStopResult::different_runtime;
        }
        if (GetProcessId(process.get()) == GetCurrentProcessId() ||
            !exchange_icon_message(pipe.get(), IconMessage::stop, {}))
            return IconStopResult::unavailable;
        pipe.reset();
        return WaitForSingleObject(process.get(), 10000) == WAIT_OBJECT_0 ? IconStopResult::stopped
                                                                          : IconStopResult::unavailable;
    } catch (...) {
        return IconStopResult::unavailable;
    }
}
void serve_icon_requests(const std::wstring &endpoint, IconQueue &queue, HANDLE stop_event,
                         const std::function<void(std::string_view)> &refusal) {
    PSECURITY_DESCRIPTOR raw = nullptr;
    const auto sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;" + own_sid() + L")";
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &raw,
                                                                 nullptr) != FALSE,
            "Cannot create private icon pipe policy");
    struct Release {
        PSECURITY_DESCRIPTOR p;
        ~Release() { LocalFree(p); }
    } release{raw};
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), raw, FALSE};
    UniqueHandle pipe(CreateNamedPipeW(
        endpoint.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 16, 65536,
        1000, &attributes));
    require(static_cast<bool>(pipe), "AETHER_ICON_SERVICE: endpoint unavailable or service already running");
    auto activity = GetTickCount64();
    while (WaitForSingleObject(stop_event, 0) == WAIT_TIMEOUT) {
        Pending connect;
        const auto connected = ConnectNamedPipe(pipe.get(), &connect.overlapped);
        const auto error = connected ? ERROR_SUCCESS : GetLastError();
        DWORD count = 0;
        bool ready = connected || error == ERROR_PIPE_CONNECTED;
        if (!ready && error == ERROR_IO_PENDING) {
            SetLastError(ERROR_IO_PENDING);
            ready = connect.finish(pipe.get(), FALSE, count, 500);
        }
        if (!ready) {
            DisconnectNamedPipe(pipe.get());
            const auto current = queue.stats();
            if (current.active || current.pending)
                activity = GetTickCount64();
            else if (GetTickCount64() - activity >= 60000)
                break;
            continue;
        }
        bool accepted = false, stop = false;
        try {
            std::array<std::uint8_t, 65536> buffer{};
            Pending read;
            require(read.finish(pipe.get(),
                                ReadFile(pipe.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &count,
                                         &read.overlapped),
                                count),
                    "Incomplete icon request");
            verify_client(pipe.get()); // Impersonation ends before any source/cache operation.
            const std::span<const std::uint8_t> bytes(buffer.data(), count);
            require(count >= 12 && word(bytes, 0) == 0x32504349 && word(bytes, 8) <= 32760 &&
                        count == 12 + word(bytes, 8) * 2,
                    "Invalid icon request envelope");
            const auto kind = static_cast<IconMessage>(word(bytes, 4));
            std::wstring path;
            for (std::size_t i = 12; i < bytes.size(); i += 2)
                path.push_back(static_cast<wchar_t>(bytes[i] | (unsigned(bytes[i + 1]) << 8)));
            if (kind == IconMessage::enqueue)
                accepted = queue.submit(std::move(path));
            else if (path.empty() && (kind == IconMessage::ping || kind == IconMessage::stop)) {
                accepted = true;
                stop = kind == IconMessage::stop;
            }
        } catch (const std::exception &error) {
            if (refusal)
                refusal(error.what());
            accepted = false;
        } catch (...) {
            accepted = false;
        }
        const std::uint8_t acknowledgement = accepted ? 1 : 0;
        Pending write;
        if (write.finish(pipe.get(), WriteFile(pipe.get(), &acknowledgement, 1, &count, &write.overlapped),
                         count)) {
            Pending confirm;
            std::uint8_t received = 0;
            confirm.finish(pipe.get(), ReadFile(pipe.get(), &received, 1, &count, &confirm.overlapped), count,
                           200);
        }
        DisconnectNamedPipe(pipe.get());
        activity = GetTickCount64();
        if (stop)
            break;
    }
}
} // namespace aether::shell
