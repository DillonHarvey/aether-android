#pragma once
#include <Windows.h>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace aether::shell {
struct IconQueueStats {
    std::uint32_t pending = 0, active = 0, peak_pending = 0, peak_active = 0;
    std::uint64_t accepted = 0, completed = 0, failed = 0, coalesced = 0, rejected = 0;
};
class IconQueue final {
  public:
    explicit IconQueue(std::function<void(const std::wstring &)> processor);
    ~IconQueue();
    IconQueue(const IconQueue &) = delete;
    IconQueue &operator=(const IconQueue &) = delete;
    bool submit(std::wstring path);
    IconQueueStats stats() const;
    void stop();

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
// The endpoint is bound to the current Windows user/session. A nonempty suffix
// is only used by independent native tests, never supplied by an archive or DLL.
std::wstring icon_endpoint(std::wstring_view suffix = {});
enum class IconMessage : std::uint32_t { enqueue = 1, stop = 2, ping = 3 };
// Background-thread API only. Connect, payload and acknowledgement are bounded.
bool send_icon_message(const std::wstring &endpoint, IconMessage kind, std::wstring_view path = {});
enum class IconStopResult { not_running, stopped, different_runtime, unavailable };
// Installer-only shutdown: authenticate the peer, compare its actual image with
// the selected runtime, stop over that same connection, then wait for that exact
// process handle. A different runtime is never stopped and no process is killed.
IconStopResult stop_icon_service(const std::wstring &endpoint, const std::filesystem::path &executable);
// An idle server exits after 60 seconds, or on its own stop event/authenticated
// stop message. The single client receiver never performs metadata extraction.
void serve_icon_requests(const std::wstring &endpoint, IconQueue &queue, HANDLE stop_event,
                         const std::function<void(std::string_view)> &refusal = {});
} // namespace aether::shell
