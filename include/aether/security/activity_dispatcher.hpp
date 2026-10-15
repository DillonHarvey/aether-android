#pragma once
#include "aether/security/activity_session.hpp"

namespace aether::security {
struct ActivityCompletion {
    std::uint64_t ticket = 0;
    ActivityCommandKind kind = ActivityCommandKind::refresh;
    bool handled = false, read_unavailable = false;
};
struct ActivityDispatchMetrics {
    std::uint64_t submitted = 0, completed = 0, read_requests = 0, coalesced_reads = 0;
    std::uint64_t read_failures = 0, recovered_reads = 0, peak_outstanding = 0;
    std::uint32_t io_thread = 0;
};
struct ActivityPublication {
    std::shared_ptr<const ActivityState> state, last_live;
    std::uint32_t process_id = 0;
    std::uint64_t commands = 0, broker_calls = 0;
    bool exited = false;
    std::string audit = "[]";
    std::string durable_audit = "{}";
};
// One serial I/O thread owns IsolatedActivity. The UI submits bounded commands and
// consumes completions without waiting on pipes. One read may be pending at a time.
class ActivityDispatcher final {
  public:
    explicit ActivityDispatcher(const std::filesystem::path &apk, ActivityMode mode = ActivityMode::normal);
    explicit ActivityDispatcher(InstalledActivity application);
    ~ActivityDispatcher();
    ActivityDispatcher(const ActivityDispatcher &) = delete;
    ActivityDispatcher &operator=(const ActivityDispatcher &) = delete;
    std::uint64_t submit(ActivityCommand command);
    void signal(android::WindowSignal value);
    void place_views(std::span<const android::ViewPlacement> placements);
    void pointer(const android::PointerInput &input);
    std::uint64_t key(const android::KeyInput &input);
    std::uint64_t refresh();
    void close();
    void abort() noexcept;
    HANDLE completion_event() const noexcept;
    void set_notification(HWND window, UINT message); // Host-only HWND; detached before destruction.
    // Called on the UI thread. Commits the latest immutable validated state and
    // returns ordered acknowledgements, including unhandled native key decisions.
    std::vector<ActivityCompletion> consume();
    bool idle() const;
    bool read_pending() const;
    ActivityDispatchMetrics dispatch_metrics() const;
    const ActivityPublication &publication() const noexcept;
    const ActivityState &snapshot() const;
    const auto &views() const { return snapshot().views; }
    const auto &metrics() const { return snapshot().framework; }
    auto content_view() const { return snapshot().content; }
    auto state() const { return snapshot().lifecycle; }
    std::uint32_t probe(std::string_view name) const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::security
