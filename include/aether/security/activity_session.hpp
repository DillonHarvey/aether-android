#pragma once
#include "aether/security/activity_protocol.hpp"
#include "aether/security/installed_activity.hpp"
#include "aether/security/worker.hpp"

namespace aether::security {
class ActivityReadUnavailable final : public std::exception {
  public:
    const char *what() const noexcept override { return "AETHER_ACTIVITY_READ_UNAVAILABLE"; }
};
// Genuine Android process termination, including status zero before any Activity.
// Distinct from runtime refusal, Java failure and successful Activity startup.
class ActivityProcessExited final : public std::runtime_error {
  public:
    explicit ActivityProcessExited(std::uint8_t value)
        : std::runtime_error("AETHER_GUEST_EXIT: Android application exited with status " + std::to_string(value)),
          status(value) {}
    const std::uint8_t status;
};
enum class ActivityMode { normal, read_recovery_probe, exit_zero_probe, exit_255_probe };
// Synchronous connection owned by one host I/O thread. Presentation and execution
// remain separate; ActivityDispatcher publishes immutable state to the HWND owner.
class IsolatedActivity final {
  public:
    explicit IsolatedActivity(const std::filesystem::path &apk, ActivityMode mode = ActivityMode::normal);
    explicit IsolatedActivity(InstalledActivity application);
    ~IsolatedActivity();
    IsolatedActivity(const IsolatedActivity &) = delete;
    IsolatedActivity &operator=(const IsolatedActivity &) = delete;
    void signal(android::WindowSignal signal);
    void place_views(std::span<const android::ViewPlacement> placements);
    bool pointer(const android::PointerInput &input);
    bool key(const android::KeyInput &input);
    void refresh();
    void close();
    void dispatch(const ActivityCommand &command);
    bool service_background(); // Single I/O owner; no presentation command or publication.
    void cancel() noexcept; // Cross-thread abort only; never calls guest code or waits.
    const ActivityState &snapshot() const noexcept;
    const auto &views() const noexcept { return snapshot().views; }
    const auto &metrics() const noexcept { return snapshot().framework; }
    auto content_view() const noexcept { return snapshot().content; }
    auto state() const noexcept { return snapshot().lifecycle; }
    std::uint32_t probe(std::string_view name) const;
    std::uint32_t process_id() const noexcept;
    std::uint64_t command_count() const noexcept;
    std::uint64_t broker_calls() const noexcept;
    bool exited() const noexcept;
    std::string audit_json() const;
    std::string durable_audit_json() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
class WorkerProgressWriter;
// Called only after the executable has verified its own token and inherited channel.
// Return normal close zero or the genuine guest exit status; never call host ExitProcess.
std::uint8_t run_activity_worker(HANDLE reader, HANDLE writer, std::uint64_t session, std::uint64_t app_id,
                         bool read_recovery_probe = false, bool installed = false,
                         std::span<const std::uint8_t> mapped_package = {},
                         WorkerProgressWriter *progress = nullptr);
} // namespace aether::security
