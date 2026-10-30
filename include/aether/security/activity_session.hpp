#pragma once
#include "aether/security/activity_protocol.hpp"
#include "aether/security/installed_activity.hpp"
#include "aether/security/worker.hpp"
#include "aether/host/windows/document_service.hpp"
#include <functional>

namespace aether::host { class ClipboardWindowContext; }

namespace aether::security {
struct ActivityLaunch;
// Synchronous borrowed record on the I/O owner. Receipt must finish within the
// already armed exchange deadline; the sink cannot extend transport authority.
using ActivityTextEditSink =
    std::function<void(const android::TextEditObservation &, std::uint64_t, AwakeDeadlineClock::time_point)>;
using ActivitySoftInputSink =
    std::function<bool(const android::SoftInputObservation &, std::uint64_t, AwakeDeadlineClock::time_point)>;
using ActivityTerminalActivationSink =
    std::function<void(const ActivityTerminalActivations &, std::uint64_t, AwakeDeadlineClock::time_point)>;
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
enum class ActivityMode { normal, read_recovery_probe, exit_zero_probe, exit_255_probe, abort_probe, allocation_failure_probe };
// Synchronous connection owned by one host I/O thread. Presentation and execution
// remain separate; ActivityDispatcher publishes immutable state to the HWND owner.
class IsolatedActivity final {
  public:
    // Optional trusted developer output root; never changes APK admission or worker lookup.
    // Empty preserves the installation-local developer storage and audit paths.
    explicit IsolatedActivity(const std::filesystem::path &apk, ActivityMode mode = ActivityMode::normal,
                              const std::filesystem::path &developer_output_root = {}, ActivityTextEditSink observer = {},
                              ActivitySoftInputSink soft_input_observer = {},
                              std::shared_ptr<host::ClipboardWindowContext> clipboard_window = {},
                              ActivityTerminalActivationSink terminal_activation_observer = {});
    explicit IsolatedActivity(InstalledActivity application, ActivityTextEditSink observer = {},
                              ActivitySoftInputSink soft_input_observer = {},
                              std::shared_ptr<host::ClipboardWindowContext> clipboard_window = {},
                              ActivityTerminalActivationSink terminal_activation_observer = {});
    ~IsolatedActivity();
    IsolatedActivity(const IsolatedActivity &) = delete;
    IsolatedActivity &operator=(const IsolatedActivity &) = delete;
    void signal(android::WindowSignal signal);
    void place_views(std::span<const android::ViewPlacement> placements);
    bool pointer(const android::PointerInput &input);
    bool key(const android::KeyInput &input);
    bool drop_file(const std::wstring &path); // Explicitly unsupported until real brokered document delivery exists
    void refresh();
    void close();
    void dispatch(const ActivityCommand &command);
    void drop_document(host::PreparedDocumentSource source, const ActivityCommand &command);
    void drop_text(std::u16string text, const ActivityCommand &command);
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
                           WorkerProgressWriter *progress = nullptr, bool audio_playback = false,
                           const ActivityLaunch *launch = nullptr);
} // namespace aether::security
