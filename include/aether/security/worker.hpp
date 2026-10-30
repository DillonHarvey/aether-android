#pragma once
#include "aether/security/protocol.hpp"
#include "aether/security/worker_image.hpp"
#include <Windows.h>
#include <filesystem>
#include <chrono>
#include <memory>
#include <optional>
#include <ratio>
#include <string>

namespace aether::security {
class WorkerProgress;
// Transport deadlines measure awake Windows time, excluding system sleep and
// hibernation. This is independent of guest-visible clocks and timeout values.
struct AwakeDeadlineClock {
    using rep = std::int64_t;
    using period = std::ratio<1, 10'000'000>;
    using duration = std::chrono::duration<rep, period>;
    using time_point = std::chrono::time_point<AwakeDeadlineClock>;
    static constexpr bool is_steady = true;
    static time_point now() noexcept;
};
enum class WorkerRole { guest, graphics, metadata };
struct WorkerOptions {
    std::filesystem::path executable;
    std::wstring profile;
    bool less_privileged = true;
    std::uint32_t timeout_ms = 15000;
    bool exchange_deadlines = false; // Trusted host arms a deadline around each interactive exchange.
    WorkerRole role = WorkerRole::guest;
};
// Read from retained Windows process/job handles, never from worker messages.
struct WorkerAccounting {
    std::uint64_t user_time_100ns = 0;
    std::uint64_t kernel_time_100ns = 0;
    std::uint64_t peak_commit_bytes = 0;
    std::uint64_t memory_limit_bytes = 0;
    std::uint64_t user_time_limit_100ns = 0;
    std::uint32_t active_processes = 0;
    std::uint32_t total_processes = 0;
    std::uint32_t active_process_limit = 0;
    std::uint32_t limit_flags = 0;
    std::vector<std::uint32_t> active_process_ids;
};
// Throws before guest work if the actual Windows token differs from the policy.
// Token checks alone; callers must also verify their service-specific mitigation policy.
void verify_appcontainer_identity(HANDLE process, PSID expected_sid = nullptr,
                                  std::optional<bool> less_privileged = std::nullopt,
                                  std::span<PSID const> expected_capabilities = {});
void verify_isolated_process(HANDLE process, PSID expected_sid = nullptr,
                             std::optional<bool> less_privileged = std::nullopt);
// Dedicated service: LPAC, exactly registryRead, no guest translation or dynamic code/mitigation opt-outs.
void verify_graphics_process(HANDLE process, PSID expected_sid = nullptr);
// Metadata-only service: LPAC, zero Windows capabilities, dynamic code prohibited.
void verify_metadata_process(HANDLE process, PSID expected_sid = nullptr);
// Borrowed byte-pipe reader, one OS owner and no concurrent/blocking readers.
// Partial bytes remain in the pipe until an entire bounded frame is available.
class PipeFramePoller final {
  public:
    explicit PipeFramePoller(HANDLE reader, std::chrono::milliseconds timeout = std::chrono::milliseconds{15000});
    ~PipeFramePoller();
    PipeFramePoller(const PipeFramePoller &) = delete;
    PipeFramePoller &operator=(const PipeFramePoller &) = delete;
    std::optional<Frame> poll();
    void reset(); // After a successful blocking read consumed the same channel.
    std::optional<AwakeDeadlineClock::time_point> partial_deadline() const;
  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
Frame read_pipe_frame(HANDLE reader);
void write_pipe_frame(HANDLE writer, const Frame &frame);
// Fixed terminal diagnostic for a caught host std::bad_alloc; no heap allocation.
bool write_worker_allocation_failure(HANDLE writer, std::uint64_t session) noexcept;
// Parent-owned, synchronous single-request channel. A separate hard-deadline thread
// terminates the job even if the worker blocks a pipe operation. No full-trust fallback.
class WorkerProcess final {
  public:
    explicit WorkerProcess(const WorkerOptions &options);
    ~WorkerProcess();
    WorkerProcess(const WorkerProcess &) = delete;
    WorkerProcess &operator=(const WorkerProcess &) = delete;
    std::uint64_t duplicate_progress_mapping(const WorkerProgress &progress);
    void send(const Frame &frame);
    Frame receive();
    std::optional<Frame> try_receive_idle(); // Guest interactive idle only; arms exchange on a full frame.
    void begin_exchange();
    AwakeDeadlineClock::time_point exchange_deadline() const;
    void end_exchange();
    std::uint32_t wait();
    void terminate();
    void request_stop() noexcept; // Safe cross-thread cancellation while the owner retains this object.
    std::uint32_t process_id() const noexcept;
    WorkerImageAccess image_access() const noexcept;
    bool timed_out() const noexcept;
    WorkerAccounting accounting() const;

  private:
    friend class Broker;
    HANDLE primary_thread() const noexcept;
    std::uint64_t start_uptime_ticks() const noexcept;
    friend class GraphicsProcess;
    friend class IsolatedActivity;
    friend class MetadataProcess;
    std::uint64_t duplicate_package_mapping(HANDLE handle);
    std::uint64_t duplicate_metadata_mapping(HANDLE handle);
    std::uint64_t duplicate_graphics_handle(HANDLE handle);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::security
