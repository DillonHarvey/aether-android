#pragma once
#include "aether/host/file_service.hpp"
#include "aether/host/time_service.hpp"
#include "aether/security/audio_broker.hpp"
#include "aether/security/audit.hpp"
#include "aether/security/graphics_service.hpp"
#include "aether/security/protocol.hpp"
#include <chrono>
#include <map>
#include <vector>

namespace aether::security {
class WorkerProcess;
struct BrokerPolicy {
    std::uint64_t app_id = 0, session = 0;
    bool monotonic_time = false;
    std::uint32_t request_limit = 64;
    bool private_storage = false;
    bool interactive = false;
    bool audio_playback = false;
    bool graphics = false;
    bool wall_time = false;
};
// Each instance belongs to exactly one parent-verified process and inherited channel.
// No request supplies an app identity, host path/address or function name.
class Broker final {
  public:
    explicit Broker(BrokerPolicy policy, std::shared_ptr<AuditTrail> journal,
                    std::unique_ptr<host::FileService> files = {}, std::vector<std::uint8_t> package = {},
                    std::unique_ptr<host::AudioService> audio = {}, bool retain_fixture_pcm = false,
                    std::unique_ptr<GraphicsService> graphics = {});
    ~Broker();
    Frame dispatch(const Frame &request);
    Frame dispatch_idle(const Frame &request); // Interactive only; independent absolute one-second quota.
    Frame dispatch_prepared(const Frame &request, AuditTicket ticket); // No audit file I/O on this thread.
    void bind_worker_thread(const WorkerProcess &worker); // Trusted setup, before any request.
    void close() noexcept;
    void revoke_storage() noexcept;
    void revoke_audio() noexcept { audio_.revoke(); }
    void revoke_graphics() noexcept;
    const AudioBroker &audio() const noexcept { return audio_; }
    void begin_turn(); // Trusted host only, after completing the preceding UI exchange.
    std::uint64_t total_requests() const noexcept { return total_requests_; }
    const std::vector<AuditEntry> &audit() const noexcept { return audit_; }
    bool closed() const noexcept { return closed_; }

  private:
    BrokerPolicy policy_;
    const std::shared_ptr<AuditTrail> journal_;
    host::HostTimeService time_;
    std::vector<AuditEntry> audit_;
    std::uint64_t next_sequence_ = 1;
    std::uint64_t total_requests_ = 0;
    std::uint32_t turn_requests_ = 0;
    bool closed_ = false;
    bool idle_dispatch_ = false, executing_ = false;
    std::uint32_t idle_requests_ = 0;
    std::chrono::steady_clock::time_point idle_window_start_{};
    std::unique_ptr<host::FileService> files_;
    std::map<std::uint64_t, int> descriptors_;
    struct FilePathLedger;
    std::unique_ptr<FilePathLedger> file_paths_;
    const std::vector<std::uint8_t> package_;
    const std::string package_hash_;
    AudioBroker audio_;
    std::unique_ptr<GraphicsService> graphics_;
    void revoke_all() noexcept;
    Frame execute(const Frame &request, AuditTicket ticket);
    host::FileResult file_request(const Frame &request, Frame &response);
};
} // namespace aether::security
