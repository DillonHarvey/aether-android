#pragma once
#include "aether/host/file_service.hpp"
#include "aether/security/protocol.hpp"
#include <array>
#include <memory>

namespace aether::security {
struct AuditEntry {
    std::uint64_t app_id, sequence;
    Operation operation;
    Status status;
    std::uint32_t payload_bytes;
    host::FileError file_error = host::FileError::none;
    std::uint32_t audio_error = 0;
    std::uint32_t graphics_operation = UINT32_MAX;
};
struct AuditContext {
    std::uint64_t app_id = 0, session = 0;
    std::uint32_t capabilities = 0, parent_process = 0, worker_process = 0;
    bool operator==(const AuditContext &) const = default;
};
enum class AuditKind : std::uint32_t { start = 1, intent, outcome, end };
inline constexpr std::size_t audit_record_bytes = 168;
inline constexpr std::uint64_t audit_request_limit = 3000;
using AuditDigest = std::array<std::uint8_t, 32>;
struct AuditRecord {
    AuditKind kind = AuditKind::start;
    std::uint64_t index = 0, utc_100ns = 0, received_session = 0;
    AuditContext context;
    AuditEntry entry{};
    std::uint32_t flags = 0; // Outcome: uncertainty. End: aborted and/or outstanding intent.
    AuditDigest previous{}, digest{};
};
std::array<std::uint8_t, audit_record_bytes> encode_audit_record(const AuditRecord &record);
AuditRecord decode_audit_record(std::span<const std::uint8_t> bytes);
struct AuditSummary {
    AuditContext context;
    std::uint64_t records = 0, intents = 0, outcomes = 0, first_utc_100ns = 0;
    bool ended = false, pending = false, aborted = false;
    AuditDigest digest{};
};
// Reject corruption/truncation; an intact file without an end record is explicitly unfinished.
AuditSummary inspect_audit(std::span<const std::uint8_t> bytes);
class AuditWriter {
  public:
    virtual ~AuditWriter() = default;
    virtual void open(const AuditContext &context) = 0;
    // Success means this complete record has been persisted, not merely queued.
    virtual void append(std::span<const std::uint8_t> record) = 0;
    virtual std::filesystem::path path() const = 0;
};
class AuditTicket final {
  public:
    AuditTicket() = default;

  private:
    std::uint64_t value_ = 0;
    std::uint64_t trail_ = 0;
    AuditTicket(std::uint64_t value, std::uint64_t trail) : value_(value), trail_(trail) {}
    friend class AuditTrail;
};
// Exactly one bounded request may be outstanding. begin/complete/finish perform I/O;
// claim/note only access memory, allowing a UI-owned provider between durable records.
class AuditTrail final {
  public:
    explicit AuditTrail(std::unique_ptr<AuditWriter> writer);
    ~AuditTrail();
    AuditTrail(const AuditTrail &) = delete;
    AuditTrail &operator=(const AuditTrail &) = delete;
    void configure(std::uint64_t app_id, std::uint64_t session, std::uint32_t capabilities);
    void bind_worker(std::uint32_t process_id);
    AuditTicket begin(const Frame &request);
    void claim(AuditTicket ticket, const Frame &request);
    void note(AuditTicket ticket, const AuditEntry &entry);
    void complete(AuditTicket ticket);
    void finish(bool aborted = false);
    void finish_aborted() noexcept; // I/O owner only; best-effort footer, never retry a failed append.
    std::filesystem::path path() const;
    std::string json() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
// Files are final app audit artifacts: protected broker-only roots, 16 retained
// sessions per app, one MiB per file, no overwrite/repair of incomplete records.
std::shared_ptr<AuditTrail> make_file_audit(const std::filesystem::path &parent);
std::shared_ptr<AuditTrail> make_file_audit_at_root(const std::filesystem::path &root);
} // namespace aether::security
