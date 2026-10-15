#include "aether/security/audit.hpp"
#include "aether/apk/inspect.hpp"
#include "aether/common/text.hpp"
#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <optional>
#include <sstream>

namespace aether::security {
namespace {
std::atomic<std::uint64_t> next_trail{1};
void require(bool valid, const char *message) {
    if (!valid)
        throw ProtocolError(std::string("AETHER_AUDIT: ") + message);
}
void put(std::span<std::uint8_t> bytes, std::size_t offset, std::uint64_t value, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i)
        bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
}
std::uint64_t get(std::span<const std::uint8_t> bytes, std::size_t offset, std::size_t width) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i)
        value |= static_cast<std::uint64_t>(bytes[offset + i]) << (i * 8);
    return value;
}
AuditDigest digest(std::span<const std::uint8_t> bytes) {
    const auto text = apk::sha256(bytes);
    AuditDigest result{};
    const auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    for (std::size_t i = 0; i < result.size(); ++i)
        result[i] = static_cast<std::uint8_t>(digit(text[2 * i]) * 16 + digit(text[2 * i + 1]));
    return result;
}
std::string hex(const AuditDigest &bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string text;
    text.reserve(64);
    for (auto byte : bytes) {
        text += digits[byte >> 4];
        text += digits[byte & 15];
    }
    return text;
}
std::uint64_t now() {
    FILETIME time{};
    GetSystemTimePreciseAsFileTime(&time);
    return static_cast<std::uint64_t>(time.dwHighDateTime) << 32 | time.dwLowDateTime;
}
bool same_request(const Frame &one, const Frame &two) {
    return one.header.operation == two.header.operation && one.header.sequence == two.header.sequence &&
           one.header.session == two.header.session && one.header.payload_size == two.header.payload_size &&
           one.header.status == two.header.status && one.payload == two.payload;
}
bool same_identity(const AuditRecord &one, const AuditRecord &two) {
    return one.entry.app_id == two.entry.app_id && one.entry.sequence == two.entry.sequence &&
           one.entry.operation == two.entry.operation && one.entry.payload_bytes == two.entry.payload_bytes &&
           one.received_session == two.received_session;
}
void validate(const AuditRecord &record) {
    const auto &entry = record.entry;
    require(record.index && record.index <= 2 * audit_request_limit + 2 && record.utc_100ns &&
                record.context.app_id && record.context.session && record.context.parent_process &&
                record.context.capabilities <= 31 && entry.app_id == record.context.app_id &&
                static_cast<std::uint32_t>(entry.operation) <= UINT16_MAX,
            "Invalid record identity or bounds");
    require(static_cast<unsigned>(entry.file_error) <= static_cast<unsigned>(host::FileError::io) &&
                entry.audio_error <= 8 &&
                (entry.graphics_operation == UINT32_MAX || entry.graphics_operation < 54),
            "Invalid typed service metadata");
    if (record.kind == AuditKind::intent) {
        require(static_cast<std::uint32_t>(entry.status) == UINT32_MAX && record.flags == 0 &&
                    entry.file_error == host::FileError::none && entry.audio_error == 0 &&
                    entry.graphics_operation == UINT32_MAX,
                "Noncanonical intent");
    } else if (record.kind == AuditKind::outcome) {
        require(static_cast<unsigned>(entry.status) <= static_cast<unsigned>(Status::quota) &&
                    record.flags <= 1 && (!record.flags || entry.status == Status::invalid),
                "Invalid outcome");
    } else {
        require(record.kind == AuditKind::start || record.kind == AuditKind::end, "Unknown record kind");
        require(entry.sequence == 0 && static_cast<unsigned>(entry.operation) == 0 &&
                    entry.status == Status::ok && entry.payload_bytes == 0 &&
                    entry.file_error == host::FileError::none && entry.audio_error == 0 &&
                    entry.graphics_operation == UINT32_MAX && record.received_session == 0 &&
                    (record.kind == AuditKind::start ? record.flags == 0 : record.flags <= 3),
                "Noncanonical session record");
    }
}
} // namespace
std::array<std::uint8_t, audit_record_bytes> encode_audit_record(const AuditRecord &record) {
    validate(record);
    std::array<std::uint8_t, audit_record_bytes> bytes{};
    put(bytes, 0, 0x31554141, 4);
    put(bytes, 4, 1, 4);
    put(bytes, 8, static_cast<std::uint32_t>(record.kind), 4);
    put(bytes, 12, record.flags, 4);
    put(bytes, 16, record.index, 8);
    put(bytes, 24, record.utc_100ns, 8);
    put(bytes, 32, record.context.app_id, 8);
    put(bytes, 40, record.context.session, 8);
    put(bytes, 48, record.entry.sequence, 8);
    put(bytes, 56, record.received_session, 8);
    put(bytes, 64, static_cast<std::uint32_t>(record.entry.operation), 4);
    put(bytes, 68, static_cast<std::uint32_t>(record.entry.status), 4);
    put(bytes, 72, record.entry.payload_bytes, 4);
    put(bytes, 76, static_cast<std::uint32_t>(record.entry.file_error), 4);
    put(bytes, 80, record.entry.audio_error, 4);
    put(bytes, 84, record.entry.graphics_operation, 4);
    put(bytes, 88, record.context.capabilities, 4);
    put(bytes, 92, record.context.parent_process, 4);
    put(bytes, 96, record.context.worker_process, 4);
    std::copy(record.previous.begin(), record.previous.end(), bytes.begin() + 100);
    // Bytes 132..135 are reserved zeroes; the complete SHA-256 follows the body.
    const auto hash = digest(std::span(bytes).first(136));
    std::copy(hash.begin(), hash.end(), bytes.begin() + 136);
    return bytes;
}
AuditRecord decode_audit_record(std::span<const std::uint8_t> bytes) {
    require(bytes.size() == audit_record_bytes && get(bytes, 0, 4) == 0x31554141 && get(bytes, 4, 4) == 1,
            "Invalid record length, magic or version");
    const auto hash = digest(bytes.first(136));
    require(std::equal(hash.begin(), hash.end(), bytes.begin() + 136), "Record digest mismatch");
    AuditRecord record;
    record.kind = static_cast<AuditKind>(get(bytes, 8, 4));
    record.flags = static_cast<std::uint32_t>(get(bytes, 12, 4));
    record.index = get(bytes, 16, 8);
    record.utc_100ns = get(bytes, 24, 8);
    record.context = {get(bytes, 32, 8), get(bytes, 40, 8), static_cast<std::uint32_t>(get(bytes, 88, 4)),
                      static_cast<std::uint32_t>(get(bytes, 92, 4)),
                      static_cast<std::uint32_t>(get(bytes, 96, 4))};
    record.entry = {record.context.app_id,
                    get(bytes, 48, 8),
                    static_cast<Operation>(get(bytes, 64, 4)),
                    static_cast<Status>(get(bytes, 68, 4)),
                    static_cast<std::uint32_t>(get(bytes, 72, 4)),
                    static_cast<host::FileError>(get(bytes, 76, 4)),
                    static_cast<std::uint32_t>(get(bytes, 80, 4)),
                    static_cast<std::uint32_t>(get(bytes, 84, 4))};
    record.received_session = get(bytes, 56, 8);
    std::copy_n(bytes.begin() + 100, 32, record.previous.begin());
    record.digest = hash;
    validate(record);
    const auto canonical = encode_audit_record(record);
    require(std::equal(bytes.begin(), bytes.end(), canonical.begin()), "Noncanonical encoded record");
    return record;
}
AuditSummary inspect_audit(std::span<const std::uint8_t> bytes) {
    require(!bytes.empty() && bytes.size() <= 1024 * 1024 && bytes.size() % audit_record_bytes == 0,
            "Audit file is empty, oversized or truncated");
    AuditSummary summary;
    std::optional<AuditRecord> pending;
    for (std::size_t offset = 0; offset < bytes.size(); offset += audit_record_bytes) {
        const auto record = decode_audit_record(bytes.subspan(offset, audit_record_bytes));
        require(!summary.ended && record.index == summary.records + 1 && record.previous == summary.digest,
                "Audit chain is out of order or has trailing records");
        if (!summary.records) {
            require(record.kind == AuditKind::start, "Audit file lacks a start record");
            summary.context = record.context;
            summary.first_utc_100ns = record.utc_100ns;
        } else {
            require(record.context == summary.context, "Audit context changed within a file");
            if (record.kind == AuditKind::intent) {
                require(!pending && summary.intents < audit_request_limit,
                        "Overlapping or excessive intents");
                pending = record;
                ++summary.intents;
            } else if (record.kind == AuditKind::outcome) {
                require(pending && same_identity(*pending, record), "Outcome does not match its intent");
                pending.reset();
                ++summary.outcomes;
            } else {
                require(record.kind == AuditKind::end && ((record.flags & 2) != 0) == pending.has_value() &&
                            (!pending || (record.flags & 1)),
                        "Invalid end record");
                summary.ended = true;
                summary.aborted = (record.flags & 1) != 0;
            }
        }
        ++summary.records;
        summary.digest = record.digest;
    }
    summary.pending = pending.has_value();
    return summary;
}
struct AuditTrail::Impl {
    std::unique_ptr<AuditWriter> writer;
    const std::uint64_t identity = next_trail.fetch_add(1);
    mutable std::mutex mutex;
    AuditContext context;
    AuditDigest previous{};
    std::uint64_t records = 0, requests = 0, outcomes = 0;
    std::optional<Frame> request;
    std::optional<AuditEntry> outcome;
    std::uint64_t ticket = 0;
    DWORD io_thread = 0;
    bool configured = false, started = false, ended = false, failed = false, claimed = false;
    explicit Impl(std::unique_ptr<AuditWriter> value) : writer(std::move(value)) {
        require(writer != nullptr && identity,
                "Missing audit writer or exhausted identity; no unaudited fallback");
    }
    AuditRecord base(AuditKind kind) const {
        AuditRecord record;
        record.kind = kind;
        record.context = context;
        record.entry.app_id = context.app_id;
        record.entry.status = Status::ok;
        record.index = records + 1;
        record.utc_100ns = now();
        record.previous = previous;
        return record;
    }
    void append(AuditRecord record) {
        require(!failed && !ended, "Audit is terminal");
        try {
            const auto bytes = encode_audit_record(record);
            writer->append(bytes); // A failed/partial write is never retried.
            previous = digest(std::span(bytes).first(136));
            ++records;
        } catch (...) {
            failed = true;
            throw;
        }
    }
    void start() {
        require(configured && !ended && !failed, "Audit context is not available");
        require(!io_thread || io_thread == GetCurrentThreadId(), "Wrong audit I/O owner thread");
        if (!started) {
            io_thread = GetCurrentThreadId();
            try {
                writer->open(context);
                append(base(AuditKind::start));
                started = true;
            } catch (...) {
                failed = true;
                throw;
            }
        }
    }
    void check(AuditTicket value) const {
        require(!failed && !ended && request && value.value_ && value.value_ == ticket &&
                    value.trail_ == identity,
                "Foreign, stale or absent audit ticket");
    }
};
AuditTrail::AuditTrail(std::unique_ptr<AuditWriter> writer)
    : impl_(std::make_unique<Impl>(std::move(writer))) {}
AuditTrail::~AuditTrail() = default;
void AuditTrail::configure(std::uint64_t app_id, std::uint64_t session, std::uint32_t capabilities) {
    auto &p = *impl_;
    std::lock_guard lock(p.mutex);
    require(!p.configured && app_id && session && capabilities <= 31,
            "Audit context already bound or invalid");
    p.context = {app_id, session, capabilities, GetCurrentProcessId(), 0};
    p.configured = true;
}
void AuditTrail::bind_worker(std::uint32_t process_id) {
    auto &p = *impl_;
    std::lock_guard lock(p.mutex);
    require(p.configured && !p.started && !p.context.worker_process && process_id,
            "Invalid or repeated worker binding");
    p.context.worker_process = process_id;
    p.start();
}
AuditTicket AuditTrail::begin(const Frame &request) {
    auto &p = *impl_;
    std::lock_guard lock(p.mutex);
    require(!p.request && p.requests < audit_request_limit && request.payload.size() <= maximum_payload,
            "Outstanding request or audit capacity exhausted");
    p.start();
    // Keep an in-memory copy solely to bind authorization to exact request bytes.
    p.request = request;
    p.outcome.reset();
    p.claimed = false;
    auto record = p.base(AuditKind::intent);
    record.entry = {p.context.app_id, request.header.sequence, request.header.operation,
                    static_cast<Status>(UINT32_MAX), request.header.payload_size};
    record.received_session = request.header.session;
    p.append(record);
    p.ticket = record.index;
    ++p.requests;
    return AuditTicket(p.ticket, p.identity);
}
void AuditTrail::claim(AuditTicket ticket, const Frame &request) {
    auto &p = *impl_;
    std::lock_guard lock(p.mutex);
    p.check(ticket);
    require(!p.claimed && same_request(*p.request, request), "Audit intent does not authorize these bytes");
    p.claimed = true;
}
void AuditTrail::note(AuditTicket ticket, const AuditEntry &entry) {
    auto &p = *impl_;
    std::lock_guard lock(p.mutex);
    p.check(ticket);
    require(p.claimed && !p.outcome && entry.app_id == p.context.app_id &&
                entry.sequence == p.request->header.sequence &&
                entry.operation == p.request->header.operation &&
                entry.payload_bytes == p.request->header.payload_size,
            "Audit outcome does not match the claimed request");
    p.outcome = entry;
}
void AuditTrail::complete(AuditTicket ticket) {
    auto &p = *impl_;
    std::lock_guard lock(p.mutex);
    require(p.io_thread == GetCurrentThreadId(), "Wrong audit I/O owner thread");
    p.check(ticket);
    auto record = p.base(AuditKind::outcome);
    record.entry = p.outcome.value_or(AuditEntry{p.context.app_id, p.request->header.sequence,
                                                 p.request->header.operation, Status::invalid,
                                                 p.request->header.payload_size});
    record.received_session = p.request->header.session;
    record.flags = p.outcome ? 0u : 1u;
    p.append(record);
    ++p.outcomes;
    p.request.reset();
    p.outcome.reset();
}
void AuditTrail::finish(bool aborted) {
    auto &p = *impl_;
    std::lock_guard lock(p.mutex);
    require(p.io_thread == GetCurrentThreadId(), "Wrong audit I/O owner thread");
    require(p.started && !p.ended && !p.failed, "Cannot finish this audit");
    auto record = p.base(AuditKind::end);
    record.flags = (aborted || p.request ? 1u : 0u) | (p.request ? 2u : 0u);
    p.append(record);
    p.ended = true;
}
void AuditTrail::finish_aborted() noexcept {
    auto &p = *impl_;
    std::lock_guard lock(p.mutex);
    if (!p.started || p.ended || p.failed)
        return;
    try {
        require(p.io_thread == GetCurrentThreadId(), "Wrong audit I/O owner thread");
        auto record = p.base(AuditKind::end);
        record.flags = 1u | (p.request ? 2u : 0u);
        p.append(record);
        p.ended = true;
    } catch (...) {
        p.failed = true;
    }
}
std::filesystem::path AuditTrail::path() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->writer->path();
}
std::string AuditTrail::json() const {
    const auto &p = *impl_;
    std::lock_guard lock(p.mutex);
    std::ostringstream out;
    out << "{\"path\":" << json_quote(utf8(p.writer->path().wstring()))
        << ",\"session\":" << p.context.session << ",\"appId\":" << p.context.app_id
        << ",\"capabilities\":" << p.context.capabilities
        << ",\"parentProcessId\":" << p.context.parent_process
        << ",\"workerProcessId\":" << p.context.worker_process << ",\"ioThread\":" << p.io_thread
        << ",\"records\":" << p.records << ",\"intents\":" << p.requests << ",\"outcomes\":" << p.outcomes
        << ",\"ended\":" << (p.ended ? "true" : "false") << ",\"failed\":" << (p.failed ? "true" : "false")
        << ",\"pending\":" << (p.request ? "true" : "false")
        << ",\"chainSha256\":" << json_quote(hex(p.previous)) << '}';
    return out.str();
}
} // namespace aether::security
