#include "local_calendar.hpp"
#include "aether/security/broker.hpp"
#include "aether/security/worker.hpp"
#include "aether/apk/inspect.hpp"
#include <algorithm>
#include <atomic>
#include <bit>
#include <exception>

namespace aether::security {
namespace {
std::atomic<std::uint64_t> next_descriptor{1};
Status file_status(host::FileError error) {
    switch (error) {
    case host::FileError::none:
        return Status::ok;
    case host::FileError::denied:
        return Status::denied;
    case host::FileError::unsupported:
        return Status::unsupported;
    case host::FileError::descriptor_limit:
    case host::FileError::quota:
        return Status::quota;
    default:
        return Status::invalid;
    }
}
constexpr std::size_t file_transfer_limit = maximum_payload - 16;
std::string package_hash(const std::vector<std::uint8_t> &bytes) {
    return bytes.empty() ? std::string{} : apk::sha256(bytes);
}
} // namespace
Broker::Broker(BrokerPolicy policy, std::shared_ptr<AuditTrail> journal,
               std::unique_ptr<host::FileService> files, std::vector<std::uint8_t> package,
               std::unique_ptr<host::AudioService> audio, bool retain_fixture_pcm,
               std::unique_ptr<GraphicsService> graphics)
    : policy_(policy), journal_(std::move(journal)), files_(std::move(files)), package_(std::move(package)),
      package_hash_(package_hash(package_)),
      audio_(policy.audio_playback, std::move(audio), retain_fixture_pcm), graphics_(std::move(graphics)) {
    if (!policy_.app_id || !policy_.session || !policy_.request_limit || policy_.request_limit > 256)
        throw ProtocolError("AETHER_BROKER_POLICY: invalid identity or quota");
    if (policy_.private_storage && !files_)
        throw ProtocolError("AETHER_BROKER_POLICY: missing storage");
    if (policy_.graphics && !graphics_)
        throw ProtocolError("AETHER_BROKER_POLICY: missing graphics provider");
    if (!journal_)
        throw ProtocolError("AETHER_BROKER_POLICY: missing mandatory audit trail");
    journal_->configure(policy.app_id, policy.session,
                        (policy.monotonic_time ? 1u : 0u) | (policy.private_storage ? 2u : 0u) |
                            (policy.interactive ? 4u : 0u) | (policy.audio_playback ? 8u : 0u) |
                            (policy.graphics ? 16u : 0u) | (policy.wall_time ? 32u : 0u));
    audit_.reserve(policy_.request_limit + 1);
}
Broker::~Broker() { revoke_all(); }
void Broker::bind_worker_thread(const WorkerProcess &worker) {
    if (closed_ || total_requests_ || next_sequence_ != 1)
        throw ProtocolError("AETHER_BROKER_TIME: worker thread binding after requests refused");
    const auto ticks=worker.start_uptime_ticks();
    time_.bind_thread(worker.primary_thread(), worker.process_id(),
                      host::MonotonicTime{ticks/10'000'000,(ticks%10'000'000)*100});
}
void Broker::close() noexcept {
    closed_ = true;
    revoke_all();
}
void Broker::revoke_all() noexcept {
    time_.unbind_thread();
    revoke_storage();
    revoke_audio();
    revoke_graphics();
}
void Broker::revoke_graphics() noexcept {
    policy_.graphics = false;
    if (graphics_)
        graphics_->revoke();
}
void Broker::begin_turn() {
    if (!policy_.interactive || closed_ || executing_ || idle_dispatch_)
        throw ProtocolError("AETHER_BROKER_TURN: session does not accept interactive turns");
    turn_requests_ = 0;
}
void Broker::revoke_storage() noexcept {
    policy_.private_storage = false;
    for (const auto &[token, descriptor] : descriptors_) {
        (void)token;
        (void)files_->close(descriptor);
    }
    descriptors_.clear();
}
host::FileResult Broker::file_request(const Frame &request, Frame &response) {
    using host::FileError;
    using host::FileResult;
    if (!policy_.private_storage || !files_)
        return {-1, FileError::denied};
    if(request.header.operation==Operation::file_access) {
        if(request.payload.size()<24 || read_u64(request.payload,0)>3 || read_u64(request.payload,8)>7)return {-1,FileError::invalid};
        const auto scope=static_cast<host::FileAccessScope>(read_u64(request.payload,0));const auto mode=static_cast<std::uint32_t>(read_u64(request.payload,8));std::size_t offset=16;const auto name=read_text(request.payload,offset,127);
        if(offset!=request.payload.size() || !host::valid_file_access(scope,name,mode))return {-1,FileError::invalid};
        const auto result=files_->access(scope,name,mode);
        if((result.error==FileError::none && result.value!=0) || (result.error!=FileError::none && result.value!=-1))throw ProtocolError("AETHER_BROKER_STORAGE: invalid access result");return result;
    }
    if (request.header.operation == Operation::file_directory) {
        if (!request.payload.empty()) return {-1, FileError::invalid};
        std::vector<host::DirectoryEntry> entries;
        const auto result = files_->list_directory(entries);
        if (result.error != FileError::none) {
            if (result.value != -1 || !entries.empty())
                throw ProtocolError("AETHER_BROKER_DIRECTORY: invalid provider failure");
            return result;
        }
        if (result.value != static_cast<std::int64_t>(entries.size()))
            throw ProtocolError("AETHER_BROKER_DIRECTORY: inconsistent provider count");
        if (entries.size() > host::directory_entry_limit) return {-1, FileError::quota};
        std::vector<std::uint8_t> payload;
        append_u64(payload, entries.size());
        for (std::size_t i = 0; i < entries.size(); ++i) {
            const auto &entry = entries[i];
            if (!host::valid_directory_entry(entry))
                throw ProtocolError("AETHER_BROKER_DIRECTORY: invalid provider entry");
            for (std::size_t prior = 0; prior < i; ++prior)
                if (entries[prior].name == entry.name)
                    throw ProtocolError("AETHER_BROKER_DIRECTORY: duplicate provider entry");
            if (payload.size() > host::directory_payload_limit - 16 ||
                entry.name.size() + 17 > host::directory_payload_limit - 16 - payload.size())
                return {-1, FileError::quota};
            append_u64(payload, entry.inode);
            payload.push_back(entry.type);
            append_text(payload, entry.name);
        }
        response.payload.swap(payload);
        return result;
    }
    if (request.header.operation == Operation::file_data_observe) {
        if (request.payload.size() < 9) return {-1, FileError::invalid};
        std::size_t offset = 0;
        const auto name = read_text(request.payload, offset, 127);
        if (offset != request.payload.size()) return {-1, FileError::invalid};
        const auto result = files_->observe_data_file(name);
        if ((result.error == FileError::none && result.value != 1) ||
            (result.error != FileError::none && result.value != -1))
            throw ProtocolError("AETHER_BROKER_STORAGE: invalid app-data file observation result");
        return result;
    }
    if (request.header.operation == Operation::file_root) {
        if (!request.payload.empty())
            return {-1, FileError::invalid};
        const auto result = files_->private_root();
        if ((result.error == FileError::none && result.value != 0) ||
            (result.error != FileError::none && result.value != -1))
            throw ProtocolError("AETHER_BROKER_STORAGE: provider returned an invalid root result");
        return result;
    }
    if (request.header.operation == Operation::file_open) {
        if (request.payload.size() < 17)
            return {-1, FileError::invalid};
        const auto flags = read_u64(request.payload, 0);
        std::size_t offset = 8;
        const auto name = read_text(request.payload, offset, 127);
        if (offset != request.payload.size() || flags > 31 || !(flags & 3) || ((flags & 8) && !(flags & 4)) ||
            ((flags & 16) && !(flags & 2)))
            return {-1, FileError::invalid};
        if (descriptors_.size() >= 16)
            return {-1, FileError::descriptor_limit};
        const auto identity = next_descriptor.fetch_add(1);
        if (!identity || identity > UINT32_MAX)
            return {-1, FileError::quota};
        const auto result = files_->open(name, {(flags & 1) != 0, (flags & 2) != 0, (flags & 4) != 0,
                                                (flags & 8) != 0, (flags & 16) != 0});
        if (result.error != FileError::none)
            return result;
        const auto token = 0x2ee3000000000000ULL | identity;
        try {
            descriptors_.emplace(token, static_cast<int>(result.value));
        } catch (...) {
            (void)files_->close(static_cast<int>(result.value));
            throw;
        }
        return {static_cast<std::int64_t>(token), FileError::none};
    }
    if (request.payload.size() < 8)
        return {-1, FileError::invalid};
    const auto token = read_u64(request.payload, 0);
    const auto found = descriptors_.find(token);
    if (found == descriptors_.end())
        return {-1, FileError::bad_descriptor};
    const auto descriptor = found->second;
    if(request.header.operation==Operation::file_lock) {
        if(request.payload.size()!=16 || read_u64(request.payload,8)>UINT32_MAX || !host::valid_file_lock(static_cast<std::uint32_t>(read_u64(request.payload,8))))return {-1,FileError::invalid};
        const auto result=files_->lock(descriptor,static_cast<std::uint32_t>(read_u64(request.payload,8)));
        if((result.error==FileError::none && result.value!=0) || (result.error!=FileError::none && result.value!=-1))throw ProtocolError("AETHER_BROKER_STORAGE: invalid lock result");
        return result;
    }
    if (request.header.operation == Operation::file_flush) {
        if (request.payload.size() != 8)
            return {-1, FileError::invalid};
        const auto result = files_->flush(descriptor);
        if ((result.error == FileError::none && result.value != 0) ||
            (result.error != FileError::none && result.value != -1))
            throw ProtocolError("AETHER_BROKER_STORAGE: provider returned an invalid flush result");
        return result;
    }
    if (request.header.operation == Operation::file_close) {
        if (request.payload.size() != 8)
            return {-1, FileError::invalid};
        descriptors_.erase(found); // Never reuse or replay a close, even on Windows failure.
        return files_->close(descriptor);
    }
    if (request.header.operation == Operation::file_write) {
        const auto input = std::span(request.payload).subspan(8);
        if (input.size() > file_transfer_limit)
            return {-1, FileError::invalid};
        return files_->write(descriptor, input); // Exactly one write attempt.
    }
    if (request.payload.size() != 16 || read_u64(request.payload, 8) > file_transfer_limit)
        return {-1, FileError::invalid};
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(read_u64(request.payload, 8)));
    const auto result = files_->read(descriptor, bytes);
    if (result.error == FileError::none) {
        if (result.value < 0 || static_cast<std::uint64_t>(result.value) > bytes.size())
            throw ProtocolError("AETHER_BROKER_STORAGE: provider returned an invalid byte count");
        bytes.resize(static_cast<std::size_t>(result.value));
        response.payload = std::move(bytes);
    }
    return result;
}
Frame Broker::dispatch_idle(const Frame &request) {
    if (!policy_.interactive || closed_ || executing_ || idle_dispatch_) {
        close();
        throw ProtocolError("AETHER_BROKER_IDLE: idle dispatch requires an open interactive session without reentry");
    }
    idle_dispatch_ = true;
    struct Reset { bool &flag; ~Reset() { flag = false; } } reset{idle_dispatch_};
    return dispatch(request);
}
Frame Broker::dispatch(const Frame &request) {
    if (executing_) {
        close();
        throw ProtocolError("AETHER_BROKER_REENTRY: broker dispatch is already executing");
    }
    if (closed_)
        throw ProtocolError("AETHER_BROKER_CLOSED: session already terminated");
    try {
        const auto ticket = journal_->begin(request);
        Frame response;
        std::exception_ptr failure;
        try {
            response = dispatch_prepared(request, ticket);
        } catch (...) {
            failure = std::current_exception();
        }
        journal_->complete(ticket); // A result is never returned before its durable outcome.
        if (failure)
            std::rethrow_exception(failure);
        return response;
    } catch (...) {
        close();
        throw;
    }
}
Frame Broker::dispatch_prepared(const Frame &request, AuditTicket ticket) {
    if (executing_) {
        close();
        throw ProtocolError("AETHER_BROKER_REENTRY: broker dispatch is already executing");
    }
    executing_ = true;
    struct Reset { bool &flag; ~Reset() { flag = false; } } reset{executing_};
    try {
        if (closed_)
            throw ProtocolError("AETHER_BROKER_CLOSED: session already terminated");
        journal_->claim(ticket, request);
        return execute(request, ticket);
    } catch (...) {
        close();
        throw;
    }
}
Frame Broker::execute(const Frame &request, AuditTicket ticket) {
    if (closed_)
        throw ProtocolError("AETHER_BROKER_CLOSED: session already terminated");
    const auto &header = request.header;
    host::FileError file_error = host::FileError::none;
    std::uint32_t audio_error = 0, graphics_operation = UINT32_MAX;
    const auto record = [&](Status status) {
        if (policy_.interactive && audit_.size() == policy_.request_limit + 1)
            audit_.erase(audit_.begin());
        const AuditEntry entry{policy_.app_id,      header.sequence, header.operation, status,
                               header.payload_size, file_error,      audio_error,      graphics_operation};
        journal_->note(ticket, entry);
        audit_.push_back(entry);
        ++total_requests_;
    };
    if (header.session != policy_.session || header.sequence != next_sequence_ ||
        next_sequence_ == UINT64_MAX || header.status != Status::ok ||
        header.payload_size != request.payload.size() || header.payload_size > maximum_payload) {
        closed_ = true;
        record(Status::invalid);
        revoke_all();
        throw ProtocolError("AETHER_BROKER_IDENTITY: invalid session, sequence or envelope");
    }
    if (idle_dispatch_) {
        const auto now = std::chrono::steady_clock::now();
        if (!idle_requests_ || now - idle_window_start_ >= std::chrono::seconds(1)) {
            idle_window_start_ = now;
            idle_requests_ = 0;
        }
    }
    auto &requests = idle_dispatch_ ? idle_requests_ : turn_requests_;
    if (requests == policy_.request_limit) {
        closed_ = true;
        record(Status::quota);
        revoke_all();
        throw ProtocolError("AETHER_BROKER_QUOTA: request limit exceeded");
    }
    ++next_sequence_;
    ++requests;
    Frame response{{header.operation, header.sequence, policy_.session, 0, Status::denied}, {}};
    if (header.operation == Operation::monotonic_time || header.operation == Operation::uptime ||
        header.operation == Operation::elapsed_realtime || header.operation == Operation::thread_cpu ||
        header.operation == Operation::process_start_uptime) {
        if (!request.payload.empty()) {
            response.header.status = Status::invalid;
        } else if (policy_.monotonic_time) {
            host::MonotonicTime time{};
            const auto status = header.operation == Operation::uptime ? time_.read_uptime(time) :
                header.operation == Operation::elapsed_realtime ? time_.read_elapsed_realtime(time) :
                header.operation == Operation::thread_cpu ? time_.read_thread_cpu(time) :
                header.operation == Operation::process_start_uptime ? time_.read_process_start_uptime(time) : time_.read_monotonic(time);
            if (status != host::TimeStatus::ok) {
                closed_ = true;
                record(Status::invalid);
                revoke_all();
                throw ProtocolError("AETHER_BROKER_TIME: Windows clock failed");
            }
            append_u64(response.payload, time.seconds);
            append_u64(response.payload, time.nanoseconds);
            response.header.status = Status::ok;
        }
    } else if (header.operation == Operation::wall_time) {
        if (!request.payload.empty()) {
            response.header.status = Status::invalid;
        } else if (policy_.wall_time) {
            host::EpochTime time{};
            if (time_.read_wall_time(time) != host::TimeStatus::ok || time.nanoseconds >= 1'000'000'000) {
                closed_ = true;
                record(Status::invalid);
                revoke_all();
                throw ProtocolError("AETHER_BROKER_TIME: Windows UTC clock failed");
            }
            append_u64(response.payload, std::bit_cast<std::uint64_t>(time.seconds));
            append_u64(response.payload, time.nanoseconds);
            response.header.status = Status::ok;
        }
    } else if (header.operation == Operation::local_calendar) {
        if(request.payload.size()!=8)response.header.status=Status::invalid;
        else if(policy_.wall_time){
            host::LocalTime value;
            const auto status=time_.convert_local_time(std::bit_cast<std::int64_t>(read_u64(request.payload,0)),value);
            if(status==host::TimeStatus::ok){if(!host::local_time_matches_epoch(value,std::bit_cast<std::int64_t>(read_u64(request.payload,0))))throw ProtocolError("AETHER_BROKER_TIME: inconsistent local calendar");append_local_calendar(response.payload,value);response.header.status=Status::ok;}
            else response.header.status=status==host::TimeStatus::out_of_range?Status::invalid:Status::unsupported;
        }
    } else if ((header.operation >= Operation::file_open && header.operation <= Operation::file_close) ||
               header.operation == Operation::file_root || header.operation == Operation::file_flush || header.operation == Operation::file_lock || header.operation == Operation::file_access ||
               header.operation == Operation::file_data_observe || header.operation == Operation::file_directory) {
        host::FileResult result;
        try {
            result = file_request(request, response);
        } catch (const ProtocolError &) {
            result = {-1, host::FileError::invalid};
            response.payload.clear();
        } catch (...) {
            closed_ = true;
            record(Status::invalid);
            revoke_all();
            throw;
        }
        file_error = result.error;
        response.header.status = file_status(result.error);
        std::vector<std::uint8_t> payload;
        append_u64(payload, std::bit_cast<std::uint64_t>(result.value));
        append_u64(payload, static_cast<std::uint64_t>(result.error));
        payload.insert(payload.end(), response.payload.begin(), response.payload.end());
        response.payload = std::move(payload);
    } else if (header.operation >= Operation::audio_open && header.operation <= Operation::audio_close) {
        try {
            response = audio_.dispatch(request);
            if (response.header.status != Status::ok)
                audio_error = 1 + static_cast<std::uint32_t>(read_u64(response.payload, 0));
        } catch (...) {
            closed_ = true;
            record(Status::invalid);
            revoke_all();
            throw;
        }
    } else if (header.operation == Operation::graphics_bind_surface) {
        response.header.status = Status::denied; // Only the trusted parent can grant a renderer texture.
    } else if (header.operation >= Operation::graphics_call &&
               header.operation <= Operation::graphics_close) {
        if (policy_.graphics) {
            try {
                response = graphics_->dispatch(request);
                graphics_operation = graphics_->last_operation();
            } catch (...) {
                graphics_operation = graphics_->last_operation();
                closed_ = true;
                record(Status::invalid);
                revoke_all();
                throw;
            }
        }
    } else if (header.operation == Operation::package_info && !package_.empty()) {
        response.header.status = request.payload.empty() ? Status::ok : Status::invalid;
        if (request.payload.empty()) {
            append_u64(response.payload, package_.size());
            append_text(response.payload, package_hash_);
        }
    } else if (header.operation == Operation::package_read && !package_.empty()) {
        response.header.status = Status::invalid;
        if (request.payload.size() == 16) {
            const auto offset = read_u64(request.payload, 0), count = read_u64(request.payload, 8);
            if (offset <= package_.size() && count > 0 && count <= maximum_payload &&
                count <= package_.size() - offset) {
                response.payload.assign(package_.begin() + static_cast<std::size_t>(offset),
                                        package_.begin() + static_cast<std::size_t>(offset + count));
                response.header.status = Status::ok;
            }
        }
    } else if (header.operation != Operation::package_info && header.operation != Operation::package_read &&
               (header.operation < Operation::storage || header.operation > Operation::audio)) {
        response.header.status = Status::unsupported;
    }
    response.header.payload_size = static_cast<std::uint32_t>(response.payload.size());
    record(response.header.status);
    return response;
}
} // namespace aether::security
