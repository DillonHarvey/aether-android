#include "local_calendar.hpp"
#include "file_transport.hpp"
#include "aether/security/client.hpp"
#include "aether/security/activity_protocol.hpp"
#include "aether/apk/inspect.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <climits>
#include <chrono>
#include <thread>

namespace aether::security {
namespace {
constexpr std::size_t transfer_limit = maximum_payload - 16;
host::FileResult file_result(const Frame &frame) {
    if (frame.payload.size() < 16)
        throw ProtocolError("AETHER_IPC_FILE_RESULT: incomplete file reply");
    const auto error = read_u64(frame.payload, 8);
    if (error > static_cast<std::uint64_t>(host::FileError::not_empty))
        throw ProtocolError("AETHER_IPC_FILE_RESULT: unknown file error");
    const auto value = std::bit_cast<std::int64_t>(read_u64(frame.payload, 0));
    if ((error == 0) != (frame.header.status == Status::ok) || (error != 0 && value != -1))
        throw ProtocolError("AETHER_IPC_FILE_RESULT: inconsistent file reply");
    return {value, static_cast<host::FileError>(error)};
}
Status metadata_file_status(host::FileError error) noexcept {
    switch (error) {
    case host::FileError::none: return Status::ok;
    case host::FileError::denied: return Status::denied;
    case host::FileError::unsupported: return Status::unsupported;
    case host::FileError::descriptor_limit: case host::FileError::quota: return Status::quota;
    default: return Status::invalid;
    }
}
Status clipboard_wire_status(host::ClipboardStatus status) {
    switch (status) {
    case host::ClipboardStatus::ok: return Status::ok;
    case host::ClipboardStatus::denied: return Status::denied;
    case host::ClipboardStatus::unsupported:
    case host::ClipboardStatus::unavailable: return Status::unsupported;
    case host::ClipboardStatus::invalid: return Status::invalid;
    case host::ClipboardStatus::quota: return Status::quota;
    }
    throw ProtocolError("AETHER_IPC_CLIPBOARD: unknown typed status");
}
host::ClipboardStatus clipboard_reply(const Frame &response) {
    if (response.payload.size() < 8)
        throw ProtocolError("AETHER_IPC_CLIPBOARD: incomplete typed reply");
    const auto value = read_u64(response.payload, 0);
    if (value > static_cast<std::uint64_t>(host::ClipboardStatus::unavailable))
        throw ProtocolError("AETHER_IPC_CLIPBOARD: unknown typed status");
    const auto status = static_cast<host::ClipboardStatus>(value);
    if (response.header.status != clipboard_wire_status(status) ||
        (status != host::ClipboardStatus::ok && response.payload.size() != 8))
        throw ProtocolError("AETHER_IPC_CLIPBOARD: inconsistent typed reply");
    return status;
}
} // namespace
struct BrokerClient::Impl {
    HANDLE reader, writer;
    const std::uint64_t session;
    std::uint64_t next = 1;
    const std::uint64_t request_limit;
    bool broken = false;
    bool documents_revoked = false;
    const bool activity_commands;
    std::optional<AwakeDeadlineClock::time_point> activity_deadline;
    std::uint64_t activity_next = 1;
    std::uint64_t text_edit_next = 1, text_edit_revision = 0;
    bool text_edit_sending = false;
    std::uint64_t soft_input_next = 1, soft_input_revision = 0;
    bool soft_input_sending = false;
    bool terminal_activation_attempted = false;
    std::optional<ActivityReassembly> activity_inbox;
    std::unique_ptr<PipeFramePoller> activity_poller;
    const std::thread::id owner = std::this_thread::get_id();
    struct Descriptor {
        int guest = 0;
        std::uint64_t token = 0;
        file_transport::Position position;
        bool document = false;
        std::uint64_t document_drop_id = 0;
    };
    std::array<Descriptor, 16> files{};
    struct DropClaim {
        std::uint64_t id = 0;
        std::string uri;
    };
    std::array<DropClaim, host::document_drop_limit> drop_claims{};
    int next_descriptor = 3;
    Impl(HANDLE input, HANDLE output, std::uint64_t identity, bool interactive, bool activity_commands)
        : reader(input), writer(output), session(identity),
          request_limit(interactive ? UINT64_MAX - 1 : 256), activity_commands(activity_commands) {
        if (!input || !output || input == output || !identity || (activity_commands && !interactive))
            throw ProtocolError("AETHER_IPC_CLIENT: invalid channel");
    }
    void check_activity_deadline() const {
        const auto now = AwakeDeadlineClock::now();
        if (activity_deadline && now >= *activity_deadline)
            throw ProtocolError("AETHER_IPC_CLIENT: activity command reassembly timed out");
        if (activity_poller) {
            const auto frame_deadline = activity_poller->partial_deadline();
            if (frame_deadline && now >= *frame_deadline)
                throw ProtocolError("AETHER_IPC_CLIENT: partial activity frame timed out");
        }
    }
    void accept_activity(const Frame &frame) {
        check_activity_deadline();
        if (!activity_commands || activity_next == UINT64_MAX)
            throw ProtocolError("AETHER_IPC_CLIENT: activity mailbox is unavailable");
        if (!activity_inbox) {
            activity_inbox.emplace(Operation::activity_command, activity_next, session, activity_command_limit);
            activity_deadline = AwakeDeadlineClock::now() + std::chrono::seconds(15);
        }
        activity_inbox->accept(frame);
        if (activity_inbox->complete()) activity_deadline.reset();
    }
    Frame request(Operation operation, std::vector<std::uint8_t> payload) {
        if (std::this_thread::get_id() != owner || broken || terminal_activation_attempted || next > request_limit)
            throw ProtocolError("AETHER_IPC_CLIENT: wrong thread, closed channel or request quota");
        Frame message{{operation, next++, session, static_cast<std::uint32_t>(payload.size()), Status::ok},
                      std::move(payload)};
        try {
            check_activity_deadline();
            write_pipe_frame(writer, message);
            for (;;) {
                auto response = read_pipe_frame(reader);
                check_activity_deadline();
                if (activity_poller) activity_poller->reset();
                if (response.header.operation == Operation::activity_command) {
                    accept_activity(response);
                    continue;
                }
                if (response.header.session != session || response.header.sequence != message.header.sequence ||
                    response.header.operation != operation)
                    throw ProtocolError("AETHER_IPC_CLIENT: response identity mismatch");
                return response;
            }
        } catch (...) {
            broken = true;
            throw;
        }
    }
    host::TimeStatus read_time(Operation operation, host::MonotonicTime &value) noexcept {

        if (std::this_thread::get_id() != owner)
            return host::TimeStatus::unavailable;
        try {
            const auto reply = request(operation, {});
            if (reply.header.status == Status::denied && reply.payload.empty())
                return host::TimeStatus::denied;
            if (reply.header.status != Status::ok || reply.payload.size() != 16)
                throw ProtocolError("AETHER_IPC_TIME: invalid clock response");
            const host::MonotonicTime result{read_u64(reply.payload, 0), read_u64(reply.payload, 8)};
            if (result.nanoseconds >= 1'000'000'000)
                throw ProtocolError("AETHER_IPC_TIME: invalid nanoseconds");
            value = result;
            return host::TimeStatus::ok;
        } catch (...) {
            broken = true;
            return host::TimeStatus::unavailable;
        }
    }
    Descriptor *find(int descriptor) noexcept {
        if (std::this_thread::get_id() != owner || broken || descriptor < 3)
            return nullptr;
        for (auto &entry : files)
            if (entry.guest == descriptor && !entry.document)
                return &entry;
        return nullptr;
    }
    Descriptor *find_document(int descriptor) noexcept {
        if (std::this_thread::get_id() != owner || broken || descriptor < 3) return nullptr;
        for (auto &entry : files) if (entry.guest == descriptor && entry.document) return &entry;
        return nullptr;
    }
    void document_failure() noexcept {
        broken = true;
        for (auto &entry : files) if (entry.document) entry = {};
        for (auto &claim : drop_claims) claim = {};
    }
};
BrokerClient::BrokerClient(HANDLE reader, HANDLE writer, std::uint64_t session, bool interactive,
                           bool activity_commands)
    : impl_(std::make_unique<Impl>(reader, writer, session, interactive, activity_commands)) {}
BrokerClient::~BrokerClient() = default; // The broker owns cleanup even after an abrupt worker exit.
Frame BrokerClient::request(Operation operation, std::vector<std::uint8_t> payload) {
    return impl_->request(operation, std::move(payload));
}
void BrokerClient::send_text_edit_observation(const android::TextEditObservation &observation, std::uint64_t context) {
    auto &p = *impl_;
    if (std::this_thread::get_id() != p.owner || p.broken || p.terminal_activation_attempted || !p.activity_commands || p.text_edit_sending || p.soft_input_sending ||
        p.text_edit_next == UINT64_MAX || context == UINT64_MAX ||
        (context && context + 1 != p.activity_next) || observation.event.revision <= p.text_edit_revision)
        throw ProtocolError("AETHER_IPC_TEXT_EDIT: wrong owner, closed stream or invalid sequence");
    p.text_edit_sending = true;
    struct Reset { bool &active; ~Reset() { active = false; } } reset{p.text_edit_sending};
    try {
        const auto encoded = encode_activity_text_edit_observation(observation);
        std::vector<std::uint8_t> bytes;
        bytes.reserve(8 + encoded.size());
        append_u64(bytes, context);
        bytes.insert(bytes.end(), encoded.begin(), encoded.end());
        const auto ordinal = p.text_edit_next++;
        const auto deadline = AwakeDeadlineClock::now() + std::chrono::seconds(15);
        const auto check = [&] {
            p.check_activity_deadline();
            if (AwakeDeadlineClock::now() >= deadline)
                throw ProtocolError("AETHER_IPC_TEXT_EDIT: acknowledgement deadline expired");
        };
        check();
        for (std::size_t offset = 0; offset < bytes.size(); offset += maximum_payload - 16) {
            write_pipe_frame(p.writer, activity_fragment(bytes, offset, Operation::activity_text_edit, ordinal, p.session));
            check();
        }
        if (!p.activity_poller)
            p.activity_poller = std::make_unique<PipeFramePoller>(p.reader, std::chrono::milliseconds{15000});
        for (;;) {
            check();
            const auto response = p.activity_poller->poll();
            if (!response) { std::this_thread::sleep_for(std::chrono::milliseconds(1)); continue; }
            check();
            if (response->header.operation == Operation::activity_command) {
                p.accept_activity(*response);
                continue;
            }
            if (response->header.operation != Operation::activity_text_edit_ack ||
                response->header.session != p.session || response->header.sequence != ordinal ||
                response->header.status != Status::ok || response->payload.size() != 16 ||
                read_u64(response->payload, 0) != context || read_u64(response->payload, 8) != observation.event.revision)
                throw ProtocolError("AETHER_IPC_TEXT_EDIT: acknowledgement identity mismatch");
            p.text_edit_revision = observation.event.revision;
            return;
        }
    } catch (...) { p.broken = true; throw; }
}
bool BrokerClient::send_soft_input_observation(const android::SoftInputObservation &observation, std::uint64_t context) {
    auto &p = *impl_;
    if (std::this_thread::get_id() != p.owner || p.broken || p.terminal_activation_attempted || !p.activity_commands || p.text_edit_sending || p.soft_input_sending ||
        p.soft_input_next == UINT64_MAX || context == UINT64_MAX ||
        (context && context + 1 != p.activity_next) || observation.request.revision <= p.soft_input_revision)
        throw ProtocolError("AETHER_IPC_SOFT_INPUT: wrong owner, closed stream or invalid sequence");
    p.soft_input_sending = true;
    struct Reset { bool &active; ~Reset() { active = false; } } reset{p.soft_input_sending};
    try {
        const auto encoded = encode_activity_soft_input_observation(observation);
        std::vector<std::uint8_t> bytes;
        bytes.reserve(8 + encoded.size());
        append_u64(bytes, context);
        bytes.insert(bytes.end(), encoded.begin(), encoded.end());
        const auto ordinal = p.soft_input_next++;
        const auto deadline = AwakeDeadlineClock::now() + std::chrono::seconds(15);
        const auto check = [&] {
            p.check_activity_deadline();
            if (AwakeDeadlineClock::now() >= deadline)
                throw ProtocolError("AETHER_IPC_SOFT_INPUT: acknowledgement deadline expired");
        };
        check();
        for (std::size_t offset = 0; offset < bytes.size(); offset += maximum_payload - 16) {
            write_pipe_frame(p.writer, activity_fragment(bytes, offset, Operation::activity_soft_input, ordinal, p.session));
            check();
        }
        if (!p.activity_poller)
            p.activity_poller = std::make_unique<PipeFramePoller>(p.reader, std::chrono::milliseconds{15000});
        for (;;) {
            check();
            const auto response = p.activity_poller->poll();
            if (!response) { std::this_thread::sleep_for(std::chrono::milliseconds(1)); continue; }
            check();
            if (response->header.operation == Operation::activity_command) {
                p.accept_activity(*response);
                continue;
            }
            if (response->header.operation != Operation::activity_soft_input_ack ||
                response->header.session != p.session || response->header.sequence != ordinal ||
                response->header.status != Status::ok || response->payload.size() != 24 ||
                read_u64(response->payload, 0) != context || read_u64(response->payload, 8) != observation.request.revision ||
                read_u64(response->payload, 16) > 1)
                throw ProtocolError("AETHER_IPC_SOFT_INPUT: acknowledgement identity mismatch");
            p.soft_input_revision = observation.request.revision;
            return read_u64(response->payload, 16) != 0;
        }
    } catch (...) { p.broken = true; throw; }
}
void BrokerClient::send_terminal_view_activations(const ActivityTerminalActivations &batch, std::uint64_t context) {
    auto &p = *impl_;
    if (std::this_thread::get_id() != p.owner || p.broken || !p.activity_commands ||
        p.terminal_activation_attempted || p.text_edit_sending || p.soft_input_sending ||
        context == UINT64_MAX || (context && context + 1 != p.activity_next))
        throw ProtocolError("AETHER_IPC_ACTIVATION_TERMINAL: wrong owner, closed stream or invalid context");
    // Retire public broker/observation/poll entry points before encoding/writing.
    // An interrupted or failed terminal transfer is never attempted again.
    p.terminal_activation_attempted = true;
    auto deadline = AwakeDeadlineClock::now() + std::chrono::seconds(15);
    if (p.activity_deadline) deadline = (std::min)(deadline, *p.activity_deadline);
    try {
        const auto encoded = encode_activity_terminal_activations(batch);
        std::vector<std::uint8_t> bytes;
        bytes.reserve(8 + encoded.size());
        append_u64(bytes, context);
        bytes.insert(bytes.end(), encoded.begin(), encoded.end());
        const auto check = [&] {
            p.check_activity_deadline();
            if (AwakeDeadlineClock::now() >= deadline)
                throw ProtocolError("AETHER_IPC_ACTIVATION_TERMINAL: custody acknowledgement deadline expired");
        };
        check();
        for (std::size_t offset = 0; offset < bytes.size(); offset += maximum_payload - 16) {
            write_pipe_frame(p.writer,
                activity_fragment(bytes, offset, Operation::activity_activation_terminal, 1, p.session));
            check();
        }
        if (!p.activity_poller)
            p.activity_poller = std::make_unique<PipeFramePoller>(p.reader, std::chrono::milliseconds{15000});
        for (;;) {
            check();
            const auto response = p.activity_poller->poll();
            if (!response) { std::this_thread::sleep_for(std::chrono::milliseconds(1)); continue; }
            check();
            if (response->header.operation == Operation::activity_command) {
                p.accept_activity(*response); // Validate/retain only; never resume guest execution.
                continue;
            }
            if (response->header.operation != Operation::activity_activation_terminal_ack ||
                response->header.session != p.session || response->header.sequence != 1 ||
                response->header.status != Status::ok || response->payload.size() != 16 ||
                read_u64(response->payload, 0) != context ||
                read_u64(response->payload, 8) != batch.through_revision)
                throw ProtocolError("AETHER_IPC_ACTIVATION_TERMINAL: custody acknowledgement identity mismatch");
            return;
        }
    } catch (...) { p.broken = true; throw; }
}
void BrokerClient::retire_activity_channel() noexcept {
    if (std::this_thread::get_id() == impl_->owner)
        impl_->terminal_activation_attempted = true;
}
std::optional<std::vector<std::uint8_t>> BrokerClient::poll_activity_command(std::uint64_t sequence) {
    auto &p = *impl_;
    if (std::this_thread::get_id() != p.owner)
        throw ProtocolError("AETHER_IPC_CLIENT: activity poll requires the owner thread");
    if (p.broken || p.terminal_activation_attempted)
        throw ProtocolError("AETHER_IPC_CLIENT: activity poll on closed channel");
    try {
        p.check_activity_deadline();
        if (!p.activity_commands || sequence != p.activity_next || sequence == UINT64_MAX)
            throw ProtocolError("AETHER_IPC_CLIENT: activity sequence or mode mismatch");
        for (;;) {
            if (p.activity_inbox && p.activity_inbox->complete()) {
                auto bytes = p.activity_inbox->take();
                p.activity_inbox.reset();
                ++p.activity_next;
                return bytes;
            }
            if (!p.activity_poller)
                p.activity_poller = std::make_unique<PipeFramePoller>(p.reader, std::chrono::milliseconds{15000});
            auto frame = p.activity_poller->poll();
            if (!frame) return {};
            p.accept_activity(*frame);
        }
    } catch (...) {
        p.broken = true;
        throw;
    }
}
std::uint64_t BrokerClient::next_sequence() const noexcept { return impl_->next; }
void BrokerClient::verify_package(std::span<const std::uint8_t> bytes) {
    const auto info = request(Operation::package_info);
    if (info.header.status != Status::ok || info.payload.size() != 80 ||
        read_u64(info.payload, 0) != bytes.size() || bytes.empty())
        throw ProtocolError("AETHER_IPC_PACKAGE: mapped package size differs from broker metadata");
    std::size_t offset = 8;
    const auto digest = security::read_text(info.payload, offset, 64);
    if (digest.size() != 64 || offset != info.payload.size() || apk::sha256(bytes) != digest)
        throw ProtocolError("AETHER_IPC_PACKAGE: mapped package digest differs from broker metadata");
}
std::vector<std::uint8_t> BrokerClient::read_package() {
    const auto info = request(Operation::package_info);
    if (info.header.status != Status::ok || info.payload.size() != 80)
        throw ProtocolError("AETHER_IPC_PACKAGE: no bounded installed package");
    const auto size = read_u64(info.payload, 0);
    if (!size || size > 64 * 1024 * 1024)
        throw ProtocolError("AETHER_IPC_PACKAGE: package size exceeds limit");
    std::size_t offset = 8;
    const auto digest = security::read_text(info.payload, offset, 64);
    if (digest.size() != 64 || offset != info.payload.size())
        throw ProtocolError("AETHER_IPC_PACKAGE: invalid package digest");
    std::vector<std::uint8_t> bytes;
    bytes.reserve(static_cast<std::size_t>(size));
    while (bytes.size() < size) {
        const auto count = std::min<std::uint64_t>(maximum_payload, size - bytes.size());
        std::vector<std::uint8_t> payload;
        append_u64(payload, bytes.size());
        append_u64(payload, count);
        const auto reply = request(Operation::package_read, std::move(payload));
        if (reply.header.status != Status::ok || reply.payload.size() != count)
            throw ProtocolError("AETHER_IPC_PACKAGE: incomplete package read");
        bytes.insert(bytes.end(), reply.payload.begin(), reply.payload.end());
    }
    if (apk::sha256(bytes) != digest)
        throw ProtocolError("AETHER_IPC_PACKAGE: received package digest differs");
    return bytes;
}
host::TimeStatus BrokerClient::read_monotonic(host::MonotonicTime &value) const noexcept {
    return impl_->read_time(Operation::monotonic_time, value);
}
host::TimeStatus BrokerClient::read_elapsed_realtime(host::MonotonicTime &value) const noexcept {
    return impl_->read_time(Operation::elapsed_realtime, value);
}
host::TimeStatus BrokerClient::read_thread_cpu(host::MonotonicTime &value) const noexcept {
    return impl_->read_time(Operation::thread_cpu, value);
}
host::TimeStatus BrokerClient::read_process_start_uptime(host::MonotonicTime &value) const noexcept {
    return impl_->read_time(Operation::process_start_uptime,value);
}
host::TimeStatus BrokerClient::read_uptime(host::MonotonicTime &value) const noexcept {
    return impl_->read_time(Operation::uptime, value);
}
host::TimeStatus BrokerClient::read_wall_time(host::EpochTime &value) const noexcept {
    if (std::this_thread::get_id() != impl_->owner)
        return host::TimeStatus::unavailable;
    try {
        const auto reply = impl_->request(Operation::wall_time, {});
        if (reply.header.status == Status::denied && reply.payload.empty())
            return host::TimeStatus::denied;
        if (reply.header.status != Status::ok || reply.payload.size() != 16)
            throw ProtocolError("AETHER_IPC_TIME: invalid UTC clock response");
        const host::EpochTime result{std::bit_cast<std::int64_t>(read_u64(reply.payload, 0)),
                                     read_u64(reply.payload, 8)};
        if (result.nanoseconds >= 1'000'000'000)
            throw ProtocolError("AETHER_IPC_TIME: invalid UTC nanoseconds");
        value = result;
        return host::TimeStatus::ok;
    } catch (...) {
        impl_->broken = true;
        return host::TimeStatus::unavailable;
    }
}
host::TimeStatus BrokerClient::convert_local_time(std::int64_t epoch,host::LocalTime &value) const noexcept {
    if(std::this_thread::get_id()!=impl_->owner)return host::TimeStatus::unavailable;
    try {
        std::vector<std::uint8_t> payload;append_u64(payload,std::bit_cast<std::uint64_t>(epoch));
        const auto reply=impl_->request(Operation::local_calendar,std::move(payload));
        if(reply.payload.empty()){
            if(reply.header.status==Status::denied)return host::TimeStatus::denied;
            if(reply.header.status==Status::invalid)return host::TimeStatus::out_of_range;
            if(reply.header.status==Status::unsupported)return host::TimeStatus::unavailable;
        }
        if(reply.header.status!=Status::ok)throw ProtocolError("AETHER_IPC_TIME: invalid calendar status");
        auto result=read_local_calendar(reply.payload);if(!host::local_time_matches_epoch(result,epoch))throw ProtocolError("AETHER_IPC_TIME: inconsistent local calendar");value=std::move(result);return host::TimeStatus::ok;
    }catch(...){impl_->broken=true;return host::TimeStatus::unavailable;}
}
host::FileResult BrokerClient::private_root() noexcept {
    if (std::this_thread::get_id() != impl_->owner || impl_->broken)
        return {-1, host::FileError::io};
    try {
        const auto response = request(Operation::file_root);
        const auto result = file_result(response);
        if (response.payload.size() != 16 ||
            (result.error == host::FileError::none && result.value != 0))
            throw ProtocolError("AETHER_IPC_FILE_RESULT: invalid private root response");
        return result;
    } catch (...) {
        impl_->broken = true;
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::access(host::FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept {
    if(std::this_thread::get_id()!=impl_->owner || impl_->broken)return {-1,host::FileError::io};
    if(!host::valid_file_access(scope,name,mode))return {-1,host::FileError::invalid};
    try {
        std::vector<std::uint8_t> payload;append_u64(payload,static_cast<std::uint32_t>(scope));append_u64(payload,mode);append_text(payload,name);
        const auto response=request(Operation::file_access,std::move(payload));const auto result=file_result(response);
        if(response.payload.size()!=16 || (result.error==host::FileError::none && result.value!=0))throw ProtocolError("AETHER_IPC_FILE_RESULT: invalid access result");return result;
    }catch(...){impl_->broken=true;return {-1,host::FileError::io};}
}
host::FileResult BrokerClient::open(std::string_view name, host::FileOpen options) {
    if(name.find('/')!=std::string_view::npos || name.size()>127){
        const std::uint64_t flags=(options.read?1u:0u)|(options.write?2u:0u)|(options.create?4u:0u)|(options.exclusive?8u:0u)|(options.truncate?16u:0u);
        return path_request(2,host::FileAccessScope::files_leaf,-1,name,flags);
    }
    if (std::this_thread::get_id() != impl_->owner || impl_->broken)
        return {-1, host::FileError::io};
    if (name.empty() || name.size() > 127)
        return {-1, host::FileError::denied};
    auto slot =
        std::find_if(impl_->files.begin(), impl_->files.end(), [](const auto &item) { return !item.guest; });
    if (slot == impl_->files.end() || impl_->next_descriptor == INT_MAX)
        return {-1, host::FileError::descriptor_limit};
    try {
        auto position=file_transport::position(host::FileAccessScope::files_leaf,name);
        if(!position)return {-1,host::FileError::invalid};
        const std::uint64_t flags = (options.read ? 1u : 0u) | (options.write ? 2u : 0u) |
                                    (options.create ? 4u : 0u) | (options.exclusive ? 8u : 0u) |
                                    (options.truncate ? 16u : 0u);
        std::vector<std::uint8_t> payload;
        append_u64(payload, flags);
        append_text(payload, name);
        const auto response = request(Operation::file_open, std::move(payload));
        const auto result = file_result(response);
        const auto token = static_cast<std::uint64_t>(result.value);
        if (response.payload.size() != 16 || (result.error == host::FileError::none &&
            ((token & 0xffffffff00000000ULL) != 0x2ee3000000000000ULL || !(token & 0xffffffffULL) ||
             std::any_of(impl_->files.begin(), impl_->files.end(), [&](const auto &entry) {
                 return entry.guest && entry.token == token;
             }))))
            throw ProtocolError("AETHER_IPC_FILE_RESULT: invalid open response");
        if (result.error != host::FileError::none)
            return result;
        *slot = {impl_->next_descriptor++, static_cast<std::uint64_t>(result.value),std::move(*position)};
        return {slot->guest, host::FileError::none};
    } catch (...) {
        impl_->broken = true;
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::open_scoped(host::FileAccessScope scope, std::string_view name, host::FileOpen options) {
    if (std::this_thread::get_id() != impl_->owner || impl_->broken) return {-1, host::FileError::io};
    if ((scope != host::FileAccessScope::files_leaf && scope != host::FileAccessScope::data_leaf) ||
        !host::valid_file_access(scope, name, 0) || (!options.read && !options.write) ||
        (options.truncate && !options.write) || (options.exclusive && !options.create))
        return {-1, host::FileError::invalid};
    const auto slot = std::find_if(impl_->files.begin(), impl_->files.end(), [](const auto &item) {return !item.guest;});
    if (slot == impl_->files.end() || impl_->next_descriptor == INT_MAX) return {-1, host::FileError::descriptor_limit};
    try {
        auto position=file_transport::position(scope,name);
        if(!position)return {-1,host::FileError::invalid};
        const std::uint64_t flags = (options.read ? 1u : 0u) | (options.write ? 2u : 0u) |
            (options.create ? 4u : 0u) | (options.exclusive ? 8u : 0u) | (options.truncate ? 16u : 0u);
        std::vector<std::uint8_t> payload;
        append_u64(payload, static_cast<std::uint64_t>(scope)); append_u64(payload, flags); append_text(payload, name);
        const auto response = request(Operation::file_open_scoped, std::move(payload));
        const auto result = file_result(response);
        const auto token = static_cast<std::uint64_t>(result.value);
        if (response.payload.size() != 16 || response.header.status != metadata_file_status(result.error) ||
            (result.error == host::FileError::none &&
             ((token & 0xffffffff00000000ULL) != 0x2ee3000000000000ULL || !(token & 0xffffffffULL) ||
              std::any_of(impl_->files.begin(), impl_->files.end(), [&](const auto &item) {return item.guest && item.token == token;}))))
            throw ProtocolError("AETHER_IPC_FILE_OPEN_SCOPED: invalid scoped open reply");
        if (result.error != host::FileError::none) {
            if (result.error == host::FileError::io) impl_->broken = true;
            return result;
        }
        *slot = {impl_->next_descriptor++, token,std::move(*position)};
        return {slot->guest, host::FileError::none};
    } catch (...) {
        impl_->broken = true;
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::path_request(unsigned action,host::FileAccessScope scope,int parent,std::string_view name,std::uint64_t options,bool directory_required) noexcept {
    if(std::this_thread::get_id()!=impl_->owner || impl_->broken)return {-1,host::FileError::io};
    if(action>5 || (directory_required && action!=3 && action!=4))return {-1,host::FileError::invalid};
    if(action==0 && options!=0700)return {-1,host::FileError::unsupported};
    if(((action==1 || action==5) && options) || (action==2 && (options>31 || !(options&3) || ((options&8) && !(options&4)) || ((options&16) && !(options&2)))) || (action==3 && options>7) || (action==4 && options>2))return {-1,host::FileError::invalid};
    std::uint64_t base=static_cast<std::uint64_t>(scope);std::optional<file_transport::Position> position;
    if(parent>=0){const auto file=impl_->find(parent);if(!file)return {-1,host::FileError::bad_descriptor};base=file->token;
        if(!file->position.directory)return {-1,host::FileError::not_directory};if(file->position.unlinked)return {-1,host::FileError::missing};
        if(!host::valid_file_path(name,action!=2 && action!=4) || (action==5 && !name.empty()))return {-1,host::FileError::invalid};
        try{position=file_transport::position(scope,name,&file->position);}catch(...){return {-1,host::FileError::io};}
    }else if(action==5 || !host::valid_file_access(scope,name,0) || ((action==2 || action==4) && static_cast<unsigned>(scope)<2))return {-1,host::FileError::invalid};
    else try{position=file_transport::position(scope,name);}catch(...){return {-1,host::FileError::io};}
    if(!position)return {-1,host::FileError::invalid};
    const bool opening=action==1 || action==2;
    auto slot=impl_->files.end();if(opening){slot=std::find_if(impl_->files.begin(),impl_->files.end(),[](const auto &item){return !item.guest;});if(slot==impl_->files.end() || impl_->next_descriptor==INT_MAX)return {-1,host::FileError::descriptor_limit};}
    try{
        std::vector<std::uint8_t> payload;payload.reserve(48+name.size());
        append_u64(payload,action);append_u64(payload,parent>=0?1:0);append_u64(payload,base);append_u64(payload,options);append_u64(payload,directory_required?1:0);append_text(payload,name);
        const auto response=request(Operation::file_path,std::move(payload));const auto result=file_result(response);
        const auto token=static_cast<std::uint64_t>(result.value);
        if(response.payload.size()!=16 || response.header.status!=metadata_file_status(result.error) ||
            (result.error==host::FileError::none && (opening?((token&0xffffffff00000000ULL)!=0x2ee3000000000000ULL || !(token&0xffffffffULL) ||
                std::any_of(impl_->files.begin(),impl_->files.end(),[&](const auto &item){return item.guest && item.token==token;})):
                action==4?(result.value<=0 || result.value>4096):result.value!=0)))throw ProtocolError("AETHER_IPC_FILE_PATH: invalid path reply");
        if(result.error!=host::FileError::none){if(result.error==host::FileError::io)impl_->broken=true;return result;}
        if(opening){position->directory=action==1;*slot={impl_->next_descriptor++,token,std::move(*position)};return {slot->guest,host::FileError::none};}
        if(action==4)for(auto &entry:impl_->files)if(entry.guest && !entry.document)file_transport::removed(entry.position,*position,static_cast<std::uint64_t>(result.value));
        return result;
    }catch(...){impl_->broken=true;return {-1,host::FileError::io};}
}
host::FileResult BrokerClient::make_directory(host::FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept {return path_request(0,scope,-1,name,mode);}
host::FileResult BrokerClient::make_directory_relative(int parent,std::string_view name,std::uint32_t mode) noexcept {if(parent<0)return {-1,host::FileError::bad_descriptor};return path_request(0,host::FileAccessScope::files_leaf,parent,name,mode);}
host::FileResult BrokerClient::open_directory(host::FileAccessScope scope,std::string_view name) {return path_request(1,scope,-1,name,0);}
host::FileResult BrokerClient::open_directory_relative(int parent,std::string_view name) {if(parent<0)return {-1,host::FileError::bad_descriptor};return path_request(1,host::FileAccessScope::files_leaf,parent,name,0);}
host::FileResult BrokerClient::directory_valid(int descriptor) noexcept {if(descriptor<0)return {-1,host::FileError::bad_descriptor};return path_request(5,host::FileAccessScope::files_leaf,descriptor,"",0);}
host::FileResult BrokerClient::open_relative(int parent,std::string_view name,host::FileOpen options) {
    if(parent<0)return {-1,host::FileError::bad_descriptor};
    const std::uint64_t flags=(options.read?1u:0u)|(options.write?2u:0u)|(options.create?4u:0u)|(options.exclusive?8u:0u)|(options.truncate?16u:0u);
    return path_request(2,host::FileAccessScope::files_leaf,parent,name,flags);
}
host::FileResult BrokerClient::access_relative(int parent,std::string_view name,std::uint32_t mode) noexcept {return access_relative_path(parent,name,mode,false);}
host::FileResult BrokerClient::access_path(host::FileAccessScope scope,std::string_view name,std::uint32_t mode,bool directory_required) noexcept {return path_request(3,scope,-1,name,mode,directory_required);}
host::FileResult BrokerClient::access_relative_path(int parent,std::string_view name,std::uint32_t mode,bool directory_required) noexcept {if(parent<0)return {-1,host::FileError::bad_descriptor};return path_request(3,host::FileAccessScope::files_leaf,parent,name,mode,directory_required);}
host::FileResult BrokerClient::remove_relative(int parent,std::string_view name,host::FileRemoveMode mode,bool directory_required) noexcept {if(parent<0)return {-1,host::FileError::bad_descriptor};return path_request(4,host::FileAccessScope::files_leaf,parent,name,static_cast<std::uint64_t>(mode),directory_required);}
host::FileResult BrokerClient::rename_path(const host::FilePathRef &source,const host::FilePathRef &destination,host::FileRenameInfo &output) noexcept {
    namespace ft=file_transport;
    if(std::this_thread::get_id()!=impl_->owner || impl_->broken)return {-1,host::FileError::io};
    if(!host::valid_file_path(source.name) || !host::valid_file_path(destination.name))return {-1,host::FileError::invalid};
    try{
        std::vector<std::uint8_t> payload;payload.reserve(64+source.name.size()+destination.name.size());
        std::array<ft::Position,2> endpoints;
        const auto endpoint=[&](const host::FilePathRef &ref,ft::Position &canonical)->host::FileError {
            if(ref.directory<-1 || !host::valid_file_path(ref.name))return host::FileError::invalid;
            std::optional<ft::Position> prepared;std::uint64_t base=static_cast<unsigned>(ref.scope);
            if(ref.directory>=0){
                const auto held=impl_->find(ref.directory);if(!held)return host::FileError::bad_descriptor;
                if(!held->position.directory)return host::FileError::not_directory;
                if(held->position.unlinked)return host::FileError::missing;
                base=held->token;prepared=ft::position(ref.scope,ref.name,&held->position);
            }else{
                if(ref.scope!=host::FileAccessScope::files_leaf && ref.scope!=host::FileAccessScope::data_leaf)return host::FileError::invalid;
                prepared=ft::position(ref.scope,ref.name);
            }
            if(!prepared || prepared->name.empty())return host::FileError::invalid;
            canonical=std::move(*prepared);
            append_u64(payload,ref.directory>=0?1:0);append_u64(payload,base);append_u64(payload,ref.directory_required?1:0);append_text(payload,ref.name);
            return host::FileError::none;
        };
        if(const auto error=endpoint(source,endpoints[0]);error!=host::FileError::none)return {-1,error};
        if(const auto error=endpoint(destination,endpoints[1]);error!=host::FileError::none)return {-1,error};
        std::array<std::optional<ft::Candidate>,ft::descriptor_limit> candidates;
        try{for(std::size_t i=0;i<impl_->files.size();++i)if(impl_->files[i].guest && !impl_->files[i].document)candidates[i]=ft::candidate(impl_->files[i].position,endpoints[0],endpoints[1]);}
        catch(const ProtocolError &){return {-1,host::FileError::invalid};}
        host::FileRenameInfo prepared;
        const auto response=request(Operation::file_rename,std::move(payload));const auto result=file_result(response);
        if(response.header.status!=metadata_file_status(result.error))throw ProtocolError("AETHER_IPC_RENAME: inconsistent status");
        if(result.error!=host::FileError::none){
            if(response.payload.size()!=16)throw ProtocolError("AETHER_IPC_RENAME: failure contains relocation data");
            if(result.error==host::FileError::io)impl_->broken=true;
            return result;
        }
        if(result.value!=0 || response.payload.size()<48)throw ProtocolError("AETHER_IPC_RENAME: malformed result header");
        prepared.source_identity=read_u64(response.payload,16);prepared.replaced_identity=read_u64(response.payload,24);
        const auto flags=read_u64(response.payload,32),count=read_u64(response.payload,40);
        if(flags>3 || count>ft::descriptor_limit || response.payload.size()!=48+count*ft::rename_row_bytes)throw ProtocolError("AETHER_IPC_RENAME: malformed relocation extent");
        prepared.directory=(flags&1)!=0;prepared.unchanged=(flags&2)!=0;prepared.relocation_count=static_cast<std::uint32_t>(count);
        if(!ft::valid_info(prepared,endpoints[0],endpoints[1]))throw ProtocolError("AETHER_IPC_RENAME: inconsistent identity result");
        std::array<bool,ft::descriptor_limit> seen{};
        for(unsigned row=0;row<count;++row){
            const auto at=48+row*ft::rename_row_bytes,token=read_u64(response.payload,at),identity=read_u64(response.payload,at+8),scope=read_u64(response.payload,at+16),row_flags=read_u64(response.payload,at+24),depth=read_u64(response.payload,at+32),length=read_u64(response.payload,at+40);
            std::size_t index=0;for(;index<impl_->files.size();++index)if(impl_->files[index].guest && impl_->files[index].token==token)break;
            if(index==impl_->files.size() || seen[index] || row_flags>3 || !candidates[index] ||
                !ft::expected(*candidates[index],impl_->files[index].position,endpoints[0],prepared) ||
                !ft::valid_row(impl_->files[index].position,*candidates[index],endpoints[0],prepared,identity,(row_flags&1)!=0,(row_flags&2)!=0))
                throw ProtocolError("AETHER_IPC_RENAME: foreign duplicate or inconsistent relocation");
            auto &position=candidates[index]->position;
            if(scope!=static_cast<unsigned>(ft::scope(position)) || depth!=position.depth || length!=position.length)
                throw ProtocolError("AETHER_IPC_RENAME: relocation ancestry disagrees with prepared bounds");
            position.identity=identity;seen[index]=true;
            auto &relocation=prepared.relocations[row];relocation.descriptor=impl_->files[index].guest;relocation.identity=identity;
            relocation.scope=ft::scope(position);relocation.name_length=position.length;relocation.directory=position.directory;relocation.unlinked=position.unlinked;
            std::copy(position.name.begin(),position.name.end(),relocation.name.begin());
        }
        for(std::size_t i=0;i<impl_->files.size();++i)if(candidates[i] && ft::expected(*candidates[i],impl_->files[i].position,endpoints[0],prepared)!=seen[i])
            throw ProtocolError("AETHER_IPC_RENAME: missing affected descriptor relocation");
        for(std::size_t i=0;i<impl_->files.size();++i)if(seen[i])std::swap(impl_->files[i].position,candidates[i]->position);
        output=prepared;return result;
    }catch(...){impl_->broken=true;return {-1,host::FileError::io};}
}
host::FileResult BrokerClient::observe_data_file(std::string_view name) noexcept {
    if (std::this_thread::get_id() != impl_->owner || impl_->broken) return {-1, host::FileError::io};
    if (name.empty() || name.size() > 127) return {-1, host::FileError::denied};
    try {
        std::vector<std::uint8_t> payload;
        append_text(payload, name);
        const auto response = request(Operation::file_data_observe, std::move(payload));
        const auto result = file_result(response);
        if (response.payload.size() != 16 || (result.error == host::FileError::none && result.value != 1) ||
            (result.error != host::FileError::none && result.value != -1))
            throw ProtocolError("AETHER_IPC_FILE_RESULT: invalid app-data file observation response");
        return result;
    } catch (...) {
        impl_->broken = true;
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::list_directory(std::vector<host::DirectoryEntry> &output) noexcept {
    if (std::this_thread::get_id() != impl_->owner || impl_->broken) return {-1, host::FileError::io};
    try {
        const auto response = request(Operation::file_directory);
        const auto result = file_result(response);
        const auto expected_status = result.error == host::FileError::none ? Status::ok :
            result.error == host::FileError::denied ? Status::denied :
            result.error == host::FileError::unsupported ? Status::unsupported :
            (result.error == host::FileError::quota || result.error == host::FileError::descriptor_limit) ?
                Status::quota : Status::invalid;
        if (response.header.status != expected_status)
            throw ProtocolError("AETHER_IPC_DIRECTORY: inconsistent result status");
        if (result.error != host::FileError::none) {
            if (response.payload.size() != 16 || result.value != -1)
                throw ProtocolError("AETHER_IPC_DIRECTORY: invalid failure response");
            return result;
        }
        if (response.payload.size() > host::directory_payload_limit || response.payload.size() < 24)
            throw ProtocolError("AETHER_IPC_DIRECTORY: invalid snapshot size");
        const auto count = read_u64(response.payload, 16);
        if (count > host::directory_entry_limit || result.value != static_cast<std::int64_t>(count))
            throw ProtocolError("AETHER_IPC_DIRECTORY: invalid entry count");
        std::vector<host::DirectoryEntry> entries;
        std::size_t offset = 24;
        for (std::uint64_t i = 0; i < count; ++i) {
            host::DirectoryEntry entry;
            entry.inode = read_u64(response.payload, offset); offset += 8;
            if (offset == response.payload.size()) throw ProtocolError("AETHER_IPC_DIRECTORY: missing type");
            entry.type = response.payload.at(offset++);
            entry.name = security::read_text(response.payload, offset, host::directory_name_limit);
            if (!host::valid_directory_entry(entry) ||
                std::any_of(entries.begin(), entries.end(), [&](const auto &prior) { return prior.name == entry.name; }))
                throw ProtocolError("AETHER_IPC_DIRECTORY: invalid entry");
            entries.push_back(std::move(entry));
        }
        if (offset != response.payload.size()) throw ProtocolError("AETHER_IPC_DIRECTORY: trailing bytes");
        output.swap(entries);
        return result;
    } catch (...) {
        impl_->broken = true;
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::read(int descriptor, std::span<std::uint8_t> output) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file)
        return {-1, host::FileError::bad_descriptor};
    try {
        const auto count = std::min(output.size(), transfer_limit);
        std::vector<std::uint8_t> payload;
        append_u64(payload, file->token);
        append_u64(payload, count);
        const auto response = request(Operation::file_read, std::move(payload));
        const auto result = file_result(response);
        const auto bytes = result.error == host::FileError::none ? result.value : 0;
        if (bytes < 0 || static_cast<std::uint64_t>(bytes) > count ||
            response.payload.size() != 16 + static_cast<std::size_t>(bytes))
            throw ProtocolError("AETHER_IPC_FILE_RESULT: invalid read length");
        std::copy(response.payload.begin() + 16, response.payload.end(), output.begin());
        return result;
    } catch (...) {
        impl_->broken = true;
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::write(int descriptor, std::span<const std::uint8_t> input) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file)
        return {-1, host::FileError::bad_descriptor};
    try {
        const auto count = std::min(input.size(), transfer_limit);
        std::vector<std::uint8_t> payload;
        append_u64(payload, file->token);
        payload.insert(payload.end(), input.begin(), input.begin() + count);
        const auto response = request(Operation::file_write, std::move(payload));
        const auto result = file_result(response);
        if (response.payload.size() != 16 ||
            (result.error == host::FileError::none &&
             (result.value < 0 || static_cast<std::uint64_t>(result.value) > count)))
            throw ProtocolError("AETHER_IPC_FILE_RESULT: invalid write count");
        return result;
    } catch (...) {
        impl_->broken = true;
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::metadata(int descriptor, host::FileMetadata &output) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file) return {-1, host::FileError::bad_descriptor};
    try {
        std::vector<std::uint8_t> payload;
        append_u64(payload, file->token);
        const auto response = request(Operation::file_metadata, std::move(payload));
        const auto result = file_result(response);
        if (response.header.status != metadata_file_status(result.error))
            throw ProtocolError("AETHER_IPC_FILE_METADATA: inconsistent status");
        if (result.error != host::FileError::none) {
            if (response.payload.size() != 16) throw ProtocolError("AETHER_IPC_FILE_METADATA: invalid error length");
            return result;
        }
        if (result.value != 0 || response.payload.size() != 104 || read_u64(response.payload, 40) > 1 ||
            read_u64(response.payload, 96) > 1 ||
            read_u64(response.payload, 56) >= 1'000'000'000 || read_u64(response.payload, 72) >= 1'000'000'000 ||
            read_u64(response.payload, 88) >= 1'000'000'000)
            throw ProtocolError("AETHER_IPC_FILE_METADATA: invalid metadata reply");
        host::FileMetadata value;
        value.size = read_u64(response.payload, 16);
        value.identity = read_u64(response.payload, 24);
        value.allocated_bytes = read_u64(response.payload, 32);
        value.readonly = read_u64(response.payload, 40) != 0;
        value.access_seconds = std::bit_cast<std::int64_t>(read_u64(response.payload, 48));
        value.access_nanoseconds = static_cast<std::uint32_t>(read_u64(response.payload, 56));
        value.modified_seconds = std::bit_cast<std::int64_t>(read_u64(response.payload, 64));
        value.modified_nanoseconds = static_cast<std::uint32_t>(read_u64(response.payload, 72));
        value.changed_seconds = std::bit_cast<std::int64_t>(read_u64(response.payload, 80));
        value.changed_nanoseconds = static_cast<std::uint32_t>(read_u64(response.payload, 88));
        value.links = static_cast<std::uint32_t>(read_u64(response.payload, 96));
        if (!host::valid_file_metadata(value)) throw ProtocolError("AETHER_IPC_FILE_METADATA: invalid metadata bounds");
        file->position.identity=value.identity;file->position.unlinked=value.links==0;
        output = value;
        return result;
    } catch (...) {
        impl_->broken = true;
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::remove(host::FileAccessScope scope, std::string_view name, host::FileRemoveMode mode, bool directory_required) noexcept {
    if (std::this_thread::get_id() != impl_->owner || impl_->broken) return {-1, host::FileError::io};
    if (!host::valid_file_remove(scope, name, mode)) return {-1, host::FileError::invalid};
    try {
        const auto position=file_transport::position(scope,name);
        std::vector<std::uint8_t> payload;
        append_u64(payload, static_cast<std::uint64_t>(scope)); append_u64(payload, static_cast<std::uint64_t>(mode));
        append_u64(payload, directory_required ? 1 : 0); append_text(payload, name);
        const auto response = request(Operation::file_remove, std::move(payload));
        const auto result = file_result(response);
        if (response.payload.size() != 16 || response.header.status != metadata_file_status(result.error) ||
            (result.error == host::FileError::none && (result.value <= 0 || result.value > 4096)))
            throw ProtocolError("AETHER_IPC_FILE_REMOVE: invalid removal reply");
        if (result.error == host::FileError::io) impl_->broken = true; // An ambiguous completed mutation is never replayed.
        if(result.error==host::FileError::none)for(auto &entry:impl_->files)if(entry.guest && !entry.document)file_transport::removed(entry.position,*position,static_cast<std::uint64_t>(result.value));
        return result;
    } catch (...) {
        impl_->broken = true;
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::seek(int descriptor, std::int64_t offset, unsigned whence) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file) return {-1, host::FileError::bad_descriptor};
    if (whence > 2) return {-1, host::FileError::invalid};
    try {
        std::vector<std::uint8_t> payload;
        append_u64(payload, file->token);
        append_u64(payload, std::bit_cast<std::uint64_t>(offset));
        append_u64(payload, whence);
        const auto response = request(Operation::file_seek, std::move(payload));
        const auto result = file_result(response);
        if (response.header.status != metadata_file_status(result.error) || response.payload.size() != 16 ||
            (result.error == host::FileError::none &&
             (result.value < 0 || static_cast<std::uint64_t>(result.value) > host::private_file_size_limit)))
            throw ProtocolError("AETHER_IPC_FILE_SEEK: invalid seek reply");
        return result;
    } catch (...) {
        impl_->broken = true;
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::flush(int descriptor) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file)
        return {-1, host::FileError::bad_descriptor};
    try {
        std::vector<std::uint8_t> payload;
        append_u64(payload, file->token);
        const auto response = request(Operation::file_flush, std::move(payload));
        const auto result = file_result(response);
        if (response.payload.size() != 16 || (result.error == host::FileError::none && result.value != 0))
            throw ProtocolError("AETHER_IPC_FILE_RESULT: invalid flush result");
        return result;
    } catch (...) {
        impl_->broken = true;
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::lock(int descriptor,std::uint32_t operation) noexcept {
    const auto file=impl_->find(descriptor);if(!file)return {-1,host::FileError::bad_descriptor};
    if(!host::valid_file_lock(operation))return {-1,host::FileError::invalid};
    try {
        std::vector<std::uint8_t> payload;append_u64(payload,file->token);append_u64(payload,operation);
        const auto response=request(Operation::file_lock,std::move(payload));const auto result=file_result(response);
        if(response.payload.size()!=16 || (result.error==host::FileError::none && result.value!=0))throw ProtocolError("AETHER_IPC_FILE_RESULT: invalid lock result");
        return result;
    }catch(...){impl_->broken=true;return {-1,host::FileError::io};}
}
host::FileResult BrokerClient::close(int descriptor) noexcept {
    const auto file = impl_->find(descriptor);
    if (!file)
        return {-1, host::FileError::bad_descriptor};
    const auto token = file->token;
    *file = {}; // Invalidate before the single close attempt; never reuse a guest descriptor.
    try {
        std::vector<std::uint8_t> payload;
        append_u64(payload, token);
        const auto response = request(Operation::file_close, std::move(payload));
        const auto result = file_result(response);
        if (response.payload.size() != 16 || (result.error == host::FileError::none && result.value != 0))
            throw ProtocolError("AETHER_IPC_FILE_RESULT: invalid close result");
        return result;
    } catch (...) {
        impl_->broken = true;
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::describe(std::string_view uri, host::DocumentInfo &output) noexcept {
    if (std::this_thread::get_id() != impl_->owner || impl_->broken) return {-1, host::FileError::io};
    if (impl_->documents_revoked) return {-1, host::FileError::denied};
    if (!host::valid_document_uri(uri)) return {-1, host::FileError::invalid};
    try {
        std::vector<std::uint8_t> payload;
        append_text(payload, uri);
        const auto response = request(Operation::document_info, std::move(payload));
        const auto result = file_result(response);
        if (response.header.status != metadata_file_status(result.error))
            throw ProtocolError("AETHER_IPC_DOCUMENT: inconsistent description status");
        if (result.error != host::FileError::none) {
            if (response.payload.size() != 16)
                throw ProtocolError("AETHER_IPC_DOCUMENT: description failure has trailing data");
            if (result.error == host::FileError::io) impl_->document_failure();
            return result;
        }
        std::size_t offset = 16;
        host::DocumentInfo value;
        value.uri = security::read_text(response.payload, offset, host::document_uri_prefix.size() + 32);
        value.mime_type = security::read_text(response.payload, offset, 255);
        value.display_name = security::read_text(response.payload, offset, 255);
        value.size = read_u64(response.payload, offset); offset += 8;
        if (result.value != 0 || offset != response.payload.size() || !host::valid_document_info(value) || value.uri != uri)
            throw ProtocolError("AETHER_IPC_DOCUMENT: invalid description");
        output = std::move(value);
        return result;
    } catch (...) {
        impl_->document_failure();
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::open_document(std::string_view uri) noexcept {
    if (std::this_thread::get_id() != impl_->owner || impl_->broken) return {-1, host::FileError::io};
    if (impl_->documents_revoked) return {-1, host::FileError::denied};
    if (!host::valid_document_uri(uri)) return {-1, host::FileError::invalid};
    const auto slot = std::find_if(impl_->files.begin(), impl_->files.end(), [](const auto &entry) { return !entry.guest; });
    if (slot == impl_->files.end() || impl_->next_descriptor == INT_MAX) return {-1, host::FileError::descriptor_limit};
    try {
        std::vector<std::uint8_t> payload;
        append_text(payload, uri);
        const auto response = request(Operation::document_open, std::move(payload));
        const auto result = file_result(response);
        const auto token = static_cast<std::uint64_t>(result.value);
        if (response.header.status != metadata_file_status(result.error) || response.payload.size() != 16 ||
            (result.error == host::FileError::none &&
             ((token & 0xffffffff00000000ULL) != 0x2ee4000000000000ULL || !(token & 0xffffffffULL) ||
              std::any_of(impl_->files.begin(), impl_->files.end(), [&](const auto &entry) {
                  return entry.guest && entry.token == token;
              }))))
            throw ProtocolError("AETHER_IPC_DOCUMENT: invalid open reply");
        if (result.error != host::FileError::none) {
            if (result.error == host::FileError::io) impl_->document_failure();
            return result;
        }
        std::uint64_t drop_id = 0;
        for (const auto &claim : impl_->drop_claims) if (claim.id && claim.uri == uri) { drop_id = claim.id; break; }
        *slot = {impl_->next_descriptor++, token, {}, true, drop_id};
        return {slot->guest, host::FileError::none};
    } catch (...) {
        impl_->document_failure();
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::read_document(int descriptor, std::span<std::uint8_t> output) noexcept {
    if (std::this_thread::get_id() != impl_->owner) return {-1, host::FileError::bad_descriptor};
    if (impl_->documents_revoked) return {-1, host::FileError::bad_descriptor};
    const auto file = impl_->find_document(descriptor);
    if (!file) return {-1, host::FileError::bad_descriptor};
    try {
        const auto count = std::min(output.size(), transfer_limit);
        std::vector<std::uint8_t> payload;
        append_u64(payload, file->token); append_u64(payload, count);
        const auto response = request(Operation::document_read, std::move(payload));
        const auto result = file_result(response);
        const auto bytes = result.error == host::FileError::none ? result.value : 0;
        if (response.header.status != metadata_file_status(result.error) || bytes < 0 ||
            static_cast<std::uint64_t>(bytes) > count || response.payload.size() != 16 + static_cast<std::size_t>(bytes))
            throw ProtocolError("AETHER_IPC_DOCUMENT: invalid read reply");
        if (result.error == host::FileError::none)
            std::copy(response.payload.begin() + 16, response.payload.end(), output.begin());
        else if (result.error == host::FileError::io) impl_->document_failure();
        return result;
    } catch (...) {
        impl_->document_failure();
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::close_document(int descriptor) noexcept {
    if (std::this_thread::get_id() != impl_->owner) return {-1, host::FileError::bad_descriptor};
    const auto file = std::find_if(impl_->files.begin(), impl_->files.end(), [&](const auto &entry) {
        return entry.guest == descriptor && entry.document;
    });
    if (file == impl_->files.end()) return {-1, host::FileError::bad_descriptor};
    const auto token = file->token;
    *file = {}; // Retire before one close attempt, including a broken channel.
    if (impl_->broken) return {-1, host::FileError::io};
    try {
        std::vector<std::uint8_t> payload;
        append_u64(payload, token);
        const auto response = request(Operation::document_close, std::move(payload));
        const auto result = file_result(response);
        if (response.header.status != metadata_file_status(result.error) || response.payload.size() != 16 ||
            (result.error == host::FileError::none && result.value != 0))
            throw ProtocolError("AETHER_IPC_DOCUMENT: invalid close reply");
        if (result.error == host::FileError::io) impl_->document_failure();
        return result;
    } catch (...) {
        impl_->document_failure();
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::claim_drop(std::string_view uri, std::uint64_t drop_id) noexcept {
    if (std::this_thread::get_id() != impl_->owner || impl_->broken) return {-1, host::FileError::io};
    if (impl_->documents_revoked) return {-1, host::FileError::denied};
    if (!drop_id || !host::valid_document_uri(uri)) return {-1, host::FileError::invalid};
    auto slot = std::find_if(impl_->drop_claims.begin(), impl_->drop_claims.end(), [&](const auto &claim) {
        return claim.id == drop_id || (claim.id && claim.uri == uri);
    });
    if (slot != impl_->drop_claims.end()) {
        if (slot->id != drop_id || slot->uri != uri) return {-1, host::FileError::invalid};
    } else {
        slot = std::find_if(impl_->drop_claims.begin(), impl_->drop_claims.end(), [](const auto &claim) { return !claim.id; });
        if (slot == impl_->drop_claims.end()) return {-1, host::FileError::quota};
    }
    try {
        // Allocate local ownership before the once-only host claim. Moving the
        // accepted record into its reserved fixed slot cannot allocate afterward.
        Impl::DropClaim claim{drop_id, std::string(uri)};
        std::vector<std::uint8_t> payload;
        append_u64(payload, drop_id); append_text(payload, uri);
        const auto response = request(Operation::document_drop_claim, std::move(payload));
        const auto result = file_result(response);
        if (response.header.status != metadata_file_status(result.error) || response.payload.size() != 16 ||
            (result.error == host::FileError::none && result.value != 0))
            throw ProtocolError("AETHER_IPC_DOCUMENT: invalid drop claim reply");
        if (result.error == host::FileError::none) *slot = std::move(claim);
        else if (result.error == host::FileError::io) impl_->document_failure();
        return result;
    } catch (...) {
        impl_->document_failure();
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::release_drop(std::string_view uri, std::uint64_t drop_id) noexcept {
    if (std::this_thread::get_id() != impl_->owner) return {-1, host::FileError::io};
    if (!drop_id || !host::valid_document_uri(uri)) return {-1, host::FileError::invalid};
    const auto claimed = std::find_if(impl_->drop_claims.begin(), impl_->drop_claims.end(), [&](const auto &claim) {
        return claim.id == drop_id && claim.uri == uri;
    });
    if (claimed != impl_->drop_claims.end()) {
        *claimed = {};
        for (auto &entry : impl_->files)
            if (entry.document && entry.document_drop_id == drop_id) entry = {};
    }
    // Consume the local exact-source ownership before one release attempt. No
    // private-file or startup-document descriptor is affected or sent again.
    if (impl_->broken) return {-1, host::FileError::io};
    if (impl_->documents_revoked) return {-1, host::FileError::denied};
    try {
        std::vector<std::uint8_t> payload;
        append_u64(payload, drop_id); append_text(payload, uri);
        const auto response = request(Operation::document_drop_release, std::move(payload));
        const auto result = file_result(response);
        if (response.header.status != metadata_file_status(result.error) || response.payload.size() != 16 ||
            (result.error == host::FileError::none && result.value != 0))
            throw ProtocolError("AETHER_IPC_DOCUMENT: invalid drop release reply");
        if (result.error == host::FileError::io) impl_->document_failure();
        return result;
    } catch (...) {
        impl_->document_failure();
        return {-1, host::FileError::io};
    }
}
host::FileResult BrokerClient::read_drop_text(std::uint64_t drop_id, const host::DropTextInfo &info,
                                            std::u16string &output) noexcept {
    using host::FileError;
    if (std::this_thread::get_id() != impl_->owner || impl_->broken) return {-1, FileError::io};
    if (!drop_id || !host::valid_drop_text_info(info)) return {-1, FileError::invalid};
    try {
        // Reserve the entire bounded result before consuming the one-shot info
        // record, including the distinct present-but-empty text selection.
        std::u16string selected(static_cast<std::size_t>(info.units), u'\0');
        std::vector<std::uint8_t> query;
        append_u64(query, drop_id);
        const auto metadata = request(Operation::drop_text_info, std::move(query));
        const auto description = file_result(metadata);
        if (metadata.header.status != metadata_file_status(description.error))
            throw ProtocolError("AETHER_IPC_DROP_TEXT: inconsistent metadata status");
        if (description.error != FileError::none) {
            if (metadata.payload.size() != 16)
                throw ProtocolError("AETHER_IPC_DROP_TEXT: metadata failure has trailing data");
            if (description.error == FileError::io) impl_->broken = true;
            return description;
        }
        std::size_t at = 16;
        host::DropTextInfo actual;
        actual.units = read_u64(metadata.payload, at); at += 8;
        actual.utf16le_sha256 = security::read_text(metadata.payload, at, 64);
        if (description.value != 0 || at != metadata.payload.size() || !host::valid_drop_text_info(actual) || actual != info)
            throw ProtocolError("AETHER_IPC_DROP_TEXT: metadata differs from the reviewed selection");
        for (std::uint64_t offset = 0; offset < info.units;) {
            const auto count = std::min<std::uint64_t>(host::drop_text_chunk_limit, info.units - offset);
            std::vector<std::uint8_t> payload;
            append_u64(payload, drop_id); append_u64(payload, offset); append_u64(payload, count);
            const auto response = request(Operation::drop_text_read, std::move(payload));
            const auto result = file_result(response);
            if (response.header.status != metadata_file_status(result.error))
                throw ProtocolError("AETHER_IPC_DROP_TEXT: inconsistent chunk status");
            if (result.error != FileError::none) {
                if (response.payload.size() != 16)
                    throw ProtocolError("AETHER_IPC_DROP_TEXT: chunk failure has trailing data");
                if (result.error == FileError::io) impl_->broken = true;
                return result;
            }
            if (result.value != static_cast<std::int64_t>(count) ||
                response.payload.size() != 16 + static_cast<std::size_t>(count) * 2)
                throw ProtocolError("AETHER_IPC_DROP_TEXT: invalid bounded chunk extent");
            for (std::uint64_t index = 0; index < count; ++index) {
                const auto byte = 16 + static_cast<std::size_t>(index) * 2;
                selected[static_cast<std::size_t>(offset + index)] = static_cast<char16_t>(
                    static_cast<std::uint16_t>(response.payload[byte]) |
                    (static_cast<std::uint16_t>(response.payload[byte + 1]) << 8));
            }
            offset += count;
        }
        if (!host::matches_drop_text(info, selected))
            throw ProtocolError("AETHER_IPC_DROP_TEXT: readback differs from the reviewed selection");
        output = std::move(selected); // No partial text was ever exposed to the caller.
        return {0, FileError::none};
    } catch (...) {
        impl_->broken = true;
        return {-1, FileError::io};
    }
}
host::ClipboardStatus BrokerClient::has_text(bool &value) noexcept {
    using host::ClipboardStatus;
    value = false;
    if (std::this_thread::get_id() != impl_->owner || impl_->broken) return ClipboardStatus::unavailable;
    try {
        std::vector<std::uint8_t> payload;
        append_u64(payload, 0);
        const auto response = request(Operation::clipboard, std::move(payload));
        const auto status = clipboard_reply(response);
        if (status != ClipboardStatus::ok) return status;
        if (response.payload.size() != 16 || read_u64(response.payload, 8) > 1)
            throw ProtocolError("AETHER_IPC_CLIPBOARD: invalid availability reply");
        value = read_u64(response.payload, 8) != 0;
        return ClipboardStatus::ok;
    } catch (...) { impl_->broken = true; return ClipboardStatus::unavailable; }
}
host::ClipboardStatus BrokerClient::read_text(std::optional<std::u16string> &value) noexcept {
    using host::ClipboardStatus;
    value.reset(); // A denied or unavailable query never returns earlier clipboard content.
    if (std::this_thread::get_id() != impl_->owner || impl_->broken) return ClipboardStatus::unavailable;
    try {
        std::vector<std::uint8_t> payload;
        append_u64(payload, 1);
        const auto response = request(Operation::clipboard, std::move(payload));
        const auto status = clipboard_reply(response);
        if (status != ClipboardStatus::ok) return status;
        const auto id = read_u64(response.payload, 8), present = read_u64(response.payload, 16);
        if (present > 1 || (!present && (id || response.payload.size() != 24)) || (present && !id))
            throw ProtocolError("AETHER_IPC_CLIPBOARD: invalid snapshot identity or presence");
        if (!present) return ClipboardStatus::ok;
        std::size_t at = 24;
        host::DropTextInfo info;
        info.units = read_u64(response.payload, at); at += 8;
        info.utf16le_sha256 = security::read_text(response.payload, at, 64);
        if (at != response.payload.size() || !host::valid_drop_text_info(info))
            throw ProtocolError("AETHER_IPC_CLIPBOARD: invalid snapshot metadata");
        std::u16string selected(static_cast<std::size_t>(info.units), u'\0');
        for (std::uint64_t offset = 0; offset < info.units;) {
            const auto count = std::min<std::uint64_t>(host::drop_text_chunk_limit, info.units - offset);
            std::vector<std::uint8_t> query;
            append_u64(query, 2); append_u64(query, id); append_u64(query, offset); append_u64(query, count);
            const auto chunk = request(Operation::clipboard, std::move(query));
            const auto chunk_status = clipboard_reply(chunk);
            if (chunk_status != ClipboardStatus::ok) return chunk_status;
            if (chunk.payload.size() != 16 + static_cast<std::size_t>(count) * 2 || read_u64(chunk.payload, 8) != count)
                throw ProtocolError("AETHER_IPC_CLIPBOARD: invalid snapshot chunk");
            for (std::uint64_t index = 0; index < count; ++index) {
                const auto byte = 16 + static_cast<std::size_t>(index) * 2;
                selected[static_cast<std::size_t>(offset + index)] = static_cast<char16_t>(
                    static_cast<std::uint16_t>(chunk.payload[byte]) |
                    (static_cast<std::uint16_t>(chunk.payload[byte + 1]) << 8));
            }
            offset += count;
        }
        if (!host::matches_drop_text(info, selected))
            throw ProtocolError("AETHER_IPC_CLIPBOARD: snapshot readback differs from its metadata");
        value.emplace(std::move(selected));
        return ClipboardStatus::ok;
    } catch (...) { impl_->broken = true; return ClipboardStatus::unavailable; }
}
host::ClipboardStatus BrokerClient::write_text(std::u16string_view value) noexcept {
    using host::ClipboardStatus;
    if (std::this_thread::get_id() != impl_->owner || impl_->broken) return ClipboardStatus::unavailable;
    if (!host::valid_drop_text(value)) return ClipboardStatus::invalid;
    try {
        const auto info = host::describe_drop_text(value);
        std::vector<std::uint8_t> payload;
        append_u64(payload, 3); append_u64(payload, info.units); append_text(payload, info.utf16le_sha256);
        const auto begun = request(Operation::clipboard, std::move(payload));
        const auto status = clipboard_reply(begun);
        if (status != ClipboardStatus::ok) return status;
        if (begun.payload.size() != 16 || !read_u64(begun.payload, 8))
            throw ProtocolError("AETHER_IPC_CLIPBOARD: invalid upload identity");
        const auto id = read_u64(begun.payload, 8);
        for (std::uint64_t offset = 0; offset < info.units;) {
            const auto count = std::min<std::uint64_t>(host::drop_text_chunk_limit, info.units - offset);
            std::vector<std::uint8_t> part;
            append_u64(part, 4); append_u64(part, id); append_u64(part, offset); append_u64(part, count);
            for (std::uint64_t index = 0; index < count; ++index) {
                const auto unit = value[static_cast<std::size_t>(offset + index)];
                part.push_back(static_cast<std::uint8_t>(unit)); part.push_back(static_cast<std::uint8_t>(unit >> 8));
            }
            const auto response = request(Operation::clipboard, std::move(part));
            const auto chunk_status = clipboard_reply(response);
            if (chunk_status != ClipboardStatus::ok) return chunk_status;
            if (response.payload.size() != 8) throw ProtocolError("AETHER_IPC_CLIPBOARD: upload has trailing data");
            offset += count;
        }
        std::vector<std::uint8_t> commit;
        append_u64(commit, 5); append_u64(commit, id);
        const auto response = request(Operation::clipboard, std::move(commit));
        const auto committed = clipboard_reply(response);
        if (committed == ClipboardStatus::ok && response.payload.size() != 8)
            throw ProtocolError("AETHER_IPC_CLIPBOARD: commit has trailing data");
        return committed;
    } catch (...) { impl_->broken = true; return ClipboardStatus::unavailable; }
}
host::ClipboardStatus BrokerClient::clear() noexcept {
    using host::ClipboardStatus;
    if (std::this_thread::get_id() != impl_->owner || impl_->broken) return ClipboardStatus::unavailable;
    try {
        std::vector<std::uint8_t> payload;
        append_u64(payload, 6);
        const auto response = request(Operation::clipboard, std::move(payload));
        const auto status = clipboard_reply(response);
        if (status == ClipboardStatus::ok && response.payload.size() != 8)
            throw ProtocolError("AETHER_IPC_CLIPBOARD: clear has trailing data");
        return status;
    } catch (...) { impl_->broken = true; return ClipboardStatus::unavailable; }
}
void BrokerClient::revoke_documents() noexcept {
    if (std::this_thread::get_id() != impl_->owner) return;
    impl_->documents_revoked = true;
    for (auto &entry : impl_->files) if (entry.guest && entry.document) (void)close_document(entry.guest);
    for (auto &claim : impl_->drop_claims) claim = {};
}
} // namespace aether::security
