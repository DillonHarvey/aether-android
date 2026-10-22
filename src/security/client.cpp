#include "local_calendar.hpp"
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
    if (error > static_cast<std::uint64_t>(host::FileError::would_block))
        throw ProtocolError("AETHER_IPC_FILE_RESULT: unknown file error");
    const auto value = std::bit_cast<std::int64_t>(read_u64(frame.payload, 0));
    if ((error == 0) != (frame.header.status == Status::ok) || (error != 0 && value != -1))
        throw ProtocolError("AETHER_IPC_FILE_RESULT: inconsistent file reply");
    return {value, static_cast<host::FileError>(error)};
}
} // namespace
struct BrokerClient::Impl {
    HANDLE reader, writer;
    const std::uint64_t session;
    std::uint64_t next = 1;
    const std::uint64_t request_limit;
    bool broken = false;
    const bool activity_commands;
    std::optional<std::chrono::steady_clock::time_point> activity_deadline;
    std::uint64_t activity_next = 1;
    std::optional<ActivityReassembly> activity_inbox;
    std::unique_ptr<PipeFramePoller> activity_poller;
    const std::thread::id owner = std::this_thread::get_id();
    struct Descriptor {
        int guest = 0;
        std::uint64_t token = 0;
    };
    std::array<Descriptor, 16> files{};
    int next_descriptor = 3;
    Impl(HANDLE input, HANDLE output, std::uint64_t identity, bool interactive, bool activity_commands)
        : reader(input), writer(output), session(identity),
          request_limit(interactive ? UINT64_MAX - 1 : 256), activity_commands(activity_commands) {
        if (!input || !output || input == output || !identity || (activity_commands && !interactive))
            throw ProtocolError("AETHER_IPC_CLIENT: invalid channel");
    }
    void check_activity_deadline() const {
        const auto now = std::chrono::steady_clock::now();
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
            activity_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        }
        activity_inbox->accept(frame);
        if (activity_inbox->complete()) activity_deadline.reset();
    }
    Frame request(Operation operation, std::vector<std::uint8_t> payload) {
        if (std::this_thread::get_id() != owner || broken || next > request_limit)
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
            if (entry.guest == descriptor)
                return &entry;
        return nullptr;
    }
};
BrokerClient::BrokerClient(HANDLE reader, HANDLE writer, std::uint64_t session, bool interactive,
                           bool activity_commands)
    : impl_(std::make_unique<Impl>(reader, writer, session, interactive, activity_commands)) {}
BrokerClient::~BrokerClient() = default; // The broker owns cleanup even after an abrupt worker exit.
Frame BrokerClient::request(Operation operation, std::vector<std::uint8_t> payload) {
    return impl_->request(operation, std::move(payload));
}
std::optional<std::vector<std::uint8_t>> BrokerClient::poll_activity_command(std::uint64_t sequence) {
    auto &p = *impl_;
    if (std::this_thread::get_id() != p.owner)
        throw ProtocolError("AETHER_IPC_CLIENT: activity poll requires the owner thread");
    if (p.broken)
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
    const auto digest = read_text(info.payload, offset, 64);
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
    const auto digest = read_text(info.payload, offset, 64);
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
    if (std::this_thread::get_id() != impl_->owner || impl_->broken)
        return {-1, host::FileError::io};
    if (name.empty() || name.size() > 127)
        return {-1, host::FileError::denied};
    auto slot =
        std::find_if(impl_->files.begin(), impl_->files.end(), [](const auto &item) { return !item.guest; });
    if (slot == impl_->files.end() || impl_->next_descriptor == INT_MAX)
        return {-1, host::FileError::descriptor_limit};
    try {
        const std::uint64_t flags = (options.read ? 1u : 0u) | (options.write ? 2u : 0u) |
                                    (options.create ? 4u : 0u) | (options.exclusive ? 8u : 0u) |
                                    (options.truncate ? 16u : 0u);
        std::vector<std::uint8_t> payload;
        append_u64(payload, flags);
        append_text(payload, name);
        const auto response = request(Operation::file_open, std::move(payload));
        const auto result = file_result(response);
        if (response.payload.size() != 16 || (result.error == host::FileError::none && result.value <= 0))
            throw ProtocolError("AETHER_IPC_FILE_RESULT: invalid open response");
        if (result.error != host::FileError::none)
            return result;
        *slot = {impl_->next_descriptor++, static_cast<std::uint64_t>(result.value)};
        return {slot->guest, host::FileError::none};
    } catch (...) {
        impl_->broken = true;
        return {-1, host::FileError::io};
    }
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
            entry.name = read_text(response.payload, offset, host::directory_name_limit);
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
} // namespace aether::security
