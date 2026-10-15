#include "aether/security/client.hpp"
#include "aether/apk/inspect.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <climits>
#include <thread>

namespace aether::security {
namespace {
constexpr std::size_t transfer_limit = maximum_payload - 16;
host::FileResult file_result(const Frame &frame) {
    if (frame.payload.size() < 16)
        throw ProtocolError("AETHER_IPC_FILE_RESULT: incomplete file reply");
    const auto error = read_u64(frame.payload, 8);
    if (error > static_cast<std::uint64_t>(host::FileError::io))
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
    const std::thread::id owner = std::this_thread::get_id();
    struct Descriptor {
        int guest = 0;
        std::uint64_t token = 0;
    };
    std::array<Descriptor, 16> files{};
    int next_descriptor = 3;
    Impl(HANDLE input, HANDLE output, std::uint64_t identity, bool interactive)
        : reader(input), writer(output), session(identity),
          request_limit(interactive ? UINT64_MAX - 1 : 256) {
        if (!input || !output || input == output || !identity)
            throw ProtocolError("AETHER_IPC_CLIENT: invalid channel");
    }
    Frame request(Operation operation, std::vector<std::uint8_t> payload) {
        if (std::this_thread::get_id() != owner || broken || next > request_limit)
            throw ProtocolError("AETHER_IPC_CLIENT: wrong thread, closed channel or request quota");
        Frame message{{operation, next++, session, static_cast<std::uint32_t>(payload.size()), Status::ok},
                      std::move(payload)};
        try {
            write_pipe_frame(writer, message);
            auto response = read_pipe_frame(reader);
            if (response.header.session != session || response.header.sequence != message.header.sequence ||
                response.header.operation != operation)
                throw ProtocolError("AETHER_IPC_CLIENT: response identity mismatch");
            return response;
        } catch (...) {
            broken = true;
            throw;
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
BrokerClient::BrokerClient(HANDLE reader, HANDLE writer, std::uint64_t session, bool interactive)
    : impl_(std::make_unique<Impl>(reader, writer, session, interactive)) {}
BrokerClient::~BrokerClient() = default; // The broker owns cleanup even after an abrupt worker exit.
Frame BrokerClient::request(Operation operation, std::vector<std::uint8_t> payload) {
    return impl_->request(operation, std::move(payload));
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
    if (std::this_thread::get_id() != impl_->owner)
        return host::TimeStatus::unavailable;
    try {
        const auto reply = impl_->request(Operation::monotonic_time, {});
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
        impl_->broken = true;
        return host::TimeStatus::unavailable;
    }
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
