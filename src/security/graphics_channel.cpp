#include "aether/security/graphics_channel.hpp"
#include "aether/host/graphics_surface.hpp"
#include <algorithm>
#include <optional>
namespace aether::security {
namespace {
void require(bool value) {
    if (!value)
        throw ProtocolError("AETHER_GRAPHICS_TRANSFER: invalid transaction");
}
} // namespace
Frame BrokerGraphicsChannel::request(Operation op, std::vector<std::uint8_t> bytes) {
    require(!broken_);
    try {
        auto result = transport_(op, std::move(bytes));
        if (result.header.status == Status::denied) {
            broken_ = true;
            throw graphics::GraphicsCopyError(a64::Fault::capability_denied,
                                              "Broker denied graphics capability");
        }
        require(result.header.status == Status::ok);
        return result;
    } catch (...) {
        broken_ = true;
        throw;
    }
}
graphics::GraphicsReply BrokerGraphicsChannel::receive(Frame initial) {
    try {
        require(initial.payload.size() >= 8);
        const auto size = read_u64(initial.payload, 0);
        require(size && size <= graphics::graphics_packet_limit && initial.payload.size() - 8 <= size);
        std::vector<std::uint8_t> bytes(initial.payload.begin() + 8, initial.payload.end());
        while (bytes.size() < size) {
            std::vector<std::uint8_t> range;
            append_u64(range, bytes.size());
            const auto count =
                std::min<std::size_t>(maximum_payload, static_cast<std::size_t>(size) - bytes.size());
            append_u64(range, count);
            auto part = request(Operation::graphics_result, std::move(range));
            require(part.payload.size() == count);
            bytes.insert(bytes.end(), part.payload.begin(), part.payload.end());
        }
        last_ = decode_graphics_reply(bytes);
        return last_;
    } catch (...) {
        broken_ = true;
        throw;
    }
}
graphics::GraphicsReply BrokerGraphicsChannel::exchange(const graphics::GraphicsCommand &command) {
    require(!closed_ && !broken_);
    const auto bytes = encode_graphics_command(command);
    try {
        if (bytes.size() <= maximum_payload)
            return receive(request(Operation::graphics_call, bytes));
        std::vector<std::uint8_t> begin;
        append_u64(begin, bytes.size());
        require(request(Operation::graphics_begin, std::move(begin)).payload.empty());
        for (std::size_t offset = 0; offset < bytes.size();) {
            const auto count = std::min(maximum_payload - 8, bytes.size() - offset);
            std::vector<std::uint8_t> chunk;
            append_u64(chunk, offset);
            chunk.insert(chunk.end(), bytes.begin() + offset, bytes.begin() + offset + count);
            require(request(Operation::graphics_chunk, std::move(chunk)).payload.empty());
            offset += count;
        }
        return receive(request(Operation::graphics_commit));
    } catch (...) {
        broken_ = true; // A malformed acknowledgement must not permit another mutation on this channel.
        throw;
    }
}
graphics::GraphicsReply BrokerGraphicsChannel::close() {
    if (closed_ || broken_)
        return last_;
    closed_ = true;
    return receive(request(Operation::graphics_close));
}
struct GraphicsBroker::Impl {
    std::unique_ptr<graphics::GraphicsChannel> executor;
    graphics::GraphicsReply snapshot;
    bool retain_pixels, closed = false;
    std::uint32_t operation = UINT32_MAX;
    std::optional<std::size_t> expected;
    std::vector<std::uint8_t> upload, result, pixels;
    std::size_t next_read = 0;
    Impl(std::unique_ptr<graphics::GraphicsChannel> backend, bool retain)
        : executor(std::move(backend)), retain_pixels(retain) {
        require(executor != nullptr);
    }
    void clear() {
        expected.reset();
        upload.clear();
        result.clear();
        next_read = 0;
    }
    void execute(std::span<const std::uint8_t> bytes) {
        const auto command = decode_graphics_command(bytes);
        operation = static_cast<std::uint32_t>(command.operation);
        auto reply = executor->exchange(command);
        snapshot.metrics = reply.metrics;
        snapshot.host = reply.host;
        if (retain_pixels && command.operation == graphics::Operation::read_pixels &&
            reply.fault == a64::Fault::none) {
            for (const auto &o : reply.outputs) {
                require(pixels.size() + o.bytes.size() <= 16 * 1024 * 1024);
                pixels.insert(pixels.end(), o.bytes.begin(), o.bytes.end());
            }
        }
        result = encode_graphics_reply(reply);
        next_read = 0;
    }
};
GraphicsBroker::GraphicsBroker(std::uint64_t app_id, bool retain)
    : GraphicsBroker(std::make_unique<graphics::GraphicsExecutor>(app_id), retain) {}
GraphicsBroker::GraphicsBroker(std::unique_ptr<graphics::GraphicsChannel> executor, bool retain)
    : impl_(std::make_unique<Impl>(std::move(executor), retain)) {}
GraphicsBroker::~GraphicsBroker() { revoke(); }
Frame GraphicsBroker::dispatch(const Frame &request) {
    auto &p = *impl_;
    p.operation = UINT32_MAX;
    Frame reply{{request.header.operation, request.header.sequence, request.header.session, 0, Status::ok},
                {}};
    try {
        const auto op = request.header.operation;
        const auto &bytes = request.payload;
        require((!p.closed || op == Operation::graphics_result) && bytes.size() <= maximum_payload);
        if (op == Operation::graphics_close) {
            require(bytes.empty());
            p.clear();
            p.closed = true;
            p.snapshot = p.executor->close();
            p.result = encode_graphics_reply(p.snapshot);
        } else if (op == Operation::graphics_result) {
            require(bytes.size() == 16 && !p.result.empty());
            const auto offset = read_u64(bytes, 0), size = read_u64(bytes, 8);
            require(offset == p.next_read && size && size <= maximum_payload &&
                    size <= p.result.size() - p.next_read);
            reply.payload.assign(p.result.begin() + p.next_read,
                                 p.result.begin() + p.next_read + static_cast<std::size_t>(size));
            p.next_read += static_cast<std::size_t>(size);
            if (p.next_read == p.result.size()) {
                p.result.clear();
                p.next_read = 0;
            }
        } else {
            require(p.result.empty());
            if (op == Operation::graphics_begin) {
                require(!p.expected && bytes.size() == 8);
                const auto size = read_u64(bytes, 0);
                require(size > maximum_payload && size <= graphics::graphics_packet_limit);
                p.expected = static_cast<std::size_t>(size);
                p.upload.clear();
                p.upload.reserve(*p.expected);
            } else if (op == Operation::graphics_chunk) {
                require(p.expected && bytes.size() > 8 && read_u64(bytes, 0) == p.upload.size() &&
                        bytes.size() - 8 <= *p.expected - p.upload.size());
                p.upload.insert(p.upload.end(), bytes.begin() + 8, bytes.end());
            } else if (op == Operation::graphics_commit) {
                require(p.expected && bytes.empty() && p.upload.size() == *p.expected);
                p.expected.reset();
                p.execute(p.upload);
                p.upload.clear();
            } else {
                require(op == Operation::graphics_call && !p.expected);
                p.execute(bytes);
            }
        }
        if (op != Operation::graphics_result && !p.result.empty()) {
            append_u64(reply.payload, p.result.size());
            const auto count = std::min(maximum_payload - 8, p.result.size());
            reply.payload.insert(reply.payload.end(), p.result.begin(), p.result.begin() + count);
            p.next_read = count;
            if (p.next_read == p.result.size()) {
                p.result.clear();
                p.next_read = 0;
            }
        }
        reply.header.payload_size = static_cast<std::uint32_t>(reply.payload.size());
        return reply;
    } catch (...) {
        revoke();
        throw;
    }
}
void GraphicsBroker::revoke() noexcept {
    auto &p = *impl_;
    p.clear();
    if (!p.closed) {
        p.closed = true;
        try {
            p.snapshot = p.executor->close();
        } catch (...) {
        }
    }
}
std::uint32_t GraphicsBroker::last_operation() const noexcept { return impl_->operation; }
const graphics::Metrics &GraphicsBroker::metrics() const noexcept { return impl_->snapshot.metrics; }
const graphics::HostInfo &GraphicsBroker::host_info() const noexcept { return impl_->snapshot.host; }
const std::vector<std::uint8_t> &GraphicsBroker::fixture_pixels() const noexcept { return impl_->pixels; }
std::size_t GraphicsBroker::retained_transfer_bytes() const noexcept {
    return impl_->upload.size() + impl_->result.size();
}
std::uint64_t GraphicsBroker::attach_window(std::unique_ptr<host::HostSurface> surface) {
    require(!impl_->closed);
    auto *local = dynamic_cast<graphics::GraphicsExecutor *>(impl_->executor.get());
    require(local != nullptr);
    const auto token = local->attach_window(std::move(surface));
    impl_->snapshot.metrics = local->metrics();
    return token;
}
graphics::GraphicsReply GraphicsBroker::bind_shared_window(const graphics::SharedWindowGrant &grant) {
    require(!impl_->closed && !impl_->expected && impl_->result.empty());
    auto *local = dynamic_cast<graphics::GraphicsExecutor *>(impl_->executor.get());
    require(local != nullptr);
    impl_->snapshot = local->bind_shared_window(grant);
    return impl_->snapshot;
}
} // namespace aether::security
