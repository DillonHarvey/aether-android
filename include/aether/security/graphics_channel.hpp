#pragma once
#include "aether/security/client.hpp"
#include "aether/security/graphics_protocol.hpp"
#include "aether/security/graphics_service.hpp"
#include <functional>
namespace aether::security {
class BrokerGraphicsChannel final : public graphics::GraphicsChannel {
  public:
    using Transport = std::function<Frame(Operation, std::vector<std::uint8_t>)>;
    explicit BrokerGraphicsChannel(BrokerClient &client)
        : transport_([&client](Operation op, std::vector<std::uint8_t> bytes) {
              return client.request(op, std::move(bytes));
          }) {}
    explicit BrokerGraphicsChannel(Transport transport) : transport_(std::move(transport)) {}
    graphics::GraphicsReply exchange(const graphics::GraphicsCommand &command) override;
    graphics::GraphicsReply close() override;

  private:
    Transport transport_;
    graphics::GraphicsReply last_;
    bool closed_ = false, broken_ = false;
    graphics::GraphicsReply receive(Frame initial);
    Frame request(Operation operation, std::vector<std::uint8_t> bytes = {});
};
class GraphicsBroker final : public GraphicsService {
  public:
    explicit GraphicsBroker(std::uint64_t app_id, bool retain_fixture_pixels = false);
    GraphicsBroker(std::unique_ptr<graphics::GraphicsChannel> executor, bool retain_fixture_pixels = false);
    ~GraphicsBroker() override;
    Frame dispatch(const Frame &request) override;
    void revoke() noexcept override;
    std::uint32_t last_operation() const noexcept override;
    const graphics::Metrics &metrics() const noexcept;
    const graphics::HostInfo &host_info() const noexcept;
    const std::vector<std::uint8_t> &fixture_pixels() const noexcept;
    std::size_t retained_transfer_bytes() const noexcept;
    std::uint64_t attach_window(std::unique_ptr<host::HostSurface> surface);
    graphics::GraphicsReply bind_shared_window(const graphics::SharedWindowGrant &grant);

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::security
