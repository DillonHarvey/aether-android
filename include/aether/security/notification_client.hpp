#pragma once
#include "aether/host/notification_service.hpp"
#include "aether/security/client.hpp"
namespace aether::security {
// Owner-thread, app-bound worker adapter. No Windows identity enters this API.
class BrokerNotificationService final : public host::NotificationService {
  public:
    explicit BrokerNotificationService(BrokerClient &client) : client_(client) {}
    host::NotificationStatus enabled(bool &value) noexcept override;
    host::NotificationStatus post(const host::NotificationText &value) noexcept override;
    host::NotificationStatus cancel(std::int32_t id) noexcept override;
    host::NotificationStatus cancel_all() noexcept override;
  private:
    BrokerClient &client_;
    host::NotificationStatus send(std::vector<std::uint8_t> payload, bool *enabled = nullptr) noexcept;
};
} // namespace aether::security
