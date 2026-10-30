#include "aether/security/notification_client.hpp"
#include <bit>
namespace aether::security {
using host::NotificationStatus;
NotificationStatus BrokerNotificationService::send(std::vector<std::uint8_t> payload, bool *enabled) noexcept {
    if (enabled) *enabled = false;
    try {
        const auto reply = client_.request(Operation::notification, std::move(payload));
        if (reply.header.status == Status::ok) {
            if (enabled) {
                if (reply.payload.size() != 8 || read_u64(reply.payload, 0) > 1) return NotificationStatus::invalid;
                *enabled = read_u64(reply.payload, 0) != 0;
            } else if (!reply.payload.empty()) return NotificationStatus::invalid;
            return NotificationStatus::ok;
        }
        if (!reply.payload.empty()) return NotificationStatus::invalid;
        switch (reply.header.status) {
        case Status::denied: return NotificationStatus::denied;
        case Status::unsupported: return NotificationStatus::unsupported;
        case Status::quota: return NotificationStatus::quota;
        default: return NotificationStatus::invalid;
        }
    } catch (...) { return NotificationStatus::unsupported; }
}
NotificationStatus BrokerNotificationService::enabled(bool &value) noexcept {
    try { std::vector<std::uint8_t> payload; append_u64(payload, 0); return send(std::move(payload), &value); }
    catch (...) { value = false; return NotificationStatus::unsupported; }
}
NotificationStatus BrokerNotificationService::post(const host::NotificationText &value) noexcept {
    if (value.channel.empty() || value.channel.size() > 128 || value.title.size() > 256 || value.text.size() > 2048)
        return NotificationStatus::invalid;
    try {
        std::vector<std::uint8_t> payload; append_u64(payload, 1);
        append_u64(payload, std::bit_cast<std::uint32_t>(value.id));
        append_text(payload, value.channel); append_text(payload, value.title); append_text(payload, value.text);
        return send(std::move(payload));
    } catch (...) { return NotificationStatus::unsupported; }
}
NotificationStatus BrokerNotificationService::cancel(std::int32_t id) noexcept {
    try { std::vector<std::uint8_t> payload; append_u64(payload, 2); append_u64(payload, std::bit_cast<std::uint32_t>(id)); return send(std::move(payload)); }
    catch (...) { return NotificationStatus::unsupported; }
}
NotificationStatus BrokerNotificationService::cancel_all() noexcept {
    try { std::vector<std::uint8_t> payload; append_u64(payload, 3); return send(std::move(payload)); }
    catch (...) { return NotificationStatus::unsupported; }
}
} // namespace aether::security
