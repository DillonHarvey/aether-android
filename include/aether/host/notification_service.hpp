#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace aether::host {
// Fixed activation envelope; text content never enters routing metadata.
inline std::wstring notification_activation_arguments(std::int32_t id) {
    return L"aether-notification-v1:" + std::to_wstring(id);
}
enum class NotificationStatus { ok, denied, unsupported, invalid, quota };
// Trusted installation maintenance only. Clears every prior-session toast for
// this exact Aether.App.<32 lowercase hex> AUMID without requiring a live
// provider or registration. The caller verifies its owned projection first.
// One Windows clear attempt; failure leaves lifecycle completion to the caller.
NotificationStatus clear_notification_history(std::string_view trusted_aumid) noexcept;
struct NotificationText {
    std::int32_t id = 0;
    std::string channel, title, text;
};
// Values only. App identity and Windows registration never come from a request.
class NotificationService {
  public:
    virtual ~NotificationService() = default;
    virtual NotificationStatus enabled(bool &value) noexcept = 0;
    virtual NotificationStatus post(const NotificationText &notification) noexcept = 0;
    virtual NotificationStatus cancel(std::int32_t id) noexcept = 0;
    virtual NotificationStatus cancel_all() noexcept = 0;
};
// One owner thread and one installed AUMID. The trusted caller may set
// registration_verified only after validating the installed shortcut and a
// supported toast activation registration, together with explicit app consent.
// A successful Show means accepted by Windows, not displayed or activated.
// Tracks at most 32 distinct IDs per provider lifetime; Windows history from
// earlier sessions is separate. Null contentIntent activation performs no
// Android operation; nonnull PendingIntent and notification actions are unsupported.
// CX-WIN-0014: Windows Notification Center per-app attribution.
// Each installed app has its own AUMID derived from its opaque installed ID
// and its own toast registration. Windows groups and attributes history by
// that AUMID. An unverified registration remains unavailable.
class HostNotificationService final : public NotificationService {
  public:
    explicit HostNotificationService(std::string trusted_aumid, bool registration_verified = false);
    ~HostNotificationService() override;
    HostNotificationService(const HostNotificationService &) = delete;
    HostNotificationService &operator=(const HostNotificationService &) = delete;
    NotificationStatus enabled(bool &value) noexcept override;
    NotificationStatus post(const NotificationText &notification) noexcept override;
    NotificationStatus cancel(std::int32_t id) noexcept override;
    NotificationStatus cancel_all() noexcept override;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::host
