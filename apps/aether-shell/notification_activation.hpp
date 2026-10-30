#pragma once
#include <optional>
#include <string>
#include <vector>

namespace aether::install {
// Caller retains RuntimeUseLease. This owner-thread COM mode never opens UI or
// executes APK code. Only the currently supported null-content-intent activation
// is acknowledged; PendingIntent/Intent delivery is not implemented here.
std::optional<int> run_notification_server(const std::vector<std::string> &arguments);
} // namespace aether::install
