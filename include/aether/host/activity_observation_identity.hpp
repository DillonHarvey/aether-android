#pragma once
#include "aether/apk/launcher.hpp"
#include "aether/apk/package.hpp"
#include "aether/security/activity_launch.hpp"
#include "aether/security/activity_protocol.hpp"
#include "aether/security/installed_activity.hpp"
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace aether::host {
// Derived only from the held original package and its existing resolved request.
// Names supplied by a worker never populate this host-only identity.
struct TrustedActivityLaunchIdentity {
    std::string apk_hash, package, activity;
    std::int32_t requested_orientation = -1;
};
inline TrustedActivityLaunchIdentity freeze_activity_launch_identity(
    apk::Bytes held, const security::ActivityLaunch *resolved) {
    const auto inspection = apk::inspect_package(held, {}, {}, apk::ScanScope::installation);
    const auto hash = apk::sha256(held);
    const auto &manifest = inspection.manifest;
    std::size_t declaration = 0;
    std::string activity;
    if (resolved) {
        resolved->validate_against(manifest, hash);
        declaration = resolved->declaration;
        activity = manifest.activities.at(resolved->target).name;
    } else {
        // Preserve legacy scenario-20 launcher/Intent semantics. Resolving the
        // same declared launcher does not construct a supplied ActivityLaunch.
        const auto selection = apk::select_launcher(manifest);
        if (selection.status != apk::LauncherStatus::selected || !selection.activity)
            throw apk::InspectError("AETHER_WINDOW_OBSERVATION_IDENTITY", "activity-window",
                                    "Held package has no unique supported launcher identity");
        declaration = *selection.activity;
        const auto &entry = manifest.activities.at(declaration);
        activity = entry.target.empty() ? entry.name : entry.target;
    }
    return {hash, manifest.package_id, std::move(activity),
            apk::requested_orientation(manifest, declaration)};
}

struct ActivityObservationOrigin {
    std::string installed_id, apk_hash, package, activity;
    std::uint64_t package_generation = 0;
};
inline std::optional<ActivityObservationOrigin> capture_activity_observation_origin(
    const security::InstalledActivity &application) {
    if (!security::valid_installed_id(application.id) || !application.package ||
        application.package->empty() || !application.lease || !application.package_file)
        throw std::invalid_argument(
            "AETHER_WINDOW_OBSERVATION_IDENTITY: no held installed application identity");
    const auto launch = freeze_activity_launch_identity(*application.package, application.launch.get());
    if (application.diagnostic_package_sha256 != launch.apk_hash)
        throw std::invalid_argument(
            "AETHER_WINDOW_OBSERVATION_IDENTITY: captured package identities disagree");
    return ActivityObservationOrigin{application.id, launch.apk_hash, launch.package, launch.activity,
                                     application.diagnostic_package_generation};
}

// One installed UI connection. First accepted host session/PID remain fixed;
// reuse of the same package cannot relabel another worker or transport session.
// This proves identity provenance only, never attachment, rendering or visibility.
class ActivityObservationIdentityBinding final {
    std::optional<ActivityObservationOrigin> origin_;
    std::uint64_t transport_session_ = 0;
    std::uint32_t worker_pid_ = 0;

  public:
    explicit ActivityObservationIdentityBinding(std::optional<ActivityObservationOrigin> origin)
        : origin_(std::move(origin)) {}
    // Current validated publication only; never use a retained last_live state
    // to prove a new observation. No guest callback or allocation occurs here.
    bool bind(const security::ActivityState &state, std::uint64_t transport_session,
              std::uint32_t worker_pid) noexcept {
        if (!origin_ || !transport_session || !worker_pid || state.apk_hash != origin_->apk_hash ||
            state.package != origin_->package || state.activity != origin_->activity)
            return false;
        if (transport_session_)
            return transport_session_ == transport_session && worker_pid_ == worker_pid;
        transport_session_ = transport_session;
        worker_pid_ = worker_pid;
        return true;
    }
    const ActivityObservationOrigin *origin() const noexcept { return origin_ ? &*origin_ : nullptr; }
    std::uint64_t transport_session() const noexcept { return transport_session_; }
    std::uint32_t worker_pid() const noexcept { return worker_pid_; }
};
} // namespace aether::host
