#pragma once
#include "aether/install/diagnostics.hpp"
#include <array>

namespace aether::install {
struct TroubleshootingOptions {
    bool host_details = false, audit_summaries = false;
    bool operator==(const TroubleshootingOptions &) const = default;
};
struct AuditSessionSummary {
    std::string session, state, code, sha256;
    std::uint64_t records = 0, intents = 0, outcomes = 0, uncertain_outcomes = 0;
    std::array<std::uint64_t, 5> statuses{};
    bool pending = false, aborted = false;
};
struct TroubleshootingReport {
    AppDiagnostics diagnostics;
    TroubleshootingOptions options;
    std::string windows_build, architecture;
    std::string audit_status = "not-requested", audit_code;
    std::vector<AuditSessionSummary> sessions;
    bool collection_complete = true;
    bool passed() const;
    std::string json() const;
    std::string text() const;
};
// This plan does not enumerate or read optional sources. Call collection only
// after the caller has explicitly opted into these choices for this one app.
std::string troubleshooting_plan(TroubleshootingOptions options);
std::string troubleshooting_preview(const InstalledApp &app, TroubleshootingOptions options);
// The caller retains the read-only store session throughout collection. Audit
// collection additionally holds existing app/audit directories and an existing
// session lease; it never creates a lease, repairs logs or starts a worker.
TroubleshootingReport collect_troubleshooting(const PackageStore &store, std::string_view id,
                                              TroubleshootingOptions options);
void export_troubleshooting(const TroubleshootingReport &report, const std::filesystem::path &destination);
} // namespace aether::install
