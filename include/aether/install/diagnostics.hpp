#pragma once
#include "aether/install/store.hpp"
#include "aether/install/faults.hpp"
#include <optional>
#include <string_view>

namespace aether::install {
// Host-selected outcome; detailed diagnostic evidence is retained separately.
enum class AppSessionFailure { failed, incomplete };
std::string_view session_failure_code(AppSessionFailure failure) noexcept;
inline constexpr std::string_view session_failure_stage = "installed-activity-session";
struct AppDiagnosticCheck {
    std::string name, status, code, detail;
};
// Read-only report with bounded retained technical fault text. Diagnostic text
// is untrusted and best-effort redacted; no private files or memory are collected.
struct AppDiagnostics {
    InstalledApp app;
    std::string lifecycle;
    std::optional<apk::SignatureReport> observed_signature;
    std::vector<AppDiagnosticCheck> checks;
    std::optional<AppSessionFailure> session_failure;
    FaultHistory faults;
    std::vector<DiagnosticFault> inspection_faults;
    std::optional<DiagnosticFault> current_fault;
    std::string fault_retention_error;
    bool passed() const;
    std::string json() const;
    std::string text() const;
};
// Explicit export creates the requested final file once. Existing destinations
// are never overwritten; a failed write may leave a partial report for review.
void export_diagnostics(const AppDiagnostics &report, const std::filesystem::path &destination);
} // namespace aether::install
