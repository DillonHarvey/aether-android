#pragma once
#include "aether/install/store.hpp"

namespace aether::install {
struct AppDiagnosticCheck {
    std::string name, status, code, detail;
};
// A deliberately small report: no host paths, private app files, audit records,
// environment, certificate subjects, memory or execution traces are collected.
struct AppDiagnostics {
    InstalledApp app;
    std::string lifecycle;
    std::optional<apk::SignatureReport> observed_signature;
    std::vector<AppDiagnosticCheck> checks;
    bool passed() const;
    std::string json() const;
    std::string text() const;
};
// Explicit export creates the requested final file once. Existing destinations
// are never overwritten; a failed write may leave a partial report for review.
void export_diagnostics(const AppDiagnostics &report, const std::filesystem::path &destination);
} // namespace aether::install
