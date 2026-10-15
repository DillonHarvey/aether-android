#pragma once
#include "aether/android/selftest.hpp"
#include "aether/security/installed_activity.hpp"

namespace aether::host {
// Pure Win32-to-Android translation; no host handles or pointers cross this boundary.
std::uint32_t android_keycode(std::uint32_t virtual_key) noexcept;
std::uint32_t android_modifiers(bool shift, bool alt, bool control, bool meta) noexcept;
android::PointerInput logical_pointer(android::PointerAction action, std::uint32_t pointer,
                                      std::uint32_t source, int x, int y, unsigned dpi);
struct WindowReport {
    std::vector<a64::Check> checks;
    std::string apk_sha256, package, activity, capture_path;
    std::string installed_id, app_user_model_id;
    std::string display_name, icon_sha256;
    security::InstalledRelaunch relaunch;
    std::u16string result_text, trace;
    std::uint64_t messages = 0, paints = 0, layouts = 0, resizes = 0, dpi_changes = 0, timer_reads = 0;
    std::uint64_t changed_pixels = 0;
    unsigned initial_dpi = 0, final_dpi = 0, width = 0, height = 0;
    bool created = false, closed = false, selftest = false;
    std::uint32_t window_process = 0, worker_process = 0;
    std::uint64_t worker_commands = 0, broker_calls = 0;
    bool worker_exited = false;
    std::uint32_t io_thread = 0;
    std::uint64_t coalesced_reads = 0, read_failures = 0, recovered_reads = 0, peak_pending = 0;
    std::uint64_t responsive_ticks = 0;
    std::string broker_audit = "[]";
    std::string durable_audit = "{}";
    android::FrameworkMetrics framework;
    dex::RuntimeMetrics managed;
    jni::Metrics jni;
    a64::Metrics cpu;
    bool passed() const;
    std::string json() const;
    std::string text(bool verbose) const;
};
// Only a hash-identified first-party APK may execute until the Phase 7 security gate.
// Selftest uses a hidden real HWND, bounded message exercise, PNG evidence and automatic close.
WindowReport run_fixture_window(const std::filesystem::path &apk, bool selftest);
WindowReport run_installed_window(security::InstalledActivity application);
} // namespace aether::host
