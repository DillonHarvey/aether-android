#pragma once
#include "aether/a64/selftest.hpp"
#include "aether/android/framework.hpp"
#include "aether/jni/bridge.hpp"

namespace aether::android {
struct FrameworkSelftestReport {
    std::vector<a64::Check> checks;
    std::vector<ViewState> initial_views;
    std::vector<std::string> events;
    std::string apk_sha256, dex_sha256, resources_sha256, package, launch_activity;
    std::u16string result_text, managed_trace;
    std::uint32_t api_flags = 0;
    bool storage_attempted = false;
    std::int32_t storage_result = 0;
    std::uint32_t storage_denials = 0;
    FrameworkMetrics framework;
    dex::RuntimeMetrics managed;
    jni::Metrics jni;
    a64::Metrics cpu;
    bool passed() const;
    std::string json() const;
    std::string text(bool verbose) const;
};
FrameworkSelftestReport framework_selftest(const std::filesystem::path &apk);
FrameworkSelftestReport framework_selftest(apk::Bytes bytes, const host::TimeService &time,
                                           const a64::AppContext &app, host::FileService *files = nullptr,
                                           bool storage_allowed = false,
                                           std::u16string_view storage_contents = {});
std::string api_support_report(std::string_view query, bool json);
} // namespace aether::android
