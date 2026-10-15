#include "aether/android/selftest.hpp"
#include "aether/common/text.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/security/apk_session.hpp"
#include <bit>

namespace aether::security {
ApkWorkerResult execute_apk_fixture(BrokerClient &client, std::uint64_t app_id, bool storage_allowed,
                                    const std::array<std::wstring, 3> &denied_files) {
    ApkWorkerResult result;
    const auto package = client.read_package();
    const auto wide = utf16("Aether private storage " + std::to_string(app_id));
    const std::u16string contents(wide.begin(), wide.end());
    const a64::AppContext app{app_id, true};
    android::FrameworkSelftestReport report;
    try {
        report = android::framework_selftest(package, client, app, &client, storage_allowed, contents);
    } catch (const dex::DexError &error) {
        throw ProtocolError(error.code + ": " + error.what());
    }
    if (!report.passed())
        for (const auto &check : report.checks)
            if (!check.passed)
                throw ProtocolError("AETHER_ISOLATED_APK_CHECK: " + check.name);
    for (const auto &path : denied_files) {
        host::UniqueHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (file || GetLastError() != ERROR_ACCESS_DENIED)
            throw ProtocolError("AETHER_ISOLATED_STORAGE_ESCAPE: broker-owned file was not access-denied");
        ++result[ApkMetric::direct_file_denials];
    }
    result[ApkMetric::app_id] = app_id;
    result[ApkMetric::checks] = report.checks.size();
    result[ApkMetric::storage_result] =
        std::bit_cast<std::uint64_t>(static_cast<std::int64_t>(report.storage_result));
    result[ApkMetric::storage_denials] = report.storage_denials;
    result[ApkMetric::compiled_blocks] = report.cpu.compiled_blocks;
    result[ApkMetric::emitted_bytes] = report.cpu.emitted_bytes;
    result[ApkMetric::rx_failures] = report.cpu.rx_failures;
    result[ApkMetric::interpreter_fallbacks] = report.cpu.interpreter_fallbacks;
    result[ApkMetric::native_calls] = report.jni.native_calls;
    result[ApkMetric::managed_callbacks] = report.jni.managed_callbacks;
    result[ApkMetric::on_load_calls] = report.jni.on_load_calls;
    result[ApkMetric::managed_instructions] = report.managed.instructions;
    result[ApkMetric::pinned_references] = report.managed.pinned_references;
    result[ApkMetric::local_references] = report.jni.local_references;
    result[ApkMetric::global_references] = report.jni.global_references;
    result[ApkMetric::string_buffers] = report.jni.string_buffers;
    result[ApkMetric::lifecycle_callbacks] = report.framework.lifecycle_callbacks;
    result[ApkText::apk_hash] = report.apk_sha256;
    result[ApkText::dex_hash] = report.dex_sha256;
    result[ApkText::resources_hash] = report.resources_sha256;
    result[ApkText::package] = report.package;
    result[ApkText::activity] = report.launch_activity;
    result[ApkText::result] = utf8(std::wstring(report.result_text.begin(), report.result_text.end()));
    result[ApkText::trace] = utf8(std::wstring(report.managed_trace.begin(), report.managed_trace.end()));
    return result;
}
} // namespace aether::security
