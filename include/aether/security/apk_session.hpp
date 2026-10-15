#pragma once
#include "aether/security/client.hpp"
#include <array>

namespace aether::security {
enum class ApkMetric : std::size_t {
    app_id,
    checks,
    storage_result,
    storage_denials,
    compiled_blocks,
    emitted_bytes,
    rx_failures,
    interpreter_fallbacks,
    native_calls,
    managed_callbacks,
    on_load_calls,
    managed_instructions,
    pinned_references,
    local_references,
    global_references,
    string_buffers,
    direct_file_denials,
    lifecycle_callbacks,
    count
};
enum class ApkText : std::size_t {
    apk_hash,
    dex_hash,
    resources_hash,
    package,
    activity,
    result,
    trace,
    count
};
struct ApkWorkerResult {
    std::array<std::uint64_t, static_cast<std::size_t>(ApkMetric::count)> metrics{};
    std::array<std::string, static_cast<std::size_t>(ApkText::count)> texts{};
    std::uint64_t &operator[](ApkMetric field) { return metrics[static_cast<std::size_t>(field)]; }
    std::uint64_t operator[](ApkMetric field) const { return metrics[static_cast<std::size_t>(field)]; }
    std::string &operator[](ApkText field) { return texts[static_cast<std::size_t>(field)]; }
    const std::string &operator[](ApkText field) const { return texts[static_cast<std::size_t>(field)]; }
    std::vector<std::uint8_t> encode() const;
    static ApkWorkerResult decode(std::span<const std::uint8_t> bytes);
    std::string json() const;
};
// Compiled-fixture entry only: validates the received APK hash before parsing or execution.
ApkWorkerResult execute_apk_fixture(BrokerClient &client, std::uint64_t app_id, bool storage_allowed,
                                    const std::array<std::wstring, 3> &denied_files);
// Development CLI proof. Real storage and APK execution in three independently verified LPACs.
std::string isolated_apk_selftest(const std::filesystem::path &apk, bool json);
} // namespace aether::security
