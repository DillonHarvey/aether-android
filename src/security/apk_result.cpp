#include "aether/common/text.hpp"
#include "aether/security/apk_session.hpp"
#include <bit>
#include <sstream>

namespace aether::security {
std::vector<std::uint8_t> ApkWorkerResult::encode() const {
    std::vector<std::uint8_t> bytes;
    append_u64(bytes, 0x41504b31); // APK result schema, independent of transport version.
    for (const auto value : metrics)
        append_u64(bytes, value);
    for (const auto &text : texts)
        append_text(bytes, text);
    return bytes;
}
ApkWorkerResult ApkWorkerResult::decode(std::span<const std::uint8_t> bytes) {
    if (bytes.size() > maximum_payload || read_u64(bytes, 0) != 0x41504b31)
        throw ProtocolError("AETHER_IPC_APK_RESULT: invalid result schema");
    ApkWorkerResult result;
    std::size_t offset = 8;
    for (auto &value : result.metrics) {
        value = read_u64(bytes, offset);
        offset += 8;
    }
    constexpr std::array<std::size_t, 7> limits{64, 64, 64, 255, 512, 512, 1024};
    for (std::size_t i = 0; i < result.texts.size(); ++i)
        result.texts[i] = read_text(bytes, offset, limits[i]);
    if (offset != bytes.size())
        throw ProtocolError("AETHER_IPC_APK_RESULT: trailing result bytes");
    return result;
}
std::string ApkWorkerResult::json() const {
    constexpr std::array names{"appId",
                               "checks",
                               "storageResult",
                               "storageDenials",
                               "compiledBlocks",
                               "emittedBytes",
                               "rxFailures",
                               "interpreterFallbacks",
                               "nativeCalls",
                               "managedCallbacks",
                               "onLoadCalls",
                               "managedInstructions",
                               "pinnedReferences",
                               "localReferences",
                               "globalReferences",
                               "stringBuffers",
                               "directFileDenials",
                               "lifecycleCallbacks"};
    constexpr std::array text_names{"apkSha256",  "dexSha256", "resourcesSha256", "package", "activity",
                                    "resultText", "trace"};
    static_assert(names.size() == static_cast<std::size_t>(ApkMetric::count));
    static_assert(text_names.size() == static_cast<std::size_t>(ApkText::count));
    std::ostringstream out;
    out << '{';
    for (std::size_t i = 0; i < metrics.size(); ++i) {
        if (i)
            out << ',';
        out << json_quote(names[i]) << ':';
        if (i == static_cast<std::size_t>(ApkMetric::storage_result))
            out << std::bit_cast<std::int64_t>(metrics[i]);
        else
            out << metrics[i];
    }
    for (std::size_t i = 0; i < texts.size(); ++i)
        out << ',' << json_quote(text_names[i]) << ':' << json_quote(texts[i]);
    out << '}';
    return out.str();
}
} // namespace aether::security
