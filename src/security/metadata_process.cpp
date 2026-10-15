#include "aether/security/metadata_process.hpp"
#include <bcrypt.h>

namespace aether::security {
namespace {
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(std::string("AETHER_ICON_WORKER: ") + message);
}
} // namespace
MetadataProcess::MetadataProcess(const std::filesystem::path &executable, std::uint32_t timeout)
    : worker_({executable, metadata_profile, true, timeout, false, WorkerRole::metadata}) {}
MetadataResult MetadataProcess::inspect(const shell::IconSource &source) {
    require(!used_, "One-shot worker cannot be reused");
    used_ = true;
    MetadataResult result;
    result.isolated = true;
    result.pid = worker_.process_id();
    try {
        std::uint64_t session = 0;
        require(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&session), sizeof(session),
                                BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 &&
                    session,
                "Cannot create session identity");
        host::UniqueHandle mapping(
            CreateFileMappingW(source.handle(), nullptr, PAGE_READONLY, 0, 0, nullptr));
        require(static_cast<bool>(mapping), "Cannot map the stable read-only package");
        std::vector<std::uint8_t> grant;
        append_u64(grant, 2);
        append_u64(grant, worker_.duplicate_metadata_mapping(mapping.get()));
        append_u64(grant, source.size());
        append_u64(grant, 256);
        append_u64(grant, 96);
        worker_.send({{Operation::boot, 0, session, static_cast<std::uint32_t>(grant.size()), Status::ok},
                      std::move(grant)});
        std::uint64_t sequence = 0;
        auto receive = [&](Operation operation) {
            auto frame = worker_.receive();
            require(frame.header.session == session && frame.header.sequence == sequence++ &&
                        frame.header.operation == operation && frame.header.status == Status::ok,
                    "Unexpected worker message identity or type");
            return frame;
        };
        result.preview = decode_icon_description(receive(Operation::icon_result).payload);
        auto &bitmap = result.preview.presentation.bitmap;
        const auto total = std::size_t(bitmap.width) * bitmap.height * 4;
        bitmap.rgba.reserve(total);
        while (bitmap.rgba.size() < total) {
            const auto frame = receive(Operation::icon_pixels);
            require(!frame.payload.empty() && frame.payload.size() <= total - bitmap.rgba.size(),
                    "Unexpected pixel transfer extent");
            bitmap.rgba.insert(bitmap.rgba.end(), frame.payload.begin(), frame.payload.end());
        }
        require(receive(Operation::finished).payload.empty(), "Unexpected final payload");
        result.exit_code = worker_.wait();
        require(result.exit_code == 0 && !worker_.timed_out() && source.unchanged(),
                "Worker failed or source changed before commit");
    } catch (const std::exception &error) {
        worker_.request_stop();
        result.exit_code = worker_.wait();
        result.timed_out = worker_.timed_out();
        result.preview = {};
        result.preview.status = result.timed_out ? apk::IconStatus::timed_out : apk::IconStatus::invalid;
        result.preview.code = result.timed_out ? "AETHER_ICON_WORKER_TIMEOUT" : "AETHER_ICON_WORKER_FAILED";
        result.preview.reason = std::string_view(error.what()).substr(0, 512);
        result.preview.presentation.bitmap = apk::fallback_icon();
        result.preview.presentation.renderer_version = 2;
    }
    // Process exit can precede the job's accounting update. This new service
    // observes the actual kernel counters with a separate 100 ms settlement bound.
    const auto until = GetTickCount64() + 100;
    do {
        result.accounting = worker_.accounting();
        if (!result.accounting.active_processes)
            break;
        Sleep(1);
    } while (GetTickCount64() < until);
    require(!result.accounting.active_processes && result.accounting.total_processes == 1 &&
                result.accounting.active_process_limit == 1 &&
                result.accounting.memory_limit_bytes == 256 * 1024 * 1024 &&
                result.accounting.user_time_limit_100ns == 100000000 && result.accounting.limit_flags == 9482,
            "Unexpected metadata worker accounting");
    return result;
}
} // namespace aether::security
