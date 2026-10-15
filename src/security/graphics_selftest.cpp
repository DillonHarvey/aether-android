#include "aether/apk/inspect.hpp"
#include "aether/common/text.hpp"
#include "aether/graphics/fixture_hash.hpp"
#include "aether/security/broker.hpp"
#include "aether/security/graphics_process.hpp"
#include "aether/security/graphics_session.hpp"
#include <bcrypt.h>
#include <fstream>
#include <sstream>
namespace aether::graphics {
namespace {
using security::Frame;
using security::Status;
using WireOperation = security::Operation;
void require(bool value, const char *message) {
    if (!value)
        throw a64::GuestError("AETHER_GRAPHICS_ISOLATION", message);
}
std::uint64_t identity() {
    std::uint64_t n = 0;
    require(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&n), sizeof(n),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 &&
                n,
            "Cannot create graphics session identity");
    return n;
}
std::filesystem::path directory() {
    std::array<wchar_t, 32768> path{};
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    require(size > 0 && size < path.size(), "Cannot locate graphics worker");
    return std::filesystem::path(path.data()).parent_path();
}
Frame run(security::WorkerProcess &worker, security::Broker &broker, security::GraphicsBroker &graphics,
          std::uint64_t session, std::uint64_t app_id, bool revoke) {
    Frame boot{{WireOperation::boot, 0, session, 40, Status::ok}, {}};
    for (auto n : {std::uint64_t{14}, static_cast<std::uint64_t>(GetCurrentProcessId()), app_id,
                   std::uint64_t{1}, std::uint64_t{0}})
        security::append_u64(boot.payload, n);
    worker.send(boot);
    const auto ack = worker.receive();
    require(ack.header.operation == WireOperation::boot && ack.header.session == session &&
                ack.header.sequence == 0 && ack.header.status == Status::ok && ack.payload.empty(),
            "Invalid graphics worker acknowledgement");
    for (;;) {
        const auto request = worker.receive();
        if (request.header.operation == WireOperation::finished) {
            require(request.header.session == session &&
                        ((request.header.status == Status::ok &&
                          request.header.sequence == broker.total_requests() + 1) ||
                         (request.header.status == Status::invalid && request.header.sequence == 0 &&
                          request.payload.size() <= 512)),
                    "Invalid graphics completion");
            return request;
        }
        const auto reply = broker.dispatch(request);
        if (revoke && graphics.metrics().draws == 1) {
            broker.revoke_graphics();
            revoke = false;
        }
        worker.send(reply);
    }
}
std::string audit_json(const security::Broker &broker) {
    std::ostringstream out;
    out << '[';
    bool comma = false;
    for (const auto &e : broker.audit()) {
        if (comma)
            out << ',';
        comma = true;
        out << "{\"appId\":" << e.app_id << ",\"sequence\":" << e.sequence
            << ",\"operation\":" << static_cast<unsigned>(e.operation)
            << ",\"status\":" << static_cast<unsigned>(e.status) << ",\"payloadBytes\":" << e.payload_bytes
            << ",\"graphicsOperation\":"
            << (e.graphics_operation == UINT32_MAX ? "null" : std::to_string(e.graphics_operation)) << '}';
    }
    out << ']';
    return out.str();
}
bool released(const Metrics &m) {
    return !m.contexts && !m.surfaces && !m.shaders && !m.programs && !m.buffers && !m.buffer_bytes &&
           !m.window_bindings && !m.window_surfaces && !m.cleanup_failures;
}
} // namespace
SelftestReport graphics_selftest(const std::filesystem::path &path) {
    apk::InspectLimits limits;
    limits.archive_bytes = 1024 * 1024;
    const auto bytes = apk::read_package(path, limits);
    const auto hash = apk::sha256(bytes);
    if (hash != fixture::sha256)
        throw a64::GuestError(
            "AETHER_GRAPHICS_FIXTURE_NOT_TRUSTED",
            "Only the exact built-in first-party GLES ELF fixture may execute before Phase 7");
    const auto base = directory(), worker_path = base / L"runtime" / L"aether_worker.exe";
    const auto graphics_path = base / L"runtime" / L"aether_graphics_worker.exe";
    require(std::filesystem::is_regular_file(worker_path) && std::filesystem::is_regular_file(graphics_path),
            "Isolated graphics worker is absent; execution refused");
    SelftestReport report;
    std::ostringstream isolation;
    isolation << "{\"mode\":\"LPAC\",\"windowsCapabilities\":0,\"brokerOwnsAngle\":false,"
                 "\"graphicsServiceMode\":\"LPAC\",\"graphicsServiceCapabilities\":1,"
                 "\"graphicsServiceCapabilityNames\":[\"registryRead\"],"
                 "\"graphicsDynamicCodeProhibited\":true,\"graphicsJobUiMask\":255,"
                 "\"graphicsCommandTimeoutMs\":5000,"
                 "\"externalApkExecution\":false,\"parentProcessId\":"
              << GetCurrentProcessId() << ",\"runs\":[";
    constexpr std::array<const char *, 4> names{"allowed", "denied", "revoked", "altered"};
    for (std::size_t i = 0; i < names.size(); ++i) {
        const auto app_id = std::uint64_t{80} + (i == 3 ? 0 : i), session = identity();
        auto package = bytes;
        if (i == 3)
            package[0] ^= 1;
        const auto sent_hash = apk::sha256(package);
        auto service = std::make_unique<security::GraphicsProcess>(graphics_path, app_id);
        auto *service_process = service.get();
        auto provider = std::make_unique<security::GraphicsBroker>(std::move(service), i == 0);
        auto *observed = provider.get();
        const auto journal = security::make_file_audit(base / "audit-data");
        security::Broker broker({app_id, session, true, 256, false, false, false, i != 1}, journal, {},
                                std::move(package), {}, false, std::move(provider));
        const auto profile = L"Aether.Development.Graphics." + std::to_wstring(app_id);
        security::WorkerProcess worker({worker_path, profile, true});
        journal->bind_worker(worker.process_id());
        const auto final = run(worker, broker, *observed, session, app_id, i == 2);
        const auto exit = worker.wait();
        broker.revoke_graphics(); // Also close unused services after denial or altered-fixture rejection.
        journal->finish(final.header.status != Status::ok);
        require(!worker.timed_out(), "Graphics worker exceeded its deadline");
        const std::string diagnostic(final.payload.begin(), final.payload.end());
        if (i == 0) {
            if (final.header.status != Status::ok)
                throw a64::GuestError("AETHER_GRAPHICS_ISOLATION", "Graphics worker failed: " + diagnostic);
            require(exit == 0, "Graphics worker did not exit normally");
            report = security::decode_graphics_result(final.payload);
            require(report.passed() && report.fixture_sha256 == hash && report.relocations == 59,
                    "Isolated graphics fixture checks failed");
            GraphicsReply actual, claimed;
            actual.metrics = observed->metrics();
            actual.host = observed->host_info();
            claimed.metrics = report.graphics;
            claimed.host = report.host;
            require(security::encode_graphics_reply(actual) == security::encode_graphics_reply(claimed),
                    "Worker observations differ from broker graphics");
            const auto &pixels = observed->fixture_pixels();
            require(pixels.size() == 117504 && report.capture_sha256 == apk::sha256(pixels),
                    "Guest and broker readback bytes differ");
            const auto capture = base / L"graphics-guest.rgba";
            std::ofstream file(capture, std::ios::binary | std::ios::trunc);
            file.write(reinterpret_cast<const char *>(pixels.data()),
                       static_cast<std::streamsize>(pixels.size()));
            file.close();
            require(static_cast<bool>(file), "Cannot save actual graphics evidence");
            report.capture_path = utf8(capture.wstring());
        } else if (i < 3) {
            require(final.header.status == Status::invalid && exit == 1 &&
                        diagnostic.starts_with("AETHER_GRAPHICS_SELFTEST:") &&
                        diagnostic.find("AETHER_GUEST_CAPABILITY_DENIED") != std::string::npos,
                    "Actual translated graphics did not report broker denial");
            require(!broker.audit().empty() && broker.audit().back().status == Status::denied &&
                        broker.audit().back().operation == WireOperation::graphics_call,
                    "Missing graphics broker denial");
            require(observed->metrics().draws == (i == 1 ? 0 : 1) && observed->metrics().readbacks == 0,
                    "Denied or revoked graphics performed unexpected work");
        } else {
            require(final.header.status == Status::invalid && exit == 1 &&
                        diagnostic.starts_with("AETHER_GRAPHICS_FIXTURE_NOT_TRUSTED:"),
                    "Worker accepted an altered graphics fixture");
            for (const auto &e : broker.audit())
                require(e.operation == WireOperation::package_info ||
                            e.operation == WireOperation::package_read,
                        "Altered graphics fixture reached runtime service");
        }
        require(released(observed->metrics()) && observed->retained_transfer_bytes() == 0,
                "Broker retained graphics resources or transfer data");
        const auto usage = service_process->accounting();
        require(!service_process->timed_out() && usage.active_processes == 0 &&
                    usage.active_process_ids.empty() && usage.total_processes == 1 &&
                    service_process->process_id() != worker.process_id() &&
                    service_process->process_id() != GetCurrentProcessId(),
                "Graphics service isolation or shutdown failed");
        if (i)
            isolation << ',';
        isolation << "{\"case\":" << json_quote(names[i]) << ",\"appId\":" << app_id
                  << ",\"profile\":" << json_quote(utf8(profile)) << ",\"processId\":" << worker.process_id()
                  << ",\"exitCode\":" << exit << ",\"fixtureSha256\":" << json_quote(sent_hash)
                  << ",\"graphicsProcessId\":" << service_process->process_id()
                  << ",\"graphicsActiveProcesses\":" << usage.active_processes
                  << ",\"graphicsTotalProcesses\":" << usage.total_processes
                  << ",\"graphicsMemoryLimitBytes\":" << usage.memory_limit_bytes
                  << ",\"graphicsPeakCommitBytes\":" << usage.peak_commit_bytes
                  << ",\"graphicsUserTime100ns\":" << usage.user_time_100ns
                  << ",\"graphicsUserTimeLimit100ns\":" << usage.user_time_limit_100ns
                  << ",\"graphicsLimitFlags\":" << usage.limit_flags
                  << ",\"graphicsImageMaximumAccess\":" << service_process->image_access().file
                  << ",\"graphicsDirectoryMaximumAccess\":" << service_process->image_access().directory
                  << ",\"draws\":" << observed->metrics().draws
                  << ",\"readbacks\":" << observed->metrics().readbacks
                  << ",\"resourcesReleased\":true,\"retainedTransferBytes\":0,\"diagnostic\":"
                  << json_quote(i ? diagnostic : "") << ",\"audit\":" << audit_json(broker)
                  << ",\"durableAudit\":" << journal->json() << '}';
    }
    isolation << "]}";
    report.isolation_json = isolation.str();
    return report;
}
} // namespace aether::graphics
