#include "aether/apk/inspect.hpp"
#include "aether/audio/fixture_hash.hpp"
#include "aether/common/text.hpp"
#include "aether/security/audio_session.hpp"
#include "aether/security/broker.hpp"
#include <bcrypt.h>
#include <fstream>
#include <sstream>

namespace aether::audio {
namespace {
using namespace security;
void require(bool value, const char *message) {
    if (!value)
        throw a64::GuestError("AETHER_AUDIO_ISOLATION", message);
}
std::uint64_t session_identity() {
    std::uint64_t value = 0;
    require(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&value), sizeof(value),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 &&
                value,
            "Cannot create an audio session identity");
    return value;
}
std::filesystem::path binary_directory() {
    std::array<wchar_t, 32768> path{};
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    require(size > 0 && size < path.size(), "Cannot locate isolated audio worker");
    return std::filesystem::path(path.data()).parent_path();
}
Frame run(WorkerProcess &worker, Broker &broker, std::uint64_t session, std::uint64_t app_id, bool revoke) {
    Frame boot{{Operation::boot, 0, session, 40, Status::ok}, {}};
    for (const auto n : {std::uint64_t{13}, static_cast<std::uint64_t>(GetCurrentProcessId()), app_id,
                         std::uint64_t{1}, std::uint64_t{0}})
        append_u64(boot.payload, n);
    worker.send(boot);
    const auto ack = worker.receive();
    require(ack.header.operation == Operation::boot && ack.header.sequence == 0 &&
                ack.header.session == session && ack.header.status == Status::ok && ack.payload.empty(),
            "Worker did not acknowledge isolated audio startup");
    for (;;) {
        auto request = worker.receive();
        if (request.header.operation == Operation::finished) {
            require(request.header.session == session &&
                        ((request.header.status == Status::ok &&
                          request.header.sequence == broker.total_requests() + 1) ||
                         (request.header.status == Status::invalid && request.header.sequence == 0 &&
                          request.payload.size() <= 512)),
                    "Invalid isolated audio completion");
            return request;
        }
        const auto response = broker.dispatch(request);
        if (revoke && request.header.operation == Operation::audio_control && request.payload.size() == 16 &&
            read_u64(request.payload, 8) == static_cast<std::uint64_t>(AudioControl::start) &&
            response.header.status == Status::ok) {
            // Revoke a live started stream; the next actual guest write must reach the broker and fail.
            broker.revoke_audio();
            revoke = false;
        }
        worker.send(response);
    }
}
std::string audit_json(const Broker &broker) {
    std::ostringstream out;
    out << '[';
    bool comma = false;
    for (const auto &entry : broker.audit()) {
        if (comma)
            out << ',';
        comma = true;
        out << "{\"appId\":" << entry.app_id << ",\"sequence\":" << entry.sequence
            << ",\"operation\":" << static_cast<unsigned>(entry.operation)
            << ",\"status\":" << static_cast<unsigned>(entry.status)
            << ",\"payloadBytes\":" << entry.payload_bytes << ",\"audioError\":" << entry.audio_error << '}';
    }
    out << ']';
    return out.str();
}
} // namespace
SelftestReport audio_selftest(const std::filesystem::path &path) {
    apk::InspectLimits limits;
    limits.archive_bytes = 1024 * 1024;
    const auto bytes = apk::read_package(path, limits);
    const auto hash = apk::sha256(bytes);
    if (hash != fixture::sha256)
        throw a64::GuestError("AETHER_AUDIO_FIXTURE_NOT_TRUSTED",
                              "Only the exact built-in first-party AAudio ELF may execute before Phase 7");
    const auto directory = binary_directory(), worker_path = directory / L"runtime" / L"aether_worker.exe";
    require(std::filesystem::is_regular_file(worker_path),
            "Isolated audio worker is absent; execution refused");
    SelftestReport report;
    std::ostringstream isolation;
    isolation << "{\"mode\":\"LPAC\",\"windowsCapabilities\":0,\"brokerOwnsWasapi\":true,"
                 "\"externalApkExecution\":false,\"parentProcessId\":"
              << GetCurrentProcessId() << ",\"runs\":[";
    constexpr std::array<const char *, 4> names{"allowed", "denied", "revoked", "altered"};
    for (std::size_t i = 0; i < names.size(); ++i) {
        const auto app_id = std::uint64_t{77} + (i == 3 ? 0 : i), session = session_identity();
        auto package = bytes;
        if (i == 3)
            package[0] ^= 1;
        const auto sent_hash = apk::sha256(package);
        const auto journal = make_file_audit(directory / "audit-data");
        Broker broker({app_id, session, true, 256, false, false, i != 1}, journal, {}, std::move(package),
                      std::make_unique<host::HostAudioService>(true), i == 0);
        const auto profile = L"Aether.Development.Audio." + std::to_wstring(app_id);
        WorkerProcess worker({worker_path, profile, true});
        journal->bind_worker(worker.process_id());
        const auto final = run(worker, broker, session, app_id, i == 2);
        const auto exit = worker.wait();
        journal->finish(final.header.status != Status::ok);
        require(!worker.timed_out(), "Isolated audio worker exceeded its deadline");
        const auto &snapshot = broker.audio().snapshot();
        const std::string diagnostic(final.payload.begin(), final.payload.end());
        if (i == 0) {
            if (final.header.status != Status::ok)
                throw a64::GuestError("AETHER_AUDIO_ISOLATION", "Audio worker failed: " + diagnostic);
            require(exit == 0, "Audio worker failed to exit normally");
            report = decode_audio_result(final.payload);
            require(report.passed() && report.fixture_hash == hash && report.relocations == 36 &&
                        report.fixture_frames == 32768,
                    "Isolated fixture checks failed");
            auto observed = snapshot;
            observed.token = 0xb6a0000000000001ULL;
            observed.value = 0;
            const AudioSnapshot claimed{observed.token, 0, host::AudioState::closed, report.host,
                                        report.playback};
            require(observed.encode() == claimed.encode(),
                    "Worker audio observations differ from the actual broker stream");
            const auto &pcm = broker.audio().fixture_pcm();
            require(pcm.size() == host::AudioStream::maximum_write_bytes,
                    "Missing actual transferred guest PCM");
            const auto capture = directory / L"audio-guest.pcm";
            std::ofstream output(capture, std::ios::binary | std::ios::trunc);
            output.write(reinterpret_cast<const char *>(pcm.data()),
                         static_cast<std::streamsize>(pcm.size()));
            output.close();
            require(static_cast<bool>(output), "Cannot save final guest PCM evidence");
            report.capture_path = utf8(capture.wstring());
        } else if (i < 3) {
            require(final.header.status == Status::invalid && exit == 1 &&
                        diagnostic.starts_with("AETHER_AUDIO_SELFTEST:") &&
                        diagnostic.find("CAPABILITY_DENIED") != std::string::npos,
                    "Actual translated audio did not report capability denial");
            require(!broker.audit().empty() && broker.audit().back().status == Status::denied &&
                        broker.audit().back().operation ==
                            (i == 1 ? Operation::audio_open : Operation::audio_write_begin),
                    "Audio denial did not come from the broker");
            require(snapshot.metrics.write_calls == (i == 1 ? 0 : 3) &&
                        snapshot.metrics.starts == (i == 1 ? 0 : 1),
                    "Denied or revoked audio performed an unexpected device write");
        } else {
            require(final.header.status == Status::invalid && exit == 1 &&
                        diagnostic.starts_with("AETHER_AUDIO_FIXTURE_NOT_TRUSTED:"),
                    "Worker accepted an altered audio fixture");
            for (const auto &entry : broker.audit())
                require(entry.operation == Operation::package_info ||
                            entry.operation == Operation::package_read,
                        "Altered audio fixture reached a runtime service");
        }
        require(!broker.audio().has_stream() && broker.audio().staged_bytes() == 0 &&
                    snapshot.metrics.cleanup_failures == 0,
                "Isolated audio leaked a stream or staged PCM");
        if (i)
            isolation << ',';
        isolation << "{\"case\":" << json_quote(names[i]) << ",\"appId\":" << app_id
                  << ",\"profile\":" << json_quote(utf8(profile)) << ",\"processId\":" << worker.process_id()
                  << ",\"exitCode\":" << exit << ",\"fixtureSha256\":" << json_quote(sent_hash)
                  << ",\"streams\":0,\"stagedBytes\":0,\"writeCalls\":" << snapshot.metrics.write_calls
                  << ",\"framesWritten\":" << snapshot.metrics.frames_written
                  << ",\"starts\":" << snapshot.metrics.starts
                  << ",\"cleanupFailures\":" << snapshot.metrics.cleanup_failures
                  << ",\"diagnostic\":" << json_quote(i ? diagnostic : "")
                  << ",\"audit\":" << audit_json(broker) << ",\"durableAudit\":" << journal->json() << '}';
    }
    isolation << "]}";
    report.isolation_json = isolation.str();
    return report;
}
} // namespace aether::audio
