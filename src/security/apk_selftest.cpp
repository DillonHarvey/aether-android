#include "aether/apk/inspect.hpp"
#include "aether/common/text.hpp"
#include "aether/dex/fixture_hash.hpp"
#include "aether/security/apk_session.hpp"
#include "aether/security/broker.hpp"
#include "aether/security/storage.hpp"
#include <bcrypt.h>
#include <bit>
#include <sstream>

namespace aether::security {
namespace {
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(std::string("AETHER_ISOLATED_APK: ") + message);
}
std::uint64_t random_session() {
    std::uint64_t value = 0;
    require(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&value), sizeof(value),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 &&
                value,
            "Cannot create a session identity");
    return value;
}
std::filesystem::path binary_directory() {
    std::array<wchar_t, 32768> path{};
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    require(size > 0 && size < path.size(), "Cannot locate the worker installation");
    return std::filesystem::path(path.data()).parent_path();
}
std::string seed_text(std::uint64_t app_id) { return "Parent canary " + std::to_string(app_id); }
void seed(PrivateStorage &storage, std::uint64_t app_id) {
    const auto text = seed_text(app_id);
    const auto file = storage.open("proof.txt", {false, true, true, false, true});
    require(file.error == host::FileError::none, "Cannot initialize controlled storage canary");
    const auto write = storage.write(static_cast<int>(file.value),
                                     {reinterpret_cast<const std::uint8_t *>(text.data()), text.size()});
    const auto close = storage.close(static_cast<int>(file.value));
    require(write.error == host::FileError::none && write.value == static_cast<std::int64_t>(text.size()) &&
                close.error == host::FileError::none,
            "Controlled storage initialization failed");
}
std::string read_proof(PrivateStorage &storage) {
    const auto file = storage.open("proof.txt", {true});
    require(file.error == host::FileError::none, "Cannot verify private file result");
    std::array<std::uint8_t, 128> bytes{};
    const auto read = storage.read(static_cast<int>(file.value), bytes);
    const auto close = storage.close(static_cast<int>(file.value));
    require(read.error == host::FileError::none && read.value >= 0 &&
                read.value < static_cast<std::int64_t>(bytes.size()) && close.error == host::FileError::none,
            "Private file readback failed");
    return {reinterpret_cast<const char *>(bytes.data()), static_cast<std::size_t>(read.value)};
}
Frame boot(std::uint64_t session, std::uint64_t app_id, bool allowed,
           const std::array<std::filesystem::path, 3> &paths) {
    Frame frame{{Operation::boot, 0, session, 0, Status::ok}, {}};
    const auto first = utf8(paths[0].wstring());
    for (const auto value : {std::uint64_t{10}, static_cast<std::uint64_t>(GetCurrentProcessId()), app_id,
                             static_cast<std::uint64_t>(allowed), static_cast<std::uint64_t>(first.size())})
        append_u64(frame.payload, value);
    frame.payload.insert(frame.payload.end(), first.begin(), first.end());
    append_text(frame.payload, utf8(paths[1].wstring()));
    append_text(frame.payload, utf8(paths[2].wstring()));
    frame.header.payload_size = static_cast<std::uint32_t>(frame.payload.size());
    return frame;
}
Frame run(WorkerProcess &worker, Broker &broker, const Frame &configuration) {
    worker.send(configuration);
    const auto ack = worker.receive();
    require(ack.header.operation == Operation::boot && ack.header.sequence == 0 &&
                ack.header.session == configuration.header.session && ack.header.status == Status::ok &&
                ack.payload.empty(),
            "Worker did not acknowledge isolated startup");
    for (;;) {
        auto frame = worker.receive();
        if (frame.header.operation == Operation::finished) {
            require(frame.header.session == configuration.header.session,
                    "Final worker result has the wrong session identity");
            if (frame.header.status == Status::ok)
                require(frame.header.sequence == broker.audit().size() + 1,
                        "Final worker sequence is inconsistent");
            return frame;
        }
        worker.send(broker.dispatch(frame));
    }
}
std::string audit_json(const Broker &broker) {
    std::ostringstream out;
    out << '[';
    for (std::size_t i = 0; i < broker.audit().size(); ++i) {
        const auto &entry = broker.audit()[i];
        if (i)
            out << ',';
        out << "{\"appId\":" << entry.app_id << ",\"sequence\":" << entry.sequence
            << ",\"operation\":" << static_cast<unsigned>(entry.operation)
            << ",\"status\":" << static_cast<unsigned>(entry.status)
            << ",\"payloadBytes\":" << entry.payload_bytes
            << ",\"fileError\":" << static_cast<unsigned>(entry.file_error) << '}';
    }
    out << ']';
    return out.str();
}
} // namespace
std::string isolated_apk_selftest(const std::filesystem::path &path, bool json) {
    apk::InspectLimits limits;
    limits.archive_bytes = 64 * 1024 * 1024;
    const auto bytes = apk::read_package(path, limits);
    const auto hash = apk::sha256(bytes);
    require(hash == dex::fixture::apk_sha256,
            "Only the exact first-party APK may execute before the security gate");
    const auto directory = binary_directory();
    const auto worker_path = directory / L"runtime" / L"aether_worker.exe";
    require(std::filesystem::is_regular_file(worker_path), "Isolated worker is absent; execution refused");
    const auto parent = directory / L"isolated-apk-data";
    std::filesystem::create_directory(parent);
    std::array<std::filesystem::path, 3> paths;
    for (std::size_t i = 0; i < paths.size(); ++i) {
        PrivateStorage storage(parent, 73 + i);
        seed(storage, 73 + i);
        paths[i] = storage.root() / L"proof.txt";
    }
    std::ostringstream reports;
    reports << '[';
    for (std::size_t i = 0; i < paths.size(); ++i) {
        const std::uint64_t app_id = 73 + i;
        const bool allowed = i < 2;
        const auto session = random_session();
        auto storage = std::make_unique<PrivateStorage>(parent, app_id);
        auto *readback = storage.get();
        const auto journal = make_file_audit(directory / "audit-data");
        Broker broker({app_id, session, true, 256, allowed}, journal, std::move(storage), bytes);
        WorkerProcess worker(
            {worker_path, L"Aether.Development.Application." + std::to_wstring(app_id), true});
        journal->bind_worker(worker.process_id());
        const auto final = run(worker, broker, boot(session, app_id, allowed, paths));
        const auto exit = worker.wait();
        journal->finish(final.header.status != Status::ok);
        if (final.header.status != Status::ok) {
            const std::string detail(final.payload.begin(), final.payload.end());
            throw ProtocolError("AETHER_ISOLATED_APK_WORKER: " + detail);
        }
        require(exit == 0 && !worker.timed_out(), "APK worker failed or exceeded its deadline");
        const auto result = ApkWorkerResult::decode(final.payload);
        require(result[ApkMetric::app_id] == app_id && result[ApkText::apk_hash] == hash &&
                    result[ApkMetric::checks] == 20 && result[ApkMetric::direct_file_denials] == 3 &&
                    result[ApkMetric::storage_denials] == 4 && result[ApkText::result] == "ARM64 result: 42",
                "APK worker result does not match the first-party oracle");
        const auto expected =
            allowed ? "Aether private storage " + std::to_string(app_id) : seed_text(app_id);
        require(read_proof(*readback) == expected,
                "Worker modified the wrong app's data or failed its authorized write");
        if (i)
            reports << ',';
        reports << "{\"result\":" << result.json() << ",\"storageAllowed\":" << (allowed ? "true" : "false")
                << ",\"profile\":" << json_quote("Aether.Development.Application." + std::to_string(app_id))
                << ",\"processId\":" << worker.process_id() << ",\"audit\":" << audit_json(broker)
                << ",\"durableAudit\":" << journal->json() << '}';
    }
    reports << ']';
    // Test the worker's own allowlist, after a correctly framed and hashed transfer.
    auto corrupt = bytes;
    corrupt[0] ^= 1;
    const auto corrupt_hash = apk::sha256(corrupt);
    const auto session = random_session();
    const auto journal = make_file_audit(directory / "audit-data");
    Broker broker({73, session, true, 256, false}, journal, {}, std::move(corrupt));
    WorkerProcess worker({worker_path, L"Aether.Development.Application.73", true});
    journal->bind_worker(worker.process_id());
    const auto rejected = run(worker, broker, boot(session, 73, false, paths));
    const std::string diagnostic(rejected.payload.begin(), rejected.payload.end());
    const auto rejected_exit = worker.wait();
    journal->finish(true);
    require(rejected.header.status == Status::invalid && rejected_exit == 1 && !worker.timed_out() &&
                diagnostic.starts_with("AETHER_ANDROID_FIXTURE_NOT_TRUSTED:"),
            "Worker accepted an altered APK");
    for (const auto &entry : broker.audit())
        require(entry.operation == Operation::package_info || entry.operation == Operation::package_read,
                "Altered APK reached a runtime capability service");
    if (!json)
        return "Isolated APK self-test: PASS; 3 LPAC applications, 60 Activity/DEX/JNI/ARM64 checks, scoped "
               "storage, 9 direct file denials and altered-APK rejection. Production security gate remains "
               "open.";
    return "{\"schemaVersion\":1,\"passed\":true,\"scope\":\"hash-identified-first-party-only\","
           "\"isolation\":\"LPAC\",\"windowsCapabilities\":0,\"androidOsStarted\":false,\"windowCreated\":"
           "false,"
           "\"externalApkExecution\":false,\"alteredPackageRejectedBeforeExecution\":true,\"applications\":" +
           reports.str() + ",\"alteredPackage\":{\"sha256\":" + json_quote(corrupt_hash) +
           ",\"processId\":" + std::to_string(worker.process_id()) +
           ",\"exitCode\":" + std::to_string(rejected_exit) +
           ",\"diagnosticCode\":\"AETHER_ANDROID_FIXTURE_NOT_TRUSTED\",\"audit\":" + audit_json(broker) +
           ",\"durableAudit\":" + journal->json() + "}}";
}
} // namespace aether::security
