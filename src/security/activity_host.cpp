#include "aether/apk/inspect.hpp"
#include "aether/dex/fixture_hash.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/security/activity_session.hpp"
#include "aether/security/broker.hpp"
#include "aether/security/storage.hpp"
#include "aether/security/worker_progress.hpp"
#include <bcrypt.h>
#include <cstdio>
#include <sstream>
#include <thread>

namespace aether::security {
namespace {
void require(bool value, const char *message) {
    if (!value)
        throw ProtocolError(std::string("AETHER_ACTIVITY_HOST: ") + message);
}
std::filesystem::path binary_directory() {
    std::array<wchar_t, 32768> buffer{};
    const auto length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    require(length && length < buffer.size(), "Cannot locate the worker installation");
    return std::filesystem::path(std::wstring(buffer.data(), length)).parent_path();
}
} // namespace
struct IsolatedActivity::Impl {
    std::uint64_t session = 0, next_command = 1;
    const std::thread::id owner = std::this_thread::get_id();
    std::shared_ptr<const void> installation_lease;
    ActivityState state;
    std::string package_hash;
    std::shared_ptr<AuditTrail> journal;
    std::unique_ptr<Broker> broker;
    std::unique_ptr<WorkerProgress> progress;
    std::unique_ptr<WorkerProcess> worker;
    bool exited = false, failed = false;
    explicit Impl(const std::filesystem::path &path, ActivityMode mode,
                  const InstalledActivity *application = nullptr) {
        require(mode == ActivityMode::normal || mode == ActivityMode::read_recovery_probe ||
                    mode == ActivityMode::exit_zero_probe || mode == ActivityMode::exit_255_probe,
                "Invalid Activity mode");
        apk::InspectLimits limits;
        if (application)
            require(valid_installed_id(application->id) && application->package && application->lease &&
                        application->package_file && !application->package->empty() &&
                        (application->permissions & ~installed_permission_mask) == 0 &&
                        (application->permissions & installed_clock) &&
                        application->data_root.is_absolute() && application->audit_root.is_absolute() &&
                        mode == ActivityMode::normal,
                    "Invalid installed Activity configuration");
        auto package = application ? *application->package : apk::read_package(path, limits);
        package_hash = apk::sha256(package);
        if (!application && package_hash != dex::fixture::apk_sha256)
            throw dex::DexError("AETHER_ANDROID_FIXTURE_NOT_TRUSTED",
                                "Direct developer run accepts only the first-party fixture. "
                                "Install other APKs with Aether, then launch their installed app ID");
        require(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&session), sizeof(session),
                                BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 &&
                    session,
                "Cannot create worker session identity");
        const auto directory = binary_directory();
        const auto app_id = application ? installed_broker_id(application->id) : 76;
        const auto permissions = application ? application->permissions : installed_clock | installed_files;
        std::unique_ptr<host::FileService> storage;
        std::wstring profile = L"Aether.Development.Application.76";
        if (application) {
            installation_lease = application->lease;
            profile = L"Aether.Installed." + std::wstring(application->id.begin(), application->id.end());
            journal = make_file_audit_at_root(application->audit_root);
            if (permissions & installed_files)
                storage = std::make_unique<PrivateStorage>(application->data_root);
        } else {
            const auto storage_parent = directory / "activity-data";
            std::filesystem::create_directory(storage_parent);
            journal = make_file_audit(directory / "audit-data");
            storage = std::make_unique<PrivateStorage>(storage_parent, app_id);
        }
        struct StartupCompletion {
            Impl &session;
            bool ready = false;
            ~StartupCompletion() {
                if (!ready) {
                    session.worker.reset();
                    session.journal->finish_aborted();
                }
            }
        } startup{*this};
        BrokerPolicy policy{app_id, session, (permissions & installed_clock) != 0,
                            256, (permissions & installed_files) != 0, true};
        policy.wall_time = (permissions & installed_wall_clock) != 0;
        broker = std::make_unique<Broker>(policy, journal, std::move(storage), std::move(package));
        if (application) progress = std::make_unique<WorkerProgress>();
        worker = std::make_unique<WorkerProcess>(
            WorkerOptions{directory / "runtime" / "aether_worker.exe", profile, true, 15000, true});
        journal->bind_worker(worker->process_id());
        broker->bind_worker_thread(*worker);
        Frame boot{{Operation::boot, 0, session, 40, Status::ok}, {}};
        for (const auto value :
             {std::uint64_t{application ? 20u
                            : mode == ActivityMode::normal ? 11u
                            : mode == ActivityMode::read_recovery_probe ? 12u
                            : mode == ActivityMode::exit_zero_probe ? 29u : 30u},
              static_cast<std::uint64_t>(GetCurrentProcessId()), app_id, std::uint64_t{1}, std::uint64_t{0}})
            append_u64(boot.payload, value);
        if (application) {
            host::UniqueHandle mapping(
                CreateFileMappingW(application->package_file, nullptr, PAGE_READONLY, 0, 0, nullptr));
            require(static_cast<bool>(mapping), "Cannot map the held installed package for read access");
            append_u64(boot.payload, worker->duplicate_package_mapping(mapping.get()));
            append_u64(boot.payload, application->package->size());
            append_u64(boot.payload, worker->duplicate_progress_mapping(*progress));
            boot.header.payload_size = static_cast<std::uint32_t>(boot.payload.size());
        }
        try {
        worker->send(boot);
        const auto ack = worker->receive();
        require(ack.header.operation == Operation::boot && ack.header.sequence == 0 &&
                    ack.header.session == session && ack.header.status == Status::ok && ack.payload.empty(),
                "Worker did not acknowledge startup");
        state = *receive_state(0);
        require(state.lifecycle == android::Lifecycle::resumed && state.content, "Activity did not launch");
        worker->end_exchange();
        startup.ready = true;
        } catch (const ActivityProcessExited &) {
            startup.ready = true; // The typed exit has already been waited and journaled.
            throw;
        } catch (const std::exception &error) {
            // Never read worker-writable diagnostics while the process can mutate
            // them. These records are untrusted context, never policy evidence.
            if (!progress) throw;
            try { worker->request_stop(); (void)worker->wait(); }
            catch (...) { throw ProtocolError(std::string(error.what()) + "; startup diagnostics unavailable: worker exit not confirmed"); }
            throw ProtocolError(std::string(error.what()) + "; worker-reported startup diagnostics (untrusted): " + progress->summary_after_exit());
        }
    }
    ~Impl() {
        worker.reset();
        journal->finish_aborted(); // This session, including destruction, belongs to its I/O thread.
    }
    [[noreturn]] void process_exited(const Frame &frame) {
        const auto status = guest_exit_status(frame, session);
        require(worker->wait() == status && !worker->timed_out(),
                "Guest exit record differs from its Windows process result");
        broker->close();
        journal->finish();
        exited = true;
        throw ActivityProcessExited(status);
    }
    std::optional<ActivityState> receive_state(std::uint64_t sequence, bool reading = false) {
        ActivityReassembly received(Operation::activity_state, sequence, session, activity_state_limit);
        bool began = false;
        while (!received.complete()) {
            const auto frame = worker->receive();
            if (frame.header.operation == Operation::guest_exited)
                process_exited(frame);
            if (frame.header.operation == Operation::activity_read_unavailable) {
                validate_activity_read_unavailable(frame, sequence, session, reading, began);
                return std::nullopt;
            }
            if (frame.header.operation == Operation::finished) {
                require(frame.header.session == session && frame.header.status == Status::invalid &&
                            frame.payload.size() <= maximum_worker_error,
                        "Unexpected worker completion record");
                throw ProtocolError("AETHER_ACTIVITY_WORKER: " +
                                    std::string(frame.payload.begin(), frame.payload.end()));
            }
            if (frame.header.operation == Operation::activity_state) {
                began = true;
                received.accept(frame);
            } else {
                require(!began, "Broker request interleaved with a presentation response");
                worker->send(broker->dispatch(frame));
            }
        }
        auto result = ActivityState::decode(received.take());
        require(result.apk_hash == package_hash && !result.package.empty() && !result.activity.empty(),
                "Worker identity differs from the authorized APK");
        if (!state.package.empty())
            require(state.package == result.package && state.activity == result.activity &&
                        result.framework.view_revision >= state.framework.view_revision,
                    "Worker changed application identity or regressed its view revision");
        return result;
    }
    bool service_background() {
        require(std::this_thread::get_id() == owner && !exited && !failed,
                "Wrong owner thread or closed background service");
        try {
            const auto frame = worker->try_receive_idle();
            if (!frame) return false;
            if (frame->header.operation == Operation::guest_exited)
                process_exited(*frame);
            if (frame->header.operation == Operation::finished) {
                require(frame->header.session == session && frame->header.status == Status::invalid &&
                    frame->payload.size() <= maximum_worker_error, "Unexpected idle worker completion record");
                throw ProtocolError("AETHER_ACTIVITY_WORKER: " + std::string(frame->payload.begin(), frame->payload.end()));
            }
            require(frame->header.operation != Operation::activity_state &&
                    frame->header.operation != Operation::activity_read_unavailable,
                    "Unsolicited presentation response while idle");
            worker->send(broker->dispatch_idle(*frame));
            worker->end_exchange();
            return true;
        } catch (const ActivityProcessExited &) {
            throw; // App-owned termination is already waited and is not a runtime refusal.
        } catch (...) {
            failed = true;
            broker->close();
            try { worker->terminate(); }
            catch (...) { std::fputs("AETHER_ACTIVITY_TERMINATION_FAILED\n", stderr); }
            journal->finish_aborted();
            throw;
        }
    }
    void transact(const ActivityCommand &command) {
        require(std::this_thread::get_id() == owner && !exited && !failed && next_command != UINT64_MAX,
                "Wrong owner thread or closed Activity session");
        bool unavailable = false;
        try {
            const auto bytes = command.encode();
            worker->begin_exchange();
            broker->begin_turn();
            const auto sequence = next_command++;
            for (std::size_t offset = 0; offset < bytes.size(); offset += maximum_payload - 16)
                worker->send(
                    activity_fragment(bytes, offset, Operation::activity_command, sequence, session));
            auto next = receive_state(sequence, command.kind == ActivityCommandKind::refresh);
            if (!next) {
                worker->end_exchange();
                unavailable = true;
            } else if (command.kind == ActivityCommandKind::close) {
                require(next->lifecycle == android::Lifecycle::destroyed && next->views.empty(),
                        "Activity did not close");
                require(worker->wait() == 0 && !worker->timed_out(),
                        "Activity worker failed during shutdown");
                journal->finish();
                exited = true;
            } else {
                require(next->lifecycle != android::Lifecycle::destroyed &&
                            next->lifecycle != android::Lifecycle::failed,
                        "Worker unexpectedly ended the Activity");
                worker->end_exchange();
            }
            if (next)
                state = std::move(*next);
        } catch (const ActivityProcessExited &) {
            throw; // App-owned termination is already waited and is not a runtime refusal.
        } catch (...) {
            failed = true;
            broker->close();
            try {
                worker->terminate();
            } catch (...) {
                std::fputs("AETHER_ACTIVITY_TERMINATION_FAILED\n", stderr);
            }
            journal->finish_aborted();
            throw;
        }
        if (unavailable)
            throw ActivityReadUnavailable{};
    }
};
IsolatedActivity::IsolatedActivity(const std::filesystem::path &apk, ActivityMode mode)
    : impl_(std::make_unique<Impl>(apk, mode)) {}
IsolatedActivity::IsolatedActivity(InstalledActivity application)
    : impl_(std::make_unique<Impl>(std::filesystem::path{}, ActivityMode::normal, &application)) {}
IsolatedActivity::~IsolatedActivity() = default;
void IsolatedActivity::dispatch(const ActivityCommand &command) { impl_->transact(command); }
bool IsolatedActivity::service_background() { return impl_->service_background(); }
void IsolatedActivity::cancel() noexcept { impl_->worker->request_stop(); }
void IsolatedActivity::signal(android::WindowSignal value) {
    if (value == android::WindowSignal::close) {
        close();
        return;
    }
    ActivityCommand command;
    command.kind = ActivityCommandKind::signal;
    command.signal = value;
    impl_->transact(command);
}
void IsolatedActivity::place_views(std::span<const android::ViewPlacement> placements) {
    ActivityCommand command;
    command.kind = ActivityCommandKind::place;
    command.placements.assign(placements.begin(), placements.end());
    impl_->transact(command);
}
bool IsolatedActivity::pointer(const android::PointerInput &input) {
    ActivityCommand command;
    command.kind = ActivityCommandKind::pointer;
    command.pointer = input;
    impl_->transact(command);
    return impl_->state.handled;
}
bool IsolatedActivity::key(const android::KeyInput &input) {
    ActivityCommand command;
    command.kind = ActivityCommandKind::key;
    command.key = input;
    impl_->transact(command);
    return impl_->state.handled;
}
void IsolatedActivity::refresh() { impl_->transact(ActivityCommand{}); }
void IsolatedActivity::close() {
    if (!impl_->exited) {
        ActivityCommand command;
        command.kind = ActivityCommandKind::close;
        impl_->transact(command);
    }
}
const ActivityState &IsolatedActivity::snapshot() const noexcept { return impl_->state; }
std::uint32_t IsolatedActivity::probe(std::string_view name) const {
    for (std::size_t index = 0; index < activity_probes.size(); ++index)
        if (activity_probes[index] == name)
            return impl_->state.probes[index];
    throw ProtocolError("AETHER_ACTIVITY_PROBE: unknown first-party input probe");
}
std::uint32_t IsolatedActivity::process_id() const noexcept { return impl_->worker->process_id(); }
std::uint64_t IsolatedActivity::command_count() const noexcept { return impl_->next_command - 1; }
std::uint64_t IsolatedActivity::broker_calls() const noexcept { return impl_->broker->total_requests(); }
bool IsolatedActivity::exited() const noexcept { return impl_->exited; }
std::string IsolatedActivity::durable_audit_json() const { return impl_->journal->json(); }
std::string IsolatedActivity::audit_json() const {
    std::ostringstream out;
    out << '[';
    bool first = true;
    for (const auto &entry : impl_->broker->audit()) {
        if (!first)
            out << ',';
        first = false;
        out << "{\"appId\":" << entry.app_id << ",\"sequence\":" << entry.sequence
            << ",\"operation\":" << static_cast<unsigned>(entry.operation)
            << ",\"status\":" << static_cast<unsigned>(entry.status)
            << ",\"payloadBytes\":" << entry.payload_bytes
            << ",\"fileError\":" << static_cast<unsigned>(entry.file_error) << '}';
    }
    out << ']';
    return out.str();
}
} // namespace aether::security
