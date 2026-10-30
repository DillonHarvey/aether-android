#include "aether/apk/inspect.hpp"
#include "aether/common/text.hpp"
#include "aether/security/activity_launch.hpp"
#include "aether/dex/fixture_hash.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/host/windows/clipboard_service.hpp"
#include "aether/security/activity_session.hpp"
#include "aether/security/broker.hpp"
#include "aether/security/storage.hpp"
#include "aether/security/worker_progress.hpp"
#include <bcrypt.h>
#include <cstdio>
#include <sstream>
#include <thread>
#include <utility>

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
    std::uint64_t session = 0, next_command = 1, next_observation = 1, last_observation_event_revision = 0;
    std::uint64_t next_soft_input = 1, last_soft_input_revision = 0;
    std::optional<android::SoftInputRequest> expected_soft_input;
    const std::thread::id owner = std::this_thread::get_id();
    std::shared_ptr<const void> installation_lease;
    ActivityState state;
    std::string package_hash;
    std::shared_ptr<AuditTrail> journal;
    std::unique_ptr<Broker> broker;
    std::unique_ptr<WorkerProgress> progress;
    std::unique_ptr<WorkerProcess> worker;
    ActivityTextEditSink text_edit_observer;
    ActivitySoftInputSink soft_input_observer;
    ActivityTerminalActivationSink terminal_activation_observer;
    bool terminal_activations_received = false;
    bool exited = false, failed = false;
    explicit Impl(const std::filesystem::path &path, ActivityMode mode,
                  const InstalledActivity *application = nullptr,
                  const std::filesystem::path &developer_output_root = {}, ActivityTextEditSink observer = {},
                  ActivitySoftInputSink soft_observer = {},
                  std::shared_ptr<host::ClipboardWindowContext> clipboard_window = {},
                  ActivityTerminalActivationSink terminal_observer = {})
        : text_edit_observer(std::move(observer)), soft_input_observer(std::move(soft_observer)),
          terminal_activation_observer(std::move(terminal_observer)) {
        require(mode == ActivityMode::normal || mode == ActivityMode::read_recovery_probe ||
                    mode == ActivityMode::exit_zero_probe || mode == ActivityMode::exit_255_probe ||
                    mode == ActivityMode::abort_probe || mode == ActivityMode::allocation_failure_probe,
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
        std::vector<std::uint8_t> launch_bytes;
        if (application && application->launch) {
            application->launch->validate();
            require(application->launch->apk_hash == package_hash, "Launch request belongs to different held APK bytes");
            launch_bytes = application->launch->encode();
        }
        std::shared_ptr<host::DocumentService> documents;
        if (application) {
            const bool supplied = application->read_document.has_value();
            const bool declared = application->launch && application->launch->read_document.has_value();
            require(supplied == declared, "Document service and captured launch metadata must be supplied together");
            if (supplied) {
                const auto &document = *application->read_document;
                require(document.service && host::valid_document_info(document.info) &&
                            *application->launch->read_document == document.info,
                        "Document service metadata differs from the admitted launch");
                host::DocumentInfo actual;
                const auto result = document.service->describe(document.info.uri, actual);
                require(result.error == host::FileError::none && result.value == 0 && actual == document.info,
                        "Admitted document service no longer describes the reviewed document");
                const auto delivered = application->launch->delivered_intent();
                const auto text = [](std::string_view value) {
                    const auto wide = utf16(value);
                    return std::u16string(wide.begin(), wide.end());
                };
                require(delivered.action == std::optional<std::u16string>{u"android.intent.action.VIEW"} &&
                            delivered.data == std::optional<std::u16string>{text(actual.uri)} &&
                            delivered.mime_type == std::optional<std::u16string>{text(actual.mime_type)} &&
                            delivered.resolved_mime_type == delivered.mime_type && delivered.flags == 0x10000001u,
                        "Delivered VIEW request differs from the approved document service");
                documents = document.service;
            }
        }
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
            const auto &output = developer_output_root.empty() ? directory : developer_output_root;
            require(output.is_absolute(), "Developer output root must be a trusted absolute path");
            const auto storage_parent = output / "activity-data";
            std::filesystem::create_directory(storage_parent);
            journal = make_file_audit(output / "audit-data");
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
        policy.clipboard = application && (permissions & installed_clipboard) != 0 && clipboard_window;
        std::unique_ptr<host::ClipboardService> clipboard;
        if (policy.clipboard) clipboard = std::make_unique<host::HostClipboardService>(std::move(clipboard_window));
        // Admission supplies this host-only identity only after saved consent,
        // held-package checks and current owned notification registration.
        policy.notifications = application && (permissions & installed_notifications) != 0 &&
            !application->notification_aumid.empty();
        std::unique_ptr<host::NotificationService> notifications;
        if (policy.notifications) {
            require(application->notification_aumid == "Aether.App." + application->id,
                    "Notification attribution differs from the admitted app");
            notifications = std::make_unique<host::HostNotificationService>(application->notification_aumid, true);
        }
        policy.audio_playback = application && (permissions & installed_audio_playback) != 0;
        std::unique_ptr<host::AudioService> audio;
        if (policy.audio_playback) {
            require(!application->audio_display_name.empty() && application->audio_icon_path.is_absolute(),
                    "Missing trusted installed audio attribution");
            audio = std::make_unique<host::HostAudioService>(host::AudioSessionIdentity{
                application->id, application->audio_display_name, application->audio_icon_path});
        }
        broker = std::make_unique<Broker>(policy, journal, std::move(storage), std::move(package),
                                           std::move(audio), false, nullptr, std::move(notifications), std::move(documents),
                                           std::move(clipboard));
        if (application) progress = std::make_unique<WorkerProgress>();
        worker = std::make_unique<WorkerProcess>(
            WorkerOptions{directory / "runtime" / "aether_worker.exe", profile, true, 15000, true});
        journal->bind_worker(worker->process_id());
        broker->bind_worker_thread(*worker);
        Frame boot{{Operation::boot, 0, session, 40, Status::ok}, {}};
        for (const auto value :
             {std::uint64_t{application ? (application->launch ? installed_intent_scenario : 20u)
                            : mode == ActivityMode::normal ? 11u
                            : mode == ActivityMode::read_recovery_probe ? 12u
                            : mode == ActivityMode::exit_zero_probe ? 29u
                            : mode == ActivityMode::exit_255_probe ? 30u
                            : mode == ActivityMode::abort_probe ? 31u : 32u},
              static_cast<std::uint64_t>(GetCurrentProcessId()), app_id, std::uint64_t{1}, std::uint64_t{0}})
            append_u64(boot.payload, value);
        if (application) {
            host::UniqueHandle mapping(
                CreateFileMappingW(application->package_file, nullptr, PAGE_READONLY, 0, 0, nullptr));
            require(static_cast<bool>(mapping), "Cannot map the held installed package for read access");
            append_u64(boot.payload, worker->duplicate_package_mapping(mapping.get()));
            append_u64(boot.payload, application->package->size());
            append_u64(boot.payload, worker->duplicate_progress_mapping(*progress));
            append_u64(boot.payload, policy.audio_playback ? 1u : 0u);
            if (application->launch) append_u64(boot.payload, launch_bytes.size());
            boot.header.payload_size = static_cast<std::uint32_t>(boot.payload.size());
        }
        try {
        worker->send(boot);
        const auto ack = worker->receive();
        require(ack.header.operation == Operation::boot && ack.header.sequence == 0 &&
                    ack.header.session == session && ack.header.status == Status::ok && ack.payload.empty(),
                "Worker did not acknowledge startup");
        for (std::size_t offset = 0; offset < launch_bytes.size(); offset += maximum_payload - 16)
            worker->send(activity_fragment(launch_bytes, offset, Operation::activity_launch, 0, session));
        state = *receive_state(0);
        require(state.lifecycle == android::Lifecycle::resumed && state.content, "Activity did not launch");
        if (application && application->launch) {
            const auto text = [](std::u16string_view value) { return utf8(std::wstring(value.begin(), value.end())); };
            require(state.apk_hash == package_hash && state.package == text(application->launch->package) &&
                        state.activity == text(application->launch->target_name),
                    "Initial Activity state differs from the immutable resolved request");
        }
        worker->end_exchange();
        startup.ready = true;
        } catch (const ActivityProcessExited &) {
            startup.ready = true; // The typed exit has already been waited and journaled.
            throw;
        } catch (const std::exception &error) {
            // Confirm exit before reading either retained kernel accounting or
            // worker-writable progress. The two sources have different authority.
            std::uint32_t exit_code = 0;
            try { worker->request_stop(); exit_code = worker->wait(); }
            catch (...) { throw ProtocolError(std::string(error.what()) + "; startup diagnostics unavailable: worker exit not confirmed"); }
            std::string diagnostic(error.what());
            try {
                const auto usage = worker->accounting();
                const auto accounting = "; parent-trusted worker resource accounting: peak_commit_bytes=" +
                    std::to_string(usage.peak_commit_bytes) + ", memory_limit_bytes=" +
                    std::to_string(usage.memory_limit_bytes) + ", user_time_100ns=" +
                    std::to_string(usage.user_time_100ns) + ", user_time_limit_100ns=" +
                    std::to_string(usage.user_time_limit_100ns) + ", windows_exit_code=" +
                    std::to_string(exit_code);
                diagnostic += accounting;
            } catch (...) {
                diagnostic += "; parent-trusted worker resource accounting unavailable; confirmed windows_exit_code=" +
                    std::to_string(exit_code);
            }
            if (progress) {
                try {
                    diagnostic += "; worker-reported startup diagnostics (untrusted): " + progress->summary_after_exit();
                } catch (...) {
                    diagnostic += "; worker-reported startup diagnostics unavailable";
                }
            }
            throw ProtocolError(std::move(diagnostic));
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
    void receive_text_edit(const Frame &first, std::uint64_t expected_context) {
        require(next_observation != UINT64_MAX, "TextEdit observation sequence exhausted");
        ActivityReassembly received(Operation::activity_text_edit, next_observation, session,
                                    activity_text_edit_observation_limit + 8);
        received.accept(first);
        while (!received.complete()) {
            const auto frame = worker->receive();
            if (frame.header.operation == Operation::guest_exited) process_exited(frame);
            received.accept(frame); // No broker or presentation interleave inside one record.
        }
        auto bytes = received.take();
        require(bytes.size() > 8, "Incomplete TextEdit observation context");
        const auto context = read_u64(bytes, 0);
        // A background observation can race a newly submitted command. Its
        // zero context remains valid before that command's presentation starts.
        require(context == 0 || context == expected_context, "TextEdit observation command context mismatch");
        const auto observation = decode_activity_text_edit_observation(std::span<const std::uint8_t>(bytes).subspan(8));
        require(observation.event.revision > last_observation_event_revision,
                "TextEdit observation event order regressed");
        if (text_edit_observer) text_edit_observer(observation, context, worker->exchange_deadline());
        // No observer means explicit consumption without later replay or new
        // provider creation. Receipt alone is not a native acceptance result.
        Frame ack{{Operation::activity_text_edit_ack, next_observation, session, 16, Status::ok}, {}};
        append_u64(ack.payload, context);
        append_u64(ack.payload, observation.event.revision);
        worker->send(ack); // Rechecks the original deadline; never resets it.
        last_observation_event_revision = observation.event.revision;
        ++next_observation;
    }
    void receive_soft_input(const Frame &first, std::uint64_t expected_context) {
        require(next_soft_input != UINT64_MAX, "Soft input observation sequence exhausted");
        ActivityReassembly received(Operation::activity_soft_input, next_soft_input, session,
                                    activity_soft_input_observation_limit + 8);
        received.accept(first);
        while (!received.complete()) {
            const auto frame = worker->receive();
            if (frame.header.operation == Operation::guest_exited) process_exited(frame);
            received.accept(frame);
        }
        auto bytes = received.take();
        require(bytes.size() > 8, "Incomplete soft input observation context");
        const auto context = read_u64(bytes, 0);
        require(context == 0 || context == expected_context, "Soft input command context mismatch");
        const auto observation = decode_activity_soft_input_observation(std::span<const std::uint8_t>(bytes).subspan(8));
        require(observation.request.revision > last_soft_input_revision, "Soft input request revision regressed");
        // Consume the host's actual claim witness before any external callback.
        // A worker-originated flag/record alone cannot create a native action.
        const auto expected = context ? std::exchange(expected_soft_input, std::nullopt)
                                      : std::optional<android::SoftInputRequest>{};
        const auto &request = observation.request;
        const bool admitted = context && expected && expected->revision == request.revision &&
            expected->window_generation == request.window_generation && expected->view == request.view &&
            expected->show == request.show && expected->implicit == request.implicit;
        const bool accepted = admitted && soft_input_observer &&
            soft_input_observer(observation, context, worker->exchange_deadline());
        Frame ack{{Operation::activity_soft_input_ack, next_soft_input, session, 24, Status::ok}, {}};
        append_u64(ack.payload, context); append_u64(ack.payload, request.revision); append_u64(ack.payload, accepted);
        worker->send(ack);
        last_soft_input_revision = request.revision;
        ++next_soft_input;
    }
    [[noreturn]] void receive_terminal_activations(const Frame &first, std::uint64_t expected_context) {
        require(!terminal_activations_received, "Duplicate terminal activation stream");
        ActivityReassembly received(Operation::activity_activation_terminal, 1, session,
                                    activity_terminal_activations_limit);
        received.accept(first);
        while (!received.complete()) received.accept(worker->receive());
        const auto bytes = received.take();
        require(bytes.size() > 8, "Incomplete terminal activation context");
        const auto context = read_u64(bytes, 0);
        require(context == 0 || context == expected_context, "Terminal activation command context mismatch");
        const auto batch = decode_activity_terminal_activations(std::span<const std::uint8_t>(bytes).subspan(8));
        require(batch.records.empty()
                    ? batch.through_revision == state.view_activation_revision
                    : state.view_activation_revision != UINT64_MAX &&
                      batch.records.front().revision == state.view_activation_revision + 1 &&
                      batch.records.back().revision == batch.through_revision,
                "Terminal activation history does not continue the last state");
        terminal_activations_received = true; // Consume stream authority before the borrowed sink.
        if (terminal_activation_observer)
            terminal_activation_observer(batch, context, worker->exchange_deadline());
        Frame ack{{Operation::activity_activation_terminal_ack, 1, session, 16, Status::ok}, {}};
        append_u64(ack.payload, context); append_u64(ack.payload, batch.through_revision);
        worker->send(ack); // Original exchange deadline remains armed throughout UI custody.
        // Terminal receipt can never release queued commands or enter idle broker service.
        const auto final = worker->receive();
        if (batch.reason == ActivityTerminalReason::guest_exit) {
            require(final.header.operation == Operation::guest_exited, "Terminal guest exit has no matching final record");
            process_exited(final);
        }
        require(final.header.operation == Operation::finished && final.header.sequence == 0 && final.header.session == session &&
                    final.header.status == Status::invalid && final.payload.size() <= maximum_worker_error,
                "Terminal failure has no matching final record");
        throw ProtocolError("AETHER_ACTIVITY_WORKER: " + std::string(final.payload.begin(), final.payload.end()));
    }
    std::optional<ActivityState> receive_state(std::uint64_t sequence, bool reading = false) {
        ActivityReassembly received(Operation::activity_state, sequence, session, activity_state_limit);
        bool began = false;
        while (!received.complete()) {
            const auto frame = worker->receive();
            if (frame.header.operation == Operation::guest_exited)
                process_exited(frame);
            if (frame.header.operation == Operation::activity_activation_terminal) {
                require(!began, "Terminal activations interleaved with a presentation response");
                receive_terminal_activations(frame, sequence);
            }
            require(frame.header.operation != Operation::activity_activation_terminal_ack,
                    "Worker sent a host-only terminal activation acknowledgement");
            if (frame.header.operation == Operation::activity_text_edit) {
                require(!began, "TextEdit observation interleaved with a presentation response");
                receive_text_edit(frame, sequence);
                continue;
            }
            if (frame.header.operation == Operation::activity_soft_input) {
                require(!began, "Soft input observation interleaved with a presentation response");
                receive_soft_input(frame, sequence);
                continue;
            }
            require(frame.header.operation != Operation::activity_soft_input_ack,
                    "Worker sent a host-only soft input acknowledgement");
            require(frame.header.operation != Operation::activity_text_edit_ack,
                    "Worker sent a host-only TextEdit acknowledgement");
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
            if (frame->header.operation == Operation::activity_activation_terminal)
                receive_terminal_activations(*frame, 0);
            require(frame->header.operation != Operation::activity_activation_terminal_ack,
                    "Worker sent a host-only terminal activation acknowledgement while idle");
            if (frame->header.operation == Operation::activity_text_edit) {
                receive_text_edit(*frame, 0);
                worker->end_exchange();
                return true;
            }
            if (frame->header.operation == Operation::activity_soft_input) {
                receive_soft_input(*frame, 0); // Unclaimed idle records receive false; no UI action.
                worker->end_exchange();
                return true;
            }
            require(frame->header.operation != Operation::activity_soft_input_ack,
                    "Worker sent a host-only soft input acknowledgement while idle");
            require(frame->header.operation != Operation::activity_text_edit_ack,
                    "Worker sent a host-only TextEdit acknowledgement while idle");
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
            expected_soft_input.reset();
            if (command.kind == ActivityCommandKind::claim_soft_input && !state.soft_input_requests.empty()) {
                const auto &head = state.soft_input_requests.front();
                if (head.revision == command.soft_input_revision && head.view == command.view)
                    expected_soft_input = head;
            }
            struct ResetClaim { Impl &session; ~ResetClaim() { session.expected_soft_input.reset(); } } reset_claim{*this};
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
IsolatedActivity::IsolatedActivity(const std::filesystem::path &apk, ActivityMode mode,
                                 const std::filesystem::path &developer_output_root, ActivityTextEditSink observer,
                                 ActivitySoftInputSink soft_observer,
                                 std::shared_ptr<host::ClipboardWindowContext> clipboard_window,
                                   ActivityTerminalActivationSink terminal_observer)
    : impl_(std::make_unique<Impl>(apk, mode, nullptr, developer_output_root, std::move(observer),
                                   std::move(soft_observer), std::move(clipboard_window), std::move(terminal_observer))) {}
IsolatedActivity::IsolatedActivity(InstalledActivity application, ActivityTextEditSink observer,
                                   ActivitySoftInputSink soft_observer,
                                   std::shared_ptr<host::ClipboardWindowContext> clipboard_window,
                                   ActivityTerminalActivationSink terminal_observer)
    : impl_(std::make_unique<Impl>(std::filesystem::path{}, ActivityMode::normal, &application,
                                   std::filesystem::path{}, std::move(observer), std::move(soft_observer),
                                   std::move(clipboard_window), std::move(terminal_observer))) {}
IsolatedActivity::~IsolatedActivity() = default;
void IsolatedActivity::dispatch(const ActivityCommand &command) {
    require(command.kind != ActivityCommandKind::drag || command.drag.action != android::DragAction::drop,
            "DROP requires explicitly reviewed document service admission");
    impl_->transact(command);
}
void IsolatedActivity::drop_document(host::PreparedDocumentSource source, const ActivityCommand &command) {
    auto &p = *impl_;
    require(std::this_thread::get_id() == p.owner && p.installation_lease && !p.exited && !p.failed &&
                command.kind == ActivityCommandKind::drag && command.drag.action == android::DragAction::drop &&
                command.drag.kind == host::DropPayloadKind::file &&
                command.drag.document && source.service && source.info == *command.drag.document,
            "Invalid current installed Activity document DROP admission");
    (void)command.encode();
    const auto result = p.broker->stage_drop_document(source.info, std::move(source.service), command.drag.id);
    if (result.error != host::FileError::none) {
        p.state.handled = false; // Refused admission is not a guest mutation and is never retried.
        return;
    }
    try {
        p.transact(command);
        // A real requestDragAndDropPermissions may retain rights independently
        // from the callback's handled boolean. Only unclaimed intake is retired.
        p.broker->finish_drop_document(command.drag.id);
    } catch (...) {
        p.broker->discard_drop_document(command.drag.id);
        throw;
    }
}
void IsolatedActivity::drop_text(std::u16string text, const ActivityCommand &command) {
    auto &p = *impl_;
    require(std::this_thread::get_id() == p.owner && p.installation_lease && !p.exited && !p.failed &&
                command.kind == ActivityCommandKind::drag && command.drag.action == android::DragAction::drop &&
                command.drag.kind == host::DropPayloadKind::plain_text && command.drag.text_info &&
                host::matches_drop_text(*command.drag.text_info, text),
            "Invalid current installed Activity text DROP admission");
    (void)command.encode();
    const auto result = p.broker->stage_drop_text(*command.drag.text_info, std::move(text), command.drag.id);
    if (result.error != host::FileError::none) {
        p.state.handled = false;
        return;
    }
    try {
        p.transact(command);
        // Plain text is a delivered managed copy, not a retained URI grant.
        p.broker->discard_drop_text(command.drag.id);
    } catch (...) {
        p.broker->discard_drop_text(command.drag.id);
        throw;
    }
}
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
bool IsolatedActivity::drop_file(const std::wstring &path) {
    (void)path;
    // A key event cannot carry a document identity, MIME type or scoped grant.
    // A raw path alone does not carry explicit recipient/document review.
    throw ProtocolError("AETHER_ACTIVITY_DROP_UNSUPPORTED: Use reviewed typed document DROP admission");
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
