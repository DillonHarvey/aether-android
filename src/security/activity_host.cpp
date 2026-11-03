#include "aether/apk/inspect.hpp"
#include "aether/common/text.hpp"
#include "aether/security/activity_launch.hpp"
#include "aether/dex/fixture_hash.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/host/windows/clipboard_service.hpp"
#include "aether/host/native_window_context.hpp"
#include "aether/host/activity_observation_identity.hpp"
#include "aether/security/activity_session.hpp"
#include "aether/security/broker.hpp"
#include "aether/security/graphics_channel.hpp"
#include "aether/security/graphics_process.hpp"
#include "aether/security/native_surface_protocol.hpp"
#include "aether/security/viewport_protocol.hpp"
#include "aether/security/storage.hpp"
#include "aether/security/worker_progress.hpp"
#include "aether/security/startup_work.hpp"
#include <bcrypt.h>
#include <algorithm>
#include <cstdio>
#include <exception>
#include <map>
#include <sstream>
#include <thread>
#include <utility>

namespace aether::security {
namespace {
// Must remain derivable: throw_with_nested cannot attach a cause to the final
// ProtocolError type. The public boundary already handles std::exception.
class ActivityFailureContext : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};
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
// Defer the existing isolated renderer startup until an admitted graphics
// command needs it. Neither an idle app nor closing an unused channel starts
// a process. A failed startup is terminal and never retried.
class ActivityGraphicsChannel final : public graphics::GraphicsChannel {
    const std::filesystem::path executable;
    const std::uint64_t app_id;
    std::unique_ptr<GraphicsProcess> renderer;
    std::shared_ptr<host::NativeWindowContext> window;
    std::function<AwakeDeadlineClock::time_point()> outer_deadline;
    struct WindowSurface {
        std::uint64_t display = 0, producer = 0;
        bool deleted = false;
    };
    std::map<std::uint64_t, WindowSurface> window_surfaces;
    std::uint64_t draw_surface = 0, read_surface = 0;
    std::optional<android::NativeSurfaceRequest> admitted_request;
    std::optional<android::NativeSurfaceAdmission> admitted;
    bool attempted = false, closed = false, failed = false;
    void start_renderer() {
        if (renderer) return;
        require(!attempted, "Installed graphics renderer startup already failed");
        attempted = true;
        renderer = std::make_unique<GraphicsProcess>(executable, app_id);
    }
    void collect_deleted_windows() {
        std::erase_if(window_surfaces, [this](const auto &entry) {
            return entry.second.deleted && entry.first != draw_surface && entry.first != read_surface;
        });
    }
    void record_window_result(const graphics::GraphicsCommand &command, const graphics::GraphicsReply &reply) {
        if (reply.fault != a64::Fault::none || !reply.value) return;
        using Op = graphics::Operation;
        if (command.operation == Op::create_window && admitted && command.scalars[2] == admitted->backend_token) {
            require(window_surfaces.size() < 4 && !window_surfaces.contains(reply.value),
                    "Renderer window surface identity is duplicated or oversized");
            window_surfaces.emplace(reply.value, WindowSurface{command.scalars[0], admitted->producer, false});
        } else if (command.operation == Op::make_current) {
            draw_surface = command.scalars[1];
            read_surface = command.scalars[2];
        } else if (command.operation == Op::release_thread) {
            draw_surface = read_surface = 0;
        } else if (command.operation == Op::destroy_surface) {
            if (const auto found = window_surfaces.find(command.scalars[1]); found != window_surfaces.end())
                found->second.deleted = true;
        } else if (command.operation == Op::terminate) {
            for (auto &[id, surface] : window_surfaces) { (void)id; surface.deleted = true; }
        }
        collect_deleted_windows();
    }
    void check_deadline() const {
        require(outer_deadline && AwakeDeadlineClock::now() < outer_deadline(),
                "Activity exchange expired during native surface realization");
    }
    void retire_producer(std::uint64_t producer) {
        if (!renderer) return;
        auto current = window_surfaces.find(draw_surface);
        if (current == window_surfaces.end() || current->second.producer != producer)
            current = window_surfaces.find(read_surface);
        if (current != window_surfaces.end() && current->second.producer == producer) {
            check_deadline();
            graphics::GraphicsCommand command;
            command.operation = graphics::Operation::make_current;
            command.scalars[0] = current->second.display;
            // Direct renderer call: never resize/recreate a retiring consumer.
            const auto reply = renderer->exchange(command);
            require(reply.fault == a64::Fault::none && reply.value == 1,
                    "Cannot unbind the retiring native surface");
            record_window_result(command, reply);
        }
        for (auto it = window_surfaces.begin(); it != window_surfaces.end();) {
            if (it->second.producer != producer) { ++it; continue; }
            require(!it->second.deleted, "Retiring native surface remains current after unbinding");
            check_deadline();
            graphics::GraphicsCommand command;
            command.operation = graphics::Operation::destroy_surface;
            command.scalars[0] = it->second.display;
            command.scalars[1] = it->first;
            const auto reply = renderer->exchange(command);
            require(reply.fault == a64::Fault::none && reply.value == 1,
                    "Cannot drain the retiring native surface");
            it = window_surfaces.erase(it);
        }
        check_deadline();
    }
  public:
    ActivityGraphicsChannel(std::filesystem::path path, std::uint64_t id,
                            std::shared_ptr<host::NativeWindowContext> surface,
                            std::function<AwakeDeadlineClock::time_point()> deadline)
        : executable(std::move(path)), app_id(id), window(std::move(surface)), outer_deadline(std::move(deadline)) {}
    android::NativeSurfaceAdmission realize(const android::NativeSurfaceRequest &request) {
        require(window && !closed && !failed, "Native surface requires an installed UI presentation context");
        try {
            check_deadline();
            if (request.action == android::NativeSurfaceRequest::Action::abandon) {
                require(admitted && admitted_request && admitted->producer == request.producer &&
                            admitted_request->view == request.view &&
                            admitted_request->root == request.root &&
                            admitted_request->window_generation == request.window_generation,
                        "Native surface abandonment does not identify the admitted producer");
                retire_producer(request.producer);
            } else if (admitted_request) {
                require(admitted_request->view == request.view &&
                            admitted_request->root == request.root &&
                            admitted_request->window_generation == request.window_generation,
                        "Only one native surface consumer can be admitted");
            }
            const auto remaining = outer_deadline() - AwakeDeadlineClock::now();
            const auto wait = (std::min)(std::chrono::duration_cast<std::chrono::steady_clock::duration>(remaining),
                std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::seconds(5)));
            const auto result = window->request_surface(request, std::chrono::steady_clock::now() + wait);
            check_deadline();
            if (request.action == android::NativeSurfaceRequest::Action::admit && !result.producer) {
                require(!result.backend_token && !result.width && !result.height && !result.format,
                        "Deferred native admission contains producer data");
                return result; // Existing producer/backing custody is unchanged.
            }
            require(result.backend_token == window->token(), "UI native surface changed its permanent backend identity");
            if (request.action == android::NativeSurfaceRequest::Action::abandon) {
                require(result.producer == admitted->producer, "UI abandoned a different native producer");
                admitted.reset(); admitted_request.reset();
            } else {
                require(!admitted || result.producer == admitted->producer,
                        "UI replaced a producer without consumer retirement");
                // Admission is committed only after the real isolated renderer
                // accepts this actual backing. Java callbacks run after ACK.
                start_renderer();
                const auto snapshot = window->snapshot();
                require(snapshot.surface.width == result.width && snapshot.surface.height == result.height,
                        "Native surface admission differs from its actual backing");
                const bool deleted_current = std::any_of(window_surfaces.begin(), window_surfaces.end(),
                    [this](const auto &entry) {
                        return entry.second.deleted && (entry.first == draw_surface || entry.first == read_surface);
                    });
                if (deleted_current) {
                    // Complete actual prior EGL retirement before binding a new
                    // texture generation, rather than reviving a deleted one.
                    retire_producer(result.producer);
                }
                renderer->bind_window(snapshot.surface, snapshot.token, false);
                (void)window->snapshot();
                check_deadline();
                admitted = result; admitted_request = request;
            }
            return result;
        } catch (...) {
            failed = true;
            if (renderer) renderer->request_stop();
            throw;
        }
    }
    graphics::GraphicsReply exchange(const graphics::GraphicsCommand &command) override {
        require(!closed && !failed, "Installed graphics channel is closed or failed");
        try {
            if (window) {
                require(static_cast<bool>(outer_deadline), "Missing original Activity exchange deadline");
                const auto remaining = outer_deadline() - AwakeDeadlineClock::now();
                require(remaining > AwakeDeadlineClock::duration::zero(), "Activity exchange expired before presentation");
                const auto limit = std::chrono::duration_cast<std::chrono::steady_clock::duration>(remaining);
                const auto wait = (std::min)(limit, std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                    std::chrono::milliseconds(GraphicsProcess::command_timeout_ms)));
                // This wait cannot extend the already-armed Activity watchdog.
                // It holds no dispatcher lock while the UI publishes its HWND.
                (void)window->wait_snapshot(std::chrono::steady_clock::now() + wait);
            }
            start_renderer();
            if (window) {
                // Constructor-time cancellation can precede Dispatcher.active.
                // Never use an old captured snapshot after terminal UI close.
                const auto binding = window->snapshot();
                // EGL permits a destroyed-but-current surface to survive until
                // unbinding. Do not resize/recreate it before that genuine
                // cleanup command reaches the renderer.
                const bool deleted_current = std::any_of(window_surfaces.begin(), window_surfaces.end(),
                    [this](const auto &entry) {
                        return entry.second.deleted && (entry.first == draw_surface || entry.first == read_surface);
                    });
                if (!deleted_current) renderer->bind_window(binding.surface, binding.token, false);
                (void)window->snapshot();
                require(AwakeDeadlineClock::now() < outer_deadline(), "Activity exchange expired while binding presentation");
            }
            auto copied = command;
            if (window && copied.operation == graphics::Operation::create_window &&
                (!admitted || copied.scalars[2] != admitted->backend_token))
                copied.scalars[2] = 0; // Renderer reports EGL_BAD_NATIVE_WINDOW through its normal error state.
            auto reply = renderer->exchange(copied);
            record_window_result(copied, reply);
            return reply;
        } catch (...) {
            failed = true; // Never retry a failed startup, binding or command.
            if (renderer) renderer->request_stop();
            throw;
        }
    }
    graphics::GraphicsReply close() override {
        closed = true;
        return renderer ? renderer->close() : graphics::GraphicsReply{};
    }
};
} // namespace
struct IsolatedActivity::Impl {
    std::uint64_t session = 0, next_command = 1, next_observation = 1, last_observation_event_revision = 0;
    std::uint64_t next_soft_input = 1, last_soft_input_revision = 0;
    std::uint64_t next_surface = 1;
    std::uint64_t next_viewport = 1;
    std::shared_ptr<host::NativeWindowContext> viewport_window;
    std::optional<host::TrustedActivityLaunchIdentity> viewport_launch;
    ViewportLease viewport_custody;
    struct KeyOrigin {
        std::uint64_t origin = 0, final_ordinal = 0;
        KeyDispatchOutcome initial = KeyDispatchOutcome::none;
        KeyDispatchOutcome final = KeyDispatchOutcome::none;
    };
    std::array<KeyOrigin, 256> key_origins{};
    std::uint64_t next_key_result = 1;
    std::uint64_t next_finish_request = 1, last_finish_activity = 0, last_finish_generation = 0;
    std::optional<ActivityFinishRequest> finish_request;
    std::optional<android::SoftInputRequest> expected_soft_input;
    const std::thread::id owner = std::this_thread::get_id();
    std::shared_ptr<const void> installation_lease;
    ActivityState state;
    std::string package_hash;
    std::shared_ptr<AuditTrail> journal;
    std::unique_ptr<Broker> broker;
    ActivityGraphicsChannel *activity_graphics = nullptr; // Borrowed from broker-owned GraphicsBroker.
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
                  ActivityTerminalActivationSink terminal_observer = {},
                  std::shared_ptr<host::NativeWindowContext> native_window = {})
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
        if (application && native_window) {
            // Resolve the same held launch before composition. Legacy installed
            // launches retain their original MAIN selection and Intent delivery.
            viewport_launch = host::freeze_activity_launch_identity(package, application->launch.get());
            require(viewport_launch->apk_hash == package_hash,
                    "Viewport launch differs from the held installed package");
            viewport_window = native_window; // Graphics borrows the same context below.
        }
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
        // Only the admitted installed-app path receives native graphics.
        // Commands remain in the existing isolated renderer, never this host.
        policy.graphics = application != nullptr;
        std::unique_ptr<GraphicsService> graphics;
        if (policy.graphics) {
            auto channel = std::make_unique<ActivityGraphicsChannel>(
                directory / "runtime" / "aether_graphics_worker.exe", app_id, std::move(native_window), [this] {
                    require(worker != nullptr, "Graphics request has no current Activity worker");
                    return worker->exchange_deadline();
                });
            activity_graphics = channel.get();
            graphics = std::make_unique<GraphicsBroker>(std::move(channel));
        }
        broker = std::make_unique<Broker>(policy, journal, std::move(storage), std::move(package),
                                           std::move(audio), false, std::move(graphics), std::move(notifications), std::move(documents),
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
            const auto deadline=worker->exchange_deadline().time_since_epoch().count();
            const auto accounting=worker->accounting();
            require(deadline>0 && accounting.user_time_limit_100ns && accounting.memory_limit_bytes,
                    "Missing actual startup resource admission");
            const StartupWorkPolicy work_policy{1,static_cast<std::uint64_t>(deadline),
                accounting.user_time_limit_100ns,accounting.memory_limit_bytes};
            require(valid_startup_work_policy(work_policy),"Invalid actual startup resource admission");
            for(const auto value:{work_policy.version,work_policy.absolute_awake_deadline_100ns,
                work_policy.user_cpu_limit_100ns,work_policy.memory_limit_bytes})append_u64(boot.payload,value);
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
        } catch (...) {
            fail_session(std::current_exception(), "startup");
        }
    }
    [[noreturn]] void fail_session(std::exception_ptr primary, std::string_view phase) {
        failed = true;
        viewport_custody.retire_binding();
        std::string diagnostic = "AETHER_ACTIVITY_FAILURE_CONTEXT: phase=" + std::string(phase);
        const auto cleanup = [&](std::string_view operation, const auto &action) {
            try {
                action();
            } catch (const std::exception &error) {
                diagnostic += "; "; diagnostic += operation;
                diagnostic += " failed: "; diagnostic += error.what();
            } catch (...) {
                diagnostic += "; "; diagnostic += operation;
                diagnostic += " failed: non-standard exception";
            }
        };
        cleanup("broker close", [&] { broker->close(); });
        bool confirmed = false;
        // Exactly one termination attempt. No diagnostic reads of the shared
        // worker mapping are allowed unless process termination is confirmed.
        cleanup("worker termination", [&] { worker->terminate(); confirmed = true; });
        if (confirmed) {
            diagnostic += "; worker_exit_confirmed=true; timed_out=";
            diagnostic += worker->timed_out() ? "true" : "false";
            cleanup("worker exit status", [&] {
                diagnostic += "; windows_exit_code=" + std::to_string(worker->wait());
            });
            cleanup("worker accounting", [&] {
                const auto usage = worker->accounting();
                diagnostic += "; parent-trusted worker resource accounting: peak_commit_bytes=" +
                    std::to_string(usage.peak_commit_bytes) + ", memory_limit_bytes=" +
                    std::to_string(usage.memory_limit_bytes) + ", user_time_100ns=" +
                    std::to_string(usage.user_time_100ns) + ", kernel_time_100ns=" +
                    std::to_string(usage.kernel_time_100ns) + ", user_time_limit_100ns=" +
                    std::to_string(usage.user_time_limit_100ns);
            });
            if (progress) cleanup("worker progress", [&] {
                diagnostic += "; worker-reported diagnostics (untrusted): " + progress->summary_after_exit();
            });
        } else {
            diagnostic += "; worker exit not confirmed; resource/progress diagnostics not read";
        }
        cleanup("audit completion", [&] { journal->finish_aborted(); });
        // Preserve the original typed exception and any existing nested causes;
        // cleanup/accounting faults add context without replacing that failure.
        try {
            std::rethrow_exception(primary);
        } catch (...) {
            std::throw_with_nested(ActivityFailureContext(std::move(diagnostic)));
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
        viewport_custody.retire_binding();
        throw ActivityProcessExited(status);
    }
    void receive_viewport(const Frame &frame, std::uint64_t expected_context) {
        require(viewport_window && viewport_launch,
                "Viewport admission requires the actual installed UI presentation context");
        require(next_viewport != UINT64_MAX &&
                    !terminal_activations_received && !exited && !failed &&
                    frame.header.operation == Operation::activity_viewport_request &&
                    frame.header.status == Status::ok && frame.header.session == session &&
                    frame.header.sequence == next_viewport && frame.header.payload_size == frame.payload.size(),
                "Viewport request is not an admitted ordered Activity operation");
        const auto transaction = decode_viewport_request(frame.payload);
        const auto &request = transaction.request;
        require(transaction.context == expected_context, "Viewport request command context mismatch");
        require(request.requested_orientation == viewport_launch->requested_orientation,
                "Viewport request differs from the held launch orientation");
        if (request.phase == android::ViewportPhase::launch_geometry) {
            require(!viewport_custody.geometry() && state.package.empty(),
                    "Viewport launch geometry was replayed or relabelled");
        } else {
            require(viewport_custody.geometry() && !viewport_custody.binding_pending(),
                    "Viewport binding has no geometry or an uncorroborated prior attachment");
        }
        ++next_viewport; // Consume before owner mutation. Failure never retries this request.
        const auto remaining = worker->exchange_deadline() - AwakeDeadlineClock::now();
        require(remaining > AwakeDeadlineClock::duration::zero(),
                "Viewport admission exceeded the Activity exchange deadline");
        const auto admission = viewport_window->request_viewport(request,
            std::chrono::steady_clock::now() +
                std::chrono::duration_cast<std::chrono::steady_clock::duration>(remaining));
        require(AwakeDeadlineClock::now() < worker->exchange_deadline(),
                "Viewport admission exceeded the Activity exchange deadline");
        validate_viewport_admission(request, admission);
        // This stages a binding; only a later actual decoded state can commit it.
        viewport_custody.commit(request, admission);
        auto payload = encode_viewport_ack(request, admission, transaction.context);
        Frame ack{{Operation::activity_viewport_ack, frame.header.sequence, session,
                   static_cast<std::uint32_t>(payload.size()), Status::ok}, std::move(payload)};
        worker->send(ack); // The original watchdog remains armed across UI geometry admission.
    }
    void validate_viewport_state(const ActivityState &candidate) {
        if (!viewport_custody.geometry()) {
            require(!candidate.viewport_geometry_revision,
                    "Activity state invents a viewport geometry admission");
            return;
        }
        require(viewport_launch && candidate.apk_hash == viewport_launch->apk_hash &&
                    candidate.package == viewport_launch->package && candidate.activity == viewport_launch->activity,
                "Viewport state differs from the held resolved launch");
        if (!candidate.viewport_geometry_revision) {
            require(!viewport_custody.binding_pending() || !candidate.content || candidate.finishing ||
                        candidate.lifecycle == android::Lifecycle::destroyed ||
                        candidate.lifecycle == android::Lifecycle::failed,
                    "Live Activity state withdrew an uncorroborated viewport binding");
            // No content, retirement or actual root/configuration drift withdraws
            // binding authority without inventing a replacement geometry lease.
            viewport_custody.retire_binding();
            return;
        }
        require(candidate.lifecycle != android::Lifecycle::destroyed &&
                    candidate.lifecycle != android::Lifecycle::failed && !candidate.finishing,
                "Terminal Activity state retains a viewport binding");
        viewport_custody.validate_binding(
            {candidate.activity_object, candidate.content, candidate.window_generation, candidate.attachment_revision},
            candidate.viewport_geometry_revision, candidate.configuration);
    }
    void receive_native_surface(const Frame &frame, std::uint64_t expected_context) {
        require(activity_graphics && next_surface != UINT64_MAX && !terminal_activations_received &&
                    frame.header.operation == Operation::activity_surface_request &&
                    frame.header.status == Status::ok && frame.header.session == session &&
                    frame.header.sequence == next_surface,
                "Native surface request is not an admitted ordered Activity operation");
        const auto transaction = decode_native_surface_request(frame.payload);
        require(transaction.context == 0 || transaction.context == expected_context,
                "Native surface request command context mismatch");
        ++next_surface; // Consume this attempt before any owner/renderer mutation.
        const auto admission = activity_graphics->realize(transaction.request);
        auto payload = encode_native_surface_ack(transaction.request, admission, transaction.context);
        Frame ack{{Operation::activity_surface_ack, frame.header.sequence, session,
                   static_cast<std::uint32_t>(payload.size()), Status::ok}, std::move(payload)};
        worker->send(ack); // The original host exchange watchdog stays armed.
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
    void receive_finish_request(const Frame &frame) {
        require(next_finish_request != UINT64_MAX && frame.header.operation == Operation::activity_finish_request &&
                    frame.header.sequence == next_finish_request && frame.header.session == session &&
                    frame.header.status == Status::ok && frame.header.payload_size == frame.payload.size(),
                "Invalid Activity finish notice stream identity");
        const auto request = decode_activity_finish_request(frame.payload);
        require(request.ordinal == next_finish_request && !finish_request &&
                    request.activity != last_finish_activity && request.window_generation > last_finish_generation,
                "Duplicate, regressed or unconsumed Activity finish notice");
        // The real worker finishing latch prevents successor recreation. Do not
        // compare this fact with an older presentation snapshot in the I/O path.
        finish_request = request;
        last_finish_activity = request.activity;
        last_finish_generation = request.window_generation;
        Frame ack{{Operation::activity_finish_ack, request.ordinal, session, 24, Status::ok}, {}};
        append_u64(ack.payload, request.ordinal);
        append_u64(ack.payload, request.activity);
        append_u64(ack.payload, request.window_generation);
        worker->send(ack); // Fixed custody precedes receipt; no UI or guest callback.
        ++next_finish_request;
    }
    void receive_key_result(const Frame &frame) {
        require(next_key_result != UINT64_MAX && frame.header.operation == Operation::activity_key_result &&
                    frame.header.sequence == next_key_result && frame.header.session == session &&
                    frame.header.status == Status::ok && frame.header.payload_size == frame.payload.size(),
                "Invalid final key result stream identity");
        const auto result = decode_activity_key_result(frame.payload);
        const auto found = std::find_if(key_origins.begin(), key_origins.end(),
            [&](const auto &entry) { return entry.origin == result.origin; });
        require(found != key_origins.end() && !found->final_ordinal &&
                    (found->initial == KeyDispatchOutcome::none || found->initial == KeyDispatchOutcome::deferred),
                "Final key result has no unsettled deferred key origin");
        // Fixed host custody precedes receipt. A result arriving before its
        // initial state stays private until that state proves deferred admission.
        found->final = result.outcome;
        found->final_ordinal = next_key_result;
        Frame ack{{Operation::activity_key_result_ack, next_key_result, session, 16, Status::ok}, {}};
        append_u64(ack.payload, next_key_result);
        append_u64(ack.payload, result.origin);
        worker->send(ack);
        ++next_key_result;
    }
    std::vector<ActivityKeyResult> take_key_results() {
        require(std::this_thread::get_id() == owner, "Wrong final key custody owner");
        std::array<std::size_t, 256> ready{};
        std::size_t count = 0;
        for (std::size_t i = 0; i < key_origins.size(); ++i)
            if (key_origins[i].initial == KeyDispatchOutcome::deferred && key_origins[i].final_ordinal)
                ready[count++] = i;
        std::sort(ready.begin(), ready.begin() + count, [&](auto a, auto b) {
            return key_origins[a].final_ordinal < key_origins[b].final_ordinal;
        });
        std::vector<ActivityKeyResult> results;
        results.reserve(count); // Allocation failure cannot discard acknowledged custody.
        for (std::size_t i = 0; i < count; ++i) {
            const auto &entry = key_origins[ready[i]];
            results.push_back({entry.origin, entry.final});
        }
        for (std::size_t i = 0; i < count; ++i) key_origins[ready[i]] = {};
        return results;
    }
    std::optional<ActivityState> receive_state(std::uint64_t sequence, bool reading = false) {
        ActivityReassembly received(Operation::activity_state, sequence, session, activity_state_limit);
        bool began = false;
        while (!received.complete()) {
            const auto frame = worker->receive();
            if (frame.header.operation == Operation::guest_exited)
                process_exited(frame);
            if (frame.header.operation == Operation::activity_finish_request) {
                require(!began, "Activity finish notice interleaved with a presentation response");
                receive_finish_request(frame);
                continue;
            }
            require(frame.header.operation != Operation::activity_finish_ack,
                    "Worker sent a host-only Activity finish receipt");
            if (frame.header.operation == Operation::activity_key_result) {
                require(!began, "Final key result interleaved with a presentation response");
                receive_key_result(frame);
                continue;
            }
            require(frame.header.operation != Operation::activity_key_result_ack,
                    "Worker sent a host-only final key receipt");
            if (frame.header.operation == Operation::activity_surface_request) {
                require(!began, "Native surface request interleaved with a presentation response");
                receive_native_surface(frame, sequence);
                continue;
            }
            if (frame.header.operation == Operation::activity_viewport_request) {
                require(!began, "Viewport request interleaved with a presentation response");
                receive_viewport(frame, sequence);
                continue;
            }
            require(frame.header.operation != Operation::activity_viewport_ack,
                    "Worker sent a host-only viewport acknowledgement");
            require(frame.header.operation != Operation::activity_surface_ack,
                    "Worker sent a host-only native surface acknowledgement");
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
        validate_viewport_state(result);
        return result;
    }
    bool service_background() {
        require(std::this_thread::get_id() == owner && !exited && !failed,
                "Wrong owner thread or closed background service");
        try {
            const auto frame = worker->try_receive_idle();
            if (!frame) return false;
            if (frame->header.operation == Operation::activity_finish_request) {
                receive_finish_request(*frame);
                worker->end_exchange();
                return true;
            }
            require(frame->header.operation != Operation::activity_finish_ack,
                    "Worker sent a host-only Activity finish receipt while idle");
            if (frame->header.operation == Operation::activity_key_result) {
                receive_key_result(*frame);
                worker->end_exchange();
                return true;
            }
            require(frame->header.operation != Operation::activity_key_result_ack,
                    "Worker sent a host-only final key receipt while idle");
            if (frame->header.operation == Operation::activity_surface_request) {
                receive_native_surface(*frame, 0);
                worker->end_exchange();
                return true;
            }
            if (frame->header.operation == Operation::activity_viewport_request) {
                receive_viewport(*frame, 0);
                worker->end_exchange();
                return true;
            }
            require(frame->header.operation != Operation::activity_viewport_ack,
                    "Worker sent a host-only viewport acknowledgement while idle");
            require(frame->header.operation != Operation::activity_surface_ack,
                    "Worker sent a host-only native surface acknowledgement while idle");
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
            fail_session(std::current_exception(), "background");
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
            KeyOrigin *key_origin = nullptr;
            if (command.kind == ActivityCommandKind::key) {
                const auto slot = std::find_if(key_origins.begin(), key_origins.end(),
                    [](const auto &entry) { return !entry.origin; });
                require(slot != key_origins.end(), "Pending final key custody quota exceeded");
                key_origin = &*slot;
                key_origin->origin = sequence; // Before the first command fragment can reach the worker.
            }
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
            if (key_origin) {
                require(next && next->key_outcome != KeyDispatchOutcome::none,
                        "Key command has no initial outcome");
                key_origin->initial = next->key_outcome;
                if (key_origin->initial != KeyDispatchOutcome::deferred) {
                    require(!key_origin->final_ordinal, "Immediate key outcome also supplied a deferred final");
                    *key_origin = {};
                }
            } else if (next) {
                require(next->key_outcome == KeyDispatchOutcome::none, "Non-key command supplied a key outcome");
            }
            if (!next) {
                worker->end_exchange();
                unavailable = true;
            } else if (command.kind == ActivityCommandKind::close) {
                require(std::all_of(key_origins.begin(), key_origins.end(), [](const auto &entry) {
                    return !entry.origin || entry.final_ordinal;
                }), "Activity closed before its pending keys received final outcomes");
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
            fail_session(std::current_exception(), "command");
        }
        if (unavailable)
            throw ActivityReadUnavailable{};
    }
};
IsolatedActivity::IsolatedActivity(const std::filesystem::path &apk, ActivityMode mode,
                                 const std::filesystem::path &developer_output_root, ActivityTextEditSink observer,
                                 ActivitySoftInputSink soft_observer,
                                 std::shared_ptr<host::ClipboardWindowContext> clipboard_window,
                                    ActivityTerminalActivationSink terminal_observer,
                                    std::shared_ptr<host::NativeWindowContext> native_window)
    : impl_(std::make_unique<Impl>(apk, mode, nullptr, developer_output_root, std::move(observer),
                                   std::move(soft_observer), std::move(clipboard_window), std::move(terminal_observer), std::move(native_window))) {}
IsolatedActivity::IsolatedActivity(InstalledActivity application, ActivityTextEditSink observer,
                                   ActivitySoftInputSink soft_observer,
                                   std::shared_ptr<host::ClipboardWindowContext> clipboard_window,
                                    ActivityTerminalActivationSink terminal_observer,
                                    std::shared_ptr<host::NativeWindowContext> native_window)
    : impl_(std::make_unique<Impl>(std::filesystem::path{}, ActivityMode::normal, &application,
                                   std::filesystem::path{}, std::move(observer), std::move(soft_observer),
                                   std::move(clipboard_window), std::move(terminal_observer), std::move(native_window))) {}
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
        p.state.key_outcome = KeyDispatchOutcome::none;
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
        p.state.key_outcome = KeyDispatchOutcome::none;
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
std::vector<ActivityKeyResult> IsolatedActivity::take_key_results() { return impl_->take_key_results(); }
std::optional<ActivityFinishRequest> IsolatedActivity::take_finish_request() {
    require(std::this_thread::get_id() == impl_->owner, "Wrong Activity finish custody owner");
    return std::exchange(impl_->finish_request, std::nullopt);
}
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
    if (impl_->state.key_outcome == KeyDispatchOutcome::deferred)
        throw ProtocolError("AETHER_ACTIVITY_KEY_DEFERRED_UNSUPPORTED: Key already admitted; do not resubmit. Synchronous key() requires an immediate outcome; use dispatch() and take_key_results()");
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
std::uint64_t IsolatedActivity::transport_session() const noexcept { return impl_->session; }
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
