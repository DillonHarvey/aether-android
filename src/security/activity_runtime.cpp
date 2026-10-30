#include "aether/security/notification_client.hpp"
#include "aether/apk/archive.hpp"
#include "aether/common/abort_message.hpp"
#include "aether/apk/compatibility.hpp"
#include "aether/apk/inspect.hpp"
#include "aether/apk/launcher.hpp"
#include "aether/apk/native_inventory.hpp"
#include "aether/apk/package.hpp"
#include "aether/audio/guest.hpp"
#include "aether/dex/archive_source.hpp"
#include "aether/dex/fixture_hash.hpp"
#include "aether/common/text.hpp"
#include "aether/common/process_exit.hpp"
#include "aether/elf/archive_source.hpp"
#include "aether/security/activity_session.hpp"
#include "aether/security/activity_launch.hpp"
#include "aether/security/audio_client.hpp"
#include "aether/security/client.hpp"
#include "aether/security/worker_progress.hpp"
#include <algorithm>
#include <exception>

#include <thread>

namespace aether::security {
namespace {
[[noreturn]] void fail(std::string message) { throw ProtocolError("AETHER_ACTIVITY_RUNTIME: " + message); }
struct ActivityPackage {
    std::vector<std::uint8_t> bytes;
    apk::ResourceTable resources;
    std::shared_ptr<dex::ClassSource> code;
    apk::PackageView archives;
    apk::NativeDirectory libraries;
    std::string hash, package, launcher, component_name, descriptor, application_descriptor, factory_descriptor;
    std::optional<apk::IntentValue> delivered_intent;
    std::int32_t requested_orientation = -1;
    android::DisplayConfiguration configuration;
    std::uint32_t config_changes = 0, target_sdk = 1;
    apk::ResourceTable display_resources(const android::DisplayConfiguration &display) const {
        if (!display.valid())
            fail("Invalid actual display configuration");
        apk::ResourceConfiguration target{static_cast<std::uint16_t>(display.density_dpi), android::compatibility_sdk,
                                          apk::ResourceSelectionPolicy::runtime_display};
        target.orientation = static_cast<std::uint8_t>(display.orientation());
        target.width_dp = static_cast<std::uint16_t>(display.screen_width_dp);
        target.height_dp = static_cast<std::uint16_t>(display.screen_height_dp);
        target.smallest_width_dp = static_cast<std::uint16_t>(display.smallest_screen_width_dp);
        return apk::ResourceTable::compose(archives, package, &target,
                                           {.names = apk::ResourceNamePolicy::optimized, .retain_bags = true});
    }
    explicit ActivityPackage(BrokerClient &client, bool installed, apk::Bytes mapped, WorkerProgressWriter *progress,
                             const ActivityLaunch *launch) {
        if (launch && !installed)
            fail("Resolved Activity launch requires an installed package");
        const auto stage = [progress](std::uint32_t id, std::string_view label) { if (progress) progress->stage(id,label); };
        stage(101,"package_verify");
        apk::InspectLimits limits;
        if (installed)
            client.verify_package(mapped);
        else
            bytes = client.read_package();
        const auto input = installed ? mapped : apk::Bytes(bytes);
        stage(102,"package_hash");
        hash = apk::sha256(input);
        if (!installed && hash != dex::fixture::apk_sha256)
            throw dex::DexError("AETHER_ANDROID_FIXTURE_NOT_TRUSTED",
                                "Developer Activity probes accept only the exact first-party APK");
        stage(103,"package_inspect");
        const auto report = apk::inspect_package(input, limits, {}, apk::ScanScope::runtime);
        const auto compatibility = apk::execution_compatibility(report);
        if (!compatibility.installable)
            throw dex::DexError("AETHER_ANDROID_PACKAGE_UNSUPPORTED", compatibility.reason);
        stage(104,"package_open");
        archives = apk::open_package(input, limits);
        const auto &manifest = report.manifest;
        package = manifest.package_id;
        application_descriptor = manifest.application_name.empty() ? "android.app.Application"
                                                                 : manifest.application_name;
        std::replace(application_descriptor.begin(), application_descriptor.end(), '.', '/');
        application_descriptor = 'L' + application_descriptor + ';';
        if (!manifest.app_component_factory_name.empty()) {
            factory_descriptor = manifest.app_component_factory_name;
            std::replace(factory_descriptor.begin(), factory_descriptor.end(), '.', '/');
            factory_descriptor = 'L' + factory_descriptor + ';';
        }
        std::size_t declaration = 0, target = 0;
        if (launch) {
            // Reinspect the immutable mapped APK and rerun the shared resolver
            // before creating any managed runtime or Application object.
            launch->validate_against(manifest, hash);
            if (launch->read_document) {
                host::DocumentInfo actual;
                const auto result = client.describe(launch->read_document->uri, actual);
                if (result.error != host::FileError::none || result.value != 0 ||
                    actual != *launch->read_document)
                    fail("Approved document metadata does not match the session-bound provider");
            }
            declaration = launch->declaration;
            target = launch->target;
            delivered_intent = launch->delivered_intent();
        } else {
            const auto selection = apk::select_launcher(manifest);
            if (!selection.activity)
                fail(selection.reason);
            declaration = *selection.activity;
        }
        requested_orientation = apk::requested_orientation(manifest, declaration);
        config_changes = apk::handled_configuration_changes(manifest, declaration);
        target_sdk = manifest.target_sdk.value_or(manifest.min_sdk.value_or(1));
        if (requested_orientation == 1) {
            configuration.screen_width_dp = 380;
            configuration.screen_height_dp = 560;
        }
        const auto &activity = manifest.activities[declaration];
        // The Intent names the selected declaration, including an alias. Its
        // executable class remains the separately resolved real target below.
        component_name = activity.name;
        launcher = launch ? manifest.activities[target].name
                          : (activity.target.empty() ? activity.name : activity.target);
        descriptor = launcher;
        std::replace(descriptor.begin(), descriptor.end(), '.', '/');
        descriptor = 'L' + descriptor + ';';
        std::vector<dex::ArchiveDexInput> dex_inputs;
        for (const auto &dex : report.dex)
            dex_inputs.push_back({archives.part(dex.file.container).archive, dex});
        stage(105,"dex_directory_index");
        code = std::make_shared<dex::ArchiveSource>(dex_inputs, dex::ArchiveIndexPolicy::directory);
        stage(106,"resource_compose");
        resources = display_resources(configuration);
        libraries = apk::NativeDirectory(report.native);
        stage(107,"managed_create");
    }
};

// Resolve Java and guest dynamic roots only from this immutable installed APK.
// The bridge retains validated resident graphs and separates JNI/ELF initialization.
class NativeLibraries final : public dex::NativeInterface {
    dex::ManagedRuntime &managed;
    a64::GuestMemory &memory;
    const a64::AppContext &app;
    BrokerClient &client;
    const ActivityPackage &package;
    const bool installed;
    std::unique_ptr<BrokerAudioService> audio_provider;
    std::unique_ptr<audio::GuestAudioServices> audio_services;
    std::unique_ptr<jni::Bridge> bridge;

    std::vector<elf::ModuleInput> module_inputs(std::string_view root) {
        const auto selected=package.libraries.inspect(package.archives,root);
        std::vector<elf::ModuleInput> modules;modules.reserve(selected.members().size());
        auto budget=std::make_shared<elf::ArchiveScanBudget>();
        for(const auto &member:selected.members()){
            const auto entry=package.archives.file(member.file);
            modules.push_back({member.name,{},std::make_shared<elf::ArchiveSource>(*entry.archive,entry.index,member.file.sha256,budget)});
        }
        return modules;
    }
  public:
    NativeLibraries(dex::ManagedRuntime &managed, a64::GuestMemory &memory, const a64::AppContext &app,
                    BrokerClient &client, const ActivityPackage &package, bool installed)
        : managed(managed), memory(memory), app(app), client(client), package(package), installed(installed) {
        managed.set_native_interface(this);
    }
    ~NativeLibraries() { managed.set_native_interface(nullptr); }
    bool supports_background() const noexcept override {return true;}
    void finish_logical_thread(dex::ManagedRuntime &runtime) override {if(bridge)bridge->finish_logical_thread(runtime);}
    void discard_logical_thread(dex::ObjectId thread) noexcept override {if(bridge)bridge->discard_logical_thread(thread);}

    std::uint64_t capture_signal_mask(dex::ManagedRuntime &runtime) override {return bridge?bridge->capture_signal_mask(runtime):0;}
    void load_library(dex::ManagedRuntime &runtime, std::u16string_view name) override {
        {
            std::string root = "lib";
            if (name.empty() || name.size() > 128)
                throw dex::DexError("AETHER_JNI_LIBRARY_UNSUPPORTED", "Invalid native library name");
            for (auto c : name) {
                if (!((c >= u'a' && c <= u'z') || (c >= u'A' && c <= u'Z') || (c >= u'0' && c <= u'9') ||
                      c == u'_' || c == u'-' || c == u'.' || c == u'+'))
                    throw dex::DexError("AETHER_JNI_LIBRARY_UNSUPPORTED", "Unsupported native library name");
                root += static_cast<char>(c);
            }
            root += ".so";
            if (bridge && bridge->has_library(root)) { bridge->load_library(runtime, name); return; }
            auto modules=module_inputs(root);
            if (bridge) bridge->add_library(modules, root);
            else {
                if (installed && !audio_services) {
                    // Even a denied installed app uses only the broker provider.
                    // AppContext and the independent broker policy both enforce consent.
                    audio_provider = std::make_unique<BrokerAudioService>(client);
                    audio_services = std::make_unique<audio::GuestAudioServices>(memory, app, false,
                                                                                audio_provider.get());
                }
                bridge=std::make_unique<jni::Bridge>(managed,memory,app,client,modules,root,&client,false,
                                                     package.package,audio_services.get());
                bridge->set_module_provider([this](std::string_view requested){
                    try{return module_inputs(requested);}
                    catch(const apk::InspectError &failure){throw bionic::DynamicLinkSourceError{failure.diagnostic.code};}
                });
            }
        }
        bridge->load_library(runtime, name);
    }
    dex::Value invoke(dex::ManagedRuntime &runtime, dex::Index method,
                      std::span<const dex::Value> arguments) override {
        if (!bridge)
            throw dex::DexError("AETHER_JNI_LIBRARY_UNSUPPORTED",
                                "Native method called before System.loadLibrary");
        return bridge->invoke(runtime, method, arguments);
    }
    jni::Metrics metrics() const { return bridge ? bridge->metrics() : jni::Metrics{}; }
    a64::Metrics cpu_metrics() const { return bridge ? bridge->cpu_metrics() : a64::Metrics{}; }
    void shutdown() {
        if (bridge)
            bridge->shutdown();
        if (audio_services)
            audio_services->shutdown();
        managed.set_native_interface(nullptr);
    }
};

class Runtime {
    ActivityPackage fixture;
    dex::ManagedRuntime managed;
    a64::GuestMemory memory;
    a64::AppContext app;
    NativeLibraries bridge;
    BrokerNotificationService notifications;
    BrokerClient &observation_client;
    std::uint64_t observation_context = 0;
    bool terminal_activations_attempted = false;
    android::ActivitySession activity;

  public:
    Runtime(BrokerClient &client, std::uint64_t app_id, bool installed, apk::Bytes mapped,
            WorkerProgressWriter *progress, bool audio_playback, const ActivityLaunch *launch)
        : fixture(client, installed, mapped, progress, launch), managed(std::move(fixture.code)),
          app{app_id, true, false, installed && audio_playback},
          bridge(managed, memory, app, client, fixture, installed),
          notifications(client), observation_client(client),
          activity(managed, fixture.package, std::move(fixture.resources), &client, &client, fixture.configuration,
                   &notifications, installed ? &client : nullptr, installed ? &client : nullptr) {
        app.process_state = managed.process_state();
        managed.set_progress_sink(progress);
        if (progress) progress->stage(108,"application_initialize");
        std::string_view stage = "Application";
        try {
            activity.initialize_application(fixture.application_descriptor, fixture.factory_descriptor);
            if (progress) progress->stage(109,"activity_launch");
            stage = "Activity";
            if (fixture.delivered_intent)
                activity.launch(fixture.descriptor, *fixture.delivered_intent, fixture.requested_orientation,
                                fixture.config_changes, fixture.target_sdk, fixture.component_name);
            else
                activity.launch(fixture.descriptor, fixture.requested_orientation, fixture.config_changes, fixture.target_sdk,
                                fixture.component_name);
            activity.check_view_activations();
        } catch (const ProcessExit &exit) {
            flush_terminal_activations(exit.signal ? ActivityTerminalReason::failure : ActivityTerminalReason::guest_exit);
            throw;
        } catch (const dex::JavaException &error) {
            flush_terminal_activations(ActivityTerminalReason::failure);
            const auto message = managed.exception_message(error.object);
            throw dex::DexError("AETHER_ANDROID_STARTUP_EXCEPTION",
                                std::string(stage) + " startup raised " +
                                    std::string(managed.object_type(error.object)) + ": " +
                                    utf8(std::wstring(message.begin(), message.end())));
        } catch (...) {
            flush_terminal_activations(ActivityTerminalReason::failure);
            throw;
        }
    }
    ~Runtime() {
        try { activity.set_text_edit_observer({}); } catch (...) { }
        try { activity.set_soft_input_observer({}); } catch (...) { }
        managed.close_tasks();
        managed.close_main_callbacks();
    }
    void activate_text_edit_observer() {
        activity.set_text_edit_observer([this](const android::TextEditObservation &observation) {
            observation_client.send_text_edit_observation(observation, observation_context);
        });
        activity.set_soft_input_observer([this](const android::SoftInputObservation &observation) {
            return observation_client.send_soft_input_observation(observation, observation_context);
        });
    }
    void check_text_edit_observer() const {
        activity.check_view_activations();
        activity.check_text_edit_observer();
    }
    void flush_terminal_activations(ActivityTerminalReason reason) {
        if (terminal_activations_attempted) return;
        terminal_activations_attempted = true; // No terminal transport attempt is retried.
        activity.prepare_terminal_cleanup();
        struct RetireChannel {
            BrokerClient &client;
            ~RetireChannel() { client.retire_activity_channel(); }
        } retire{observation_client};
        std::exception_ptr sticky_failure;
        try { check_text_edit_observer(); }
        catch (...) {
            sticky_failure = std::current_exception();
            reason = ActivityTerminalReason::failure;
        }
        ActivityTerminalActivations batch;
        batch.reason = reason;
        // Read only exact completed records. Do not snapshot a partially
        // unwound Activity, collect managed objects, or invoke guest callbacks.
        batch.records = activity.terminal_view_activations();
        batch.through_revision = activity.view_activation_revision();
        // Even an empty worker queue can leave earlier state records in host
        // custody. Terminal intent drains those facts without inventing any.
        observation_client.send_terminal_view_activations(batch, observation_context);
        // Custody is terminal, not ordinary state acknowledgement or success.
        // Preserve the sticky failure even when its valid prefix was received.
        if (sticky_failure) std::rethrow_exception(sticky_failure);
    }
    void acknowledge_snapshot_activations(const ActivityState &state) {
        if (!state.view_activations.empty())
            activity.acknowledge_view_activations(state.view_activations.back().revision);
    }
    void deactivate_text_edit_observer() {
        activity.set_text_edit_observer({});
        activity.set_soft_input_observer({});
    }
    void set_observation_context(std::uint64_t context) { observation_context = context; }
    bool pump_one() {
        try {
            const auto result = managed.run_task();
            check_text_edit_observer();
            return result;
        } catch (...) { check_text_edit_observer(); throw; }
    }
    bool pump_main() {
        try {
            const auto result = managed.run_main_callback();
            check_text_edit_observer();
            return result;
        } catch (...) { check_text_edit_observer(); throw; }
    }
    auto next_deadline() const { return managed.next_task_deadline(); }
    ActivityState snapshot(bool handled = false) {
        check_text_edit_observer();
        ActivityState result;
        result.apk_hash = fixture.hash;
        result.package = fixture.package;
        result.activity = fixture.launcher;
        result.lifecycle = activity.state();
        result.requested_orientation = activity.requested_orientation();
        result.configuration = activity.display_configuration();
        result.content = activity.content_view();
        result.views = activity.snapshot_views();
        result.soft_input_requests = activity.soft_input_requests();
        result.view_activations = activity.pending_view_activations();
        result.view_activation_revision = activity.view_activation_revision();
        result.accessibility_metadata_attempt = activity.accessibility_metadata_attempt();
        result.accessibility_metadata_status = activity.accessibility_metadata_status();
        result.accessibility_invalidation_revision = activity.accessibility_invalidation_revision();
        for (auto &[id, view] : result.views) {
            (void)id;
            // Publish only semantic eligibility. Managed listener identities
            // remain in the worker and are never carried by the state wire.
            view.clickable = view.kind == android::ViewKind::checkbox || view.listener != 0;
        }
        result.handled = handled;
        for (dex::Index i = 0; i < managed.image().fields.size(); ++i) {
            if (fixture.hash != dex::fixture::apk_sha256)
                break; // Probe names/types belong only to the exact developer fixture.
            const auto &field = managed.image().fields[i];
            if (managed.image().types[field.owner] != fixture.descriptor)
                continue;
            if (field.name == "trace")
                result.trace = managed.string(managed.get_static(i).bits);
            for (std::size_t probe = 0; probe < activity_probes.size(); ++probe)
                if (field.name == activity_probes[probe])
                    result.probes[probe] = static_cast<std::uint32_t>(managed.get_static(i).bits);
        }
        result.framework = activity.metrics();
        result.managed = managed.metrics();
        result.jni = bridge.metrics();
        result.cpu = bridge.cpu_metrics();
        return result;
    }
    ActivityState execute(const ActivityCommand &command) {
        bool handled = false;
        switch (command.kind) {
        case ActivityCommandKind::prepare_accessibility_metadata:
            handled = activity.prepare_accessibility_metadata(command.expected_view_revision, command.view);
            break;
        case ActivityCommandKind::collection_selection:
            handled = activity.collection_selection(command.view, command.collection_owner,
                command.expected_metadata_revision, command.expected_view_revision, command.collection_selection_operation);
            break;
        case ActivityCommandKind::configure:
            if (command.configuration != activity.display_configuration()) {
                auto replacement = fixture.display_resources(command.configuration);
                activity.configure(command.configuration, std::move(replacement));
            }
            break;
        case ActivityCommandKind::refresh:
            managed.collect();
            break;
        case ActivityCommandKind::place:
            activity.place_views(command.placements);
            break;
        case ActivityCommandKind::pointer:
            handled = activity.pointer(command.pointer);
            break;
        case ActivityCommandKind::drag: {
            if (command.drag.action == android::DragAction::started &&
                command.expected_view_revision != activity.metrics().view_revision) break;
            auto input = command.drag;
            if (input.action == android::DragAction::drop && input.kind == host::DropPayloadKind::plain_text) {
                if (!input.text_info) fail("Text DROP has no reviewed broker descriptor");
                std::u16string text;
                const auto result = observation_client.read_drop_text(input.id, *input.text_info, text);
                if (result.error != host::FileError::none || result.value != 0) break;
                input.text = std::move(text); // Only validated broker output reaches the actual callback.
            }
            handled = activity.drag(input);
            break;
        }
        case ActivityCommandKind::invoke:
            // A queued UIA element can retire during an earlier guest callback
            // or configuration recreation. Reject it without failing the app.
            handled = activity.views().contains(command.view) && activity.click(command.view);
            break;
        case ActivityCommandKind::focus:
            handled = activity.focus(command.view);
            break;
        case ActivityCommandKind::toggle:
            handled = activity.toggle(command.view);
            break;
        case ActivityCommandKind::scroll:
            handled = activity.scroll(command.view, command.scroll_amount);
            break;
        case ActivityCommandKind::set_scroll_percent:
            handled = activity.set_scroll_percent(command.view, command.scroll_percent);
            break;
        case ActivityCommandKind::replace_text:
            handled = activity.replace_text(command.view, command.replacement_text);
            break;
        case ActivityCommandKind::set_selection:
            handled = activity.set_selection(command.view, command.selection_start, command.selection_end,
                                             command.expected_text, command.expected_buffer_revision,
                                             command.expected_text_revision, command.selection_operation);
            break;
        case ActivityCommandKind::reveal_text_range:
            handled = activity.reveal_text_range(command.view, command.expected_view_revision, command.expected_text,
                                                 command.range_top, command.range_bottom, command.align_top);
            break;
        case ActivityCommandKind::claim_soft_input: {
            const auto requests = activity.soft_input_requests();
            handled = !requests.empty() && requests.front().view == command.view &&
                activity.claim_soft_input(command.soft_input_revision, command.ime_token,
                                           command.expected_view_revision, command.expected_text);
            break;
        }
        case ActivityCommandKind::ime_edit:
            handled = activity.ime_edit(command.ime_kind, command.view, command.ime_token,
                                         command.expected_view_revision, command.expected_text,
                                         command.replacement_text, command.ime_cursor, command.ime_conversion);
            break;
        case ActivityCommandKind::key:
            handled = activity.key(command.key);
            break;
        case ActivityCommandKind::signal:
            activity.signal(command.signal);
            break;
        case ActivityCommandKind::close:
            managed.close_tasks();
            managed.close_main_callbacks();
            activity.close();
            bridge.shutdown();
            managed.collect();
            break;
        }
        return snapshot(handled);
    }
};
void send_state(HANDLE writer, const ActivityState &state, std::uint64_t sequence, std::uint64_t session) {
    const auto bytes = state.encode();
    for (std::size_t offset = 0; offset < bytes.size(); offset += maximum_payload - 16)
        write_pipe_frame(writer,
                         activity_fragment(bytes, offset, Operation::activity_state, sequence, session));
}
} // namespace
std::uint8_t run_activity_worker(HANDLE reader, HANDLE writer, std::uint64_t session, std::uint64_t app_id,
                         bool read_recovery_probe, bool installed, apk::Bytes mapped_package,
                         WorkerProgressWriter *progress, bool audio_playback, const ActivityLaunch *launch) {
    try {
        BrokerClient client(reader, writer, session, true, true);
        Runtime runtime(client, app_id, installed, mapped_package, progress, audio_playback, launch);
        try {
            if (progress) progress->stage(110,"initial_state");
            {
                const auto initial_state = runtime.snapshot();
                send_state(writer, initial_state, 0, session);
                runtime.acknowledge_snapshot_activations(initial_state);
            }
            // Startup providers have not been exposed yet. Begin the acknowledged
            // actual-event stream only after the initial document state is sent.
            runtime.activate_text_edit_observer();
            for (std::uint64_t sequence = 1; sequence != UINT64_MAX; ++sequence) {
                runtime.set_observation_context(0);
                runtime.check_text_edit_observer();
                std::optional<std::vector<std::uint8_t>> bytes;
                while (!(bytes = client.poll_activity_command(sequence))) {
                    // Command delivery takes priority before each single managed quantum.
                    // BrokerClient retains commands that arrive during a broker RPC.
                    const bool delivered = runtime.pump_main();
                    if ((bytes = client.poll_activity_command(sequence))) break;
                    const bool advanced = runtime.pump_one();
                    if (delivered || advanced) continue;
                    const auto now = std::chrono::steady_clock::now();
                    auto wake = now + std::chrono::milliseconds(10);
                    if (const auto deadline = runtime.next_deadline()) wake = std::min(wake, *deadline);
                    if (wake > now) std::this_thread::sleep_for(wake - now);
                }
                const auto command = ActivityCommand::decode(*bytes);
                runtime.set_observation_context(sequence);
                if (read_recovery_probe && command.kind == ActivityCommandKind::refresh) {
                    // Controlled first-party failure: no read, guest callback or state mutation occurs.
                    // The public run path never enables this probe.
                    Sleep(1500);
                    runtime.check_text_edit_observer();
                    write_pipe_frame(
                        writer, {{Operation::activity_read_unavailable, sequence, session, 0, Status::ok}, {}});
                    read_recovery_probe = false;
                    continue;
                }
                const auto state = runtime.execute(command);
                send_state(writer, state, sequence, session);
                runtime.acknowledge_snapshot_activations(state);
                runtime.check_text_edit_observer();
                if (command.kind == ActivityCommandKind::close) {
                    runtime.deactivate_text_edit_observer();
                    return 0;
                }
            }
            fail("Activity command sequence exhausted");
        } catch (const ProcessExit &exit) {
            // Keep Runtime alive until hidden noexcept observer failures have
            // been checked; they must not become a successful guest-exit record.
            runtime.flush_terminal_activations(exit.signal ? ActivityTerminalReason::failure : ActivityTerminalReason::guest_exit);
            runtime.deactivate_text_edit_observer();
            if (exit.signal) throw ProtocolError(guest_signal_diagnostic(exit));
            if (progress) progress->stage(111,"guest_exited");
            write_pipe_frame(writer, guest_exit_frame(session, exit.status));
            return exit.status;
        } catch (...) {
            runtime.flush_terminal_activations(ActivityTerminalReason::failure);
            throw;
        }
    } catch (const ProcessExit &exit) {
        if(exit.signal)throw ProtocolError(guest_signal_diagnostic(exit));
        if (progress) progress->stage(111,"guest_exited");
        write_pipe_frame(writer, guest_exit_frame(session, exit.status));
        return exit.status;
    } catch (const dex::DexError &error) {
        throw ProtocolError(error.code + ": " + error.what());
    }
}
} // namespace aether::security
