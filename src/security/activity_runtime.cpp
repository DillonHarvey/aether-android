#include "aether/security/notification_client.hpp"
#include "aether/apk/archive.hpp"
#include "aether/common/abort_message.hpp"
#include "aether/apk/compatibility.hpp"
#include "aether/apk/inspect.hpp"
#include "aether/apk/launcher.hpp"
#include "aether/apk/native_inventory.hpp"
#include "aether/apk/package.hpp"
#include "aether/audio/guest.hpp"
#include "aether/graphics/guest.hpp"
#include "aether/dex/archive_source.hpp"
#include "aether/dex/fixture_hash.hpp"
#include "aether/common/text.hpp"
#include "aether/common/process_exit.hpp"
#include "aether/common/android_process_identity.hpp"
#include "aether/elf/archive_source.hpp"
#include "aether/security/activity_session.hpp"
#include "aether/security/activity_launch.hpp"
#include "aether/security/audio_client.hpp"
#include "aether/security/client.hpp"
#include "aether/security/graphics_channel.hpp"
#include "aether/android/native_window.hpp"
#include "aether/android/native_activity.hpp"
#include "aether/android/viewport.hpp"
#include "aether/security/worker_progress.hpp"
#include "aether/security/startup_work.hpp"
#include <algorithm>
#include <exception>
#include <functional>

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
    android::PackageMetadata package_metadata;
    apk::ManifestInteger theme;
    // Selected component metadata is distinct from the executable alias target.
    // Retention alone does not admit a NativeActivity entry or load a library.
    apk::ManifestNativeEntry native_entry;
    std::string hash, package, launcher, component_name, descriptor, application_descriptor, factory_descriptor;
    std::optional<apk::IntentValue> delivered_intent;
    std::int32_t requested_orientation = -1;
    android::DisplayConfiguration configuration;
    std::optional<android::ViewportAdmission> launch_viewport;
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
        auto report = apk::inspect_package(input, limits, {}, apk::ScanScope::runtime);
        const auto compatibility = apk::execution_compatibility(report);
        if (!compatibility.installable)
            throw dex::DexError("AETHER_ANDROID_PACKAGE_UNSUPPORTED", compatibility.reason);
        stage(104,"package_open");
        archives = apk::open_package(input, limits);
        const auto &manifest = report.manifest;
        package = manifest.package_id;
        package_metadata.declared_services = manifest.declared_services;
        package_metadata.service_inventory_bound = manifest.service_inventory_bound;
        package_metadata.application_enabled = manifest.enabled;
        package_metadata.application_enabled_bound = true;
        // Attribute absence is known: integer_value rejects unsupported typed
        // values, and Android defines absent version-code components as zero.
        package_metadata.version_code = manifest.version_code.value_or(0);
        package_metadata.version_code_major = manifest.version_code_major.value_or(0);
        if(manifest.version_name_present) {
            if(manifest.version_name_resource) {
                package_metadata.version_name_resource = manifest.version_name_resource;
            } else {
                const auto literal = utf16(manifest.version_name);
                package_metadata.version_name = std::u16string(literal.begin(),literal.end());
            }
        }
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
        theme = apk::activity_theme(manifest, declaration);
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
        package_metadata.application_label = manifest.label;
        package_metadata.supports_rtl = manifest.supports_rtl;
        package_metadata.application_target_sdk = target_sdk;
        package_metadata.supports_rtl_bound = true;
        {
            const auto title_name = utf16(activity.name);
            package_metadata.activity_name.assign(title_name.begin(), title_name.end());
        }
        if (activity.target.empty()) {
            package_metadata.activity_label = activity.label;
            package_metadata.activity_label_bound = true;
        }
        if(!manifest.activity_native_entries.empty())
            native_entry=manifest.activity_native_entries.at(declaration);
        launcher = launch ? manifest.activities[target].name
                          : (activity.target.empty() ? activity.name : activity.target);
        descriptor = launcher;
        std::replace(descriptor.begin(), descriptor.end(), '.', '/');
        descriptor = 'L' + descriptor + ';';
        if (installed) {
            const android::ViewportRequest request{
                android::ViewportPhase::launch_geometry, requested_orientation, 0, {}};
            auto admitted = client.request_viewport(request, 0);
            if (!admitted.geometry_revision || !admitted.width_px || !admitted.height_px ||
                !admitted.host_dpi || !admitted.configuration.valid() || !admitted.has_navigation_bar.has_value() ||
                admitted.identity != android::ViewportIdentity{})
                fail("Launch viewport acknowledgement has no valid unbound host geometry");
            // Actual host geometry is fixed before resource composition and
            // before any Application, Theme or Activity construction.
            configuration = admitted.configuration;
            launch_viewport = std::move(admitted);
        }
        std::vector<dex::ArchiveDexInput> dex_inputs;
        for (const auto &dex : report.dex)
            dex_inputs.push_back({archives.part(dex.file.container).archive, dex});
        stage(105,"dex_directory_index");
        code = std::make_shared<dex::ArchiveSource>(dex_inputs, dex::ArchiveIndexPolicy::directory);
        stage(106,"resource_compose");
        resources = display_resources(configuration);
        libraries = apk::NativeDirectory(report.native);
        // Transfer complete raw component metadata only after every launch,
        // title, native-entry and resource-composition use of this report.
        // No second owned Activity/metadata inventory is allocated here.
        package_metadata.activity_config_changes = std::move(report.manifest.activity_config_changes);
        package_metadata.activity_recreate_on_config_changes =
            std::move(report.manifest.activity_recreate_on_config_changes);
        package_metadata.activities = std::move(report.manifest.activities);
        package_metadata.activity_meta_data = std::move(report.manifest.activity_meta_data);
        package_metadata.activity_meta_data_bound = report.manifest.activity_meta_data_bound;
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
    WorkerProgressWriter *progress;
    android::DisplayConfiguration native_configuration;
    std::unique_ptr<BrokerAudioService> audio_provider;
    std::unique_ptr<audio::GuestAudioServices> audio_services;
    std::unique_ptr<BrokerGraphicsChannel> graphics_provider;
    std::unique_ptr<graphics::GuestGraphicsServices> graphics_services;
    std::unique_ptr<jni::Bridge> bridge;
    std::optional<std::uint64_t> last_trimmed_compile_count;
    bool native_setup_failed = false;
    std::optional<apk::SelectedNativeEntry> native_entry_selection;
    jni::ManagedAssetManagerAccess asset_manager_access;
    std::function<bool(dex::ObjectId)> canonical_asset_manager_valid;
    android::NativeActivityInputCompletionFactory input_completion_factory;
    android::NativeActivityHostWorkFactory host_work_factory;
    std::shared_ptr<android::NativeWindows> native_windows;
    std::function<std::shared_ptr<android::NativeWindowProducer>(dex::ObjectId)> surface_valid;

    void reclaim_native_warmup_translations(std::uint64_t compiled_before) {
        if(!bridge)return;
        const auto compiled=bridge->cpu_metrics().compiled_blocks;
        if(last_trimmed_compile_count && compiled_before==compiled)return;
        // Public native calls have unwound here. The bridge additionally proves
        // aggregate quiescence, including inactive/parked execution capsules.
        if(bridge->trim_translation_cache())last_trimmed_compile_count=compiled;
    }
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
                    BrokerClient &client, const ActivityPackage &package, bool installed,WorkerProgressWriter *progress)
        : managed(managed), memory(memory), app(app), client(client), package(package), installed(installed),progress(progress),
          native_configuration(package.configuration) {
        managed.set_native_interface(this);
    }
    ~NativeLibraries() {
        asset_manager_access = {};
        canonical_asset_manager_valid = {};
        surface_valid = {};
        bridge.reset();
        managed.set_native_interface(nullptr);
    }
    void set_asset_manager_access(jni::ManagedAssetManagerAccess access) {
        canonical_asset_manager_valid = {};
        asset_manager_access = std::move(access);
    }
    void set_canonical_asset_manager_validator(std::function<bool(dex::ObjectId)> validator) {
        asset_manager_access = {};
        canonical_asset_manager_valid = std::move(validator);
    }
    void clear_asset_manager_access() noexcept {
        asset_manager_access = {};
        canonical_asset_manager_valid = {};
    }
    void set_native_windows(std::shared_ptr<android::NativeWindows> windows,
                            std::function<std::shared_ptr<android::NativeWindowProducer>(dex::ObjectId)> resolver) {
        if (bridge || native_windows || !windows || !resolver)
            throw ProtocolError("AETHER_NATIVE_SURFACE: native registry requires initial session binding");
        native_windows = std::move(windows);
        surface_valid = std::move(resolver);
    }
    void clear_surface_validator() noexcept { surface_valid = {}; }
    void set_native_input_completion_factory(android::NativeActivityInputCompletionFactory factory) {
        if(bridge || input_completion_factory || !factory)
            throw ProtocolError("AETHER_NATIVE_INPUT: completion factory requires initial session binding");
        input_completion_factory=std::move(factory);
    }
    void clear_native_input_completion_factory() noexcept { input_completion_factory={}; }
    void set_native_activity_host_work_factory(android::NativeActivityHostWorkFactory factory) {
        if(bridge || host_work_factory || !factory)throw ProtocolError("AETHER_NATIVE_ACTIVITY_WORK: invalid initial binding");
        host_work_factory=std::move(factory);
    }
    void clear_native_activity_host_work_factory() noexcept { host_work_factory={}; }

    void set_display_configuration(const android::DisplayConfiguration &configuration) {
        if(!configuration.valid())throw ProtocolError("AETHER_NATIVE_CONFIGURATION: invalid display facts");
        if(bridge)bridge->set_display_configuration(configuration);
        native_configuration=configuration;
    }
    void prepare_native_surface_admission() {
        if (graphics_services) graphics_services->prepare_native_surface_admission();
    }
    bool supports_background() const noexcept override {return true;}
    bool pump_native_tasks(dex::ManagedRuntime &runtime) override {
        if(&runtime!=&managed)throw dex::DexError("AETHER_JNI_STATE", "Native task pump belongs to another runtime");
        return bridge && bridge->pump_native_tasks(runtime);
    }
    std::optional<std::chrono::steady_clock::time_point> next_native_deadline() const override {
        return bridge?bridge->next_native_deadline():std::nullopt;
    }
    void finish_logical_thread(dex::ManagedRuntime &runtime) override {if(bridge)bridge->finish_logical_thread(runtime);}
    void discard_logical_thread(dex::ObjectId thread) noexcept override {if(bridge)bridge->discard_logical_thread(thread);}

    std::uint64_t capture_signal_mask(dex::ManagedRuntime &runtime) override {return bridge?bridge->capture_signal_mask(runtime):0;}
    void prepare_library(dex::ManagedRuntime &runtime, std::u16string_view name) {
        if(&runtime!=&managed)throw dex::DexError("AETHER_JNI_STATE", "Native graph belongs to another runtime");
        if(native_setup_failed)
            throw dex::DexError("AETHER_JNI_LOAD_STATE", "Native host binding previously failed; initializers remain barred");
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
            if (bridge && bridge->has_library(root)) return;
            auto modules=module_inputs(root);
            if (bridge) bridge->add_library(modules, root);
            else {
                // Binding failure may retire shared native registries. Never
                // publish a partial bridge or silently retry its setup.
                native_setup_failed=true;
                if (installed && !audio_services) {
                    // Even a denied installed app uses only the broker provider.
                    // AppContext and the independent broker policy both enforce consent.
                    audio_provider = std::make_unique<BrokerAudioService>(client);
                    audio_services = std::make_unique<audio::GuestAudioServices>(memory, app, false,
                                                                                audio_provider.get());
                }
                if (installed && !graphics_services) {
                    // Installed native graphics always uses the copied-command
                    // broker channel. The independent host policy admits it.
                    graphics_provider = std::make_unique<BrokerGraphicsChannel>(client);
                    graphics_services = std::make_unique<graphics::GuestGraphicsServices>(memory, app,
                                                                                         graphics_provider.get());
                    if (native_windows) graphics_services->set_native_windows(native_windows);
                }
                auto prepared=std::make_unique<jni::Bridge>(managed,memory,app,client,modules,root,&client,false,
                                                     package.package,audio_services.get(),graphics_services.get());
                if(progress)prepared->set_initialization_observer(progress,
                    [](void *context,const elf::InitializationProgress &event) noexcept {
                        static_cast<WorkerProgressWriter *>(context)->native_initialization(
                            static_cast<std::uint32_t>(event.stage),event.module,event.entry);
                    });
                jni::ManagedAssetManagerAccess access;
                access.publish = [this](dex::ObjectId object) -> std::uint64_t {
                    return asset_manager_access.publish ? asset_manager_access.publish(object) : 0;
                };
                access.owns = [this](std::uint64_t token) {
                    return asset_manager_access.owns && asset_manager_access.owns(token);
                };
                if (asset_manager_access.publish && asset_manager_access.owns) {
                    prepared->set_assets(package.archives, std::move(access));
                } else {
                    // The direct startup profile has no retained provider-work
                    // owner for eager source preparation. Preserve its original
                    // canonical manager admission without inventing an allowance.
                    prepared->set_assets(package.archives, [this](dex::ObjectId object) {
                        return canonical_asset_manager_valid && canonical_asset_manager_valid(object);
                    });
                }
                prepared->set_display_configuration(native_configuration);
                if (native_windows)
                    prepared->set_native_windows(native_windows, [this](dex::ObjectId object) {
                        return surface_valid ? surface_valid(object) : std::shared_ptr<android::NativeWindowProducer>{};
                    });
                prepared->set_native_input_completion_factory([this](const android::NativeActivityInputCompletion &completion) {
                    if(!input_completion_factory)
                        throw ProtocolError("AETHER_NATIVE_INPUT: completion receiver has retired");
                    return input_completion_factory(completion);
                });
                prepared->set_native_activity_host_work_factory([this](const android::NativeActivityHostWork &work) {
                    if(!host_work_factory)throw ProtocolError("AETHER_NATIVE_ACTIVITY_WORK: receiver retired");
                    return host_work_factory(work);
                });
                prepared->bind_main_looper();
                prepared->set_module_provider([this](std::string_view requested){
                    try{return module_inputs(requested);}
                    catch(const apk::InspectError &failure){throw bionic::DynamicLinkSourceError{failure.diagnostic.code};}
                });
                bridge=std::move(prepared);
                native_setup_failed=false;
            }
        }
    }
    void load_library(dex::ManagedRuntime &runtime, std::u16string_view name) override {
        prepare_library(runtime,name);
        const auto compiled_before=bridge->cpu_metrics().compiled_blocks;
        bridge->load_library(runtime,name);
        reclaim_native_warmup_translations(compiled_before);
    }
    android::NativeActivityResult native_activity(const android::NativeActivityRequest &request) {
        if(request.stage==android::NativeActivityStage::create){
            if(!native_entry_selection)native_entry_selection=apk::decode_native_entry(package.native_entry);
            const auto &library=native_entry_selection->library;
            prepare_library(managed,std::u16string(library.begin(),library.end()));
        }
        if(!bridge || !native_entry_selection)
            throw dex::DexError("AETHER_JNI_NATIVE_ACTIVITY_STATE", "Native lifecycle precedes its actual entry");
        const auto compiled_before=bridge->cpu_metrics().compiled_blocks;
        auto result=bridge->native_activity(request,"lib"+native_entry_selection->library+".so",native_entry_selection->function);
        if(request.stage==android::NativeActivityStage::create)reclaim_native_warmup_translations(compiled_before);
        return result;
    }
    bool native_activity_key(const android::NativeActivityKeyInput &input) {
        return bridge && bridge->native_activity_key(input);
    }
    bool native_activity_pointer(const android::NativeActivityPointerInput &input) {
        return bridge && bridge->native_activity_pointer(input);
    }
    dex::Value invoke(dex::ManagedRuntime &runtime, dex::Index method,
                      std::span<const dex::Value> arguments) override {
        if (!bridge)
            throw dex::DexError("AETHER_JNI_LIBRARY_UNSUPPORTED",
                                "Native method called before System.loadLibrary");
        return bridge->invoke(runtime, method, arguments);
    }
    void finish_main_work(){if(bridge)bridge->finish_main_work();}
    jni::Metrics metrics() const { return bridge ? bridge->metrics() : jni::Metrics{}; }
    bool has_cpu() const noexcept{return bool(bridge);}
    a64::Metrics cpu_metrics() const { return bridge ? bridge->cpu_metrics() : a64::Metrics{}; }
    void shutdown() {
        // Finalize guest libraries before retiring the service channels they
        // can call. Attempt every cleanup while preserving the first failure.
        std::exception_ptr first;
        const auto cleanup = [&](const auto &action) {
            try { action(); } catch (...) { if (!first) first = std::current_exception(); }
        };
        cleanup([&] { if (bridge) bridge->shutdown(); });
        cleanup([&] { if (graphics_services) graphics_services->shutdown(); });
        cleanup([&] { if (audio_services) audio_services->shutdown(); });
        cleanup([&] { managed.set_native_interface(nullptr); });
        if (first) std::rethrow_exception(first);
    }
};

class Runtime {
    ActivityPackage fixture;
    std::unique_ptr<StartupWorkController> work_admission;
    dex::ManagedRuntime managed;
    a64::GuestMemory memory;
    a64::AppContext app;
    const bool installed_app;
    NativeLibraries bridge;
    BrokerNotificationService notifications;
    BrokerClient &observation_client;
    std::uint64_t observation_context = 0;
    bool terminal_activations_attempted = false;
    std::array<ActivityKeyResult, 256> key_results{};
    android::ActivitySession activity;
    WorkerProgressWriter *startup_progress;
    dex::ManagedRuntime::TaskId startup_task=0;
    bool startup_started=false;
    std::optional<android::ViewportAdmission> bound_viewport;

    void bind_initial_viewport() {
        if (!installed_app) return;
        if (!fixture.launch_viewport)
            fail("AETHER_VIEWPORT: installed startup has no host geometry admission");
        const auto &initial = *fixture.launch_viewport;
        if (!initial.geometry_revision || !initial.width_px || !initial.height_px ||
            !initial.host_dpi || !initial.configuration.valid())
            fail("AETHER_VIEWPORT: initial host geometry admission is incomplete");
        if (activity.display_configuration() != initial.configuration)
            fail("AETHER_VIEWPORT: Activity configuration differs from admitted startup geometry");
        if (!activity.content_view() || activity.finishing()) return;
        const android::ViewportIdentity identity{
            activity.activity(), activity.content_view(), activity.window_generation(), activity.attachment_revision()};
        if (!identity.activity || !identity.window_generation || !identity.attachment_revision)
            fail("AETHER_VIEWPORT: actual content root has no committed Activity/Window incarnation");
        android::ViewportRequest request;
        request.phase = android::ViewportPhase::bind_content;
        request.requested_orientation = activity.requested_orientation();
        request.geometry_revision = initial.geometry_revision;
        request.identity = identity;
        const auto admitted = observation_client.request_viewport(request, observation_context);
        const android::ViewportIdentity current{
            activity.activity(), activity.content_view(), activity.window_generation(), activity.attachment_revision()};
        if (admitted.identity != identity || current != identity ||
            admitted.geometry_revision != initial.geometry_revision || admitted.width_px != initial.width_px ||
            admitted.height_px != initial.height_px || admitted.host_dpi != initial.host_dpi ||
            admitted.has_navigation_bar != initial.has_navigation_bar ||
            admitted.configuration != initial.configuration || activity.display_configuration() != initial.configuration ||
            activity.requested_orientation() != request.requested_orientation)
            fail("AETHER_VIEWPORT: initial content binding changed its admitted identity or geometry");
        bound_viewport = admitted;
    }
    std::uint64_t current_viewport_geometry_revision() const {
        if (!bound_viewport || !activity.activity() || !activity.content_view() || activity.finishing() ||
            activity.state() == android::Lifecycle::empty || activity.state() == android::Lifecycle::destroyed ||
            activity.state() == android::Lifecycle::failed ||
            activity.display_configuration() != bound_viewport->configuration ||
            activity.requested_orientation() != fixture.requested_orientation)
            return 0;
        const android::ViewportIdentity current{
            activity.activity(), activity.content_view(), activity.window_generation(), activity.attachment_revision()};
        return current == bound_viewport->identity ? bound_viewport->geometry_revision : 0;
    }

  public:
    Runtime(BrokerClient &client, std::uint64_t app_id, bool installed, apk::Bytes mapped,
            WorkerProgressWriter *progress, bool audio_playback, const ActivityLaunch *launch,
            const StartupWorkPolicy *work_policy)
        : fixture(client, installed, mapped, progress, launch),
          work_admission(work_policy?std::make_unique<StartupWorkController>(*work_policy):nullptr),
          managed(std::move(fixture.code)),
          app{app_id, true, installed, installed && audio_playback},
          installed_app(installed),
          bridge(managed, memory, app, client, fixture, installed,progress),
          notifications(client), observation_client(client),
          activity(managed, fixture.package, std::move(fixture.resources), &client, &client, fixture.configuration,
                   &notifications, installed ? &client : nullptr, installed ? &client : nullptr),startup_progress(progress) {
        if(work_policy && !installed)fail("Resource startup policy requires the installed path");
        app.process_state = managed.process_state();
        activity.set_package_metadata(std::move(fixture.package_metadata));
        if (installed) {
            // Share the exact native AppContext identity; these facts convey no
            // Windows identity, broker permission or execution allowance.
            activity.set_process_identity(virtual_android_process_identity(app.instance_id));
            // Only this software backend's accessibility Binder lookup is absent.
            // The real manager initializer and its other state remain required.
            activity.set_accessibility_backend_availability(
                android::AccessibilityBackendAvailability::service_absent);
        }
        // Explicit Aether interactive-session component matching, not inferred
        // Android encryption/unlock state or a filesystem capability. Fixture
        // and hand-constructed sessions remain unbound; broker grants are unchanged.
        if (installed)
            activity.set_component_query_policy(
                android::ImplicitComponentQueryPolicy::interactive_session_both_classes);
        activity.set_target_sdk(fixture.target_sdk);
        activity.set_activity_theme(fixture.theme);
        if (fixture.launch_viewport) activity.set_launch_viewport(*fixture.launch_viewport);
        activity.set_resource_file_reader([this](std::string_view container,std::string_view path,
                                                 std::size_t max_bytes)
            ->std::optional<std::vector<std::uint8_t>> {
            struct ResourceReadCharge {
                dex::ManagedRuntime &runtime;
                void operator()(std::uint64_t count) const { runtime.charge_provider_work(count); }
                bool same(std::string_view left,std::string_view right) const {
                    (*this)(1); // Actual name-length comparison.
                    if(left.size()!=right.size())return false;
                    for(std::size_t at=0;at<left.size();++at) {
                        (*this)(1); // Debit before each actual byte-pair comparison.
                        if(left[at]!=right[at])return false;
                    }
                    return true;
                }
            } reader_charge{managed};
            // The borrowed wrapper cannot allocate. Extraction admits its own
            // output object/capacity and fixed miniz scratch; these are the
            // additional reader-owned objects alive during that extraction.
            const std::function<void(std::uint64_t)> charge(std::ref(reader_charge));
            constexpr auto reader_bytes=sizeof(ResourceReadCharge)+sizeof(charge);
            if(max_bytes<reader_bytes)
                throw apk::InspectError("AETHER_RESOURCE_LIMIT","apk-runtime-resource",
                                        "Held resource reader exceeds its admitted working bytes");
            const apk::PackagePart *part=nullptr;
            for(const auto &candidate:fixture.archives.parts) {
                reader_charge(1);
                if(reader_charge.same(candidate.path,container)) { part=&candidate;break; }
            }
            if(!part)
                throw apk::InspectError("AETHER_PACKAGE_COMPOSITION_UNSUPPORTED","package-composition",
                                        "An inspected member's original APK container is absent");
            if(!part->archive)fail("Packaged resource has no held authenticated archive");
            const auto &entries=part->archive->entries();
            for(std::size_t index=0;index<entries.size();++index) {
                reader_charge(1);
                const auto &entry=entries[index];
                if(entry.directory || !reader_charge.same(entry.path,path))continue;
                if(entry.bytes>max_bytes-reader_bytes)
                    throw apk::InspectError("AETHER_RESOURCE_FILE_LIMIT","apk-runtime-resource",
                                            "Packaged resource exceeds its admitted buffer budget");
                return part->archive->read_admitted(index,max_bytes-reader_bytes,charge);
            }
            return std::nullopt;
        });
        activity.set_native_activity_observer([this](const android::NativeActivityRequest &request){
            return bridge.native_activity(request);
        });
        activity.set_native_activity_pointer_observer([this](const android::NativeActivityPointerInput &input){
            return bridge.native_activity_pointer(input);
        });
        bridge.set_native_input_completion_factory([this](const android::NativeActivityInputCompletion &completion) {
            return activity.make_native_pointer_completion(completion);
        });
        activity.set_native_activity_key_observer([this](const android::NativeActivityKeyInput &input) {
            return bridge.native_activity_key(input);
        });
        activity.set_key_completion_observer([this](std::uint64_t origin, android::KeyDispatchOutcome outcome) {
            complete_key(origin,outcome);
        });
        bridge.set_native_activity_host_work_factory([this](const android::NativeActivityHostWork &work) {
            return activity.make_native_activity_work(work);
        });
        if (work_admission) {
            jni::ManagedAssetManagerAccess asset_access;
            asset_access.publish = [this](dex::ObjectId object) { return activity.publish_native_asset_manager(object); };
            asset_access.owns = [this](std::uint64_t token) { return activity.owns_native_asset_manager(token); };
            bridge.set_asset_manager_access(std::move(asset_access));
        } else {
            bridge.set_canonical_asset_manager_validator([this](dex::ObjectId object) {
                return activity.owns_asset_manager(object);
            });
        }
        bridge.set_native_windows(activity.native_windows(), [this](dex::ObjectId object) {
            return activity.surface_producer(object);
        });
        if (installed)
            activity.set_native_surface_observer([this](const android::NativeSurfaceRequest &request) {
                if (request.action == android::NativeSurfaceRequest::Action::admit)
                    bridge.prepare_native_surface_admission();
                return observation_client.request_native_surface(request, observation_context);
            });
        managed.set_progress_sink(progress);
    }
    void startup_body() {
        if (startup_progress) startup_progress->stage(108,"application_initialize");
        std::string_view stage = "Application";
        try {
            // Admit actual immutable source identities under this retained
            // startup work owner before any original managed/native callback.
            if (work_admission) activity.prepare_native_asset_manager_sources();
            activity.initialize_application(fixture.application_descriptor, fixture.factory_descriptor);
            if (startup_progress) startup_progress->stage(109,"activity_launch");
            stage = "Activity";
            if (fixture.delivered_intent)
                activity.launch(fixture.descriptor, *fixture.delivered_intent, fixture.requested_orientation,
                                fixture.config_changes, fixture.target_sdk, fixture.component_name);
            else
                activity.launch(fixture.descriptor, fixture.requested_orientation, fixture.config_changes, fixture.target_sdk,
                                fixture.component_name);
            activity.reconcile_native_surface();
            activity.check_view_activations();
            // Binding records the actual committed content tree and immutable
            // geometry only. It does not run drawing or publish a ready frame.
            bind_initial_viewport();
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
    void start() {
        if(startup_started)fail("Activity startup entry cannot be replayed");
        startup_started=true;
        if(!work_admission){startup_body();return;}
        startup_task=managed.prepare_main_work([this]{startup_body();},{std::nullopt,work_admission.get()});
        try {
            for(;;){
                const auto grant=work_admission->admit(managed.main_work_actual_work(startup_task));
                if(grant.stop!=WorkStopReason::none || !grant.quantum)
                    throw ProtocolError(std::string(work_stop_name(grant.stop)));
                if(startup_progress){
                    const auto cpu_before_resume=bridge.cpu_metrics();
                    startup_progress->native_work(1,managed.main_work_actual_work(startup_task),
                        bridge.has_cpu()?&cpu_before_resume:nullptr,true);
                }
                (void)managed.run_main_work(startup_task,grant.quantum);
                const auto state=managed.main_work_state(startup_task);
                if(startup_progress){
                    const auto cpu_after_resume=bridge.cpu_metrics();
                    const bool retained=state!=dex::Scheduler::State::completed &&
                        state!=dex::Scheduler::State::failed && state!=dex::Scheduler::State::cancelled;
                    startup_progress->native_work(2,managed.main_work_actual_work(startup_task),
                        bridge.has_cpu()?&cpu_after_resume:nullptr,retained);
                }
                if(state==dex::Scheduler::State::completed || state==dex::Scheduler::State::failed ||
                   state==dex::Scheduler::State::cancelled){
                    const auto error=managed.main_work_exception(startup_task);
                    if(!managed.release_main_work(startup_task))fail("Cannot release terminal main startup work");
                    startup_task=0;bridge.finish_main_work();
                    if(error)std::rethrow_exception(error);
                    if(state!=dex::Scheduler::State::completed)fail("Main startup work was cancelled");
                    break;
                }
                if(state==dex::Scheduler::State::parked || state==dex::Scheduler::State::sleeping){
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    managed.wake_main_work(startup_task);
                }
                // No other guest/CPU/JNI execution is driven while this main
                // stack is retained. Host work admission never publishes ready.
            }
        }catch(...){
            const auto error=std::current_exception();
            if(startup_task){
                managed.cancel_main_work(startup_task);
                if(!managed.release_main_work(startup_task))fail("Cannot retire cancelled main startup work");
                startup_task=0;
            }
            bridge.finish_main_work();
            std::rethrow_exception(error);
        }
    }
    ~Runtime() {
        if(startup_task){
            try{managed.cancel_main_work(startup_task);(void)managed.release_main_work(startup_task);}catch(...){std::terminate();}
            startup_task=0;
        }
        try{bridge.finish_main_work();}catch(...){std::terminate();}
        // Field destruction retires Activity before native services. Existing
        // native handles use the package directly; no late Java identity query
        // may call through a destroyed ActivitySession.
        bridge.clear_asset_manager_access();
        bridge.clear_surface_validator();
        bridge.clear_native_input_completion_factory();
        bridge.clear_native_activity_host_work_factory();
        try { activity.set_native_surface_observer({}); } catch (...) { }
        try { activity.set_text_edit_observer({}); } catch (...) { }
        try { activity.set_soft_input_observer({}); } catch (...) { }
        managed.close_tasks();
        managed.close_main_callbacks();
    }
    void reserve_key(std::uint64_t origin) {
        if(!origin || origin==UINT64_MAX)fail("Invalid original key command sequence");
        const auto slot=std::find_if(key_results.begin(),key_results.end(),[](const auto &entry){return !entry.origin;});
        if(slot==key_results.end())fail("Deferred key result capacity exhausted");
        *slot={origin,KeyDispatchOutcome::none};
    }
    void complete_key(std::uint64_t origin, KeyDispatchOutcome outcome) {
        const auto slot=std::find_if(key_results.begin(),key_results.end(),[&](const auto &entry){return entry.origin==origin;});
        if(slot==key_results.end() || slot->outcome!=KeyDispatchOutcome::none ||
            (outcome!=KeyDispatchOutcome::handled && outcome!=KeyDispatchOutcome::unhandled && outcome!=KeyDispatchOutcome::cancelled))
            fail("Deferred key completion has no exact unresolved original command");
        slot->outcome=outcome; // Pure fixed storage publication, never transport or guest work.
    }
    bool flush_key_results() {
        bool progress=false;
        for(;;){
            auto first=key_results.end();
            for(auto it=key_results.begin();it!=key_results.end();++it)
                if(it->origin && (first==key_results.end() || it->origin<first->origin))first=it;
            if(first==key_results.end() || first->outcome==KeyDispatchOutcome::none)return progress;
            observation_client.send_key_result(*first);
            *first={}; // Exact custody acknowledgement precedes release; failures are not replayed.
            progress=true;
        }
    }
    void flush_finish_request() {
        if(const auto request=activity.pending_finish_request()) {
            observation_client.send_finish_request(*request);
            activity.acknowledge_finish_request(request->ordinal);
        }
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
            if(activity.finishing())return false;
            const auto result = managed.run_task();
            activity.reconcile_native_surface();
            check_text_edit_observer();
            return result;
        } catch (...) { check_text_edit_observer(); throw; }
    }
    bool pump_main() {
        try {
            if(activity.finishing())return false;
            const auto result = managed.run_main_callback();
            activity.reconcile_native_surface();
            check_text_edit_observer();
            return result;
        } catch (...) { check_text_edit_observer(); throw; }
    }
    auto next_deadline() const { return managed.next_task_deadline(); }
    ActivityState snapshot(bool handled = false, KeyDispatchOutcome key_outcome = KeyDispatchOutcome::none) {
        check_text_edit_observer();
        ActivityState result;
        result.apk_hash = fixture.hash;
        result.package = fixture.package;
        result.activity = fixture.launcher;
        result.lifecycle = activity.state();
        result.requested_orientation = activity.requested_orientation();
        result.configuration = activity.display_configuration();
        result.content = activity.content_view();
        result.activity_object = activity.activity();
        result.finishing = result.activity_object && activity.finishing();
        result.window_generation = activity.window_generation();
        result.input_generation = activity.input_generation();
        result.attachment_revision = activity.attachment_revision();
        result.viewport_geometry_revision = current_viewport_geometry_revision();
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
        result.key_outcome = key_outcome;
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
    ActivityState execute(const ActivityCommand &command, std::uint64_t origin) {
        bool handled = false;
        auto key_outcome = KeyDispatchOutcome::none;
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
                bridge.set_display_configuration(command.configuration);
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
            if (installed_app && !command.pointer.root)
                fail("Installed pointer input requires an actual captured content root");
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
            if (installed_app && (!command.key.root || !command.key.window_generation || !command.key.input_generation ||
                !command.key.capture_generation || !command.key.event_time_known || !command.key.source_known))
                fail("Installed key input requires actual captured content, generations, source and event time");
            reserve_key(origin);
            key_outcome=activity.dispatch_key(command.key,origin);
            if(key_outcome!=KeyDispatchOutcome::deferred) {
                const auto slot=std::find_if(key_results.begin(),key_results.end(),[&](const auto &entry){return entry.origin==origin;});
                if(slot==key_results.end() || slot->outcome!=KeyDispatchOutcome::none ||
                    (key_outcome!=KeyDispatchOutcome::handled && key_outcome!=KeyDispatchOutcome::unhandled &&
                     key_outcome!=KeyDispatchOutcome::cancelled))fail("Immediate key result conflicts with deferred custody");
                *slot={};
            }
            handled=key_outcome==KeyDispatchOutcome::handled;
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
        if (command.kind != ActivityCommandKind::close) activity.reconcile_native_surface();
        return snapshot(handled, key_outcome);
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
                         WorkerProgressWriter *progress, bool audio_playback, const ActivityLaunch *launch,
                         const StartupWorkPolicy *work_policy) {
    try {
        BrokerClient client(reader, writer, session, true, true);
        Runtime runtime(client, app_id, installed, mapped_package, progress, audio_playback, launch,work_policy);
        try {
            runtime.start();
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
                    runtime.flush_key_results();
                    runtime.flush_finish_request();
                    if ((bytes = client.poll_activity_command(sequence))) break;
                    const bool advanced = runtime.pump_one();
                    runtime.flush_key_results();
                    runtime.flush_finish_request();
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
                const auto state = runtime.execute(command, sequence);
                if(command.kind==ActivityCommandKind::close)runtime.flush_key_results();
                send_state(writer, state, sequence, session);
                runtime.acknowledge_snapshot_activations(state);
                runtime.check_text_edit_observer();
                if (command.kind == ActivityCommandKind::close) {
                    runtime.deactivate_text_edit_observer();
                    return 0;
                }
                // Real bounded progress between acknowledged commands prevents
                // queued input from starving its native consumer/final callback.
                runtime.set_observation_context(0);
                (void)runtime.pump_main();
                runtime.flush_key_results();
                runtime.flush_finish_request();
                (void)runtime.pump_one();
                runtime.flush_key_results();
                runtime.flush_finish_request();
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
