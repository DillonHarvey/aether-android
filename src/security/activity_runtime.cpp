#include "aether/apk/archive.hpp"
#include "aether/apk/compatibility.hpp"
#include "aether/apk/inspect.hpp"
#include "aether/apk/launcher.hpp"
#include "aether/apk/native_inventory.hpp"
#include "aether/apk/package.hpp"
#include "aether/dex/archive_source.hpp"
#include "aether/dex/fixture_hash.hpp"
#include "aether/common/text.hpp"
#include "aether/common/process_exit.hpp"
#include "aether/elf/archive_source.hpp"
#include "aether/security/activity_session.hpp"
#include "aether/security/client.hpp"
#include "aether/security/worker_progress.hpp"
#include <algorithm>

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
    std::string hash, package, launcher, descriptor, application_descriptor, factory_descriptor;
    explicit ActivityPackage(BrokerClient &client, bool installed, apk::Bytes mapped, WorkerProgressWriter *progress) {
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
        const auto selection = apk::select_launcher(manifest);
        if (!selection.activity)
            fail(selection.reason);
        const auto &activity = manifest.activities[*selection.activity];
        launcher = activity.target.empty() ? activity.name : activity.target;
        descriptor = launcher;
        std::replace(descriptor.begin(), descriptor.end(), '.', '/');
        descriptor = 'L' + descriptor + ';';
        std::vector<dex::ArchiveDexInput> dex_inputs;
        for (const auto &dex : report.dex)
            dex_inputs.push_back({archives.part(dex.file.container).archive, dex});
        stage(105,"dex_directory_index");
        code = std::make_shared<dex::ArchiveSource>(dex_inputs, dex::ArchiveIndexPolicy::directory);
        // Fixed neutral resource context, not an Android API-support claim or a
        // projection of Windows locale/DPI. Device-qualified resources remain
        // unavailable until the corresponding runtime configuration exists.
        constexpr apk::ResourceConfiguration resource_target{160, android::compatibility_sdk,
                                                             apk::ResourceSelectionPolicy::neutral_runtime};
        stage(106,"resource_compose");
        resources =
            apk::ResourceTable::compose(archives, package, &resource_target,
                                        {.names = apk::ResourceNamePolicy::optimized, .retain_bags = true});
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
                    BrokerClient &client, const ActivityPackage &package)
        : managed(managed), memory(memory), app(app), client(client), package(package) {
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
                bridge=std::make_unique<jni::Bridge>(managed,memory,app,client,modules,root,&client,false,package.package);
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
        managed.set_native_interface(nullptr);
    }
};

class Runtime {
    ActivityPackage fixture;
    dex::ManagedRuntime managed;
    a64::GuestMemory memory;
    a64::AppContext app;
    NativeLibraries bridge;
    android::ActivitySession activity;

  public:
    Runtime(BrokerClient &client, std::uint64_t app_id, bool installed, apk::Bytes mapped, WorkerProgressWriter *progress)
        : fixture(client, installed, mapped, progress), managed(std::move(fixture.code)), app{app_id, true},
          bridge(managed, memory, app, client, fixture),
          activity(managed, fixture.package, std::move(fixture.resources), &client, &client) {
        app.process_state = managed.process_state();
        managed.set_progress_sink(progress);
        if (progress) progress->stage(108,"application_initialize");
        std::string_view stage = "Application";
        try {
            activity.initialize_application(fixture.application_descriptor, fixture.factory_descriptor);
            if (progress) progress->stage(109,"activity_launch");
            stage = "Activity";
            activity.launch(fixture.descriptor);
        } catch (const dex::JavaException &error) {
            const auto message = managed.exception_message(error.object);
            throw dex::DexError("AETHER_ANDROID_STARTUP_EXCEPTION",
                                std::string(stage) + " startup raised " +
                                    std::string(managed.object_type(error.object)) + ": " +
                                    utf8(std::wstring(message.begin(), message.end())));
        }
    }
    ~Runtime() {
        managed.close_tasks();
        managed.close_main_callbacks();
    }
    bool pump_one() { return managed.run_task(); }
    bool pump_main() { return managed.run_main_callback(); }
    auto next_deadline() const { return managed.next_task_deadline(); }
    ActivityState snapshot(bool handled = false) {
        ActivityState result;
        result.apk_hash = fixture.hash;
        result.package = fixture.package;
        result.activity = fixture.launcher;
        result.lifecycle = activity.state();
        result.content = activity.content_view();
        result.views = activity.views();
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
        case ActivityCommandKind::refresh:
            managed.collect();
            break;
        case ActivityCommandKind::place:
            activity.place_views(command.placements);
            break;
        case ActivityCommandKind::pointer:
            handled = activity.pointer(command.pointer);
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
                         bool read_recovery_probe, bool installed, apk::Bytes mapped_package, WorkerProgressWriter *progress) {
    try {
        BrokerClient client(reader, writer, session, true, true);
        Runtime runtime(client, app_id, installed, mapped_package, progress);
        if (progress) progress->stage(110,"initial_state");
        send_state(writer, runtime.snapshot(), 0, session);
        for (std::uint64_t sequence = 1; sequence != UINT64_MAX; ++sequence) {
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
            if (read_recovery_probe && command.kind == ActivityCommandKind::refresh) {
                // Controlled first-party failure: no read, guest callback or state mutation occurs.
                // The public run path never enables this probe.
                Sleep(1500);
                write_pipe_frame(
                    writer, {{Operation::activity_read_unavailable, sequence, session, 0, Status::ok}, {}});
                read_recovery_probe = false;
                continue;
            }
            send_state(writer, runtime.execute(command), sequence, session);
            if (command.kind == ActivityCommandKind::close)
                return 0;
        }
        fail("Activity command sequence exhausted");
    } catch (const ProcessExit &exit) {
        if(exit.signal)throw ProtocolError("AETHER_GUEST_SIGNAL: guest terminated abnormally by signal " + std::to_string(exit.signal));
        if (progress) progress->stage(111,"guest_exited");
        write_pipe_frame(writer, guest_exit_frame(session, exit.status));
        return exit.status;
    } catch (const dex::DexError &error) {
        throw ProtocolError(error.code + ": " + error.what());
    }
}
} // namespace aether::security
