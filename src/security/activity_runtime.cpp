#include "aether/apk/archive.hpp"
#include "aether/apk/compatibility.hpp"
#include "aether/apk/inspect.hpp"
#include "aether/apk/launcher.hpp"
#include "aether/apk/native_inventory.hpp"
#include "aether/apk/package.hpp"
#include "aether/dex/archive_source.hpp"
#include "aether/dex/fixture_hash.hpp"
#include "aether/elf/archive_source.hpp"
#include "aether/security/activity_session.hpp"
#include "aether/security/client.hpp"
#include <algorithm>

namespace aether::security {
namespace {
[[noreturn]] void fail(std::string message) { throw ProtocolError("AETHER_ACTIVITY_RUNTIME: " + message); }
struct ActivityPackage {
    std::vector<std::uint8_t> bytes;
    apk::ResourceTable resources;
    std::shared_ptr<dex::ClassSource> code;
    apk::PackageView archives;
    apk::NativeInventory libraries;
    std::vector<apk::PackageView::Member> native_entries;
    std::string hash, package, launcher, descriptor;
    explicit ActivityPackage(BrokerClient &client, bool installed, apk::Bytes mapped) {
        apk::InspectLimits limits;
        if (installed)
            client.verify_package(mapped);
        else
            bytes = client.read_package();
        const auto input = installed ? mapped : apk::Bytes(bytes);
        hash = apk::sha256(input);
        if (!installed && hash != dex::fixture::apk_sha256)
            throw dex::DexError("AETHER_ANDROID_FIXTURE_NOT_TRUSTED",
                                "Developer Activity probes accept only the exact first-party APK");
        const auto report = apk::inspect_package(input, limits);
        const auto compatibility = apk::execution_compatibility(report);
        if (!compatibility.installable)
            throw dex::DexError("AETHER_ANDROID_PACKAGE_UNSUPPORTED", compatibility.reason);
        archives = apk::open_package(input, limits);
        const auto &manifest = report.manifest;
        package = manifest.package_id;
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
        code = std::make_shared<dex::ArchiveSource>(dex_inputs);
        // Fixed neutral resource context, not an Android API-support claim or a
        // projection of Windows locale/DPI. Device-qualified resources remain
        // unavailable until the corresponding runtime configuration exists.
        constexpr apk::ResourceConfiguration resource_target{160, 35,
                                                             apk::ResourceSelectionPolicy::neutral_runtime};
        resources =
            apk::ResourceTable::compose(archives, package, &resource_target,
                                        {.names = apk::ResourceNamePolicy::compiled, .retain_bags = true});
        libraries = apk::NativeInventory(report.native);
        native_entries.resize(libraries.members().size());
        constexpr std::string_view native_prefix = "lib/arm64-v8a/";
        // Scan the directory once, rather than searching every archive entry for
        // each library in a potentially large native catalogue.
        for (const auto &part : archives.parts) {
            const auto &archive = part.archive;
            for (std::size_t index = 0; index < archive->entries().size(); ++index) {
                const auto &entry = archive->entries()[index];
                if (!entry.path.starts_with(native_prefix))
                    continue;
                if (const auto member =
                        libraries.find(std::string_view(entry.path).substr(native_prefix.size()))) {
                    const auto &file = libraries.members()[*member].file;
                    if (native_entries[*member].archive || entry.bytes != file.bytes ||
                        entry.compressed_bytes != file.compressed_bytes || entry.path != file.path ||
                        part.path != file.container)
                        fail("Native archive entry differs from its inspected identity");
                    native_entries[*member] = {archive, index};
                }
            }
        }
        if (std::any_of(native_entries.begin(), native_entries.end(),
                        [](const auto &entry) { return !entry.archive; }))
            fail("An inspected native member is absent from the immutable archive");
    }
};

// Resolve System.loadLibrary from this immutable APK. The existing bridge owns
// one dependency graph; a second independent native root fails explicitly.
class NativeLibraries final : public dex::NativeInterface {
    dex::ManagedRuntime &managed;
    a64::GuestMemory &memory;
    const a64::AppContext &app;
    BrokerClient &client;
    const ActivityPackage &package;
    std::unique_ptr<jni::Bridge> bridge;

  public:
    NativeLibraries(dex::ManagedRuntime &managed, a64::GuestMemory &memory, const a64::AppContext &app,
                    BrokerClient &client, const ActivityPackage &package)
        : managed(managed), memory(memory), app(app), client(client), package(package) {
        managed.set_native_interface(this);
    }
    ~NativeLibraries() { managed.set_native_interface(nullptr); }
    void load_library(dex::ManagedRuntime &runtime, std::u16string_view name) override {
        if (!bridge) {
            std::string root = "lib";
            if (name.empty() || name.size() > 128)
                throw dex::DexError("AETHER_JNI_LIBRARY_UNSUPPORTED", "Invalid native library name");
            for (auto c : name) {
                if (!((c >= u'a' && c <= u'z') || (c >= u'A' && c <= u'Z') || (c >= u'0' && c <= u'9') ||
                      c == u'_' || c == u'-' || c == u'.'))
                    throw dex::DexError("AETHER_JNI_LIBRARY_UNSUPPORTED", "Unsupported native library name");
                root += static_cast<char>(c);
            }
            root += ".so";
            const auto selected = package.libraries.select(root);
            std::vector<elf::ModuleInput> modules;
            modules.reserve(selected.size());
            auto budget = std::make_shared<elf::ArchiveScanBudget>();
            for (const auto index : selected) {
                const auto &member = package.libraries.members()[index];
                modules.push_back({member.name,
                                   {},
                                   std::make_shared<elf::ArchiveSource>(
                                       *package.native_entries[index].archive,
                                       package.native_entries[index].index, member.file.sha256, budget)});
            }
            bridge =
                std::make_unique<jni::Bridge>(managed, memory, app, client, modules, root, &client, false);
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
    Runtime(BrokerClient &client, std::uint64_t app_id, bool installed, apk::Bytes mapped)
        : fixture(client, installed, mapped), managed(std::move(fixture.code)), app{app_id, true},
          bridge(managed, memory, app, client, fixture),
          activity(managed, fixture.package, std::move(fixture.resources)) {
        activity.launch(fixture.descriptor);
    }
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
void run_activity_worker(HANDLE reader, HANDLE writer, std::uint64_t session, std::uint64_t app_id,
                         bool read_recovery_probe, bool installed, apk::Bytes mapped_package) {
    try {
        BrokerClient client(reader, writer, session, true);
        Runtime runtime(client, app_id, installed, mapped_package);
        send_state(writer, runtime.snapshot(), 0, session);
        for (std::uint64_t sequence = 1; sequence != UINT64_MAX; ++sequence) {
            ActivityReassembly request(Operation::activity_command, sequence, session,
                                       activity_command_limit);
            while (!request.complete())
                request.accept(read_pipe_frame(reader));
            const auto command = ActivityCommand::decode(request.take());
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
                return;
        }
        fail("Activity command sequence exhausted");
    } catch (const dex::DexError &error) {
        throw ProtocolError(error.code + ": " + error.what());
    }
}
} // namespace aether::security
