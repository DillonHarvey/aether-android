#include "aether/android/selftest.hpp"
#include "aether/apk/archive.hpp"
#include "aether/apk/launcher.hpp"
#include "aether/common/text.hpp"
#include "aether/dex/fixture_hash.hpp"
#include "aether/elf/fixture_hashes.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <sstream>

namespace aether::android {
namespace {
std::string narrow(std::u16string_view text) { return utf8(std::wstring(text.begin(), text.end())); }
struct RetainedString {
    dex::ManagedRuntime &runtime;
    dex::ObjectId object;
    RetainedString(dex::ManagedRuntime &owner, std::u16string_view text)
        : runtime(owner), object(owner.new_string(text)) {
        runtime.retain(object);
    }
    ~RetainedString() { runtime.release(object); }
};
} // namespace
FrameworkSelftestReport framework_selftest(const std::filesystem::path &path) {
    apk::InspectLimits limits;
    limits.archive_bytes = 64 * 1024 * 1024;
    const auto bytes = apk::read_package(path, limits);
    host::HostTimeService time;
    const a64::AppContext app{5, true};
    return framework_selftest(bytes, time, app);
}
FrameworkSelftestReport framework_selftest(apk::Bytes bytes, const host::TimeService &time,
                                           const a64::AppContext &app, host::FileService *files,
                                           bool storage_allowed, std::u16string_view storage_contents) {
    FrameworkSelftestReport report;
    apk::InspectLimits limits;
    limits.archive_bytes = 64 * 1024 * 1024;
    if (bytes.size() > limits.archive_bytes)
        throw dex::DexError("AETHER_ANDROID_FIXTURE_LIMIT", "APK exceeds the bounded execution input limit");
    report.apk_sha256 = apk::sha256(bytes);
    if (report.apk_sha256 != dex::fixture::apk_sha256)
        throw dex::DexError("AETHER_ANDROID_FIXTURE_NOT_TRUSTED",
                            "Only the exact built-in first-party APK may execute before Phase 7");
    apk::Archive archive(bytes, limits);
    const auto entry = [&](std::string_view name) {
        for (std::size_t i = 0; i < archive.entries().size(); ++i)
            if (archive.entries()[i].path == name)
                return archive.read(i);
        throw dex::DexError("AETHER_ANDROID_FIXTURE_ENTRY", "Required first-party APK entry is absent");
    };
    const auto manifest = apk::parse_manifest(entry("AndroidManifest.xml"));
    report.package = manifest.package_id;
    const auto selection = apk::select_launcher(manifest);
    if (!selection.activity)
        throw dex::DexError("AETHER_ANDROID_LAUNCHER", selection.reason);
    const auto &activity = manifest.activities[*selection.activity];
    report.launch_activity = activity.target.empty() ? activity.name : activity.target;
    auto descriptor = report.launch_activity;
    std::replace(descriptor.begin(), descriptor.end(), '.', '/');
    descriptor = 'L' + descriptor + ';';
    const auto code = entry("classes.dex"), resource_bytes = entry("resources.arsc");
    const auto root = entry("lib/arm64-v8a/libaether_fixture.so"),
               support = entry("lib/arm64-v8a/libaether_support.so");
    if (apk::sha256(root) != elf::fixture::aether_fixture_sha256 ||
        apk::sha256(support) != elf::fixture::aether_support_sha256)
        throw dex::DexError("AETHER_ANDROID_FIXTURE_NOT_TRUSTED",
                            "APK native entries differ from the reviewed registry");
    report.dex_sha256 = apk::sha256(code);
    report.resources_sha256 = apk::sha256(resource_bytes);
    dex::ManagedRuntime runtime(dex::parse(code));
    a64::GuestMemory memory;
    const std::array inputs{elf::ModuleInput{"libaether_fixture.so", root},
                            elf::ModuleInput{"libaether_support.so", support}};
    jni::Bridge bridge(runtime, memory, app, time, inputs, "libaether_fixture.so", files);
    ActivitySession session(runtime, report.package, apk::ResourceTable::parse(resource_bytes));
    const auto check = [&](std::string name, bool passed) {
        report.checks.push_back({std::move(name), passed, {}});
    };
    const auto trace = [&]() -> std::u16string {
        for (dex::Index i = 0; i < runtime.image().fields.size(); ++i) {
            const auto &field = runtime.image().fields[i];
            if (runtime.image().types[field.owner] == descriptor && field.name == "trace")
                return std::u16string(runtime.string(runtime.get_static(i).bits));
        }
        throw dex::DexError("AETHER_ANDROID_FIXTURE_FIELD", "Managed lifecycle trace field is absent");
    };
    check("manifest-resource-package-identity", session.resources().package_name() == report.package);
    session.launch(descriptor);
    check("actual-dex-create-start-resume",
          session.state() == Lifecycle::resumed && trace() == u"create;start;resume;");
    check("onload-reentrant-class-initialization", bridge.metrics().on_load_calls == 1);
    dex::ObjectId title = 0, status = 0, button = 0;
    for (const auto &[id, view] : session.views()) {
        report.initial_views.push_back(view);
        if (view.id == 101)
            title = id;
        if (view.id == 102)
            status = id;
        if (view.id == 103)
            button = id;
    }
    if (!title || !status || !button || !session.content_view())
        throw dex::DexError("AETHER_ANDROID_FIXTURE_VIEW",
                            "DEX did not construct the expected fixture views");
    const auto &layout = session.views().at(session.content_view());
    check("dex-created-retained-layout",
          layout.kind == ViewKind::linear_layout && layout.orientation == 1 &&
              layout.children == std::vector<dex::ObjectId>{title, status, button});
    check("actual-package-string-resources",
          session.views().at(title).text == u"HelloAether" &&
              session.views().at(status).text == u"Ready to translate ARM64" &&
              session.views().at(button).text == u"Translate ARM64");
    const std::array instance{dex::Value::reference(session.activity())};
    report.api_flags = static_cast<std::uint32_t>(
        runtime.invoke(runtime.lookup(descriptor, "frameworkChecks", "()I", false), instance).bits);
    check("dex-permissions-features-service-denial-resource-lookup", report.api_flags == 511);
    const auto package_name = runtime.invoke(
        runtime.lookup(descriptor, "packageNameForTest", "()Ljava/lang/String;", false), instance);
    check("application-context-package-name", narrow(runtime.string(package_name.bits)) == report.package);
    runtime.collect();
    check("native-roots-retain-managed-click-listener", session.click(button));
    report.result_text = session.views().at(status).text;
    check("actual-dex-button-jni-a64-callback-result", report.result_text == u"ARM64 result: 42" &&
                                                           bridge.metrics().native_calls == 1 &&
                                                           bridge.metrics().managed_callbacks == 1);
    if (files) {
        report.storage_attempted = true;
        const auto store = [&](std::u16string_view name) {
            const RetainedString path(runtime, name), contents(runtime, storage_contents);
            const std::array args{dex::Value::reference(path.object), dex::Value::reference(contents.object)};
            const auto result = runtime.invoke_static("Lcom/aether/hello/RuntimeFixture;", "storageRoundTrip",
                                                      "(Ljava/lang/String;Ljava/lang/String;)I", args);
            return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(result.bits));
        };
        report.storage_result = store(u"proof.txt");
        check("actual-dex-jni-a64-private-file-roundtrip-or-denial",
              report.storage_result ==
                  (storage_allowed ? static_cast<std::int32_t>(storage_contents.size()) : -13));
        for (const auto name : {u"../escape.txt", u"/absolute.txt", u"file:stream", u"app_74/proof.txt"})
            if (store(name) == -13)
                ++report.storage_denials;
        check("actual-native-storage-paths-cannot-select-another-root", report.storage_denials == 4);
        check("native-storage-releases-jni-string-buffers", bridge.metrics().string_buffers == 0 &&
                                                                bridge.metrics().local_references == 0 &&
                                                                bridge.metrics().global_references == 0);
    }
    session.signal(WindowSignal::focus_gained);
    session.signal(WindowSignal::focus_gained);
    session.signal(WindowSignal::focus_lost);
    check("focus-distinct-from-resume-and-duplicate-coalescing",
          session.state() == Lifecycle::resumed && trace() == u"create;start;resume;focus+;focus-;");
    session.signal(WindowSignal::deactivate);
    check("deactivation-pauses-and-denies-host-click",
          session.state() == Lifecycle::paused && !session.click(button));
    session.signal(WindowSignal::minimize);
    check("minimize-stops", session.state() == Lifecycle::stopped);
    session.signal(WindowSignal::restore);
    check("inactive-restore-restarts-without-resuming", session.state() == Lifecycle::started);
    session.signal(WindowSignal::activate);
    check("reactivation-resumes", session.state() == Lifecycle::resumed);
    session.close();
    bridge.shutdown();
    report.managed_trace = trace();
    check("actual-dex-orderly-close-callbacks",
          session.state() == Lifecycle::destroyed &&
              report.managed_trace ==
                  u"create;start;resume;focus+;focus-;pause;stop;restart;start;resume;pause;stop;destroy;");
    runtime.collect();
    check("framework-and-jni-retained-roots-released",
          session.views().empty() && runtime.metrics().pinned_references == 0 &&
              bridge.metrics().local_references == 0 && bridge.metrics().global_references == 0 &&
              bridge.metrics().string_buffers == 0);
    check("real-windows-jit-path",
          bridge.cpu_metrics().compiled_blocks > 0 && bridge.cpu_metrics().emitted_bytes > 0 &&
              bridge.cpu_metrics().rx_failures == 0 && bridge.cpu_metrics().interpreter_fallbacks == 0);
    report.events = session.events();
    report.framework = session.metrics();
    report.managed = runtime.metrics();
    report.jni = bridge.metrics();
    report.cpu = bridge.cpu_metrics();
    return report;
}
bool FrameworkSelftestReport::passed() const {
    return !checks.empty() &&
           std::all_of(checks.begin(), checks.end(), [](const auto &check) { return check.passed; });
}
std::string FrameworkSelftestReport::json() const {
    std::ostringstream out;
    out << "{\"schemaVersion\":1,\"mode\":\"self-authored-fixtures-only\",\"androidOsStarted\":false,"
           "\"windowCreated\":false,\"passed\":"
        << (passed() ? "true" : "false") << ",\"apkSha256\":" << json_quote(apk_sha256)
        << ",\"dexSha256\":" << json_quote(dex_sha256)
        << ",\"resourcesSha256\":" << json_quote(resources_sha256) << ",\"package\":" << json_quote(package)
        << ",\"launchActivity\":" << json_quote(launch_activity)
        << ",\"resultText\":" << json_quote(narrow(result_text))
        << ",\"managedTrace\":" << json_quote(narrow(managed_trace)) << ",\"apiFlags\":" << api_flags
        << ",\"storageAttempted\":" << (storage_attempted ? "true" : "false")
        << ",\"storageResult\":" << storage_result << ",\"storageDenials\":" << storage_denials
        << ",\"framework\":{\"apiCalls\":" << framework.api_calls
        << ",\"lifecycleCallbacks\":" << framework.lifecycle_callbacks
        << ",\"managedClicks\":" << framework.managed_clicks
        << ",\"deniedPermissions\":" << framework.denied_permissions
        << ",\"unsupportedServices\":" << framework.unsupported_services
        << ",\"viewRevision\":" << framework.view_revision
        << "},\"managed\":{\"instructions\":" << managed.instructions
        << ",\"calls\":" << managed.managed_calls << ",\"nativeCalls\":" << managed.native_calls
        << ",\"collections\":" << managed.collections << ",\"reclaimed\":" << managed.reclaimed
        << ",\"liveObjects\":" << managed.live_objects
        << ",\"pinnedReferences\":" << managed.pinned_references << "},\"jni\":{\"calls\":" << jni.calls
        << ",\"nativeCalls\":" << jni.native_calls << ",\"managedCallbacks\":" << jni.managed_callbacks
        << ",\"onLoadCalls\":" << jni.on_load_calls << ",\"localReferences\":" << jni.local_references
        << ",\"globalReferences\":" << jni.global_references << ",\"stringBuffers\":" << jni.string_buffers
        << "},\"cpu\":{\"compiledBlocks\":" << cpu.compiled_blocks
        << ",\"emittedBytes\":" << cpu.emitted_bytes << ",\"rxFailures\":" << cpu.rx_failures
        << ",\"interpreterFallbacks\":" << cpu.interpreter_fallbacks << "},\"initialViews\":[";
    bool first = true;
    for (const auto &view : initial_views) {
        if (!first)
            out << ',';
        first = false;
        const auto kind = view.kind == ViewKind::linear_layout ? "LinearLayout"
                          : view.kind == ViewKind::button      ? "Button"
                                                               : "TextView";
        out << "{\"id\":" << view.id << ",\"kind\":" << json_quote(kind)
            << ",\"text\":" << json_quote(narrow(view.text)) << '}';
    }
    out << "],\"events\":[";
    first = true;
    for (const auto &event : events) {
        if (!first)
            out << ',';
        first = false;
        out << json_quote(event);
    }
    out << "],\"checks\":[";
    first = true;
    for (const auto &check : checks) {
        if (!first)
            out << ',';
        first = false;
        out << "{\"name\":" << json_quote(check.name) << ",\"passed\":" << (check.passed ? "true" : "false")
            << '}';
    }
    out << "]}";
    return out.str();
}
std::string FrameworkSelftestReport::text(bool verbose) const {
    std::ostringstream out;
    out << "Framework self-test: " << (passed() ? "PASS" : "FAIL") << " (" << checks.size() << " checks)\n"
        << launch_activity << " -> retained views -> DEX button -> JNI -> translated ARM64 -> "
        << narrow(result_text) << '\n'
        << "Managed lifecycle: " << narrow(managed_trace) << '\n'
        << "No window in this phase; no Android OS; arbitrary APK execution remains disabled.\n";
    if (verbose || !passed())
        for (const auto &check : checks)
            out << (check.passed ? "  PASS " : "  FAIL ") << check.name << '\n';
    return out.str();
}
std::string api_support_report(std::string_view query, bool json) {
    std::ostringstream out;
    if (json)
        out << "{\"schemaVersion\":1,\"query\":" << json_quote(query) << ",\"apis\":[";
    bool first = true;
    for (const auto &api : api_registry()) {
        const auto status = status_name(api.status);
        if (api.owner.find(query) == std::string_view::npos &&
            api.name.find(query) == std::string_view::npos &&
            api.signature.find(query) == std::string_view::npos &&
            api.behavior.find(query) == std::string_view::npos &&
            status.find(query) == std::string_view::npos)
            continue;
        if (json) {
            if (!first)
                out << ',';
            out << "{\"class\":" << json_quote(api.owner) << ",\"method\":" << json_quote(api.name)
                << ",\"signature\":" << json_quote(api.signature) << ",\"status\":" << json_quote(status)
                << ",\"behavior\":" << json_quote(api.behavior) << '}';
        } else
            out << status << "  " << api.owner << '.' << api.name << api.signature << "  " << api.behavior
                << '\n';
        first = false;
    }
    if (json)
        out << "]}";
    return out.str();
}
} // namespace aether::android
