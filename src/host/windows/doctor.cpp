#include "aether/host/doctor.hpp"
#include "aether/build_info.hpp"
#include "aether/common/text.hpp"
#include <Windows.h>
#include <algorithm>
#include <array>
#include <filesystem>
#include <sstream>
#include <system_error>

namespace aether::host {
namespace {
namespace fs = std::filesystem;

std::wstring environment(const wchar_t *name) {
    const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (size == 0)
        return {};
    std::wstring result(size, L'\0');
    const DWORD copied = GetEnvironmentVariableW(name, result.data(), size);
    if (copied == 0 || copied >= size)
        return {};
    result.resize(copied);
    return result;
}
bool path_exists(const fs::path &path) {
    if (path.empty())
        return false;
    std::error_code error;
    return fs::exists(path, error) && !error;
}
fs::path search_path(const wchar_t *filename) {
    std::array<wchar_t, 32768> buffer{};
    const DWORD count =
        SearchPathW(nullptr, filename, nullptr, static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
    return count != 0 && count < buffer.size() ? fs::path(std::wstring(buffer.data(), count)) : fs::path{};
}
std::vector<fs::path> directories(const fs::path &root) {
    std::vector<fs::path> result;
    std::error_code error;
    fs::directory_iterator iterator(root, fs::directory_options::skip_permission_denied, error);
    while (!error && iterator != fs::directory_iterator{}) {
        if (iterator->is_directory(error))
            result.push_back(iterator->path());
        iterator.increment(error);
    }
    std::sort(result.rbegin(), result.rend());
    return result;
}
std::vector<fs::path> visual_studio_roots() {
    std::vector<fs::path> result;
    const auto configured = environment(L"VSINSTALLDIR");
    if (!configured.empty())
        result.emplace_back(configured);
    for (const auto *variable : {L"ProgramFiles", L"ProgramFiles(x86)"}) {
        const auto base = environment(variable);
        if (base.empty())
            continue;
        for (const auto &year : directories(fs::path(base) / L"Microsoft Visual Studio")) {
            for (const auto &edition : directories(year))
                result.push_back(edition);
        }
    }
    return result;
}
fs::path find_visual_studio_tool(const std::vector<fs::path> &roots, const fs::path &relative) {
    for (const auto &root : roots)
        if (path_exists(root / relative))
            return root / relative;
    return {};
}
std::string registry_build() {
    std::array<wchar_t, 64> buffer{};
    DWORD bytes = static_cast<DWORD>(buffer.size() * sizeof(wchar_t));
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                     L"CurrentBuildNumber", RRF_RT_REG_SZ, nullptr, buffer.data(), &bytes) != ERROR_SUCCESS)
        return "unknown";
    return utf8(buffer.data());
}
void add_tool(DoctorReport &report, std::string name, const fs::path &location, std::string scope) {
    const bool detected = path_exists(location);
    report.prerequisites.push_back({std::move(name), detected ? "detected" : "not-detected",
                                    detected ? utf8(location.wstring()) : "", std::move(scope)});
}
} // namespace

DoctorReport query_doctor() {
    DoctorReport report;
    report.windows_build = registry_build();
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    report.host_architecture =
        info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x86_64" : "unsupported";
    const auto &build_number = report.windows_build;
    const bool numeric = !build_number.empty() && std::all_of(build_number.begin(), build_number.end(),
                                                              [](char c) { return c >= '0' && c <= '9'; });
    report.supported_host =
        report.host_architecture == "x86_64" && numeric &&
        (build_number.size() > 5 || (build_number.size() == 5 && build_number >= "22000"));

    const auto vs_roots = visual_studio_roots();
    auto compiler = search_path(L"cl.exe");
    if (compiler.empty()) {
        for (const auto &root : vs_roots) {
            for (const auto &version : directories(root / L"VC/Tools/MSVC")) {
                const auto candidate = version / L"bin/Hostx64/x64/cl.exe";
                if (path_exists(candidate)) {
                    compiler = candidate;
                    break;
                }
            }
            if (!compiler.empty())
                break;
        }
    }
    auto cmake = search_path(L"cmake.exe");
    if (cmake.empty())
        cmake = find_visual_studio_tool(vs_roots,
                                        L"Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe");
    auto ninja = search_path(L"ninja.exe");
    if (ninja.empty())
        ninja = find_visual_studio_tool(vs_roots,
                                        L"Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe");
    add_tool(report, "MSVC x64 compiler", compiler, "development");
    add_tool(report, "CMake", cmake, "development");
    add_tool(report, "Ninja", ninja, "development");

    fs::path sdk_header;
    const auto sdk_environment = environment(L"WindowsSdkDir");
    const auto program_files = environment(L"ProgramFiles(x86)");
    const std::array<fs::path, 2> sdk_roots = {
        fs::path(sdk_environment),
        program_files.empty() ? fs::path{} : fs::path(program_files) / L"Windows Kits/10"};
    for (const auto &root : sdk_roots) {
        if (root.empty())
            continue;
        for (const auto &version : directories(root / L"Include")) {
            if (path_exists(version / L"um/Windows.h") &&
                path_exists(root / L"Lib" / version.filename() / L"um/x64/kernel32.lib")) {
                sdk_header = version / L"um/Windows.h";
                break;
            }
        }
        if (!sdk_header.empty())
            break;
    }
    add_tool(report, "Windows SDK x64", sdk_header, "development");
    add_tool(report, "Git", search_path(L"git.exe"), "development");
    add_tool(report, "Python (test driver)", search_path(L"python.exe"), "development");

    fs::path android = environment(L"ANDROID_SDK_ROOT");
    if (android.empty())
        android = environment(L"ANDROID_HOME");
    if (android.empty()) {
        const auto local = environment(L"LOCALAPPDATA");
        if (!local.empty())
            android = fs::path(local) / L"Android/Sdk";
    }
    add_tool(report, "Android SDK build-tools", android.empty() ? fs::path{} : android / L"build-tools",
             "fixture-only");
    fs::path ndk = environment(L"ANDROID_NDK_HOME");
    if (ndk.empty() && !android.empty()) {
        const auto versions = directories(android / L"ndk");
        if (!versions.empty())
            ndk = versions.front();
    }
    add_tool(report, "Android NDK", ndk.empty() ? fs::path{} : ndk / L"build/cmake/android.toolchain.cmake",
             "fixture-only");
    auto javac = search_path(L"javac.exe");
    const auto java_home = environment(L"JAVA_HOME");
    if (javac.empty() && !java_home.empty())
        javac = fs::path(java_home) / L"bin/javac.exe";
    if (javac.empty()) {
        const auto pf = environment(L"ProgramFiles");
        if (!pf.empty())
            for (const auto &candidate : directories(fs::path(pf) / L"Microsoft")) {
                if (path_exists(candidate / L"bin/javac.exe")) {
                    javac = candidate / L"bin/javac.exe";
                    break;
                }
            }
    }
    add_tool(report, "Java compiler", javac, "fixture-only");
    return report;
}

bool DoctorReport::development_ready() const {
    return supported_host &&
           std::all_of(prerequisites.begin(), prerequisites.end(), [](const Prerequisite &item) {
               return item.scope != "development" || item.status == "detected";
           });
}
std::string DoctorReport::json() const {
    std::string result =
        "{\"schemaVersion\":1,\"product\":\"Aether\",\"version\":" + json_quote(build::version) +
        ",\"windowsBuild\":" + json_quote(windows_build) +
        ",\"hostArchitecture\":" + json_quote(host_architecture) +
        ",\"supportedHost\":" + (supported_host ? "true" : "false") +
        ",\"developmentToolsDetected\":" + (development_ready() ? "true" : "false") +
        ",\"compiler\":" + json_quote(build::compiler) +
        ",\"buildConfiguration\":" + json_quote(build::configuration) +
        ",\"cmakeVersion\":" + json_quote(build::cmake) +
        ",\"executionAvailable\":true,\"executionScope\":\"installed-apk-experimental\","
        "\"windowBackend\":\"win32-gdi-activity-subset\","
        "\"graphicsBackend\":\"angle-d3d11-first-party-window-and-pbuffer\","
        "\"audioBackend\":\"wasapi-aaudio-first-party-pcm16\","
        "\"translator\":\"dynarmic-arm64-subset\",\"sandbox\":\"lpac-required\","
        "\"androidOsRuntimeRequired\":false,\"prerequisites\":[";
    bool first = true;
    for (const auto &item : prerequisites) {
        if (!first)
            result += ',';
        first = false;
        result += "{\"name\":" + json_quote(item.name) + ",\"status\":" + json_quote(item.status) +
                  ",\"location\":" + json_quote(item.location) + ",\"scope\":" + json_quote(item.scope) + '}';
    }
    return result + "]}";
}
std::string DoctorReport::text(bool verbose) const {
    std::ostringstream output;
    output << "Aether " << build::version << " doctor\nWindows build " << windows_build << " ("
           << host_architecture
           << "): " << (supported_host ? "supported host" : "unsupported or unverified host")
           << "\nBuilt with " << build::compiler << ", CMake " << build::cmake << " (" << build::configuration
           << ")\n";
    for (const auto &item : prerequisites) {
        output << "  " << item.name << ": " << item.status << " [" << item.scope << "]\n";
        if (verbose && !item.location.empty())
            output << "    " << item.location << '\n';
    }
    output << "Detection checks files; a successful configure/build/test proves the toolchain works.\n"
           << "ARM64 translation: Dynarmic JIT with a bounded Android native ABI subset.\n"
           << "DEX/JNI/Activity and Win32/GDI window: experimental installed-APK compatibility.\n"
           << "Guest EGL/GLES: first-party ANGLE/D3D11 window/pbuffer subset; use graphics-window-selftest.\n"
           << "Guest AAudio: first-party shared WASAPI PCM16 subset; use audio-selftest (private session "
              "muted).\n"
           << "Third-party installation is enabled. Every installed launch requires LPAC; unsupported "
              "Android features fail with diagnostics. No full-trust fallback.\n"
           << "Android SDK/NDK/Java are fixture build tools only. No Android OS runtime is required.\n";
    return output.str();
}
} // namespace aether::host
