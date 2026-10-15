#include "aether/a64/selftest.hpp"
#include "aether/android/selftest.hpp"
#include "aether/apk/inspect.hpp"
#include "aether/apk/package_set.hpp"
#include "aether/apk/preview.hpp"
#include "aether/apk/signature.hpp"
#include "aether/audio/selftest.hpp"
#include "aether/build_info.hpp"
#include "aether/common/text.hpp"
#include "aether/dex/selftest.hpp"
#include "aether/diagnostics/diagnostic.hpp"
#include "aether/elf/selftest.hpp"
#include "aether/graphics/selftest.hpp"
#include "aether/graphics/window.hpp"
#include "aether/host/doctor.hpp"
#include "aether/host/window.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "aether/install/cli.hpp"
#include "aether/install/runtime.hpp"
#include "aether/install/store.hpp"
#include "aether/security/apk_session.hpp"
#include "aether/shell/icon_broker.hpp"
#include <algorithm>
#include <array>
#include <exception>
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <string>
#include <vector>

namespace {
int fail(const aether::DiagnosticEvent &event, int status, bool json) {
    // Machine-readable failures use stdout, human-readable failures use stderr.
    (json ? std::cout : std::cerr) << (json ? event.json() : event.text()) << '\n';
    return status;
}

int run(const std::vector<std::string> &arguments, bool json) {
    if (arguments.size() == 3 && arguments[0] == "shell-icons" && arguments[1] == "build-assets") {
        // Build-only generation directly into the requested final output directory.
        // This command does not register COM or enable automatic package reads.
        const std::filesystem::path directory(aether::utf16(arguments[2]));
        for (const auto bundle : {false, true}) {
            const auto data = aether::apk::icon_file(bundle ? aether::apk::bundle_fallback_icon()
                                                          : aether::apk::fallback_icon(), 2);
            const auto path = directory / (bundle ? L"bundle.ico" : L"package.ico");
            aether::host::UniqueHandle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
            DWORD written = 0;
            if (!file || !WriteFile(file.get(), data.data(), static_cast<DWORD>(data.size()), &written, nullptr) ||
                written != data.size() || !FlushFileBuffers(file.get()))
                throw std::runtime_error("Cannot generate final Shell icon resource");
        }
        return 0;
    }
    if (const auto result = aether::shell::dispatch_icon_cli(arguments, json))
        return *result;
    if (!arguments.empty() && arguments.front() == "package") {
        std::vector<std::string> positional;
        std::string output;
        bool output_next = false, seen_json = false;
        for (std::size_t i = 1; i < arguments.size(); ++i) {
            const auto &arg = arguments[i];
            if (output_next) {
                if (arg.empty() || arg.starts_with('-'))
                    throw aether::apk::InspectError("AETHER_CLI_USAGE", "cli", "--output requires a path");
                output = arg;
                output_next = false;
            } else if (arg == "--output" && output.empty())
                output_next = true;
            else if (arg == "--json" && !seen_json)
                seen_json = true;
            else if (!arg.starts_with('-') || arg == "-")
                positional.push_back(arg);
            else
                throw aether::apk::InspectError("AETHER_CLI_USAGE", "cli",
                                                "Unknown or repeated preview option");
        }
        if (output_next || positional.size() != 2 ||
            (positional[0] != "inspect" && positional[0] != "icon") ||
            ((positional[0] == "icon") != !output.empty()))
            return fail({"AETHER_CLI_USAGE",
                         "cli",
                         "Use package inspect <path|-> or package icon <path|-> --output <new.ico>",
                         "Icon preview never installs or executes an app.",
                         {},
                         {},
                         {}},
                        2, json);
        aether::apk::PackagePreview report;
        if (positional[1] == "-") {
            if (_setmode(_fileno(stdin), _O_BINARY) == -1)
                throw std::runtime_error("Cannot read binary stdin");
            std::vector<std::uint8_t> input;
            std::array<char, 65536> block{};
            while (std::cin.read(block.data(), block.size()) || std::cin.gcount()) {
                const auto count = static_cast<std::size_t>(std::cin.gcount());
                if (count > 64 * 1024 * 1024 - input.size())
                    throw aether::apk::InspectError(
                        "AETHER_ICON_INPUT_LIMIT", "package-preview",
                        "Pipe input exceeds 64 MiB; use a local file for larger packages");
                input.insert(input.end(), block.data(), block.data() + count);
            }
            if (std::cin.bad())
                throw std::runtime_error("Cannot read stdin");
            report = aether::apk::preview_package(input);
        } else
            report = aether::apk::preview_package(std::filesystem::path(aether::utf16(positional[1])));
        if (!output.empty()) {
            const auto icon =
                aether::apk::icon_file(report.presentation.bitmap, report.presentation.renderer_version);
            aether::host::UniqueHandle file(CreateFileW(aether::utf16(output).c_str(), GENERIC_WRITE, 0,
                                                        nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
            DWORD written = 0;
            if (!file ||
                !WriteFile(file.get(), icon.data(), static_cast<DWORD>(icon.size()), &written, nullptr) ||
                written != icon.size() || !FlushFileBuffers(file.get()))
                throw aether::apk::InspectError(
                    "AETHER_ICON_OUTPUT_FAILED", "package-preview",
                    "Cannot create the requested new icon; existing files are preserved");
        }
        std::cout << (json ? report.json()
                           : std::string(aether::apk::preview_format_name(report.format)) + ": " +
                                 std::string(aether::apk::icon_status_name(report.status)) + " " +
                                 report.package_name + "\n" + report.presentation.icon_entry + "\n" +
                                 report.reason)
                  << '\n';
        return report.status == aether::apk::IconStatus::extracted ||
                       report.status == aether::apk::IconStatus::no_icon
                   ? 0
               : report.status == aether::apk::IconStatus::unsupported ? 3
                                                                       : 1;
    }
    if (const auto result = aether::install::dispatch_cli(arguments, json))
        return *result;
    std::string command;
    bool verbose = false;
    bool check_development = false;
    std::vector<std::string> positional;
    bool seen_json = false;
    std::string fixture_path;
    bool wants_fixture = false;
    std::string apk_path;
    bool wants_apk = false;
    for (const auto &arg : arguments) {
        if (wants_apk) {
            if (arg.empty() || arg.starts_with('-'))
                return fail(
                    {"AETHER_CLI_USAGE", "cli", "--apk requires a path", "Use aether --help.", {}, {}, {}}, 2,
                    json);
            apk_path = arg;
            wants_apk = false;
            continue;
        }
        if (arg == "--apk" && apk_path.empty()) {
            wants_apk = true;
            continue;
        }
        if (wants_fixture) {
            if (arg.empty() || arg.starts_with('-'))
                return fail({"AETHER_CLI_USAGE",
                             "cli",
                             "--fixture requires a path",
                             "Use aether --help.",
                             {},
                             {},
                             {}},
                            2, json);
            fixture_path = arg;
            wants_fixture = false;
            continue;
        }
        if (arg == "--fixture" && fixture_path.empty()) {
            wants_fixture = true;
            continue;
        }
        if (arg == "--json" && !seen_json) {
            seen_json = true;
            continue;
        }
        if (arg == "--verbose" && !verbose) {
            verbose = true;
            continue;
        }
        if (arg == "--check-development" && !check_development) {
            check_development = true;
            continue;
        }
        if (command.empty() && (arg == "--help" || arg == "--version" || !arg.starts_with('-'))) {
            command = arg;
            continue;
        }
        if (!arg.starts_with('-') || arg == "-") {
            positional.push_back(arg);
            continue;
        }
        return fail({"AETHER_CLI_USAGE",
                     "cli",
                     "Unknown or repeated option",
                     "Use aether --help.",
                     {},
                     {},
                     {{"option", arg}}},
                    2, json);
    }
    if (command.empty())
        command = "--help";
    const bool apk_test = command == "dex-selftest" || command == "framework-selftest" ||
                          command == "window-selftest" || command == "isolation-selftest";
    if (wants_apk || (!apk_path.empty() && !apk_test) ||
        (apk_test && (apk_path.empty() || !positional.empty())))
        return fail({"AETHER_CLI_USAGE",
                     "cli",
                     "APK self-tests require exactly --apk <path>",
                     "Use aether <command> --apk tests/fixtures/hello-aether.apk.",
                     {},
                     {},
                     {}},
                    2, json);
    const bool native_test = command == "native-selftest" || command == "audio-selftest" ||
                             command == "graphics-selftest" || command == "graphics-window-selftest" ||
                             command == "graphics-run";
    if (wants_fixture || (!fixture_path.empty() && !native_test) ||
        (native_test && (fixture_path.empty() || !positional.empty())))
        return fail({"AETHER_CLI_USAGE",
                     "cli",
                     "Native self-tests require exactly --fixture <path>",
                     "Use the command's hash-identified first-party ELF fixture; see aether --help.",
                     {},
                     {},
                     {}},
                    2, json);
    if (check_development && command != "doctor")
        return fail({"AETHER_CLI_USAGE",
                     "cli",
                     "--check-development requires doctor",
                     "Use aether doctor --check-development.",
                     {},
                     {},
                     {}},
                    2, json);
    if (command == "--help" || command == "--version" || command == "doctor" ||
        command == "translate-selftest") {
        if (!positional.empty())
            return fail({"AETHER_CLI_USAGE",
                         "cli",
                         "Unexpected positional argument",
                         "Use aether --help.",
                         {},
                         {},
                         {}},
                        2, json);
    }
    if (command == "--version") {
        if (json)
            std::cout << "{\"schemaVersion\":1,\"product\":\"Aether\",\"version\":"
                      << aether::json_quote(aether::build::version)
                      << ",\"hostTarget\":\"windows-x86_64\"}\n";
        else
            std::cout << "Aether " << aether::build::version << " (Windows x64)\n";
        return 0;
    }
    if (command == "--help") {
        if (json) {
            std::cout
                << "{\"schemaVersion\":1,\"product\":\"Aether\",\"availableCommands\":[\"--help\",\"--"
                   "version\",\"doctor\",\"inspect\",\"package\",\"inspect-xapk\",\"verify-signature\","
                   "\"translate-"
                   "selftest\","
                   "\"native-selftest\",\"dex-"
                   "selftest\",\"framework-selftest\",\"window-selftest\",\"graphics-selftest\","
                   "\"graphics-window-selftest\",\"graphics-run\",\"audio-selftest\","
                   "\"isolation-selftest\",\"run\",\"api-support\",\"install\",\"update\",\"list\",\"info\","
                   "\"uninstall\",\"repair\",\"launch\",\"relaunch\",\"settings\",\"register\","
                   "\"diagnostics\",\"troubleshoot\",\"privacy\"],"
                   "\"unavailableCommands\":[]}\n";
        } else {
            std::cout
                << "Aether - Windows-native Android compatibility research\n"
                   "Usage: aether <command> [--json] [--verbose]\n\n"
                   "Available:\n  --version\n  --help\n  doctor [--check-development]\n  inspect <apk|-> "
                   "(read-only; - reads binary stdin)\n  translate-selftest (self-authored fixtures only)\n"
                   "  inspect-xapk <xapk|-> (read-only verified XAPK v2 member set)\n"
                   "  package inspect <path|-> (metadata/artwork only; no installation assessment)\n"
                   "  package icon <path|-> --output <new.ico> (write preview or fallback artwork)\n"
                   "  verify-signature <apk|-> (read-only APK v2/v3/v3.1 signature verification)\n"
                   "  native-selftest --fixture <so> (hash-identified first-party fixture only)\n\n"
                   "  dex-selftest --apk <apk> (hash-identified first-party DEX/JNI fixture only)\n\n"
                   "  framework-selftest --apk <apk> (first-party Activity/lifecycle/view proof)\n"
                   "  isolation-selftest --apk <apk> (LPAC first-party Activity and private storage proof)\n"
                   "  window-selftest --apk <apk> (hidden HWND, input, DPI and rendering proof)\n"
                   "  graphics-selftest --fixture <so> (first-party translated EGL/GLES pixel proof)\n"
                   "  graphics-window-selftest --fixture <so> (hidden GPU window/input proof)\n"
                   "  graphics-run --fixture <so> (interactive first-party ARM64 graphics window)\n"
                   "  audio-selftest --fixture <so> (first-party ARM64 AAudio/WASAPI; private session "
                   "muted)\n"
                   "  run <apk> (normal Win32 window; exact first-party fixture only)\n"
                   "  api-support [query] (search Android class/method/signature/status)\n\n"
                   "  install <apk> --dry-run (inspection only; no execution or writes)\n"
                   "  install <apk> --developer-fixture --yes (exact fixture package storage)\n"
                   "  install <apk> --expected-sha256 <preview-hash> --yes (experimental APK storage)\n"
                   "    Add --windows --expected-sha256 <preview-hash> --allow-clock\n"
                   "    [--allow-private-files] for one complete Windows installation.\n"
                   "  update <apk> --app-id <id> --dry-run (review both versions)\n"
                   "  update <apk> --app-id <id> --expected-current-sha256 <old-hash>\n"
                   "    --expected-sha256 <new-hash> --yes (verified newer version; preserves grants/data)\n"
                   "  list (installed/pending/retained package records)\n"
                   "  info --app-id <id> (verify stored package integrity)\n"
                   "  launch --app-id <id> (isolated installed Activity)\n"
                   "  relaunch --app-id <id> (resolve verified Windows registration)\n"
                   "  register --app-id <id> --yes (per-user Start and uninstall entries)\n"
                   "  explorer status (inspect optional APK handler registration)\n"
                   "  explorer register [--store <root>] --yes (offer Install with Aether)\n"
                   "  explorer repair|remove --yes (owned entries only; defaults stay unchanged)\n"
                   "  runtime status [--root <runtime>] (installation and dependency state)\n"
                   "  runtime prepare --root <new-directory> --yes (fresh installation intent)\n"
                   "  runtime finalize --yes (record the installed payload)\n"
                   "  runtime upgrade --root <runtime> --bundle <AetherSetup.exe> --yes (external compatible "
                   "upgrade)\n"
                   "  runtime check-removal --root <runtime> (external exclusive preflight)\n"
                   "  runtime remove --root <runtime> --yes (external owned removal)\n"
                   "  runtime repair [--root <runtime>] --yes (truncate an incomplete final frame)\n"
                   "  runtime forget-store --store <empty-store> [--root <runtime>] --yes\n"
                   "  privacy [--json] (offline privacy and permissions guide for this build)\n"
                   "  settings --app-id <id> (inspect recorded permission grants)\n"
                   "    [--allow-clock|--deny-clock] [--allow-private-files|--deny-private-files] --yes\n"
                   "    Optional review: --expected-current-sha256 <hash> --expected-permissions <grants>\n"
                   "    Grants: none, monotonic-clock, private-files, or monotonic-clock,private-files.\n"
                   "  diagnostics --app-id <id> [--output <new-report.json>] (read-only app checks)\n"
                   "    No APK execution or private app data collection. Exit 1 if a check fails.\n"
                   "  troubleshoot --app-id <id> [--include-host-details] [--include-audit-summaries]\n"
                   "    Without --yes: collection preview only. With --yes: collect the selected details.\n"
                   "    [--output <new-bundle.json>] saves the captured bundle without replacing files.\n"
                   "  uninstall --app-id <id> --yes <--keep-data|--delete-data>\n"
                   "  repair --yes (recover interrupted package-store transactions)\n"
                   "  Store commands accept --store <absolute-local-root> for development.\n"
                   "  Default store: LocalAppData known folder / Aether.\n\n"
                   "Exit codes: 0 success, 1 failure, 2 usage, 3 unsupported.\n"
                   "--json emits one JSON object to stdout, including errors.\n"
                   "Installed third-party APKs use experimental Android compatibility and LPAC isolation.\n"
                   "Developer run/selftest commands remain restricted to their original fixtures.\n";
        }
        return 0;
    }
    if (command == "doctor") {
        const auto report = aether::host::query_doctor();
        std::cout << (json ? report.json() + '\n' : report.text(verbose));
        return report.supported_host && (!check_development || report.development_ready()) ? 0 : 1;
    }
    if (command == "translate-selftest") {
        const auto report = aether::a64::translate_selftest();
        std::cout << (json ? report.json() + '\n' : report.text(verbose));
        return report.passed() ? 0 : 1;
    }
    if (command == "native-selftest") {
        const auto report = aether::elf::native_selftest(aether::utf16(fixture_path));
        std::cout << (json ? report.json() + '\n' : report.text(verbose));
        return report.passed() ? 0 : 1;
    }
    if (command == "audio-selftest") {
        const auto report = aether::audio::audio_selftest(aether::utf16(fixture_path));
        std::cout << (json ? report.json() + '\n' : report.text(verbose));
        return report.passed() ? 0 : 1;
    }
    if (command == "graphics-selftest") {
        const auto report = aether::graphics::graphics_selftest(aether::utf16(fixture_path));
        std::cout << (json ? report.json() + '\n' : report.text(verbose));
        return report.passed() ? 0 : 1;
    }
    if (command == "graphics-window-selftest" || command == "graphics-run") {
        const auto report = aether::graphics::run_graphics_window(aether::utf16(fixture_path),
                                                                  command == "graphics-window-selftest");
        std::cout << (json ? report.json() + '\n' : report.text(verbose));
        return report.passed() ? 0 : 1;
    }
    if (command == "dex-selftest") {
        const auto report = aether::dex::managed_selftest(aether::utf16(apk_path));
        std::cout << (json ? report.json() + '\n' : report.text(verbose));
        return report.passed() ? 0 : 1;
    }
    if (command == "framework-selftest") {
        const auto report = aether::android::framework_selftest(aether::utf16(apk_path));
        std::cout << (json ? report.json() + '\n' : report.text(verbose));
        return report.passed() ? 0 : 1;
    }
    if (command == "isolation-selftest") {
        std::cout << aether::security::isolated_apk_selftest(aether::utf16(apk_path), json) << '\n';
        return 0;
    }
    if (command == "run" || command == "window-selftest") {
        if (command == "run" && positional.size() != 1)
            return fail({"AETHER_CLI_USAGE",
                         "cli",
                         "run requires exactly one APK path",
                         "Use aether run tests/fixtures/hello-aether.apk.",
                         {},
                         {},
                         {}},
                        2, json);
        const auto report = aether::host::run_fixture_window(
            aether::utf16(command == "run" ? positional[0] : apk_path), command == "window-selftest");
        std::cout << (json ? report.json() + '\n' : report.text(verbose));
        return report.passed() ? 0 : 1;
    }
    if (command == "api-support") {
        if (positional.size() > 1)
            return fail({"AETHER_CLI_USAGE",
                         "cli",
                         "api-support accepts at most one search query",
                         "Use aether api-support [query] --json.",
                         {},
                         {},
                         {}},
                        2, json);
        std::cout << aether::android::api_support_report(positional.empty() ? "" : positional[0], json)
                  << (json ? "\n" : "");
        return 0;
    }
    if (command == "inspect" || command == "verify-signature" || command == "inspect-xapk") {
        if (positional.size() != 1)
            return fail({"AETHER_CLI_USAGE",
                         "cli",
                         command + " requires exactly one package path or -",
                         "Use aether " + command + " <package> --json.",
                         {},
                         {},
                         {}},
                        2, json);
        std::vector<std::uint8_t> bytes;
        if (positional[0] == "-") {
            if (_setmode(_fileno(stdin), _O_BINARY) == -1)
                throw std::runtime_error("Cannot read binary stdin");
            std::array<char, 65536> block{};
            const aether::apk::InspectLimits limits;
            while (std::cin.read(block.data(), block.size()) || std::cin.gcount() != 0) {
                const auto count = static_cast<std::size_t>(std::cin.gcount());
                if (count > limits.archive_bytes - bytes.size())
                    throw aether::apk::InspectError("AETHER_APK_LIMIT", "apk-read",
                                                    "Standard input exceeds archive size limit");
                bytes.insert(bytes.end(), block.data(), block.data() + count);
            }
            if (std::cin.bad())
                throw std::runtime_error("Cannot read stdin");
        } else
            bytes = aether::apk::read_package(aether::utf16(positional[0]));
        if (command == "inspect-xapk") {
            const auto report = aether::apk::inspect_xapk(bytes);
            std::cout << (json ? report.json() + '\n' : report.text(verbose));
            return 0;
        }
        if (command == "verify-signature") {
            const auto signing = aether::apk::verify_signature(bytes);
            std::cout << (json ? "{\"schemaVersion\":1,\"operation\":\"verify-signature\","
                                 "\"executionAvailable\":false,\"signing\":" +
                                     signing.json() + "}\n"
                               : signing.text());
            return signing.verified() ? 0 : (signing.status == "unsupported" ? 3 : 1);
        }
        const auto report = aether::apk::inspect(bytes);
        const auto signing = aether::apk::verify_signature(bytes);
        std::cout << (json ? report.json(&signing) + '\n' : report.text(verbose, &signing));
        return 0;
    }
    return fail(
        {"AETHER_CLI_USAGE", "cli", "Unknown command", "Use aether --help.", {}, {}, {{"command", command}}},
        2, json);
}
} // namespace

int wmain(int argc, wchar_t **argv) {
    bool json = false;
    for (int i = 1; i < argc; ++i)
        if (std::wstring_view(argv[i]) == L"--json")
            json = true;
    try {
        std::vector<std::string> arguments;
        for (int i = 1; i < argc; ++i)
            arguments.push_back(aether::utf8(argv[i]));
        std::optional<aether::install::RuntimeUseLease> runtime;
        if (!aether::install::is_runtime_command(arguments))
            runtime.emplace();
        return run(arguments, json);
    } catch (const aether::install::InstallError &error) {
        return fail({error.code,
                     "install",
                     error.what(),
                     "See docs/WINDOWS_NATIVE_INTEGRATION.md for package-store commands and limitations.",
                     {},
                     {},
                     {}},
                    error.code == "AETHER_CLI_USAGE" || error.code == "AETHER_INSTALL_CONFIRMATION_REQUIRED"
                        ? 2
                    : error.code == "AETHER_INSTALL_UNSUPPORTED" ? 3
                                                                 : 1,
                    json);
    } catch (const aether::security::ProtocolError &error) {
        return fail({"AETHER_ISOLATED_WORKER_FAILED",
                     "isolation",
                     error.what(),
                     "Review the reported Android compatibility or isolation failure; see "
                     "docs/ISOLATED_WORKER.md. Execution never falls back to full trust.",
                     {},
                     {},
                     {}},
                    1, json);
    } catch (const aether::dex::DexError &error) {
        if (error.code.starts_with("AETHER_WINDOW_"))
            return fail({error.code, "windows-ui", error.what(), "See docs/WINDOW_HOST.md.", {}, {}, {}}, 1,
                        json);
        if (error.code.starts_with("AETHER_ANDROID_"))
            return fail(
                {error.code, "android-framework", error.what(), "See docs/ANDROID_FRAMEWORK.md.", {}, {}, {}},
                1, json);
        return fail({error.code, "dex-jni", error.what(), "See docs/DEX_JNI_RUNTIME.md.", {}, {}, {}}, 1,
                    json);
    } catch (const aether::dex::JavaException &) {
        return fail({"AETHER_MANAGED_EXCEPTION",
                     "dex-jni",
                     "An uncaught managed exception left the fixture",
                     "See docs/DEX_JNI_RUNTIME.md.",
                     {},
                     {},
                     {}},
                    1, json);
    } catch (const aether::elf::ElfError &error) {
        return fail({error.code, "elf", error.what(), "See docs/ABI_SUPPORT_MATRIX.md.", {}, {}, {}}, 1,
                    json);
    } catch (const aether::a64::GuestError &error) {
        if (error.code.starts_with("AETHER_AUDIO_"))
            return fail({error.code, "audio", error.what(), "See docs/GUEST_AUDIO.md.", {}, {}, {}}, 1, json);
        if (error.code.starts_with("AETHER_GRAPHICS_"))
            return fail({error.code, "graphics", error.what(), "See docs/GUEST_GRAPHICS.md.", {}, {}, {}}, 1,
                        json);
        return fail({error.code, "a64", error.what(), "See docs/A64_TRANSLATION.md.", {}, {}, {}}, 1, json);
    } catch (const aether::apk::InspectError &error) {
        return fail(error.diagnostic, 1, json);
    } catch (const std::exception &) {
        // Do not expose arbitrary exception text or host paths by default.
        return fail({"AETHER_INTERNAL_ERROR",
                     "cli",
                     "A host operation failed",
                     "Run doctor --verbose and record the command and Aether version.",
                     {},
                     {},
                     {}},
                    1, json);
    }
}
