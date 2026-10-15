#include "install_dialog.hpp"
#include "aether/apk/artwork.hpp"
#include "aether/apk/launcher.hpp"
#include "aether/common/text.hpp"
#include "aether/install/store.hpp"
#include "privacy_dialog.hpp"
#include "privacy_ids.h"
#include <Windows.h>
#include <commctrl.h>
#include <future>
#include <iostream>
#include <set>
#include <sstream>
#include <utility>

namespace aether::install {
namespace {
constexpr int install_button = 100, update_button = 101, deny_files = 200, allow_files = 201;

void honor_visibility(HWND window) {
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    GetStartupInfoW(&startup);
    if ((startup.dwFlags & STARTF_USESHOWWINDOW) && startup.wShowWindow == SW_SHOWMINNOACTIVE)
        ShowWindow(window, SW_SHOWMINNOACTIVE);
}
std::string error_code(const std::exception &error) {
    if (const auto *value = dynamic_cast<const InstallError *>(&error))
        return value->code;
    if (const auto *value = dynamic_cast<const apk::InspectError *>(&error))
        return value->diagnostic.code;
    return "AETHER_SHELL_FAILED";
}
std::wstring display(std::string_view value, std::string_view fallback = "not declared") {
    return utf16(apk::clean_display_name(value, fallback));
}
std::wstring detail_text(std::wstring_view value) {
    std::wstring result;
    for (const auto character : value) {
        if (character == 0x061c || character == 0x200e || character == 0x200f ||
            (character >= 0x202a && character <= 0x202e) || (character >= 0x2066 && character <= 0x2069))
            continue;
        result += character < 32 || (character >= 0x7f && character <= 0x9f) || character == 0x2028 ||
                          character == 0x2029
                      ? L' '
                      : character;
        if (result.size() == 2048) {
            if (result.back() >= 0xd800 && result.back() <= 0xdbff)
                result.pop_back();
            result += L" [truncated]";
            break;
        }
    }
    return result;
}
std::wstring sdk(const std::optional<std::uint32_t> &value) {
    return value ? std::to_wstring(*value) : L"not declared";
}
struct Icon {
    HICON value = nullptr;
    explicit Icon(const apk::IconBitmap &bitmap) {
        // Only Aether's canonical DIB encoder supplies these bytes. Raw APK
        // images never enter a Windows image decoder.
        auto bytes = apk::icon_file(bitmap, 2);
        const auto number = [&](std::size_t offset) {
            return static_cast<DWORD>(bytes.at(offset)) | (static_cast<DWORD>(bytes.at(offset + 1)) << 8) |
                   (static_cast<DWORD>(bytes.at(offset + 2)) << 16) |
                   (static_cast<DWORD>(bytes.at(offset + 3)) << 24);
        };
        const auto size = GetSystemMetrics(SM_CXICON);
        std::size_t selected = 6 + 6 * 16;
        for (std::size_t offset = 6; offset < 6 + 7 * 16; offset += 16)
            if ((bytes.at(offset) ? int(bytes.at(offset)) : 256) >= size) {
                selected = offset;
                break;
            }
        const auto length = number(selected + 8), offset = number(selected + 12);
        if (offset <= bytes.size() && length <= bytes.size() - offset)
            value = CreateIconFromResourceEx(bytes.data() + offset, length, TRUE, 0x00030000, size, size, 0);
        if (!value)
            throw InstallError("AETHER_SHELL_ICON", "Windows could not create the installation preview icon");
    }
    ~Icon() {
        if (value)
            DestroyIcon(value);
    }
    Icon(const Icon &) = delete;
    Icon &operator=(const Icon &) = delete;
};
struct Observation {
    std::shared_ptr<const InstallPreview> package;
    std::optional<UpdatePreview> update;
    std::wstring heading = L"Inspecting APK", content, details;
    std::string code;
    bool available = false;
};
struct Review {
    const std::filesystem::path source, root;
    std::future<Observation> read;
    Observation shown;
    std::shared_ptr<const InstallPreview> selected;
    std::optional<UpdatePreview> selected_update;
    std::unique_ptr<Icon> icon = std::make_unique<Icon>(apk::fallback_icon());
    std::string icon_hash = apk::sha256(apk::icon_file(apk::fallback_icon(), 2));
    bool clock = false, files = false, previous_failure = false;
    ULONGLONG last_read = 0;
    unsigned reads = 0, failures = 0, recoveries = 0;

    Observation observe() const {
        Observation result;
        try {
            result.package = std::make_shared<const InstallPreview>(preview(source));
            const auto &report = result.package->inspection;
            const auto &manifest = report.manifest;
            result.heading = L"Install " + display(report.presentation->label, "Android app") + L"?";
            result.content = L"Package: " + display(manifest.package_id) + L"\nVersion: " +
                             display(manifest.version_name) + L" (" + sdk(manifest.version_code) +
                             L")\nAndroid API: minimum " + sdk(manifest.min_sdk) + L", target " +
                             sdk(manifest.target_sdk) + L"\nNative ABI: ";
            std::set<std::string> abis;
            for (const auto &library : report.native)
                abis.insert(library.abi);
            if (abis.empty())
                result.content += L"none declared";
            for (const auto &abi : abis)
                result.content += (abi == *abis.begin() ? L"" : L", ") + display(abi);
            result.content += L"\nSource: " + display(utf8(source.filename().wstring())) + L"\n\n";
            if (result.package->signing.verified()) {
                result.content +=
                    report.format == apk::PackageFormat::xapk
                        ? L"Signing: every APK in this XAPK has verified signatures and the "
                          L"same certificate set. Publisher identity is not authenticated.\n"
                        : L"Signing: APK " + display(result.package->signing.scheme) +
                              L" signatures verified. Publisher identity is not authenticated.\n";
                for (const auto &signer : result.package->signing.signers)
                    result.content += L"Certificate SHA-256: " + utf16(signer.certificate_sha256) + L"\n";
            } else {
                result.content += L"Signing: unverified. No publisher identity has been authenticated.\n";
                if (result.package->signing.status == "unsupported")
                    result.content += L"Signing support: " + display(result.package->signing.message) + L"\n";
            }
            if (result.package->installable) {
                result.content += L"Compatibility: experimental Android support. Choose its permissions "
                                  L"below; installing does not start the app.";
                result.available = true;
            } else {
                result.content +=
                    L"Not supported for installation. " + detail_text(utf16(result.package->reason));
                result.code = "AETHER_INSTALL_UNSUPPORTED";
            }
            result.details = L"SHA-256: " + utf16(report.sha256) + L"\nSource path: " +
                             detail_text(source.wstring()) + L"\n\n" +
                             detail_text(utf16(result.package->reason)) + L"\n\nActivities declared: " +
                             std::to_wstring(manifest.activities.size());
            for (std::size_t i = 0; i < manifest.activities.size() && i < 8; ++i)
                result.details += L"\n" + display(manifest.activities[i].name) +
                                  (manifest.activities[i].launcher ? L" (declared launcher)" : L"");
            if (manifest.activities.size() > 8)
                result.details += L"\nAdditional activities omitted from this preview.";
            const auto launcher = apk::select_launcher(manifest);
            if (launcher.activity) {
                const auto &selected_activity = manifest.activities[*launcher.activity];
                result.details += L"\n\nSelected launcher: " + display(selected_activity.name) +
                                  L"\nActivity class: " +
                                  display(selected_activity.target.empty() ? selected_activity.name
                                                                           : selected_activity.target);
            } else {
                result.details += L"\n\nLauncher selection: " + detail_text(utf16(launcher.reason));
            }
            result.details +=
                L"\n\nAndroid permissions declared: " + std::to_wstring(manifest.permissions.size());
            for (std::size_t i = 0; i < manifest.permissions.size() && i < 8; ++i)
                result.details += L"\n" + display(manifest.permissions[i]);
            if (manifest.permissions.size() > 8)
                result.details += L"\nAdditional permissions omitted from this preview.";
            result.details +=
                L"\nDeclarations are not grants.\n\nAvailable here: monotonic time and optional "
                L"app-private file access. Host folders, network, camera and microphone access "
                L"are not granted. Google Play Services, WebView, general Services, "
                L"BroadcastReceivers and ContentProviders are unsupported. This preview does "
                L"not enumerate those unsupported component types.";
            // A read session never creates a missing store. A conflict disables
            // this new-install flow without silently updating existing grants.
            PackageStore store(root);
            for (const auto &app : store.list())
                if (app.package_id == manifest.package_id && app.state != State::removed) {
                    result.available = false;
                    result.code = "AETHER_INSTALL_CONFLICT";
                    result.update = store.review_update(*result.package, app.id);
                    result.heading = L"Update " + display(report.presentation->label, "Android app") + L"?";
                    result.content += L"\n\nThis package already has an installation or retained state. "
                                      L"Current version: " +
                                      display(app.version_name) + L" (" + std::to_wstring(app.version_code) +
                                      L").\n" + detail_text(utf16(result.update->reason)) +
                                      L"\nUpdates keep existing permissions; the new-install choices below "
                                      L"do not change them.";
                    result.details +=
                        L"\n\nCurrent app ID: " + utf16(app.id) + L"\nCurrent SHA-256: " + utf16(app.sha256) +
                        L"\nExisting clock permission: " +
                        ((app.permissions & security::installed_clock) ? L"allowed" : L"denied") +
                        L"\nExisting private files permission: " +
                        ((app.permissions & security::installed_files) ? L"allowed" : L"denied");
                    if (result.update->updateable)
                        result.code.clear();
                    else {
                        result.code = result.update->code;
                        result.content += L"\n" + utf16(result.code);
                    }
                    break;
                }
        } catch (const std::exception &error) {
            result.available = false;
            result.update.reset();
            result.code = error_code(error);
            result.heading = L"APK inspection unavailable";
            result.content = L"The source or installation status could not be read. Checking again "
                             L"automatically. Your permission choices stay selected.\n\n" +
                             detail_text(utf16(error.what())) + L"\n" + utf16(result.code);
            result.details = L"No installation has been attempted. Keep the source available and resolve "
                             L"the reported file or store issue, or choose Cancel.";
        }
        return result;
    }
    void enable(HWND window) const {
        SendMessageW(window, TDM_ENABLE_BUTTON, install_button, shown.available && clock);
        SendMessageW(window, TDM_ENABLE_BUTTON, update_button, shown.update && shown.update->updateable);
    }
    void apply(HWND window, Observation value) {
        if (value.package) {
            const auto &bitmap = value.package->inspection.presentation->bitmap;
            const auto hash = apk::sha256(apk::icon_file(bitmap, 2));
            if (hash != icon_hash) {
                auto next = std::make_unique<Icon>(bitmap);
                SendMessageW(window, TDM_UPDATE_ICON, TDIE_ICON_MAIN, reinterpret_cast<LPARAM>(next->value));
                icon = std::move(next);
                icon_hash = hash;
            }
        }
        const auto update = [&](TASKDIALOG_ELEMENTS element, const std::wstring &old,
                                const std::wstring &text) {
            if (old != text)
                SendMessageW(window, TDM_SET_ELEMENT_TEXT, element, reinterpret_cast<LPARAM>(text.c_str()));
        };
        update(TDE_MAIN_INSTRUCTION, shown.heading, value.heading);
        update(TDE_CONTENT, shown.content, value.content);
        update(TDE_EXPANDED_INFORMATION, shown.details, value.details);
        const bool failed = !value.code.empty() && value.code != "AETHER_INSTALL_UNSUPPORTED" &&
                            value.code != "AETHER_INSTALL_CONFLICT" &&
                            !value.code.starts_with("AETHER_UPDATE_");
        if (failed)
            ++failures;
        else if (previous_failure)
            ++recoveries;
        previous_failure = failed;
        shown = std::move(value);
        enable(window);
    }
    void update(HWND window) {
        if (read.valid()) {
            if (read.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                return;
            apply(window, read.get());
        }
        const auto now = GetTickCount64();
        if (reads == 0 || now - last_read >= 1000) {
            last_read = now;
            read = std::async(std::launch::async, [this] { return observe(); });
            ++reads;
        }
    }
    std::string metrics() const {
        return "\"previewReads\":" + std::to_string(reads) +
               ",\"previewReadFailures\":" + std::to_string(failures) +
               ",\"previewReadRecoveries\":" + std::to_string(recoveries) +
               ",\"previewReadConcurrencyLimit\":1";
    }
    static HRESULT CALLBACK callback(HWND window, UINT notification, WPARAM value, LPARAM, LONG_PTR data) {
        auto &self = *reinterpret_cast<Review *>(data);
        try {
            if (notification == TDN_CREATED) {
                honor_visibility(window);
                self.enable(window);
                self.update(window);
            } else if (notification == TDN_BUTTON_CLICKED && value == IDC_PRIVACY_OPEN) {
                show_privacy_dialog(window);
                return S_FALSE;
            } else if (notification == TDN_TIMER)
                self.update(window);
            else if (notification == TDN_VERIFICATION_CLICKED) {
                self.clock = value != 0;
                self.enable(window);
            } else if (notification == TDN_RADIO_BUTTON_CLICKED)
                self.files = value == allow_files;
            else if (notification == TDN_BUTTON_CLICKED && value == install_button) {
                if (!self.shown.available || !self.clock || !self.shown.package)
                    return S_FALSE;
                // Bind consent to the last displayed preview, never an unseen
                // result from the in-flight read or another source read.
                self.selected = self.shown.package;
            } else if (notification == TDN_BUTTON_CLICKED && value == update_button) {
                if (!self.shown.package || !self.shown.update || !self.shown.update->updateable)
                    return S_FALSE;
                self.selected = self.shown.package;
                self.selected_update = self.shown.update;
            }
        } catch (...) {
            self.shown.available = false;
            self.shown.update.reset();
            self.enable(window);
            if (notification == TDN_BUTTON_CLICKED && (value == install_button || value == update_button))
                return S_FALSE;
        }
        // Reading (or failing to open) the guide can never accept or dismiss consent.
        return notification == TDN_BUTTON_CLICKED && value == IDC_PRIVACY_OPEN ? S_FALSE : S_OK;
    }
};
struct Outcome {
    std::optional<InstalledApp> app;
    std::string code, message;
};
struct Commit {
    const std::filesystem::path source, root;
    const std::string sha256;
    const std::uint32_t permissions;
    const std::optional<UpdatePreview> update;
    std::future<Outcome> write;
    Outcome outcome;
    bool done = false;
    unsigned attempts = 0;

    void finish(HWND window) {
        const auto heading =
            outcome.app
                ? std::wstring(update ? L"Updated " : L"Installed ") + display(outcome.app->display_name)
                : std::wstring(update ? L"Update needs attention" : L"Installation could not complete");
        const auto content = outcome.app
                                 ? (update ? L"The app version is updated. Its identity, private data and "
                                             L"permissions are preserved."
                                           : L"The app now has its own Start shortcut and Windows Installed "
                                             L"apps entry. Open it from Start when you are ready.")
                                 : detail_text(utf16(outcome.message)) + L"\n\n" + utf16(outcome.code) +
                                       L"\nNo automatic retry will be made. Inspect the source or resolve "
                                       L"the reported issue before starting another installation.";
        SendMessageW(window, TDM_SET_PROGRESS_BAR_MARQUEE, FALSE, 0);
        SendMessageW(window, TDM_SET_MARQUEE_PROGRESS_BAR, FALSE, 0);
        SendMessageW(window, TDM_SET_PROGRESS_BAR_POS, 100, 0);
        SendMessageW(window, TDM_SET_ELEMENT_TEXT, TDE_MAIN_INSTRUCTION,
                     reinterpret_cast<LPARAM>(heading.c_str()));
        SendMessageW(window, TDM_SET_ELEMENT_TEXT, TDE_CONTENT, reinterpret_cast<LPARAM>(content.c_str()));
        done = true;
        SendMessageW(window, TDM_ENABLE_BUTTON, IDCLOSE, TRUE);
    }
    static HRESULT CALLBACK callback(HWND window, UINT notification, WPARAM, LPARAM, LONG_PTR data) {
        auto &self = *reinterpret_cast<Commit *>(data);
        try {
            if (notification == TDN_CREATED) {
                honor_visibility(window);
                SendMessageW(window, TDM_ENABLE_BUTTON, IDCLOSE, FALSE);
                SendMessageW(window, TDM_SET_PROGRESS_BAR_MARQUEE, TRUE, 30);
                ++self.attempts;
                self.write = std::async(std::launch::async, [&self] {
                    try {
                        return Outcome{
                            self.update
                                ? update_package(self.source, self.root, self.update->current.id,
                                                 self.update->current.sha256, self.sha256)
                                : install_windows(self.source, self.root, self.sha256, self.permissions),
                            {},
                            {}};
                    } catch (const std::exception &error) {
                        return Outcome{{}, error_code(error), error.what()};
                    }
                });
            } else if (notification == TDN_TIMER && self.write.valid() &&
                       self.write.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
                self.outcome = self.write.get();
                self.finish(window);
            } else if (notification == TDN_BUTTON_CLICKED && !self.done)
                return S_FALSE; // An in-flight transaction is never cancelled halfway through.
        } catch (const std::exception &error) {
            self.outcome = {{}, error_code(error), error.what()};
            self.finish(window);
        }
        return S_OK;
    }
};
} // namespace

int show_install_dialog(const std::filesystem::path &source, const std::filesystem::path &root, bool json) {
    Review review{source, root};
    review.shown.content =
        L"Reading package details and the current installation status. No app code is run.";
    review.shown.details =
        L"Package identity, signing status, components and declared permissions will appear here.";
    const auto initial_content = review.shown.content, initial_details = review.shown.details;
    const TASKDIALOG_BUTTON buttons[] = {
        {install_button, L"Install"}, {update_button, L"Update"}, {IDC_PRIVACY_OPEN, L"Privacy..."}};
    const TASKDIALOG_BUTTON radios[] = {{deny_files, L"Deny private file access"},
                                        {allow_files, L"Allow files inside this app's private storage only"}};
    TASKDIALOGCONFIG config{};
    config.cbSize = sizeof(config);
    config.hInstance = GetModuleHandleW(nullptr);
    config.dwFlags =
        TDF_ALLOW_DIALOG_CANCELLATION | TDF_CALLBACK_TIMER | TDF_CAN_BE_MINIMIZED | TDF_USE_HICON_MAIN;
    config.dwCommonButtons = TDCBF_CANCEL_BUTTON;
    config.pszWindowTitle =
        source.extension() == L".xapk" ? L"Aether - Install XAPK" : L"Aether - Install APK";
    config.pszMainInstruction = L"Inspecting APK";
    config.pszContent = initial_content.c_str();
    config.pszExpandedInformation = initial_details.c_str();
    config.pszExpandedControlText = L"Hide package details";
    config.pszCollapsedControlText = L"Show package details";
    config.pszVerificationText = L"Allow monotonic time (new installations only)";
    config.hMainIcon = review.icon->value;
    config.cButtons = static_cast<UINT>(std::size(buttons));
    config.pButtons = buttons;
    config.cRadioButtons = static_cast<UINT>(std::size(radios));
    config.pRadioButtons = radios;
    config.nDefaultRadioButton = deny_files;
    config.nDefaultButton = IDCANCEL;
    config.pfCallback = Review::callback;
    config.lpCallbackData = reinterpret_cast<LONG_PTR>(&review);
    config.cxWidth = 360;
    int selected = IDCANCEL;
    BOOL clock = FALSE;
    const auto status = TaskDialogIndirect(&config, &selected, nullptr, &clock);
    if (FAILED(status))
        throw InstallError("AETHER_SHELL_DIALOG", "Windows could not open the APK installation confirmation");
    // Finish the read before obtaining the write lock. Its result cannot change
    // the already selected preview or permission choices.
    if (review.read.valid())
        review.read.get();
    if ((selected != install_button && selected != update_button) || !review.selected) {
        if (json)
            std::cout
                << "{\"schemaVersion\":1,\"operation\":\"install\",\"cancelled\":true,\"writeAttempts\":0,"
                << review.metrics() << "}\n";
        return 0;
    }
    Commit commit{source, root, review.selected->inspection.sha256,
                  security::installed_clock | (review.files ? security::installed_files : 0),
                  review.selected_update};
    TASKDIALOGCONFIG progress{};
    progress.cbSize = sizeof(progress);
    progress.hInstance = GetModuleHandleW(nullptr);
    progress.dwFlags = TDF_CALLBACK_TIMER | TDF_CAN_BE_MINIMIZED | TDF_SHOW_MARQUEE_PROGRESS_BAR;
    progress.dwCommonButtons = TDCBF_CLOSE_BUTTON;
    progress.pszWindowTitle = L"Aether - Installation result";
    progress.pszMainInstruction = commit.update ? L"Updating app" : L"Installing app";
    progress.pszContent =
        commit.update ? L"Rechecking both approved versions and updating the app while preserving its data "
                        L"and permissions."
                      : L"Rechecking the approved APK and creating its private storage and Windows entries.";
    progress.nDefaultButton = IDCLOSE;
    progress.pfCallback = Commit::callback;
    progress.lpCallbackData = reinterpret_cast<LONG_PTR>(&commit);
    progress.cxWidth = 360;
    const auto committed = TaskDialogIndirect(&progress, nullptr, nullptr, nullptr);
    if (FAILED(committed))
        throw InstallError("AETHER_SHELL_DIALOG", "Windows could not display the installation result");
    if (json) {
        std::cout << "{\"schemaVersion\":1,\"operation\":" << json_quote(commit.update ? "update" : "install")
                  << ",\"cancelled\":false,\"reviewedSha256\":" << json_quote(commit.sha256)
                  << ",\"writeAttempts\":" << commit.attempts << ',' << review.metrics();
        if (commit.update)
            std::cout << ",\"reviewedCurrentSha256\":" << json_quote(commit.update->current.sha256)
                      << ",\"reviewedAppId\":" << json_quote(commit.update->current.id);
        if (commit.outcome.app)
            std::cout << ",\"app\":" << commit.outcome.app->json();
        else
            std::cout << ",\"code\":" << json_quote(commit.outcome.code)
                      << ",\"message\":" << json_quote(commit.outcome.message);
        std::cout << "}\n";
    }
    return commit.outcome.app ? 0 : 1;
}
} // namespace aether::install
