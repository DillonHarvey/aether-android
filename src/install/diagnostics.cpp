#include "aether/install/diagnostics.hpp"
#include "aether/common/text.hpp"
#include "aether/host/windows/unique_handle.hpp"
#include "private.hpp"
#include <Windows.h>
#include <algorithm>
#include <sstream>

namespace aether::install {
namespace {
void require(bool value, const char *code, const char *message) {
    if (!value)
        throw InstallError(code, message);
}
void fingerprints(std::ostream &out, const std::vector<std::string> &values) {
    out << '[';
    for (std::size_t index = 0; index < values.size(); ++index)
        out << (index ? "," : "") << json_quote(values[index]);
    out << ']';
}
void permissions(std::ostream &out, std::uint32_t mask) {
    out << '[';
    if (mask & security::installed_clock)
        out << "\"monotonic-clock\"";
    if (mask & security::installed_files)
        out << ((mask & security::installed_clock) ? "," : "") << "\"private-files\"";
    if (mask & security::installed_wall_clock)
        out << ((mask & (security::installed_clock | security::installed_files)) ? "," : "") << "\"wall-clock\"";
    out << ']';
}
} // namespace

bool AppDiagnostics::passed() const {
    return std::none_of(checks.begin(), checks.end(),
                        [](const auto &check) { return check.status == "fail"; });
}
std::string AppDiagnostics::json() const {
    std::ostringstream out;
    out << "{\"schemaVersion\":1,\"operation\":\"diagnostics\",\"passed\":" << (passed() ? "true" : "false")
        << ",\"readOnlyInspection\":true,\"guestExecution\":false,\"app\":{\"appId\":" << json_quote(app.id)
        << ",\"packageId\":" << json_quote(app.package_id)
        << ",\"versionName\":" << json_quote(app.version_name) << ",\"versionCode\":" << app.version_code
        << ",\"state\":" << json_quote(lifecycle) << ",\"packageGeneration\":" << app.package_generation
        << ",\"sha256\":" << json_quote(app.sha256) << ",\"packageBytes\":" << app.package_bytes
        << ",\"recordedPermissionGrants\":";
    permissions(out, app.permissions);
    out << ",\"effectivePermissions\":";
    permissions(out, installed_state(app.state) ? app.permissions : 0);
    out << ",\"signingIdentityRecorded\":" << (app.signing == SigningState::not_recorded ? "false" : "true")
        << ",\"recordedSigningState\":"
        << json_quote(app.signing == SigningState::not_recorded ? "not-recorded"
                                                                : signing_status(app.signing))
        << ",\"recordedCertificatesSha256\":";
    fingerprints(out, app.signer_certificates);
    out << ",\"publisherAuthenticated\":false},\"observedSignature\":";
    if (!observed_signature)
        out << "null";
    else {
        std::vector<std::string> certificates;
        for (const auto &signer : observed_signature->signers)
            certificates.push_back(signer.certificate_sha256);
        std::sort(certificates.begin(), certificates.end());
        out << "{\"status\":" << json_quote(observed_signature->status)
            << ",\"scheme\":" << json_quote(observed_signature->scheme) << ",\"certificatesSha256\":";
        fingerprints(out, certificates);
        out << '}';
    }
    out << ",\"checks\":[";
    for (std::size_t index = 0; index < checks.size(); ++index) {
        const auto &check = checks[index];
        out << (index ? "," : "") << "{\"name\":" << json_quote(check.name)
            << ",\"status\":" << json_quote(check.status) << ",\"code\":" << json_quote(check.code)
            << ",\"detail\":" << json_quote(check.detail) << '}';
    }
    out << "],\"excluded\":[\"host-paths\",\"private-app-files\",\"audit-logs\",\"environment\","
           "\"memory\"],\"notAssessed\":[\"runtime-readiness\",\"worker-isolation\","
           "\"Android-API-behavior\",\"Windows-UI-and-pins\"]}";
    return out.str();
}
std::string AppDiagnostics::text() const {
    std::ostringstream out;
    out << "App diagnostics: " << (passed() ? "no failed checks" : "attention required")
        << "\nApp ID: " << app.id << "\nPackage: " << json_quote(app.package_id)
        << "\nVersion: " << json_quote(app.version_name) << " (" << app.version_code << ")\n";
    for (const auto &check : checks)
        out << check.name << ": " << check.status << (check.code.empty() ? "" : " [" + check.code + "]")
            << " - " << check.detail << '\n';
    out << "Read-only inspection; no APK execution or private app data collected.\n"
           "Runtime readiness, worker isolation, Android behavior and Windows UI are not assessed.\n";
    return out.str();
}
void export_diagnostics(const AppDiagnostics &report, const std::filesystem::path &destination) {
    detail::export_report_json(report.json(), destination);
}
void detail::export_report_json(std::string_view json, const std::filesystem::path &destination,
                                std::size_t maximum_bytes) {
    const auto path = std::filesystem::absolute(destination).lexically_normal();
    const auto native = path.native();
    require(native.size() >= 4 && native[1] == L':' && (native[2] == L'\\' || native[2] == L'/') &&
                ((native[0] >= L'A' && native[0] <= L'Z') || (native[0] >= L'a' && native[0] <= L'z')) &&
                !path.filename().empty(),
            "AETHER_DIAGNOSTICS_OUTPUT", "Choose a new diagnostics file on a local drive");
    for (const auto &part : path.relative_path()) {
        const auto name = part.native();
        require(!name.empty() && name.back() != L'.' && name.back() != L' ' &&
                    name.find_first_of(L":<>\"|?*") == std::wstring::npos &&
                    std::none_of(name.begin(), name.end(), [](wchar_t c) { return c < 32; }),
                "AETHER_DIAGNOSTICS_OUTPUT", "Diagnostics output path contains an unsafe component");
    }
    const auto bytes = std::string(json) + '\n';
    require(maximum_bytes && maximum_bytes <= 256 * 1024 && bytes.size() <= maximum_bytes,
            "AETHER_DIAGNOSTICS_OUTPUT", "Diagnostics report exceeds its bound");
    host::UniqueHandle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!file) {
        const auto error = GetLastError();
        throw InstallError(error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS
                               ? "AETHER_DIAGNOSTICS_OUTPUT_EXISTS"
                               : "AETHER_DIAGNOSTICS_OUTPUT",
                           "Cannot create diagnostics output; choose a new file in an existing folder");
    }
    BY_HANDLE_FILE_INFORMATION info{};
    require(GetFileType(file.get()) == FILE_TYPE_DISK && GetFileInformationByHandle(file.get(), &info) &&
                !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
                info.nNumberOfLinks == 1 && info.nFileSizeHigh == 0 && info.nFileSizeLow == 0,
            "AETHER_DIAGNOSTICS_OUTPUT", "Diagnostics destination is not a new ordinary file");
    DWORD written = 0;
    require(WriteFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
                written == bytes.size() && FlushFileBuffers(file.get()),
            "AETHER_DIAGNOSTICS_OUTPUT",
            "Diagnostics export failed; inspect the possibly partial final file");
}
} // namespace aether::install
