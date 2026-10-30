#include "aether/install/open_file.hpp"
#include "aether/common/text.hpp"
#include "aether/install/link_registration.hpp"
#include <algorithm>
#include <set>
#include <stdexcept>

namespace aether::install {
namespace {
[[noreturn]] void usage(const char *message) {
    throw InstallError("AETHER_CLI_USAGE", message);
}
std::wstring unicode(std::string_view value) {
    try {
        auto result = utf16(value);
        if (result.find(L'\0') != result.npos) usage("File options cannot contain null characters");
        return result;
    } catch (const std::invalid_argument &) {
        usage("File options require valid UTF-8 text");
    }
}
std::u16string units(std::string_view value) {
    const auto wide = utf16(value);
    return {wide.begin(), wide.end()};
}
std::string extension(const std::filesystem::path &file) {
    const auto raw = file.extension().native();
    std::string result;
    if (raw.size() < 2 || raw.size() > 16 || raw.front() != L'.')
        throw InstallError("AETHER_FILE_NOT_REGISTERED", "The selected document has no supported extension offer");
    for (auto unit : raw) {
        if (unit >= L'A' && unit <= L'Z') unit = static_cast<wchar_t>(unit + (L'a' - L'A'));
        if (unit > 127)
            throw InstallError("AETHER_FILE_NOT_REGISTERED", "The document extension has no canonical offer");
        result.push_back(static_cast<char>(unit));
    }
    return result;
}
} // namespace
OpenFileOptions parse_open_file_options(const std::vector<std::string> &arguments) {
    OpenFileOptions result;
    std::set<std::string_view> seen;
    bool command = false, has_file = false, has_mime = false;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        const auto &argument = arguments[index];
        if (argument == "--json" || argument == "--verbose") {
            if (!seen.emplace(argument).second) usage("A file option was specified more than once");
            (argument == "--json" ? result.json : result.verbose) = true;
            continue;
        }
        if (!command) {
            if (argument != "open-file") usage("Use open-file --file PATH --mime TYPE with optional --app-id and --store");
            command = true;
            continue;
        }
        if (argument != "--file" && argument != "--mime" && argument != "--app-id" && argument != "--store")
            usage("Unknown file option; positional arguments, grants, flags and selectors are unsupported");
        if (!seen.emplace(argument).second) usage("A file option was specified more than once");
        if (index + 1 == arguments.size() || arguments[index + 1].empty() || arguments[index + 1].starts_with('-'))
            usage("The file option requires a nonempty value");
        const auto &value = arguments[++index];
        const auto wide = unicode(value);
        if (argument == "--file") {
            result.file = std::filesystem::path(wide);
            if (!result.file.is_absolute()) usage("--file requires an absolute local file path");
            has_file = true;
        } else if (argument == "--mime") {
            if (!host::valid_document_mime(value)) usage("--mime requires a canonical lowercase concrete MIME type");
            result.mime_type = value;
            has_mime = true;
        } else if (argument == "--app-id") {
            if (!valid_app_id(value))
                throw InstallError("AETHER_INSTALL_ID", "App ID must be exactly 32 lowercase hexadecimal characters");
            result.app_id = value;
        } else {
            result.store = std::filesystem::path(wide);
            if (!result.store.is_absolute()) usage("--store requires an absolute local path");
        }
    }
    if (!command || !has_file || !has_mime)
        usage("Use open-file --file PATH --mime TYPE with optional --app-id and --store");
    if (result.store.empty()) result.store = default_store_root();
    return result;
}
apk::IntentValue make_open_file_intent(const host::DocumentInfo &document) {
    if (!host::valid_document_info(document))
        throw InstallError("AETHER_OPEN_FILE_INPUT", "The selected document metadata is outside the supported profile");
    apk::IntentValue result;
    result.action = u"android.intent.action.VIEW";
    result.data = units(document.uri);
    result.mime_type = units(document.mime_type);
    result.resolved_mime_type = result.mime_type;
    result.mime_state = apk::IntentMimeState::resolved;
    result.flags = 0x10000000u; // Matching is not a read grant.
    result.default_only = true;
    result.validate();
    return result;
}
apk::ActivityIntentPolicy open_file_policy() noexcept { return open_link_policy(); }
std::string registered_file_mime(const PackageStore &store, std::string_view app_id,
                                 const std::filesystem::path &file) {
    const auto suffix = extension(file);
    const auto apps = store.list();
    const auto selected = std::find_if(apps.begin(), apps.end(), [&](const auto &app) { return app.id == app_id; });
    if (selected == apps.end() || !installed_state(selected->state))
        throw InstallError("AETHER_FILE_NOT_REGISTERED", "The selected app is no longer installed");
    const auto offer = link_registration(LinkRegistrationOperation::status, *selected, store.root());
    const auto found = std::find_if(offer.files.begin(), offer.files.end(), [&](const auto &item) {
        return item.extension == suffix;
    });
    if (!offer.verified || found == offer.files.end() || !host::valid_document_mime(found->mime_type))
        throw InstallError("AETHER_FILE_NOT_REGISTERED", "This app has no current verified offer for the document extension");
    return found->mime_type;
}
void require_registered_file_offer(const PackageStore &store, std::string_view app_id,
                                   const std::filesystem::path &file, std::string_view mime_type) {
    if (registered_file_mime(store, app_id, file) != mime_type)
        throw InstallError("AETHER_FILE_NOT_REGISTERED", "The registered document MIME choice changed after review");
}
} // namespace aether::install
