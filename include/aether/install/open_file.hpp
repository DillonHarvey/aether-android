#pragma once
#include "aether/host/windows/document_service.hpp"
#include "aether/install/open_link.hpp"

namespace aether::install {
struct OpenFileOptions {
    std::filesystem::path file;
    std::string mime_type;
    std::optional<std::string> app_id;
    std::filesystem::path store;
    bool json = false, verbose = false;
    bool registered_activation = false; // Trusted native route, never a CLI flag.
};
// Parsing never opens a document, grants access, registers a handler or launches.
OpenFileOptions parse_open_file_options(const std::vector<std::string> &arguments);
// Read-only matching request only. prepare_file adds authority after explicit
// recipient/document approval, independently of app-private-file permission.
apk::IntentValue make_open_file_intent(const host::DocumentInfo &document);
apk::ActivityIntentPolicy open_file_policy() noexcept;
// Resolve only a verified current opt-in extension/MIME pair for this app.
// The caller keeps its store snapshot; no source file is opened here.
std::string registered_file_mime(const PackageStore &store, std::string_view app_id,
                                 const std::filesystem::path &file);
void require_registered_file_offer(const PackageStore &store, std::string_view app_id,
                                   const std::filesystem::path &file, std::string_view mime_type);
} // namespace aether::install
