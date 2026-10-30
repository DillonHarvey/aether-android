#pragma once
#include "aether/apk/intent_value.hpp"
#include "aether/host/document_service.hpp"
#include "aether/security/protocol.hpp"

namespace aether::security {
inline constexpr std::size_t activity_launch_limit = apk::manifest_activity_bytes;
inline constexpr std::uint64_t activity_launch_schema = 3;
inline constexpr std::uint64_t installed_intent_scenario = 33;
// Immutable when retained by InstalledActivity. Request component/package stay
// original; delivered_intent names the independently selected manifest alias.
// All fields are values, never host paths, provider authority, handles or executable names.
struct ActivityLaunch {
    std::string apk_hash;
    std::u16string package, component_name, target_name;
    std::size_t declaration = 0, target = 0;
    bool user_selected = false; // Explicit chooser decision; worker checks original match membership.
    apk::IntentValue intent;
    apk::ActivityIntentPolicy policy;
    // Describes the separately approved host service; decoding cannot create it.
    std::optional<host::DocumentInfo> read_document;
    void validate() const;
    void validate_against(const apk::ManifestInfo &manifest, std::string_view hash) const;
    apk::IntentValue delivered_intent() const;
    std::vector<std::uint8_t> encode() const;
    static ActivityLaunch decode(std::span<const std::uint8_t> bytes);
};
// Only after normal held-package admission/consent. Failure never falls back
// to MAIN. Current fresh-root delivery supports no task/grant flag except
// NEW_TASK. The separate approved-file join may add READ_URI_PERMISSION only
// with exact document metadata; ordinary resolution cannot create that grant.
ActivityLaunch resolve_activity_launch(const apk::ManifestInfo &manifest, std::string_view hash,
                                       apk::IntentValue intent, const apk::ActivityIntentPolicy &policy,
                                       std::optional<std::size_t> chosen_declaration = {});
} // namespace aether::security
