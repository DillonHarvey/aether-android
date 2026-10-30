#pragma once
#include "aether/install/store.hpp"

namespace aether::install {
struct OpenLinkOptions {
    std::u16string uri;
    std::optional<std::string> app_id;
    std::filesystem::path store;
    bool json = false, verbose = false;
    bool registered_activation = false; // Trusted native route only; never a CLI option.
};
OpenLinkOptions parse_open_link_options(const std::vector<std::string> &arguments);
apk::IntentValue make_open_link_intent(std::u16string_view uri);
apk::ActivityIntentPolicy open_link_policy() noexcept;
// Check a still-current opt-in offer while the caller retains the store snapshot.
// No registration, repair or launch occurs here.
void require_registered_link_offer(const PackageStore &store, std::string_view app_id,
                                   std::u16string_view uri);

enum class LinkDisposition { candidate, no_match, unsupported, unavailable, ineligible };
struct LinkReviewRow {
    std::string app_id, display_name, package_id, apk_hash;
    std::string component_name, target_name;
    std::uint64_t package_generation = 0;
    std::uint32_t permissions = 0, target_sdk = 1;
    State state = State::removed;
    ShellState shell = ShellState::none;
    bool shell_verified = false;
    LinkDisposition disposition = LinkDisposition::unavailable;
    std::optional<std::size_t> declaration, target;
    std::string code; // Fixed diagnostic code, never raw URI/error text.
};
struct LinkReview {
    apk::IntentValue intent; // Original canonical request; no injected component.
    apk::ActivityIntentPolicy policy;
    std::optional<std::string> app_id;
    std::vector<LinkReviewRow> rows;
    std::size_t inspected = 0;
    bool complete = true; // False means some installed alternatives were unavailable.
};
} // namespace aether::install
