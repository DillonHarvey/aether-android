#include "aether/install/link_activation.hpp"
#include "aether/install/open_link.hpp"
#include "aether/common/uri.hpp"
#include <algorithm>

namespace aether::install {
namespace {
bool padding(char16_t unit) noexcept { return unit == u' ' || unit == u'\t'; }
[[noreturn]] void usage() {
    throw InstallError("AETHER_LINK_ACTIVATION_USAGE",
                       "Link activation requires its fixed application identity and one unambiguous quoted URI");
}
[[noreturn]] void input() {
    throw InstallError("AETHER_LINK_ACTIVATION_INPUT",
                       "Link activation input is outside the supported URI profile");
}
} // namespace

std::optional<LinkActivation> parse_link_activation(std::u16string_view raw_tail) {
    auto tail = raw_tail;
    while (!tail.empty() && padding(tail.front())) tail.remove_prefix(1);
    constexpr std::u16string_view command = u"link-activation";
    const auto boundary = tail.find_first_of(u" \t");
    if (tail.substr(0, boundary) != command) return {};
    // Bound recognized activation input before any owned string allocation.
    // The allowance covers the fixed command/ID/quotes and limited padding.
    if (raw_tail.size() > uri::text_units + 256) input();
    auto at = command.size();
    if (at == tail.size() || tail[at++] != u' ') usage();
    constexpr std::size_t identity_units = 32;
    if (tail.size() - at < identity_units) usage();
    const auto identity = tail.substr(at, identity_units);
    if (!std::all_of(identity.begin(), identity.end(), [](char16_t unit) {
            return (unit >= u'0' && unit <= u'9') || (unit >= u'a' && unit <= u'f');
        })) usage();
    at += identity_units;
    if (at == tail.size() || tail[at++] != u' ') usage();
    if (at == tail.size() || tail[at++] != u'"') usage();
    const auto end = tail.find(u'"', at);
    if (end == tail.npos) usage();
    const auto value = tail.substr(at, end - at);
    const auto trailing = tail.substr(end + 1);
    if (!std::all_of(trailing.begin(), trailing.end(), padding)) usage();
    // No quote escaping, argv reconstruction, trimming or option parsing.
    // The ordinary producer supplies the existing URI checks and refusals.
    if (value.size() > uri::text_units) input();
    try { (void)make_open_link_intent(value); }
    catch (const InstallError &) { input(); }
    LinkActivation result;
    result.app_id.reserve(identity_units);
    for (const auto unit : identity) result.app_id.push_back(static_cast<char>(unit));
    result.uri = value;
    return result;
}
} // namespace aether::install
