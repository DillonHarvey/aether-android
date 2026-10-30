#include "aether/install/open_link.hpp"
#include "aether/install/link_registration.hpp"
#include "aether/common/text.hpp"
#include "aether/common/uri.hpp"
#include <algorithm>
#include <set>

namespace aether::install {
namespace {
[[noreturn]] void usage(std::string_view message) {
    throw InstallError("AETHER_CLI_USAGE", std::string(message));
}
[[noreturn]] void invalid(std::string_view message) {
    throw InstallError("AETHER_OPEN_LINK_INVALID", std::string(message));
}
[[noreturn]] void unsupported(std::string_view message) {
    throw InstallError("AETHER_OPEN_LINK_UNSUPPORTED", std::string(message));
}
bool letter(char16_t unit) noexcept {
    return (unit >= u'A' && unit <= u'Z') || (unit >= u'a' && unit <= u'z');
}
bool digit(char16_t unit) noexcept { return unit >= u'0' && unit <= u'9'; }
bool hexadecimal(char16_t unit) noexcept {
    return digit(unit) || (unit >= u'A' && unit <= u'F') || (unit >= u'a' && unit <= u'f');
}
bool same_scheme(std::u16string_view value, std::u16string_view wanted) noexcept {
    if (value.size() != wanted.size()) return false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        const auto unit = value[index] >= u'A' && value[index] <= u'Z' ?
            static_cast<char16_t>(value[index] + (u'a' - u'A')) : value[index];
        if (unit != wanted[index]) return false;
    }
    return true;
}
bool forbidden(char16_t unit) noexcept {
    return unit <= u' ' || (unit >= u'\u007f' && unit <= u'\u009f') || unit == u'\\';
}
bool unreserved(char16_t unit) noexcept {
    return letter(unit) || digit(unit) || unit == u'-' || unit == u'.' || unit == u'_' || unit == u'~';
}
bool sub_delimiter(char16_t unit) noexcept {
    return std::u16string_view(u"!$&'()*+,;=").find(unit) != std::u16string_view::npos;
}
void port(std::u16string_view value) {
    if (value.empty()) invalid("HTTP link authority has an empty port");
    std::uint32_t number = 0;
    for (const auto unit : value) {
        if (!digit(unit)) invalid("HTTP link port must contain only ASCII decimal digits");
        const auto next = static_cast<std::uint32_t>(unit - u'0');
        if (number > (65535u - next) / 10u) invalid("HTTP link port exceeds the supported endpoint range");
        number = number * 10u + next;
    }
}
bool ipv4_tail(std::u16string_view value) noexcept {
    std::size_t first = 0;
    for (unsigned count = 0; count < 4; ++count) {
        const auto separator = value.find(u'.', first);
        if ((separator == value.npos) != (count == 3)) return false;
        const auto part = value.substr(first, separator == value.npos ? value.size() - first : separator - first);
        if (part.empty() || part.size() > 3 || (part.size() > 1 && part.front() == u'0')) return false;
        unsigned number = 0;
        for (const auto unit : part) {
            if (!digit(unit)) return false;
            number = number * 10u + static_cast<unsigned>(unit - u'0');
        }
        if (number > 255) return false;
        first = separator == value.npos ? value.size() : separator + 1;
    }
    return true;
}
bool ipv6(std::u16string_view value) noexcept {
    std::size_t at = 0;
    unsigned groups = 0;
    bool compressed = false;
    if (value.starts_with(u"::")) { compressed = true; at = 2; }
    else if (value.empty() || value.front() == u':') return false;
    while (at < value.size()) {
        const auto end = value.find(u':', at);
        const auto part = value.substr(at, end == value.npos ? value.size() - at : end - at);
        if (part.empty()) return false;
        if (part.find(u'.') != part.npos) {
            if (end != value.npos || !ipv4_tail(part)) return false;
            groups += 2;
        } else {
            if (part.size() > 4 || !std::all_of(part.begin(), part.end(), hexadecimal)) return false;
            ++groups;
        }
        if (groups > 8) return false;
        if (end == value.npos) break;
        at = end + 1;
        if (at < value.size() && value[at] == u':') {
            if (compressed) return false;
            compressed = true;
            ++at;
        } else if (at == value.size()) return false;
    }
    return compressed ? groups < 8 : groups == 8;
}
bool ip_literal(std::u16string_view value) noexcept {
    if (value.size() > 2 && (value.front() == u'v' || value.front() == u'V')) {
        const auto dot = value.find(u'.');
        if (dot == value.npos || dot == 1 || dot + 1 == value.size() ||
            !std::all_of(value.begin() + 1, value.begin() + dot, hexadecimal)) return false;
        return std::all_of(value.begin() + dot + 1, value.end(), [](char16_t unit) {
            return unreserved(unit) || sub_delimiter(unit) || unit == u':';
        });
    }
    return ipv6(value);
}
void http_authority(std::u16string_view value) {
    if (value.empty()) invalid("HTTP links require a nonempty authority");
    if (value.find(u'@') != value.npos)
        unsupported("HTTP link user information is outside the public open-link profile");
    std::u16string_view host;
    if (value.front() == u'[') {
        const auto close = value.find(u']');
        if (close == value.npos || !ip_literal(value.substr(1, close - 1)))
            invalid("HTTP link authority has an invalid IP literal");
        host = value.substr(0, close + 1);
        const auto tail = value.substr(close + 1);
        if (!tail.empty()) {
            if (tail.front() != u':') invalid("HTTP link authority has text after its IP literal");
            port(tail.substr(1));
        }
    } else {
        const auto separator = value.find(u':');
        host = value.substr(0, separator);
        if (separator != value.npos) port(value.substr(separator + 1));
        for (std::size_t index = 0; index < host.size(); ++index) {
            const auto unit = host[index];
            if (unit == u'%') {
                if (host.size() - index < 3 || !hexadecimal(host[index + 1]) || !hexadecimal(host[index + 2]))
                    invalid("HTTP link host has an invalid percent escape");
                index += 2;
            } else if (unit < 128 && !unreserved(unit) && !sub_delimiter(unit))
                invalid("HTTP link authority has an invalid registered host character");
        }
    }
    const auto decoded = uri::decode(host);
    if (decoded.empty() || std::any_of(decoded.begin(), decoded.end(), [](char16_t unit) {
            return forbidden(unit) || unit == u'/' || unit == u'?' || unit == u'#' || unit == u'@';
        })) invalid("HTTP links require a nonempty decoded host without authority delimiters");
}
std::u16string unicode(std::string_view value) {
    try {
        const auto wide = utf16(value);
        return {wide.begin(), wide.end()};
    } catch (const std::invalid_argument &) { usage("open-link options require valid UTF-8 text"); }
}
} // namespace

OpenLinkOptions parse_open_link_options(const std::vector<std::string> &arguments) {
    OpenLinkOptions result;
    std::set<std::string_view> seen;
    bool command = false, has_uri = false;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        const auto &argument = arguments[index];
        if (argument == "--json" || argument == "--verbose") {
            if (!seen.emplace(argument).second) usage("An open-link option was specified more than once");
            (argument == "--json" ? result.json : result.verbose) = true;
            continue;
        }
        if (!command) {
            if (argument != "open-link") usage("Use open-link --uri VALUE with optional --app-id and --store");
            command = true;
            continue;
        }
        if (argument != "--uri" && argument != "--app-id" && argument != "--store")
            usage("Unknown open-link option; positional arguments, grants, flags, extras and selectors are unsupported");
        if (!seen.emplace(argument).second) usage("An open-link option was specified more than once");
        if (index + 1 == arguments.size() || arguments[index + 1].empty() || arguments[index + 1].starts_with('-'))
            usage("The open-link option requires a nonempty value");
        const auto &value = arguments[++index];
        if (argument == "--uri") { result.uri = unicode(value); has_uri = true; }
        else if (argument == "--app-id") {
            if (!valid_app_id(value))
                throw InstallError("AETHER_INSTALL_ID", "App ID must be exactly 32 lowercase hexadecimal characters");
            result.app_id = value;
        } else {
            const auto wide = unicode(value);
            if (wide.find(u'\0') != wide.npos) usage("--store requires an absolute local path without null characters");
            result.store = std::filesystem::path(std::wstring(wide.begin(), wide.end()));
            if (!result.store.is_absolute()) usage("--store requires an absolute local path");
        }
    }
    if (!command || !has_uri) usage("Use open-link --uri VALUE with optional --app-id and --store");
    if (result.store.empty()) result.store = default_store_root();
    // Parsing performs no store access, registration, repair or launch.
    (void)make_open_link_intent(result.uri);
    return result;
}
apk::IntentValue make_open_link_intent(std::u16string_view raw) {
    if (raw.empty()) invalid("open-link requires a nonempty absolute URI");
    if (raw.size() > uri::text_units)
        throw InstallError("AETHER_OPEN_LINK_LIMIT", "open-link URI exceeds 4096 UTF-16 units");
    if (std::any_of(raw.begin(), raw.end(), forbidden))
        invalid("open-link URI contains a control character, raw ASCII space or backslash");
    const auto colon = raw.find(u':');
    if (colon == raw.npos || colon == 0 || !letter(raw.front()))
        invalid("open-link requires an absolute URI with an RFC scheme");
    for (const auto unit : raw.substr(1, colon - 1))
        if (!letter(unit) && !digit(unit) && unit != u'+' && unit != u'-' && unit != u'.')
            invalid("open-link URI scheme contains an invalid character");
    const auto scheme = raw.substr(0, colon);
    if (same_scheme(scheme, u"file") || same_scheme(scheme, u"content") || same_scheme(scheme, u"intent") ||
        same_scheme(scheme, u"android.resource"))
        unsupported("This URI scheme requires unavailable file, provider, grant or Intent-URI semantics");
    if (same_scheme(scheme, u"http") || same_scheme(scheme, u"https")) {
        const uri::Parsed parsed(raw);
        const auto authority = parsed.authority();
        if (!authority) invalid("HTTP links require a hierarchical URI with a double-slash authority");
        http_authority(raw.substr(authority->first, authority->last - authority->first));
    }
    // This public producer deliberately admits absolute custom opaque and
    // hierarchical schemes. It does not narrow general Android Uri values or
    // invoke a Windows URL parser, ShellExecute, content provider or grant API.
    apk::IntentValue value;
    value.action = u"android.intent.action.VIEW";
    value.data = std::u16string(raw); // Preserve the exact admitted value.
    value.categories = std::vector<std::optional<std::u16string>>{u"android.intent.category.BROWSABLE"};
    value.flags = 0x10000000u; // NEW_TASK is the only supported fresh-root launch flag.
    value.default_only = true; // Query policy; DEFAULT is not added to actual categories.
    apk::canonicalize_intent_categories(value);
    value.validate();
    return value;
}
apk::ActivityIntentPolicy open_link_policy() noexcept {
    // Explicit Aether Android15 public-link profile, not caller-controlled flags
    // or a claim of Android domain/default/preference selection or URI grants.
    apk::ActivityIntentPolicy policy;
    policy.filters.relative_reference_groups = true;
    policy.enforce_explicit_filters = true;
    policy.block_null_action = true;
    return policy;
}
void require_registered_link_offer(const PackageStore &store, std::string_view app_id,
                                   std::u16string_view raw) {
    (void)make_open_link_intent(raw);
    std::string scheme;
    for (const auto unit : raw.substr(0, raw.find(u':')))
        scheme.push_back(static_cast<char>(unit >= u'A' && unit <= u'Z' ? unit - u'A' + u'a' : unit));
    const auto apps = store.list();
    const auto found = std::find_if(apps.begin(), apps.end(), [&](const auto &app) { return app.id == app_id; });
    if (found == apps.end())
        throw InstallError("AETHER_LINK_NOT_REGISTERED", "The selected app is no longer registered");
    const auto offer = link_registration(LinkRegistrationOperation::status, *found, store.root());
    if (!offer.verified || std::find(offer.schemes.begin(), offer.schemes.end(), scheme) == offer.schemes.end())
        throw InstallError("AETHER_LINK_NOT_REGISTERED", "This app has no current verified offer for the link scheme");
}
} // namespace aether::install
