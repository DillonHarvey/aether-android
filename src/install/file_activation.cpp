#include "aether/install/file_activation.hpp"
#include "aether/install/store.hpp"
#include <algorithm>
#include <cstddef>

namespace aether::install {
namespace {
bool padding(char16_t unit) noexcept { return unit == u' ' || unit == u'\t'; }
[[noreturn]] void invalid() {
    throw InstallError("AETHER_FILE_ACTIVATION_INPUT",
        "File activation requires its fixed app identity and one quoted absolute local file path");
}
} // namespace
std::optional<FileActivation> parse_file_activation(std::u16string_view raw_tail) {
    auto tail = raw_tail;
    while (!tail.empty() && padding(tail.front())) tail.remove_prefix(1);
    constexpr std::u16string_view command = u"file-activation";
    if (tail.substr(0, tail.find_first_of(u" \t")) != command) return {};
    // The existing held-document provider supports canonical DOS paths below
    // MAX_PATH. Bound the whole recognized command before allocating strings.
    if (raw_tail.size() > 260 + 256) invalid();
    auto at = command.size();
    if (at == tail.size() || tail[at++] != u' ') invalid();
    if (tail.size() - at < 32) invalid();
    const auto id = tail.substr(at, 32);
    if (!std::all_of(id.begin(), id.end(), [](char16_t unit) {
        return (unit >= u'0' && unit <= u'9') || (unit >= u'a' && unit <= u'f');
    })) invalid();
    at += 32;
    if (at == tail.size() || tail[at++] != u' ' || at == tail.size() || tail[at++] != u'"') invalid();
    const auto end = tail.find(u'"', at);
    if (end == tail.npos || !std::all_of(tail.begin() + static_cast<std::ptrdiff_t>(end + 1), tail.end(), padding))
        invalid();
    const auto path = tail.substr(at, end - at);
    if (path.size() < 4 || path.size() >= 260 ||
        !((path[0] >= u'A' && path[0] <= u'Z') || (path[0] >= u'a' && path[0] <= u'z')) ||
        path[1] != u':' || path[2] != u'\\') invalid();
    for (std::size_t index = 0; index < path.size(); ++index) {
        const auto unit = path[index];
        if (unit < 32 || unit == 127 || (unit == u':' && index != 1) || unit == u'/') invalid();
        if (unit >= 0xd800 && unit <= 0xdbff) {
            if (++index == path.size() || path[index] < 0xdc00 || path[index] > 0xdfff) invalid();
        } else if (unit >= 0xdc00 && unit <= 0xdfff) invalid();
    }
    FileActivation result;
    result.app_id.reserve(32);
    for (const auto unit : id) result.app_id.push_back(static_cast<char>(unit));
    // Backslashes are literal Windows filename data, never argv escape syntax.
    // Provider validation subsequently rejects reparses, ADS, nonlocal drives,
    // noncanonical components and anything outside its unchanged file profile.
    result.file = std::filesystem::path(std::wstring(path.begin(), path.end()));
    return result;
}
} // namespace aether::install
