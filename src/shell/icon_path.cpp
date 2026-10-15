#include "aether/shell/icons.hpp"
#include <algorithm>
#include <cwctype>

namespace aether::shell {
namespace {
bool equal(std::wstring_view a, std::wstring_view b) noexcept {
    return a.size() == b.size() && CompareStringOrdinal(a.data(), static_cast<int>(a.size()), b.data(),
                                                        static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}
} // namespace
bool bundle_path(std::wstring_view path) noexcept {
    return path.size() >= 4 && equal(path.substr(path.size() - 4), L".aab");
}
std::wstring icon_input_path(std::wstring_view input) {
    if (input.size() > 32760 || input.empty())
        return {};
    if (input.starts_with(L"\\\\?\\"))
        input.remove_prefix(4);
    if (input.size() > 32756) // Leave room for the canonical extended-length prefix.
        return {};
    if (input.size() < 4 ||
        !((input[0] >= L'A' && input[0] <= L'Z') || (input[0] >= L'a' && input[0] <= L'z')) ||
        input[1] != L':' || input[2] != L'\\')
        return {};
    std::wstring result = L"\\\\?\\";
    result.append(input.substr(0, 3));
    for (std::size_t start = 3; start < input.size();) {
        const auto end = input.find(L'\\', start);
        const auto part = input.substr(start, end == input.npos ? end : end - start);
        if (part.empty() || part == L"." || part == L".." || part.size() > 255 || part.back() == L'.' ||
            part.back() == L' ' || part.find_first_of(L"/:*?\"<>|") != part.npos ||
            std::any_of(part.begin(), part.end(), [](wchar_t c) { return c < 32; }))
            return {};
        // No unpaired UTF-16 surrogates, including in directory names.
        for (std::size_t i = 0; i < part.size(); ++i) {
            const auto c = static_cast<unsigned>(part[i]);
            if (c >= 0xd800 && c <= 0xdbff) {
                if (++i == part.size() || part[i] < 0xdc00 || part[i] > 0xdfff)
                    return {};
            } else if (c >= 0xdc00 && c <= 0xdfff)
                return {};
        }
        result.append(part);
        if (end == input.npos)
            break;
        result.push_back(L'\\');
        start = end + 1;
    }
    const auto dot = result.find_last_of(L'.');
    const auto suffix = dot == result.npos ? std::wstring_view{} : std::wstring_view(result).substr(dot);
    if (!equal(suffix, L".apk") && !equal(suffix, L".xapk") && !equal(suffix, L".apks") &&
        !equal(suffix, L".apkm") && !equal(suffix, L".aab"))
        return {};
    return result;
}
} // namespace aether::shell
