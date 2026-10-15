#include "aether/common/text.hpp"
#include <Windows.h>
#include <limits>
#include <stdexcept>

namespace aether {
namespace {
int text_size(std::size_t size) {
    if (size > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        throw std::length_error("Text exceeds Windows conversion limit");
    }
    return static_cast<int>(size);
}
} // namespace

std::string utf8(std::wstring_view value) {
    if (value.empty())
        return {};
    const int size = text_size(value.size());
    const int required =
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), size, nullptr, 0, nullptr, nullptr);
    if (required == 0)
        throw std::invalid_argument("Invalid UTF-16 text");
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), size, result.data(), required,
                            nullptr, nullptr) != required)
        throw std::runtime_error("UTF-8 conversion failed");
    return result;
}

std::wstring utf16(std::string_view value) {
    if (value.empty())
        return {};
    const int size = text_size(value.size());
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), size, nullptr, 0);
    if (required == 0)
        throw std::invalid_argument("Invalid UTF-8 text");
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), size, result.data(), required) !=
        required)
        throw std::runtime_error("UTF-16 conversion failed");
    return result;
}

std::string json_quote(std::string_view value) {
    (void)utf16(value);
    constexpr char hex[] = "0123456789abcdef";
    std::string result = "\"";
    for (const char character : value) {
        const auto c = static_cast<unsigned char>(character);
        if (c == '"' || c == '\\') {
            result += '\\';
            result += character;
        } else if (c < 0x20) {
            result += "\\u00";
            result += hex[c >> 4];
            result += hex[c & 15];
        } else {
            result += character;
        }
    }
    result += '"';
    return result;
}
} // namespace aether
