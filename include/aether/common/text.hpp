#pragma once
#include <string>
#include <string_view>

namespace aether {
std::string utf8(std::wstring_view value);
std::wstring utf16(std::string_view value);
// JSON strings are UTF-8. Invalid input is rejected, never emitted as invalid JSON.
std::string json_quote(std::string_view value);
} // namespace aether
