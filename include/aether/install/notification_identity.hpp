#pragma once
#include "aether/security/installed_activity.hpp"
#include "aether/host/notification_service.hpp"
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
namespace aether::install {
// Stable, domain-separated bijection of all 128 opaque installed-ID bits.
// Do not overwrite GUID version/variant bits or truncate the installed ID.
inline std::wstring notification_clsid(std::string_view id) {
    if (!security::valid_installed_id(id))
        throw std::invalid_argument("Invalid installed notification identity");
    constexpr std::string_view domain = "7a6e4b15082c48d293af16e954bc0d71";
    constexpr wchar_t hex[] = L"0123456789abcdef";
    const auto digit = [](char c) { return static_cast<unsigned>(c <= '9' ? c - '0' : c - 'a' + 10); };
    std::wstring value = L"{";
    bool nonzero = false;
    for (std::size_t index = 0; index < id.size(); ++index) {
        if (index == 8 || index == 12 || index == 16 || index == 20) value += L'-';
        const auto nibble = digit(id[index]) ^ digit(domain[index]);
        value += hex[nibble]; nonzero = nonzero || nibble != 0;
    }
    if (!nonzero)
        throw std::invalid_argument("Installed notification identity maps to a reserved CLSID");
    value += L'}';
    return value;
}
inline std::wstring notification_arguments(std::int32_t id) {
    return host::notification_activation_arguments(id);
}
} // namespace aether::install
