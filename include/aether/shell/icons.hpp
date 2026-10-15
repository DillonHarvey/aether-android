#pragma once
#include <Windows.h>
#include <string>
#include <string_view>

namespace aether::shell {
// Stable identity shared by the x64 COM server, installer and independent tests.
inline constexpr CLSID icon_handler_clsid{
    0xacee5212, 0x4797, 0x4dcd, {0x81, 0xc2, 0x95, 0xc1, 0x57, 0x41, 0xd2, 0xfd}};
inline constexpr wchar_t icon_handler_id[] = L"{ACEE5212-4797-4DCD-81C2-95C15741D2FD}";
inline constexpr int package_icon_resource = 101, bundle_icon_resource = 102;
inline constexpr unsigned icon_cache_version = 2;
// Decoder policy revision in the source key; record/ICO layouts stay unchanged.
// A new revision requeues both older fallbacks and successful container artwork.
inline constexpr unsigned icon_content_version = 3;
// Syntactic validation only: never opens a package, directory, device or network path.
// Returns an absolute extended-length local path, or an empty string.
std::wstring icon_input_path(std::wstring_view input);
bool bundle_path(std::wstring_view path) noexcept;
} // namespace aether::shell
