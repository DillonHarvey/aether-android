#include "aether/host/window.hpp"
#include <Windows.h>

namespace aether::host {
std::uint32_t android_keycode(std::uint32_t key) noexcept {
    if (key >= 'A' && key <= 'Z')
        return 29 + key - 'A';
    if (key >= '0' && key <= '9')
        return 7 + key - '0';
    if (key >= VK_NUMPAD0 && key <= VK_NUMPAD9)
        return 144 + key - VK_NUMPAD0;
    if (key >= VK_F1 && key <= VK_F12)
        return 131 + key - VK_F1;
    switch (key) {
    case VK_TAB:
        return 61;
    case VK_RETURN:
        return 66;
    case VK_SPACE:
        return 62;
    case VK_BACK:
        return 67;
    case VK_ESCAPE:
        return 111;
    case VK_DELETE:
        return 112;
    case VK_INSERT:
        return 124;
    case VK_UP:
        return 19;
    case VK_DOWN:
        return 20;
    case VK_LEFT:
        return 21;
    case VK_RIGHT:
        return 22;
    case VK_HOME:
        return 122;
    case VK_END:
        return 123;
    case VK_PRIOR:
        return 92;
    case VK_NEXT:
        return 93;
    case VK_SHIFT:
    case VK_LSHIFT:
        return 59;
    case VK_RSHIFT:
        return 60;
    case VK_MENU:
    case VK_LMENU:
        return 57;
    case VK_RMENU:
        return 58;
    case VK_CONTROL:
    case VK_LCONTROL:
        return 113;
    case VK_RCONTROL:
        return 114;
    case VK_LWIN:
        return 117;
    case VK_RWIN:
        return 118;
    case VK_CAPITAL:
        return 115;
    case VK_NUMLOCK:
        return 143;
    case VK_SCROLL:
        return 116;
    case VK_OEM_COMMA:
        return 55;
    case VK_OEM_PERIOD:
        return 56;
    case VK_OEM_1:
        return 74;
    case VK_OEM_2:
        return 76;
    case VK_OEM_3:
        return 68;
    case VK_OEM_4:
        return 71;
    case VK_OEM_5:
        return 73;
    case VK_OEM_6:
        return 72;
    case VK_OEM_7:
        return 75;
    case VK_OEM_PLUS:
        return 70;
    case VK_OEM_MINUS:
        return 69;
    case VK_ADD:
        return 157;
    case VK_SUBTRACT:
        return 156;
    case VK_MULTIPLY:
        return 155;
    case VK_DIVIDE:
        return 154;
    case VK_DECIMAL:
        return 158;
    default:
        return 0;
    }
}
std::uint32_t android_modifiers(bool shift, bool alt, bool control, bool meta) noexcept {
    return (shift ? 1u : 0u) | (alt ? 2u : 0u) | (control ? 0x1000u : 0u) | (meta ? 0x10000u : 0u);
}
android::PointerInput logical_pointer(android::PointerAction action, std::uint32_t pointer,
                                      std::uint32_t source, int x, int y, unsigned dpi) {
    if (dpi < 48 || dpi > 960 || x < -32768 || x > 32767 || y < -32768 || y > 32767)
        throw dex::DexError("AETHER_WINDOW_INPUT", "Client coordinates or DPI exceed the supported range");
    return {action, pointer, source, static_cast<float>(x) * 96.0f / static_cast<float>(dpi),
            static_cast<float>(y) * 96.0f / static_cast<float>(dpi)};
}
} // namespace aether::host
