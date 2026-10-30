#pragma once
#include "aether/dex/runtime.hpp"

namespace aether::android {
struct ViewBounds {
    float x = 0, y = 0, width = 0, height = 0;
    bool contains(float px, float py) const noexcept {
        return px >= x && py >= y && px < x + width && py < y + height;
    }
    bool operator==(const ViewBounds &) const = default;
};
struct ViewPlacement {
    dex::ObjectId view;
    ViewBounds bounds;
};
enum class PointerAction : std::uint32_t { down = 0, up = 1, move = 2, cancel = 3 };
struct PointerInput {
    PointerAction action = PointerAction::move;
    std::uint32_t pointer = 0, source = 0x2002; // Android SOURCE_MOUSE; touchscreen is 0x1002.
    float x = 0, y = 0;                         // Activity-local density-independent coordinates.
};
enum class KeyCharacterStatus : std::uint32_t { none = 0, bmp = 1, unsupported = 2 };
inline constexpr std::uint32_t key_lock_meta_mask = 0x700000u;
inline constexpr std::uint32_t key_meta_mask = 0x711003u;
struct KeyInput {
    bool up = false;
    std::uint32_t code = 0, meta = 0, repeat = 0; // Android keycode and AMETA bits.
    KeyCharacterStatus character_status = KeyCharacterStatus::none;
    std::uint32_t unicode = 0; // One admitted UTF-16 unit; never a truncated sequence.
};
inline constexpr bool valid_key_input(const KeyInput &event) noexcept {
    if (event.code > 512 || event.repeat > 65535 || (event.meta & ~key_meta_mask)) return false;
    switch (event.character_status) {
    case KeyCharacterStatus::none:
    case KeyCharacterStatus::unsupported:
        return event.unicode == 0;
    case KeyCharacterStatus::bmp:
        if (event.meta & ~(key_lock_meta_mask | 1u)) return false;
        if (event.unicode == 9) return event.code == 61;
        if (event.unicode == 10) return event.code == 66 || event.code == 160;
        return event.code != 67 && event.code != 112 && event.unicode >= 0x20 && event.unicode <= 0xffff &&
               !(event.unicode >= 0x7f && event.unicode <= 0x9f) &&
               !(event.unicode >= 0xd800 && event.unicode <= 0xdfff);
    }
    return false;
}
} // namespace aether::android
