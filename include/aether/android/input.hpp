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
struct KeyInput {
    bool up = false;
    std::uint32_t code = 0, meta = 0, repeat = 0; // Android keycode and AMETA bits.
};
} // namespace aether::android
