#pragma once
#include <Windows.h>

namespace aether::install {
// The owned modal view pumps messages so its parent's automatic reads continue.
void show_privacy_dialog(HWND owner = nullptr);
} // namespace aether::install
