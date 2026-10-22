#pragma once
#include <Windows.h>

namespace aether::install {
// Hide the owner until Back/close, retaining drafts and pumping its automatic reads.
void show_privacy_dialog(HWND owner = nullptr);
} // namespace aether::install
