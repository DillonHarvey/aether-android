#pragma once
#include <Windows.h>
#include <string_view>

namespace aether::shell {
// Does no extraction, IPC wait or process startup on the caller's thread.
void queue_icon_read(HMODULE module, std::wstring_view path) noexcept;
bool icon_reads_pending() noexcept;
} // namespace aether::shell
