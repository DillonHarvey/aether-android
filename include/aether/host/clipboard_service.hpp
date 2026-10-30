#pragma once
#include "aether/host/drop_text.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace aether::host {
inline constexpr std::size_t clipboard_text_limit = 4096;
enum class ClipboardStatus : std::uint64_t { ok, denied, unsupported, invalid, quota, unavailable };
// Separate persisted clipboard authority. Dropped text and document URIs never
// supply it. Only bounded plain Unicode text is supported by this interface.
class ClipboardService {
  public:
    virtual ~ClipboardService() = default;
    // Trusted native admission only; no HWND or binding epoch crosses guest IPC.
    // A successful check arms this exact tenure for the following native call.
    // Native methods must not silently reauthorize a later focus-loss/regain
    // tenure between this check and the actual clipboard access.
    virtual ClipboardStatus check_access(std::uint64_t &epoch) noexcept {
        epoch = 0;
        return ClipboardStatus::denied;
    }
    virtual ClipboardStatus has_text(bool &value) noexcept = 0;
    virtual ClipboardStatus read_text(std::optional<std::u16string> &value) noexcept = 0;
    virtual ClipboardStatus write_text(std::u16string_view value) noexcept = 0;
    virtual ClipboardStatus clear() noexcept = 0;
};
} // namespace aether::host
