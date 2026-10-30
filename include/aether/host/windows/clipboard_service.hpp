#pragma once
#include "aether/host/clipboard_service.hpp"
#include <Windows.h>
#include <memory>

namespace aether::host {
// Construct on the Activity UI owner before its I/O thread starts. Binding is
// UI-only; retirement is a cross-thread-safe host cancellation operation.
class ClipboardWindowContext final {
  public:
    ClipboardWindowContext();
    ~ClipboardWindowContext();
    ClipboardWindowContext(const ClipboardWindowContext &) = delete;
    ClipboardWindowContext &operator=(const ClipboardWindowContext &) = delete;
    void bind(HWND window) noexcept;
    void retire() noexcept;
    void close() noexcept; // Permanent terminal retirement; future binds remain denied.
    ClipboardStatus check_access(std::uint64_t &epoch) const noexcept;
  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    ClipboardStatus snapshot(HWND &window, std::uint64_t &epoch) const noexcept;
    friend class HostClipboardService;
};
// One installed broker's I/O owner. A preceding explicit check_access arms one
// operation in that exact foreground tenure; operations never reauthorize it.
class HostClipboardService final : public ClipboardService {
  public:
    explicit HostClipboardService(std::shared_ptr<ClipboardWindowContext> context);
    ClipboardStatus check_access(std::uint64_t &epoch) noexcept override;
    ClipboardStatus has_text(bool &value) noexcept override;
    ClipboardStatus read_text(std::optional<std::u16string> &value) noexcept override;
    ClipboardStatus write_text(std::u16string_view value) noexcept override;
    ClipboardStatus clear() noexcept override;
  private:
    const std::shared_ptr<ClipboardWindowContext> context_;
    const DWORD owner_ = GetCurrentThreadId();
    HWND armed_window_ = nullptr;
    std::uint64_t armed_epoch_ = 0;
    ClipboardStatus consume(HWND &window, std::uint64_t &epoch) noexcept;
    bool current(HWND window, std::uint64_t epoch) const noexcept;
};
} // namespace aether::host
