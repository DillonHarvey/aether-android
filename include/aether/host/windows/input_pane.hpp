#pragma once
#include <Windows.h>
#include <memory>
#include <optional>

namespace aether::host {
enum class PaneAttempt { accepted, declined, unsupported };
// One owned HWND and its PMv2 UI thread. Create, use and destroy on that thread.
// Native callbacks only retain weak observation state and post changed_message.
class InputPane final {
  public:
    InputPane(HWND window, UINT changed_message);
    ~InputPane() noexcept;
    InputPane(const InputPane &) = delete;
    InputPane &operator=(const InputPane &) = delete;
    // Each call makes at most one native request. Acceptance is not visibility.
    PaneAttempt request_show() noexcept;
    PaneAttempt request_hide() noexcept;
    // Focus/lifecycle retirement forgets ownership without hiding another app's pane.
    void abandon() noexcept;
    // Actual native screen coordinates, physical pixels under the PMv2 contract.
    // nullopt means unknown; an empty rectangle means observed absence.
    std::optional<RECT> occlusion() const noexcept;
    // Passive read recovery only: never repeats a show/hide request.
    void refresh() noexcept;

  private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};
} // namespace aether::host
