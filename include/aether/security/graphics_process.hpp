#pragma once
#include "aether/graphics/command.hpp"
#include "aether/host/graphics_presenter.hpp"
#include "aether/security/worker.hpp"

namespace aether::security {
// Single-owner, copied-command graphics service. The child has its own AppContainer,
// one-process job and cumulative CPU/commit limits. Each complete command, including
// transfer and response, has one independently enforced deadline. No automatic retry.
class GraphicsProcess final : public graphics::GraphicsChannel {
  public:
    static constexpr std::uint32_t command_timeout_ms = 5000;
    GraphicsProcess(const std::filesystem::path &executable, std::uint64_t app_id);
    ~GraphicsProcess() override;
    graphics::GraphicsReply exchange(const graphics::GraphicsCommand &command) override;
    graphics::GraphicsReply close() override;
    std::uint32_t process_id() const noexcept;
    WorkerAccounting accounting() const;
    WorkerImageAccess image_access() const noexcept;
    bool timed_out() const noexcept;
    void request_stop() noexcept;
    void bind_window(const host::SurfaceSnapshot &surface, std::uint64_t token, bool capture);
    host::PresentationMetrics presentation_metrics() const noexcept;
    const std::vector<std::uint8_t> &presentation_pixels() const noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::security
