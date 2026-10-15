#pragma once
#include "aether/elf/guest_loader.hpp"
#include "aether/host/audio_stream.hpp"

namespace aether::audio {
std::span<const std::string_view> api_registry() noexcept;
struct Metrics {
    std::uint64_t calls = 0, rejected = 0, api_errors = 0, streams_opened = 0, streams_closed = 0;
    std::size_t builders = 0, streams = 0;
};
// One app/address-space/owner thread. Muting is a trusted harness choice, not guest policy.
// The supplied provider owns resource policy; the default is for direct development tests.
class GuestAudioServices final : public a64::GuestServices, public elf::ImportResolver {
  public:
    static constexpr a64::Address trampoline_base = 0x90000;
    static constexpr std::uint32_t first_service = 0xd00;
    GuestAudioServices(a64::GuestMemory &memory, const a64::AppContext &app, bool muted = false,
                       host::AudioService *provider = nullptr);
    ~GuestAudioServices();
    GuestAudioServices(const GuestAudioServices &) = delete;
    GuestAudioServices &operator=(const GuestAudioServices &) = delete;
    static bool handles_service(std::uint32_t service) noexcept;
    bool has_library(std::string_view library) const noexcept override;
    std::optional<elf::GuestSymbol> resolve(std::string_view library, std::string_view name,
                                            std::string_view version) const override;
    a64::Fault invoke(std::uint32_t service, a64::Address instruction,
                      std::array<std::uint64_t, 31> &registers) noexcept override;
    const Metrics &metrics() const noexcept;
    const host::AudioInfo &host_info() const noexcept;
    const host::AudioMetrics &host_metrics() const noexcept;
    std::string_view last_error() const noexcept;
    void shutdown();

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::audio
