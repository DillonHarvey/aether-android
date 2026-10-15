#pragma once
#include "aether/bionic/guest_posix.hpp"
#include "aether/graphics/guest.hpp"
#include <filesystem>

namespace aether::graphics::detail {
// Shared execution harness for the exact first-party graphics ELF, never arbitrary input.
class FixtureRuntime final {
    struct Image {
        std::vector<std::uint8_t> bytes;
        std::string hash;
    };
    static Image load(const std::filesystem::path &path);
    static Image load(std::vector<std::uint8_t> bytes);
    Image image_; // Hash verification precedes every executable/service member.

  public:
    static constexpr a64::Address output = 0x30000000;
    static constexpr std::size_t output_size = 65536;
    a64::GuestMemory memory;
    a64::AppContext app{6, true, true};
    host::HostTimeService time;
    bionic::GuestPosixServices posix;
    GuestGraphicsServices graphics;

  private:
    class Services final : public a64::GuestServices, public elf::ImportResolver {
        bionic::GuestPosixServices &posix_;
        GuestGraphicsServices &graphics_;

      public:
        Services(bionic::GuestPosixServices &posix, GuestGraphicsServices &graphics);
        bool has_library(std::string_view library) const noexcept override;
        std::optional<elf::GuestSymbol> resolve(std::string_view library, std::string_view name,
                                                std::string_view version) const override;
        a64::Fault invoke(std::uint32_t service, a64::Address instruction,
                          std::array<std::uint64_t, 31> &registers) noexcept override;
        a64::Fault invoke_frame(std::uint32_t service, a64::Address instruction,
                                a64::ServiceState &state) noexcept override;
    } services_;
    elf::GuestLoader loader_;
    std::unique_ptr<a64::GuestCpu> cpu_;
    bool finalized_ = false;
    static constexpr a64::Address stack = 0x31000000, stack_top = stack + 65536;

  public:
    explicit FixtureRuntime(const std::filesystem::path &path);
    FixtureRuntime(std::vector<std::uint8_t> bytes, std::uint64_t app_id, host::TimeService &provider,
                   GraphicsChannel &channel);
    std::uint64_t value(std::string_view name, std::initializer_list<std::uint64_t> arguments = {});
    void call(std::string_view name, std::initializer_list<std::uint64_t> arguments = {});
    void finalize();
    const std::string &hash() const noexcept;
    std::size_t relocations() const noexcept;
    const a64::Metrics &cpu_metrics() const noexcept;
};
std::string save_capture(std::string_view name, std::span<const std::uint8_t> pixels);
} // namespace aether::graphics::detail
