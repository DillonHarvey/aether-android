#pragma once
#include "aether/elf/guest_loader.hpp"
#include "aether/host/file_service.hpp"
#include "aether/host/time_service.hpp"

namespace aether::bionic {
struct ServiceMetrics {
    std::uint64_t calls = 0, clock_reads = 0, allocations = 0, frees = 0;
    std::uint64_t errors = 0, rejected_operations = 0, file_operations = 0;
    std::size_t allocated_bytes = 0;
};
class GuestPosixServices final : public a64::GuestServices, public elf::ImportResolver {
  public:
    static constexpr a64::Address trampoline_base = 0x20000, errno_address = 0x24000;
    GuestPosixServices(a64::GuestMemory &memory, const a64::AppContext &app, const host::TimeService &time,
                       std::uint32_t logical_thread = 1, host::FileService *files = nullptr);
    ~GuestPosixServices();
    bool has_library(std::string_view library) const noexcept override;
    std::optional<elf::GuestSymbol> resolve(std::string_view library, std::string_view name,
                                            std::string_view version) const override;
    a64::Fault invoke(std::uint32_t service, a64::Address instruction,
                      std::array<std::uint64_t, 31> &registers) noexcept override;
    const ServiceMetrics &metrics() const noexcept;
    std::string_view last_rejection() const noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::bionic
