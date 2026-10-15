#pragma once
#include "aether/host/file_service.hpp"

namespace aether::security {
// Broker-only storage. Roots and files grant Windows access to the owner and SYSTEM,
// never an AppContainer SID. Existing roots with an unexpected ACL fail closed.
class PrivateStorage final : public host::FileService {
  public:
    static constexpr std::size_t maximum_names = 32;
    PrivateStorage(const std::filesystem::path &parent, std::uint64_t app_id);
    explicit PrivateStorage(const std::filesystem::path &root);
    ~PrivateStorage() override;
    const std::filesystem::path &root() const noexcept;
    host::FileResult open(std::string_view name, host::FileOpen options) override;
    host::FileResult read(int descriptor, std::span<std::uint8_t> output) noexcept override;
    host::FileResult write(int descriptor, std::span<const std::uint8_t> input) noexcept override;
    host::FileResult close(int descriptor) noexcept override;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::security
