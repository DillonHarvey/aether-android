#pragma once
#include "aether/host/file_service.hpp"

namespace aether::security {
enum class StoragePurpose { private_files, audit };
// Broker-only storage. Roots and files grant Windows access to the owner and SYSTEM,
// never an AppContainer SID. Existing roots with an unexpected ACL fail closed.
class PrivateStorage final : public host::FileService {
  public:
    static constexpr std::size_t maximum_names = 32;
    static constexpr std::size_t maximum_audit_names = 256;
    PrivateStorage(const std::filesystem::path &parent, std::uint64_t app_id,
                   StoragePurpose purpose = StoragePurpose::private_files);
    explicit PrivateStorage(const std::filesystem::path &root,
                            StoragePurpose purpose = StoragePurpose::private_files);
    ~PrivateStorage() override;
    const std::filesystem::path &root() const noexcept;
    host::FileResult private_root() noexcept override;
    host::FileResult list_directory(std::vector<host::DirectoryEntry> &entries) override;
    host::FileResult observe_data_file(std::string_view name) override;
    host::FileResult open(std::string_view name, host::FileOpen options) override;
    host::FileResult read(int descriptor, std::span<std::uint8_t> output) noexcept override;
    host::FileResult write(int descriptor, std::span<const std::uint8_t> input) noexcept override;
    host::FileResult close(int descriptor) noexcept override;
    host::FileResult flush(int descriptor) noexcept override;
    host::FileResult access(host::FileAccessScope scope,std::string_view name,std::uint32_t mode) noexcept override;
    host::FileResult lock(int descriptor,std::uint32_t operation) noexcept override;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::security
