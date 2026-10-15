#pragma once
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string_view>

namespace aether::host {
enum class FileError {
    none,
    missing,
    denied,
    exists,
    bad_descriptor,
    invalid,
    unsupported,
    descriptor_limit,
    quota,
    io
};
struct FileResult {
    std::int64_t value = -1;
    FileError error = FileError::none;
};
struct FileOpen {
    bool read = false, write = false, create = false, exclusive = false, truncate = false;
};
class FileService {
  public:
    virtual ~FileService() = default;
    virtual FileResult open(std::string_view name, FileOpen options) = 0;
    virtual FileResult read(int descriptor, std::span<std::uint8_t> output) noexcept = 0;
    virtual FileResult write(int descriptor, std::span<const std::uint8_t> input) noexcept = 0;
    virtual FileResult close(int descriptor) noexcept = 0;
};
// Opens one-component names relative to a held directory handle. No guest path is a host path.
class HostFileService final : public FileService {
  public:
    explicit HostFileService(const std::filesystem::path &root);
    ~HostFileService() override;
    HostFileService(const HostFileService &) = delete;
    HostFileService &operator=(const HostFileService &) = delete;
    FileResult open(std::string_view name, FileOpen options) override;
    FileResult read(int descriptor, std::span<std::uint8_t> output) noexcept override;
    FileResult write(int descriptor, std::span<const std::uint8_t> input) noexcept override;
    FileResult close(int descriptor) noexcept override;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::host
