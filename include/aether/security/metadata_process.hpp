#pragma once
#include "aether/apk/preview.hpp"
#include "aether/security/worker.hpp"
#include "aether/shell/icon_cache.hpp"

namespace aether::security {
inline constexpr wchar_t metadata_profile[] = L"Aether.IconMetadata.v2";
inline constexpr std::uint32_t metadata_timeout_ms = 5000;
// Strict description and bounded raw pixel transfer. No path/encoded image from
// the child is ever used as a host file or Shell icon artifact.
std::vector<std::uint8_t> encode_icon_description(const apk::PackagePreview &preview);
apk::PackagePreview decode_icon_description(std::span<const std::uint8_t> bytes);
struct MetadataResult {
    apk::PackagePreview preview;
    WorkerAccounting accounting;
    std::uint32_t pid = 0, exit_code = 0;
    bool isolated = false, timed_out = false;
};
class MetadataProcess final {
  public:
    explicit MetadataProcess(const std::filesystem::path &executable,
                             std::uint32_t timeout = metadata_timeout_ms);
    MetadataResult inspect(const shell::IconSource &source);
    void request_stop() noexcept { worker_.request_stop(); }

  private:
    WorkerProcess worker_;
    bool used_ = false;
};
} // namespace aether::security
