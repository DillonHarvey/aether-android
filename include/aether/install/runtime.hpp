#pragma once
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace aether::install {
// Installed hosts retain this shared lease until their windows/workers close.
// Unmanaged development builds are read-only no-ops, never implicitly adopted.
class RuntimeUseLease final {
  public:
    explicit RuntimeUseLease(const std::filesystem::path &store = {});
    ~RuntimeUseLease();
    RuntimeUseLease(const RuntimeUseLease &) = delete;
    RuntimeUseLease &operator=(const RuntimeUseLease &) = delete;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
// Called only after the store's journal is open, before any app mutation.
void remember_runtime_store(const std::filesystem::path &store);
int runtime_cli(const std::vector<std::string> &arguments, bool json);
bool is_runtime_command(const std::vector<std::string> &arguments);
} // namespace aether::install
