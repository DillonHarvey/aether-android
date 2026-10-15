#pragma once
#include <Windows.h>
#include <filesystem>
#include <memory>
#include <string>

namespace aether::security {
struct WorkerImageAccess {
    DWORD file = 0, directory = 0;
};
// Trusted build/install tooling uses this policy; launch never applies it.
std::wstring worker_image_sddl();
std::wstring runtime_directory_sddl();
void verify_owned_runtime_file(HANDLE file);
void verify_runtime_directory(HANDLE directory);
// Hold the selected regular file and its parent against replacement while the
// worker is alive. Validation is read-only and rejects unprovisioned images.
class WorkerImage final {
  public:
    explicit WorkerImage(const std::filesystem::path &path);
    ~WorkerImage();
    WorkerImage(const WorkerImage &) = delete;
    WorkerImage &operator=(const WorkerImage &) = delete;
    WorkerImageAccess verify_process(HANDLE process) const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::security
