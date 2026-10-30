#pragma once
#include "aether/host/windows/document_service.hpp"
#include "aether/host/drop_text.hpp"
#include <Windows.h>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>

namespace aether::host {
struct FileDropCapture {
    std::uint64_t generation = 0;
    std::filesystem::path file;
    POINT entered{}, dropped{};
    std::optional<POINT> location;
    DropPayloadKind kind = DropPayloadKind::file;
    std::optional<std::u16string> text;
};
struct FileDropCallbacks {
    std::function<std::uint64_t(POINT)> begin;
    std::function<bool(std::uint64_t, POINT)> over;
    std::function<bool(FileDropCapture)> accept;
    std::function<void(std::uint64_t)> cancel;
};
// UI apartment only. COPY acknowledges bounded native intake for review, not
// Android acceptance. Source data is extracted only in the actual Drop call.
class FileDrop final {
  public:
    FileDrop(HWND window, FileDropCallbacks callbacks);
    ~FileDrop() noexcept;
    FileDrop(const FileDrop &) = delete;
    FileDrop &operator=(const FileDrop &) = delete;
    void retire() noexcept;
  private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};
// A modeless owned confirmation. The exact file is held once before review;
// edits and focus are preserved during passive one-second metadata recovery.
class FileDropReview final {
  public:
    FileDropReview(HWND owner, std::wstring recipient, const std::filesystem::path &path);
    ~FileDropReview() noexcept;
    FileDropReview(const FileDropReview &) = delete;
    FileDropReview &operator=(const FileDropReview &) = delete;
    bool closed() const noexcept;
    bool translate(MSG &message) noexcept;
    std::optional<PreparedDocumentSource> take();
    void cancel() noexcept;
  private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};
// Exact selected-text consent. Approving transfers a copy; it does not grant
// clipboard access, document authority, or a revocable file permission.
class TextDropReview final {
  public:
    TextDropReview(HWND owner, std::wstring recipient, std::u16string text);
    ~TextDropReview() noexcept;
    TextDropReview(const TextDropReview &) = delete;
    TextDropReview &operator=(const TextDropReview &) = delete;
    bool closed() const noexcept;
    bool translate(MSG &message) noexcept;
    std::optional<std::u16string> take();
    void cancel() noexcept;
  private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};
} // namespace aether::host
