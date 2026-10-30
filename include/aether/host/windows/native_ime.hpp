#pragma once
#include <Windows.h>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace aether::host {
struct NativeImeConversion {
    std::u16string composition; // Exact native baseline, never replacement text.
    bool available = true;
    std::int32_t start = -1, end = -1; // Relative UTF-16 target range, or known absent.
    std::int32_t unchanged_prefix = -1; // Native Unicode delta start, when independently captured.
    std::string previous_composition_sha256; // Exact previous native UTF-16LE baseline.
};
struct NativeImePacket {
    std::optional<std::u16string> result, composition;
    std::optional<std::int32_t> cursor;
    std::optional<NativeImeConversion> conversion;
    bool cancel = false;
};
// The Activity window owns this private native context. HIMC/ HWND values never
// become guest handles or command payloads. Methods run on the window UI thread.
class NativeIme final {
  public:
    explicit NativeIme(HWND window);
    ~NativeIme() noexcept;
    NativeIme(const NativeIme &) = delete;
    NativeIme &operator=(const NativeIme &) = delete;
    NativeImePacket read(LPARAM flags);
    void reset_composition_evidence() noexcept; // Passive lifecycle fence; no native write.
    void position(POINT client_caret, RECT client_line, unsigned candidate_mask = 1, bool force = false);
    void cancel();
  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::host
