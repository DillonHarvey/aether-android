#pragma once
#include <Windows.h>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace aether::host {
enum class TextBoundary { character, word, line, paragraph, document };
struct TextRectangle {
    float left = 0, top = 0, width = 0, height = 0;
};
struct TextCluster {
    std::uint32_t start = 0, length = 0;
    TextRectangle bounds;
};
// Host-owned shaping. All coordinates are physical pixels relative to the text
// origin at a fixed 96-DPI render target. Queries never call guest code.
class TextLayout final {
  public:
    TextLayout(std::u16string text, float width_pixels, float font_pixels);
    ~TextLayout();
    TextLayout(const TextLayout &) = delete;
    TextLayout &operator=(const TextLayout &) = delete;
    std::u16string_view text() const noexcept;
    float width() const noexcept;
    float height() const noexcept;
    float font_size() const noexcept;
    std::vector<TextRectangle> rectangles(std::uint32_t start, std::uint32_t length) const;
    std::vector<TextCluster> clusters() const;
    // Native Windows ICU (explicit en_US), not an Android-pinned Unicode oracle.
    // Character uses extended grapheme clusters; Control/Format-only clusters
    // attach to adjacent visible units (leading prefix to first, otherwise to
    // previous). Nonempty control-only text has no character units: {}.
    // Word uses lexical starts with trailing separators on the previous word;
    // leading separators attach to the first word; all-nonlexical text is one unit.
    // Line uses actual DirectWrite lengths. Paragraph uses CRLF/CR/LF/NEL/PS,
    // not LS. Consecutive hardbreaks attach to the preceding paragraph; a leading
    // prefix attaches to first following content; hardbreak-only text is one unit.
    // Other maps include sorted unique 0..length; empty text is {0}.
    // A zero-length final physical line shares the document-end boundary.
    std::vector<std::uint32_t> boundaries(TextBoundary unit) const;
    std::uint32_t hit_test(float x, float y) const;
    void draw(HDC dc, POINT origin, RECT clip, COLORREF color, COLORREF background,
              std::int32_t selection_start = -1, std::int32_t selection_end = -1,
              bool focused = false) const;
  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace aether::host
