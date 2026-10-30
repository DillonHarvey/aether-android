#include "aether/host/windows/text_layout.hpp"
#include <d2d1.h>
#include <dwrite.h>
#include <icu.h>
#include <wrl/client.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <iomanip>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace aether::host {
namespace {
using Microsoft::WRL::ComPtr;
constexpr std::size_t maximum_text_units = 65536;
constexpr float maximum_extent = 327680.0f;
constexpr UINT32 maximum_hit_rectangles = 2 * (65536 + 1);
[[noreturn]] void invalid(const char *message) {
    throw std::invalid_argument(std::string("AETHER_TEXT_LAYOUT: ") + message);
}
void checked(HRESULT result, const char *operation) {
    if (SUCCEEDED(result)) return;
    std::ostringstream message;
    message << "AETHER_TEXT_LAYOUT: " << operation << " failed (HRESULT 0x"
            << std::hex << std::uppercase << static_cast<std::uint32_t>(result) << ')';
    throw std::runtime_error(message.str());
}
void checked_rectangle(const DWRITE_HIT_TEST_METRICS &value) {
    if (!std::isfinite(value.left) || !std::isfinite(value.top) ||
        !std::isfinite(value.width) || !std::isfinite(value.height) ||
        value.width < 0 || value.height < 0)
        throw std::runtime_error("AETHER_TEXT_LAYOUT: Invalid native hit-test geometry");
}
[[noreturn]] void boundary_error(const char *message) {
    throw std::runtime_error(std::string("AETHER_TEXT_BOUNDARIES: ") + message);
}
void icu_checked(UErrorCode result, const char *operation) {
    if (U_SUCCESS(result)) return; // ICU negative warnings are successful results.
    std::ostringstream message;
    message << "AETHER_TEXT_BOUNDARIES: " << operation << " failed (ICU error "
            << static_cast<int>(result) << ')';
    throw std::runtime_error(message.str());
}
bool control_cluster(std::u16string_view text, std::uint32_t start, std::uint32_t end) {
    for (auto offset = start; offset < end;) {
        UChar32 codepoint = text[offset++];
        if (codepoint >= 0xD800 && codepoint <= 0xDBFF && offset < end &&
            text[offset] >= 0xDC00 && text[offset] <= 0xDFFF) {
            codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + (text[offset++] - 0xDC00);
        }
        const auto category = u_charType(codepoint);
        if (category != U_CONTROL_CHAR && category != U_FORMAT_CHAR) return false;
    }
    return true;
}
D2D1_COLOR_F color_value(COLORREF value) noexcept {
    return D2D1::ColorF(static_cast<float>(GetRValue(value)) / 255.0f,
                        static_cast<float>(GetGValue(value)) / 255.0f,
                        static_cast<float>(GetBValue(value)) / 255.0f, 1.0f);
}
} // namespace

struct TextLayout::Impl {
    const std::u16string value;
    const float width_pixels, font_pixels;
    float height_pixels = 0;
    ComPtr<IDWriteFactory> write_factory;
    ComPtr<IDWriteTextLayout> layout;
    mutable std::mutex mutex;
    mutable ComPtr<ID2D1Factory> draw_factory;
    mutable ComPtr<ID2D1DCRenderTarget> target;
    mutable std::array<std::optional<std::vector<std::uint32_t>>, 5> unit_maps;
    Impl(std::u16string text, float width, float font)
        : value(std::move(text)), width_pixels(width), font_pixels(font) {
        if (value.size() > maximum_text_units) invalid("Text exceeds the 65536 UTF-16 unit bound");
        if (!std::isfinite(width) || width <= 0 || width > maximum_extent)
            invalid("Width must be finite and within the physical-pixel layout bound");
        if (!std::isfinite(font) || font < 8 || font > 160)
            invalid("Font size must be finite and between 8 and 160 physical pixels");
        checked(DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
                                     reinterpret_cast<IUnknown **>(write_factory.GetAddressOf())),
                "Create DirectWrite factory");
        ComPtr<IDWriteTextFormat> format;
        checked(write_factory->CreateTextFormat(L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_NORMAL,
                    DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, font, L"en-US", &format),
                "Create text format");
        checked(format->SetWordWrapping(DWRITE_WORD_WRAPPING_WRAP), "Set word wrapping");
        checked(format->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING), "Set text alignment");
        checked(format->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR), "Set paragraph alignment");
        // An explicit length preserves embedded NULs and the original UTF-16 value.
        checked(write_factory->CreateTextLayout(reinterpret_cast<const WCHAR *>(value.data()),
                    static_cast<UINT32>(value.size()), format.Get(), width, maximum_extent, &layout),
                "Create shaped text layout");
        DWRITE_TEXT_METRICS metrics{};
        checked(layout->GetMetrics(&metrics), "Measure shaped text");
        if (!std::isfinite(metrics.height) || metrics.height <= 0 || metrics.height > maximum_extent)
            throw std::runtime_error("AETHER_TEXT_LAYOUT_LIMIT: Shaped height exceeds the physical-pixel bound");
        height_pixels = metrics.height;
    }
    void range_bounds(std::uint32_t start, std::uint32_t length) const {
        if (start > value.size() || length > value.size() - start)
            invalid("Text range exceeds its immutable UTF-16 value");
    }
    std::vector<TextRectangle> ranges(std::uint32_t start, std::uint32_t length) const {
        range_bounds(start, length);
        if (!length) {
            FLOAT x = 0, y = 0;
            DWRITE_HIT_TEST_METRICS metrics{};
            checked(layout->HitTestTextPosition(start, FALSE, &x, &y, &metrics), "Locate text caret");
            checked_rectangle(metrics);
            if (!std::isfinite(x) || !std::isfinite(y))
                throw std::runtime_error("AETHER_TEXT_LAYOUT: Invalid native caret geometry");
            return {{x, y, 0.0f, metrics.height}};
        }
        UINT32 needed = 0;
        const auto count_result = layout->HitTestTextRange(start, length, 0, 0, nullptr, 0, &needed);
        if (count_result != HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
            checked(count_result, "Count text range rectangles");
        if (needed > maximum_hit_rectangles)
            throw std::runtime_error("AETHER_TEXT_LAYOUT_LIMIT: Native range geometry exceeds its bound");
        if (!needed) return {};
        std::vector<DWRITE_HIT_TEST_METRICS> native(needed);
        UINT32 actual = 0;
        checked(layout->HitTestTextRange(start, length, 0, 0, native.data(), needed, &actual),
                "Read text range rectangles");
        if (actual > needed)
            throw std::runtime_error("AETHER_TEXT_LAYOUT: Native range count changed unexpectedly");
        std::vector<TextRectangle> result;
        result.reserve(actual);
        for (UINT32 i = 0; i < actual; ++i) {
            const auto &item = native[i];
            checked_rectangle(item);
            result.push_back({item.left, item.top, item.width, item.height});
        }
        return result;
    }
    std::vector<std::uint32_t> unicode_boundaries(TextBoundary unit) const {
        const auto type = unit == TextBoundary::character ? UBRK_CHARACTER : UBRK_WORD;
        UErrorCode status = U_ZERO_ERROR;
        using Iterator = std::unique_ptr<UBreakIterator, decltype(&ubrk_close)>;
        Iterator iterator(ubrk_open(type, "en_US", value.data(), static_cast<std::int32_t>(value.size()),
                                   &status), &ubrk_close);
        icu_checked(status, "Open native Unicode break iterator");
        if (!iterator) boundary_error("Native break iterator returned no object");
        auto previous = ubrk_first(iterator.get());
        if (previous != 0) boundary_error("Native Unicode boundaries do not begin at zero");
        std::vector<std::uint32_t> result;
        result.reserve(value.size() + 1);
        bool found_unit = false;
        if (unit == TextBoundary::word) result.push_back(0);
        for (auto next = ubrk_next(iterator.get()); next != UBRK_DONE; next = ubrk_next(iterator.get())) {
            if (next <= previous || next < 0 || static_cast<std::size_t>(next) > value.size())
                boundary_error("Native Unicode boundary is unordered or outside the text");
            const auto start = static_cast<std::uint32_t>(previous);
            const auto end = static_cast<std::uint32_t>(next);
            if (unit == TextBoundary::character) {
                if (!control_cluster(value, start, end)) {
                    // Leading controls belong to the first visible unit;
                    // intervening and trailing controls belong to the previous.
                    result.push_back(found_unit ? start : 0);
                    found_unit = true;
                }
            } else {
                const auto rule = ubrk_getRuleStatus(iterator.get());
                if (rule < 0) boundary_error("Native word rule status is invalid");
                if (rule >= UBRK_WORD_NONE_LIMIT) {
                    if (found_unit) result.push_back(start);
                    found_unit = true;
                }
            }
            previous = next;
        }
        if (static_cast<std::size_t>(previous) != value.size())
            boundary_error("Native Unicode boundaries do not cover the text");
        if ((unit == TextBoundary::word || found_unit) &&
            (result.empty() || result.back() != value.size()))
            result.push_back(static_cast<std::uint32_t>(value.size()));
        return result;
    }
    std::vector<std::uint32_t> line_boundaries() const {
        UINT32 needed = 0;
        const auto count_result = layout->GetLineMetrics(nullptr, 0, &needed);
        if (count_result != HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
            checked(count_result, "Count shaped text lines");
        if (!needed || needed > value.size() + 1)
            boundary_error("Native line count exceeds its text bound");
        std::vector<DWRITE_LINE_METRICS> lines(needed);
        UINT32 actual = 0;
        checked(layout->GetLineMetrics(lines.data(), needed, &actual), "Read shaped text lines");
        if (!actual || actual > needed) boundary_error("Native line count changed unexpectedly");
        std::vector<std::uint32_t> result{0};
        result.reserve(static_cast<std::size_t>(actual) + 1);
        std::uint32_t end = 0;
        for (UINT32 i = 0; i < actual; ++i) {
            const auto length = lines[i].length;
            if (length > value.size() - end || (!length && i + 1 != actual))
                boundary_error("Native line length exceeds or fails to advance through text");
            end += length; // DirectWrite includes the entire newline sequence.
            if (end != result.back()) result.push_back(end);
        }
        if (end != value.size()) boundary_error("Native lines do not cover the immutable text");
        return result;
    }
    std::vector<std::uint32_t> make_boundaries(TextBoundary unit) const {
        if (value.empty()) return {0};
        if (unit == TextBoundary::character || unit == TextBoundary::word)
            return unicode_boundaries(unit);
        if (unit == TextBoundary::line) return line_boundaries();
        std::vector<std::uint32_t> result{0};
        if (unit == TextBoundary::paragraph) {
            const auto terminator_length = [&](std::size_t at) -> std::size_t {
                if (at >= value.size()) return 0;
                if (value[at] == u'\r')
                    return at + 1 < value.size() && value[at + 1] == u'\n' ? 2 : 1;
                return value[at] == u'\n' || value[at] == u'\u0085' || value[at] == u'\u2029' ? 1 : 0;
            };
            bool found_content = false;
            for (std::size_t offset = 0; offset < value.size();) {
                const auto length = terminator_length(offset);
                if (!length) {
                    found_content = true;
                    ++offset; // U+2028 is a line break inside this paragraph profile.
                    continue;
                }
                offset += length;
                while (const auto next = terminator_length(offset)) offset += next;
                // Empty trailing lines attach to their preceding paragraph.
                // A leading hardbreak prefix attaches to first following content.
                if (found_content) result.push_back(static_cast<std::uint32_t>(offset));
            }
        }
        if (result.back() != value.size()) result.push_back(static_cast<std::uint32_t>(value.size()));
        return result;
    }
    void ensure_target() const {
        if (!draw_factory)
            checked(D2D1CreateFactory(D2D1_FACTORY_TYPE_MULTI_THREADED, draw_factory.GetAddressOf()),
                    "Create Direct2D factory");
        if (!target) {
            const auto properties = D2D1::RenderTargetProperties(D2D1_RENDER_TARGET_TYPE_SOFTWARE,
                D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_IGNORE), 96, 96,
                D2D1_RENDER_TARGET_USAGE_GDI_COMPATIBLE);
            checked(draw_factory->CreateDCRenderTarget(&properties, &target), "Create DC render target");
        }
    }
};

TextLayout::TextLayout(std::u16string text, float width_pixels, float font_pixels)
    : impl_(std::make_unique<Impl>(std::move(text), width_pixels, font_pixels)) {}
TextLayout::~TextLayout() = default;
std::u16string_view TextLayout::text() const noexcept { return impl_->value; }
float TextLayout::width() const noexcept { return impl_->width_pixels; }
float TextLayout::height() const noexcept { return impl_->height_pixels; }
float TextLayout::font_size() const noexcept { return impl_->font_pixels; }
std::vector<TextRectangle> TextLayout::rectangles(std::uint32_t start, std::uint32_t length) const {
    std::lock_guard lock(impl_->mutex);
    return impl_->ranges(start, length);
}
std::vector<TextCluster> TextLayout::clusters() const {
    auto &p = *impl_;
    std::lock_guard lock(p.mutex);
    UINT32 needed = 0;
    const auto count_result = p.layout->GetClusterMetrics(nullptr, 0, &needed);
    if (count_result != HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
        checked(count_result, "Count shaping clusters");
    if (needed > p.value.size())
        throw std::runtime_error("AETHER_TEXT_LAYOUT_LIMIT: Native cluster count exceeds its text bound");
    if (!needed) return {};
    std::vector<DWRITE_CLUSTER_METRICS> native(needed);
    UINT32 actual = 0;
    checked(p.layout->GetClusterMetrics(native.data(), needed, &actual), "Read shaping clusters");
    if (actual > needed)
        throw std::runtime_error("AETHER_TEXT_LAYOUT: Native cluster count changed unexpectedly");
    std::vector<TextCluster> result;
    result.reserve(actual);
    std::uint32_t start = 0;
    for (UINT32 i = 0; i < actual; ++i) {
        const auto length = static_cast<std::uint32_t>(native[i].length);
        if (!length || start > p.value.size() || length > p.value.size() - start)
            throw std::runtime_error("AETHER_TEXT_LAYOUT: Invalid native cluster span");
        const auto boxes = p.ranges(start, length);
        TextRectangle bounds{};
        bool first = true;
        for (const auto &box : boxes) {
            if (first) { bounds = box; first = false; }
            else {
                const auto right = std::max(bounds.left + bounds.width, box.left + box.width);
                const auto bottom = std::max(bounds.top + bounds.height, box.top + box.height);
                bounds.left = std::min(bounds.left, box.left);
                bounds.top = std::min(bounds.top, box.top);
                bounds.width = right - bounds.left;
                bounds.height = bottom - bounds.top;
            }
        }
        result.push_back({start, length, bounds});
        start += length;
    }
    if (start != p.value.size())
        throw std::runtime_error("AETHER_TEXT_LAYOUT: Native clusters do not cover the immutable text");
    // These are DirectWrite shaping clusters, not a promise of full Unicode
    // extended-grapheme or Android selection semantics.
    return result;
}
std::vector<std::uint32_t> TextLayout::boundaries(TextBoundary unit) const {
    const auto index = static_cast<std::size_t>(unit);
    if (index >= impl_->unit_maps.size()) invalid("Unknown native text boundary unit");
    auto &p = *impl_;
    std::lock_guard lock(p.mutex);
    auto &cached = p.unit_maps[index];
    if (!cached) {
        auto result = p.make_boundaries(unit);
        if (result.size() > p.value.size() + 1)
            boundary_error("Text boundary map exceeds the UTF-16 text bound");
        std::uint32_t previous = 0;
        bool first = true;
        for (const auto offset : result) {
            if (offset > p.value.size() || (!first && offset <= previous))
                boundary_error("Text boundary map is unordered or outside the text");
            previous = offset;
            first = false;
        }
        if (!result.empty() && (result.front() != 0 || result.back() != p.value.size()))
            boundary_error("Text boundary map does not cover the immutable text");
        if (result.empty() && (unit != TextBoundary::character || p.value.empty()))
            boundary_error("Only nonempty control-only text may have no character units");
        cached = std::move(result);
    }
    return *cached;
}
std::uint32_t TextLayout::hit_test(float x, float y) const {
    if (!std::isfinite(x) || !std::isfinite(y)) invalid("Hit-test coordinates must be finite");
    auto &p = *impl_;
    std::lock_guard lock(p.mutex);
    BOOL trailing = FALSE, inside = FALSE;
    DWRITE_HIT_TEST_METRICS metrics{};
    checked(p.layout->HitTestPoint(x, y, &trailing, &inside, &metrics), "Hit-test shaped text point");
    checked_rectangle(metrics);
    (void)inside; // UIA point lookup intentionally returns the nearest insertion position.
    if (metrics.textPosition > p.value.size() || metrics.length > p.value.size() - metrics.textPosition)
        throw std::runtime_error("AETHER_TEXT_LAYOUT: Native hit-test span exceeds its text");
    return metrics.textPosition + (trailing ? metrics.length : 0);
}
void TextLayout::draw(HDC dc, POINT origin, RECT clip, COLORREF color, COLORREF background,
                      std::int32_t selection_start, std::int32_t selection_end, bool focused) const {
    if (!dc) invalid("Drawing requires an HDC");
    auto &p = *impl_;
    if (selection_start < -1 || selection_end < -1 ||
        (selection_start >= 0 && static_cast<std::size_t>(selection_start) > p.value.size()) ||
        (selection_end >= 0 && static_cast<std::size_t>(selection_end) > p.value.size()))
        invalid("Drawing selection exceeds its immutable UTF-16 value");
    RECT current{}, bound{};
    if (GetClipBox(dc, &current) == ERROR)
        throw std::runtime_error("AETHER_TEXT_LAYOUT: Read DC clip failed");
    if (!IntersectRect(&bound, &clip, &current)) return;
    const auto width = static_cast<std::int64_t>(bound.right) - bound.left;
    const auto height = static_cast<std::int64_t>(bound.bottom) - bound.top;
    if (width <= 0 || height <= 0) return;
    // The render bitmap is restricted by the existing window-buffer budget,
    // independently of the larger offscreen shaping-coordinate bound.
    if (width > 16384 || height > 16384 || width * height > 16777216)
        invalid("Drawing clip exceeds the window-buffer dimension or pixel bound");
    const auto local_x = static_cast<float>(static_cast<std::int64_t>(origin.x) - bound.left);
    const auto local_y = static_cast<float>(static_cast<std::int64_t>(origin.y) - bound.top);
    std::lock_guard lock(p.mutex);
    p.ensure_target();
    struct ReleaseTarget {
        ComPtr<ID2D1DCRenderTarget> &target;
        ~ReleaseTarget() { target.Reset(); }
    } release_target{p.target};
    // Cache shaping and the small factory only. A previously visible/scrolled
    // layout must not retain a last-visible DC bitmap, including on exceptions.
    checked(p.target->BindDC(dc, &bound), "Bind text render DC");
    p.target->SetDpi(96, 96);
    p.target->SetTransform(D2D1::Matrix3x2F::Identity());
    ComPtr<ID2D1SolidColorBrush> foreground, selection;
    checked(p.target->CreateSolidColorBrush(color_value(color), &foreground), "Create text brush");
    checked(p.target->CreateSolidColorBrush(color_value(focused ? RGB(186, 216, 255) : RGB(218, 223, 230)),
                                           &selection), "Create selection brush");
    // All geometry and brushes are acquired before BeginDraw so allocation/API
    // failures cannot leave an unfinished draw scope.
    std::vector<TextRectangle> selected;
    const bool has_selection = selection_start >= 0 && selection_end >= 0;
    if (has_selection && selection_start != selection_end) {
        const auto first = static_cast<std::uint32_t>(std::min(selection_start, selection_end));
        const auto count = static_cast<std::uint32_t>(std::max(selection_start, selection_end)) - first;
        selected = p.ranges(first, count);
    } else if (has_selection && focused) selected = p.ranges(static_cast<std::uint32_t>(selection_end), 0);
    p.target->BeginDraw();
    // BindDC renders through an internal bitmap; it does not promise to import
    // existing GDI pixels. Main supplies the exact flat text-content background,
    // and its clip excludes control borders/focus and all clipped ancestors.
    p.target->Clear(color_value(background));
    p.target->PushAxisAlignedClip(D2D1::RectF(0, 0, static_cast<float>(width), static_cast<float>(height)),
                                  D2D1_ANTIALIAS_MODE_ALIASED);
    for (const auto &box : selected) {
        const auto rectangle = D2D1::RectF(local_x + box.left, local_y + box.top,
            local_x + box.left + box.width, local_y + box.top + box.height);
        if (selection_start != selection_end) p.target->FillRectangle(rectangle, selection.Get());
    }
    p.target->DrawTextLayout(D2D1::Point2F(local_x, local_y), p.layout.Get(), foreground.Get(),
                             D2D1_DRAW_TEXT_OPTIONS_CLIP);
    if (has_selection && focused && selection_start == selection_end)
        for (const auto &box : selected)
            p.target->FillRectangle(D2D1::RectF(local_x + box.left - 0.5f, local_y + box.top,
                local_x + box.left + 0.5f, local_y + box.top + box.height), foreground.Get());
    p.target->PopAxisAlignedClip();
    const auto result = p.target->EndDraw();
    if (FAILED(result)) {
        p.target.Reset(); // No automatic replay of a failed paint.
        checked(result, "Draw shaped text");
    }
}
} // namespace aether::host
