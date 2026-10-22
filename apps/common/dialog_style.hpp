#pragma once
#include <Windows.h>

namespace aether::install::dialog_style {
inline constexpr COLORREF background = RGB(250, 251, 254), ink = RGB(24, 33, 49),
                          muted = RGB(99, 112, 132), blue = RGB(32, 105, 232);
inline constexpr int close_id = 103;

inline int px(int value, int dpi) { return MulDiv(value, dpi, 96); }

inline HFONT font(int size, int weight, int dpi) {
    return CreateFontW(-px(size, dpi), 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH,
                       L"Segoe UI");
}

inline LRESULT header_hit_test(HWND window, LPARAM position, int dpi) {
    POINT point{static_cast<short>(LOWORD(position)), static_cast<short>(HIWORD(position))};
    ScreenToClient(window, &point);
    return point.y >= 0 && point.y < px(64, dpi) ? HTCAPTION : HTCLIENT;
}

// Keep ordinary BUTTON controls for keyboard and accessibility; paint the X
// ourselves so its appearance does not depend on the system's symbol font.
inline void draw_button(const DRAWITEMSTRUCT &item, HFONT normal, int dpi, bool primary = false) {
    auto rect = item.rcItem;
    const bool close = item.CtlID == close_id;
    const bool enabled = !(item.itemState & ODS_DISABLED);
    const bool pressed = (item.itemState & ODS_SELECTED) != 0;
    const auto fill = CreateSolidBrush(
        primary ? (enabled ? (pressed ? RGB(22, 80, 185) : blue) : RGB(185, 197, 215))
                : (pressed ? RGB(230, 235, 244) : background));
    const auto old_brush = SelectObject(item.hDC, fill);
    const auto old_pen = SelectObject(item.hDC, GetStockObject(NULL_PEN));
    RoundRect(item.hDC, rect.left, rect.top, rect.right, rect.bottom, px(10, dpi), px(10, dpi));
    SelectObject(item.hDC, old_pen);
    SelectObject(item.hDC, old_brush);
    DeleteObject(fill);
    if (close) {
        const auto pen = CreatePen(PS_SOLID, px(2, dpi), enabled ? ink : muted);
        const auto previous = SelectObject(item.hDC, pen);
        const auto x = (rect.left + rect.right) / 2, y = (rect.top + rect.bottom) / 2;
        const auto radius = px(6, dpi);
        MoveToEx(item.hDC, x - radius, y - radius, nullptr);
        LineTo(item.hDC, x + radius, y + radius);
        MoveToEx(item.hDC, x + radius, y - radius, nullptr);
        LineTo(item.hDC, x - radius, y + radius);
        SelectObject(item.hDC, previous);
        DeleteObject(pen);
    } else {
        wchar_t text[128]{};
        GetWindowTextW(item.hwndItem, text, 128);
        SetBkMode(item.hDC, TRANSPARENT);
        SetTextColor(item.hDC, primary ? RGB(255, 255, 255)
                                       : (enabled && item.CtlID != IDCANCEL ? blue : muted));
        const auto old_font = SelectObject(item.hDC, normal);
        DrawTextW(item.hDC, text, -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        SelectObject(item.hDC, old_font);
    }
    if (item.itemState & ODS_FOCUS) {
        InflateRect(&rect, -px(4, dpi), -px(4, dpi));
        DrawFocusRect(item.hDC, &rect);
    }
}
} // namespace aether::install::dialog_style
