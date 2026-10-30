#include "link_dialog.hpp"
#include "aether/apk/artwork.hpp"
#include "aether/common/text.hpp"
#include <Windows.h>
#include <commctrl.h>
#include <algorithm>
#include <chrono>
#include <future>
#include <string_view>
#include <tuple>
#include <utility>

namespace aether::install {
namespace {
constexpr int uri_id = 1200, list_id = 1201, details_id = 1202, open_id = 1203;
constexpr UINT_PTR timer_id = 1;
using Key = std::tuple<std::string, std::string, std::string, std::optional<std::size_t>, std::optional<std::size_t>>;
Key key(const LinkReviewRow &row) { return {row.app_id, row.component_name, row.target_name, row.declaration, row.target}; }
bool same_review(const LinkReviewRow &left, const LinkReviewRow &right) {
    return key(left) == key(right) && left.apk_hash == right.apk_hash &&
        left.display_name == right.display_name &&
        left.package_generation == right.package_generation && left.permissions == right.permissions &&
        left.state == right.state && left.shell == right.shell && left.shell_verified == right.shell_verified &&
        left.disposition == right.disposition && left.package_id == right.package_id && left.target_sdk == right.target_sdk;
}
std::wstring safe(std::u16string_view value) {
    // Display transformations never replace the raw request. Escape controls,
    // bidi overrides and isolated surrogate units so review cannot hide them.
    constexpr wchar_t digits[] = L"0123456789ABCDEF";
    std::wstring result;
    for (std::size_t at = 0; at < value.size(); ++at) {
        const auto unit = value[at];
        const bool pair = unit >= 0xd800 && unit <= 0xdbff && at + 1 < value.size() &&
                          value[at + 1] >= 0xdc00 && value[at + 1] <= 0xdfff;
        if (pair) { result.push_back(unit); result.push_back(value[++at]); continue; }
        if (unit < 32 || (unit >= 0x7f && unit <= 0x9f) || unit == 0x061c || unit == 0x200e || unit == 0x200f ||
            (unit >= 0x2028 && unit <= 0x202e) || (unit >= 0x2066 && unit <= 0x2069) ||
            (unit >= 0xd800 && unit <= 0xdfff) || unit == u'\\') {
            result += L"\\u";
            for (int shift = 12; shift >= 0; shift -= 4) result.push_back(digits[(unit >> shift) & 15]);
        } else result.push_back(unit);
    }
    return result;
}
std::wstring safe(std::string_view value) {
    const auto wide = utf16(value);
    return safe(std::u16string(wide.begin(), wide.end()));
}
const wchar_t *disposition(LinkDisposition value) {
    switch (value) {
    case LinkDisposition::candidate: return L"Available to choose";
    case LinkDisposition::no_match: return L"Does not match";
    case LinkDisposition::unsupported: return L"Unsupported matching requirements";
    case LinkDisposition::ineligible: return L"Not eligible for external opening";
    case LinkDisposition::unavailable: return L"Unavailable";
    }
    return L"Unavailable";
}
std::string error_code(const std::exception &error) {
    if (const auto *value = dynamic_cast<const InstallError *>(&error)) return value->code;
    if (const auto *value = dynamic_cast<const apk::InspectError *>(&error)) return value->diagnostic.code;
    return "AETHER_OPEN_LINK_UNAVAILABLE";
}
struct Observation { std::optional<LinkReview> review; std::string code; std::uint64_t generation = 0; };
struct Preparation { std::optional<security::InstalledActivity> application; std::string code; };
struct Chooser {
    OpenLinkOptions options;
    std::optional<OpenFileOptions> file_options;
    std::optional<host::PreparedDocumentSource> document;
    HWND window = nullptr, edit = nullptr, list = nullptr, details = nullptr, status = nullptr, open = nullptr, cancel = nullptr;
    HFONT font = nullptr;
    int dpi = 96;
    std::u16string draft;
    std::future<Observation> read;
    std::future<Preparation> preparation;
    std::optional<LinkReview> shown;
    std::optional<Key> selected;
    std::optional<LinkReviewRow> reviewed_row;
    std::optional<security::InstalledActivity> result;
    std::uint64_t generation = 0;
    ULONGLONG last_read = 0;
    bool fresh = false, updating = false, closed = false;
    std::wstring message = L"Choose an installed Activity, then select Open. No target is selected automatically.";
    explicit Chooser(const OpenLinkOptions &value) : options(value), draft(value.uri) {
        if (draft.size() > 4096 || draft.find(u'\0') != draft.npos)
            throw InstallError("AETHER_OPEN_LINK_INPUT", "Link input exceeds the native edit profile");
    }
    explicit Chooser(const OpenFileOptions &value)
        : options{{}, value.app_id, value.store.empty() ? default_store_root() : value.store,
                  value.json, value.verbose, value.registered_activation}, file_options(value) {
        if (options.registered_activation) {
            if (!options.app_id)
                throw InstallError("AETHER_FILE_NOT_REGISTERED", "Registered opening requires an app identity");
            PackageStore store(options.store);
            require_registered_file_offer(store, *options.app_id, value.file, value.mime_type);
        }
        // Hold this exact file once. Timer reads inspect only its held provider;
        // they never reopen a path or regenerate a document URI.
        document = host::prepare_document_source(value.file, value.mime_type);
        message = L"Choose an installed Activity. Open read-only shares only this document for that app session.";
    }
    ~Chooser() {
        if (IsWindow(window)) DestroyWindow(window);
        if (read.valid()) read.wait();
        if (preparation.valid()) preparation.wait();
        if (font) DeleteObject(font);
    }
    std::optional<std::size_t> selected_index() const {
        if (!shown || !selected) return {};
        for (std::size_t index = 0; index < shown->rows.size(); ++index)
            if (key(shown->rows[index]) == *selected) return index;
        return {};
    }
    bool can_open() const {
        const auto index = selected_index();
        const auto visual = list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1;
        return !preparation.valid() && fresh && index && reviewed_row &&
            visual >= 0 && static_cast<std::size_t>(visual) == *index &&
            shown->rows[*index].disposition == LinkDisposition::candidate &&
            same_review(*reviewed_row, shown->rows[*index]);
    }
    void set_text(HWND control, const std::wstring &value, bool preserve = false) const {
        std::wstring old(static_cast<std::size_t>(GetWindowTextLengthW(control)) + 1, L'\0');
        old.resize(static_cast<std::size_t>(GetWindowTextW(control, old.data(), static_cast<int>(old.size()))));
        if (old == value) return;
        DWORD first = 0, last = 0;
        LRESULT line = 0;
        if (preserve) {
            SendMessageW(control, EM_GETSEL, reinterpret_cast<WPARAM>(&first), reinterpret_cast<LPARAM>(&last));
            line = SendMessageW(control, EM_GETFIRSTVISIBLELINE, 0, 0);
        }
        SetWindowTextW(control, value.c_str());
        if (preserve) {
            SendMessageW(control, EM_SETSEL, std::min<std::size_t>(first, value.size()),
                         static_cast<LPARAM>(std::min<std::size_t>(last, value.size())));
            SendMessageW(control, EM_LINESCROLL, 0, line - SendMessageW(control, EM_GETFIRSTVISIBLELINE, 0, 0));
        }
    }
    void render() {
        std::wstring review;
        if (document)
            review = L"Document (controls and bidi marks are escaped for review):\r\n" + safe(document->info.display_name) +
                L"\r\nMIME type: " + safe(document->info.mime_type) + L"\r\nSize: " + std::to_wstring(document->info.size) +
                L" bytes\r\n\r\nOpen read-only gives the selected app access to this held document for this session. "
                L"It grants no write access, folder access or persistent file permission.";
        else
            review = L"Link (controls, backslashes and bidi marks are escaped for review):\r\n" + safe(draft);
        if (const auto index = selected_index()) {
            const auto &row = shown->rows[*index];
            review += L"\r\n\r\nPackage: " + safe(row.package_id) + L"\r\nSelected Activity / alias: " + safe(row.component_name) +
                L"\r\nExecutable target: " + safe(row.target_name) + L"\r\n" + disposition(row.disposition);
            if (!row.code.empty()) review += L"\r\n" + safe(row.code);
            if (reviewed_row && !same_review(*reviewed_row, row))
                review += L"\r\nThis target changed. Select its row again to review the current target.";
        }
        set_text(details, review, true);
        set_text(status, message);
        EnableWindow(open, can_open());
        const bool busy = preparation.valid();
        EnableWindow(edit, !busy); EnableWindow(list, !busy); EnableWindow(cancel, !busy);
    }
    void replace_rows(const std::optional<Key> &top_key, const std::optional<Key> &focused_key) {
        const auto top = ListView_GetTopIndex(list);
        const auto horizontal = GetScrollPos(list, SB_HORZ);
        updating = true;
        SendMessageW(list, WM_SETREDRAW, FALSE, 0);
        ListView_DeleteAllItems(list);
        if (shown) for (std::size_t index = 0; index < shown->rows.size(); ++index) {
            const auto &row = shown->rows[index];
            auto app = utf16(apk::clean_display_name(row.display_name, row.package_id));
            LVITEMW item{}; item.mask = LVIF_TEXT; item.iItem = static_cast<int>(index); item.pszText = app.data();
            ListView_InsertItem(list, &item);
            auto component = safe(row.component_name.empty() ? row.package_id : row.component_name);
            ListView_SetItemText(list, item.iItem, 1, component.data());
            auto state = std::wstring(disposition(row.disposition));
            ListView_SetItemText(list, item.iItem, 2, state.data());
            if (selected && key(row) == *selected)
                ListView_SetItemState(list, item.iItem, LVIS_SELECTED, LVIS_SELECTED);
            if (focused_key && key(row) == *focused_key)
                ListView_SetItemState(list, item.iItem, LVIS_FOCUSED, LVIS_FOCUSED);
        }
        if (ListView_GetItemCount(list)) {
            auto restored = std::min(top, ListView_GetItemCount(list) - 1);
            if (shown && top_key) for (std::size_t index = 0; index < shown->rows.size(); ++index)
                if (key(shown->rows[index]) == *top_key) { restored = static_cast<int>(index); break; }
            RECT row{};
            if (ListView_GetItemRect(list, 0, &row, LVIR_BOUNDS))
                ListView_Scroll(list, horizontal - GetScrollPos(list, SB_HORZ),
                    (restored - ListView_GetTopIndex(list)) * (row.bottom - row.top));
        }
        SendMessageW(list, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(list, nullptr, TRUE);
        updating = false;
    }
    void choose() {
        if (updating || preparation.valid() || !shown) return;
        const auto index = ListView_GetNextItem(list, -1, LVNI_SELECTED);
        if (index < 0 || static_cast<std::size_t>(index) >= shown->rows.size()) {
            selected.reset(); reviewed_row.reset();
            message = L"No target is selected. Choose an available Activity, review it, then select Open.";
            render();
            return;
        }
        if (!fresh) {
            selected = key(shown->rows[static_cast<std::size_t>(index)]);
            reviewed_row.reset();
            message = L"The displayed list is unavailable or out of date. Select a target again after the automatic check completes.";
            render();
            return;
        }
        reviewed_row = shown->rows[static_cast<std::size_t>(index)];
        selected = key(*reviewed_row);
        message = reviewed_row->disposition == LinkDisposition::candidate ?
            (document ? L"Review the document and recipient below. Open read-only approves this one document and Activity." :
                        L"Review the link and selected Activity below. Open prepares this choice once.") :
            L"This row cannot open the request. Choose an available Activity.";
        render();
    }
    void poll() {
        if (preparation.valid()) {
            if (preparation.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) return;
            auto prepared = preparation.get();
            if (prepared.application) { result = std::move(prepared.application); DestroyWindow(window); return; }
            fresh = false; last_read = 0;
            message = L"Opening was not prepared (" + safe(prepared.code) + L"). Checking again automatically. Select a target again; no automatic retry.";
            reviewed_row.reset();
        }
        if (read.valid()) {
            if (read.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) return;
            auto observation = read.get();
            if (observation.generation == generation) {
                fresh = observation.review.has_value();
                if (observation.review) {
                    std::optional<Key> top_key, focused_key;
                    const auto top = ListView_GetTopIndex(list);
                    const auto focused = ListView_GetNextItem(list, -1, LVNI_FOCUSED);
                    if (shown && top >= 0 && static_cast<std::size_t>(top) < shown->rows.size())
                        top_key = key(shown->rows[static_cast<std::size_t>(top)]);
                    if (shown && focused >= 0 && static_cast<std::size_t>(focused) < shown->rows.size())
                        focused_key = key(shown->rows[static_cast<std::size_t>(focused)]);
                    const bool changed = !shown || shown->rows.size() != observation.review->rows.size() ||
                        !std::equal(shown->rows.begin(), shown->rows.end(), observation.review->rows.begin(),
                            [](const auto &left, const auto &right) {
                                return same_review(left, right) && left.display_name == right.display_name && left.code == right.code;
                            });
                    shown = std::move(observation.review);
                    if (changed) replace_rows(top_key, focused_key);
                    message = shown->rows.empty() ? L"No installed Activity matches this request. Status updates automatically." :
                        (!shown->complete ? L"Some installed apps are unavailable. Choose an available Activity; status updates automatically." :
                         L"Choose an installed Activity and review it below. Status updates automatically.");
                } else message = L"Opening review unavailable (" + safe(observation.code) + L"). Checking again automatically. Your input and previous list are kept.";
            }
        }
        render();
        const auto now = GetTickCount64();
        if (!preparation.valid() && now - last_read >= 1000) {
            last_read = now;
            read = std::async(std::launch::async, [path = options.store, app = options.app_id, uri = draft,
                                                   registered = options.registered_activation, current = generation,
                                                   file_request = file_options, source = document] {
                try {
                    const auto intent = source ? make_open_file_intent(source->info) : make_open_link_intent(uri);
                    if (source) {
                        host::DocumentInfo actual;
                        if (!source->service || source->service->describe(source->info.uri, actual).error != host::FileError::none ||
                            actual != source->info)
                            throw InstallError("AETHER_OPEN_FILE_UNAVAILABLE", "The held document is no longer available for review");
                    }
                    PackageStore store(path);
                    if (registered) {
                        if (!app) throw InstallError("AETHER_LINK_NOT_REGISTERED", "Registered opening requires an app identity");
                        if (file_request)
                            require_registered_file_offer(store, *app, file_request->file, file_request->mime_type);
                        else
                            require_registered_link_offer(store, *app, uri);
                    }
                    return Observation{store.review_link(intent, source ? open_file_policy() : open_link_policy(), app), {}, current};
                } catch (const std::exception &error) { return Observation{{}, error_code(error), current}; }
            });
        }
    }
    void prepare() {
        if (!can_open()) return;
        const auto index = *selected_index();
        const auto review = *shown;
        preparation = std::async(std::launch::async, [path = options.store, registered = options.registered_activation,
                                                       review, index, prior = std::move(read),
                                                       file_request = file_options, source = document]() mutable {
            try {
                if (prior.valid()) prior.get();
                PackageStore store(path);
                if (registered) {
                    if (!review.app_id || !review.intent.data)
                        throw InstallError("AETHER_LINK_NOT_REGISTERED", "Registered opening requires the original app and link");
                    if (file_request)
                        require_registered_file_offer(store, *review.app_id, file_request->file, file_request->mime_type);
                    else
                        require_registered_link_offer(store, *review.app_id, *review.intent.data);
                }
                return Preparation{source ? store.prepare_file(review, index, *source) : store.prepare_link(review, index), {}};
            } catch (const std::exception &error) { return Preparation{{}, error_code(error)}; }
        });
        message = L"Checking the reviewed package and Activity before opening...";
        render();
    }
    HWND control(const wchar_t *type, const wchar_t *caption, DWORD style, int id) {
        const auto kind = std::wstring_view(type);
        const auto created = CreateWindowExW(kind == WC_LISTVIEWW || kind == L"EDIT" ? WS_EX_CLIENTEDGE : 0,
            type, caption, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0, window,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
        if (!created) throw InstallError("AETHER_SHELL_DIALOG", "Cannot create an open-link control");
        SendMessageW(created, WM_SETFONT, reinterpret_cast<WPARAM>(font), FALSE);
        return created;
    }
    int px(int value) const { return MulDiv(value, dpi, 96); }
    void layout() {
        RECT area{}; GetClientRect(window, &area);
        const int width = MulDiv(area.right, 96, dpi), height = MulDiv(area.bottom, 96, dpi);
        const auto place = [&](HWND control, int x, int y, int w, int h) {
            MoveWindow(control, px(x), px(y), px(w), px(h), TRUE);
        };
        place(GetDlgItem(window, 1204), 16, 12, width - 32, 20);
        place(edit, 16, 36, width - 32, 28);
        place(GetDlgItem(window, 1205), 16, 74, width - 32, 20);
        const auto list_height = std::max(100, (height - 230) / 2);
        place(list, 16, 98, width - 32, list_height);
        place(details, 16, 108 + list_height, width - 32, std::max(60, height - list_height - 186));
        const int action_width = document ? 140 : 92;
        place(status, 16, height - 70, width - action_width - 140, 54);
        place(cancel, width - action_width - 120, height - 52, 92, 30);
        place(open, width - action_width - 16, height - 52, action_width, 30);
    }
    void create() {
        INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES}; InitCommonControlsEx(&controls);
        WNDCLASSW cls{}; cls.lpfnWndProc = procedure; cls.hInstance = GetModuleHandleW(nullptr);
        cls.hCursor = LoadCursorW(nullptr, IDC_ARROW); cls.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
        cls.lpszClassName = L"Aether.OpenLink";
        if (!RegisterClassW(&cls) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
            throw InstallError("AETHER_SHELL_DIALOG", "Cannot register the open-link window");
        dpi = static_cast<int>(GetDpiForSystem());
        font = CreateFontW(-MulDiv(10, dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                          DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        window = CreateWindowExW(WS_EX_APPWINDOW | WS_EX_CONTROLPARENT, cls.lpszClassName,
            document ? L"Aether - Open a document read-only" : L"Aether - Open a link",
            WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, px(900), px(640), nullptr, nullptr, cls.hInstance, this);
        if (!window) throw InstallError("AETHER_SHELL_DIALOG", "Cannot create the open-link window");
        control(L"STATIC", document ? L"Document to open read-only:" : L"Link to open:", SS_NOPREFIX, 1204);
        edit = control(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP | (document ? ES_READONLY : 0), uri_id);
        SendMessageW(edit, EM_SETLIMITTEXT, 4096, 0);
        control(L"STATIC", L"Installed Activities (select one explicitly):", SS_NOPREFIX, 1205);
        list = control(WC_LISTVIEWW, L"Installed Activities", LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_TABSTOP, list_id);
        ListView_SetExtendedListViewStyle(list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        for (int index = 0; index < 3; ++index) {
            LVCOLUMNW column{}; column.mask = LVCF_TEXT | LVCF_WIDTH;
            wchar_t app[] = L"App", activity[] = L"Activity / alias", state[] = L"Status";
            column.pszText = index == 0 ? app : index == 1 ? activity : state;
            column.cx = px(index == 0 ? 180 : index == 1 ? 400 : 240);
            ListView_InsertColumn(list, index, &column);
        }
        details = control(L"EDIT", L"", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_TABSTOP, details_id);
        SendMessageW(details, EM_SETLIMITTEXT, 65535, 0);
        status = control(L"STATIC", L"", SS_NOPREFIX, 1206);
        cancel = control(L"BUTTON", L"Cancel", BS_PUSHBUTTON | WS_TABSTOP, IDCANCEL);
        open = control(L"BUTTON", document ? L"&Open read-only" : L"&Open", BS_PUSHBUTTON | WS_TABSTOP, open_id);
        updating = true;
        SetWindowTextW(edit, document ? safe(document->info.display_name).c_str() : std::wstring(draft.begin(), draft.end()).c_str());
        updating = false;
        layout(); render();
        if (!SetTimer(window, timer_id, 100, nullptr)) throw InstallError("AETHER_SHELL_DIALOG", "Cannot observe link review");
        poll(); ShowWindow(window, SW_SHOW); SetFocus(edit);
    }
    static LRESULT CALLBACK procedure(HWND handle, UINT message, WPARAM wparam, LPARAM lparam) {
        auto *self = reinterpret_cast<Chooser *>(GetWindowLongPtrW(handle, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<Chooser *>(reinterpret_cast<CREATESTRUCTW *>(lparam)->lpCreateParams);
            SetWindowLongPtrW(handle, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self)); self->window = handle;
        }
        if (!self) return DefWindowProcW(handle, message, wparam, lparam);
        try {
            if (message == WM_SIZE && self->edit && self->open) { self->layout(); return 0; }
            if (message == WM_TIMER && wparam == timer_id) { self->poll(); return 0; }
            if (message == WM_COMMAND) {
                if (LOWORD(wparam) == uri_id && HIWORD(wparam) == EN_CHANGE && !self->file_options &&
                    !self->updating && !self->preparation.valid()) {
                    std::wstring input(static_cast<std::size_t>(GetWindowTextLengthW(self->edit)) + 1, L'\0');
                    input.resize(static_cast<std::size_t>(GetWindowTextW(self->edit, input.data(), static_cast<int>(input.size()))));
                    self->draft.assign(input.begin(), input.end()); ++self->generation;
                    self->fresh = false; self->reviewed_row.reset(); self->last_read = 0;
                    self->message = L"Link changed. Checking matching installed Activities automatically..."; self->render();
                    return 0;
                }
                if (LOWORD(wparam) == open_id && HIWORD(wparam) == BN_CLICKED) { self->prepare(); return 0; }
                if (LOWORD(wparam) == IDCANCEL && !self->preparation.valid()) { DestroyWindow(handle); return 0; }
            }
            if (message == WM_NOTIFY && reinterpret_cast<NMHDR *>(lparam)->idFrom == list_id) {
                const auto code = reinterpret_cast<NMHDR *>(lparam)->code;
                if (code == LVN_ITEMCHANGED) {
                    const auto *change = reinterpret_cast<const NMLISTVIEW *>(lparam);
                    if ((change->uChanged & LVIF_STATE) && ((change->uOldState ^ change->uNewState) & LVIS_SELECTED))
                        self->choose();
                } else if (code == NM_CLICK || code == NM_RETURN) self->choose();
            }
            if (message == WM_CLOSE) { if (!self->preparation.valid()) DestroyWindow(handle); return 0; }
            if (message == WM_DESTROY) { KillTimer(handle, timer_id); self->closed = true; return 0; }
            if (message == WM_GETMINMAXINFO) {
                auto *limits = reinterpret_cast<MINMAXINFO *>(lparam);
                limits->ptMinTrackSize = {self->px(640), self->px(480)}; return 0;
            }
        } catch (const std::exception &) {
            self->fresh = false; self->last_read = 0;
            self->message = L"Opening review is unavailable. Checking again automatically; your input is kept. Opening is never retried automatically.";
            if (self->status && self->open) { SetWindowTextW(self->status, self->message.c_str()); EnableWindow(self->open, FALSE); }
        }
        return DefWindowProcW(handle, message, wparam, lparam);
    }
    std::optional<security::InstalledActivity> show() {
        create();
        MSG event{};
        while (!closed) {
            const auto received = GetMessageW(&event, nullptr, 0, 0);
            if (received <= 0) { if (!received) PostQuitMessage(static_cast<int>(event.wParam)); break; }
            if (!IsDialogMessageW(window, &event)) { TranslateMessage(&event); DispatchMessageW(&event); }
        }
        return std::move(result);
    }
};
} // namespace
std::optional<security::InstalledActivity> show_link_dialog(const OpenLinkOptions &options) {
    Chooser dialog(options);
    return dialog.show();
}
std::optional<security::InstalledActivity> show_file_dialog(const OpenFileOptions &options) {
    Chooser dialog(options);
    return dialog.show();
}
} // namespace aether::install
