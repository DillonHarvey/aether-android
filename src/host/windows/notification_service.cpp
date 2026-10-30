#include "aether/host/notification_service.hpp"
#include "aether/common/text.hpp"
#include <Windows.h>
#include <algorithm>
#include <cstddef>
#include <new>
#include <roapi.h>
#include <set>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <windows.data.xml.dom.h>
#include <windows.ui.notifications.h>
#include <winstring.h>
#include <wrl/client.h>

namespace aether::host {
namespace {
using Microsoft::WRL::ComPtr;
namespace Toast = ABI::Windows::UI::Notifications;
namespace Xml = ABI::Windows::Data::Xml::Dom;
struct Failure {
    NotificationStatus status;
};
void checked(HRESULT result) {
    if (SUCCEEDED(result))
        return;
    if (result == E_ACCESSDENIED)
        throw Failure{NotificationStatus::denied};
    if (result == E_INVALIDARG)
        throw Failure{NotificationStatus::invalid};
    if (result == E_OUTOFMEMORY || result == HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY) ||
        result == HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_QUOTA))
        throw Failure{NotificationStatus::quota};
    throw Failure{NotificationStatus::unsupported};
}
template <class Function> NotificationStatus guarded(Function &&operation) noexcept {
    try {
        operation();
        return NotificationStatus::ok;
    } catch (const Failure &failure) {
        return failure.status;
    } catch (const std::bad_alloc &) {
        return NotificationStatus::quota;
    } catch (const std::invalid_argument &) {
        return NotificationStatus::invalid;
    } catch (...) {
        return NotificationStatus::unsupported;
    }
}
struct RuntimeScope {
    HRESULT initialized = RoInitialize(RO_INIT_SINGLETHREADED);
    RuntimeScope() noexcept {
        // Maintenance can run on an existing STA or MTA. The failed mode
        // negotiation acquires no reference and never retries a history write.
        if (initialized == RPC_E_CHANGED_MODE)
            initialized = RoInitialize(RO_INIT_MULTITHREADED);
    }
    ~RuntimeScope() {
        if (SUCCEEDED(initialized))
            RoUninitialize();
    }
};
class Text final {
  public:
    explicit Text(std::wstring_view text) {
        checked(WindowsCreateString(text.data(), static_cast<UINT32>(text.size()), &value_));
    }
    ~Text() { WindowsDeleteString(value_); }
    Text(const Text &) = delete;
    Text &operator=(const Text &) = delete;
    HSTRING get() const noexcept { return value_; }

  private:
    HSTRING value_ = nullptr;
};
template <class Interface> ComPtr<Interface> factory(std::wstring_view class_name) {
    const Text name(class_name);
    ComPtr<Interface> result;
    checked(RoGetActivationFactory(name.get(), IID_PPV_ARGS(result.GetAddressOf())));
    return result;
}
bool valid_aumid(std::string_view id) noexcept {
    constexpr std::string_view prefix = "Aether.App.";
    return id.starts_with(prefix) && id.size() == prefix.size() + 32 &&
           std::all_of(id.begin() + static_cast<std::ptrdiff_t>(prefix.size()), id.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}
std::wstring notification_text(std::string_view text, std::size_t maximum, bool channel = false) {
    if (text.size() > maximum || text.find('\0') != std::string_view::npos)
        throw Failure{NotificationStatus::invalid};
    auto value = utf16(text);
    for (const auto unit : value)
        if ((unit < 32 && (channel || (unit != L'\t' && unit != L'\r' && unit != L'\n'))) ||
            (channel && unit >= 0x7f && unit <= 0x9f) ||
            unit == 0xfffe || unit == 0xffff)
            throw Failure{NotificationStatus::invalid};
    return value;
}
template <class Parent, class Child> void append(Parent *parent, Child *child) {
    ComPtr<Xml::IXmlNode> parent_node, child_node, appended;
    checked(parent->QueryInterface(IID_PPV_ARGS(&parent_node)));
    checked(child->QueryInterface(IID_PPV_ARGS(&child_node)));
    checked(parent_node->AppendChild(child_node.Get(), &appended));
}
ComPtr<Xml::IXmlElement> element(Xml::IXmlDocument *document, std::wstring_view name) {
    const Text tag(name);
    ComPtr<Xml::IXmlElement> result;
    checked(document->CreateElement(tag.get(), &result));
    return result;
}
void attribute(Xml::IXmlElement *target, std::wstring_view name, std::wstring_view value) {
    const Text key(name), text(value);
    checked(target->SetAttribute(key.get(), text.get()));
}
void append_text(Xml::IXmlDocument *document, Xml::IXmlElement *parent, std::wstring_view value) {
    auto target = element(document, L"text");
    const Text text(value);
    ComPtr<Xml::IXmlText> node;
    checked(document->CreateTextNode(text.get(), &node));
    append(target.Get(), node.Get());
    append(parent, target.Get());
}
ComPtr<Xml::IXmlDocument> content(std::wstring_view title, std::wstring_view body, std::int32_t id) {
    const Text class_name(RuntimeClass_Windows_Data_Xml_Dom_XmlDocument);
    ComPtr<IInspectable> object;
    checked(RoActivateInstance(class_name.get(), &object));
    ComPtr<Xml::IXmlDocument> document;
    checked(object.As(&document));
    auto toast = element(document.Get(), L"toast");
    attribute(toast.Get(), L"launch", notification_activation_arguments(id));
    auto visual = element(document.Get(), L"visual");
    auto binding = element(document.Get(), L"binding");
    attribute(binding.Get(), L"template", L"ToastGeneric");
    // Guest text is always a DOM text node, never XML, a URI or a command.
    append_text(document.Get(), binding.Get(), title);
    append_text(document.Get(), binding.Get(), body);
    append(visual.Get(), binding.Get());
    append(toast.Get(), visual.Get());
    auto audio = element(document.Get(), L"audio");
    attribute(audio.Get(), L"silent", L"true");
    append(toast.Get(), audio.Get());
    append(document.Get(), toast.Get());
    return document;
}
ComPtr<Toast::IToastNotificationHistory> history() {
    auto manager = factory<Toast::IToastNotificationManagerStatics2>(
        RuntimeClass_Windows_UI_Notifications_ToastNotificationManager);
    ComPtr<Toast::IToastNotificationHistory> result;
    checked(manager->get_History(&result));
    return result;
}
} // namespace
struct HostNotificationService::Impl {
    const std::thread::id owner = std::this_thread::get_id();
    const bool valid, registration_verified;
    const std::wstring aumid;
    std::set<std::int32_t> identifiers;
    Impl(std::string_view identity, bool registered)
        : valid(valid_aumid(identity)), registration_verified(registered), aumid(valid ? utf16(identity) : L"") {}
    void require_ready() const {
        if (!valid)
            throw Failure{NotificationStatus::invalid};
        // A bare AUMID never proves consent or unpackaged persistent-toast
        // registration. Only trusted installed admission can supply this gate.
        if (!registration_verified || std::this_thread::get_id() != owner)
            throw Failure{NotificationStatus::unsupported};
    }
    ComPtr<Toast::IToastNotifier> notifier() const {
        auto manager = factory<Toast::IToastNotificationManagerStatics>(
            RuntimeClass_Windows_UI_Notifications_ToastNotificationManager);
        const Text identity(aumid);
        ComPtr<Toast::IToastNotifier> result;
        checked(manager->CreateToastNotifierWithId(identity.get(), &result));
        return result;
    }
};
HostNotificationService::HostNotificationService(std::string trusted_aumid, bool registration_verified)
    : impl_(std::make_unique<Impl>(trusted_aumid, registration_verified)) {}
HostNotificationService::~HostNotificationService() = default;
NotificationStatus clear_notification_history(std::string_view trusted_aumid) noexcept {
    return guarded([&] {
        if (!valid_aumid(trusted_aumid))
            throw Failure{NotificationStatus::invalid};
        RuntimeScope runtime;
        checked(runtime.initialized);
        auto previous = history();
        const Text identity(utf16(trusted_aumid));
        // This addresses the app's complete Windows history, including toasts
        // from earlier processes. Never use the process-wide Clear() overload.
        checked(previous->ClearWithId(identity.get()));
    });
}
NotificationStatus HostNotificationService::enabled(bool &value) noexcept {
    value = false;
    return guarded([&] {
        impl_->require_ready();
        RuntimeScope runtime;
        checked(runtime.initialized);
        auto target = impl_->notifier();
        Toast::NotificationSetting setting{};
        checked(target->get_Setting(&setting));
        value = setting == Toast::NotificationSetting_Enabled;
    });
}
NotificationStatus HostNotificationService::post(const NotificationText &notification) noexcept {
    return guarded([&] {
        (void)notification_text(notification.channel, 128, true);
        const auto title = notification_text(notification.title, 256);
        const auto body = notification_text(notification.text, 2048);
        impl_->require_ready();
        RuntimeScope runtime;
        checked(runtime.initialized);
        auto target = impl_->notifier();
        Toast::NotificationSetting setting{};
        checked(target->get_Setting(&setting));
        if (setting != Toast::NotificationSetting_Enabled)
            throw Failure{NotificationStatus::denied};
        auto document = content(title, body, notification.id);
        auto maker = factory<Toast::IToastNotificationFactory>(
            RuntimeClass_Windows_UI_Notifications_ToastNotification);
        ComPtr<Toast::IToastNotification> toast;
        checked(maker->CreateToastNotification(document.Get(), &toast));
        ComPtr<Toast::IToastNotification2> identity;
        checked(toast.As(&identity));
        const Text tag(std::to_wstring(notification.id)), group(L"Aether");
        checked(identity->put_Tag(tag.get()));
        checked(identity->put_Group(group.get()));
        if (!impl_->identifiers.contains(notification.id) && impl_->identifiers.size() >= 32)
            throw Failure{NotificationStatus::quota};
        // Allocate ownership before Show: a failed/uncertain post remains tracked
        // and is never retried. Replacement of the same ID does not grow the set.
        impl_->identifiers.insert(notification.id);
        // Same app/tag/group replaces the previous notification through Windows.
        // Do not erase history first: a failed Show must not pre-delete it.
        checked(target->Show(toast.Get()));
    });
}
NotificationStatus HostNotificationService::cancel(std::int32_t id) noexcept {
    return guarded([&] {
        impl_->require_ready();
        RuntimeScope runtime;
        checked(runtime.initialized);
        auto previous = history();
        const Text tag(std::to_wstring(id)), group(L"Aether"), identity(impl_->aumid);
        checked(previous->RemoveGroupedTagWithId(tag.get(), group.get(), identity.get()));
        impl_->identifiers.erase(id);
    });
}
NotificationStatus HostNotificationService::cancel_all() noexcept {
    return guarded([&] {
        impl_->require_ready();
        RuntimeScope runtime;
        checked(runtime.initialized);
        auto previous = history();
        const Text identity(impl_->aumid);
        checked(previous->ClearWithId(identity.get()));
        impl_->identifiers.clear();
    });
}
} // namespace aether::host
