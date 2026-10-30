#include "aether/android/framework.hpp"
#include "aether/common/text.hpp"
#include "aether/apk/inspect.hpp"
#include "bundle.hpp"
#include "preferences.hpp"
#include "component_names.hpp"
#include "intents.hpp"
#include "intent_categories.hpp"
#include "uris.hpp"
#include "aether/host/process_info.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <limits>
#include <set>
#include <exception>

namespace aether::android {
using dex::ObjectId;
using dex::Value;
namespace {
constexpr std::string_view handler_type = "Landroid/os/Handler;", looper_type = "Landroid/os/Looper;";
constexpr std::string_view factory_type = "Landroid/app/AppComponentFactory;";
constexpr std::string_view application_info_type = "Landroid/content/pm/ApplicationInfo;";
constexpr std::string_view package_item_type = "Landroid/content/pm/PackageItemInfo;";
constexpr std::string_view file_type = "Ljava/io/File;";
constexpr std::string_view application_type = "Landroid/app/Application;";
constexpr std::string_view lifecycle_type = "Landroid/app/Application$ActivityLifecycleCallbacks;";
constexpr std::string_view component_callbacks_type = "Landroid/content/ComponentCallbacks;";
constexpr std::string_view component_callbacks2_type = "Landroid/content/ComponentCallbacks2;";
constexpr std::string_view context_impl_type = "Landroid/app/ContextImpl;";
constexpr std::string_view resolver_type = "Landroid/content/ContentResolver;";
constexpr std::string_view session_resolver_type = "Laether/android/ContentResolver;";
constexpr std::string_view content_interface_type = "Landroid/content/ContentInterface;";
constexpr std::string_view activity_thread_type = "Landroid/app/ActivityThread;";
constexpr std::string_view app_bind_type = "Landroid/app/ActivityThread$AppBindData;";
constexpr std::string_view loaded_apk_type = "Landroid/app/LoadedApk;";
constexpr std::string_view configuration_type = "Landroid/content/res/Configuration;";
constexpr std::string_view notification_type = "Landroid/app/Notification;";
constexpr std::string_view notification_builder_type = "Landroid/app/Notification$Builder;";
constexpr std::string_view notification_channel_type = "Landroid/app/NotificationChannel;";
constexpr std::string_view notification_manager_type = "Landroid/app/NotificationManager;";
constexpr std::string_view clipboard_manager_type = "Landroid/content/ClipboardManager;";
constexpr std::string_view compound_button_type = "Landroid/widget/CompoundButton;";
constexpr std::string_view checkbox_type = "Landroid/widget/CheckBox;";
constexpr std::string_view checkable_type = "Landroid/widget/Checkable;";
constexpr std::string_view checked_listener_type = "Landroid/widget/CompoundButton$OnCheckedChangeListener;";
constexpr std::string_view accessibility_node_type = "Landroid/view/accessibility/AccessibilityNodeInfo;";
constexpr std::string_view accessibility_collection_type = "Landroid/view/accessibility/AccessibilityNodeInfo$CollectionInfo;";
constexpr std::string_view accessibility_collection_builder_type = "Landroid/view/accessibility/AccessibilityNodeInfo$CollectionInfo$Builder;";
constexpr std::string_view accessibility_item_type = "Landroid/view/accessibility/AccessibilityNodeInfo$CollectionItemInfo;";
constexpr std::string_view accessibility_provider_type = "Landroid/view/accessibility/AccessibilityNodeProvider;";
constexpr std::string_view accessibility_event_type = "Landroid/view/accessibility/AccessibilityEvent;";
constexpr std::string_view accessibility_record_type = "Landroid/view/accessibility/AccessibilityRecord;";
constexpr std::string_view scroll_view_type = "Landroid/widget/ScrollView;";
constexpr std::string_view edit_text_type = "Landroid/widget/EditText;";
constexpr std::string_view editable_type = "Landroid/text/Editable;";
constexpr std::string_view buffer_type = "Landroid/text/SpannableStringBuilder;";
constexpr std::string_view buffer_mode_type = "Landroid/widget/TextView$BufferType;";
constexpr std::string_view watcher_type = "Landroid/text/TextWatcher;";
constexpr std::string_view spannable_type = "Landroid/text/Spannable;";
constexpr std::string_view input_connection_type = "Landroid/view/inputmethod/InputConnection;";
constexpr std::string_view base_input_connection_type = "Landroid/view/inputmethod/BaseInputConnection;";
constexpr std::string_view editable_input_connection_type = "Lcom/android/internal/inputmethod/EditableInputConnection;";
constexpr std::string_view editor_info_type = "Landroid/view/inputmethod/EditorInfo;";
constexpr std::string_view input_type_type = "Landroid/text/InputType;";
constexpr std::string_view key_callback_type = "Landroid/view/KeyEvent$Callback;";
constexpr std::string_view key_listener_type = "Landroid/view/View$OnKeyListener;";
constexpr std::string_view input_method_manager_type = "Landroid/view/inputmethod/InputMethodManager;";
constexpr std::string_view window_token_type = "Laether/android/WindowToken;";
constexpr std::string_view window_binder_type = "Landroid/os/IBinder;";
constexpr std::string_view drag_event_type = "Landroid/view/DragEvent;";
constexpr std::string_view drag_listener_type = "Landroid/view/View$OnDragListener;";
constexpr std::string_view clip_data_type = "Landroid/content/ClipData;";
constexpr std::string_view clip_item_type = "Landroid/content/ClipData$Item;";
constexpr std::string_view clip_description_type = "Landroid/content/ClipDescription;";
constexpr std::string_view drag_permissions_type = "Landroid/view/DragAndDropPermissions;";
std::optional<std::uint32_t> drag_action_constant(std::string_view owner, std::string_view name) {
    if (owner != drag_event_type) return {};
    if (name == "ACTION_DRAG_STARTED") return 1;
    if (name == "ACTION_DRAG_LOCATION") return 2;
    if (name == "ACTION_DROP") return 3;
    if (name == "ACTION_DRAG_ENDED") return 4;
    if (name == "ACTION_DRAG_ENTERED") return 5;
    if (name == "ACTION_DRAG_EXITED") return 6;
    return {};
}
enum class DragObjectKind { event, data, item, description, permissions };
class DragObjectState final : public dex::HostObjectState {
  public:
    DragObjectKind kind;
    // Event: description, data, Activity. Data: description, item. Item: Uri, text.
    std::array<Value, 3> references{Value::reference(0), Value::reference(0), Value::reference(0)};
    DragAction action = DragAction::started;
    std::uint64_t id = 0, generation = 0;
    float x = 0, y = 0;
    bool result = false, released = false;
    std::string mime, uri, label;
    explicit DragObjectState(DragObjectKind value) : kind(value) {}
    std::span<const Value> values() const noexcept override { return references; }
    std::size_t bytes() const noexcept override {
        return sizeof(*this) + mime.capacity() + uri.capacity() + label.capacity() + 3;
    }
};
class AccessibilityObjectState final : public dex::HostObjectState {
  public:
    enum class Kind { node, collection, item, collection_builder };
    Kind kind;
    std::array<Value, 3> references{Value::reference(0), Value::reference(0), Value::reference(0)};
    AccessibilityCollectionInfo collection;
    AccessibilityCollectionItemInfo item;
    std::uint32_t actions = 0;
    bool selected = false;
    explicit AccessibilityObjectState(Kind value) : kind(value) {}
    std::span<const Value> values() const noexcept override { return references; }
    std::size_t bytes() const noexcept override { return sizeof(*this); }
};
class ViewObjectState final : public dex::HostObjectState {
  public:
    bool selected = false;
    // Checked listener, description, text, watchers, key listener, drag listener.
    std::array<Value, 6> references;
    std::size_t watcher_count = 0;
    std::int32_t mode = 0;
    bool broadcasting = false, ime_consumes_input = false, show_soft_input_on_focus = true;
    std::int32_t batch_depth = 0;
    std::vector<TextEditEvent> text_edit_events;
    std::vector<TextMutation> text_mutations;
    ViewObjectState() { references.fill(Value::reference(0)); }
    std::span<const Value> values() const noexcept override { return references; }
    std::size_t bytes() const noexcept override {
        auto result = sizeof(*this) + text_edit_events.capacity() * sizeof(TextEditEvent) +
            text_mutations.capacity() * sizeof(TextMutation);
        for (const auto &event : text_edit_events) result += (event.text.capacity() + 1) * sizeof(char16_t);
        return result;
    }
};
class EditableState final : public dex::HostObjectState {
  public:
    std::u16string text;
    std::array<Value, 1> references{Value::reference(0)};
    std::int32_t start = -1, end = -1;
    std::int32_t composing_start = -1, composing_end = -1;
    std::span<const Value> values() const noexcept override { return references; }
    std::size_t bytes() const noexcept override { return sizeof(*this) + (text.capacity() + 1) * sizeof(char16_t); }
    std::optional<std::u16string_view> char_sequence_view() const noexcept override { return text; }
};
class EditorInfoState final : public dex::HostObjectState {
  public:
    std::array<Value, 3> references{Value::reference(0), Value::reference(0), Value::reference(0)};
    std::int32_t input_type = 0, ime_options = 0, initial_start = -1, initial_end = -1, initial_caps = 0, field_id = 0;
    std::span<const Value> values() const noexcept override { return references; }
    std::size_t bytes() const noexcept override { return sizeof(*this); }
};
class InputConnectionState final : public dex::HostObjectState {
  public:
    // Target View and BaseInputConnection's PRIVATE fallback Editable. The
    // View-backed subclass resolves getEditableText virtually on its target.
    std::array<Value, 2> references{Value::reference(0), Value::reference(0)};
    bool view_editor = false;
    std::int32_t batch_depth = 0;
    std::span<const Value> values() const noexcept override { return references; }
    std::size_t bytes() const noexcept override { return sizeof(*this); }
};
struct ManagedRoot {
    dex::ManagedRuntime &runtime;
    ObjectId object;
    ManagedRoot(dex::ManagedRuntime &runtime, ObjectId object) : runtime(runtime), object(object) { runtime.retain(object); }
    ~ManagedRoot() { runtime.release(object); }
};
struct ImeBinding {
    ManagedRoot owner, connection, buffer;
    std::uint64_t token = 0, text_revision = 0, selection_revision = 0, composition_revision = 0;
    std::u16string expected_text;
    bool owned_preedit = false;
    bool conversion_interrupted = false;
    ImeBinding(dex::ManagedRuntime &runtime, ObjectId view, ObjectId input, ObjectId editable, std::uint64_t value)
        : owner(runtime, view), connection(runtime, input), buffer(runtime, editable), token(value) {}
};
struct NotificationData {
    std::string channel;
    std::u16string title, text;
    std::int32_t small_icon = 0;
    std::size_t bytes() const noexcept {
        return channel.capacity() + 1 + (title.capacity() + text.capacity() + 2) * sizeof(char16_t);
    }
};
class NotificationState final : public dex::HostObjectState {
  public:
    explicit NotificationState(NotificationData data) : data(std::move(data)) {}
    NotificationData data;
    std::span<const Value> values() const noexcept override { return {}; }
    std::size_t bytes() const noexcept override { return sizeof(*this) + data.bytes(); }
};
class NotificationBuilderState final : public dex::HostObjectState {
  public:
    explicit NotificationBuilderState(ObjectId context) : references_{Value::reference(context)} {}
    NotificationData data;
    std::span<const Value> values() const noexcept override { return references_; }
    std::size_t bytes() const noexcept override { return sizeof(*this) + data.bytes(); }
  private:
    std::array<Value, 1> references_;
};
struct NotificationChannelData {
    std::string id;
    std::u16string name;
    std::int32_t importance = 0;
    bool operator==(const NotificationChannelData &) const = default;
    std::size_t bytes() const noexcept { return id.capacity() + 1 + (name.capacity() + 1) * sizeof(char16_t); }
};
class NotificationChannelState final : public dex::HostObjectState {
  public:
    NotificationChannelData data;
    std::span<const Value> values() const noexcept override { return {}; }
    std::size_t bytes() const noexcept override { return sizeof(*this) + data.bytes(); }
};
class NotificationManagerState final : public dex::HostObjectState {
  public:
    std::vector<NotificationChannelData> channels;
    std::span<const Value> values() const noexcept override { return {}; }
    std::size_t bytes() const noexcept override {
        auto result = sizeof(*this) + channels.capacity() * sizeof(NotificationChannelData);
        for (const auto &channel : channels) result += channel.bytes();
        return result;
    }
};
class ConfigurationState final : public dex::HostObjectState {
  public:
    explicit ConfigurationState(DisplayConfiguration value) : value(value) {}
    DisplayConfiguration value;
    std::span<const Value> values() const noexcept override { return {}; }
    std::size_t bytes() const noexcept override { return sizeof(*this); }
};
// Logical Android paths, never Windows paths or directory authority.
enum class PrivateFileKind { canonical_root, root_alias, relative_path, data_path, lexical_path };
bool private_file_segment(std::u16string_view segment) {
    return !segment.empty() && segment.size() <= 127 && segment.front() != u'.' &&
        segment.back() != u'.' && segment.find(u"..") == std::u16string_view::npos &&
        std::all_of(segment.begin(), segment.end(), [](char16_t c) {
            return (c >= u'a' && c <= u'z') || (c >= u'A' && c <= u'Z') || (c >= u'0' && c <= u'9') ||
                   c == u'_' || c == u'-' || c == u'.';
        });
}
class PrivateFileState final : public dex::HostObjectState {
  public:
    PrivateFileState(std::u16string path, std::string relative, ObjectId context, PrivateFileKind kind)
        : kind(kind), path(std::move(path)), relative(std::move(relative)), references_{Value::reference(context)} {}
    PrivateFileKind kind;
    std::u16string path;
    std::string relative;
    ObjectId context() const noexcept { return references_[0].bits; }
    std::span<const Value> values() const noexcept override { return references_; }
    std::size_t bytes() const noexcept override {
        return sizeof(PrivateFileState) + (path.capacity() + 1) * sizeof(char16_t) + relative.capacity() + 1;
    }
  private:
    std::array<Value, 1> references_;
};
// Shared session lifetime, never a guest handle or an arbitrary host pathname.
struct InputLease {
    host::FileService *files;
    host::DocumentService *documents;
    bool active = true;
    std::array<bool,16> used{};
    std::array<bool,16> document_slots{};
    std::array<int,16> descriptors;
    InputLease(host::FileService *files, host::DocumentService *documents) : files(files), documents(documents) {
        descriptors.fill(-1);
    }
    host::FileResult invalidate() noexcept {
        if(!active)return {0,host::FileError::none};
        active=false;auto *service=files;files=nullptr;
        auto *document_service=documents;documents=nullptr;
        host::FileResult failure{0,host::FileError::none};
        for(std::size_t n=0;n<used.size();++n) {
            const auto descriptor=descriptors[n];descriptors[n]=-1;used[n]=false;
            const auto document=document_slots[n];document_slots[n]=false;
            if(descriptor>=0 && (document ? document_service!=nullptr : service!=nullptr)) {
                const auto closed=document ? document_service->close_document(descriptor) : service->close(descriptor);
                if(closed.error!=host::FileError::none || closed.value!=0)
                    failure={-1,closed.error==host::FileError::none?host::FileError::io:closed.error};
            }
        }
        if(document_service)document_service->revoke_documents();
        return failure;
    }
};
class SessionInput final : public dex::HostInputStream {
  public:
    SessionInput(std::shared_ptr<InputLease> lease,std::size_t slot,std::string snapshot,bool metadata)
        : lease_(std::move(lease)),slot_(slot),snapshot_(std::move(snapshot)),metadata_(metadata),
          bytes_(sizeof(SessionInput)+sizeof(InputLease)+snapshot_.capacity()+1) {}
    ~SessionInput() override { (void)close(); }
    std::size_t bytes() const noexcept override { return bytes_; }
    host::FileResult read(std::span<std::uint8_t> output) noexcept override {
        if(closed_ || !lease_->active)return {-1,host::FileError::bad_descriptor};
        if(metadata_) {
            const auto count=std::min(output.size(),snapshot_.size()-offset_);
            std::copy_n(reinterpret_cast<const std::uint8_t *>(snapshot_.data())+offset_,count,output.data());
            offset_+=count;return {static_cast<std::int64_t>(count),host::FileError::none};
        }
        if(!lease_->files)return {-1,host::FileError::unsupported};
        const auto root=lease_->files->private_root();
        if(root.error!=host::FileError::none)return {-1,root.error};
        if(root.value!=0)return {-1,host::FileError::io};
        const auto result=lease_->files->read(lease_->descriptors[slot_],output);
        if(result.error==host::FileError::none && (result.value<0 || static_cast<std::uint64_t>(result.value)>output.size()))
            return {-1,host::FileError::io};
        return result;
    }
    host::FileResult close() noexcept override {
        if(closed_)return {0,host::FileError::none};
        closed_=true;
        if(!lease_->active)return {0,host::FileError::none};
        const auto descriptor=lease_->descriptors[slot_];lease_->descriptors[slot_]=-1;lease_->used[slot_]=false;
        if(descriptor>=0 && lease_->files)return lease_->files->close(descriptor);
        return {0,host::FileError::none};
    }
    void descriptor(int value) noexcept { lease_->descriptors[slot_]=value; }
  private:
    std::shared_ptr<InputLease> lease_;
    std::size_t slot_,offset_=0;
    const std::string snapshot_;
    const bool metadata_;
    const std::size_t bytes_;
    bool closed_=false;
};
class DocumentInput final : public dex::HostInputStream {
  public:
    DocumentInput(std::shared_ptr<InputLease> lease, std::size_t slot)
        : lease_(std::move(lease)), slot_(slot) {}
    ~DocumentInput() override { (void)close(); }
    std::size_t bytes() const noexcept override { return sizeof(*this) + sizeof(InputLease); }
    host::FileResult read(std::span<std::uint8_t> output) noexcept override {
        if(closed_ || !lease_->active || !lease_->document_slots[slot_])
            return {-1,host::FileError::bad_descriptor};
        if(!lease_->documents)return {-1,host::FileError::denied};
        const auto result=lease_->documents->read_document(lease_->descriptors[slot_],output);
        if(result.error==host::FileError::none && (result.value<0 || static_cast<std::uint64_t>(result.value)>output.size()))
            return {-1,host::FileError::io};
        return result;
    }
    host::FileResult close() noexcept override {
        if(closed_)return {0,host::FileError::none};
        closed_=true;
        if(!lease_->active)return {0,host::FileError::none};
        const auto descriptor=lease_->descriptors[slot_];
        lease_->descriptors[slot_]=-1;lease_->used[slot_]=false;lease_->document_slots[slot_]=false;
        if(descriptor>=0 && lease_->documents)return lease_->documents->close_document(descriptor);
        return {0,host::FileError::none};
    }
    void descriptor(int value) noexcept { lease_->descriptors[slot_]=value; }
  private:
    std::shared_ptr<InputLease> lease_;
    std::size_t slot_;
    bool closed_=false;
};
class LifecycleState final : public dex::HostObjectState {
  public:
    // First16 are lifecycle callbacks; next16 are component callbacks. Unused
    // slots are null references, valid in the traced host-state value span.
    std::array<Value,32> callbacks{};
    LifecycleState() { callbacks.fill(Value::reference(0)); }
    std::size_t count=0;
    std::size_t component_count=0;
    std::array<ObjectId,16> component_owners{};
    std::span<const Value> values()const noexcept override{return callbacks;}
    std::size_t bytes()const noexcept override{return sizeof(*this);}
};
class ActivityIntentState final : public dex::HostObjectState {
  public:
    explicit ActivityIntentState(ObjectId intent = 0) : references{Value::reference(intent)} {}
    std::array<Value, 1> references;
    std::span<const Value> values() const noexcept override { return references; }
    std::size_t bytes() const noexcept override { return sizeof(*this); }
};
class HandlerState final : public dex::HostObjectState {
  public:
    explicit HandlerState(ObjectId looper) : references_{Value::reference(looper)} {}
    ObjectId looper() const noexcept { return references_[0].bits; }
    std::span<const Value> values() const noexcept override { return references_; }
    std::size_t bytes() const noexcept override { return sizeof(HandlerState); }

  private:
    std::array<Value, 1> references_;
};
[[noreturn]] void bad(std::string_view code, std::string message) {
    throw dex::DexError("AETHER_ANDROID_" + std::string(code), std::move(message));
}
std::u16string unicode(std::string_view value) {
    const auto wide = utf16(value);
    return {wide.begin(), wide.end()};
}
std::string narrow(std::u16string_view value) { return utf8(std::wstring(value.begin(), value.end())); }
struct ClassInfo {
    std::string_view name, superclass;
    bool is_abstract = false, is_interface = false;
};
constexpr ClassInfo classes[]{
    {drag_event_type, "Ljava/lang/Object;"},
    {drag_listener_type, "Ljava/lang/Object;", true, true},
    {clip_data_type, "Ljava/lang/Object;"},
    {clip_item_type, "Ljava/lang/Object;"},
    {clip_description_type, "Ljava/lang/Object;"},
    {drag_permissions_type, "Ljava/lang/Object;"},
    {notification_builder_type, "Ljava/lang/Object;"},
    {notification_manager_type, "Ljava/lang/Object;"},
    {clipboard_manager_type, "Landroid/text/ClipboardManager;"},
    {"Landroid/text/ClipboardManager;", "Ljava/lang/Object;", true},
    {factory_type, "Ljava/lang/Object;"},
    {lifecycle_type, "Ljava/lang/Object;", true, true},
    {component_callbacks_type, "Ljava/lang/Object;", true, true},
    {component_callbacks2_type, "Ljava/lang/Object;", true, true},
    {application_info_type, package_item_type},
    {package_item_type, "Ljava/lang/Object;"},
    {intent_type, "Ljava/lang/Object;"},
    {component_type, "Ljava/lang/Object;"},
    {intent_categories_type, "Ljava/lang/Object;"},
    {intent_categories_iterator_type, "Ljava/lang/Object;"},
    {uri_type, "Ljava/lang/Object;", true},
    {abstract_uri_type, uri_type, true},
    {string_uri_type, abstract_uri_type},
    {app_bind_type, "Ljava/lang/Object;"},
    {loaded_apk_type, "Ljava/lang/Object;"},
    {file_type, "Ljava/lang/Object;"},
    {"Landroid/text/TextUtils;", "Ljava/lang/Object;"},
    {input_connection_type, "Ljava/lang/Object;", true, true},
    {input_type_type, "Ljava/lang/Object;", true, true},
    {base_input_connection_type, "Ljava/lang/Object;"},
    {editable_input_connection_type, base_input_connection_type},
    {editor_info_type, "Ljava/lang/Object;"},
    {input_method_manager_type, "Ljava/lang/Object;"},
    {window_binder_type, "Ljava/lang/Object;", true, true},
    {window_token_type, "Ljava/lang/Object;"},
    {context_impl_type, "Landroid/content/Context;"},
    {activity_thread_type, "Ljava/lang/Object;"},
    {"Landroid/content/Context;", "Ljava/lang/Object;", true},
    {"Landroid/content/ContextWrapper;", "Landroid/content/Context;"},
    {"Landroid/view/ContextThemeWrapper;", "Landroid/content/ContextWrapper;"},
    {"Landroid/app/Activity;", "Landroid/view/ContextThemeWrapper;"},
    {"Landroid/app/Application;", "Landroid/content/ContextWrapper;"},
    {base_bundle_type, "Ljava/lang/Object;"},
    {bundle_type, base_bundle_type},
    {"Landroid/os/Parcelable;", "Ljava/lang/Object;", true, true},
    {"Landroid/os/SystemClock;", "Ljava/lang/Object;"},
    {"Landroid/os/Process;", "Ljava/lang/Object;"},
    {handler_type, "Ljava/lang/Object;"},
    {looper_type, "Ljava/lang/Object;"},
    {"Landroid/view/InputEvent;", "Ljava/lang/Object;", true},
    {"Landroid/view/MotionEvent;", "Landroid/view/InputEvent;"},
    {"Landroid/view/KeyEvent;", "Landroid/view/InputEvent;"},
    {key_callback_type, "Ljava/lang/Object;", true, true},
    {key_listener_type, "Ljava/lang/Object;", true, true},
    {"Landroid/content/res/Resources;", "Ljava/lang/Object;"},
    {configuration_type, "Ljava/lang/Object;"},
    {"Landroid/content/res/Resources$NotFoundException;", "Ljava/lang/RuntimeException;"},
    {"Landroid/content/pm/PackageManager;", "Ljava/lang/Object;", true},
    {"Laether/android/PackageManager;", "Landroid/content/pm/PackageManager;"},
    {"Landroid/view/View;", "Ljava/lang/Object;"},
    {accessibility_node_type, "Ljava/lang/Object;"},
    {accessibility_collection_type, "Ljava/lang/Object;"},
    {accessibility_collection_builder_type, "Ljava/lang/Object;"},
    {accessibility_item_type, "Ljava/lang/Object;"},
    {accessibility_provider_type, "Ljava/lang/Object;", true},
    {accessibility_record_type, "Ljava/lang/Object;"},
    {accessibility_event_type, accessibility_record_type},
    {"Landroid/view/ViewGroup;", "Landroid/view/View;", true},
    {"Landroid/widget/LinearLayout;", "Landroid/view/ViewGroup;"},
    {"Landroid/widget/FrameLayout;", "Landroid/view/ViewGroup;"},
    {scroll_view_type, "Landroid/widget/FrameLayout;"},
    {edit_text_type, "Landroid/widget/TextView;"},
    {buffer_type, "Ljava/lang/Object;"},
    {buffer_mode_type, "Ljava/lang/Enum;"},
    {editable_type, "Ljava/lang/Object;", true, true},
    {spannable_type, "Ljava/lang/Object;", true, true},
    {"Landroid/text/Spanned;", "Ljava/lang/Object;", true, true},
    {"Landroid/text/GetChars;", "Ljava/lang/Object;", true, true},
    {"Landroid/text/NoCopySpan;", "Ljava/lang/Object;", true, true},
    {watcher_type, "Ljava/lang/Object;", true, true},
    {"Landroid/text/Selection;", "Ljava/lang/Object;"},
    {"Landroid/widget/TextView;", "Landroid/view/View;"},
    {"Landroid/widget/Button;", "Landroid/widget/TextView;"},
    {compound_button_type, "Landroid/widget/Button;", true},
    {checkbox_type, compound_button_type},
    {checkable_type, "Ljava/lang/Object;", true, true},
    {checked_listener_type, "Ljava/lang/Object;", true, true},
    {"Landroid/view/View$OnClickListener;", "Ljava/lang/Object;", true, true}};
std::optional<dex::HostClass> class_metadata(std::string_view type) {
    if (const auto preferences = preferences_class(type)) return preferences;
    static constexpr std::array window_token_interfaces{window_binder_type};
    if (type == window_token_type)
        return dex::HostClass{"Ljava/lang/Object;", window_token_interfaces, false, false, true, true};
    static constexpr std::array resolver_interfaces{content_interface_type};
    if(type==content_interface_type)return dex::HostClass{"Ljava/lang/Object;",{},true,true,false,true};
    if(type==resolver_type)return dex::HostClass{"Ljava/lang/Object;",resolver_interfaces,true,false,true,true};
    if(type==session_resolver_type)return dex::HostClass{resolver_type,{},false,false,true,true};
    static constexpr std::array<std::string_view, 2> bundle_interfaces{"Ljava/lang/Cloneable;",
                                                                       "Landroid/os/Parcelable;"};
    static constexpr std::array component_parent{component_callbacks_type};
    static constexpr std::array component2_parent{component_callbacks2_type};
    static constexpr std::array activity_interfaces{component_callbacks2_type, key_callback_type};
    static constexpr std::array view_interfaces{key_callback_type};
    static constexpr std::array<std::string_view, 1> notification_interfaces{"Landroid/os/Parcelable;"};
    if (type == drag_event_type || type == clip_data_type || type == clip_description_type || type == drag_permissions_type)
        return dex::HostClass{"Ljava/lang/Object;", notification_interfaces, false, false, true, true};
    static constexpr std::array<std::string_view, 2> intent_interfaces{
        "Landroid/os/Parcelable;", "Ljava/lang/Cloneable;"};
    static constexpr std::array<std::string_view, 3> component_interfaces{
        "Landroid/os/Parcelable;", "Ljava/lang/Cloneable;", "Ljava/lang/Comparable;"};
    if (type == intent_type)
        return dex::HostClass{"Ljava/lang/Object;", intent_interfaces, false, false, true, true};
    if (type == component_type)
        return dex::HostClass{"Ljava/lang/Object;", component_interfaces, false, false, false, true};
    static constexpr std::array<std::string_view, 2> category_interfaces{
        "Ljava/util/Collection;", "Ljava/util/Set;"};
    static constexpr std::array<std::string_view, 1> category_iterator_interfaces{"Ljava/util/Iterator;"};
    static constexpr std::array<std::string_view, 2> uri_interfaces{"Landroid/os/Parcelable;", "Ljava/lang/Comparable;"};
    if (type == uri_type)
        return dex::HostClass{"Ljava/lang/Object;", uri_interfaces, true, false, false, true};
    if (type == abstract_uri_type)
        return dex::HostClass{uri_type, {}, true, false, false, true};
    if (type == string_uri_type)
        return dex::HostClass{abstract_uri_type, {}, false, false, false, true};
    if (type == intent_categories_type)
        return dex::HostClass{"Ljava/lang/Object;", category_interfaces, false, false, false, true};
    if (type == intent_categories_iterator_type)
        return dex::HostClass{"Ljava/lang/Object;", category_iterator_interfaces, false, false, true, true};
    static constexpr std::array checkable_interfaces{checkable_type};
    static constexpr std::array<std::string_view, 4> editable_interfaces{
        "Ljava/lang/CharSequence;", "Landroid/text/GetChars;", spannable_type, "Ljava/lang/Appendable;"};
    static constexpr std::array<std::string_view, 5> buffer_interfaces{
        "Ljava/lang/CharSequence;", "Landroid/text/GetChars;", spannable_type, editable_type, "Ljava/lang/Appendable;"};
    static constexpr std::array<std::string_view, 1> spanned_interfaces{"Ljava/lang/CharSequence;"};
    static constexpr std::array<std::string_view, 1> spannable_interfaces{"Landroid/text/Spanned;"};
    static constexpr std::array<std::string_view, 1> watcher_interfaces{"Landroid/text/NoCopySpan;"};
    static constexpr std::array input_connection_interfaces{input_connection_type};
    if (type == base_input_connection_type)
        return dex::HostClass{"Ljava/lang/Object;", input_connection_interfaces, false, false, true, true};
    static constexpr std::array editor_info_interfaces{input_type_type, std::string_view{"Landroid/os/Parcelable;"}};
    if (type == editor_info_type)
        return dex::HostClass{"Ljava/lang/Object;", editor_info_interfaces, false, false, true, true};
    if (type == buffer_type) return dex::HostClass{"Ljava/lang/Object;", buffer_interfaces, false, false, true, true};
    if (type == editable_type) return dex::HostClass{"Ljava/lang/Object;", editable_interfaces, true, true, true, true};
    if (type == spannable_type) return dex::HostClass{"Ljava/lang/Object;", spannable_interfaces, true, true, true, true};
    if (type == "Landroid/text/Spanned;" || type == "Landroid/text/GetChars;")
        return dex::HostClass{"Ljava/lang/Object;", spanned_interfaces, true, true, true, true};
    if (type == watcher_type) return dex::HostClass{"Ljava/lang/Object;", watcher_interfaces, true, true, true, true};
    if (type == compound_button_type)
        return dex::HostClass{"Landroid/widget/Button;", checkable_interfaces, true, false, true, true};
    if (type == notification_type || type == notification_channel_type)
        return dex::HostClass{"Ljava/lang/Object;", notification_interfaces, false, false, true, true};
    if (type == component_callbacks2_type)
        return dex::HostClass{"Ljava/lang/Object;", component_parent, true, true, true, true};
    if (type == application_type)
        return dex::HostClass{"Landroid/content/ContextWrapper;", component2_parent, false, false, true, true};
    if (type == "Landroid/app/Activity;")
        return dex::HostClass{"Landroid/view/ContextThemeWrapper;", activity_interfaces, false, false, true, true};
    if (type == "Landroid/view/View;")
        return dex::HostClass{"Ljava/lang/Object;", view_interfaces, false, false, true, true};
    if (type == "Landroid/os/Build$VERSION;")
        return dex::HostClass{"Ljava/lang/Object;", {}, false, false, true, true};
    if (type == bundle_type)
        return dex::HostClass{base_bundle_type, bundle_interfaces, false, false, true, true};
    if (type == accessibility_node_type)
        return dex::HostClass{"Ljava/lang/Object;", bundle_interfaces, false, false, true, true};
    if (type == accessibility_event_type)
        return dex::HostClass{accessibility_record_type, bundle_interfaces, false, false, true, true};
    for (const auto &entry : classes)
        if (entry.name == type)
            return dex::HostClass{entry.superclass, {}, entry.is_abstract, entry.is_interface, type != file_type, true};
    return {};
}
std::optional<std::uint32_t> accessibility_constant(std::string_view owner, std::string_view name) {
    if (owner == accessibility_node_type) {
        if (name == "ACTION_SELECT") return 4;
        if (name == "ACTION_CLEAR_SELECTION") return 8;
    }
    if (owner == accessibility_collection_type) {
        if (name == "SELECTION_MODE_NONE") return 0;
        if (name == "SELECTION_MODE_SINGLE") return 1;
        if (name == "SELECTION_MODE_MULTIPLE") return 2;
        if (name == "UNDEFINED") return 0xffffffffu;
    }
    if (owner == accessibility_event_type && name == "TYPE_WINDOW_CONTENT_CHANGED") return 2048;
    if (owner == accessibility_provider_type && name == "HOST_VIEW_ID") return 0xffffffffu;
    return {};
}
bool api_static(const ApiSupport &api) {
    if ((api.owner == accessibility_node_type || api.owner == accessibility_collection_type ||
         api.owner == accessibility_item_type) && api.name == "obtain") return true;
    if (api.owner == clip_data_type && api.name == "newPlainText") return true;
    if (api.owner == base_input_connection_type)
        return api.name == "getComposingSpanStart" || api.name == "getComposingSpanEnd" ||
               api.name == "removeComposingSpans" || api.name == "setComposingSpans";
    if (api.owner == uri_type) return api.name == "parse" || api.name == "decode";
    if (api.owner == component_type)
        return api.name == "createRelative" || api.name == "unflattenFromString" ||
               (api.name == "flattenToShortString" && api.signature.starts_with("(L"));
    return api.owner == "Landroid/text/Selection;" || api.owner == "Ljava/lang/System;" || api.owner == "Landroid/os/SystemClock;" ||
           api.owner == "Landroid/text/TextUtils;" ||
           (api.owner == "Landroid/os/Process;" && api.name == "getStartUptimeMillis") ||
           (api.owner == activity_thread_type &&
            (api.name == "currentApplication" || api.name == "currentActivityThread")) ||
           (api.owner == application_type && api.name == "getProcessName") ||
           (api.owner == looper_type && (api.name == "getMainLooper" || api.name == "myLooper"));
}
std::optional<std::uint32_t> uri_api_flags(const ApiSupport &api) {
    if(api.owner==resolver_type && (api.name=="getType" || api.name=="openInputStream"))return 0x11u;
    if(api.name=="getContentResolver")return api.owner=="Landroid/content/Context;" ? 0x401u : 1u;
    if (api.owner == uri_type) {
        if (api_static(api)) return 9u;
        if (api.name == "isHierarchical" || api.name == "isRelative" || api.name == "toString" ||
            api.name.starts_with("get")) return 0x401u;
        return 1u;
    }
    if (api.owner == abstract_uri_type) return api.name == "getEncodedUserInfo" ? 0x11u : 1u;
    if (api.owner == string_uri_type) return 1u;
    return {};
}
bool public_api(const ApiSupport &api) {
    if (api.name == "<init>" || api.name == "<clinit>")
        return false;
    if (api.owner == "Landroid/content/ContextWrapper;" && api.name == "attachBaseContext")
        return false;
    if (api.owner == "Landroid/app/Activity;" && api.name.starts_with("on") &&
        api.name != "onWindowFocusChanged" && api.name != "onKeyDown" && api.name != "onKeyUp")
        return false; // These Activity lifecycle callbacks are protected.
    if (api.owner == "Landroid/widget/TextView;" &&
        (api.name == "onTextChanged" || api.name == "onSelectionChanged")) return false;
    if (api.owner == "Landroid/view/View;" && api.name == "dispatchSetSelected") return false;
    return true;
}
std::string_view component_method_owner(std::string_view owner,std::string_view name) {
    if ((owner == uri_type || owner == abstract_uri_type) && name == "describeContents")
        return "Landroid/os/Parcelable;";
    if (owner == editable_type && (name == "length" || name == "charAt" || name == "subSequence" || name == "toString"))
        return "Ljava/lang/CharSequence;";
    if (owner == editable_type && name == "getChars") return "Landroid/text/GetChars;";
    if(owner==component_callbacks2_type && (name=="onConfigurationChanged" || name=="onLowMemory"))
        return component_callbacks_type;
    return owner;
}
std::vector<std::string> api_parameters(std::string_view signature) {
    std::vector<std::string> result;
    for (std::size_t at = 1; at < signature.size() && signature[at] != ')';) {
        const auto start = at;
        while (at < signature.size() && signature[at] == '[') ++at;
        if (at >= signature.size()) bad("API_METADATA", "Invalid API parameter descriptor");
        if (signature[at] == 'L') {
            at = signature.find(';', at);
            if (at == std::string_view::npos) bad("API_METADATA", "Invalid API object descriptor");
        }
        ++at;
        result.emplace_back(signature.substr(start, at - start));
    }
    return result;
}
const ApiSupport &resolve(const dex::DexImage &image, dex::Index index) {
    const auto &method = image.methods.at(index);
    const auto &signature = image.prototypes.at(method.prototype).descriptor;
    auto owner = std::string_view(image.types.at(method.owner));
    for (unsigned depth = 0; depth < 256; ++depth) {
        owner = component_method_owner(preferences_owner(owner), method.name);
        for (const auto &api : api_registry())
            if (api.owner == owner && api.name == method.name && api.signature == signature) {
                if (api.status == ApiStatus::not_started || api.status == ApiStatus::stub)
                    bad("API_UNSUPPORTED", std::string(owner) + "." + method.name + signature + ": " +
                                               std::string(api.behavior));
                return api;
            }
        // Constructors are never inherited.
        if (method.name == "<init>")
            break;
        if (const auto *definition = image.definition(owner)) {
            if (definition->superclass == dex::no_index)
                break;
            owner = image.types.at(definition->superclass);
        } else if (const auto info = class_metadata(owner))
            owner = info->superclass;
        else
            break;
    }
    bad("API_UNSUPPORTED",
        image.types.at(method.owner) + "." + method.name + signature + " is not implemented");
}
} // namespace
struct ActivitySession::Impl {
    dex::ManagedRuntime &runtime;
    std::string package, activity_type;
    apk::ResourceTable resources;
    DisplayConfiguration configuration;
    const host::TimeService *time;
    host::FileService *files;
    host::NotificationService *notifications;
    host::ClipboardService *clipboard;
    std::shared_ptr<InputLease> input_lease;
    std::unique_ptr<PreferencesService> preferences;
    bool input_cleanup_failed = false;
    bool terminal_cleanup = false;
    ObjectId files_directory = 0;
    ObjectId application = 0, resource_object = 0, package_manager = 0, content_resolver = 0, activity = 0, content = 0;
    ObjectId main_looper = 0, base_context = 0, activity_thread = 0;
    ObjectId configuration_object = 0;
    ObjectId notification_manager = 0;
    ObjectId clipboard_manager = 0, clipboard_name = 0, plain_text_mime = 0;
    ObjectId input_method_manager = 0, window_token = 0, input_method_name = 0;
    std::uint64_t soft_input_revision = 0, window_generation = 1;
    std::array<ViewActivation, view_activation_limit> view_activations{};
    std::size_t view_activation_count = 0;
    std::uint64_t view_activation_revision = 0;
    enum class ActivationFailure { none, invalid, quota, exhausted };
    ActivationFailure view_activation_failure = ActivationFailure::none;
    std::array<SoftInputRequest, 32> soft_input_queue{};
    std::size_t soft_input_count = 0;
    SoftInputObserver soft_input_observer;
    bool notifying_soft_input = false;
    std::exception_ptr soft_input_observer_failure;
    ObjectId bound_application = 0, loaded_package = 0, data_directory = 0;
    ObjectId application_info = 0, package_name = 0, component_factory = 0, selected_loader = 0, launch_intent = 0;
    std::string application_type_name;
    bool factory_constructed = false, selecting_loader = false, factory_application_active = false, factory_activity_active = false;
    enum class ApplicationStage { empty, constructing, attaching, creating, ready, failed };
    ApplicationStage application_stage = ApplicationStage::empty;
    bool application_constructed = false, application_attached = false, activity_attached = false;
    bool application_published = false;
    std::vector<ObjectId> owned;
    std::map<ObjectId, ViewState> views;
    struct AccessibilityMetadata {
        std::optional<AccessibilityCollectionInfo> collection;
        std::optional<AccessibilityCollectionItemInfo> item;
        ObjectId owner = 0;
        bool node_provider_present = false;
        std::uint32_t actions = 0;
        std::optional<bool> selection_required;
    };
    std::map<ObjectId, AccessibilityMetadata> accessibility_metadata;
    std::uint64_t accessibility_attempt = 0, accessibility_invalidation = 1;
    AccessibilityMetadataStatus accessibility_status = AccessibilityMetadataStatus::none;
    ObjectId accessibility_activity = 0, accessibility_content = 0;
    std::uint64_t accessibility_generation = 0, accessibility_view_revision = 0, accessibility_source_invalidation = 0;
    bool preparing_accessibility = false;
    struct AccessibilityProviderQuery {
        ObjectId view, thread;
        bool present;
        AccessibilityProviderQuery *previous;
    };
    AccessibilityProviderQuery *accessibility_provider_query = nullptr;
    std::map<ObjectId, ViewBounds> unscrolled_bounds;
    std::array<ObjectId, 3> buffer_modes{};
    std::size_t text_depth = 0;
    struct PendingCompositionRemoval;
    PendingCompositionRemoval *pending_composition = nullptr;
    struct ConversionObservation;
    ConversionObservation *conversion_observation = nullptr;
    std::unique_ptr<ImeBinding> ime;
    std::uint64_t last_ime_token = 0;
    std::uint64_t text_edit_sequence = 0;
    TextEditObserver text_edit_observer;
    bool notifying_text_edit = false;
    std::exception_ptr text_edit_observer_failure;
    std::vector<std::string> events;
    std::array<std::u16string,2> standard_output;
    std::size_t output_characters=0;
    FrameworkMetrics metrics;
    struct InputData {
        std::optional<PointerInput> pointer;
        std::optional<KeyInput> key;
    };
    std::map<ObjectId, InputData> input_events;
    struct DragSequence {
        std::uint64_t id = 0, generation = 0;
        host::DropPayloadKind kind = host::DropPayloadKind::file;
        ObjectId owner = 0, root = 0, description = 0, target = 0;
        std::string mime;
        std::vector<ObjectId> recipients, interested;
        float x = 0, y = 0;
        bool dropped = false, result = false;
    };
    std::optional<DragSequence> drag_sequence;
    std::uint64_t last_drag_id = 0;
    ObjectId active_drag_event = 0;
    bool dispatching_drag = false;
    struct DropGrant { std::uint64_t id, generation; std::string uri; ObjectId permission; };
    std::vector<DropGrant> drop_grants;
    ObjectId pointer_target = 0, key_target = 0, focused_view = 0;
    std::uint32_t pointer_id = 0, held_key = 0;
    std::int32_t orientation_request = -1;
    std::uint32_t config_changes = 0, target_sdk = 35, changing_configuration = 0;
    std::uint32_t pending_configuration = 0;
    Lifecycle state = Lifecycle::empty;
    std::string_view callback;
    bool called_super = false, active = true, visible = true, focused = false, attached = false;
    bool suspended = false, window_focused = false;
    std::uint64_t lifecycle_revision=0;
    bool application_configuration_delivery = false;
    explicit Impl(dex::ManagedRuntime &runtime, std::string package, apk::ResourceTable resources,
                  const host::TimeService *time, host::FileService *files, DisplayConfiguration configuration,
                  host::NotificationService *notifications, host::DocumentService *documents, host::ClipboardService *clipboard)
        : runtime(runtime), package(std::move(package)), resources(std::move(resources)), configuration(configuration), time(time), files(files), notifications(notifications), clipboard(clipboard), input_lease(std::make_shared<InputLease>(files,documents)) {
        if (!configuration.valid())
            bad("CONFIGURATION", "Invalid virtual display configuration");
        if (this->package.empty() ||
            (!this->resources.package_name().empty() && this->resources.package_name() != this->package))
            bad("PACKAGE", "Manifest and compiled resource packages disagree");
    }
    ObjectId own(ObjectId object) {
        runtime.retain(object);
        try {
            owned.push_back(object);
        } catch (...) {
            runtime.release(object);
            throw;
        }
        return object;
    }
    void disown(ObjectId object) {
        const auto found = std::find(owned.begin(), owned.end(), object);
        if (found == owned.end()) bad("ACTIVITY_STATE", "Activity-owned root is missing");
        runtime.release(object);
        owned.erase(found);
    }
    void clear_soft_input_requests() noexcept {
        for (std::size_t index = 0; index < soft_input_count; ++index)
            runtime.release(soft_input_queue[index].view);
        soft_input_count = 0;
    }
    void retire_soft_input_window() {
        clear_soft_input_requests();
        if (window_token) {
            const auto retired = std::exchange(window_token, 0);
            disown(retired);
        }
        if (window_generation == UINT64_MAX)
            bad("SOFT_INPUT_WINDOW_LIMIT", "Soft input window generation exhausted");
        ++window_generation;
    }
    bool soft_input_window_ready() const {
        return attached && activity_attached && activity && state == Lifecycle::resumed &&
            active && visible && !suspended && window_focused && focused;
    }
    bool soft_input_editor_ready(ObjectId object, bool idle) {
        return soft_input_window_ready() && object && views.contains(object) && in_tree(object) &&
            view(object).kind == ViewKind::edit_text && enabled(object) && focused_view == object &&
            (!idle || (!pointer_target && !key_target));
    }
    ObjectId input_method_service() {
        if (!input_method_manager)
            input_method_manager = own(runtime.new_object(input_method_manager_type));
        return input_method_manager;
    }
    ObjectId attached_window_token(ObjectId object) {
        if (!activity_attached || !activity || !object || !views.contains(object) || !in_tree(object)) return 0;
        if (!window_token) window_token = own(runtime.new_object(window_token_type));
        return window_token;
    }
    bool enqueue_soft_input(ObjectId object, bool show, bool implicit) {
        if (!soft_input_window_ready() || (show && !soft_input_editor_ready(object, false)) ||
            soft_input_count == soft_input_queue.size() || soft_input_revision == UINT64_MAX) return false;
        if (show && implicit && !view_state(object).show_soft_input_on_focus) return false;
        runtime.retain(object);
        soft_input_queue[soft_input_count++] = {++soft_input_revision, window_generation, object, show, implicit};
        return true; // Queue acceptance, never native visibility.
    }
    Value soft_input_api(const ApiSupport &api, std::span<const Value> args) {
        if (args.empty() || args[0].kind != dex::ValueKind::reference || !args[0].bits)
            runtime.raise("Ljava/lang/NullPointerException;");
        if (args[0].bits != input_method_manager)
            bad("SOFT_INPUT_SERVICE", "InputMethodManager is not this session's canonical service");
        if ((api.name != "showSoftInput" && api.name != "hideSoftInputFromWindow") ||
            api.signature.find("ResultReceiver") != api.signature.npos)
            runtime.raise("Ljava/lang/UnsupportedOperationException;", u"Soft input overload is outside the supported flag-zero profile");
        if (args.size() != 3 || args[1].kind != dex::ValueKind::reference || args[2].kind != dex::ValueKind::word)
            bad("SOFT_INPUT_ARGUMENT", "Soft input request arguments do not match their descriptor");
        if (args[2].bits)
            runtime.raise("Ljava/lang/UnsupportedOperationException;", u"Soft input forced, implicit and conditional flags are unsupported");
        const auto object = args[1].bits;
        if (api.name == "showSoftInput") {
            if (!object) return Value::word(0);
            if (!runtime.assignable(object, "Landroid/view/View;"))
                runtime.raise("Ljava/lang/IllegalArgumentException;", u"Soft input target is not a View");
            return Value::word(enqueue_soft_input(object, true, false));
        }
        if (!object || object != window_token || !runtime.assignable(object, window_binder_type)) return Value::word(0);
        return Value::word(enqueue_soft_input(0, false, false));
    }
    void require_private_root() {
        const auto result = files ? files->private_root()
                                  : host::FileResult{-1, host::FileError::unsupported};
        if (result.error == host::FileError::denied) {
            ++metrics.denied_permissions;
            runtime.raise("Ljava/lang/SecurityException;", u"Aether private-files permission is denied");
        }
        if (result.error != host::FileError::none || result.value != 0)
            bad("STORAGE_UNAVAILABLE", "Broker private-file root is unavailable");
    }
    std::u16string logical_data_path() const {
        if (package.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.") !=
            std::string::npos)
            bad("PACKAGE", "Package cannot identify a logical private-file root");
        return unicode("/data/user/0/" + package);
    }
    ObjectId private_root() {
        require_private_root(); // Never cache authorization or filesystem readiness.
        if (!files_directory) {
            auto root_state = std::make_unique<PrivateFileState>(logical_data_path() + u"/files", "", base_context, PrivateFileKind::canonical_root);
            const auto object = runtime.new_object(file_type);
            runtime.set_host_state(object, std::move(root_state));
            files_directory = own(object);
        }
        return files_directory;
    }
    ObjectId app_info() {
        if (!application_info) application_info = own(runtime.new_object(application_info_type));
        return application_info;
    }
    ObjectId package_string() {
        if (!package_name) package_name = own(runtime.new_string(unicode(package)));
        return package_name;
    }
    void bind_package() {
        // This binding exists before Application construction/publication and owns
        // the session package/resources/base Context already held by this Impl.
        loaded_package = own(runtime.new_object(loaded_apk_type));
        bound_application = own(runtime.new_object(app_bind_type));
        (void)current_activity_thread();
    }
    ObjectId current_activity_thread() {
        if (!activity_thread)
            activity_thread = own(runtime.new_object(activity_thread_type));
        return activity_thread;
    }
    bool extends_application(std::string_view type) const {
        for (unsigned depth = 0; depth < 256; ++depth) {
            if (type == application_type)
                return true;
            const auto *definition = runtime.class_definition(type);
            if (!definition || definition->superclass == dex::no_index)
                return false;
            type = runtime.image().types.at(definition->superclass);
        }
        bad("CLASS_LIMIT", "Application hierarchy exceeds limit");
    }
    bool extends_framework(std::string_view type, std::string_view base) const {
        for (unsigned depth = 0; depth < 256; ++depth) {
            if (type == base) return true;
            const auto *definition = runtime.class_definition(type);
            if (!definition || definition->superclass == dex::no_index) return false;
            type = runtime.image().types.at(definition->superclass);
        }
        bad("CLASS_LIMIT", "Component factory hierarchy exceeds limit");
    }
    std::u16string component_name(std::string_view descriptor) const {
        if (descriptor.size() < 3 || descriptor.front() != 'L' || descriptor.back() != ';')
            bad("COMPONENT", "Component descriptor is invalid");
        std::string name(descriptor.substr(1, descriptor.size()-2));
        std::replace(name.begin(), name.end(), '/', '.');
        return unicode(name);
    }
    ObjectId construct_application() {
        if (application || application_stage != ApplicationStage::constructing)
            bad("APPLICATION_CONSTRUCTOR", "Application construction is not active or already occurred");
        application = own(runtime.new_object(application_type_name));
        runtime.set_host_state(application,std::make_unique<LifecycleState>());
        if (application_type_name == application_type)
            application_constructed = true;
        else {
            const std::array args{Value::reference(application)};
            (void)runtime.invoke(runtime.lookup(application_type_name, "<init>", "()V", false), args);
            if (!application_constructed)
                bad("APPLICATION_CONSTRUCTOR", "Application constructor did not initialize its framework base");
        }
        return application;
    }
    ObjectId construct_activity() {
        if (activity || !factory_activity_active)
            bad("ACTIVITY_CONSTRUCTOR", "Activity construction is not active or already occurred");
        activity = own(runtime.new_object(activity_type));
        if (!runtime.assignable(activity, "Landroid/app/Activity;"))
            bad("ACTIVITY", "Launch class does not extend Activity");
        // Activity.mIntent is null during construction. Framework attach
        // supplies the real launch record after the constructor returns.
        runtime.set_host_state(activity, std::make_unique<ActivityIntentState>());
        const std::array args{Value::reference(activity)};
        (void)runtime.invoke(runtime.lookup(activity_type, "<init>", "()V", false), args);
        return activity;
    }
    ObjectId main_loop() {
        if (!main_looper)
            main_looper = own(runtime.new_object(looper_type));
        return main_looper;
    }
    void cleanup(bool report_input_errors=true) {
        if (!input_events.empty() || dispatching_drag)
            bad("INPUT_REENTRANT", "Cannot dispose framework during input dispatch");
        clear_soft_input_requests();
        clear_drag_sequence();
        std::exception_ptr drag_error;
        if (terminal_cleanup) drop_grants.clear();
        else try { release_drop_grants(); } catch (...) { drag_error = std::current_exception(); }
        window_token = 0; // owned roots are released below, including the retired token.
        std::exception_ptr ime_error;
        if (terminal_cleanup) ime.reset(); // RAII roots only; no virtual close or conversion edits.
        else try { retire_ime(true); } catch (...) { ime_error = std::current_exception(); }
        runtime.close_tasks();
        runtime.close_main_callbacks();
        std::exception_ptr preferences_error;
        if (preferences) {
            if (!terminal_cleanup)
                try { preferences->close(); } catch (...) { preferences_error = std::current_exception(); }
            // Destruction abandons pending writes; it never retries or flushes.
            preferences.reset(); // close is idempotent; never retry uncertain disk work.
        }
        const auto input_closed=input_lease->invalidate();
        if(input_closed.error!=host::FileError::none && !input_cleanup_failed) {
            input_cleanup_failed=true;++metrics.unsupported_services;
        }
        for (const auto &[id, view] : views) {
            (void)id;
            runtime.release(view.listener);
        }
        views.clear();
        unscrolled_bounds.clear();
        if(application)runtime.set_host_state(application,{});
        for (auto object : owned)
            runtime.release(object);
        owned.clear();
        application = resource_object = package_manager = content_resolver = activity = content = main_looper = files_directory = base_context = activity_thread = 0;
        bound_application = loaded_package = data_directory = 0;
        application_info = package_name = component_factory = selected_loader = launch_intent = 0;
        configuration_object = 0;
        notification_manager = 0;
        clipboard_manager = clipboard_name = plain_text_mime = 0;
        clipboard = nullptr;
        input_method_manager = input_method_name = 0;
        buffer_modes.fill(0);
        application_attached = activity_attached = application_published = false;
        pointer_target = key_target = focused_view = 0;
        held_key = 0;
        if (attached) {
            runtime.set_host_interface(nullptr);
            attached = false;
        }
        if (ime_error && report_input_errors) std::rethrow_exception(ime_error);
        if (drag_error && report_input_errors) std::rethrow_exception(drag_error);
        if (preferences_error && report_input_errors) std::rethrow_exception(preferences_error);
        if(input_cleanup_failed && report_input_errors)
            bad("INPUT_STREAM_CLOSE_UNAVAILABLE","Session input descriptor cleanup failed");
    }
    void log(std::string event) {
        if (events.size() >= 4096)
            bad("EVENT_LIMIT", "Lifecycle event quota exceeded");
        events.push_back(std::move(event));
    }
    std::optional<dex::Index> override_method(std::string_view type, std::string_view name,
                                              std::string_view signature) const {
        for (unsigned depth = 0; depth < 256; ++depth) {
            const auto *definition = runtime.class_definition(type);
            if (!definition)
                return {};
            for (auto index : definition->virtual_methods) {
                const auto &method = runtime.image().methods.at(index);
                if (method.name == name &&
                    runtime.image().prototypes.at(method.prototype).descriptor == signature)
                    return index;
            }
            if (definition->superclass == dex::no_index)
                return {};
            type = runtime.image().types.at(definition->superclass);
        }
        bad("CLASS_LIMIT", "Activity/listener hierarchy exceeds limit");
    }
    std::optional<dex::Index> collection_selection_policy_getter(ObjectId object) const {
        // Recognize a real managed library contract, never an arbitrary View
        // method with the same name or a synthetic Android SDK extension.
        std::string_view type = runtime.object_type(object);
        std::optional<dex::Index> resolved;
        bool invalid_override = false;
        for (unsigned depth = 0; depth < 256; ++depth) {
            const auto *definition = runtime.class_definition(type);
            if (!definition) return {};
            std::optional<dex::Index> declared;
            bool valid = false;
            for (const auto index : definition->virtual_methods) {
                const auto &method = runtime.image().methods.at(index);
                if (method.name != "isSelectionRequired" ||
                    runtime.image().prototypes.at(method.prototype).descriptor != "()Z") continue;
                declared = index;
                valid = method.owner == definition->type && method.declared && !method.direct &&
                    (method.flags & 1) && !(method.flags & (2 | 8 | 0x100 | 0x400)) && method.code;
                break;
            }
            if (!resolved && !invalid_override && declared) {
                if (valid) resolved = declared;
                else invalid_override = true;
            }
            if (type == "Lcom/google/android/material/chip/ChipGroup;" ||
                type == "Lcom/google/android/material/button/MaterialButtonToggleGroup;")
                return (definition->flags & 1) && declared && valid && !invalid_override ? resolved : std::nullopt;
            if (definition->superclass == dex::no_index) return {};
            type = runtime.image().types.at(definition->superclass);
        }
        bad("CLASS_LIMIT", "Selection policy hierarchy exceeds limit");
    }
    const LifecycleState &lifecycle_state() const {
        const auto *value=dynamic_cast<const LifecycleState *>(runtime.host_state(application));
        if(!value)bad("LIFECYCLE_STATE","Application callback registry is unavailable");
        return *value;
    }
    struct ListenerSnapshot {
        dex::ManagedRuntime &runtime;std::array<Value,16> values{};std::size_t count=0,pinned=0;
        ListenerSnapshot(dex::ManagedRuntime &runtime,const LifecycleState &source):runtime(runtime),count(source.count) {
            std::copy_n(source.callbacks.begin(), count, values.begin());
            try {for(;pinned<count;++pinned)runtime.retain(values[pinned].bits);}
            catch(...) {while(pinned)runtime.release(values[--pinned].bits);throw;}
        }
        ~ListenerSnapshot(){while(pinned)runtime.release(values[--pinned].bits);}
    };
    void change_lifecycle(ObjectId listener,bool add) {
        if(!application_constructed)bad("APPLICATION_STATE","Registration requires the initialized Application base");
        const auto revision=lifecycle_revision;
        ListenerSnapshot snapshot(runtime,lifecycle_state());
        auto next=std::make_unique<LifecycleState>(lifecycle_state());
        if(add) {
            if(next->count==16)bad("LIFECYCLE_LIMIT","Application lifecycle registration limit of 16 exceeded");
            next->callbacks[next->count++]=Value::reference(listener);
        } else {
            std::size_t match=next->count;
            for(std::size_t n=0;n<next->count;++n) {
                const auto candidate=next->callbacks[n].bits;
                bool equal=listener==candidate;
                if(listener)if(const auto method=override_method(runtime.object_type(listener),"equals","(Ljava/lang/Object;)Z")) {
                    const std::array<Value,2> args{Value::reference(listener),Value::reference(candidate)};
                    equal=runtime.invoke_virtual(*method,args).bits!=0;
                }
                if(lifecycle_revision!=revision)bad("LIFECYCLE_MUTATION","Listener equality mutated the registry during unregister");
                if(equal){match=n;break;}
            }
            if(match==next->count)return;
            for(std::size_t n=match+1;n<next->count;++n)next->callbacks[n-1]=next->callbacks[n];
            next->callbacks[--next->count]=Value::reference(0);
        }
        if(lifecycle_revision==std::numeric_limits<std::uint64_t>::max())bad("LIFECYCLE_LIMIT","Lifecycle registry revision exhausted");
        runtime.set_host_state(application,std::move(next));++lifecycle_revision;
    }
    struct ComponentSnapshot {
        dex::ManagedRuntime &runtime;
        std::array<Value,16> values{};
        std::size_t count=0,pinned=0;
        ComponentSnapshot(dex::ManagedRuntime &runtime,const LifecycleState &source,ObjectId owner=0)
            :runtime(runtime) {
            for(std::size_t n=0;n<source.component_count;++n)
                if(!owner || source.component_owners[n]==owner)
                    values[count++]=source.callbacks[16+n];
            try {for(;pinned<count;++pinned)runtime.retain(values[pinned].bits);}
            catch(...) {while(pinned)runtime.release(values[--pinned].bits);throw;}
        }
        ~ComponentSnapshot(){while(pinned)runtime.release(values[--pinned].bits);}
    };
    ObjectId component_owner(ObjectId receiver) {
        if(!application_constructed)
            bad("APPLICATION_STATE","Component registration requires the initialized Application base");
        if(receiver==application && application)return application;
        if(receiver==activity && activity && target_sdk>=33)return activity;
        context(receiver); // The canonical base and legacy Activity delegate to Application.
        return application;
    }
    void change_components(ObjectId owner,ObjectId listener,bool add) {
        const auto revision=lifecycle_revision;
        ComponentSnapshot snapshot(runtime,lifecycle_state());
        auto next=std::make_unique<LifecycleState>(lifecycle_state());
        if(add) {
            if(next->component_count==16)
                bad("COMPONENT_LIMIT","Component registration limit of 16 across supported Contexts exceeded");
            const auto at=next->component_count++;
            next->callbacks[16+at]=Value::reference(listener);
            next->component_owners[at]=owner;
        } else {
            std::size_t match=next->component_count;
            for(std::size_t n=0;n<next->component_count;++n) {
                if(next->component_owners[n]!=owner)continue;
                const auto candidate=next->callbacks[16+n].bits;
                bool equal=listener==candidate;
                if(listener)if(const auto method=override_method(runtime.object_type(listener),"equals","(Ljava/lang/Object;)Z")) {
                    const std::array args{Value::reference(listener),Value::reference(candidate)};
                    equal=runtime.invoke_virtual(*method,args).bits!=0;
                }
                if(lifecycle_revision!=revision)
                    bad("COMPONENT_MUTATION","Callback equality changed a callback registry during unregister");
                if(equal){match=n;break;}
            }
            if(match==next->component_count)return;
            for(std::size_t n=match+1;n<next->component_count;++n) {
                next->callbacks[15+n]=next->callbacks[16+n];
                next->component_owners[n-1]=next->component_owners[n];
            }
            next->callbacks[16+--next->component_count]=Value::reference(0);
            next->component_owners[next->component_count]=0;
        }
        if(lifecycle_revision==std::numeric_limits<std::uint64_t>::max())
            bad("COMPONENT_LIMIT","Callback registry revision exhausted");
        runtime.set_host_state(application,std::move(next));++lifecycle_revision;
    }
    void retire_components(ObjectId owner) {
        const auto &current=lifecycle_state();
        bool found=false;
        for(std::size_t n=0;n<current.component_count;++n)found=found || current.component_owners[n]==owner;
        if(!found)return;
        auto next=std::make_unique<LifecycleState>(current);
        std::size_t kept=0;
        for(std::size_t n=0;n<next->component_count;++n)
            if(next->component_owners[n]!=owner) {
                next->callbacks[16+kept]=next->callbacks[16+n];
                next->component_owners[kept++]=next->component_owners[n];
            }
        for(std::size_t n=kept;n<next->component_count;++n) {
            next->callbacks[16+n]=Value::reference(0);next->component_owners[n]=0;
        }
        next->component_count=kept;
        if(lifecycle_revision==std::numeric_limits<std::uint64_t>::max())
            bad("COMPONENT_LIMIT","Callback registry revision exhausted");
        runtime.set_host_state(application,std::move(next));++lifecycle_revision;
    }
    void dispatch_components(ObjectId owner,ObjectId configuration_id) {
        ComponentSnapshot snapshot(runtime,lifecycle_state(),owner);
        const std::array args{Value::reference(configuration_id)};
        for(std::size_t n=0;n<snapshot.count;++n) {
            if(!snapshot.values[n].bits)runtime.raise("Ljava/lang/NullPointerException;");
            (void)runtime.invoke_virtual_named(snapshot.values[n].bits,"onConfigurationChanged",
                "(Landroid/content/res/Configuration;)V",args);
        }
    }
    void deliver_application_configuration() {
        if(application_stage!=ApplicationStage::ready)return;
        if(application_configuration_delivery)
            bad("CONFIGURATION_REENTRANT","Application configuration notification is already active");
        application_configuration_delivery=true;
        struct End {bool &active;~End(){active=false;}} end{application_configuration_delivery};
        const std::array args{Value::reference(application),Value::reference(configuration_object)};
        if(const auto method=override_method(application_type_name,"onConfigurationChanged",
                "(Landroid/content/res/Configuration;)V"))
            (void)runtime.invoke(*method,args);
        else dispatch_components(application,configuration_object);
        ++metrics.lifecycle_callbacks;
        log("Application.onConfigurationChanged");
    }
    static std::string_view lifecycle_suffix(std::string_view event) {
        if(event=="onCreate")return "Created";
        if(event=="onStart")return "Started";
        if(event=="onResume")return "Resumed";
        if(event=="onPause")return "Paused";
        if(event=="onStop")return "Stopped";
        if(event=="onDestroy")return "Destroyed";
        if(event=="onSaveInstanceState")return "SaveInstanceState";
        return {};
    }
    void notify_lifecycle(std::string_view event,std::string_view phase,std::optional<Value> argument={}) {
        const auto suffix=lifecycle_suffix(event);if(suffix.empty())return;
        ListenerSnapshot snapshot(runtime,lifecycle_state());
        const auto name="onActivity"+std::string(phase)+std::string(suffix);
        const bool created=event=="onCreate" || event=="onSaveInstanceState";
        const auto signature=created?"(Landroid/app/Activity;Landroid/os/Bundle;)V":"(Landroid/app/Activity;)V";
        const std::array<Value,2> args{Value::reference(activity),argument.value_or(Value::reference(0))};
        for(std::size_t n=0;n<snapshot.count;++n)
            (void)runtime.invoke_virtual_named(snapshot.values[n].bits,name,signature,std::span<const Value>(args).first(created?2:1));
    }
    void normal_lifecycle(std::string_view event,std::optional<Value> argument={}) {
        called_super=true;
        if(event=="onConfigurationChanged" && argument)
            dispatch_components(activity,argument->bits);
        if (event == "onSaveInstanceState" || event == "onRestoreInstanceState") {
            if (!argument) bad("SAVED_STATE", "State callback requires a Bundle");
            const auto key = runtime.new_string(u"aether:view-focus-id");
            runtime.retain(key);
            struct Release { dex::ManagedRuntime &runtime; ObjectId id; ~Release() { runtime.release(id); } } root{runtime, key};
            if (event == "onSaveInstanceState") {
                const auto focused_id = focused_view && in_tree(focused_view) ? view(focused_view).id : -1;
                const std::array args{*argument, Value::reference(key),
                                      Value::word(std::bit_cast<std::uint32_t>(focused_id))};
                (void)invoke_bundle(runtime, bundle_type, "putInt", "(Ljava/lang/String;I)V", args);
            } else {
                // State is in the real Bundle: clear/copy or app edits affect
                // restoration. Text is re-created from current resources; the
                // supported TextView profile does not implement freezesText.
                const std::array args{*argument, Value::reference(key), Value::word(0xffffffffu)};
                const auto restored_id = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(
                    invoke_bundle(runtime, bundle_type, "getInt", "(Ljava/lang/String;I)I", args).bits));
                std::vector<ObjectId> todo;
                if (content && restored_id >= 0) todo.push_back(content);
                while (!todo.empty()) {
                    const auto id = todo.back(); todo.pop_back();
                    const auto &current = view(id);
                    if (current.id == restored_id) {
                        if (enabled(id)) focus(id);
                        break;
                    }
                    todo.insert(todo.end(), current.children.rbegin(), current.children.rend());
                }
            }
        }
        notify_lifecycle(event,{},argument);
    }
    void post_resume() {
        callback="onPostResume";called_super=false;
        if(const auto method=override_method(activity_type,"onPostResume","()V")) {
            const std::array<Value,1> args{Value::reference(activity)};
            (void)runtime.invoke_virtual(*method,args);
            if(!called_super)bad("SUPER_NOT_CALLED","Activity callback did not call super.onPostResume");
        } else called_super=true;
        callback="onResume";
    }
    void deliver(std::string_view name, Lifecycle next, std::string_view signature = "()V",
                 std::optional<Value> argument = {}) {
        if (!callback.empty())
            bad("LIFECYCLE_REENTRANT", "Cannot deliver lifecycle callbacks recursively");
        callback = name;
        called_super = false;
        struct End {
            Impl &p;
            ~End() { p.callback = {}; }
        } end{*this};
        try {
            notify_lifecycle(name,"Pre",argument);
            if (const auto method = override_method(activity_type, name, signature)) {
                std::vector<Value> args{Value::reference(activity)};
                if (argument)
                    args.push_back(*argument);
                (void)runtime.invoke(*method, args);
                if (!called_super && name != "onWindowFocusChanged" && name != "onSaveInstanceState" &&
                    name != "onRestoreInstanceState")
                    bad("SUPER_NOT_CALLED", "Activity callback did not call super." + std::string(name));
            } else normal_lifecycle(name,argument);
            if(name=="onResume")post_resume();
            notify_lifecycle(name,"Post",argument);
            ++metrics.lifecycle_callbacks;
            log(std::string(name));
            state = next;
        } catch (...) {
            state = Lifecycle::failed;
            throw;
        }
    }
    void create_activity(ObjectId saved = 0, ObjectId custom_intent = 0) {
        factory_activity_active = true;
        struct EndFactory { bool &active; ~EndFactory() { active = false; } } end{factory_activity_active};
        if (component_factory) {
            ObjectId result = 0;
            if (const auto method = override_method(runtime.object_type(component_factory), "instantiateActivity",
                    "(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Intent;)Landroid/app/Activity;")) {
                const auto name = runtime.new_string(component_name(activity_type));
                runtime.retain(name);
                struct Release { dex::ManagedRuntime &runtime; ObjectId id; ~Release() { runtime.release(id); } } root{runtime, name};
                const std::array args{Value::reference(component_factory), Value::reference(selected_loader),
                                      Value::reference(name), Value::reference(launch_intent)};
                result = runtime.invoke_virtual(*method, args).bits;
            } else result = construct_activity();
            if (!activity || result != activity)
                bad("FACTORY_ACTIVITY_UNSUPPORTED", "Factory did not return the actual declared Activity");
        } else construct_activity();
        factory_activity_active = false;
        // The factory receives the original launch record. Android relaunch
        // restores a captured nonnull custom mIntent after normal attach;
        // a captured null falls back to the original record Intent.
        runtime.set_host_state(activity, std::make_unique<ActivityIntentState>(
            custom_intent ? custom_intent : launch_intent));
        activity_attached = true;
        deliver("onCreate", Lifecycle::created, "(Landroid/os/Bundle;)V", Value::reference(saved));
        deliver("onStart", Lifecycle::started);
        if (saved)
            deliver("onRestoreInstanceState", Lifecycle::started, "(Landroid/os/Bundle;)V", Value::reference(saved));
        deliver("onPostCreate", Lifecycle::started, "(Landroid/os/Bundle;)V", Value::reference(saved));
        if (visible && !suspended && active)
            deliver("onResume", Lifecycle::resumed);
        else if (!visible || suspended)
            deliver("onStop", Lifecycle::stopped);
    }
    void retire_activity() {
        clear_drag_sequence();
        release_drop_grants();
        retire_soft_input_window();
        cancel_input();
        focus(0);
        retire_components(activity);
        for (const auto &[id, current] : views) {
            runtime.release(current.listener);
            disown(id);
        }
        views.clear();
        unscrolled_bounds.clear();
        disown(activity);
        activity = content = 0;
        activity_attached = false;
        focused = false;
        state = Lifecycle::empty;
        ++metrics.view_revision;
    }
    void apply_configuration_change() {
        if (!pending_configuration || !activity) return;
        if (!callback.empty() || !input_events.empty() || dispatching_drag)
            bad("CONFIGURATION_REENTRANT", "Configuration cannot interrupt a lifecycle or input callback");
        const auto changed = pending_configuration;
        pending_configuration = 0;
        if ((changed & ~config_changes) == 0) {
            deliver("onConfigurationChanged", state, "(Landroid/content/res/Configuration;)V",
                    Value::reference(configuration_object));
            return;
        }
        const auto *intent_state = dynamic_cast<const ActivityIntentState *>(runtime.host_state(activity));
        if (!intent_state) bad("ACTIVITY_INTENT", "Activity has no attached Intent storage");
        const auto custom_intent = intent_state->references[0].bits;
        ManagedRoot intent_root(runtime, custom_intent);
        const auto saved = runtime.new_object(bundle_type);
        runtime.retain(saved);
        struct Release { dex::ManagedRuntime &runtime; ObjectId id; ~Release() { runtime.release(id); } } root{runtime, saved};
        const std::array args{Value::reference(saved)};
        (void)invoke_bundle(runtime, bundle_type, "<init>", "()V", args);
        changing_configuration = changed;
        struct Reset {
            Impl &p;
            ~Reset() { p.changing_configuration = 0; }
        } reset{*this};
        if (focused) {
            focused = false;
            deliver("onWindowFocusChanged", state, "(Z)V", Value::word(0));
        }
        cancel_input();
        if (state == Lifecycle::resumed) deliver("onPause", Lifecycle::paused);
        if (target_sdk < 28)
            deliver("onSaveInstanceState", state, "(Landroid/os/Bundle;)V", Value::reference(saved));
        if (state == Lifecycle::paused || state == Lifecycle::started)
            deliver("onStop", Lifecycle::stopped);
        if (target_sdk >= 28)
            deliver("onSaveInstanceState", state, "(Landroid/os/Bundle;)V", Value::reference(saved));
        deliver("onDestroy", Lifecycle::destroyed);
        retire_activity();
        changing_configuration = 0;
        create_activity(saved, custom_intent);
        if (visible && active && !suspended && window_focused && state == Lifecycle::resumed) {
            focused = true;
            deliver("onWindowFocusChanged", state, "(Z)V", Value::word(1));
        }
    }
    ViewState &view(ObjectId object) {
        const auto found = views.find(object);
        if (found == views.end())
            bad("VIEW", "View is not initialized in this application");
        return found->second;
    }
    void context(ObjectId object) const {
        if (object == base_context && base_context)
            return;
        if (object == application && application) {
            if (!application_attached)
                runtime.raise("Ljava/lang/NullPointerException;", u"Application base Context is not attached");
            return;
        }
        if (object == activity && activity) {
            if (!activity_attached)
                runtime.raise("Ljava/lang/NullPointerException;", u"Activity base Context is not attached");
            return;
        }
        bad("CONTEXT", "Context is not attached to this application");
    }
    ObjectId resolver_service() {
        if(!content_resolver) {
            if(runtime.class_definition(resolver_type) || runtime.class_definition(session_resolver_type) ||
               runtime.class_definition(content_interface_type))
                bad("CONTENT_TYPE","Package classes collide with the actual session ContentResolver implementation");
            content_resolver=own(runtime.new_object(session_resolver_type));
        }
        return content_resolver;
    }
    Value resolver_api(const ApiSupport &api, std::span<const Value> args) {
        // Original bounded service; null/scheme/failure behavior reviewed
        // against Android15 ContentResolver at frameworks/base revision
        // 4e43ad12e1b211f15152e9c5b16b0fe88e6b93f3. No source is imported.
        if(args.size()!=2 || args[0].kind!=dex::ValueKind::reference || args[1].kind!=dex::ValueKind::reference)
            bad("CONTENT_ARGUMENT","ContentResolver requires its receiver and a Uri reference");
        if(!args[0].bits)runtime.raise("Ljava/lang/NullPointerException;");
        if(!content_resolver || args[0].bits!=content_resolver || runtime.object_type(args[0].bits)!=session_resolver_type)
            bad("CONTENT_RESOLVER","ContentResolver is not the canonical service of this session");
        const auto uri_id=args[1].bits;
        if(!uri_id)runtime.raise("Ljava/lang/NullPointerException;",api.name=="getType"?u"url":u"uri");
        ManagedRoot uri_root(runtime,uri_id);
        if(runtime.object_type(uri_id)!=string_uri_type)
            bad("CONTENT_UNSUPPORTED","ContentResolver currently requires the actual StringUri representation");
        const auto raw=uri_text(runtime,uri_id);
        const uri::Parsed parsed(raw);
        const auto scheme=parsed.part(uri::Part::scheme);
        const auto scheme_text=scheme?std::u16string_view(raw).substr(scheme->first,scheme->last-scheme->first):std::u16string_view{};
        const bool get_type=api.name=="getType";
        if(scheme_text!=u"content") {
            if(get_type)return Value::reference(0);
            if(scheme_text==u"file" || scheme_text==u"android.resource")
                bad("CONTENT_UNSUPPORTED","ContentResolver file and Android-resource streams are not implemented");
            runtime.raise("Ljava/io/FileNotFoundException;",u"No supported content provider is available");
        }
        std::string name;
        if(std::all_of(raw.begin(),raw.end(),[](char16_t unit){return unit<128;}))
            {
                std::string converted;
                converted.reserve(raw.size());
                for (char16_t u : raw) converted.push_back(static_cast<char>(u));
                name = std::move(converted);
            }
        if(!host::valid_document_uri(name)) {
            if(get_type)return Value::reference(0);
            runtime.raise("Ljava/io/FileNotFoundException;",u"No supported content document exists for this Uri");
        }
        auto *service=input_lease->documents;
        if(!input_lease->active)bad("CONTENT_STATE","Document service belongs to a closed framework session");
        if(get_type) {
            host::DocumentInfo info;
            const auto result=service?service->describe(name,info):host::FileResult{-1,host::FileError::denied};
            if(result.error==host::FileError::denied)++metrics.denied_permissions;
            // Android getType catches provider failures and returns null,
            // including denial. No MIME value is invented or logged.
            if(result.error!=host::FileError::none)return Value::reference(0);
            if(result.value!=0 || !host::valid_document_info(info) || info.uri!=name)
                bad("CONTENT_RESULT","Document provider returned invalid metadata");
            return Value::reference(runtime.new_string(unicode(info.mime_type)));
        }
        if(!service) {
            ++metrics.denied_permissions;
            runtime.raise("Ljava/lang/SecurityException;",u"No document read grant is available");
        }
        std::size_t slot=0;
        while(slot<input_lease->used.size() && input_lease->used[slot])++slot;
        if(slot==input_lease->used.size())bad("INPUT_STREAM_LIMIT","Session live input source limit of 16 exceeded");
        auto source=std::make_unique<DocumentInput>(input_lease,slot);
        input_lease->used[slot]=true;
        input_lease->document_slots[slot]=true;
        const auto opened=service->open_document(name);
        if(opened.error==host::FileError::denied) {
            ++metrics.denied_permissions;
            runtime.raise("Ljava/lang/SecurityException;",u"The document read grant is denied");
        }
        if(opened.error==host::FileError::missing || opened.error==host::FileError::invalid)
            runtime.raise("Ljava/io/FileNotFoundException;",u"The granted document is unavailable");
        if(opened.error==host::FileError::descriptor_limit || opened.error==host::FileError::quota)
            bad("INPUT_STREAM_LIMIT","Document input descriptor or storage quota exceeded");
        if(opened.error==host::FileError::unsupported)
            bad("CONTENT_UNSUPPORTED","The document provider cannot open a read stream");
        if(opened.error!=host::FileError::none)
            runtime.raise("Ljava/io/FileNotFoundException;",u"The document read stream could not be opened");
        if(opened.value<0 || opened.value>std::numeric_limits<int>::max())
            bad("CONTENT_RESULT","Document provider returned an invalid opaque descriptor");
        source->descriptor(static_cast<int>(opened.value));
        return Value::reference(runtime.new_host_input_stream(std::move(source)));
    }
    ObjectId notification_service() {
        if (!notification_manager) {
            const auto object = runtime.new_object(notification_manager_type);
            runtime.set_host_state(object, std::make_unique<NotificationManagerState>());
            notification_manager = own(object);
        }
        return notification_manager;
    }
    ObjectId clipboard_service() {
        if (!clipboard_manager) clipboard_manager = own(runtime.new_object(clipboard_manager_type));
        return clipboard_manager;
    }
    ObjectId plain_clip_description(ObjectId label) {
        std::u16string label_text;
        if (label) {
            label_text = runtime.char_sequence(label);
            if (label_text.size() > 256)
                runtime.raise("Ljava/lang/IllegalArgumentException;", u"Plain-text clip label exceeds the supported bound");
        }
        const auto stored_label = label ? runtime.new_string(label_text) : 0;
        ManagedRoot label_root(runtime, stored_label);
        auto metadata = std::make_unique<DragObjectState>(DragObjectKind::description);
        metadata->mime = "text/plain";
        metadata->references[0] = Value::reference(stored_label);
        return new_drag_object(clip_description_type, std::move(metadata));
    }
    ObjectId plain_clip(ObjectId label, std::u16string_view text) {
        if (!host::valid_drop_text(text))
            runtime.raise("Ljava/lang/IllegalArgumentException;", u"Clipboard text must be bounded well-formed Unicode without null characters");
        const auto description = plain_clip_description(label);
        ManagedRoot description_root(runtime, description);
        const auto string = runtime.new_string(text);
        ManagedRoot text_root(runtime, string);
        auto item_metadata = std::make_unique<DragObjectState>(DragObjectKind::item);
        item_metadata->references[1] = Value::reference(string);
        const auto item = new_drag_object(clip_item_type, std::move(item_metadata));
        ManagedRoot item_root(runtime, item);
        auto data_metadata = std::make_unique<DragObjectState>(DragObjectKind::data);
        data_metadata->references[0] = Value::reference(description);
        data_metadata->references[1] = Value::reference(item);
        return new_drag_object(clip_data_type, std::move(data_metadata));
    }
    void clipboard_result(host::ClipboardStatus status) {
        switch (status) {
        case host::ClipboardStatus::ok: return;
        case host::ClipboardStatus::denied:
            ++metrics.denied_permissions;
            runtime.raise("Ljava/lang/SecurityException;", u"Windows clipboard permission or current foreground access is denied");
        case host::ClipboardStatus::invalid:
            runtime.raise("Ljava/lang/IllegalArgumentException;", u"Clipboard data is outside the supported plain-text profile");
        case host::ClipboardStatus::quota:
            runtime.raise("Ljava/lang/IllegalStateException;", u"Clipboard text exceeds the supported quota");
        case host::ClipboardStatus::unavailable:
            runtime.raise("Ljava/lang/IllegalStateException;", u"Windows clipboard is currently unavailable");
        case host::ClipboardStatus::unsupported:
            runtime.raise("Ljava/lang/UnsupportedOperationException;", u"Windows clipboard format or operation is unsupported");
        }
        bad("CLIPBOARD_RESULT", "Clipboard provider returned an unknown status");
    }
    Value clipboard_api(const ApiSupport &api, std::span<const Value> args) {
        if (args.empty() || args[0].kind != dex::ValueKind::reference || !args[0].bits)
            runtime.raise("Ljava/lang/NullPointerException;");
        if (args[0].bits != clipboard_manager)
            bad("CLIPBOARD_SERVICE", "ClipboardManager is not this session's canonical service");
        const auto name = api.name;
        const bool query = name == "getPrimaryClip" || name == "getPrimaryClipDescription" || name == "hasPrimaryClip";
        // No background/default-IME exception is invented for this Activity
        // profile. Host focus and saved consent are checked independently too.
        if (query) {
            if (!clipboard || !soft_input_window_ready())
                return name == "hasPrimaryClip" ? Value::word(0) : Value::reference(0);
            if (name == "getPrimaryClip") {
                std::optional<std::u16string> text;
                const auto result = clipboard->read_text(text);
                if (result == host::ClipboardStatus::denied) return Value::reference(0);
                clipboard_result(result);
                if (!text) return Value::reference(0);
                if (!host::valid_drop_text(*text)) bad("CLIPBOARD_RESULT", "Clipboard provider returned invalid Unicode text");
                // Windows CF_UNICODETEXT has no Android label. Return a fresh
                // actual native snapshot, never a cached label from our writes.
                return Value::reference(plain_clip(0, *text));
            }
            bool available = false;
            const auto result = clipboard->has_text(available);
            if (result == host::ClipboardStatus::denied)
                return name == "hasPrimaryClip" ? Value::word(0) : Value::reference(0);
            clipboard_result(result);
            if (name == "hasPrimaryClip") return Value::word(available);
            return Value::reference(available ? plain_clip_description(0) : 0);
        }
        if (!clipboard || !soft_input_window_ready()) clipboard_result(host::ClipboardStatus::denied);
        if (name == "clearPrimaryClip") { clipboard_result(clipboard->clear()); return Value::nothing(); }
        if (name == "setPrimaryClip") {
            if (args.size() != 2 || !args[1].bits) runtime.raise("Ljava/lang/NullPointerException;");
            const auto data = drag_object(args[1].bits, DragObjectKind::data);
            const auto description = drag_object(data.references[0].bits, DragObjectKind::description);
            const auto item = drag_object(data.references[1].bits, DragObjectKind::item);
            if (description.mime != "text/plain" || item.references[0].bits || !item.references[1].bits)
                runtime.raise("Ljava/lang/UnsupportedOperationException;", u"Only one plain-text clipboard item is supported");
            const std::u16string text(runtime.char_sequence(item.references[1].bits));
            if (!host::valid_drop_text(text)) clipboard_result(host::ClipboardStatus::invalid);
            clipboard_result(clipboard->write_text(text)); // One explicit write, never replayed.
            return Value::nothing();
        }
        bad("CLIPBOARD_API_UNSUPPORTED", "Clipboard operation is outside the supported plain-text profile");
    }
    bool notification_permission() {
        bool enabled = false;
        return notifications && notifications->enabled(enabled) == host::NotificationStatus::ok && enabled;
    }
    void notification_result(host::NotificationStatus status) {
        switch (status) {
        case host::NotificationStatus::ok: return;
        case host::NotificationStatus::denied:
            ++metrics.denied_permissions;
            runtime.raise("Ljava/lang/SecurityException;", u"Aether notification permission is denied");
        case host::NotificationStatus::unsupported:
            ++metrics.unsupported_services;
            runtime.raise("Ljava/lang/UnsupportedOperationException;", u"Host notification delivery is unavailable");
        case host::NotificationStatus::invalid:
            runtime.raise("Ljava/lang/IllegalArgumentException;", u"Notification text or identity is invalid");
        case host::NotificationStatus::quota:
            runtime.raise("Ljava/lang/IllegalStateException;", u"Notification quota exceeded");
        }
        bad("NOTIFICATION_STATUS", "Unknown notification provider result");
    }
    ObjectId notification_reference(std::span<const Value> args, std::size_t at,
                                     std::string_view type, bool nullable = false) {
        const auto value = args[at];
        if (value.kind != dex::ValueKind::reference && !(value.kind == dex::ValueKind::word && !value.bits))
            bad("NOTIFICATION_ARGUMENT", "Notification argument requires a managed reference");
        if (!value.bits) {
            if (!nullable) runtime.raise("Ljava/lang/NullPointerException;");
            return 0;
        }
        if (!runtime.assignable(value.bits, type))
            bad("NOTIFICATION_ARGUMENT", "Notification reference has an incompatible managed type");
        return value.bits;
    }
    std::int32_t notification_integer(std::span<const Value> args, std::size_t at) {
        if (args[at].kind != dex::ValueKind::word)
            bad("NOTIFICATION_ARGUMENT", "Notification argument requires a Java int");
        return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[at].bits));
    }
    std::u16string notification_text(ObjectId object, std::size_t limit) {
        if (!object) return {};
        const auto text = std::u16string(runtime.char_sequence(object));
        if (text.size() > limit)
            runtime.raise("Ljava/lang/IllegalArgumentException;", u"Notification text exceeds the supported bound");
        try {
            if (narrow(text).size() > limit || std::any_of(text.begin(), text.end(), [](char16_t c) {
                    return c == 0 || c == 0xfffe || c == 0xffff || (c < 32 && c != u'\n' && c != u'\r' && c != u'\t');
                }))
                runtime.raise("Ljava/lang/IllegalArgumentException;", u"Notification text is invalid or too long");
        } catch (const std::invalid_argument &) {
            runtime.raise("Ljava/lang/IllegalArgumentException;", u"Notification text has invalid Unicode");
        }
        return std::u16string(text);
    }
    std::string notification_channel(ObjectId object) {
        const auto value = notification_text(object, 128);
        if (value.empty() || std::any_of(value.begin(), value.end(), [](char16_t c) {
                return c < 32 || (c >= 0x7f && c <= 0x9f);
            }))
            runtime.raise("Ljava/lang/IllegalArgumentException;", u"Notification channel ID is empty or contains control characters");
        return narrow(value);
    }
    template<class State> const State &notification_state(ObjectId object) {
        const auto *object_state = dynamic_cast<const State *>(runtime.host_state(object));
        if (!object_state)
            runtime.raise("Ljava/lang/IllegalStateException;", u"Notification object has not been initialized");
        return *object_state;
    }
    Value notification_api(const ApiSupport &api, std::span<const Value> args) {
        if (args.size() != api_parameters(api.signature).size() + 1)
            bad("NOTIFICATION_ARGUMENT", "Notification method argument count does not match its descriptor");
        const auto receiver = notification_reference(args, 0, api.owner);
        const auto name = api.name;
        if (api.owner == notification_channel_type) {
            if (name == "<init>") {
                if (runtime.host_state(receiver))
                    runtime.raise("Ljava/lang/IllegalStateException;", u"NotificationChannel constructor called twice");
                auto next = std::make_unique<NotificationChannelState>();
                next->data.id = notification_channel(notification_reference(args, 1, "Ljava/lang/String;"));
                next->data.name = notification_text(notification_reference(args, 2, "Ljava/lang/CharSequence;"), 256);
                next->data.importance = notification_integer(args, 3);
                if (next->data.name.empty() || next->data.importance < 0 || next->data.importance > 5)
                    runtime.raise("Ljava/lang/IllegalArgumentException;", u"Notification channel requires a name and importance 0 through 5");
                runtime.set_host_state(receiver, std::move(next));
                return Value::nothing();
            }
            const auto &current = notification_state<NotificationChannelState>(receiver).data;
            if (name == "getImportance") return Value::word(static_cast<std::uint32_t>(current.importance));
            if (name == "getId") return Value::reference(runtime.new_string(unicode(current.id)));
            if (name == "getName") return Value::reference(runtime.new_string(current.name));
        }
        if (api.owner == notification_builder_type) {
            if (name == "<init>") {
                if (runtime.host_state(receiver))
                    runtime.raise("Ljava/lang/IllegalStateException;", u"Notification.Builder constructor called twice");
                const auto owner = notification_reference(args, 1, "Landroid/content/Context;");
                context(owner);
                auto next = std::make_unique<NotificationBuilderState>(owner);
                if (args.size() == 3)
                    next->data.channel = notification_channel(notification_reference(args, 2, "Ljava/lang/String;"));
                runtime.set_host_state(receiver, std::move(next));
                return Value::nothing();
            }
            const auto &current = notification_state<NotificationBuilderState>(receiver);
            if (name == "build") {
                auto next = std::make_unique<NotificationState>(current.data);
                const auto object = runtime.new_object(notification_type);
                runtime.set_host_state(object, std::move(next));
                return Value::reference(object);
            }
            if (name == "setContentIntent") {
                // No PendingIntent objects or activation authority are fabricated.
                // A nonnull request is refused before any attempted intent dispatch.
                if (notification_reference(args, 1, "Ljava/lang/Object;", true))
                    runtime.raise("Ljava/lang/UnsupportedOperationException;", u"Notification click intents are unsupported");
                return Value::reference(receiver);
            }
            auto next = std::make_unique<NotificationBuilderState>(current);
            if (name == "setContentTitle" || name == "setContentText") {
                auto value = notification_text(notification_reference(args, 1, "Ljava/lang/CharSequence;", true),
                                               name == "setContentTitle" ? 256 : 2048);
                (name == "setContentTitle" ? next->data.title : next->data.text) = std::move(value);
            } else if (name == "setSmallIcon") {
                next->data.small_icon = notification_integer(args, 1);
                if (!next->data.small_icon)
                    runtime.raise("Ljava/lang/IllegalArgumentException;", u"Notification small icon resource must be nonzero");
            } else bad("API_UNSUPPORTED", "Notification builder method is unsupported");
            runtime.set_host_state(receiver, std::move(next));
            return Value::reference(receiver);
        }
        if (api.owner == notification_manager_type) {
            if (receiver != notification_manager)
                bad("NOTIFICATION_MANAGER", "NotificationManager is not this session's canonical service");
            const auto &current = notification_state<NotificationManagerState>(receiver);
            if (name == "areNotificationsEnabled") return Value::word(notification_permission());
            if (name == "createNotificationChannel") {
                const auto channel = notification_reference(args, 1, notification_channel_type);
                const auto &data = notification_state<NotificationChannelState>(channel).data;
                const auto at = std::find_if(current.channels.begin(), current.channels.end(),
                                            [&](const auto &item) { return item.id == data.id; });
                if (at != current.channels.end()) {
                    if (*at != data)
                        runtime.raise("Ljava/lang/UnsupportedOperationException;", u"Changing existing notification channel metadata is unsupported");
                    return Value::nothing();
                }
                if (current.channels.size() >= 32)
                    runtime.raise("Ljava/lang/IllegalStateException;", u"Notification channel quota is 32");
                auto next = std::make_unique<NotificationManagerState>(current);
                next->channels.push_back(data);
                runtime.set_host_state(receiver, std::move(next));
                return Value::nothing();
            }
            if (!notifications) notification_result(host::NotificationStatus::denied);
            if (name == "notify") {
                const auto id = notification_integer(args, 1);
                const auto object = notification_reference(args, 2, notification_type);
                const auto &data = notification_state<NotificationState>(object).data;
                if (!data.small_icon)
                    runtime.raise("Ljava/lang/IllegalArgumentException;", u"Notification requires a small icon resource");
                const auto channel = std::find_if(current.channels.begin(), current.channels.end(),
                                                  [&](const auto &item) { return item.id == data.channel; });
                if (channel == current.channels.end())
                    runtime.raise("Ljava/lang/IllegalArgumentException;", u"Notification requires an explicitly created supported channel");
                bool enabled = false;
                notification_result(notifications->enabled(enabled));
                if (!enabled) notification_result(host::NotificationStatus::denied);
                if (channel->importance == 0) return Value::nothing();
                notification_result(notifications->post({id, data.channel, narrow(data.title), narrow(data.text)}));
                return Value::nothing();
            }
            if (name == "cancel") {
                notification_result(notifications->cancel(notification_integer(args, 1)));
                return Value::nothing();
            }
            if (name == "cancelAll") {
                notification_result(notifications->cancel_all());
                return Value::nothing();
            }
        }
        bad("API_UNSUPPORTED", "Notification method is outside the supported text-only profile");
    }
    const AccessibilityObjectState &accessibility_object(ObjectId object, AccessibilityObjectState::Kind kind) const {
        if (!object) runtime.raise("Ljava/lang/NullPointerException;");
        const auto *stored = dynamic_cast<const AccessibilityObjectState *>(runtime.host_state(object));
        if (!stored || stored->kind != kind)
            bad("ACCESSIBILITY_OBJECT", "Accessibility metadata has no authenticated framework storage");
        return *stored;
    }
    ObjectId new_accessibility_object(std::string_view type, std::unique_ptr<AccessibilityObjectState> metadata) {
        const auto object = runtime.new_object(type);
        ManagedRoot root(runtime, object);
        runtime.set_host_state(object, std::move(metadata));
        return object;
    }
    ObjectId accessibility_source(ObjectId source) const {
        if (source && !views.contains(source))
            bad("ACCESSIBILITY_SOURCE", "Accessibility source is not an actual session-owned View");
        return source;
    }
    bool selected(ObjectId object) {
        if (const auto method = override_method(runtime.object_type(object), "isSelected", "()Z")) {
            const std::array args{Value::reference(object)};
            return runtime.invoke_virtual(*method, args).bits != 0;
        }
        return view_state(object).selected;
    }
    void dispatch_set_selected_base(ObjectId object, bool value, bool group) {
        if (!group) return;
        const auto children = view(object).children;
        struct Roots {
            dex::ManagedRuntime &runtime; std::vector<ObjectId> ids;
            ~Roots() { for (const auto id : ids) runtime.release(id); }
        } roots{runtime, {}};
        roots.ids.reserve(children.size());
        for (const auto child : children) { runtime.retain(child); roots.ids.push_back(child); }
        for (const auto child : children) set_selected(child, value);
    }
    void set_selected_base(ObjectId object, bool value) {
        ManagedRoot owner_root(runtime, object);
        if (view_state(object).selected == value) return;
        auto next = std::make_unique<ViewObjectState>(view_state(object));
        next->selected = value;
        runtime.set_host_state(object, std::move(next));
        if (!value) view(object).pressed = false;
        ++metrics.view_revision;
        if (const auto method = override_method(runtime.object_type(object), "dispatchSetSelected", "(Z)V")) {
            const std::array args{Value::reference(object), Value::word(value)};
            (void)runtime.invoke_virtual(*method, args);
        } else dispatch_set_selected_base(object, value, runtime.assignable(object, "Landroid/view/ViewGroup;"));
        if (accessibility_invalidation == UINT64_MAX)
            bad("ACCESSIBILITY_INVALIDATION", "Accessibility invalidation revision exhausted");
        ++accessibility_invalidation;
    }
    void set_selected(ObjectId object, bool value) {
        if (const auto method = override_method(runtime.object_type(object), "setSelected", "(Z)V")) {
            const std::array args{Value::reference(object), Value::word(value)};
            (void)runtime.invoke_virtual(*method, args);
        } else set_selected_base(object, value);
    }
    bool accessibility_action_base(ObjectId object, std::uint32_t action) {
        if (action == 4) {
            if (selected(object)) return false;
            set_selected(object, true);
            return selected(object);
        }
        if (action == 8) {
            if (!selected(object)) return false;
            set_selected(object, false);
            return !selected(object);
        }
        runtime.raise("Ljava/lang/UnsupportedOperationException;", u"Only select and clear-selection accessibility actions are supported");
    }
    bool accessibility_action(ObjectId object, std::uint32_t action) {
        if (const auto method = override_method(runtime.object_type(object), "performAccessibilityAction", "(ILandroid/os/Bundle;)Z")) {
            const std::array args{Value::reference(object), Value::word(action), Value::reference(0)};
            return runtime.invoke_virtual(*method, args).bits != 0;
        }
        return accessibility_action_base(object, action);
    }
    ObjectId accessibility_node_provider(ObjectId object) {
        if (const auto method = override_method(runtime.object_type(object), "getAccessibilityNodeProvider",
                "()Landroid/view/accessibility/AccessibilityNodeProvider;")) {
            const std::array args{Value::reference(object)};
            return runtime.invoke_virtual(*method, args).bits;
        }
        return 0; // Actual SDK base behavior without a delegate.
    }
    ObjectId create_accessibility_node_info_base(ObjectId object) {
        accessibility_source(object);
        bool queried = false, provider_present = false;
        const auto query_thread = accessibility_provider_query ? runtime.current_thread() : 0;
        for (auto *query = accessibility_provider_query; query; query = query->previous)
            if (query->view == object && query->thread == query_thread) {
                queried = true; provider_present = query->present; break;
            }
        if (!queried) {
            const auto provider = accessibility_node_provider(object);
            ManagedRoot provider_root(runtime, provider);
            provider_present = provider != 0;
        }
        if (provider_present)
            runtime.raise("Ljava/lang/UnsupportedOperationException;", u"Virtual AccessibilityNodeProvider metadata is unsupported");
        auto metadata = std::make_unique<AccessibilityObjectState>(AccessibilityObjectState::Kind::node);
        metadata->references[0] = Value::reference(object);
        const auto info = new_accessibility_object(accessibility_node_type, std::move(metadata));
        ManagedRoot root(runtime, info);
        const std::array args{Value::reference(info)};
        (void)runtime.invoke_virtual_named(object, "onInitializeAccessibilityNodeInfo",
            "(Landroid/view/accessibility/AccessibilityNodeInfo;)V", args);
        return info;
    }
    ObjectId create_accessibility_node_info(ObjectId object) {
        if (const auto method = override_method(runtime.object_type(object), "createAccessibilityNodeInfo",
                "()Landroid/view/accessibility/AccessibilityNodeInfo;")) {
            const std::array args{Value::reference(object)};
            return runtime.invoke_virtual(*method, args).bits;
        }
        return create_accessibility_node_info_base(object);
    }
    Value accessibility_api(const ApiSupport &api, std::span<const Value> args) {
        using Kind = AccessibilityObjectState::Kind;
        const auto kind = api.owner == accessibility_node_type ? Kind::node
            : api.owner == accessibility_collection_type ? Kind::collection
            : api.owner == accessibility_collection_builder_type ? Kind::collection_builder : Kind::item;
        const bool factory = api.name == "obtain";
        const bool construct = api.name == "<init>";
        const auto reference = [&](std::size_t index) -> ObjectId {
            if (index >= args.size() || (args[index].kind != dex::ValueKind::reference &&
                !(args[index].kind == dex::ValueKind::word && !args[index].bits)))
                bad("ACCESSIBILITY_ARGUMENT", "Accessibility metadata requires a reference argument");
            return args[index].bits;
        };
        const auto integer = [&](std::size_t index) -> std::int32_t {
            if (index >= args.size() || args[index].kind != dex::ValueKind::word)
                bad("ACCESSIBILITY_ARGUMENT", "Accessibility metadata requires an integer argument");
            return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[index].bits));
        };
        if (factory || construct) {
            const auto first = factory ? 0u : 1u;
            if (args.size() < first) bad("ACCESSIBILITY_ARGUMENT", "Accessibility constructor requires its receiver");
            const auto count = args.size() - first;
            auto metadata = std::make_unique<AccessibilityObjectState>(kind);
            if (kind == Kind::collection_builder) {
                if (count != 0) bad("ACCESSIBILITY_ARGUMENT", "Collection metadata builder takes no arguments");
                // Android15/API35 builder defaults differ from unknown counts
                // on an uninitialized collection declaration. Setters retain
                // raw values; the platform builder does not validate them.
                metadata->collection.row_count = 0;
                metadata->collection.column_count = 0;
            } else if (kind == Kind::node) {
                if (count == 1) {
                    const auto source = reference(first);
                    if (api.signature.starts_with("(Landroid/view/View;"))
                        metadata->references[0] = Value::reference(accessibility_source(source));
                    else *metadata = accessibility_object(source, Kind::node);
                } else if (count != 0) bad("ACCESSIBILITY_ARGUMENT", "Unsupported node metadata constructor");
            } else if (kind == Kind::collection) {
                if (count != 3 && count != 4) bad("ACCESSIBILITY_ARGUMENT", "Collection metadata requires counts and hierarchy");
                metadata->collection = {integer(first), integer(first + 1), integer(first + 2) != 0,
                    count == 4 ? integer(first + 3) : 0};
            } else {
                if (count != 5 && count != 6) bad("ACCESSIBILITY_ARGUMENT", "Collection item metadata requires indices and spans");
                metadata->item = {integer(first), integer(first + 1), integer(first + 2), integer(first + 3),
                    integer(first + 4) != 0, count == 6 && integer(first + 5) != 0};
            }
            if (factory) return Value::reference(new_accessibility_object(api.owner, std::move(metadata)));
            const auto receiver = reference(0);
            if (runtime.host_state(receiver)) bad("ACCESSIBILITY_OBJECT", "Accessibility metadata constructor called twice");
            runtime.set_host_state(receiver, std::move(metadata));
            return Value::nothing();
        }
        const auto receiver = reference(0);
        const auto &stored = accessibility_object(receiver, kind);
        if (kind == Kind::collection_builder) {
            if (api.name == "build") {
                auto completed = std::make_unique<AccessibilityObjectState>(Kind::collection);
                completed->collection = stored.collection;
                return Value::reference(new_accessibility_object(accessibility_collection_type, std::move(completed)));
            }
            auto next = std::make_unique<AccessibilityObjectState>(stored);
            const auto value = integer(1);
            if (api.name == "setRowCount") next->collection.row_count = value;
            else if (api.name == "setColumnCount") next->collection.column_count = value;
            else if (api.name == "setHierarchical") next->collection.hierarchical = value != 0;
            else if (api.name == "setSelectionMode") next->collection.selection_mode = value;
            else if (api.name == "setItemCount") next->collection.item_count = value;
            else if (api.name == "setImportantForAccessibilityItemCount") next->collection.important_item_count = value;
            else bad("API_UNSUPPORTED", "Collection metadata builder method is unsupported");
            runtime.set_host_state(receiver, std::move(next));
            return Value::reference(receiver);
        } else if (kind == Kind::node) {
            if (api.name == "getActions") return Value::word(stored.actions);
            if (api.name == "isSelected") return Value::word(stored.selected);
            if (api.name == "addAction" || api.name == "setSelected") {
                auto next = std::make_unique<AccessibilityObjectState>(stored);
                const auto value = static_cast<std::uint32_t>(integer(1));
                if (api.name == "addAction") {
                    if (value & 0xffc00000u)
                        runtime.raise("Ljava/lang/IllegalArgumentException;", u"Action is not a combination of standard accessibility actions");
                    next->actions |= value;
                } else next->selected = value != 0;
                runtime.set_host_state(receiver, std::move(next));
                return Value::nothing();
            }
            if (api.name == "recycle") return Value::nothing(); // API33+ pooling was discontinued.
            if (api.name == "getCollectionInfo") return stored.references[1];
            if (api.name == "getCollectionItemInfo") return stored.references[2];
            if (api.name == "setCollectionInfo" || api.name == "setCollectionItemInfo" || api.name == "setSource") {
                const auto replacement = reference(1);
                const auto slot = api.name == "setSource" ? 0u : api.name == "setCollectionInfo" ? 1u : 2u;
                if (slot == 0) (void)accessibility_source(replacement);
                else if (replacement) (void)accessibility_object(replacement, slot == 1 ? Kind::collection : Kind::item);
                auto next = std::make_unique<AccessibilityObjectState>(stored);
                next->references[slot] = Value::reference(replacement);
                runtime.set_host_state(receiver, std::move(next));
                return Value::nothing();
            }
        } else if (kind == Kind::collection) {
            if (api.name == "getRowCount") return Value::word(static_cast<std::uint32_t>(stored.collection.row_count));
            if (api.name == "getColumnCount") return Value::word(static_cast<std::uint32_t>(stored.collection.column_count));
            if (api.name == "getSelectionMode") return Value::word(static_cast<std::uint32_t>(stored.collection.selection_mode));
            if (api.name == "getItemCount") return Value::word(static_cast<std::uint32_t>(stored.collection.item_count));
            if (api.name == "getImportantForAccessibilityItemCount") return Value::word(static_cast<std::uint32_t>(stored.collection.important_item_count));
            if (api.name == "isHierarchical") return Value::word(stored.collection.hierarchical);
        } else {
            if (api.name == "getRowIndex") return Value::word(static_cast<std::uint32_t>(stored.item.row_index));
            if (api.name == "getRowSpan") return Value::word(static_cast<std::uint32_t>(stored.item.row_span));
            if (api.name == "getColumnIndex") return Value::word(static_cast<std::uint32_t>(stored.item.column_index));
            if (api.name == "getColumnSpan") return Value::word(static_cast<std::uint32_t>(stored.item.column_span));
            if (api.name == "isHeading") return Value::word(stored.item.heading);
            if (api.name == "isSelected") return Value::word(stored.item.selected);
        }
        bad("API_UNSUPPORTED", "Accessibility method is outside the bounded collection metadata profile");
    }
    bool accessibility_cache_current() const noexcept {
        return accessibility_status == AccessibilityMetadataStatus::ready && attached && activity_attached && activity &&
            !terminal_cleanup && state != Lifecycle::empty && state != Lifecycle::destroyed && state != Lifecycle::failed &&
            activity == accessibility_activity && content == accessibility_content &&
            window_generation == accessibility_generation && metrics.view_revision == accessibility_view_revision &&
            accessibility_invalidation == accessibility_source_invalidation;
    }
    bool in_tree(ObjectId object) {
        for (std::size_t i = 0; object && i < 257; ++i) {
            if (object == content)
                return true;
            object = view(object).parent;
        }
        return false;
    }
    bool enabled(ObjectId object) {
        if (!object || !in_tree(object))
            return false;
        for (auto id = object; id; id = view(id).parent)
            if (!view(id).enabled)
                return false;
        return true;
    }
    bool clickable(ObjectId object) {
        const auto &node = view(object);
        return node.kind == ViewKind::checkbox || node.listener != 0;
    }
    bool focusable(ObjectId object) { return view(object).kind == ViewKind::edit_text || clickable(object); }
    const DragObjectState &drag_object(ObjectId object, DragObjectKind kind) {
        if (!object) runtime.raise("Ljava/lang/NullPointerException;");
        const auto *stored = dynamic_cast<const DragObjectState *>(runtime.host_state(object));
        if (!stored || stored->kind != kind) bad("DRAG_OBJECT", "Drag object has no authenticated framework storage");
        return *stored;
    }
    ObjectId new_drag_object(std::string_view type, std::unique_ptr<DragObjectState> metadata) {
        const auto object = runtime.new_object(type);
        runtime.set_host_state(object, std::move(metadata));
        return object;
    }
    void clear_drag_sequence() {
        if (!drag_sequence) return;
        auto retired = std::move(*drag_sequence);
        drag_sequence.reset();
        for (const auto object : retired.recipients) runtime.release(object);
        if (retired.description) disown(retired.description);
    }
    bool drag_current(std::uint64_t id) const {
        return drag_sequence && drag_sequence->id == id && drag_sequence->generation == window_generation &&
            drag_sequence->owner == activity && drag_sequence->root == content && activity_attached &&
            state == Lifecycle::resumed && active && visible && !suspended && window_focused && focused;
    }
    void release_drop_grant(ObjectId object) {
        const auto stored = drag_object(object, DragObjectKind::permissions);
        const auto found = std::find_if(drop_grants.begin(), drop_grants.end(),
            [&](const auto &grant) { return grant.permission == object; });
        if (!stored.released) {
            auto next = std::make_unique<DragObjectState>(stored);
            next->released = true;
            runtime.set_host_state(object, std::move(next)); // Consume before a non-replayable broker write.
        }
        // The retained record is authoritative even if a previous metadata
        // update was interrupted. After its removal no broker write is replayed.
        if (found == drop_grants.end()) return;
        const auto grant = std::move(*found); // No string allocation after consumption.
        drop_grants.erase(found);
        disown(object);
        auto *service = input_lease->documents;
        const auto result = service ? service->release_drop(grant.uri, grant.id) :
            host::FileResult{-1, host::FileError::denied};
        if (result.error != host::FileError::none || result.value != 0)
            bad("DRAG_PERMISSION_RELEASE", "The exact dropped-document grant could not be released");
    }
    void release_drop_grants() {
        std::exception_ptr failure;
        while (!drop_grants.empty()) {
            const auto object = drop_grants.back().permission;
            try { release_drop_grant(object); }
            catch (...) {
                // A metadata allocation failure must not leave a loop or let an
                // old Activity keep a grant. Consume once and try exact release.
                if (!drop_grants.empty() && drop_grants.back().permission == object) {
                    const auto grant = std::move(drop_grants.back()); drop_grants.pop_back();
                    disown(object);
                    if (input_lease->documents) (void)input_lease->documents->release_drop(grant.uri, grant.id);
                }
                if (!failure) failure = std::current_exception();
            }
        }
        if (failure) std::rethrow_exception(failure);
    }
    bool base_drag_dispatch(ObjectId object, ObjectId event) {
        ManagedRoot target_root(runtime, object), event_root(runtime, event);
        (void)drag_object(event, DragObjectKind::event);
        if (!views.contains(object)) return false;
        const auto listener = view_state(object).references[5].bits;
        if (listener && enabled(object)) {
            ManagedRoot listener_root(runtime, listener);
            const std::array arguments{Value::reference(object), Value::reference(event)};
            if (runtime.invoke_virtual_named(listener, "onDrag", "(Landroid/view/View;Landroid/view/DragEvent;)Z", arguments).bits)
                return true;
        }
        // A false listener result falls through to the actual virtual handler.
        if (!views.contains(object)) return false;
        const std::array arguments{Value::reference(event)};
        return runtime.invoke_virtual_named(object, "onDragEvent", "(Landroid/view/DragEvent;)Z", arguments).bits != 0;
    }
    bool send_drag_event(const DragSequence &sequence, ObjectId object, DragAction action,
                         float x, float y, const std::optional<host::DocumentInfo> &document = {},
                         const std::optional<std::u16string> &text = {}) {
        if (!views.contains(object)) return false;
        ManagedRoot target_root(runtime, object);
        auto metadata = std::make_unique<DragObjectState>(DragObjectKind::event);
        metadata->action = action; metadata->id = sequence.id; metadata->generation = sequence.generation;
        metadata->result = action == DragAction::ended && sequence.result;
        metadata->references[2] = Value::reference(sequence.owner);
        metadata->references[0] = Value::reference(action == DragAction::ended ? 0 : sequence.description);
        metadata->x = x - view(object).bounds.x; metadata->y = y - view(object).bounds.y;
        if (action == DragAction::drop && (document || text)) {
            const auto value = document ? new_uri(runtime, unicode(document->uri)) : runtime.new_string(*text);
            ManagedRoot value_root(runtime, value);
            auto item_state = std::make_unique<DragObjectState>(DragObjectKind::item);
            // A present empty String is a real plain-text item, not a null
            // item and not a URI or clipboard authority.
            item_state->references[document ? 0 : 1] = Value::reference(value);
            const auto item = new_drag_object(clip_item_type, std::move(item_state));
            ManagedRoot item_root(runtime, item);
            auto data_state = std::make_unique<DragObjectState>(DragObjectKind::data);
            data_state->references[0] = Value::reference(sequence.description);
            data_state->references[1] = Value::reference(item);
            const auto data = new_drag_object(clip_data_type, std::move(data_state));
            ManagedRoot data_root(runtime, data);
            metadata->references[1] = Value::reference(data);
            if (document) metadata->uri = document->uri;
            const auto event = new_drag_object(drag_event_type, std::move(metadata));
            ManagedRoot event_root(runtime, event);
            const auto previous = std::exchange(active_drag_event, event);
            struct Restore { ObjectId &slot; ObjectId old; ~Restore() { slot = old; } } restore{active_drag_event, previous};
            const std::array arguments{Value::reference(event)};
            return runtime.invoke_virtual_named(object, "dispatchDragEvent", "(Landroid/view/DragEvent;)Z", arguments).bits != 0;
        }
        const auto event = new_drag_object(drag_event_type, std::move(metadata));
        ManagedRoot event_root(runtime, event);
        const std::array arguments{Value::reference(event)};
        return runtime.invoke_virtual_named(object, "dispatchDragEvent", "(Landroid/view/DragEvent;)Z", arguments).bits != 0;
    }
    ObjectId drag_hit(ObjectId object, float x, float y) {
        if (!drag_sequence || !views.contains(object)) return 0;
        const auto &node = view(object);
        if (!node.enabled || !node.bounds.contains(x, y)) return 0;
        for (auto child = node.children.rbegin(); child != node.children.rend(); ++child)
            if (const auto found = drag_hit(*child, x, y)) return found;
        return std::find(drag_sequence->interested.begin(), drag_sequence->interested.end(), object) !=
            drag_sequence->interested.end() ? object : 0;
    }
    bool change_drag_target(float x, float y) {
        if (!drag_sequence) return false;
        const auto id = drag_sequence->id;
        auto next = drag_hit(content, x, y);
        const auto previous = drag_sequence->target;
        if (next != previous) {
            drag_sequence->target = 0; // Callback mutations cannot restore the old target.
            if (previous && views.contains(previous) && in_tree(previous))
                (void)send_drag_event(*drag_sequence, previous, DragAction::exited, x, y);
            if (!drag_current(id)) return false;
            next = drag_hit(content, x, y);
            if (next) {
                drag_sequence->target = next;
                (void)send_drag_event(*drag_sequence, next, DragAction::entered, x, y);
                if (!drag_current(id)) return false;
                if (drag_hit(content, x, y) != next) { drag_sequence->target = 0; return false; }
            }
        }
        return drag_sequence->target != 0;
    }
    bool finish_drag_sequence(bool canceled) {
        if (!drag_sequence) return false;
        auto ending = std::move(*drag_sequence); drag_sequence.reset();
        if (canceled) ending.result = false;
        struct Release {
            Impl &p; DragSequence &value;
            ~Release() { for (const auto object : value.recipients) p.runtime.release(object); p.disown(value.description); }
        } release{*this, ending};
        for (const auto object : ending.interested) {
            if (ending.owner != activity || ending.generation != window_generation || ending.root != content) break;
            if (views.contains(object) && in_tree(object)) (void)send_drag_event(ending, object, DragAction::ended, 0, 0);
        }
        return ending.result;
    }
    bool dispatch_drag(const DragInput &input) {
        if (!input.id || !std::isfinite(input.x) || !std::isfinite(input.y) ||
            std::abs(input.x) > 32768 || std::abs(input.y) > 32768 ||
            static_cast<unsigned>(input.action) < 1 || static_cast<unsigned>(input.action) > 6 ||
            static_cast<unsigned>(input.kind) > static_cast<unsigned>(host::DropPayloadKind::plain_text) ||
            !host::valid_document_mime(input.mime_type) ||
            (input.kind == host::DropPayloadKind::plain_text && input.mime_type != "text/plain") ||
            (input.action != DragAction::drop && (input.document || input.text_info || input.text)) ||
            (input.document && (input.kind != host::DropPayloadKind::file || !host::valid_document_info(*input.document))) ||
            ((input.text_info || input.text) && input.kind != host::DropPayloadKind::plain_text))
            bad("DRAG_ARGUMENT", "Drag event fields are outside the bounded external file/plain-text profile");
        if (dispatching_drag) bad("DRAG_REENTRY", "External drag commands cannot reenter managed drag dispatch");
        dispatching_drag = true;
        struct Reset { bool &value; ~Reset() { value = false; } } reset{dispatching_drag};
        if (input.action == DragAction::started) {
            if (input.id <= last_drag_id || !host::valid_document_mime(input.mime_type) || input.document ||
                !soft_input_window_ready() || !content || pointer_target || key_target) return false;
            last_drag_id = input.id;
            const auto baseline = metrics.view_revision;
            if (drag_sequence) (void)finish_drag_sequence(true);
            if (drag_sequence || metrics.view_revision != baseline || !soft_input_window_ready() || !content ||
                pointer_target || key_target) return false;
            DragSequence next;
            next.id = input.id; next.generation = window_generation; next.kind = input.kind;
            next.owner = activity; next.root = content;
            next.mime = input.mime_type; next.x = input.x; next.y = input.y;
            auto description = std::make_unique<DragObjectState>(DragObjectKind::description);
            description->mime = input.mime_type;
            next.description = own(new_drag_object(clip_description_type, std::move(description)));
            drag_sequence.emplace(std::move(next));
            std::vector<ObjectId> pending{content};
            while (!pending.empty() && drag_current(input.id)) {
                const auto object = pending.back(); pending.pop_back();
                if (!views.contains(object) || !enabled(object)) continue;
                const auto children = view(object).children;
                pending.insert(pending.end(), children.rbegin(), children.rend());
                runtime.retain(object);
                try { drag_sequence->recipients.push_back(object); }
                catch (...) { runtime.release(object); throw; }
                const bool interested = send_drag_event(*drag_sequence, object, DragAction::started, input.x, input.y);
                if (!drag_current(input.id)) break;
                if (interested && views.contains(object) && in_tree(object) && enabled(object)) drag_sequence->interested.push_back(object);
            }
            return drag_current(input.id) && !drag_sequence->interested.empty();
        }
        if (!drag_sequence || drag_sequence->id != input.id) return false;
        if (input.mime_type != drag_sequence->mime || input.kind != drag_sequence->kind) return false;
        if (input.action == DragAction::ended) {
            // Retire live authority before callbacks; retained events cannot
            // create another grant. Only the real DROP result is reported.
            return finish_drag_sequence(false);
        }
        if (!drag_current(input.id) || drag_sequence->dropped) return false;
        drag_sequence->x = input.x; drag_sequence->y = input.y;
        if (input.action == DragAction::exited) {
            const auto target = std::exchange(drag_sequence->target, 0);
            if (target && views.contains(target) && in_tree(target))
                (void)send_drag_event(*drag_sequence, target, DragAction::exited, input.x, input.y);
            return false;
        }
        if (!change_drag_target(input.x, input.y) || !drag_current(input.id)) return false;
        const auto target = drag_sequence->target;
        if (input.action == DragAction::entered) return true;
        if (input.action == DragAction::location) {
            (void)send_drag_event(*drag_sequence, target, DragAction::location, input.x, input.y);
            return drag_current(input.id) && drag_sequence->target == target;
        }
        if (input.action != DragAction::drop) return false;
        if (input.kind == host::DropPayloadKind::file) {
            if (!input.document || input.text_info || input.text || input.document->mime_type != drag_sequence->mime) return false;
            host::DocumentInfo actual;
            const auto described = input_lease->documents ? input_lease->documents->describe(input.document->uri, actual) :
                host::FileResult{-1, host::FileError::denied};
            if (described.error != host::FileError::none || described.value != 0 || actual != *input.document) return false;
        } else {
            if (input.document || !input.text_info || !input.text ||
                !host::matches_drop_text(*input.text_info, *input.text)) return false;
        }
        drag_sequence->dropped = true; // Real DROP is delivered at most once.
        const bool accepted = send_drag_event(*drag_sequence, target, DragAction::drop, input.x, input.y, input.document, input.text);
        // A successful callback may replace its content tree. Preserve its
        // actual result without restoring that tree or its old target.
        if (!drag_sequence || drag_sequence->id != input.id || drag_sequence->generation != window_generation ||
            drag_sequence->owner != activity) return false;
        drag_sequence->result = accepted;
        // A real permission request has its own Activity/release lifetime,
        // independent of the listener's reported DROP result.
        return accepted;
    }
    ObjectId request_drag_permissions(ObjectId receiver, ObjectId event) {
        const auto delivered = drag_object(event, DragObjectKind::event);
        if (receiver != activity || event != active_drag_event || delivered.action != DragAction::drop ||
            delivered.references[2].bits != activity || delivered.generation != window_generation ||
            !drag_current(delivered.id) || !drag_sequence->dropped || delivered.uri.empty() || !input_lease->documents)
            return 0;
        const auto existing = std::find_if(drop_grants.begin(), drop_grants.end(),
            [&](const auto &grant) { return grant.id == delivered.id && grant.generation == window_generation; });
        if (existing != drop_grants.end()) return existing->permission;
        if (drop_grants.size() >= host::document_stream_limit)
            bad("DRAG_PERMISSION_LIMIT", "The bounded dropped-document grant quota is exhausted");
        auto metadata = std::make_unique<DragObjectState>(DragObjectKind::permissions);
        metadata->id = delivered.id; metadata->generation = window_generation; metadata->uri = delivered.uri;
        metadata->references[0] = Value::reference(activity);
        const auto permission = own(new_drag_object(drag_permissions_type, std::move(metadata)));
        try { drop_grants.push_back({delivered.id, window_generation, delivered.uri, permission}); }
        catch (...) { disown(permission); throw; }
        const auto result = input_lease->documents->claim_drop(delivered.uri, delivered.id);
        if (result.error != host::FileError::none || result.value != 0) {
            drop_grants.pop_back(); disown(permission);
            if (result.error == host::FileError::denied) runtime.raise("Ljava/lang/SecurityException;", u"Dropped-document read permission is denied");
            bad("DRAG_PERMISSION_UNAVAILABLE", "The exact reviewed document grant is unavailable");
        }
        return permission;
    }
    Value drag_api(const ApiSupport &api, std::span<const Value> args) {
        if (args.empty() || args[0].kind != dex::ValueKind::reference)
            bad("DRAG_ARGUMENT", "Drag API requires its reference receiver");
        const auto receiver = args[0].bits;
        ManagedRoot receiver_root(runtime, receiver);
        const auto name = api.name;
        if (api.owner == drag_event_type) {
            const auto current = drag_object(receiver, DragObjectKind::event);
            if (name == "getAction") return Value::word(static_cast<std::uint32_t>(current.action));
            if (name == "getX") return Value::word(std::bit_cast<std::uint32_t>(current.x));
            if (name == "getY") return Value::word(std::bit_cast<std::uint32_t>(current.y));
            if (name == "getClipDescription") return current.references[0];
            if (name == "getClipData") return current.references[1];
            if (name == "getLocalState") return Value::reference(0); // External Windows source.
            if (name == "getResult") return Value::word(current.result);
        } else if (api.owner == clip_data_type) {
            const auto current = drag_object(receiver, DragObjectKind::data);
            if (name == "getDescription") return current.references[0];
            if (name == "getItemCount") return Value::word(1);
            if (name == "getItemAt") {
                if (args.size() != 2 || args[1].kind != dex::ValueKind::word)
                    bad("DRAG_ARGUMENT", "ClipData item index requires an int");
                if (args[1].bits) runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
                return current.references[1];
            }
        } else if (api.owner == clip_item_type) {
            const auto current = drag_object(receiver, DragObjectKind::item);
            if (name == "getUri") return current.references[0];
            if (name == "getText") return current.references[1];
            if (name == "coerceToText") {
                if (current.references[1].bits) return current.references[1];
                runtime.raise("Ljava/lang/UnsupportedOperationException;", u"URI item text coercion is unsupported");
            }
            if (name == "getIntent" || name == "getHtmlText") return Value::reference(0);
        } else if (api.owner == clip_description_type) {
            const auto current = drag_object(receiver, DragObjectKind::description);
            if (name == "getMimeTypeCount") return Value::word(1);
            if (name == "getLabel") return current.references[0].bits ? current.references[0] :
                Value::reference(current.label.empty() ? 0 : runtime.new_string(unicode(current.label)));
            if (name == "getMimeType") {
                if (args.size() != 2 || args[1].kind != dex::ValueKind::word)
                    bad("DRAG_ARGUMENT", "ClipDescription MIME index requires an int");
                if (args[1].bits) runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
                return Value::reference(runtime.new_string(unicode(current.mime)));
            }
            if (name == "hasMimeType") {
                if (args.size() != 2 || !args[1].bits) runtime.raise("Ljava/lang/NullPointerException;");
                const auto wanted = narrow(runtime.string(args[1].bits));
                const auto slash = current.mime.find('/');
                return Value::word(wanted == "*/*" || wanted == current.mime ||
                    (wanted.ends_with("/*") && slash != std::string::npos && wanted.substr(0, wanted.size() - 2) == current.mime.substr(0, slash)));
            }
        } else if (api.owner == drag_permissions_type) {
            (void)drag_object(receiver, DragObjectKind::permissions);
            if (name == "release") { release_drop_grant(receiver); return Value::nothing(); }
        }
        bad("DRAG_API_UNSUPPORTED", "Drag API is outside the supported single read-only file/plain-text profile");
    }
    ObjectId hit(ObjectId root, float x, float y) {
        const auto &node = view(root);
        if (!node.enabled || !node.bounds.contains(x, y))
            return 0;
        for (auto child = node.children.rbegin(); child != node.children.rend(); ++child)
            if (const auto target = hit(*child, x, y))
                return target;
        return focusable(root) ? root : 0;
    }
    std::int32_t virtual_pixels(float dp) const {
        return static_cast<std::int32_t>(std::floor(static_cast<double>(dp) * configuration.density_dpi / 160.0 + 0.5));
    }
    void apply_scroll_layout() {
        if (!content || view(content).kind != ViewKind::scroll_view) return;
        auto &root = view(content);
        const auto previous_y = root.scroll_y, previous_range = root.scroll_range_y;
        const auto previous_viewport = root.scroll_viewport_y;
        root.scroll_viewport_y = unscrolled_bounds.contains(content)
            ? virtual_pixels(unscrolled_bounds.at(content).height) : 0;
        const auto child = root.children.empty() ? 0 : root.children.front();
        const auto content_height = child && unscrolled_bounds.contains(child)
            ? virtual_pixels(unscrolled_bounds.at(child).height) : 0;
        root.scroll_range_y = root.scroll_viewport_y > 0
            ? std::max(0, content_height - root.scroll_viewport_y) : 0;
        root.scroll_y = std::clamp(root.scroll_y, 0, root.scroll_range_y);
        const auto offset = static_cast<float>(root.scroll_y) * 160.0f / static_cast<float>(configuration.density_dpi);
        bool changed = previous_y != root.scroll_y || previous_range != root.scroll_range_y ||
                       previous_viewport != root.scroll_viewport_y;
        for (const auto &[id, natural] : unscrolled_bounds) {
            if (!in_tree(id)) continue;
            auto effective = natural;
            if (id != content) effective.y -= offset;
            auto &current = view(id).bounds;
            changed = changed || current != effective;
            current = effective;
        }
        if (changed) ++metrics.view_revision;
    }
    void scroll_to_base(ObjectId object, std::int32_t y) {
        auto &node = view(object);
        if (node.kind != ViewKind::scroll_view)
            runtime.raise("Ljava/lang/UnsupportedOperationException;", u"Scrolling requires a supported root ScrollView");
        if (node.parent || (in_tree(object) && object != content))
            runtime.raise("Ljava/lang/UnsupportedOperationException;", u"Nested ScrollViews are unsupported");
        if (object != content || node.children.empty()) return;
        const auto next = std::clamp(y, 0, node.scroll_range_y);
        if (node.scroll_y == next) return;
        node.scroll_y = next;
        ++metrics.view_revision;
        apply_scroll_layout();
    }
    void dispatch_scroll_to(ObjectId object, std::int32_t x, std::int32_t y) {
        if (const auto method = override_method(runtime.object_type(object), "scrollTo", "(II)V")) {
            const std::array args{Value::reference(object), Value::word(std::bit_cast<std::uint32_t>(x)),
                                  Value::word(std::bit_cast<std::uint32_t>(y))};
            (void)runtime.invoke_virtual(*method, args);
        } else scroll_to_base(object, y);
    }
    void scroll_by_base(ObjectId object, std::int32_t x, std::int32_t y) {
        // View.scrollBy calls virtual scrollTo; Java int addition wraps.
        const auto target = std::bit_cast<std::int32_t>(std::bit_cast<std::uint32_t>(view(object).scroll_y) +
                                                       std::bit_cast<std::uint32_t>(y));
        dispatch_scroll_to(object, x, target);
    }
    void dispatch_scroll_by(ObjectId object, std::int32_t y) {
        if (const auto method = override_method(runtime.object_type(object), "scrollBy", "(II)V")) {
            const std::array args{Value::reference(object), Value::word(0), Value::word(std::bit_cast<std::uint32_t>(y))};
            (void)runtime.invoke_virtual(*method, args);
        } else scroll_by_base(object, 0, y);
    }
    void reveal_focus(ObjectId object) {
        if (!object || !content || view(content).kind != ViewKind::scroll_view || !in_tree(object) ||
            object == content || !unscrolled_bounds.contains(object) || !unscrolled_bounds.contains(content)) return;
        const auto natural = unscrolled_bounds.at(object);
        const auto origin = unscrolled_bounds.at(content).y;
        const auto top = virtual_pixels(natural.y - origin), bottom = virtual_pixels(natural.y + natural.height - origin);
        const auto offset = view(content).scroll_y, height = view(content).scroll_viewport_y;
        const auto target = top < offset ? top : bottom > offset + height
            ? (bottom - top > height ? top : bottom - height) : offset;
        if (height > 0 && target != offset) dispatch_scroll_to(content, 0, target);
    }
    void focus(ObjectId object) {
        if (focused_view == object)
            return;
        const auto previous = focused_view;
        clear_soft_input_requests();
        retire_ime(true);
        if (focused_view != previous || (object &&
            (state != Lifecycle::resumed || !views.contains(object) || !enabled(object) || !focusable(object)))) return;
        if (key_target) {
            view(key_target).pressed = false;
            key_target = 0;
            held_key = 0;
        }
        if (focused_view)
            view(focused_view).focused = false;
        focused_view = object;
        if (focused_view)
            view(focused_view).focused = true;
        ++metrics.view_revision;
    }
    void cancel_input() {
        const bool changed = pointer_target || key_target;
        if (pointer_target)
            view(pointer_target).pressed = false;
        if (key_target)
            view(key_target).pressed = false;
        pointer_target = key_target = 0;
        held_key = 0;
        if (changed)
            ++metrics.view_revision;
    }
    bool default_pointer(const PointerInput &event) {
        if (state != Lifecycle::resumed || !content)
            return false;
        if (event.action == PointerAction::cancel) {
            const bool handled = pointer_target != 0;
            cancel_input();
            return handled;
        }
        if (event.action == PointerAction::down) {
            if (pointer_target)
                return false; // Single-pointer subset; do not replace a live gesture.
            cancel_input();
            pointer_target = hit(content, event.x, event.y);
            pointer_id = event.pointer;
            if (!pointer_target)
                return false;
            const auto target = pointer_target;
            focus(target);
            if (pointer_target != target || focused_view != target || state != Lifecycle::resumed ||
                !views.contains(target) || !enabled(target) || !focusable(target)) {
                if (pointer_target == target) { pointer_target = 0; pointer_id = 0; }
                return false;
            }
            view(target).pressed = true;
            ++metrics.view_revision;
            return true;
        }
        if (!pointer_target || event.pointer != pointer_id)
            return false;
        const auto target = pointer_target;
        const bool inside = enabled(target) && hit(content, event.x, event.y) == target;
        if (event.action == PointerAction::move) {
            if (view(target).pressed != inside) {
                view(target).pressed = inside;
                ++metrics.view_revision;
            }
            return true;
        }
        pointer_target = 0;
        view(target).pressed = false;
        ++metrics.view_revision;
        const auto prior_soft_input_revision = soft_input_revision;
        if (inside)
            (void)perform_click(target);
        // Only the actual accepted default editor touch path may request an
        // implicit keyboard. Real click callbacks have already run and can
        // replace the tree, focus or editor without being overridden here.
        if (inside && soft_input_revision == prior_soft_input_revision && soft_input_editor_ready(target, true))
            (void)enqueue_soft_input(target, true, true);
        return true;
    }
    KeyInput key_event(ObjectId event) const {
        const auto found = input_events.find(event);
        if (found == input_events.end() || !found->second.key)
            bad("INPUT", "Key event has expired or belongs to another session");
        return *found->second.key;
    }
    bool key_callback(ObjectId receiver, ObjectId event) {
        ManagedRoot receiver_root(runtime, receiver), event_root(runtime, event);
        const auto input = key_event(event);
        if (!receiver) runtime.raise("Ljava/lang/NullPointerException;");
        if (!runtime.assignable(receiver, key_callback_type))
            runtime.raise("Ljava/lang/IllegalArgumentException;", u"Key dispatch requires KeyEvent.Callback");
        const std::array args{Value::word(input.code), Value::reference(event)};
        return runtime.invoke_virtual_named(receiver, input.up ? "onKeyUp" : "onKeyDown",
                                            "(ILandroid/view/KeyEvent;)Z", args).bits != 0;
    }
    bool view_key_base(ObjectId object, std::uint32_t code, ObjectId event, bool text_view, bool up) {
        const auto input = key_event(event);
        ManagedRoot object_root(runtime, object), event_root(runtime, event);
        if (text_view && !up && view(object).enabled && view(object).kind == ViewKind::edit_text &&
            input.character_status != KeyCharacterStatus::bmp &&
            (code == 67 || code == 112) && !(input.meta & ~(key_lock_meta_mask | 0x1003u))) {
            const auto buffer = view_state(object).references[2].bits;
            ManagedRoot buffer_root(runtime, buffer);
            const auto start = selection_state(buffer).start, end = selection_state(buffer).end;
            if (start != end) {
                const auto empty = runtime.new_string({});
                ManagedRoot empty_root(runtime, empty);
                // BaseKeyListener deletes the captured content's selection before
                // word/line modifiers. Existing marker movement owns the cursor;
                // a callback's new selection or replacement buffer must survive.
                replace_buffer(buffer, std::min(start, end), std::max(start, end), empty, 0, 0);
                return true;
            }
        }
        if (text_view && !up && view(object).enabled && view(object).kind == ViewKind::edit_text &&
            input.character_status == KeyCharacterStatus::bmp && code != 61 &&
            input.unicode != 0xef00 && input.unicode != 0xef01) {
            const auto buffer = view_state(object).references[2].bits;
            ManagedRoot buffer_root(runtime, buffer);
            auto start = std::min(selection_state(buffer).start, selection_state(buffer).end);
            auto end = std::max(selection_state(buffer).start, selection_state(buffer).end);
            if (start < 0 || end < 0) {
                start = end = 0;
                set_selection(buffer, 0, 0);
            }
            // QwertyKeyListener collapses selection before replacing its saved
            // range. Selection callbacks may replace the owner's current buffer;
            // retain this original content and do not force a cursor afterward.
            if (start != end) set_selection(buffer, end, end);
            const auto source = runtime.new_string(std::u16string(1, static_cast<char16_t>(input.unicode)));
            ManagedRoot source_root(runtime, source);
            replace_buffer(buffer, start, end, source, 0, 1);
            return true;
        }
        // Collapsed-cursor deletion, movement and character-picker/hex input remain unsupported.
        if ((input.meta & ~key_lock_meta_mask) || (code != 23 && code != 66 && code != 62 && code != 160)) return false;
        if (!view(object).enabled) return true;
        if (view(object).kind == ViewKind::edit_text) return false;
        if (!up) {
            if (input.repeat || pointer_target || !clickable(object) || (key_target && key_target != object)) return false;
            key_target = object;
            held_key = code;
            view(object).pressed = true;
            ++metrics.view_revision;
            return true;
        }
        if (key_target != object || held_key != code) return false;
        key_target = 0;
        held_key = 0;
        view(object).pressed = false;
        ++metrics.view_revision;
        return enabled(object) && perform_click(object);
    }
    bool dispatch_view_key(ObjectId object, ObjectId event) {
        ManagedRoot object_root(runtime, object), event_root(runtime, event);
        const std::array args{Value::reference(event)};
        return runtime.invoke_virtual_named(object, "dispatchKeyEvent", "(Landroid/view/KeyEvent;)Z", args).bits != 0;
    }
    bool view_key_dispatch_base(ObjectId object, ObjectId event, bool group) {
        ManagedRoot object_root(runtime, object), event_root(runtime, event);
        const auto input = key_event(event);
        if (group && focused_view != object) {
            // Each ViewGroup forwards to its current direct focused child. Its
            // managed override may consume or call super before any leaf listener.
            auto child = focused_view;
            for (std::size_t depth = 0; child && depth < 256; ++depth) {
                const auto parent = view(child).parent;
                if (parent == object) return dispatch_view_key(child, event);
                child = parent;
            }
            return false;
        }
        const auto listener = view_state(object).references[4].bits;
        if (listener && view(object).enabled) {
            ManagedRoot listener_root(runtime, listener);
            const std::array args{Value::reference(object), Value::word(input.code), Value::reference(event)};
            if (runtime.invoke_virtual_named(listener, "onKey", "(Landroid/view/View;ILandroid/view/KeyEvent;)Z", args).bits)
                return true;
        }
        // Even if a non-consuming listener moves focus, Android dispatches the
        // event callback on this original receiver, not the newly focused View.
        return key_callback(object, event);
    }
    bool default_key(ObjectId event_object) {
        if (state != Lifecycle::resumed || !content)
            return false;
        const auto event = key_event(event_object);
        const auto root = content;
        if (focused_view && enabled(focused_view) && dispatch_view_key(root, event_object)) return true;
        if (key_callback(activity, event_object)) return true;
        if (state != Lifecycle::resumed || !content) return false;
        if (event.code == 61 && !event.up && !(event.meta & ~(key_lock_meta_mask | 1u))) { // Unhandled Tab/Shift+Tab traversal.
            std::vector<ObjectId> order, todo{content};
            while (!todo.empty()) {
                const auto id = todo.back();
                todo.pop_back();
                const auto &node = view(id);
                if (focusable(id) && enabled(id))
                    order.push_back(id);
                todo.insert(todo.end(), node.children.rbegin(), node.children.rend());
            }
            if (order.empty())
                return false;
            auto found = std::find(order.begin(), order.end(), focused_view);
            auto at = found == order.end() ? std::size_t(0) : static_cast<std::size_t>(found - order.begin());
            if (found != order.end())
                at = event.meta & 1 ? (at + order.size() - 1) % order.size() : (at + 1) % order.size();
            else if (event.meta & 1)
                at = order.size() - 1;
            focus(order[at]);
            reveal_focus(order[at]);
            return true;
        }
        return false;
    }
    bool dispatch_input(InputData data) {
        if (state != Lifecycle::resumed)
            return false;
        if (input_events.size() >= 8)
            bad("INPUT_REENTRANT", "Input dispatch nesting quota exceeded");
        const bool motion = data.pointer.has_value();
        const auto id = runtime.new_object(motion ? "Landroid/view/MotionEvent;" : "Landroid/view/KeyEvent;");
        runtime.retain(id);
        struct End {
            Impl &p;
            ObjectId id;
            ~End() {
                p.input_events.erase(id);
                p.runtime.release(id);
            }
        } end{*this, id};
        input_events.emplace(id, data);
        if (motion)
            ++metrics.pointer_events;
        else
            ++metrics.key_events;
        const auto method =
            override_method(activity_type, motion ? "dispatchTouchEvent" : "dispatchKeyEvent",
                            motion ? "(Landroid/view/MotionEvent;)Z" : "(Landroid/view/KeyEvent;)Z");
        try {
            if (method) {
                const std::array args{Value::reference(activity), Value::reference(id)};
                return runtime.invoke(*method, args).bits != 0;
            }
            return motion ? default_pointer(*data.pointer) : default_key(id);
        } catch (...) {
            cancel_input();
            throw;
        }
    }
    struct EditCall {
        Impl &owner;
        explicit EditCall(Impl &owner) : owner(owner) {
            owner.check_text_edit_observer_idle();
            if (owner.text_depth >= 8) bad("TEXT_DEPTH", "Text callback nesting quota is eight");
            ++owner.text_depth;
        }
        ~EditCall() { --owner.text_depth; }
    };
    struct ConversionObservation {
        Impl &session;
        ManagedRoot owner, buffer;
        ConversionObservation *previous;
        const ImeBinding *identity;
        std::uint64_t token, buffer_revision, text_revision, initial_event_revision;
        std::int32_t first, last;
        std::int32_t native_old_first = -1, native_old_last = -1;
        std::u16string_view native_baseline;
        bool native_prefix_candidate = false, native_prefix_used = false;
        bool native_membership_candidate = false, native_membership_used = false;
        std::int32_t native_membership_prefix = 0, native_member_first = -1, native_member_last = -1;
        bool proven, target_present, legacy_unchanged, pending_unknown = false, gap_recorded = false;
        ConversionObservation(Impl &session, ObjectId view_id, ObjectId editable_id)
            : session(session), owner(session.runtime, view_id), buffer(session.runtime, editable_id),
              previous(session.conversion_observation), identity(session.ime.get()),
              token(session.ime ? session.ime->token : 0),
              buffer_revision(session.view(view_id).text_buffer_revision),
              text_revision(session.view(view_id).text_event_revision),
              initial_event_revision(session.view(view_id).text_edit_event_revision),
              first(session.view(view_id).conversion_start), last(session.view(view_id).conversion_end),
              proven(session.view(view_id).conversion_available), target_present(proven && first >= 0),
              legacy_unchanged(proven) {
            session.conversion_observation = this;
        }
        ConversionObservation(const ConversionObservation &) = delete;
        ConversionObservation &operator=(const ConversionObservation &) = delete;
        ConversionObservation(ConversionObservation &&) = delete;
        ConversionObservation &operator=(ConversionObservation &&) = delete;
        bool matches(ObjectId view, ObjectId editable) const noexcept {
            return owner.object == view && buffer.object == editable;
        }
        bool current() const {
            return session.current_editable(owner.object, buffer.object) &&
                session.view(owner.object).text_buffer_revision == buffer_revision;
        }
        bool binding_current() const {
            return session.ime && session.ime.get() == identity && session.ime->token == token && current();
        }
        static bool utf16_boundary(std::u16string_view text, std::size_t position) noexcept {
            return position <= text.size() && (!position || position == text.size() ||
                !(text[position - 1] >= 0xd800 && text[position - 1] <= 0xdbff &&
                  text[position] >= 0xdc00 && text[position] <= 0xdfff));
        }
        void native_prefix(const ImeConversionTarget &target, std::u16string_view incoming) {
            if (!proven || first < 0 || !binding_current() || !session.ime->owned_preedit ||
                !target.available || target.unchanged_prefix <= 0) return;
            const auto &metadata = session.selection_state(buffer.object);
            const auto begin = metadata.composing_start, end = metadata.composing_end;
            if (begin < 0 || end <= begin || static_cast<std::size_t>(end) > metadata.text.size() ||
                first < begin || last <= first || last > end) return;
            const auto old = std::u16string_view(metadata.text).substr(static_cast<std::size_t>(begin),
                static_cast<std::size_t>(end - begin));
            const auto prefix = static_cast<std::size_t>(target.unchanged_prefix);
            // Keep an unchanged native unit after the old target. A change
            // starting exactly at its edge may merely append target content.
            if (prefix > old.size() || prefix > incoming.size() ||
                !utf16_boundary(old, prefix) || !utf16_boundary(incoming, prefix) ||
                old.substr(0, prefix) != incoming.substr(0, prefix)) return;
            // Hash the actual complete old composing text, with explicit
            // UTF-16LE encoding. The token is a baseline check, never a clause ID.
            try {
                std::array<std::uint8_t, editable_text_limit * 2> bytes{};
                for (std::size_t index = 0; index < old.size(); ++index) {
                    bytes[index * 2] = static_cast<std::uint8_t>(old[index] & 0xff);
                    bytes[index * 2 + 1] = static_cast<std::uint8_t>(old[index] >> 8);
                }
                if (apk::sha256(std::span<const std::uint8_t>(bytes.data(), old.size() * 2)) !=
                    target.previous_composition_sha256) return;
            } catch (...) { return; } // Optional evidence failure cannot refuse a guest edit.
            native_old_first = begin; native_old_last = end;
            native_baseline = incoming;
            native_prefix_candidate = last - begin < target.unchanged_prefix;
            native_membership_candidate = true;
            native_membership_prefix = target.unchanged_prefix;
            native_member_first = std::min(first - begin, native_membership_prefix);
            native_member_last = std::min(last - begin, native_membership_prefix);
            if (native_member_first == native_member_last) native_member_first = native_member_last = -1;
        }
        void flush_unknown() noexcept {
            if (!pending_unknown) return;
            pending_unknown = false;
            try {
                if (!current()) return;
                auto &node = session.view(owner.object);
                const bool existing_gap = !node.conversion_available &&
                    node.text_edit_event_revision > initial_event_revision &&
                    node.text_edit_dropped_revision == node.text_edit_event_revision;
                node.conversion_available = false;
                node.conversion_start = node.conversion_end = -1;
                if (!gap_recorded) {
                    gap_recorded = true;
                    if (!existing_gap) session.record_text_edit(owner.object, buffer.object,
                        TextEditEventKind::conversion_target_changed, {}, false);
                }
            } catch (...) { } // Observation cannot replace a guest exception.
        }
        void interrupt() noexcept {
            bool known = proven;
            try { known = known || (current() && session.view(owner.object).conversion_available); } catch (...) { }
            proven = false;
            legacy_unchanged = false;
            native_prefix_candidate = false;
            native_prefix_used = false;
            native_membership_candidate = false;
            native_membership_used = false;
            pending_unknown = pending_unknown || known;
            flush_unknown();
        }
        void mutation(std::int32_t start, std::int32_t removed, std::int32_t inserted,
                      std::int32_t before_length, bool composition_ended, bool same_composition,
                      bool matched_base, std::int32_t old_region_first, std::int32_t old_region_last,
                      std::int32_t new_region_first, std::int32_t new_region_last,
                      std::u16string_view replacement) {
            if (native_membership_used) {
                native_membership_used = false; // A second actual commit cannot reuse the native witness.
                if (!proven && !legacy_unchanged) { interrupt(); return; }
            }
            if (!proven && !legacy_unchanged) return;
            const auto revision = session.view(owner.object).text_event_revision;
            if (!binding_current() || text_revision == UINT64_MAX || revision != text_revision + 1 ||
                start < 0 || removed < 0 || inserted < 0 || start > before_length ||
                removed > before_length - start) { interrupt(); return; }
            if (native_prefix_candidate || native_membership_candidate) {
                // Only the first exact authenticated Base replacement can use
                // native untouched-prefix evidence. Earlier arbitrary commits
                // cannot be repaired by later matching text.
                const bool range_candidate = native_prefix_candidate, membership_candidate = native_membership_candidate;
                native_prefix_candidate = native_membership_candidate = false;
                if (matched_base && start == native_old_first && start + removed == native_old_last &&
                    old_region_first == native_old_first && old_region_last == native_old_last &&
                    new_region_first == start && new_region_last == start + inserted &&
                    replacement == native_baseline) {
                    native_prefix_used = range_candidate;
                    native_membership_used = membership_candidate;
                    proven = range_candidate;
                    legacy_unchanged = legacy_unchanged && same_composition;
                    pending_unknown = true;
                    text_revision = revision;
                    return;
                }
            }
            if (composition_ended) {
                // Actual composition removal establishes an end, independent
                // of replacement identity. Settle it after composition payloads.
                text_revision = revision;
                proven = true; // Prior positive/absence evidence settles only this actual end.
                legacy_unchanged = false;
                return;
            }
            if (!same_composition) legacy_unchanged = false;
            if (!proven) {
                if (legacy_unchanged) text_revision = revision;
                else interrupt();
                return;
            }
            if (first >= 0) {
                const auto end = start + removed, delta = inserted - removed;
                if (end < first) { first += delta; last += delta; }
                else if (start > last) { }
                else if (start > first && end < last) last += delta;
                else {
                    // Equal preedit keeps the existing unchanged-data path,
                    // separate from retained-boundary proof for changed text.
                    if (legacy_unchanged) {
                        proven = false; pending_unknown = true; text_revision = revision;
                    } else interrupt();
                    return;
                }
                if (first < 0 || last <= first || last > before_length - removed + inserted) {
                    interrupt(); return;
                }
            }
            text_revision = revision;
        }
        std::optional<ImeConversionTarget> previous_target() const {
            if (!proven || !binding_current() || session.view(owner.object).text_event_revision != text_revision)
                return {};
            const auto &metadata = session.selection_state(buffer.object);
            if (native_prefix_used && (metadata.composing_start < 0 ||
                metadata.composing_end <= metadata.composing_start ||
                std::u16string_view(metadata.text).substr(static_cast<std::size_t>(metadata.composing_start),
                    static_cast<std::size_t>(metadata.composing_end - metadata.composing_start)) != native_baseline))
                return {};
            if (metadata.composing_start < 0 || metadata.composing_end <= metadata.composing_start ||
                (first >= 0 && (first < metadata.composing_start || last > metadata.composing_end))) return {};
            return ImeConversionTarget{true, first < 0 ? -1 : first - metadata.composing_start,
                last < 0 ? -1 : last - metadata.composing_start};
        }
        bool membership_changed(const ImeConversionTarget &target) const {
            if (!native_membership_used || !target.available || target.start < 0 || !binding_current() ||
                session.view(owner.object).text_event_revision != text_revision) return false;
            const auto &metadata = session.selection_state(buffer.object);
            if (metadata.composing_start < 0 || metadata.composing_end <= metadata.composing_start ||
                std::u16string_view(metadata.text).substr(static_cast<std::size_t>(metadata.composing_start),
                    static_cast<std::size_t>(metadata.composing_end - metadata.composing_start)) != native_baseline)
                return false;
            auto begin = std::min(target.start, native_membership_prefix);
            auto end = std::min(target.end, native_membership_prefix);
            if (begin == end) begin = end = -1;
            return begin != native_member_first || end != native_member_last;
        }
        void settle() noexcept {
            pending_unknown = false;
            gap_recorded = false;
            native_prefix_candidate = native_prefix_used = false;
            native_membership_candidate = native_membership_used = false;
            try {
                if (current()) initial_event_revision = session.view(owner.object).text_edit_event_revision;
            } catch (...) { }
        }
        ~ConversionObservation() {
            flush_unknown();
            session.conversion_observation = previous;
        }
    };
    void observe_conversion_mutation(ObjectId owner, ObjectId buffer, std::int32_t start,
                                      std::int32_t removed, std::int32_t inserted, std::int32_t before_length,
                                      bool composition_ended, bool same_composition, bool matched_base,
                                      std::int32_t old_region_first, std::int32_t old_region_last,
                                      std::int32_t new_region_first, std::int32_t new_region_last,
                                      std::u16string_view replacement) {
        for (auto *observation = conversion_observation; observation; observation = observation->previous)
            if (observation->matches(owner, buffer))
                observation->mutation(start, removed, inserted, before_length, composition_ended, same_composition,
                    matched_base, old_region_first, old_region_last, new_region_first, new_region_last, replacement);
    }
    void interrupt_conversion_observations(ObjectId owner, ObjectId buffer) noexcept {
        for (auto *observation = conversion_observation; observation; observation = observation->previous)
            if (observation->matches(owner, buffer)) observation->interrupt();
    }
    struct PendingCompositionRemoval {
        Impl &session;
        ManagedRoot owner, buffer;
        PendingCompositionRemoval *previous;
        std::int32_t start, end;
        std::uint64_t buffer_revision;
        bool pending;
        PendingCompositionRemoval(Impl &session, ObjectId buffer)
            : session(session), owner(session.runtime, session.selection_state(buffer).references[0].bits),
              buffer(session.runtime, buffer), previous(session.pending_composition),
              start(session.selection_state(buffer).composing_start),
              end(session.selection_state(buffer).composing_end),
              buffer_revision(owner.object && session.views.contains(owner.object)
                  ? session.view(owner.object).text_buffer_revision : 0), pending(false) {
            // Existing EditCall nesting bounds this rooted observation stack.
            session.pending_composition = this;
        }
        void flush() noexcept {
            if (!pending) return;
            pending = false;
            try {
                const auto &metadata = session.selection_state(buffer.object);
                if (start >= 0 && end > start && static_cast<std::size_t>(end) <= metadata.text.size()) {
                    const auto first = metadata.composing_start, last = metadata.composing_end;
                    // Own source preparation can recompose this retained
                    // buffer even when a second virtual getEditable returns a
                    // different buffer. Only units still outside COMPOSING
                    // have actually finalized.
                    if (first >= 0) session.unknown_conversion(owner.object, buffer.object);
                    session.finalized_fragments(owner.object, buffer.object, start, end, first, last);
                    if (first < 0) session.end_conversion(owner.object, buffer.object);
                }
            } catch (...) {
                // Observation must not replace a real callback exception.
                const auto found = session.views.find(owner.object);
                if (found != session.views.end() && found->second.text_buffer_revision == buffer_revision) {
                    auto &node = found->second;
                    if (session.text_edit_sequence != std::numeric_limits<std::uint64_t>::max())
                        node.text_edit_event_revision = ++session.text_edit_sequence;
                    node.text_edit_dropped_revision = node.text_edit_event_revision;
                    node.conversion_available = false;
                    node.conversion_start = node.conversion_end = -1;
                }
            }
        }
        ~PendingCompositionRemoval() {
            flush();
            session.pending_composition = previous;
        }
    };
    void flush_pending_composition(PendingCompositionRemoval *except = nullptr) noexcept {
        const auto flush = [&](auto &&self, PendingCompositionRemoval *entry) -> void {
            if (!entry) return;
            self(self, entry->previous);
            if (entry != except) entry->flush();
        };
        flush(flush, pending_composition);
    }
    const EditableState &editable_state(ObjectId object) const {
        if (!object) runtime.raise("Ljava/lang/NullPointerException;");
        if (!runtime.assignable(object, editable_type))
            runtime.raise("Ljava/lang/UnsupportedOperationException;", u"Only the hosted plain Editable is supported");
        const auto *metadata = dynamic_cast<const EditableState *>(runtime.host_state(object));
        if (!metadata) bad("EDITABLE", "Editable has no authenticated plain buffer state");
        return *metadata;
    }
    const EditableState &selection_state(ObjectId object) const {
        ManagedRoot root(runtime, object);
        if (!object) runtime.raise("Ljava/lang/NullPointerException;");
        // Numeric markers model only the exact plain provider. A subclass may
        // override virtual span operations even when it has hosted text storage.
        if (runtime.object_type(object) != buffer_type)
            runtime.raise("Ljava/lang/UnsupportedOperationException;",
                          u"Selection and span-mutating edits on custom Spanned or buffer subclasses are unsupported");
        return editable_state(object); // Nominal resolution precedes fresh state acquisition.
    }
    std::int32_t selection_marker(ObjectId object, bool end) const {
        if (!object) return -1;
        ManagedRoot root(runtime, object);
        if (!runtime.assignable(object, "Landroid/text/Spanned;")) return -1;
        const auto &metadata = selection_state(object);
        return end ? metadata.end : metadata.start;
    }
    ObjectId mode_object(std::int32_t mode) {
        if (mode < 0 || mode > 2) bad("BUFFER_MODE", "Invalid text buffer mode");
        auto &cached = buffer_modes[static_cast<std::size_t>(mode)];
        if (!cached) {
            constexpr std::array<std::u16string_view, 3> names{u"NORMAL", u"SPANNABLE", u"EDITABLE"};
            cached = own(runtime.new_host_enum(buffer_mode_type, names[static_cast<std::size_t>(mode)], mode));
        }
        return cached;
    }
    std::int32_t mode_value(ObjectId object) {
        if (!object) runtime.raise("Ljava/lang/NullPointerException;");
        ManagedRoot root(runtime, object);
        for (std::int32_t mode = 0; mode < 3; ++mode)
            if (object == mode_object(mode)) return mode;
        runtime.raise("Ljava/lang/IllegalArgumentException;", u"BufferType is not a canonical platform value");
    }
    ObjectId new_editable(std::u16string text, ObjectId owner = 0, bool cursor = false) {
        if (text.size() > editable_text_limit) bad("TEXT_LIMIT", "Plain Editable quota is 4096 UTF-16 units");
        auto next = std::make_unique<EditableState>();
        next->text = std::move(text);
        next->references[0] = Value::reference(owner);
        if (cursor) next->start = next->end = 0;
        const auto object = runtime.new_object(buffer_type);
        ManagedRoot root(runtime, object);
        runtime.set_host_state(object, std::move(next));
        return object;
    }
    void composition_committed(ObjectId owner, ObjectId buffer) {
        if (!owner || view(owner).kind != ViewKind::edit_text ||
            view_state(owner).references[2].bits != buffer) return;
        auto &revision = view(owner).composition_event_revision;
        if (revision == std::numeric_limits<std::uint64_t>::max())
            bad("COMPOSITION_EVENT_REVISION", "Editable composition notification revision exhausted");
        ++revision;
        ++metrics.view_revision;
    }
    void check_view_activations() const {
        switch (view_activation_failure) {
        case ActivationFailure::none: return;
        case ActivationFailure::invalid:
            bad("VIEW_ACTIVATION_INVALID", "View activation has no authenticated receiver or window generation");
        case ActivationFailure::quota:
            bad("VIEW_ACTIVATION_QUOTA", "Unacknowledged View activations exceed the bounded queue");
        case ActivationFailure::exhausted:
            bad("VIEW_ACTIVATION_REVISION", "View activation revision exhausted");
        }
    }
    void check_text_edit_observer_idle() const {
        check_view_activations();
        if (soft_input_observer_failure) std::rethrow_exception(soft_input_observer_failure);
        if (notifying_soft_input) bad("SOFT_INPUT_OBSERVER_REENTRY", "Trusted soft input sink must not reenter the session");
        if (text_edit_observer_failure) std::rethrow_exception(text_edit_observer_failure);
        if (notifying_text_edit) bad("TEXT_EDIT_OBSERVER_REENTRY", "Trusted text edit sink must not reenter the session");
    }
    void emit_text_edit(ObjectId owner, ObjectId buffer, const TextEditEvent &event) {
        if (!text_edit_observer) return;
        check_text_edit_observer_idle();
        notifying_text_edit = true;
        struct Reset { bool &active; ~Reset() { active = false; } } reset{notifying_text_edit};
        try {
            const auto &node = view(owner);
            const auto &metadata = selection_state(buffer);
            TextEditObservation observation;
            auto &document = observation.document;
            document.object = owner;
            document.kind = ViewKind::edit_text;
            document.text = metadata.text;
            document.selection_start = metadata.start; document.selection_end = metadata.end;
            document.composing_start = metadata.composing_start; document.composing_end = metadata.composing_end;
            document.text_buffer_revision = node.text_buffer_revision;
            document.text_event_revision = node.text_event_revision;
            document.selection_event_revision = node.selection_event_revision;
            document.composition_event_revision = node.composition_event_revision;
            document.text_edit_event_revision = node.text_edit_event_revision;
            document.text_edit_dropped_revision = node.text_edit_dropped_revision;
            document.text_mutation_base_revision = node.text_mutation_base_revision;
            for (const auto &mutation : view_state(owner).text_mutations)
                if (mutation.revision > document.text_mutation_base_revision) document.text_mutations.push_back(mutation);
            document.conversion_available = node.conversion_available;
            document.conversion_start = node.conversion_start; document.conversion_end = node.conversion_end;
            const bool no_target = document.conversion_start == -1 && document.conversion_end == -1;
            const bool target_valid = document.composing_start >= 0 &&
                document.conversion_start >= document.composing_start &&
                document.conversion_end > document.conversion_start &&
                document.conversion_end <= document.composing_end &&
                static_cast<std::size_t>(document.conversion_end) <= document.text.size();
            if (document.composing_start == -1 && document.composing_end == -1) {
                // Published absence does not consume live target-ending
                // evidence: the actual end event follows finalization below.
                document.conversion_available = true;
                document.conversion_start = document.conversion_end = -1;
            } else if (!document.conversion_available || (!no_target && !target_valid)) {
                document.conversion_available = false;
                document.conversion_start = document.conversion_end = -1;
            }
            document.ime_token = ime && ime->owner.object == owner && ime->buffer.object == buffer &&
                ime_content_matches(*ime, true) ? ime->token : 0;
            if (document.composing_start >= 0 && (!document.ime_token || !ime->owned_preedit)) {
                document.conversion_available = false;
                document.conversion_start = document.conversion_end = -1;
            }
            observation.event = event;
            observation.view_revision = metrics.view_revision;
            observation.rooted = in_tree(owner);
            text_edit_observer(observation);
        } catch (...) {
            // Some composition cleanup is noexcept. Keep the original sink or
            // capture error fatal at the next snapshot/entry boundary there.
            if (!text_edit_observer_failure) text_edit_observer_failure = std::current_exception();
            throw;
        }
    }
    void record_text_edit(ObjectId owner, ObjectId buffer, TextEditEventKind kind,
                          std::u16string_view text, bool payload_known = true) {
        if (text_edit_observer) check_text_edit_observer_idle();
        if (!owner || !views.contains(owner) || view(owner).kind != ViewKind::edit_text ||
            view_state(owner).references[2].bits != buffer) return;
        auto &node = view(owner);
        // History is observational. Its bounded capacity or sequence exhaustion
        // must not refuse, replay or undo an otherwise valid guest mutation.
        if (text_edit_sequence == std::numeric_limits<std::uint64_t>::max()) {
            if (text_edit_observer) {
                try { bad("TEXT_EDIT_OBSERVER_SEQUENCE", "Text edit sink sequence exhausted"); }
                catch (...) {
                    if (!text_edit_observer_failure) text_edit_observer_failure = std::current_exception();
                    throw;
                }
            }
            node.text_edit_dropped_revision = node.text_edit_event_revision;
            return;
        }
        const auto revision = ++text_edit_sequence;
        node.text_edit_event_revision = revision;
        const auto drop = [&] { node.text_edit_dropped_revision = revision; };
        if (!payload_known || text.size() > text_edit_history_units || !node.text_buffer_revision ||
            node.text_buffer_revision == std::numeric_limits<std::uint64_t>::max()) { drop(); return; }
        // The trusted sink receives the actual operation before bounded
        // retention can evict it. Sink/capture failures are not history gaps.
        if (text_edit_observer) {
            try {
                const TextEditEvent observed_event{revision, kind, std::u16string(text), node.text_buffer_revision};
                emit_text_edit(owner, buffer, observed_event);
            }
            catch (...) {
                if (!text_edit_observer_failure) text_edit_observer_failure = std::current_exception();
                throw;
            }
        }
        try {
            auto next = std::make_unique<ViewObjectState>(view_state(owner));
            auto &history = next->text_edit_events;
            // An unavailable payload or allocation gap does not invalidate
            // already captured operations. Retain those known records on both
            // sides of the gap under the same charged count/unit bounds.
            std::size_t units = 0;
            for (const auto &event : history) units += event.text.size();
            while (!history.empty() && (history.size() >= text_edit_history_limit ||
                                       units > text_edit_history_units - text.size())) {
                units -= history.front().text.size();
                node.text_edit_dropped_revision = std::max(node.text_edit_dropped_revision,
                    history.front().revision);
                history.erase(history.begin());
            }
            history.push_back({revision, kind, std::u16string(text), node.text_buffer_revision});
            runtime.set_host_state(owner, std::move(next));
        } catch (const std::bad_alloc &) {
            drop();
        } catch (const dex::DexError &error) {
            if (error.code != "AETHER_DEX_HEAP_LIMIT") throw;
            drop(); // Keep the actual edit; report an explicit missing-history interval.
        }
    }
    bool current_editable(ObjectId owner, ObjectId buffer) {
        return owner && views.contains(owner) && view(owner).kind == ViewKind::edit_text &&
            view_state(owner).references[2].bits == buffer;
    }
    void unknown_conversion(ObjectId owner, ObjectId buffer, bool identity_uncertain = true,
                            bool observed_text_commit = false) {
        if (!current_editable(owner, buffer)) return;
        bool deferred = false;
        for (auto *observation = conversion_observation; observation; observation = observation->previous) {
            if (!observation->matches(owner, buffer)) continue;
            if (observed_text_commit && (observation->proven || observation->legacy_unchanged ||
                observation->native_membership_used) &&
                observation->binding_current()) {
                observation->pending_unknown = true;
                deferred = true;
            } else observation->interrupt();
        }
        if (identity_uncertain && ime && ime->owner.object == owner && ime->buffer.object == buffer)
            ime->conversion_interrupted = true;
        auto &node = view(owner);
        if (deferred) {
            node.conversion_available = false;
            node.conversion_start = node.conversion_end = -1;
            return; // Final genuine native metadata settles the retained identity.
        }
        if (node.conversion_available) {
            node.conversion_available = false;
            node.conversion_start = node.conversion_end = -1;
            record_text_edit(owner, buffer, TextEditEventKind::conversion_target_changed, {}, false);
        }
    }
    void end_conversion(ObjectId owner, ObjectId buffer) {
        if (!current_editable(owner, buffer)) return;
        if (ime && ime->owner.object == owner && ime->buffer.object == buffer) ime->conversion_interrupted = true;
        auto &node = view(owner);
        bool changed = node.conversion_available && node.conversion_start >= 0;
        const auto &metadata = selection_state(buffer);
        const bool composition_absent = metadata.composing_start == -1 && metadata.composing_end == -1;
        for (auto *observation = conversion_observation; observation; observation = observation->previous) {
            if (!observation->matches(owner, buffer)) continue;
            // Presence can prove an ending even when replacement erased the
            // old range's identity. It never proves a positive target mapping.
            changed = changed || (observation->target_present && observation->current() &&
                (observation->binding_current() || composition_absent));
            observation->target_present = false;
            // A real observed end is a fresh known-absence baseline. It does
            // not revive the old positive target after an ambiguous edit.
            observation->proven = observation->binding_current();
            observation->legacy_unchanged = observation->proven;
            observation->first = observation->last = -1;
            observation->text_revision = node.text_event_revision;
            observation->settle();
        }
        node.conversion_available = true;
        node.conversion_start = node.conversion_end = -1;
        if (changed) record_text_edit(owner, buffer, TextEditEventKind::conversion_target_changed, {});
    }
    bool conversion_ends_in_region(ObjectId owner, ObjectId buffer, std::int32_t start, std::int32_t end) {
        if (start < 0) return true;
        if (!current_editable(owner, buffer)) return false;
        const auto &node = view(owner);
        if (node.conversion_available && node.conversion_start >= 0 &&
            (node.conversion_end <= start || node.conversion_start >= end)) return true;
        for (auto *observation = conversion_observation; observation; observation = observation->previous)
            if (observation->matches(owner, buffer) && (observation->proven || observation->legacy_unchanged) &&
                observation->binding_current() &&
                observation->first >= 0 && (observation->last <= start || observation->first >= end)) return true;
        return false;
    }
    void apply_conversion(ObjectId owner, ObjectId buffer, std::u16string_view native_text,
                           const ImeConversionTarget &target, const std::optional<ImeConversionTarget> &previous,
                           bool native_membership_changed = false) {
        if (!current_editable(owner, buffer)) return;
        const auto &metadata = selection_state(buffer);
        const auto first = metadata.composing_start, last = metadata.composing_end;
        if (first == -1 && last == -1) {
            // Actual absence is authoritative even when an announced native
            // preedit was declined or finalized by the real callback.
            end_conversion(owner, buffer);
            return;
        }
        if (!target.available || first < 0 || last <= first ||
            std::u16string_view(metadata.text).substr(static_cast<std::size_t>(first),
                static_cast<std::size_t>(last - first)) != native_text) {
            unknown_conversion(owner, buffer);
            return;
        }
        if (target.start == -1 && target.end == -1) {
            // Actual native absence is decisive even after an ambiguous wide
            // replacement; consume prior presence only after composition events.
            end_conversion(owner, buffer);
            return;
        }
        if (!previous && !native_membership_changed)
            for (auto *observation = conversion_observation; observation; observation = observation->previous)
                if (observation->matches(owner, buffer)) observation->flush_unknown();
        auto &node = view(owner);
        node.conversion_available = true;
        node.conversion_start = target.start < 0 ? -1 : first + target.start;
        node.conversion_end = target.end < 0 ? -1 : first + target.end;
        for (auto *observation = conversion_observation; observation; observation = observation->previous)
            if (observation->matches(owner, buffer)) observation->settle();
        if (native_membership_changed || (previous && previous->available &&
            (previous->start != target.start || previous->end != target.end)))
            record_text_edit(owner, buffer, TextEditEventKind::conversion_target_changed, {});
    }
    void finalized_fragments(ObjectId owner, ObjectId buffer, std::int32_t old_start, std::int32_t old_end,
                             std::int32_t start, std::int32_t end) {
        if (old_start < 0 || old_end <= old_start) return;
        const auto text = std::u16string_view(editable_state(buffer).text);
        const auto emit = [&](std::int32_t first, std::int32_t last) {
            if (first < last) record_text_edit(owner, buffer, TextEditEventKind::composition_finalized,
                text.substr(static_cast<std::size_t>(first), static_cast<std::size_t>(last - first)));
        };
        // Text is unchanged: OLD \\ NEW identifies the retained finalized
        // fragments exactly. Project two disjoint fragments in document order.
        if (start < 0 || end <= old_start || start >= old_end) emit(old_start, old_end);
        else {
            emit(old_start, std::min(old_end, start));
            emit(std::max(old_start, end), old_end);
        }
    }
    void set_composition(ObjectId buffer, std::int32_t start, std::int32_t end, bool notify_finalization = true,
                         PendingCompositionRemoval *continuation = nullptr, bool defer_conversion = false) {
        EditCall call(*this);
        ManagedRoot root(runtime, buffer);
        const auto &old = selection_state(buffer);
        if (start == -1 && end == -1) {
            // Inactive is the only negative marker representation.
        } else {
            if (start < 0 || end < start || static_cast<std::size_t>(end) > old.text.size())
                runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
            // COMPOSING uses EXCLUSIVE_EXCLUSIVE: an empty marker is removed.
            if (start == end) start = end = -1;
        }
        if (old.composing_start == start && old.composing_end == end) return;
        const auto owner = old.references[0].bits;
        ManagedRoot owner_root(runtime, owner);
        if (current_editable(owner, buffer)) flush_pending_composition(continuation);
        const auto old_first = old.composing_start, old_last = old.composing_end;
        const bool target_ended = notify_finalization && conversion_ends_in_region(owner, buffer, start, end);
        auto next = std::make_unique<EditableState>(old);
        next->composing_start = start; next->composing_end = end;
        runtime.set_host_state(buffer, std::move(next));
        if (continuation && start < 0 && old_first >= 0) continuation->pending = true;
        const bool matched_preparation = continuation && continuation->buffer.object == buffer;
        if (!matched_preparation && !defer_conversion && !target_ended)
            interrupt_conversion_observations(owner, buffer);
        composition_committed(owner, buffer);
        if (notify_finalization) {
            if (!target_ended) unknown_conversion(owner, buffer);
            finalized_fragments(owner, buffer, old_first, old_last, start, end);
            if (target_ended) end_conversion(owner, buffer);
        }
    }
    static std::pair<std::int32_t, std::int32_t> edited_composition(const EditableState &old,
            std::int32_t start, std::int32_t end, std::int32_t inserted) {
        auto first = old.composing_start, last = old.composing_end;
        if (first < 0 || last <= first) return {-1, -1};
        const auto removed = end - start, delta = inserted - removed;
        if (!removed) {
            // Exclusive start is POINT; exclusive end is MARK.
            if (first >= start) first += inserted;
            if (last > start) last += inserted;
        } else {
            if (first >= start && first < end && last >= start && last <= end &&
                (!inserted || first > start || last < end)) return {-1, -1};
            const auto point = [&](std::int32_t position) {
                if (position < start) return position;
                if (position > end) return position + delta;
                if (position == start && inserted) return start;
                return start + inserted;
            };
            const auto mark = [&](std::int32_t position) {
                if (position < start) return position;
                if (position > end) return position + delta;
                return position == end && inserted ? start + inserted : start;
            };
            first = point(first); last = mark(last);
        }
        return first < last ? std::pair{first, last} : std::pair<std::int32_t, std::int32_t>{-1, -1};
    }
    void text_committed(ObjectId owner, ObjectId buffer) {
        if (!owner || view(owner).kind != ViewKind::edit_text ||
            view_state(owner).references[2].bits != buffer) return;
        auto &revision = view(owner).text_event_revision;
        if (revision == std::numeric_limits<std::uint64_t>::max())
            bad("TEXT_EVENT_REVISION", "Editable text notification revision exhausted");
        // Stamp committed current-buffer mutations before any subsequent
        // selection/text callback can reenter or throw, including equal text.
        ++revision;
    }
    void record_text_mutation(ObjectId owner, ObjectId buffer, std::int32_t start,
                              std::int32_t removed, std::int32_t inserted, std::int32_t before_length) {
        if (!current_editable(owner, buffer)) return;
        auto &node = view(owner);
        const auto revision = node.text_event_revision;
        const auto gap = [&] { node.text_mutation_base_revision = revision; };
        try {
            auto next = std::make_unique<ViewObjectState>(view_state(owner));
            auto &history = next->text_mutations;
            // A failed prior observation may leave charged older records in
            // place. They carry no coverage after the gap watermark.
            std::erase_if(history, [&](const auto &mutation) {
                return mutation.revision <= node.text_mutation_base_revision;
            });
            const auto previous = history.empty() ? node.text_mutation_base_revision : history.back().revision;
            if (!revision || previous != revision - 1) {
                history.clear();
                node.text_mutation_base_revision = revision ? revision - 1 : 0;
            }
            if (history.size() >= text_mutation_history_limit) {
                node.text_mutation_base_revision = history.front().revision;
                history.erase(history.begin());
            }
            history.push_back({revision, start, removed, inserted, before_length});
            runtime.set_host_state(owner, std::move(next));
        } catch (const std::bad_alloc &) {
            gap();
        } catch (const dex::DexError &error) {
            if (error.code != "AETHER_DEX_HEAP_LIMIT") throw;
            gap(); // Position observation must never reject the actual edit.
        }
    }
    void text_phase(ObjectId owner, ObjectId buffer, unsigned phase,
                    std::int32_t start, std::int32_t before, std::int32_t after) {
        if (!owner) return;
        const auto count = view_state(owner).watcher_count;
        ManagedRoot buffer_root(runtime, buffer);
        for (std::size_t i = 0; i < count; ++i) {
            // AOSP captures count per phase, then uses the live ArrayList index.
            if (i >= view_state(owner).watcher_count)
                runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
            const auto listener = runtime.array_get(view_state(owner).references[3].bits, static_cast<std::int32_t>(i)).bits;
            if (!listener) runtime.raise("Ljava/lang/NullPointerException;");
            ManagedRoot listener_root(runtime, listener);
            if (phase == 2) {
                const std::array args{Value::reference(buffer)};
                (void)runtime.invoke_virtual_named(listener, "afterTextChanged", "(Landroid/text/Editable;)V", args);
            } else {
                const std::array args{Value::reference(buffer), Value::word(static_cast<std::uint32_t>(start)),
                                      Value::word(static_cast<std::uint32_t>(before)), Value::word(static_cast<std::uint32_t>(after))};
                (void)runtime.invoke_virtual_named(listener, phase ? "onTextChanged" : "beforeTextChanged",
                    "(Ljava/lang/CharSequence;III)V", args);
            }
        }
        if (phase == 1)
            if (const auto method = override_method(runtime.object_type(owner), "onTextChanged", "(Ljava/lang/CharSequence;III)V")) {
                const std::array args{Value::reference(owner), Value::reference(buffer),
                                      Value::word(static_cast<std::uint32_t>(start)), Value::word(static_cast<std::uint32_t>(before)),
                                      Value::word(static_cast<std::uint32_t>(after))};
                (void)runtime.invoke_virtual(*method, args);
            }
    }
    void selection_changed(ObjectId buffer) {
        const auto owner = editable_state(buffer).references[0].bits;
        const auto start = editable_state(buffer).start, end = editable_state(buffer).end;
        if (!owner) return;
        if (view(owner).kind == ViewKind::edit_text && view_state(owner).references[2].bits == buffer) {
            auto &revision = view(owner).selection_event_revision;
            if (revision == std::numeric_limits<std::uint64_t>::max())
                bad("SELECTION_EVENT_REVISION", "Editable selection notification revision exhausted");
            ++revision; // Count real helper notifications, not snapshot changes.
        }
        ++metrics.view_revision;
        if (const auto method = override_method(runtime.object_type(owner), "onSelectionChanged", "(II)V")) {
            const std::array args{Value::reference(owner), Value::word(std::bit_cast<std::uint32_t>(start)),
                                  Value::word(std::bit_cast<std::uint32_t>(end))};
            (void)runtime.invoke_virtual(*method, args);
        }
    }
    void set_selection(ObjectId buffer, std::int32_t start, std::int32_t end, bool extend = false) {
        EditCall call(*this);
        ManagedRoot root(runtime, buffer);
        const auto old_start = selection_state(buffer).start, old_end = selection_state(buffer).end;
        if ((extend || old_start == start) && old_end == end) return;
        if (!extend) {
            if (start < 0 || static_cast<std::size_t>(start) > editable_state(buffer).text.size())
                runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
            auto anchor = std::make_unique<EditableState>(editable_state(buffer));
            anchor->start = start;
            runtime.set_host_state(buffer, std::move(anchor));
        }
        // Selection commits its intermediate anchor before checking the edge.
        if (end < 0 || static_cast<std::size_t>(end) > editable_state(buffer).text.size())
            runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
        auto edge = std::make_unique<EditableState>(editable_state(buffer));
        edge->end = end;
        runtime.set_host_state(buffer, std::move(edge));
        selection_changed(buffer);
    }
    void change_watchers(ObjectId owner, ObjectId listener, bool add) {
        if (listener && !runtime.assignable(listener, watcher_type))
            runtime.raise("Ljava/lang/IllegalArgumentException;", u"Listener must implement TextWatcher");
        ManagedRoot listener_root(runtime, listener);
        const auto count = view_state(owner).watcher_count;
        const auto original_array = view_state(owner).references[3].bits;
        ManagedRoot original_array_root(runtime, original_array);
        if (add) {
            if (count >= 32) bad("TEXT_WATCHERS", "TextWatcher quota is 32");
            const auto capacity = original_array ? runtime.array_length(original_array) : 0;
            const auto append = [&](ObjectId array) {
                auto next = std::make_unique<ViewObjectState>(view_state(owner));
                next->references[3] = Value::reference(array);
                next->watcher_count = count + 1;
                // Admit the allocating/rooting state publication before the
                // allocation-free validated Object[] store. No callback or
                // safepoint can observe the short publication/store interval.
                runtime.set_host_state(owner, std::move(next));
                runtime.array_set(array, static_cast<std::int32_t>(count), Value::reference(listener));
            };
            if (count == capacity) {
                // Preserve ArrayList's allocation boundaries, including capacity 33 at count 22.
                const auto grown_capacity = capacity ? capacity + capacity / 2 : 10;
                const auto array = runtime.new_array("[Ljava/lang/Object;", static_cast<std::int32_t>(grown_capacity));
                ManagedRoot array_root(runtime, array);
                for (std::size_t i = 0; i < count; ++i)
                    runtime.array_set(array, static_cast<std::int32_t>(i),
                                      runtime.array_get(original_array, static_cast<std::int32_t>(i)));
                append(array);
            } else {
                append(original_array);
            }
            return;
        }
        // TextView scans indexOf against its captured backing array/count, then removes by index.
        for (std::size_t i = 0; i < count; ++i) {
            const auto current = runtime.array_get(original_array, static_cast<std::int32_t>(i)).bits;
            ManagedRoot current_root(runtime, current);
            const std::array args{Value::reference(current)};
            const bool equal = !listener ? !current : runtime.invoke_virtual_named(listener, "equals", "(Ljava/lang/Object;)Z", args).bits != 0;
            if (!equal) continue;
            const auto current_count = view_state(owner).watcher_count;
            if (i >= current_count) runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
            const auto current_array = view_state(owner).references[3].bits;
            ManagedRoot current_array_root(runtime, current_array);
            auto next = std::make_unique<ViewObjectState>(view_state(owner));
            next->watcher_count = current_count - 1;
            runtime.set_host_state(owner, std::move(next));
            // All indices and live references are already validated. Object[]
            // shifts and the final clear do not allocate or invoke metadata.
            for (auto at = i; at + 1 < current_count; ++at)
                runtime.array_set(current_array, static_cast<std::int32_t>(at),
                                  runtime.array_get(current_array, static_cast<std::int32_t>(at + 1)));
            runtime.array_set(current_array, static_cast<std::int32_t>(current_count - 1), Value::reference(0));
            return;
        }
    }
    void replace_buffer(ObjectId buffer, std::int32_t start, std::int32_t end,
                        ObjectId source, std::int32_t source_start, std::int32_t source_end,
                        PendingCompositionRemoval *continuation = nullptr, bool composing_operation = false) {
        EditCall call(*this);
        ManagedRoot buffer_root(runtime, buffer), source_root(runtime, source);
        (void)selection_state(buffer);
        const auto check = [&] {
            const auto length = editable_state(buffer).text.size();
            if (start < 0 || end < start || static_cast<std::size_t>(end) > length)
                runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
            if (source_start < 0 || source_end < source_start ||
                (source ? static_cast<std::size_t>(source_end) > runtime.char_sequence(source).size() : source_end != 0))
                runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
            if (length - static_cast<std::size_t>(end - start) + static_cast<std::size_t>(source_end - source_start) > editable_text_limit)
                bad("TEXT_LIMIT", "Plain Editable quota is 4096 UTF-16 units");
        };
        check();
        const auto before = end - start, after = source_end - source_start;
        if (!before && !after) return;
        if (!source) runtime.raise("Ljava/lang/NullPointerException;");
        const auto owner = editable_state(buffer).references[0].bits;
        ManagedRoot owner_root(runtime, owner);
        text_phase(owner, buffer, 0, start, before, after);
        check(); // A valid callback may have changed another input buffer.
        const bool completes_current = continuation && continuation->pending &&
            continuation->buffer.object == buffer && continuation->start == start && continuation->end == end;
        if (current_editable(owner, buffer)) flush_pending_composition(completes_current ? continuation : nullptr);
        const auto replacement = std::u16string(runtime.char_sequence(source).substr(
            static_cast<std::size_t>(source_start), static_cast<std::size_t>(after)));
        auto next = std::make_unique<EditableState>(editable_state(buffer));
        const auto before_length = static_cast<std::int32_t>(next->text.size());
        const auto old_start = next->start, old_end = next->end;
        const auto old_composing_start = next->composing_start, old_composing_end = next->composing_end;
        auto composition = edited_composition(*next, start, end, after);
        // A composing source contributes its one authenticated COMPOSING marker
        // during the text commit, before any watcher sees the destination.
        if (composition.first < 0 && source != buffer && runtime.object_type(source) == buffer_type) {
            const auto &input = selection_state(source);
            if (input.composing_start >= 0) {
                const auto first = std::max(input.composing_start, source_start);
                const auto last = std::min(input.composing_end, source_end);
                if (first < last) composition = {start + first - source_start, start + last - source_start};
            }
        }
        const auto adjust = [&](std::int32_t position) {
            if (position < 0 || position < start) return position;
            if (!before) return position + after;
            if (position == start) return position;
            if (position >= end) return position + after - before;
            return start + static_cast<std::int32_t>(static_cast<std::int64_t>(position - start) * after / before);
        };
        next->text.replace(static_cast<std::size_t>(start), static_cast<std::size_t>(before), replacement);
        next->start = adjust(next->start);
        next->end = adjust(next->end);
        next->composing_start = composition.first; next->composing_end = composition.second;
        const auto observed_first = completes_current ? continuation->start : old_composing_start;
        const auto observed_last = completes_current ? continuation->end : old_composing_end;
        const bool same_composition = observed_first >= 0 && composition.first >= 0 &&
            std::u16string_view(editable_state(buffer).text).substr(static_cast<std::size_t>(observed_first),
                static_cast<std::size_t>(observed_last - observed_first)) ==
            std::u16string_view(next->text).substr(static_cast<std::size_t>(composition.first),
                static_cast<std::size_t>(composition.second - composition.first));
        // Derive payload only from this authenticated replacement after the
        // beforeTextChanged callback and source revalidation. It describes the
        // mutation now committed; later watchers produce independent records.
        auto event_kind = composing_operation ? std::optional{TextEditEventKind::composition}
            : completes_current ? std::optional{TextEditEventKind::composition_finalized} : std::nullopt;
        std::u16string_view event_text;
        bool event_known = true;
        if (composition.first >= 0) {
            event_kind = TextEditEventKind::composition;
            const auto inserted_first = std::max(start, composition.first);
            const auto inserted_last = std::min(start + after, composition.second);
            if (inserted_first < inserted_last) {
                const auto composing_first = static_cast<std::size_t>(inserted_first - start);
                const auto composing_last = static_cast<std::size_t>(inserted_last - start);
                // Trim unchanged edges within the ACTUAL replacement, never a
                // coalesced whole-Value difference or the original IME request.
                const auto old_text = std::u16string_view(editable_state(buffer).text);
                auto replaced = old_text.substr(
                    static_cast<std::size_t>(start), static_cast<std::size_t>(before));
                auto inserted = std::u16string_view(replacement);
                std::size_t comparison_origin = 0;
                if (observed_first >= 0 && observed_last > observed_first &&
                    static_cast<std::size_t>(observed_last) <= old_text.size()) {
                    // Outside unmarked changes must not inflate a composition
                    // payload. Compare only the old/new composing portions of
                    // this exact authenticated replacement operation.
                    const auto old_first = std::max(start, observed_first);
                    const auto old_composed_end = std::max(old_first, std::min(end, observed_last));
                    replaced = old_text.substr(static_cast<std::size_t>(old_first),
                        static_cast<std::size_t>(old_composed_end - old_first));
                    inserted = inserted.substr(composing_first, composing_last - composing_first);
                    comparison_origin = composing_first;
                }
                std::size_t changed_first = 0, changed_last = inserted.size(), old_last = replaced.size();
                while (changed_first < changed_last && changed_first < replaced.size() &&
                       inserted[changed_first] == replaced[changed_first]) ++changed_first;
                while (changed_last > changed_first && old_last > changed_first &&
                       inserted[changed_last - 1] == replaced[old_last - 1]) { --changed_last; --old_last; }
                // Intersect the actual operation's changed text with its
                // inserted COMPOSING slice, including a partial source span.
                auto first_changed = std::clamp(comparison_origin + changed_first, composing_first, composing_last);
                auto last_changed = std::clamp(comparison_origin + changed_last, first_changed, composing_last);
                // A real replacement still emits Composition when this slice
                // is unchanged or only deleted characters: its payload is empty.
                if (first_changed < last_changed) {
                    const auto pair_boundary = [&](std::size_t at) {
                        return at && at < replacement.size() && replacement[at - 1] >= 0xd800 &&
                            replacement[at - 1] <= 0xdbff && replacement[at] >= 0xdc00 && replacement[at] <= 0xdfff;
                    };
                    if (first_changed > composing_first && pair_boundary(first_changed)) --first_changed;
                    if (last_changed < composing_last && pair_boundary(last_changed)) ++last_changed;
                }
                event_text = std::u16string_view(replacement).substr(first_changed, last_changed - first_changed);
                if (same_composition) event_text = {}; // Outer edits cannot change an equal actual composing string.
            } else if (!(old_composing_start >= 0 && start < old_composing_end && end > old_composing_start)) {
                event_kind.reset(); // An edit outside composition only remapped its position.
            }
        } else if (completes_current) {
            event_kind = TextEditEventKind::composition_finalized;
            event_text = replacement;
        } else if (old_composing_start >= 0) {
            event_kind = TextEditEventKind::composition_finalized;
            if (start <= old_composing_start && end >= old_composing_end) {
                event_text = {}; // Original composing units were deleted; unmarked insertions are separate.
                if (source == buffer) {
                    // Self-copy supplies explicit source-interval evidence for
                    // formerly composing units retained as unmarked text.
                    const auto copied_first = std::max(old_composing_start, source_start);
                    const auto copied_last = std::min(old_composing_end, source_end);
                    if (copied_first < copied_last) event_text = std::u16string_view(replacement).substr(
                        static_cast<std::size_t>(copied_first - source_start),
                        static_cast<std::size_t>(copied_last - copied_first));
                }
            } else event_known = false;
        } else event_kind.reset();
        runtime.set_host_state(buffer, std::move(next));
        if (completes_current) continuation->pending = false;
        text_committed(owner, buffer);
        observe_conversion_mutation(owner, buffer, start, before, after, before_length, composition.first < 0,
            same_composition && observed_first == composition.first && observed_last == composition.second,
            completes_current && composing_operation, observed_first, observed_last, composition.first, composition.second,
            replacement);
        record_text_mutation(owner, buffer, start, before, after, before_length);
        if (old_composing_start != composition.first || old_composing_end != composition.second)
            composition_committed(owner, buffer);
        if (composition.first >= 0) unknown_conversion(owner, buffer, !same_composition, true);
        if (event_kind) record_text_edit(owner, buffer, *event_kind, event_text, event_known);
        if (composition.first < 0) end_conversion(owner, buffer);
        if (owner && view_state(owner).references[2].bits == buffer)
            view(owner).text = runtime.char_sequence(buffer);
        if (owner) ++metrics.view_revision;
        text_phase(owner, buffer, 1, start, before, after);
        text_phase(owner, buffer, 2, start, before, after);
        if (old_start != editable_state(buffer).start || old_end != editable_state(buffer).end)
            selection_changed(buffer);
    }
    void set_text_base(ObjectId owner, ObjectId source, std::int32_t mode) {
        EditCall call(*this);
        ManagedRoot owner_root(runtime, owner), source_root(runtime, source);
        if (view(owner).kind == ViewKind::edit_text) mode = 2;
        if (mode == 1) runtime.raise("Ljava/lang/UnsupportedOperationException;", u"Styled SPANNABLE text is unsupported");
        auto previous = view_state(owner).references[2].bits;
        if (!previous) previous = runtime.new_string({});
        ManagedRoot old_root(runtime, previous);
        const auto old_length = previous ? runtime.char_sequence(previous).size() : 0;
        const auto input_length = source ? runtime.char_sequence(source).size() : 0;
        if (input_length > 65536) bad("TEXT_LIMIT", "View text quota exceeded");
        text_phase(owner, previous, 0, 0, static_cast<std::int32_t>(old_length), static_cast<std::int32_t>(input_length));
        const bool notify_after = view_state(owner).watcher_count != 0;
        const bool editing = mode == 2 || notify_after;
        auto text = source ? std::u16string(runtime.char_sequence(source)) : std::u16string{};
        if (text.size() > (editing ? editable_text_limit : 65536)) bad("TEXT_LIMIT", "Text buffer quota exceeded");
        const auto length = static_cast<std::int32_t>(text.size());
        const auto current = editing ? new_editable(std::move(text), owner, view(owner).kind == ViewKind::edit_text)
                                     : runtime.new_string(text);
        ManagedRoot current_root(runtime, current);
        const auto replaced = view_state(owner).references[2].bits;
        const bool previous_composition = replaced && runtime.object_type(replaced) == buffer_type &&
            editable_state(replaced).composing_start >= 0;
        flush_pending_composition();
        interrupt_conversion_observations(owner, replaced);
        // Capture the final old-buffer observations before switching the
        // current buffer. The logical View history retains those exact tagged
        // payloads; replacement alone never invents a finalized string.
        auto next = std::make_unique<ViewObjectState>(view_state(owner));
        next->references[2] = Value::reference(current);
        next->mode = mode;
        next->text_mutations.clear();
        runtime.set_host_state(owner, std::move(next));
        if (view(owner).kind == ViewKind::edit_text) {
            auto &node = view(owner);
            if (node.text_buffer_revision != std::numeric_limits<std::uint64_t>::max()) ++node.text_buffer_revision;
            node.conversion_available = true;
            node.conversion_start = node.conversion_end = -1;
        }
        text_committed(owner, current);
        if (view(owner).kind == ViewKind::edit_text)
            view(owner).text_mutation_base_revision = view(owner).text_event_revision;
        if (previous_composition) composition_committed(owner, current);
        view(owner).text = runtime.char_sequence(current);
        ++metrics.view_revision;
        if (editing && view(owner).kind == ViewKind::edit_text) selection_changed(current);
        text_phase(owner, current, 1, 0, static_cast<std::int32_t>(old_length), length);
        if (notify_after) text_phase(owner, current, 2, 0, static_cast<std::int32_t>(old_length), length);
    }
    void dispatch_set_text(ObjectId owner, ObjectId source) {
        ManagedRoot source_root(runtime, source);
        const auto mode = view_state(owner).mode;
        if (const auto method = override_method(runtime.object_type(owner), "setText", "(Ljava/lang/CharSequence;Landroid/widget/TextView$BufferType;)V")) {
            const auto mode_id = mode_object(mode);
            const std::array args{Value::reference(owner), Value::reference(source), Value::reference(mode_id)};
            (void)runtime.invoke_virtual(*method, args);
        } else set_text_base(owner, source, mode);
    }
    ObjectId selection_text(ObjectId owner) {
        if (const auto method = override_method(runtime.object_type(owner), "getText", "()Landroid/text/Editable;")) {
            const std::array args{Value::reference(owner)};
            return runtime.invoke_virtual(*method, args).bits;
        }
        return view_state(owner).references[2].bits;
    }
    bool ime_target(const ImeBinding &binding, bool require_focus) {
        const auto owner = binding.owner.object, buffer = binding.buffer.object;
        if (!views.contains(owner) || view(owner).kind != ViewKind::edit_text ||
            view_state(owner).references[2].bits != buffer || runtime.object_type(buffer) != buffer_type) return false;
        if (require_focus && (state != Lifecycle::resumed || !window_focused || !focused || focused_view != owner ||
            pointer_target || key_target || !enabled(owner))) return false;
        return true;
    }
    bool ime_content_matches(const ImeBinding &binding, bool require_focus) {
        if (!ime_target(binding, require_focus)) return false;
        const auto &node = view(binding.owner.object);
        return editable_state(binding.buffer.object).text == binding.expected_text &&
            node.text_event_revision == binding.text_revision && node.selection_event_revision == binding.selection_revision &&
            node.composition_event_revision == binding.composition_revision;
    }
    void capture_ime(ImeBinding &binding) {
        const auto &node = view(binding.owner.object);
        binding.expected_text = editable_state(binding.buffer.object).text;
        binding.text_revision = node.text_event_revision;
        binding.selection_revision = node.selection_event_revision;
        binding.composition_revision = node.composition_event_revision;
    }
    void retire_ime(bool close_owned) {
        // Clear the token before virtual cleanup. Focus callbacks may reenter,
        // but cannot resurrect this native editor binding.
        auto retired = std::move(ime);
        if (!retired || runtime.process_state()->exit_status()) return;
        const auto retire_conversion = [&] {
            const auto owner = retired->owner.object, buffer = retired->buffer.object;
            if (!current_editable(owner, buffer)) return;
            if (selection_state(buffer).composing_start < 0) end_conversion(owner, buffer);
            else unknown_conversion(owner, buffer);
        };
        try {
            if (close_owned) (void)runtime.invoke_virtual_named(retired->connection.object, "closeConnection", "()V");
        } catch (...) {
            try { retire_conversion(); } catch (...) {}
            throw;
        }
        // Real finish/close mutations journal their composition evidence first.
        retire_conversion();
    }
    const InputConnectionState &connection_state(ObjectId object) const {
        if (!object) runtime.raise("Ljava/lang/NullPointerException;");
        if (!runtime.assignable(object, input_connection_type))
            runtime.raise("Ljava/lang/IllegalArgumentException;", u"Receiver is not an InputConnection");
        const auto *metadata = dynamic_cast<const InputConnectionState *>(runtime.host_state(object));
        if (!metadata) bad("INPUT_CONNECTION_STATE", "InputConnection has no authenticated constructor state");
        return *metadata;
    }
    const EditorInfoState &editor_state(ObjectId object) const {
        if (!object) runtime.raise("Ljava/lang/NullPointerException;");
        if (!runtime.assignable(object, editor_info_type))
            runtime.raise("Ljava/lang/IllegalArgumentException;", u"EditorInfo receiver type mismatch");
        const auto *metadata = dynamic_cast<const EditorInfoState *>(runtime.host_state(object));
        if (!metadata) bad("EDITOR_INFO_STATE", "EditorInfo has no authenticated constructor state");
        return *metadata;
    }
    ObjectId new_editor_info() {
        const auto object = runtime.new_object(editor_info_type);
        ManagedRoot root(runtime, object);
        runtime.set_host_state(object, std::make_unique<EditorInfoState>());
        return object;
    }
    ObjectId new_editable_connection(ObjectId owner) {
        (void)view(owner);
        const auto object = runtime.new_object(editable_input_connection_type);
        ManagedRoot root(runtime, object);
        auto metadata = std::make_unique<InputConnectionState>();
        metadata->references[0] = Value::reference(owner);
        metadata->view_editor = true;
        runtime.set_host_state(object, std::move(metadata));
        return object;
    }
    ObjectId connection_editable(ObjectId connection) {
        // Actual virtual dispatch is essential: a Java subclass can supply a
        // different Editable. It must still be the supported plain buffer.
        const auto result = runtime.invoke_virtual_named(connection, "getEditable", "()Landroid/text/Editable;").bits;
        if (result) (void)selection_state(result);
        return result;
    }
    void connection_replace(ObjectId connection, ObjectId source, std::int32_t cursor, bool composing) {
        EditCall call(*this);
        ManagedRoot connection_root(runtime, connection), source_root(runtime, source);
        if (!source) runtime.raise("Ljava/lang/NullPointerException;");
        const auto first = connection_editable(connection);
        if (!first) return;
        ManagedRoot first_root(runtime, first);
        (void)runtime.invoke_virtual_named(connection, "beginBatchEdit", "()Z");
        PendingCompositionRemoval pending(*this, first);
        auto start = selection_state(first).composing_start, end = selection_state(first).composing_end;
        const bool replacing_composition = start >= 0 && end >= 0;
        if (replacing_composition) set_composition(first, -1, -1, false, &pending);
        else {
            start = std::max(0, selection_state(first).start);
            end = std::max(0, selection_state(first).end);
        }
        if (end < start) std::swap(start, end);
        // BaseInputConnection obtains getEditable again in replaceTextInternal.
        // Retain the first buffer but do not substitute it for an override.
        const auto buffer = connection_editable(connection);
        if (!buffer) {
            pending.flush();
            (void)runtime.invoke_virtual_named(connection, "endBatchEdit", "()Z");
            return;
        }
        ManagedRoot buffer_root(runtime, buffer);
        auto input = source;
        if (composing) {
            if (runtime.assignable(input, spannable_type)) {
                if (runtime.object_type(input) != buffer_type)
                    runtime.raise("Ljava/lang/UnsupportedOperationException;", u"Custom composing Spanned text is unsupported");
            } else {
                input = new_editable(std::u16string(runtime.char_sequence(source)));
            }
        }
        ManagedRoot input_root(runtime, input);
        const auto source_length = runtime.char_sequence(input).size();
        if (source_length > editable_text_limit) bad("TEXT_LIMIT", "IME text exceeds the plain Editable quota");
        if (composing) {
            const bool own_source = input == pending.buffer.object;
            set_composition(input, 0, static_cast<std::int32_t>(source_length), !own_source,
                            &pending);
        }
        const auto old_length = selection_state(buffer).text.size();
        // Java int addition wraps before BaseInputConnection clamps it.
        const auto adjustment = cursor > 0 ? end - 1 : start;
        const auto requested = std::bit_cast<std::int32_t>(std::bit_cast<std::uint32_t>(cursor) +
                                                          std::bit_cast<std::uint32_t>(adjustment));
        const auto position = std::clamp(requested, 0, static_cast<std::int32_t>(old_length));
        set_selection(buffer, position, position);
        replace_buffer(buffer, start, end, input, 0, static_cast<std::int32_t>(source_length), &pending, composing);
        pending.flush();
        if (!cursor && start == end) set_selection(buffer, position, position);
        (void)runtime.invoke_virtual_named(connection, "endBatchEdit", "()Z");
        // Replacement/callbacks own the result, including any new View buffer.
    }
    Value input_connection_api(const ApiSupport &api, std::span<const Value> args) {
        const auto integer = [&](std::size_t at) {
            if (at >= args.size() || args[at].kind != dex::ValueKind::word)
                bad("INPUT_CONNECTION_ARGUMENT", "InputConnection integer argument is invalid");
            return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[at].bits));
        };
        const auto reference = [&](std::size_t at) {
            if (at >= args.size() || (args[at].kind != dex::ValueKind::reference &&
                !(args[at].kind == dex::ValueKind::word && !args[at].bits)))
                bad("INPUT_CONNECTION_ARGUMENT", "InputConnection reference argument is invalid");
            return args[at].bits;
        };
        const auto receiver = reference(0);
        ManagedRoot receiver_root(runtime, receiver);
        if (api.owner == base_input_connection_type && api_static(api)) {
            const auto &buffer = selection_state(receiver);
            if (api.name == "getComposingSpanStart")
                return Value::word(std::bit_cast<std::uint32_t>(buffer.composing_start));
            if (api.name == "getComposingSpanEnd")
                return Value::word(std::bit_cast<std::uint32_t>(buffer.composing_end));
            set_composition(receiver, api.name == "removeComposingSpans" ? -1 : 0,
                            api.name == "removeComposingSpans" ? -1 : static_cast<std::int32_t>(buffer.text.size()));
            return Value::nothing();
        }
        if (!receiver) runtime.raise("Ljava/lang/NullPointerException;");
        if (api.owner == editor_info_type) {
            if (api.name == "<init>") {
                if (runtime.host_state(receiver)) runtime.raise("Ljava/lang/IllegalStateException;");
                runtime.set_host_state(receiver, std::make_unique<EditorInfoState>());
                return Value::nothing();
            }
            (void)editor_state(receiver);
            if (api.name == "describeContents") return Value::word(0); // No file descriptors in this profile.
            bad("EDITOR_INFO_UNSUPPORTED", "EditorInfo method is unsupported");
        }
        if (api.owner == input_connection_type) {
            if (!runtime.assignable(receiver, input_connection_type)) runtime.raise("Ljava/lang/IllegalArgumentException;");
            if (api.name == "setImeConsumesInput") return Value::word(0); // Exact interface default.
            bad("INPUT_CONNECTION_ABSTRACT", "Abstract InputConnection method has no implementation");
        }
        if (api.name == "<init>") {
            if (runtime.host_state(receiver)) runtime.raise("Ljava/lang/IllegalStateException;");
            const auto target = reference(1);
            if (!target) runtime.raise("Ljava/lang/NullPointerException;");
            (void)view(target);
            const bool editor = api.owner == editable_input_connection_type;
            if (!runtime.assignable(target, editor ? "Landroid/widget/TextView;" : "Landroid/view/View;"))
                runtime.raise("Ljava/lang/IllegalArgumentException;");
            if (!editor && !integer(2))
                runtime.raise("Ljava/lang/UnsupportedOperationException;", u"BaseInputConnection fallback key mode is unsupported");
            auto metadata = std::make_unique<InputConnectionState>();
            metadata->references[0] = Value::reference(target);
            metadata->view_editor = editor;
            runtime.set_host_state(receiver, std::move(metadata));
            return Value::nothing();
        }
        (void)connection_state(receiver);
        if (api.name == "getEditable") {
            if (api.owner == editable_input_connection_type) {
                const auto target = connection_state(receiver).references[0].bits;
                return runtime.invoke_virtual_named(target, "getEditableText", "()Landroid/text/Editable;");
            }
            auto buffer = connection_state(receiver).references[1].bits;
            if (!buffer) {
                buffer = new_editable({}, 0, true);
                ManagedRoot buffer_root(runtime, buffer);
                auto next = std::make_unique<InputConnectionState>(connection_state(receiver));
                next->references[1] = Value::reference(buffer);
                runtime.set_host_state(receiver, std::move(next));
            }
            return Value::reference(buffer);
        }
        if (api.name == "setImeConsumesInput") {
            const auto target = connection_state(receiver).references[0].bits;
            const std::array values{Value::word(integer(1) != 0)};
            (void)runtime.invoke_virtual_named(target, "setImeConsumesInput", "(Z)V", values);
            return Value::word(1);
        }
        if (api.name == "beginBatchEdit" || api.name == "endBatchEdit") {
            if (api.owner == base_input_connection_type) return Value::word(0); // Exact Base defaults.
            const auto target = connection_state(receiver).references[0].bits;
            const auto depth = connection_state(receiver).batch_depth;
            const bool begin = api.name == "beginBatchEdit";
            if ((begin && depth < 0) || (!begin && depth <= 0)) return Value::word(0);
            if (begin && depth >= 32) bad("IME_BATCH_LIMIT", "InputConnection batch nesting quota is 32");
            (void)runtime.invoke_virtual_named(target, begin ? "beginBatchEdit" : "endBatchEdit", "()V");
            auto next = std::make_unique<InputConnectionState>(connection_state(receiver));
            if (begin && next->batch_depth >= 32) bad("IME_BATCH_LIMIT", "InputConnection batch nesting quota is 32");
            next->batch_depth += begin ? 1 : -1;
            const auto still_active = begin || next->batch_depth > 0;
            runtime.set_host_state(receiver, std::move(next));
            return Value::word(still_active);
        }
        if (api.name == "closeConnection") {
            (void)runtime.invoke_virtual_named(receiver, "finishComposingText", "()Z");
            const std::array values{Value::word(0)};
            (void)runtime.invoke_virtual_named(receiver, "setImeConsumesInput", "(Z)Z", values);
            if (api.owner == editable_input_connection_type) {
                unsigned count = 0;
                while (connection_state(receiver).batch_depth > 0) {
                    if (++count > 32) bad("IME_BATCH_LIMIT", "InputConnection close batch drain did not settle");
                    (void)runtime.invoke_virtual_named(receiver, "endBatchEdit", "()Z");
                }
                auto next = std::make_unique<InputConnectionState>(connection_state(receiver));
                next->batch_depth = -1;
                runtime.set_host_state(receiver, std::move(next));
            }
            return Value::nothing(); // Base close does not invalidate future Java calls.
        }
        if (api.name == "setComposingText" || api.name == "commitText") {
            connection_replace(receiver, reference(1), integer(2), api.name == "setComposingText");
            return Value::word(1);
        }
        const auto buffer = connection_editable(receiver);
        if (!buffer) return Value::word(api.name != "setSelection");
        ManagedRoot buffer_root(runtime, buffer);
        if (api.name == "finishComposingText") {
            (void)runtime.invoke_virtual_named(receiver, "beginBatchEdit", "()Z");
            set_composition(buffer, -1, -1);
            (void)runtime.invoke_virtual_named(receiver, "endBatchEdit", "()Z");
            if (const auto hook = override_method(runtime.object_type(receiver), "endComposingRegionEditInternal", "()V")) {
                const std::array values{Value::reference(receiver)};
                (void)runtime.invoke_virtual(*hook, values);
            }
            return Value::word(1);
        }
        if (api.name == "setComposingRegion") {
            (void)runtime.invoke_virtual_named(receiver, "beginBatchEdit", "()Z");
            auto first = integer(1), last = integer(2);
            if (last < first) std::swap(first, last);
            const auto length = static_cast<std::int32_t>(selection_state(buffer).text.size());
            first = std::clamp(first, 0, length); last = std::clamp(last, 0, length);
            // Read the actual region AFTER the virtual batch callback. Empty
            // normalization is a real removal; its retained text is finalized.
            const auto old_first = selection_state(buffer).composing_start;
            const auto old_last = selection_state(buffer).composing_end;
            const auto owner = selection_state(buffer).references[0].bits;
            if (first == last) {
                set_composition(buffer, -1, -1);
            } else {
                const bool target_ended = conversion_ends_in_region(owner, buffer, first, last);
                set_composition(buffer, -1, -1, false, nullptr, true);
                set_composition(buffer, first, last, false, nullptr, true);
                if (old_first != first || old_last != last) {
                    if (!target_ended) unknown_conversion(owner, buffer);
                    finalized_fragments(owner, buffer, old_first, old_last, first, last);
                    if (target_ended) end_conversion(owner, buffer);
                } else interrupt_conversion_observations(owner, buffer);
            }
            (void)runtime.invoke_virtual_named(receiver, "endBatchEdit", "()Z");
            if (const auto hook = override_method(runtime.object_type(receiver), "endComposingRegionEditInternal", "()V")) {
                const std::array values{Value::reference(receiver)};
                (void)runtime.invoke_virtual(*hook, values);
            }
            return Value::word(1);
        }
        if (api.name == "setSelection") {
            const auto first = integer(1), last = integer(2);
            const auto length = selection_state(buffer).text.size();
            if (first < 0 || last < 0 || static_cast<std::size_t>(first) > length || static_cast<std::size_t>(last) > length)
                return Value::word(1);
            set_selection(buffer, first, last);
            return Value::word(1);
        }
        bad("INPUT_CONNECTION_UNSUPPORTED", "InputConnection operation is outside the plain full-editor profile");
    }
    Value editable_api(const ApiSupport &api, std::span<const Value> args) {
        const auto integer = [&](std::size_t at) { return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[at].bits)); };
        if (api.owner == "Landroid/text/Selection;") {
            const auto buffer = args[0].bits;
            if (api.name == "getSelectionStart" || api.name == "getSelectionEnd") {
                const auto result = selection_marker(buffer, api.name == "getSelectionEnd");
                return Value::word(std::bit_cast<std::uint32_t>(result));
            }
            if (api.name == "removeSelection") {
                EditCall call(*this);
                ManagedRoot root(runtime, buffer);
                auto next = std::make_unique<EditableState>(selection_state(buffer));
                const bool notify = next->end != -1;
                next->start = next->end = -1;
                runtime.set_host_state(buffer, std::move(next));
                if (notify) selection_changed(buffer);
            } else if (api.name == "selectAll") {
                set_selection(buffer, 0, static_cast<std::int32_t>(selection_state(buffer).text.size()));
            } else if (api.name == "extendSelection") {
                set_selection(buffer, 0, integer(1), true);
            } else set_selection(buffer, integer(1), args.size() == 3 ? integer(2) : integer(1));
            return Value::nothing();
        }
        const auto object = args[0].bits;
        if (api.name == "<init>") {
            if (runtime.host_state(object)) runtime.raise("Ljava/lang/IllegalStateException;", u"Editable constructor called twice");
            if (args.size() > 1 && !args[1].bits) runtime.raise("Ljava/lang/NullPointerException;");
            auto text = args.size() > 1 ? std::u16string(runtime.char_sequence(args[1].bits)) : std::u16string{};
            if (text.size() > editable_text_limit) bad("TEXT_LIMIT", "Plain Editable quota is 4096 UTF-16 units");
            auto next = std::make_unique<EditableState>();
            next->text = std::move(text);
            runtime.set_host_state(object, std::move(next));
            return Value::nothing();
        }
        if (api.name == "length") return Value::word(static_cast<std::uint32_t>(editable_state(object).text.size()));
        if (api.name == "charAt") {
            const auto at = integer(1);
            const auto &text = editable_state(object).text;
            if (at < 0 || static_cast<std::size_t>(at) >= text.size()) runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
            return Value::word(text[static_cast<std::size_t>(at)]);
        }
        if (api.name == "toString") {
            const auto text = std::u16string(editable_state(object).text);
            return Value::reference(runtime.new_string(text));
        }
        if (api.name == "subSequence") {
            const auto start = integer(1), end = integer(2);
            const auto text = std::u16string(editable_state(object).text);
            if (start < 0 || end < start || static_cast<std::size_t>(end) > text.size()) runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
            return Value::reference(new_editable(text.substr(static_cast<std::size_t>(start), static_cast<std::size_t>(end - start))));
        }
        if (api.name == "getChars") {
            const auto start = integer(1), end = integer(2), offset = integer(4);
            const auto text = std::u16string(editable_state(object).text);
            if (start < 0 || end < start || static_cast<std::size_t>(end) > text.size()) runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
            const auto destination = args[3].bits;
            if (!destination) runtime.raise("Ljava/lang/NullPointerException;");
            if (runtime.object_type(destination) != "[C") runtime.raise("Ljava/lang/ArrayStoreException;");
            const auto capacity = runtime.array_length(destination);
            if (offset < 0 || static_cast<std::size_t>(offset) > capacity ||
                static_cast<std::size_t>(end - start) > capacity - static_cast<std::size_t>(offset))
                runtime.raise("Ljava/lang/IndexOutOfBoundsException;");
            for (auto at = start; at < end; ++at)
                runtime.array_set(destination, offset + (at - start), Value::word(text[static_cast<std::size_t>(at)]));
            return Value::nothing();
        }
        auto start = 0, end = static_cast<std::int32_t>(editable_state(object).text.size());
        ObjectId source = 0;
        std::int32_t first = 0, last = 0;
        std::unique_ptr<ManagedRoot> generated;
        if (api.name == "delete" || api.name == "clear" || (api.name == "append" && api.signature.starts_with("(C)"))) {
            const auto text = api.name == "append" ? std::u16string(1, static_cast<char16_t>(args[1].bits)) : std::u16string{};
            source = runtime.new_string(text);
            generated = std::make_unique<ManagedRoot>(runtime, source);
            last = static_cast<std::int32_t>(text.size());
            if (api.name == "delete") { start = integer(1); end = integer(2); }
            else if (api.name == "append") start = end;
        } else {
            const bool replace = api.name == "replace";
            const auto source_at = replace ? 3u : api.name == "insert" ? 2u : 1u;
            source = args[source_at].bits;
            if (replace) { start = integer(1); end = integer(2); }
            else if (api.name == "insert") start = end = integer(1);
            else start = end;
            const bool slice = (replace && args.size() == 6) || (!replace && api.name == "append" && args.size() == 4);
            if (slice) { first = integer(source_at + 1); last = integer(source_at + 2); }
            else {
                if (!source) runtime.raise("Ljava/lang/NullPointerException;");
                last = static_cast<std::int32_t>(runtime.char_sequence(source).size());
            }
        }
        replace_buffer(object, start, end, source, first, last);
        return api.name == "clear" ? Value::nothing() : Value::reference(object);
    }
    const ViewObjectState &view_state(ObjectId object) const {
        const auto *metadata = dynamic_cast<const ViewObjectState *>(runtime.host_state(object));
        if (!metadata) bad("VIEW", "View metadata is unavailable");
        return *metadata;
    }
    void check_descriptions(ObjectId replacement_view = 0, ObjectId replacement = 0) const {
        std::size_t total = 0;
        for (const auto &[id, node] : views) {
            (void)node;
            const auto description = id == replacement_view ? replacement : view_state(id).references[1].bits;
            if (!description) continue;
            const auto length = runtime.char_sequence(description).size();
            if (length > view_description_limit || length > activity_description_limit - total)
                bad("DESCRIPTION_LIMIT", "View content descriptions exceed the publication quota");
            total += length;
        }
    }
    const ViewObjectState &checked_state(ObjectId object) {
        if (view(object).kind != ViewKind::checkbox)
            bad("CHECKABLE", "View is not a supported compound button");
        return view_state(object);
    }
    void set_checked(ObjectId object, bool value) {
        auto &node = view(object);
        const auto broadcasting = checked_state(object).broadcasting;
        if (node.checked == value) return;
        node.checked = value;
        ++metrics.view_revision;
        if (broadcasting) return;
        auto next = std::make_unique<ViewObjectState>(checked_state(object));
        next->broadcasting = true;
        const auto listener = next->references[0].bits;
        runtime.set_host_state(object, std::move(next));
        runtime.retain(listener);
        struct Release { dex::ManagedRuntime &runtime; ObjectId id; ~Release() { runtime.release(id); } } root{runtime, listener};
        if (listener) {
            const std::array args{Value::reference(object), Value::word(value)};
            (void)runtime.invoke_virtual_named(listener, "onCheckedChanged",
                "(Landroid/widget/CompoundButton;Z)V", args);
        }
        // Match Android's observable exception behavior: a thrown listener
        // leaves broadcasting set. Reentrant state changes still take effect.
        // The callback may replace its listener or state. Reacquire and clone
        // the latest charged state, preserving those edits while ending only
        // the broadcast that completed normally. No borrowed state crosses it.
        auto completed = std::make_unique<ViewObjectState>(checked_state(object));
        completed->broadcasting = false;
        runtime.set_host_state(object, std::move(completed));
    }
    void dispatch_set_checked(ObjectId object, bool value) {
        if (const auto method = override_method(runtime.object_type(object), "setChecked", "(Z)V")) {
            const std::array args{Value::reference(object), Value::word(value)};
            (void)runtime.invoke_virtual(*method, args);
        } else set_checked(object, value);
    }
    void dispatch_toggle(ObjectId object) {
        if (const auto method = override_method(runtime.object_type(object), "toggle", "()V")) {
            const std::array args{Value::reference(object)};
            (void)runtime.invoke_virtual(*method, args);
        } else dispatch_set_checked(object, !view(object).checked);
    }
    bool perform_click_base(ObjectId object, bool compound) {
        dex::ViewActivationScope activation(runtime, object, true);
        if (compound) dispatch_toggle(object);
        const auto listener = view(object).listener;
        if (!listener)
            return false;
        const auto method =
            override_method(runtime.object_type(listener), "onClick", "(Landroid/view/View;)V");
        if (!method)
            bad("LISTENER", "OnClickListener has no managed onClick implementation");
        const std::array args{Value::reference(listener), Value::reference(object)};
        (void)runtime.invoke_virtual(*method, args);
        ++metrics.managed_clicks;
        activation.complete(true);
        return true;
    }
    bool perform_click(ObjectId object) {
        if (const auto method = override_method(runtime.object_type(object), "performClick", "()Z")) {
            const std::array args{Value::reference(object)};
            return runtime.invoke_virtual(*method, args).bits != 0;
        }
        return perform_click_base(object, view(object).kind == ViewKind::checkbox);
    }
    std::u16string resource_text(std::uint32_t id, bool strip_styles = false) {
        try {
            return resources.text(id, strip_styles);
        } catch (const apk::InspectError &e) {
            runtime.raise("Landroid/content/res/Resources$NotFoundException;", unicode(e.what()));
        }
    }
};
ActivitySession::ActivitySession(dex::ManagedRuntime &runtime, std::string package,
                                 apk::ResourceTable resources, const host::TimeService *time, host::FileService *files,
                                 DisplayConfiguration configuration, host::NotificationService *notifications,
                                 host::DocumentService *documents, host::ClipboardService *clipboard)
    : impl_(std::make_unique<Impl>(runtime, std::move(package), std::move(resources), time, files, configuration,
                                   notifications, documents, clipboard)) {
    auto &p = *impl_;
    runtime.set_host_interface(this);
    p.attached = true;
    try {
        p.base_context = p.own(runtime.new_object(context_impl_type));
        p.resource_object = p.own(runtime.new_object("Landroid/content/res/Resources;"));
        p.configuration_object = p.own(runtime.new_object(configuration_type));
        runtime.set_host_state(p.configuration_object, std::make_unique<ConfigurationState>(configuration));
        p.package_manager = p.own(runtime.new_object("Laether/android/PackageManager;"));
        p.bind_package();
    } catch (...) {
        p.cleanup(false);
        throw;
    }
}
ActivitySession::~ActivitySession() { impl_->cleanup(false); }
std::uint64_t ActivitySession::begin_view_activation(ObjectId object) const noexcept {
    const auto found = impl_->views.find(object);
    return found != impl_->views.end() && found->second.kind != ViewKind::checkbox
        ? impl_->window_generation : 0;
}
void ActivitySession::view_activated(ObjectId object, std::uint64_t generation) noexcept {
    auto &p = *impl_;
    if (p.view_activation_failure != Impl::ActivationFailure::none) return;
    // Receiver eligibility and incarnation were captured before guest code.
    // The completed callback may already have detached or retired that View.
    if (!object || !generation || generation > p.window_generation) {
        p.view_activation_failure = Impl::ActivationFailure::invalid;
        return;
    }
    if (p.view_activation_revision == UINT64_MAX) {
        p.view_activation_failure = Impl::ActivationFailure::exhausted;
        return;
    }
    if (p.view_activation_count == view_activation_limit) {
        p.view_activation_failure = Impl::ActivationFailure::quota;
        return;
    }
    p.view_activations[p.view_activation_count++] = {++p.view_activation_revision, object, generation};
}
void ActivitySession::collection_selection_policy_write(dex::ManagedRuntime &runtime, ObjectId object) {
    auto &p = *impl_;
    if (&runtime != &p.runtime || !p.views.contains(object) || !p.collection_selection_policy_getter(object)) return;
    // Invalidate before the real setter: a throwing setter may already have
    // changed private policy. This notification invokes no guest code.
    if (p.accessibility_invalidation == UINT64_MAX)
        bad("ACCESSIBILITY_INVALIDATION", "Accessibility invalidation revision exhausted");
    ++p.accessibility_invalidation;
}
void ActivitySession::check_view_activations() const { impl_->check_view_activations(); }
void ActivitySession::prepare_terminal_cleanup() noexcept {
    impl_->terminal_cleanup = true;
    impl_->text_edit_observer = nullptr;
    impl_->soft_input_observer = nullptr;
}
std::vector<ViewActivation> ActivitySession::pending_view_activations() const {
    impl_->check_view_activations();
    return {impl_->view_activations.begin(), impl_->view_activations.begin() +
        static_cast<std::ptrdiff_t>(impl_->view_activation_count)};
}
std::vector<ViewActivation> ActivitySession::terminal_view_activations() const {
    const auto &p = *impl_;
    if (p.view_activation_count > view_activation_limit || p.view_activation_count > p.view_activation_revision)
        bad("VIEW_ACTIVATION_TERMINAL", "Terminal View activation prefix has invalid coverage");
    auto previous = p.view_activation_revision - p.view_activation_count;
    for (std::size_t index = 0; index < p.view_activation_count; ++index) {
        const auto &record = p.view_activations[index];
        if (!record.view || !record.window_generation || record.window_generation > p.window_generation ||
            previous == UINT64_MAX || record.revision != previous + 1)
            bad("VIEW_ACTIVATION_TERMINAL", "Terminal View activation prefix is not exact retained history");
        previous = record.revision;
    }
    return {p.view_activations.begin(), p.view_activations.begin() +
        static_cast<std::ptrdiff_t>(p.view_activation_count)};
}
std::uint64_t ActivitySession::view_activation_revision() const noexcept {
    return impl_->view_activation_revision;
}
void ActivitySession::acknowledge_view_activations(std::uint64_t through) {
    auto &p = *impl_;
    p.check_view_activations();
    const auto last = p.view_activations.begin() + static_cast<std::ptrdiff_t>(p.view_activation_count);
    const auto acknowledged = std::find_if(p.view_activations.begin(), last,
        [through](const auto &record) { return record.revision == through; });
    if (!through || acknowledged == last)
        bad("VIEW_ACTIVATION_ACK", "View activation acknowledgement does not identify a pending prefix");
    const auto consumed = static_cast<std::size_t>(acknowledged - p.view_activations.begin()) + 1;
    std::move(acknowledged + 1, last, p.view_activations.begin());
    p.view_activation_count -= consumed;
    std::fill(p.view_activations.begin() + static_cast<std::ptrdiff_t>(p.view_activation_count), last,
              ViewActivation{});
}
std::uint64_t ActivitySession::accessibility_metadata_attempt() const noexcept { return impl_->accessibility_attempt; }
AccessibilityMetadataStatus ActivitySession::accessibility_metadata_status() const noexcept { return impl_->accessibility_status; }
std::uint64_t ActivitySession::accessibility_invalidation_revision() const noexcept { return impl_->accessibility_invalidation; }
bool ActivitySession::prepare_accessibility_metadata(std::uint64_t expected_view_revision, ObjectId expected_content) {
    auto &p = *impl_;
    p.check_text_edit_observer_idle();
    if (p.preparing_accessibility) bad("ACCESSIBILITY_REENTRY", "Accessibility metadata preparation cannot reenter");
    if (p.accessibility_attempt == UINT64_MAX) bad("ACCESSIBILITY_ATTEMPT", "Accessibility metadata attempt revision exhausted");
    ++p.accessibility_attempt;
    p.accessibility_status = AccessibilityMetadataStatus::stale;
    p.accessibility_metadata.clear();
    if (!p.attached || !p.activity_attached || !p.activity || !p.content ||
        p.state == Lifecycle::empty || p.state == Lifecycle::destroyed || p.state == Lifecycle::failed ||
        p.metrics.view_revision != expected_view_revision || p.content != expected_content) return false;
    const auto owner = p.activity, content = p.content;
    const auto generation = p.window_generation, revision = p.metrics.view_revision;
    const auto invalidation = p.accessibility_invalidation;
    struct ManifestEntry { ObjectId parent; std::vector<ObjectId> children; };
    std::map<ObjectId, ManifestEntry> manifest;
    std::vector<ObjectId> pending{content};
    while (!pending.empty()) {
        const auto id = pending.back(); pending.pop_back();
        const auto found = p.views.find(id);
        if (found == p.views.end() || manifest.contains(id) || manifest.size() == 256)
            bad("ACCESSIBILITY_TREE", "Accessibility preparation requires a bounded actual View tree");
        manifest.emplace(id, ManifestEntry{found->second.parent, found->second.children});
        pending.insert(pending.end(), found->second.children.begin(), found->second.children.end());
    }
    struct Roots {
        dex::ManagedRuntime &runtime;
        std::vector<ObjectId> ids;
        ~Roots() { for (const auto id : ids) runtime.release(id); }
    } roots{p.runtime, {}};
    roots.ids.reserve(manifest.size() + 1);
    p.runtime.retain(owner); roots.ids.push_back(owner);
    for (const auto &[id, entry] : manifest) {
        (void)entry;
        p.runtime.retain(id); roots.ids.push_back(id);
    }
    std::map<ObjectId, Impl::AccessibilityMetadata> candidate;
    for (const auto &[id, entry] : manifest) { (void)entry; candidate.emplace(id, Impl::AccessibilityMetadata{}); }
    const auto current = [&] {
        if (!p.attached || !p.activity_attached || p.activity != owner || p.content != content ||
            p.window_generation != generation || p.metrics.view_revision != revision ||
            p.accessibility_invalidation != invalidation || p.state == Lifecycle::destroyed || p.state == Lifecycle::failed)
            return false;
        for (const auto &[id, entry] : manifest) {
            const auto found = p.views.find(id);
            if (found == p.views.end() || found->second.parent != entry.parent || found->second.children != entry.children)
                return false;
        }
        return true;
    };
    p.preparing_accessibility = true;
    struct Reset { bool &active; ~Reset() { active = false; } } reset{p.preparing_accessibility};
    p.accessibility_status = AccessibilityMetadataStatus::mutated;
    const auto query_thread = p.runtime.current_thread();
    for (const auto &[id, entry] : manifest) {
        (void)entry;
        const auto provider = p.accessibility_node_provider(id);
        ManagedRoot provider_root(p.runtime, provider);
        p.check_text_edit_observer_idle();
        if (!current()) return false;
        candidate.at(id).node_provider_present = provider != 0;
        if (provider) continue; // Preserve literal presence; never invent its virtual node tree.
        Impl::AccessibilityProviderQuery query{id, query_thread, false, p.accessibility_provider_query};
        p.accessibility_provider_query = &query;
        struct RestoreQuery {
            Impl &owner; Impl::AccessibilityProviderQuery *previous;
            ~RestoreQuery() { owner.accessibility_provider_query = previous; }
        } restore_query{p, query.previous};
        const auto info = p.create_accessibility_node_info(id);
        ManagedRoot info_root(p.runtime, info);
        p.check_text_edit_observer_idle();
        if (!current()) return false;
        const auto *node = info ? dynamic_cast<const AccessibilityObjectState *>(p.runtime.host_state(info)) : nullptr;
        if (!node || node->kind != AccessibilityObjectState::Kind::node || node->references[0].bits != id) return false;
        candidate.at(id).actions = node->actions;
        if (node->references[1].bits)
            candidate.at(id).collection = p.accessibility_object(node->references[1].bits, AccessibilityObjectState::Kind::collection).collection;
        if (node->references[2].bits)
            candidate.at(id).item = p.accessibility_object(node->references[2].bits, AccessibilityObjectState::Kind::item).item;
        if (candidate.at(id).collection)
            if (const auto getter = p.collection_selection_policy_getter(id)) {
                const std::array args{Value::reference(id)};
                const bool required = p.runtime.invoke_virtual(*getter, args).bits != 0;
                p.check_text_edit_observer_idle();
                if (!current()) return false;
                candidate.at(id).selection_required = required;
            }
    }
    if (!current()) return false;
    for (auto &[id, metadata] : candidate) {
        if (!metadata.item) continue;
        auto parent = manifest.at(id).parent;
        for (std::size_t depth = 0; parent && depth < manifest.size(); ++depth) {
            const auto ancestor = candidate.find(parent);
            if (ancestor == candidate.end()) break;
            if (ancestor->second.collection) { metadata.owner = parent; break; }
            parent = manifest.at(parent).parent;
        }
    }
    p.accessibility_metadata.swap(candidate);
    p.accessibility_activity = owner; p.accessibility_content = content;
    p.accessibility_generation = generation; p.accessibility_view_revision = revision;
    p.accessibility_source_invalidation = invalidation;
    p.accessibility_status = AccessibilityMetadataStatus::ready;
    return true;
}
bool ActivitySession::collection_selection(ObjectId object, ObjectId owner, std::uint64_t expected_metadata_revision,
                                          std::uint64_t expected_view_revision, CollectionSelectionOperation operation) {
    auto &p = *impl_;
    p.check_text_edit_observer_idle();
    if ((operation != CollectionSelectionOperation::replace && operation != CollectionSelectionOperation::add &&
         operation != CollectionSelectionOperation::remove) || !object || !owner || object == owner ||
        !expected_metadata_revision || p.accessibility_attempt != expected_metadata_revision ||
        p.metrics.view_revision != expected_view_revision || !p.accessibility_cache_current() ||
        p.state != Lifecycle::resumed || p.pointer_target || p.key_target || !p.enabled(owner) || !p.enabled(object))
        return false;
    const auto original_activity = p.activity, original_content = p.content;
    const auto original_generation = p.window_generation;
    struct ManifestEntry { ObjectId parent; std::vector<ObjectId> children; };
    std::map<ObjectId, ManifestEntry> manifest;
    std::vector<ObjectId> pending{original_content};
    while (!pending.empty()) {
        const auto id = pending.back(); pending.pop_back();
        const auto found = p.views.find(id);
        if (found == p.views.end() || manifest.contains(id) || manifest.size() == 256) return false;
        manifest.emplace(id, ManifestEntry{found->second.parent, found->second.children});
        pending.insert(pending.end(), found->second.children.begin(), found->second.children.end());
    }
    if (!manifest.contains(owner) || !manifest.contains(object)) return false;
    struct Roots {
        dex::ManagedRuntime &runtime; std::vector<ObjectId> ids;
        ~Roots() { for (const auto id : ids) runtime.release(id); }
    } roots{p.runtime, {}};
    roots.ids.reserve(manifest.size() + 1);
    p.runtime.retain(original_activity); roots.ids.push_back(original_activity);
    for (const auto &[id, entry] : manifest) { (void)entry; p.runtime.retain(id); roots.ids.push_back(id); }
    const auto structural_current = [&] {
        if (!p.attached || !p.activity_attached || p.activity != original_activity || p.content != original_content ||
            p.window_generation != original_generation || p.state != Lifecycle::resumed || p.pointer_target || p.key_target)
            return false;
        for (const auto &[id, entry] : manifest) {
            const auto found = p.views.find(id);
            if (found == p.views.end() || found->second.parent != entry.parent || found->second.children != entry.children)
                return false;
        }
        return p.enabled(owner) && p.enabled(object);
    };
    const auto initial_owner = p.accessibility_metadata.find(owner);
    if (initial_owner == p.accessibility_metadata.end() || !initial_owner->second.collection ||
        !initial_owner->second.selection_required.has_value()) return false;
    const auto original_collection = *initial_owner->second.collection;
    const bool selection_required = *initial_owner->second.selection_required;
    const auto &children = manifest.at(owner).children;
    const auto anchors = static_cast<std::int32_t>(children.size());
    if (original_collection.hierarchical || original_collection.row_count < 0 || original_collection.column_count < 0 ||
        original_collection.row_count > 256 || original_collection.column_count > 256 ||
        std::int64_t(original_collection.row_count) * original_collection.column_count > 256 ||
        (original_collection.selection_mode != 1 && original_collection.selection_mode != 2) ||
        original_collection.item_count < -1 || original_collection.important_item_count < -1 ||
        (original_collection.item_count != -1 && original_collection.item_count != anchors) ||
        (original_collection.important_item_count != -1 && original_collection.important_item_count != anchors)) return false;
    std::map<ObjectId, AccessibilityCollectionItemInfo> original_items;
    std::array<bool, 256> covered{};
    for (const auto id : children) {
        const auto found = p.accessibility_metadata.find(id);
        if (found == p.accessibility_metadata.end() || found->second.owner != owner || !found->second.item) return false;
        const auto item = *found->second.item;
        if (item.row_index < 0 || item.column_index < 0 || item.row_span <= 0 || item.column_span <= 0 ||
            item.row_index >= original_collection.row_count || item.column_index >= original_collection.column_count ||
            item.row_span > original_collection.row_count - item.row_index ||
            item.column_span > original_collection.column_count - item.column_index) return false;
        for (auto row = item.row_index; row < item.row_index + item.row_span; ++row)
            for (auto column = item.column_index; column < item.column_index + item.column_span; ++column) {
                auto &cell = covered[static_cast<std::size_t>(row * original_collection.column_count + column)];
                if (cell) return false;
                cell = true;
            }
        original_items.emplace(id, item);
    }
    if (!original_items.contains(object)) return false;
    for (std::int32_t cell = 0; cell < original_collection.row_count * original_collection.column_count; ++cell)
        if (!covered[static_cast<std::size_t>(cell)] && original_collection.item_count != anchors) return false;
    const auto metadata_current = [&] {
        if (!structural_current() || !p.accessibility_cache_current()) return false;
        const auto grid = p.accessibility_metadata.find(owner);
        if (grid == p.accessibility_metadata.end() || !grid->second.collection ||
            grid->second.selection_required != selection_required) return false;
        const auto &collection = *grid->second.collection;
        if (collection.row_count != original_collection.row_count || collection.column_count != original_collection.column_count ||
            collection.hierarchical != original_collection.hierarchical || collection.selection_mode != original_collection.selection_mode ||
            collection.item_count != original_collection.item_count || collection.important_item_count != original_collection.important_item_count)
            return false;
        std::vector<ObjectId> subtree{owner};
        while (!subtree.empty()) {
            const auto id = subtree.back(); subtree.pop_back();
            const auto metadata = p.accessibility_metadata.find(id);
            if (metadata == p.accessibility_metadata.end() || metadata->second.node_provider_present) return false;
            const auto &descendants = manifest.at(id).children;
            subtree.insert(subtree.end(), descendants.begin(), descendants.end());
        }
        for (const auto &[id, original] : original_items) {
            const auto found = p.accessibility_metadata.find(id);
            if (found == p.accessibility_metadata.end() || found->second.owner != owner || !found->second.item) return false;
            const auto &item = *found->second.item;
            if (item.row_index != original.row_index || item.column_index != original.column_index ||
                item.row_span != original.row_span || item.column_span != original.column_span || item.heading != original.heading)
                return false;
        }
        // A required collection with no actual selected item is inconsistent;
        // do not act on that source or continue after a callback creates it.
        return !selection_required || std::any_of(original_items.begin(), original_items.end(),
            [&](const auto &entry) { return p.accessibility_metadata.at(entry.first).item->selected; });
    };
    if (!metadata_current()) return false;
    const auto selected_count = std::count_if(original_items.begin(), original_items.end(),
        [](const auto &entry) { return entry.second.selected; });
    if ((original_collection.selection_mode == 1 && selected_count > 1) ||
        (selection_required && selected_count == 0)) return false;
    const bool target_selected = original_items.at(object).selected;
    if (operation == CollectionSelectionOperation::add && original_collection.selection_mode == 1 &&
        selected_count > (target_selected ? 1 : 0)) return false;
    if (operation == CollectionSelectionOperation::remove && selection_required && target_selected && selected_count == 1)
        return false;
    struct Step { ObjectId view; std::uint32_t action; };
    std::vector<Step> steps;
    steps.reserve(children.size() + 1);
    const bool select_first = operation == CollectionSelectionOperation::replace && selection_required;
    if (select_first && !target_selected) steps.push_back({object, 4});
    if (operation == CollectionSelectionOperation::replace)
        for (const auto &[id, item] : original_items)
            if (id != object && (select_first || item.selected)) steps.push_back({id, 8});
    if (operation == CollectionSelectionOperation::remove) {
        if (target_selected) steps.push_back({object, 8});
    } else if (!select_first && !target_selected) steps.push_back({object, 4});
    // Required selection may change both peer membership and advertised CLEAR
    // actions when SELECT runs. Validate those later against the fresh round.
    if (!select_first)
        for (const auto &step : steps)
            if (!p.enabled(step.view) || !(p.accessibility_metadata.at(step.view).actions & step.action)) return false;
    for (const auto &step : steps) {
        if (!metadata_current()) return false;
        const auto &metadata = p.accessibility_metadata.at(step.view);
        const bool desired = step.action == 4;
        if (metadata.item->selected == desired) continue;
        if (!p.enabled(step.view) || !(metadata.actions & step.action)) return false;
        if (!desired && selection_required && std::count_if(original_items.begin(), original_items.end(),
            [&](const auto &entry) { return p.accessibility_metadata.at(entry.first).item->selected; }) <= 1) return false;
        const bool handled = p.accessibility_action(step.view, step.action);
        // Never query callbacks on a replacement Activity/tree after this
        // operation's actual callback has retired its original scope.
        if (!structural_current()) return false;
        // A false result may still have changed private app state. Query once
        // after every normal return; exceptions unwind without new callbacks.
        const bool prepared = prepare_accessibility_metadata(p.metrics.view_revision, p.content);
        if (!handled || !prepared || !metadata_current()) return false;
        if (p.accessibility_metadata.at(step.view).item->selected != desired) return false;
    }
    if (!metadata_current()) return false;
    for (const auto &[id, original] : original_items) {
        (void)original;
        const bool selected = p.accessibility_metadata.at(id).item->selected;
        if (id == object) {
            if (selected != (operation != CollectionSelectionOperation::remove)) return false;
        } else if (operation == CollectionSelectionOperation::replace ? selected : selected != original.selected) return false;
    }
    return true;
}
void ActivitySession::set_text_edit_observer(TextEditObserver observer) {
    impl_->check_text_edit_observer_idle();
    impl_->text_edit_observer = std::move(observer);
}
void ActivitySession::set_soft_input_observer(SoftInputObserver observer) {
    impl_->check_text_edit_observer_idle();
    impl_->soft_input_observer = std::move(observer);
}
std::vector<SoftInputRequest> ActivitySession::soft_input_requests() const {
    impl_->check_text_edit_observer_idle();
    return {impl_->soft_input_queue.begin(), impl_->soft_input_queue.begin() +
        static_cast<std::ptrdiff_t>(impl_->soft_input_count)};
}
bool ActivitySession::claim_soft_input(std::uint64_t revision, std::uint64_t host_ime_token,
                                      std::uint64_t expected_view_revision, std::u16string_view expected_text) {
    auto &p = *impl_;
    p.check_text_edit_observer_idle();
    if (!p.soft_input_count || !revision || p.soft_input_queue[0].revision != revision) return false;
    const auto request = p.soft_input_queue[0];
    ManagedRoot request_root(p.runtime, request.view);
    // Consume the exact head before callbacks, transport or native invocation.
    // A refusal or uncertain native result can never be replayed by a read.
    p.runtime.release(request.view);
    std::move(p.soft_input_queue.begin() + 1, p.soft_input_queue.begin() +
        static_cast<std::ptrdiff_t>(p.soft_input_count), p.soft_input_queue.begin());
    --p.soft_input_count;
    if (!p.soft_input_observer || request.window_generation != p.window_generation || !p.soft_input_window_ready()) return false;
    if (request.show) {
        if (!host_ime_token || !p.soft_input_editor_ready(request.view, true) ||
            (request.implicit && !p.view_state(request.view).show_soft_input_on_focus) ||
            p.metrics.view_revision != expected_view_revision ||
            p.runtime.char_sequence(p.view_state(request.view).references[2].bits) != expected_text) return false;
        if (p.ime && p.ime->token == host_ime_token && p.ime->owner.object == request.view &&
            p.ime_content_matches(*p.ime, true)) {
            // The existing served connection remains authoritative.
        } else if (!ime_edit(ImeEditKind::begin, request.view, host_ime_token, expected_view_revision,
                             expected_text, {}, 0)) return false;
        // onCreateInputConnection/close callbacks may change focus, tree,
        // window incarnation or the real binding. Never restore their output.
        if (request.window_generation != p.window_generation || !p.soft_input_editor_ready(request.view, true) ||
            !p.ime || p.ime->token != host_ime_token || p.ime->owner.object != request.view ||
            !p.ime_content_matches(*p.ime, true) ||
            (request.implicit && !p.view_state(request.view).show_soft_input_on_focus)) return false;
    } else if (host_ime_token || expected_view_revision || !expected_text.empty()) return false;
    SoftInputObservation observation;
    observation.request = request;
    observation.view_revision = p.metrics.view_revision;
    observation.lifecycle = p.state;
    observation.window_focused = p.window_focused && p.focused;
    if (request.show) {
        const auto current = snapshot_views();
        const auto found = current.find(request.view);
        if (found == current.end()) return false;
        observation.document = found->second;
        observation.rooted = p.in_tree(request.view);
    }
    p.notifying_soft_input = true;
    struct Reset { bool &value; ~Reset() { value = false; } } reset{p.notifying_soft_input};
    try { return p.soft_input_observer(observation); }
    catch (...) {
        p.soft_input_observer_failure = std::current_exception();
        throw;
    }
}
bool ActivitySession::drag(const DragInput &input) {
    impl_->check_text_edit_observer_idle();
    try { return impl_->dispatch_drag(input); }
    catch (...) { impl_->clear_drag_sequence(); throw; }
}
void ActivitySession::check_text_edit_observer() const { impl_->check_text_edit_observer_idle(); }
void ActivitySession::initialize_application(std::string_view descriptor, std::string_view factory_descriptor) {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    (void)p.runtime.assignable(p.base_context, "Landroid/content/Context;");
    if (!p.attached || p.state != Lifecycle::empty || p.application_stage != Impl::ApplicationStage::empty)
        bad("APPLICATION_STATE", "Application initialization is not available in this session state");
    try {
        if (!p.extends_application(descriptor))
            bad("APPLICATION", "Declared Application class does not extend android.app.Application");
        p.application_type_name = descriptor;
        p.application_stage = Impl::ApplicationStage::constructing;
        if (!factory_descriptor.empty()) {
            if (!p.extends_framework(factory_descriptor, factory_type))
                bad("FACTORY", "Declared component factory does not extend AppComponentFactory");
            (void)p.app_info();
            const auto loader = p.runtime.class_loader();
            p.component_factory = p.own(p.runtime.new_object(factory_descriptor));
            const std::array factory_args{Value::reference(p.component_factory)};
            if (factory_descriptor == factory_type) p.factory_constructed = true;
            else (void)p.runtime.invoke(p.runtime.lookup(factory_descriptor, "<init>", "()V", false), factory_args);
            if (!p.factory_constructed)
                bad("FACTORY_CONSTRUCTOR", "Component factory constructor did not initialize its base");
            p.selecting_loader = true;
            ObjectId selected = loader;
            if (const auto method = p.override_method(factory_descriptor, "instantiateClassLoader",
                    "(Ljava/lang/ClassLoader;Landroid/content/pm/ApplicationInfo;)Ljava/lang/ClassLoader;")) {
                const std::array args{Value::reference(p.component_factory), Value::reference(loader), Value::reference(p.application_info)};
                selected = p.runtime.invoke_virtual(*method, args).bits;
            }
            p.selecting_loader = false;
            if (selected != loader)
                bad("FACTORY_CLASS_LOADER_UNSUPPORTED", "Custom component factory class loaders are not supported");
            p.selected_loader = loader;
            p.factory_application_active = true;
            ObjectId result = 0;
            if (const auto method = p.override_method(factory_descriptor, "instantiateApplication",
                    "(Ljava/lang/ClassLoader;Ljava/lang/String;)Landroid/app/Application;")) {
                const auto name = p.own(p.runtime.new_string(p.component_name(descriptor)));
                const std::array args{Value::reference(p.component_factory), Value::reference(loader), Value::reference(name)};
                result = p.runtime.invoke_virtual(*method, args).bits;
            } else result = p.construct_application();
            p.factory_application_active = false;
            if (!p.application || result != p.application || !p.application_constructed)
                bad("FACTORY_APPLICATION_UNSUPPORTED", "Factory did not return the actual declared Application");
        } else p.construct_application();
        const std::array args{Value::reference(p.application)};
        p.application_stage = Impl::ApplicationStage::attaching;
        if (const auto method = p.override_method(descriptor, "attachBaseContext", "(Landroid/content/Context;)V")) {
            const std::array attach_args{Value::reference(p.application), Value::reference(p.base_context)};
            (void)p.runtime.invoke(*method, attach_args);
            if (!p.application_attached)
                bad("APPLICATION_CONTEXT", "Application override did not attach its base Context");
        } else p.application_attached = true;
        p.application_published = true;
        p.application_stage = Impl::ApplicationStage::creating;
        if (const auto method = p.override_method(descriptor, "onCreate", "()V"))
            (void)p.runtime.invoke(*method, args);
        p.application_stage = Impl::ApplicationStage::ready;
    } catch (...) {
        p.selecting_loader = p.factory_application_active = p.factory_activity_active = false;
        p.application_stage = Impl::ApplicationStage::failed;
        p.application_published = false;
        p.state = Lifecycle::failed;
        throw;
    }
}
ObjectId ActivitySession::application() const noexcept { return impl_->application; }
void ActivitySession::launch(std::string_view descriptor, std::int32_t requested_orientation,
                              std::uint32_t config_changes, std::uint32_t target_sdk,
                              std::string_view component_name) {
    launch_impl(descriptor, nullptr, requested_orientation, config_changes, target_sdk, component_name);
}
void ActivitySession::launch(std::string_view descriptor, const apk::IntentValue &intent,
                              std::int32_t requested_orientation, std::uint32_t config_changes,
                              std::uint32_t target_sdk, std::string_view component_name) {
    launch_impl(descriptor, &intent, requested_orientation, config_changes, target_sdk, component_name);
}
void ActivitySession::launch_impl(std::string_view descriptor, const apk::IntentValue *intent,
                                   std::int32_t requested_orientation, std::uint32_t config_changes,
                                   std::uint32_t target_sdk, std::string_view component_name) {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    if (p.state != Lifecycle::empty || !p.attached)
        bad("LIFECYCLE_STATE", "Activity can only launch once per session");
    if (requested_orientation != -1 && requested_orientation != 0 && requested_orientation != 1)
        bad("ORIENTATION_UNSUPPORTED", "Virtual display supports only unspecified(-1), landscape(0) and portrait(1)");
    if (intent) {
        intent->validate();
        const auto selected = component_name.empty() ? p.component_name(descriptor) : unicode(component_name);
        if (!intent->component || intent->component->package != unicode(p.package) ||
            intent->component->class_name != selected)
            bad("ACTIVITY_INTENT", "Delivered Intent component disagrees with the independently selected declaration");
    }
    p.orientation_request = requested_orientation;
    p.target_sdk = target_sdk;
    // Before API13 these two dimensions were treated as handled implicitly.
    p.config_changes = config_changes | (target_sdk < 13 ? 0xc00u : 0u);
    if (p.application_stage == Impl::ApplicationStage::empty)
        initialize_application();
    if (p.application_stage != Impl::ApplicationStage::ready)
        bad("APPLICATION_STATE", "Activity requires a successfully initialized Application");
    p.activity_type = descriptor;
    try {
        // Preserve the selected manifest alias as component metadata, while
        // the immutable executable descriptor remains the selected target.
        p.launch_intent = p.own(intent ? materialize_intent(p.runtime, *intent) :
            make_launch_intent(p.runtime, unicode(p.package),
                component_name.empty() ? p.component_name(descriptor) : unicode(component_name)));
        p.create_activity();
    } catch (...) {
        p.factory_activity_active = false;
        p.state = Lifecycle::failed;
        throw;
    }
}
std::int32_t ActivitySession::requested_orientation() const noexcept { return impl_->orientation_request; }
const DisplayConfiguration &ActivitySession::display_configuration() const noexcept { return impl_->configuration; }
void ActivitySession::configure(const DisplayConfiguration &configuration, apk::ResourceTable resources) {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    if (!p.attached || !configuration.valid() || p.state == Lifecycle::failed || p.state == Lifecycle::destroyed)
        bad("CONFIGURATION", "Virtual display update requires a valid live framework session");
    if (!p.callback.empty() || !p.input_events.empty() || p.dispatching_drag || p.application_configuration_delivery)
        bad("CONFIGURATION_REENTRANT", "Configuration cannot interrupt a lifecycle or input callback");
    if (!resources.package_name().empty() && resources.package_name() != p.package)
        bad("PACKAGE", "Recomposed resources belong to another package");
    std::uint32_t changed = 0;
    if (configuration.orientation() != p.configuration.orientation()) changed |= 0x80u;
    if (configuration.screen_width_dp != p.configuration.screen_width_dp ||
        configuration.screen_height_dp != p.configuration.screen_height_dp) changed |= 0x400u;
    if (configuration.smallest_screen_width_dp != p.configuration.smallest_screen_width_dp) changed |= 0x800u;
    if (configuration.density_dpi != p.configuration.density_dpi) changed |= 0x1000u;
    // Prepare the guest storage before changing the selected resource table.
    p.runtime.set_host_state(p.configuration_object, std::make_unique<ConfigurationState>(configuration));
    p.configuration = configuration;
    p.resources = std::move(resources);
    if (!changed) return;
    p.cancel_input();
    ++p.metrics.view_revision;
    try { p.deliver_application_configuration(); }
    catch (...) { p.state = Lifecycle::failed; throw; }
    if (!p.activity) return;
    p.pending_configuration |= changed;
    // Defer Activity callbacks/recreation until it can become visible again.
    // Configuration/resource reads already describe the actual display.
    if (p.visible && !p.suspended) {
        try { p.apply_configuration_change(); }
        catch (...) { p.state = Lifecycle::failed; throw; }
    }
}
void ActivitySession::signal(WindowSignal signal) {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    if(!p.callback.empty() || p.dispatching_drag || p.application_configuration_delivery)
        bad("LIFECYCLE_REENTRANT","Cannot signal during lifecycle or Application configuration delivery");
    if (signal == WindowSignal::close) {
        close();
        return;
    }
    if (p.state == Lifecycle::empty || p.state == Lifecycle::destroyed || p.state == Lifecycle::failed)
        bad("LIFECYCLE_STATE", "Window event cannot target an inactive activity");
    if (signal == WindowSignal::focus_lost || signal == WindowSignal::deactivate ||
        signal == WindowSignal::minimize || signal == WindowSignal::suspend || signal == WindowSignal::close) {
        p.clear_soft_input_requests();
        p.retire_ime(true);
    }
    const auto deliver_focus = [&](bool focused) {
        if (p.focused != focused) {
            if (!focused)
                p.cancel_input();
            p.focused = focused;
            p.deliver("onWindowFocusChanged", p.state, "(Z)V", Value::word(focused));
        }
    };
    switch (signal) {
    case WindowSignal::activate:
        p.active = true;
        break;
    case WindowSignal::deactivate:
        p.cancel_input();
        p.active = false;
        break;
    case WindowSignal::minimize:
        p.cancel_input();
        p.visible = false;
        break;
    case WindowSignal::restore:
        p.visible = true;
        break;
    case WindowSignal::focus_gained:
    case WindowSignal::focus_lost: {
        p.window_focused = signal == WindowSignal::focus_gained;
        if (!p.window_focused || (!p.suspended && p.visible && p.active && p.state == Lifecycle::resumed))
            deliver_focus(p.window_focused);
        return;
    }
    case WindowSignal::suspend:
        p.cancel_input();
        p.suspended = true;
        deliver_focus(false);
        break;
    case WindowSignal::resume:
        p.suspended = false;
        break;
    case WindowSignal::close:
        return;
    }
    if (p.pending_configuration && p.visible && !p.suspended) {
        try { p.apply_configuration_change(); }
        catch (...) { p.state = Lifecycle::failed; throw; }
    }
    // Preserve actual visibility/activation during suspend. Window messages may
    // change those facts, but cannot restart the Activity before user resume.
    const bool visible = p.visible && !p.suspended;
    if ((!visible || !p.active) && p.state == Lifecycle::resumed)
        p.deliver("onPause", Lifecycle::paused);
    if (!visible && (p.state == Lifecycle::paused || p.state == Lifecycle::started))
        p.deliver("onStop", Lifecycle::stopped);
    if (visible && p.state == Lifecycle::stopped) {
        p.deliver("onRestart", Lifecycle::stopped);
        p.deliver("onStart", Lifecycle::started);
    }
    if (visible && p.active && (p.state == Lifecycle::started || p.state == Lifecycle::paused))
        p.deliver("onResume", Lifecycle::resumed);
    if (visible && p.active && p.state == Lifecycle::resumed && p.window_focused)
        deliver_focus(true);
}
bool ActivitySession::click(ObjectId object) {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    if (p.state != Lifecycle::resumed || !p.in_tree(object))
        return false;
    for (auto id = object; id; id = p.view(id).parent)
        if (!p.view(id).enabled)
            return false;
    return p.perform_click(object);
}
bool ActivitySession::focus(ObjectId object) {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    if (p.state != Lifecycle::resumed || p.pointer_target || !p.views.contains(object) || !p.enabled(object) ||
        !p.focusable(object))
        return false;
    // Match default_key's current Tab order. Impl::focus retires an old held
    // activation key without clicking/replaying it and advances view_revision.
    p.focus(object);
    p.reveal_focus(object);
    return true;
}
bool ActivitySession::toggle(ObjectId object) {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    if (p.state != Lifecycle::resumed || p.pointer_target || !p.views.contains(object) ||
        p.view(object).kind != ViewKind::checkbox || !p.enabled(object))
        return false;
    (void)p.perform_click(object);
    return true;
}
bool ActivitySession::scroll(ObjectId object, std::int32_t amount) {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    if (amount != -2 && amount != -1 && amount != 1 && amount != 2)
        bad("SCROLL", "Scroll amount must be a signed small or page step");
    if (p.state != Lifecycle::resumed || p.pointer_target || p.key_target || object != p.content ||
        !p.views.contains(object) || p.view(object).kind != ViewKind::scroll_view || !p.enabled(object) ||
        !p.view(object).scroll_range_y || !p.view(object).scroll_viewport_y) return false;
    const auto distance = std::abs(amount) == 2 ? p.view(object).scroll_viewport_y : std::max(1, p.virtual_pixels(16));
    p.dispatch_scroll_by(object, amount < 0 ? -distance : distance);
    return true;
}
bool ActivitySession::set_scroll_percent(ObjectId object, double percent) {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    if (!std::isfinite(percent) || percent < 0 || percent > 100)
        bad("SCROLL", "Scroll percent must be finite and between zero and 100");
    if (p.state != Lifecycle::resumed || p.pointer_target || p.key_target || object != p.content ||
        !p.views.contains(object) || p.view(object).kind != ViewKind::scroll_view || !p.enabled(object) ||
        !p.view(object).scroll_range_y || !p.view(object).scroll_viewport_y) return false;
    const auto position = static_cast<std::int32_t>(std::floor(p.view(object).scroll_range_y * percent / 100.0 + 0.5));
    p.dispatch_scroll_to(object, 0, position);
    return true;
}
bool ActivitySession::replace_text(ObjectId object, std::u16string_view text) {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    if (text.size() > editable_text_limit) bad("TEXT_LIMIT", "UIA replacement exceeds the Editable quota");
    if (p.state != Lifecycle::resumed || p.pointer_target || p.key_target || !p.views.contains(object) ||
        p.view(object).kind != ViewKind::edit_text || !p.enabled(object)) return false;
    const auto source = p.runtime.new_string(text);
    ManagedRoot source_root(p.runtime, source);
    // Android ACTION_SET_TEXT invokes the final wrapper/virtual two-argument
    // setter, then positions selection in the CURRENT text after callbacks.
    p.dispatch_set_text(object, source);
    const auto current = p.view_state(object).references[2].bits;
    ManagedRoot current_root(p.runtime, current);
    if (current) {
        const auto length = p.runtime.char_sequence(current).size();
        if (length) p.set_selection(current, static_cast<std::int32_t>(length), static_cast<std::int32_t>(length));
    }
    return true;
}
bool ActivitySession::set_selection(ObjectId object, std::int32_t start, std::int32_t end,
                                    std::u16string_view expected_text, std::uint64_t expected_buffer_revision,
                                    std::uint64_t expected_text_revision, SelectionOperation operation) {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    if (expected_text.size() > editable_text_limit || start < 0 || end < 0 ||
        static_cast<std::size_t>(start) > expected_text.size() ||
        static_cast<std::size_t>(end) > expected_text.size() || !expected_buffer_revision ||
        (operation != SelectionOperation::replace && operation != SelectionOperation::add &&
         operation != SelectionOperation::remove)) return false;
    if (p.state != Lifecycle::resumed || p.pointer_target || p.key_target || !p.views.contains(object) ||
        p.view(object).kind != ViewKind::edit_text || !p.enabled(object)) return false;
    ManagedRoot owner_root(p.runtime, object);
    const auto current = p.view_state(object).references[2].bits;
    ManagedRoot current_root(p.runtime, current);
    if (!current || p.runtime.object_type(current) != buffer_type) return false;
    // Equal text does not establish the same buffer or the same committed
    // document. Fence asynchronous positional edits against both identities.
    const auto &node = p.view(object);
    if (node.text_buffer_revision != expected_buffer_revision ||
        node.text_event_revision != expected_text_revision ||
        p.selection_state(current).text != expected_text) return false;
    if (operation != SelectionOperation::replace && start != end) {
        if (start > end) return false; // Host ranges are normalized intervals.
        const auto &selection = p.selection_state(current);
        const auto anchor = selection.start, active = selection.end;
        const bool current_selection = anchor >= 0 && active >= 0 && anchor != active &&
            static_cast<std::size_t>(anchor) <= expected_text.size() &&
            static_cast<std::size_t>(active) <= expected_text.size();
        if (!current_selection) {
            if (operation == SelectionOperation::remove) return true;
        } else {
            const auto first = std::min(anchor, active), last = std::max(anchor, active);
            if (operation == SelectionOperation::add) {
                if (end < first || start > last) return false; // A disjoint result needs multiple selections.
                const auto added_first = std::min(start, first), added_last = std::max(end, last);
                if (added_first == first && added_last == last) return true;
                // Extend toward the new outer edge. When both edges grow,
                // use the requested normalized range's forward direction.
                if (added_first < first && added_last == last) { start = added_last; end = added_first; }
                else { start = added_first; end = added_last; }
            } else {
                if (end <= first || start >= last) return true;
                if (start > first && end < last) return false; // Interior removal would split the selection.
                std::int32_t retained_first = first, retained_last = last;
                if (start <= first && end >= last) retained_first = retained_last = active;
                else if (start <= first) retained_first = end;
                else retained_last = start;
                start = anchor <= active ? retained_first : retained_last;
                end = anchor <= active ? retained_last : retained_first;
            }
        }
    }
    // No guest callback ran during computation. Commit once to the rooted
    // current Editable; onSelectionChanged remains authoritative afterward.
    p.set_selection(current, start, end);
    // onSelectionChanged may replace the buffer/tree; never write it back.
    return true;
}
bool ActivitySession::reveal_text_range(ObjectId object, std::uint64_t expected_revision,
                                      std::u16string_view expected_text, float top, float bottom, bool align_top) {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    if (!std::isfinite(top) || !std::isfinite(bottom) || top < 0 || bottom < top || bottom > 32768 ||
        expected_text.size() > editable_text_limit) return false;
    if (p.state != Lifecycle::resumed || p.pointer_target || p.key_target ||
        p.metrics.view_revision != expected_revision || !p.views.contains(object) ||
        p.view(object).kind != ViewKind::edit_text || !p.enabled(object)) return false;
    const auto root = p.content;
    if (!root || !p.views.contains(root) || p.view(root).kind != ViewKind::scroll_view ||
        p.view(root).children.size() != 1 || p.view(root).scroll_viewport_y <= 0 || p.view(root).scroll_range_y <= 0 ||
        !p.unscrolled_bounds.contains(object) || !p.unscrolled_bounds.contains(root) ||
        !p.unscrolled_bounds.contains(p.view(root).children.front())) return false;
    const auto natural = p.unscrolled_bounds.at(object);
    if (bottom > natural.height) return false;
    ManagedRoot owner_root(p.runtime, object), scroll_root(p.runtime, root);
    const auto current = p.view_state(object).references[2].bits;
    ManagedRoot current_root(p.runtime, current);
    if (!current || p.runtime.object_type(current) != buffer_type ||
        p.selection_state(current).text != expected_text || p.metrics.view_revision != expected_revision) return false;
    // The range is relative to this exact natural View rectangle, before the
    // current root ScrollView offset. No public getText or focus API runs here.
    const auto position = align_top ? p.virtual_pixels(natural.y + top)
                                   : p.virtual_pixels(natural.y + bottom) - p.view(root).scroll_viewport_y;
    const auto target = std::clamp(position, 0, p.view(root).scroll_range_y);
    p.dispatch_scroll_to(root, 0, target);
    // The real virtual scrollTo callback may replace the tree. Do not restore
    // the captured geometry, selection, focus or buffer after that callback.
    return true;
}
bool ActivitySession::ime_edit(ImeEditKind kind, ObjectId object, std::uint64_t token,
                               std::uint64_t expected_view_revision, std::u16string_view expected_text,
                               std::u16string_view text, std::int32_t cursor,
                               std::optional<ImeConversionTarget> conversion) {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    if (!object || !token || static_cast<unsigned>(kind) > static_cast<unsigned>(ImeEditKind::conversion) ||
        text.size() > editable_text_limit || expected_text.size() > editable_text_limit) return false;
    if ((conversion && kind != ImeEditKind::update && kind != ImeEditKind::conversion) ||
        (kind == ImeEditKind::conversion && (!conversion || cursor))) return false;
    if (conversion) {
        const bool none = conversion->start == -1 && conversion->end == -1;
        if ((!conversion->available && !none) || (!none && (conversion->start < 0 ||
            conversion->end <= conversion->start || static_cast<std::size_t>(conversion->end) > text.size()))) return false;
        if (conversion->unchanged_prefix == -1) {
            if (!conversion->previous_composition_sha256.empty()) return false;
        } else {
            const auto prefix = conversion->unchanged_prefix;
            if (kind != ImeEditKind::update || !conversion->available || prefix <= 0 ||
                static_cast<std::size_t>(prefix) > text.size() ||
                !Impl::ConversionObservation::utf16_boundary(text, static_cast<std::size_t>(prefix)) ||
                conversion->previous_composition_sha256.size() != 64 ||
                !std::all_of(conversion->previous_composition_sha256.begin(), conversion->previous_composition_sha256.end(),
                    [](char value) { return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'); })) return false;
        }
    }
    if (kind == ImeEditKind::begin) {
        if (!text.empty() || cursor || token <= p.last_ime_token || p.state != Lifecycle::resumed ||
            !p.window_focused || !p.focused || p.pointer_target || p.key_target || p.focused_view != object ||
            !p.views.contains(object) || p.view(object).kind != ViewKind::edit_text || !p.enabled(object) ||
            p.metrics.view_revision != expected_view_revision) return false;
        ManagedRoot owner_root(p.runtime, object);
        const auto buffer = p.view_state(object).references[2].bits;
        ManagedRoot buffer_root(p.runtime, buffer);
        if (!buffer || p.runtime.object_type(buffer) != buffer_type || p.selection_state(buffer).text != expected_text)
            return false;
        p.last_ime_token = token; // A declined native begin must not be replayed.
        p.retire_ime(true);
        const auto ready = [&] {
            return p.state == Lifecycle::resumed && p.window_focused && p.focused && !p.pointer_target && !p.key_target &&
                p.focused_view == object && p.views.contains(object) && p.view(object).kind == ViewKind::edit_text &&
                p.enabled(object) && p.view_state(object).references[2].bits == buffer &&
                p.metrics.view_revision == expected_view_revision && p.selection_state(buffer).text == expected_text;
        };
        if (!ready()) return false;
        if (!p.runtime.invoke_virtual_named(object, "onCheckIsTextEditor", "()Z").bits || !ready()) return false;
        const auto info = p.new_editor_info();
        ManagedRoot info_root(p.runtime, info);
        const std::array info_argument{Value::reference(info)};
        const auto connection = p.runtime.invoke_virtual_named(object, "onCreateInputConnection",
            "(Landroid/view/inputmethod/EditorInfo;)Landroid/view/inputmethod/InputConnection;", info_argument).bits;
        ManagedRoot connection_root(p.runtime, connection);
        if (!connection || !ready() || !p.runtime.assignable(connection, input_connection_type)) return false;
        const auto &profile = p.editor_state(info);
        if (profile.input_type != 0x20001 || profile.ime_options || profile.initial_caps ||
            profile.initial_start != p.selection_state(buffer).start || profile.initial_end != p.selection_state(buffer).end)
            return false; // Password/action/custom editor profiles are not silently treated as plain multiline.
        if (p.runtime.assignable(connection, base_input_connection_type)) {
            // BaseInputConnection has its own private fallback buffer. A native
            // View editor requires the actual virtual binding to this View.
            if (p.connection_editable(connection) != buffer || !ready()) return false;
        }
        auto binding = std::make_unique<ImeBinding>(p.runtime, object, connection, buffer, token);
        p.capture_ime(*binding);
        p.ime = std::move(binding);
        return true;
    }
    if (expected_view_revision || !expected_text.empty()) return false;
    if ((kind == ImeEditKind::update || kind == ImeEditKind::commit) &&
        (cursor < 0 || static_cast<std::size_t>(cursor) > text.size() ||
         (kind == ImeEditKind::commit && static_cast<std::size_t>(cursor) != text.size()))) return false;
    if ((kind == ImeEditKind::cursor && (!text.empty() || cursor < 0 ||
         static_cast<std::size_t>(cursor) > editable_text_limit)) ||
        ((kind == ImeEditKind::finish || kind == ImeEditKind::cancel) && (!text.empty() || cursor))) return false;
    if (!p.ime || p.ime->token != token || p.ime->owner.object != object) return false;
    if (!p.ime_content_matches(*p.ime, true)) { p.retire_ime(false); return false; }
    // A guest callback can retire the binding. These local roots/identities
    // outlive that retirement; no borrowed ImeBinding reference crosses it.
    const auto identity = p.ime.get();
    const auto connection = p.ime->connection.object, buffer = p.ime->buffer.object;
    const bool previously_owned = p.ime->owned_preedit;
    ManagedRoot owner_root(p.runtime, object), connection_root(p.runtime, connection), buffer_root(p.runtime, buffer);
    const auto current = [&] {
        return p.ime.get() == identity && p.ime && p.ime->token == token && p.ime_target(*p.ime, true);
    };
    const auto declined = [&] {
        if (p.ime.get() == identity) p.retire_ime(false);
        return false;
    };
    const auto invoke_text = [&](std::string_view name, std::u16string_view value) {
        const auto source = p.runtime.new_string(value);
        ManagedRoot source_root(p.runtime, source);
        const std::array arguments{Value::reference(source), Value::word(1)};
        return p.runtime.invoke_virtual_named(connection, name, "(Ljava/lang/CharSequence;I)Z", arguments).bits != 0;
    };
    const auto move_cursor = [&](std::int32_t offset) {
        const auto first = p.selection_state(buffer).composing_start, last = p.selection_state(buffer).composing_end;
        if (first < 0 || last < first || offset < 0 || offset > last - first) return false;
        const std::array arguments{Value::word(static_cast<std::uint32_t>(first + offset)),
                                   Value::word(static_cast<std::uint32_t>(first + offset))};
        return p.runtime.invoke_virtual_named(connection, "setSelection", "(II)Z", arguments).bits != 0;
    };
    const auto old_first = p.selection_state(buffer).composing_start;
    const auto old_last = p.selection_state(buffer).composing_end;
    const auto &old_node = p.view(object);
    ImeConversionTarget previous_target{old_node.conversion_available,
        old_node.conversion_start < 0 ? -1 : old_node.conversion_start - old_first,
        old_node.conversion_end < 0 ? -1 : old_node.conversion_end - old_first};
    std::optional<Impl::ConversionObservation> conversion_observation;
    if (kind == ImeEditKind::update) {
        conversion_observation.emplace(p, object, buffer);
        if (conversion) conversion_observation->native_prefix(*conversion, text);
    }
    try {
        if (kind == ImeEditKind::conversion) {
            if (old_first == -1 && old_last == -1) {
                // Result delivery can precede an attribute-only packet. It
                // must not turn a real completed composition into unknown.
                p.end_conversion(object, buffer);
                return true;
            }
            if (!previously_owned || old_first < 0 || old_last <= old_first) {
                p.unknown_conversion(object, buffer);
                return true; // Projection refusal never changes a valid editor binding.
            }
            p.apply_conversion(object, buffer, text, *conversion, previous_target);
            return true;
        }
        if (kind == ImeEditKind::cancel && !previously_owned) {
            p.retire_ime(false); // Never delete a guest's preexisting composition.
            return true;
        }
        if (kind == ImeEditKind::update) {
            p.ime->conversion_interrupted = false;
            if (!invoke_text("setComposingText", text) || !current()) return declined();
            if (static_cast<std::size_t>(cursor) != text.size() && (!move_cursor(cursor) || !current())) return declined();
            // The actual successful InputConnection operation's callback
            // output is authoritative, including same-buffer remapping. Only
            // edits between native commands invalidate the retained baseline.
            p.ime->owned_preedit = p.selection_state(buffer).composing_start >= 0;
        } else if (kind == ImeEditKind::commit) {
            if (!invoke_text("commitText", text) || !current()) return declined();
            p.ime->owned_preedit = false;
        } else if (kind == ImeEditKind::cursor) {
            if (!move_cursor(cursor) || !current()) return declined();
        } else if (kind == ImeEditKind::finish) {
            if (!previously_owned && p.selection_state(buffer).composing_start >= 0) return declined();
            if (!p.runtime.invoke_virtual_named(connection, "finishComposingText", "()Z").bits || !current()) return declined();
            p.ime->owned_preedit = false;
        } else if (kind == ImeEditKind::cancel) {
            if (p.selection_state(buffer).composing_start < 0 || !invoke_text("commitText", {}) || !current()) return declined();
            // An app callback may install new composition metadata. Do not
            // strip that unrelated replacement after deleting the owned text.
            if (p.selection_state(buffer).composing_start < 0)
                (void)p.runtime.invoke_virtual_named(connection, "finishComposingText", "()Z");
            if (p.ime.get() == identity) p.retire_ime(false);
            return true;
        }
        if (!current()) return declined();
        std::optional<ImeConversionTarget> proven_previous;
        if (conversion_observation) {
            proven_previous = conversion_observation->previous_target();
            if (!proven_previous && conversion_observation->legacy_unchanged &&
                conversion_observation->binding_current() && previous_target.available &&
                conversion_observation->text_revision == p.view(object).text_event_revision &&
                !p.ime->conversion_interrupted) proven_previous = previous_target;
        }
        else if (kind == ImeEditKind::update && previous_target.available &&
                 (!p.ime->conversion_interrupted || old_first < 0)) proven_previous = previous_target;
        const bool native_membership_changed = conversion_observation && conversion &&
            conversion_observation->membership_changed(*conversion);
        p.capture_ime(*p.ime); // Commit/finish retain the editor connection token.
        if (kind == ImeEditKind::update) {
            if (conversion) p.apply_conversion(object, buffer, text, *conversion, proven_previous, native_membership_changed);
            else if (p.selection_state(buffer).composing_start >= 0) p.unknown_conversion(object, buffer);
        } else if (kind == ImeEditKind::commit || kind == ImeEditKind::finish) {
            if (p.selection_state(buffer).composing_start < 0) p.end_conversion(object, buffer);
            else p.unknown_conversion(object, buffer); // A custom callback created another composition.
        }
        return true;
    } catch (...) {
        if (p.ime.get() == identity) p.retire_ime(false);
        throw; // Preserve the real callback failure; never retry or restore text.
    }
}
void ActivitySession::place_views(std::span<const ViewPlacement> placements) {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    if (placements.size() > 256 || p.state == Lifecycle::destroyed || p.state == Lifecycle::failed)
        bad("LAYOUT", "Layout cannot target an inactive or oversized view tree");
    std::set<ObjectId> seen;
    for (const auto &placement : placements) {
        (void)p.view(placement.view);
        const auto &r = placement.bounds;
        if (!seen.insert(placement.view).second || !std::isfinite(r.x) || !std::isfinite(r.y) ||
            !std::isfinite(r.width) || !std::isfinite(r.height) || r.width < 0 || r.height < 0 ||
            std::abs(r.x) > 32768 || std::abs(r.y) > 32768 || r.width > 32768 || r.height > 32768)
            bad("LAYOUT", "Invalid view rectangle");
    }
    const bool scrolling = p.content && p.view(p.content).kind == ViewKind::scroll_view;
    if (scrolling) {
        for (const auto &[id, node] : p.views) {
            (void)node;
            if (p.in_tree(id) && !seen.contains(id))
                bad("LAYOUT", "ScrollView placement requires the complete content subtree");
        }
        for (const auto &placement : placements)
            if (p.in_tree(placement.view) && (placement.bounds.x < 0 || placement.bounds.y < 0))
                bad("LAYOUT", "ScrollView natural geometry must use nonnegative content coordinates");
        const auto root = std::find_if(placements.begin(), placements.end(), [&](const auto &item) { return item.view == p.content; });
        if (root == placements.end() || root->bounds.x != 0 || root->bounds.y != 0)
            bad("LAYOUT", "Root ScrollView geometry must use the Activity origin");
        if (!p.view(p.content).children.empty()) {
            const auto child_id = p.view(p.content).children.front();
            const auto child = std::find_if(placements.begin(), placements.end(), [&](const auto &item) { return item.view == child_id; });
            if (child == placements.end() || child->bounds.x != 0 || child->bounds.y != 0 || child->bounds.width > root->bounds.width)
                bad("LAYOUT", "Root ScrollView requires a fitted-width child at its natural origin");
        }
    }
    p.unscrolled_bounds.clear();
    bool changed = false;
    for (const auto &placement : placements) {
        p.unscrolled_bounds.emplace(placement.view, placement.bounds);
        auto &r = p.view(placement.view).bounds;
        changed = changed || r != placement.bounds;
        r = placement.bounds;
    }
    if (changed)
        ++p.metrics.view_revision;
    p.apply_scroll_layout();
}
bool ActivitySession::pointer(const PointerInput &event) {
    impl_->check_text_edit_observer_idle();
    if (static_cast<unsigned>(event.action) > 3 || !std::isfinite(event.x) || !std::isfinite(event.y) ||
        std::abs(event.x) > 65536 || std::abs(event.y) > 65536 || event.pointer > 65535 ||
        (event.source != 0x2002 && event.source != 0x1002))
        bad("INPUT", "Invalid or unsupported pointer event");
    return impl_->dispatch_input({event, {}});
}
bool ActivitySession::key(const KeyInput &event) {
    impl_->check_text_edit_observer_idle();
    if (!valid_key_input(event))
        bad("INPUT", "Invalid or unsupported key event");
    return impl_->dispatch_input({{}, event});
}
void ActivitySession::close() {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    if(p.runtime.process_state()->exit_status()) {
        p.cleanup(false);return;
    }
    if(!p.callback.empty())bad("LIFECYCLE_REENTRANT","Cannot close during lifecycle delivery");
    if (!p.input_events.empty() || p.dispatching_drag)
        bad("INPUT_REENTRANT", "Cannot close during input dispatch");
    p.clear_soft_input_requests();
    p.retire_ime(true);
    p.runtime.close_tasks();
    p.runtime.close_main_callbacks();
    p.cancel_input();
    try {
        if (p.state == Lifecycle::resumed)
            p.deliver("onPause", Lifecycle::paused);
        if (p.state == Lifecycle::paused || p.state == Lifecycle::started)
            p.deliver("onStop", Lifecycle::stopped);
        if (p.state == Lifecycle::stopped || p.state == Lifecycle::created)
            p.deliver("onDestroy", Lifecycle::destroyed);
    } catch (...) {
        p.cleanup(false);
        throw;
    }
    p.cleanup();
    if (p.state != Lifecycle::failed)
        p.state = Lifecycle::destroyed;
}
Lifecycle ActivitySession::state() const noexcept { return impl_->state; }
ObjectId ActivitySession::activity() const noexcept { return impl_->activity; }
ObjectId ActivitySession::content_view() const noexcept { return impl_->content; }
const std::map<ObjectId, ViewState> &ActivitySession::views() const noexcept { return impl_->views; }
std::map<ObjectId, ViewState> ActivitySession::snapshot_views() const {
    impl_->check_text_edit_observer_idle();
    // Pure reads of the supported core CharSequences: no managed toString or
    // guest callback runs while preparing a host publication. Recheck mutable
    // StringBuilders before copying any description text.
    impl_->check_descriptions();
    auto result = impl_->views;
    const bool metadata_current = impl_->accessibility_cache_current();
    for (auto &[id, node] : result) {
        node.accessibility_collection.reset(); node.accessibility_collection_item.reset();
        node.accessibility_collection_owner = 0; node.accessibility_metadata_revision = 0;
        node.accessibility_node_provider_present = false;
        node.accessibility_actions = 0;
        node.accessibility_selection_required.reset();
        const auto metadata = impl_->accessibility_metadata.find(id);
        if (metadata_current && metadata != impl_->accessibility_metadata.end()) {
            node.accessibility_collection = metadata->second.collection;
            node.accessibility_collection_item = metadata->second.item;
            node.accessibility_collection_owner = metadata->second.owner;
            node.accessibility_metadata_revision = impl_->accessibility_attempt;
            node.accessibility_node_provider_present = metadata->second.node_provider_present;
            node.accessibility_actions = metadata->second.actions;
            node.accessibility_selection_required = metadata->second.selection_required;
        }
        node.focusable = impl_->focusable(id);
        const auto current = impl_->view_state(id).references[2].bits;
        if (current) node.text = impl_->runtime.char_sequence(current);
        if (node.kind == ViewKind::edit_text) {
            node.selection_start = impl_->editable_state(current).start;
            node.selection_end = impl_->editable_state(current).end;
            node.composing_start = impl_->editable_state(current).composing_start;
            node.composing_end = impl_->editable_state(current).composing_end;
            node.ime_token = impl_->ime && impl_->ime->owner.object == id &&
                impl_->ime_content_matches(*impl_->ime, true) ? impl_->ime->token : 0;
            if (node.composing_start == -1 && node.composing_end == -1) {
                node.conversion_available = true;
                node.conversion_start = node.conversion_end = -1;
            } else if (node.composing_start >= 0 && (!node.ime_token || !impl_->ime->owned_preedit)) {
                node.conversion_available = false;
                node.conversion_start = node.conversion_end = -1;
            }
            const auto &history = impl_->view_state(id).text_edit_events;
            for (const auto &event : history) node.text_edit_events.push_back(event);
            for (const auto &mutation : impl_->view_state(id).text_mutations)
                if (mutation.revision > node.text_mutation_base_revision)
                    node.text_mutations.push_back(mutation);
        }
        const auto description = impl_->view_state(id).references[1].bits;
        if (description) node.content_description = impl_->runtime.char_sequence(description);
    }
    return result;
}
const std::vector<std::string> &ActivitySession::events() const noexcept { return impl_->events; }
std::u16string_view ActivitySession::standard_output(bool error) const noexcept { return impl_->standard_output[error?1:0]; }
bool ActivitySession::write_standard_output(dex::ManagedRuntime &runtime,bool error,std::u16string_view text) {
    auto &p=*impl_;
    if(&runtime!=&p.runtime || !p.attached || text.size()>65536-p.output_characters)return false;
    p.standard_output[error?1:0].append(text);
    p.output_characters+=text.size();
    return true;
}
const FrameworkMetrics &ActivitySession::metrics() const noexcept { return impl_->metrics; }
const apk::ResourceTable &ActivitySession::resources() const noexcept { return impl_->resources; }
std::optional<dex::HostClass> ActivitySession::class_info(std::string_view descriptor) const {
    return class_metadata(descriptor);
}
std::optional<Value> ActivitySession::static_field(dex::ManagedRuntime &runtime, dex::Index index) {
    auto &p = *impl_;
    if (&runtime != &p.runtime || !p.attached)
        bad("STATE", "Framework field belongs to another or closed runtime");
    const auto &field = runtime.image().fields.at(index);
    if (runtime.image().types.at(field.owner) == clip_description_type &&
        runtime.image().types.at(field.type) == "Ljava/lang/String;" && field.name == "MIMETYPE_TEXT_PLAIN") {
        if (!p.plain_text_mime) p.plain_text_mime = p.own(runtime.new_string(u"text/plain"));
        return Value::reference(p.plain_text_mime);
    }
    if (runtime.image().types.at(field.owner) == "Landroid/content/Context;" &&
        runtime.image().types.at(field.type) == "Ljava/lang/String;" && field.name == "CLIPBOARD_SERVICE") {
        if (!p.clipboard_name) p.clipboard_name = p.own(runtime.new_string(u"clipboard"));
        return Value::reference(p.clipboard_name);
    }
    if (runtime.image().types.at(field.type) == "I")
        if (const auto action = drag_action_constant(runtime.image().types.at(field.owner), field.name)) return Value::word(*action);
    if (runtime.image().types.at(field.type) == "I")
        if (const auto value = accessibility_constant(runtime.image().types.at(field.owner), field.name)) return Value::word(*value);
    if (runtime.image().types.at(field.owner) == "Landroid/content/Context;" &&
        runtime.image().types.at(field.type) == "Ljava/lang/String;" && field.name == "INPUT_METHOD_SERVICE") {
        if (!p.input_method_name) p.input_method_name = p.own(runtime.new_string(u"input_method"));
        return Value::reference(p.input_method_name);
    }
    if (runtime.image().types.at(field.owner) == buffer_mode_type && runtime.image().types.at(field.type) == buffer_mode_type) {
        if (field.name == "NORMAL") return Value::reference(p.mode_object(0));
        if (field.name == "SPANNABLE") return Value::reference(p.mode_object(1));
        if (field.name == "EDITABLE") return Value::reference(p.mode_object(2));
    }
    if (runtime.image().types.at(field.owner) == "Landroid/os/Build$VERSION;" &&
        runtime.image().types.at(field.type) == "I" && field.name == "SDK_INT")
        return Value::word(compatibility_sdk);
    return {};
}
bool ActivitySession::method_is_static(const dex::DexImage &image, dex::Index method) const {
    return api_static(resolve(image, method));
}
std::optional<dex::HostMethod> ActivitySession::public_method(
    std::string_view owner, std::string_view name, std::span<const std::string> parameters) const {
    std::string current_owner(owner);
    for (unsigned depth = 0; depth < 256; ++depth) {
        owner = component_method_owner(preferences_owner(current_owner), name);
        for (const auto &api : api_registry()) {
            if (api.owner != owner || api.name != name || !public_api(api)) continue;
            const auto expected = api_parameters(api.signature);
            if (expected.size() != parameters.size() ||
                !std::equal(expected.begin(), expected.end(), parameters.begin())) continue;
            const auto close = api.signature.find(')');
            return dex::HostMethod{std::string(api.owner), std::string(api.name),
                                   std::string(api.signature.substr(close + 1)), expected,
                                   uri_api_flags(api).value_or(api_static(api) ? 9u :
                                         ((api.owner==preferences_type || api.owner==preferences_editor_type ||
                                           (api.owner==input_connection_type && api.name!="setImeConsumesInput") ||
                                           api.owner==editable_type || api.owner==watcher_type || api.owner=="Ljava/lang/CharSequence;" || api.owner=="Landroid/text/GetChars;" ||
                                           api.owner==checkable_type || api.owner==checked_listener_type ||
                                           api.owner==key_callback_type || api.owner==key_listener_type || api.owner==drag_listener_type ||
                                         api.owner==component_callbacks_type || api.owner==component_callbacks2_type ||
                                         api.owner=="Landroid/os/Parcelable;" ||
                                         (api.owner==lifecycle_type && !api.name.starts_with("onActivityPre") && !api.name.starts_with("onActivityPost")))?0x401u:
                                          (api.owner=="Landroid/view/KeyEvent;" && api.name=="dispatch") ||
                                          (api.owner=="Landroid/widget/TextView;" && api.name=="setText" &&
                                            (api.signature=="(Ljava/lang/CharSequence;)V" || api.signature=="(I)V")) ? 0x11u : 1u))};
        }
        if (owner == base_input_connection_type && name == "setImeConsumesInput") {
            current_owner = std::string(input_connection_type); // Genuine inherited interface default.
            continue;
        }
        const auto info = class_metadata(owner);
        if (!info || info->superclass.empty()) return {};
        current_owner = info->superclass;
    }
    bad("CLASS_LIMIT", "Reflected framework hierarchy exceeds limit");
}
std::optional<dex::HostField> ActivitySession::public_field(std::string_view owner, std::string_view name) const {
    if (owner == application_info_type && name == "packageName")
        return declared_field(package_item_type, name);
    return declared_field(owner, name);
}
std::optional<dex::HostField> ActivitySession::declared_field(std::string_view owner, std::string_view name) const {
    if (accessibility_constant(owner, name))
        return dex::HostField{std::string(owner), std::string(name), "I", 0x19u, true};
    if (owner == clip_description_type && name == "MIMETYPE_TEXT_PLAIN")
        return dex::HostField{std::string(owner), std::string(name), "Ljava/lang/String;", 0x19u, true};
    if (owner == "Landroid/content/Context;" && name == "CLIPBOARD_SERVICE")
        return dex::HostField{std::string(owner), std::string(name), "Ljava/lang/String;", 0x19u, true};
    if (drag_action_constant(owner, name))
        return dex::HostField{std::string(owner), std::string(name), "I", 0x19u, true};
    if (owner == "Landroid/content/Context;" && name == "INPUT_METHOD_SERVICE")
        return dex::HostField{std::string(owner), std::string(name), "Ljava/lang/String;", 0x19u, true};
    if (owner == editor_info_type) {
        if (name == "inputType" || name == "imeOptions" || name == "initialSelStart" || name == "initialSelEnd" ||
            name == "initialCapsMode" || name == "fieldId")
            return dex::HostField{std::string(owner), std::string(name), "I", 1, true};
        if (name == "packageName") return dex::HostField{std::string(owner), std::string(name), "Ljava/lang/String;", 1, true};
        if (name == "hintText" || name == "label")
            return dex::HostField{std::string(owner), std::string(name), "Ljava/lang/CharSequence;", 1, true};
    }
    if (owner == buffer_mode_type && (name == "NORMAL" || name == "SPANNABLE" || name == "EDITABLE"))
        return dex::HostField{std::string(owner), std::string(name), std::string(owner), 0x19u, true};
    // Exact Android 15 declarations; this is a deliberately partial schema.
    if (owner == configuration_type &&
        (name == "orientation" || name == "screenWidthDp" || name == "screenHeightDp" ||
         name == "smallestScreenWidthDp" || name == "densityDpi"))
        return dex::HostField{std::string(owner), std::string(name), "I", 1, true};
    if (owner == activity_thread_type && name == "mBoundApplication")
        return dex::HostField{std::string(owner), std::string(name), std::string(app_bind_type), 0, true};
    if (owner == app_bind_type && name == "appInfo")
        return dex::HostField{std::string(owner), std::string(name), std::string(application_info_type), 0, false};
    if (owner == application_info_type && name == "dataDir")
        return dex::HostField{std::string(owner), std::string(name), "Ljava/lang/String;", 1, true};
    if (owner == package_item_type && name == "packageName")
        return dex::HostField{std::string(owner), std::string(name), "Ljava/lang/String;", 1, true};
    if (owner == app_bind_type && name == "info")
        return dex::HostField{std::string(owner), std::string(name), std::string(loaded_apk_type), 0, false};
    if (owner == loaded_apk_type && name == "mDataDir")
        return dex::HostField{std::string(owner), std::string(name), "Ljava/lang/String;", 2, true};
    return {};
}
Value ActivitySession::read_reflected_field(dex::ManagedRuntime &runtime, const dex::HostField &field,
                                           dex::ObjectId receiver) {
    auto &p = *impl_;
    if (&runtime != &p.runtime || !p.attached)
        bad("STATE", "Framework field belongs to another or closed runtime");
    (void)runtime.assignable(p.base_context, "Landroid/content/Context;");
    const auto known = declared_field(field.owner, field.name);
    if (!known || known->type != field.type || known->flags != field.flags ||
        known->declaring_class_public != field.declaring_class_public)
        bad("FIELD_METADATA", "Reflected field does not match the framework declaration");
    if (field.owner == clip_description_type && field.name == "MIMETYPE_TEXT_PLAIN") {
        if (!p.plain_text_mime) p.plain_text_mime = p.own(runtime.new_string(u"text/plain"));
        return Value::reference(p.plain_text_mime);
    }
    if (field.owner == "Landroid/content/Context;" && field.name == "CLIPBOARD_SERVICE") {
        if (!p.clipboard_name) p.clipboard_name = p.own(runtime.new_string(u"clipboard"));
        return Value::reference(p.clipboard_name);
    }
    if (const auto action = drag_action_constant(field.owner, field.name)) return Value::word(*action);
    if (const auto value = accessibility_constant(field.owner, field.name)) return Value::word(*value);
    if (field.owner == "Landroid/content/Context;" && field.name == "INPUT_METHOD_SERVICE") {
        if (!p.input_method_name) p.input_method_name = p.own(runtime.new_string(u"input_method"));
        return Value::reference(p.input_method_name);
    }
    if (field.owner == editor_info_type) {
        const auto &state = p.editor_state(receiver);
        if (field.name == "inputType") return Value::word(std::bit_cast<std::uint32_t>(state.input_type));
        if (field.name == "imeOptions") return Value::word(std::bit_cast<std::uint32_t>(state.ime_options));
        if (field.name == "initialSelStart") return Value::word(std::bit_cast<std::uint32_t>(state.initial_start));
        if (field.name == "initialSelEnd") return Value::word(std::bit_cast<std::uint32_t>(state.initial_end));
        if (field.name == "initialCapsMode") return Value::word(std::bit_cast<std::uint32_t>(state.initial_caps));
        if (field.name == "fieldId") return Value::word(std::bit_cast<std::uint32_t>(state.field_id));
        return state.references[field.name == "packageName" ? 0 : field.name == "hintText" ? 1 : 2];
    }
    if (field.owner == buffer_mode_type)
        return Value::reference(p.mode_object(field.name == "NORMAL" ? 0 : field.name == "SPANNABLE" ? 1 : 2));
    if (field.owner == configuration_type) {
        if (receiver != p.configuration_object)
            bad("CONFIGURATION_RECEIVER", "Configuration is not this session's current Resources binding");
        const auto *state = dynamic_cast<const ConfigurationState *>(runtime.host_state(receiver));
        if (!state) bad("CONFIGURATION_STATE", "Configuration storage is unavailable");
        if (field.name == "orientation") return Value::word(state->value.orientation());
        if (field.name == "screenWidthDp") return Value::word(state->value.screen_width_dp);
        if (field.name == "screenHeightDp") return Value::word(state->value.screen_height_dp);
        if (field.name == "smallestScreenWidthDp") return Value::word(state->value.smallest_screen_width_dp);
        if (field.name == "densityDpi") return Value::word(state->value.density_dpi);
    }
    if (field.owner == activity_thread_type && receiver == p.activity_thread)
        return Value::reference(p.bound_application);
    if (field.owner == app_bind_type && receiver == p.bound_application)
        return Value::reference(field.name == "appInfo" ? p.app_info() : p.loaded_package);
    if (field.owner == package_item_type && p.application_info && receiver == p.application_info)
        return Value::reference(p.package_string());
    if ((field.owner == loaded_apk_type && receiver == p.loaded_package) ||
        (field.owner == application_info_type && p.application_info && receiver == p.application_info)) {
        p.require_private_root(); // Metadata never caches or expands storage authority.
        if (!p.data_directory)
            p.data_directory = p.own(runtime.new_string(p.logical_data_path()));
        return Value::reference(p.data_directory);
    }
    bad("FIELD_RECEIVER", "Reflected framework field requires this session's canonical binding");
}
void ActivitySession::write_reflected_field(dex::ManagedRuntime &runtime, const dex::HostField &field,
                                            dex::ObjectId receiver, Value value) {
    auto &p = *impl_;
    if (&runtime != &p.runtime || !p.attached) bad("STATE", "Framework field belongs to another or closed runtime");
    const auto known = declared_field(field.owner, field.name);
    if (!known || known->owner != field.owner || known->type != field.type || known->flags != field.flags ||
        known->declaring_class_public != field.declaring_class_public || field.owner != editor_info_type)
        bad("FIELD_WRITE_UNSUPPORTED", "Only declared mutable EditorInfo fields are supported");
    ManagedRoot receiver_root(runtime, receiver);
    auto next = std::make_unique<EditorInfoState>(p.editor_state(receiver));
    std::unique_ptr<ManagedRoot> value_root;
    if (field.type == "I") {
        if (value.kind != dex::ValueKind::word) bad("FIELD_ARGUMENT", "EditorInfo int field requires int bits");
        const auto number = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value.bits));
        if (field.name == "inputType") next->input_type = number;
        else if (field.name == "imeOptions") next->ime_options = number;
        else if (field.name == "initialSelStart") next->initial_start = number;
        else if (field.name == "initialSelEnd") next->initial_end = number;
        else if (field.name == "initialCapsMode") next->initial_caps = number;
        else next->field_id = number;
    } else {
        if (value.kind != dex::ValueKind::reference && !(value.kind == dex::ValueKind::word && !value.bits))
            bad("FIELD_ARGUMENT", "EditorInfo reference field requires a reference");
        value_root = std::make_unique<ManagedRoot>(runtime, value.bits);
        if (value.bits && !runtime.assignable(value.bits, field.type)) runtime.raise("Ljava/lang/IllegalArgumentException;");
        next->references[field.name == "packageName" ? 0 : field.name == "hintText" ? 1 : 2] = Value::reference(value.bits);
    }
    runtime.set_host_state(receiver, std::move(next));
}
Value ActivitySession::invoke_reflected(dex::ManagedRuntime &runtime, const dex::HostMethod &method,
                                       std::span<const Value> args) {
    const auto supported = public_method(method.owner, method.name, method.parameters);
    if (!supported || supported->owner != method.owner || supported->return_type != method.return_type ||
        supported->flags != method.flags)
        bad("API_METADATA", "Reflected method does not match the public framework declaration");
    std::string signature = "(";
    for (const auto &parameter : method.parameters) signature += parameter;
    signature += ")" + method.return_type;
    for (const auto &api : api_registry())
        if (api.owner == method.owner && api.name == method.name && api.signature == signature) {
            if (api.status == ApiStatus::not_started || api.status == ApiStatus::stub)
                bad("API_UNSUPPORTED", method.owner + "." + method.name + signature + " is not implemented");
            return invoke_api(runtime, api, args);
        }
    bad("API_UNSUPPORTED", method.owner + "." + method.name + signature + " is not implemented");
}
std::unique_ptr<dex::HostInputStream> ActivitySession::open_input_stream(dex::ManagedRuntime &runtime,
                                                                        std::u16string_view path) {
    auto &p=*impl_;
    if(&runtime!=&p.runtime || !p.attached || !p.input_lease->active)
        bad("INPUT_STREAM_STATE","Input source belongs to another or closed framework session");
    if(p.package.empty() || p.package.size()>1024 ||
       p.package.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.")!=std::string::npos)
        bad("PACKAGE","Package cannot identify a bounded logical process");
    if(path.empty() || path.size()>4096)
        runtime.raise("Ljava/io/FileNotFoundException;",u"Input path is outside Aether's supported logical namespaces");
    const auto pid=host::current_process_id();
    const auto proc=unicode("/proc/"+std::to_string(pid)+"/cmdline");
    const bool metadata=pid!=0 && path==proc;
    std::string leaf;
    if(!metadata) {
        const auto prefix=p.logical_data_path()+u"/files/";
        if(!path.starts_with(prefix))
            runtime.raise("Ljava/io/FileNotFoundException;",u"Input path is denied outside the held session namespace");
        const auto name=path.substr(prefix.size());
        if(name.empty() || name.size()>127 || name.front()==u'.' || name.back()==u'.' || name.find(u"..")!=std::u16string_view::npos ||
           !std::all_of(name.begin(),name.end(),[](char16_t c){return (c>=u'a' && c<=u'z') || (c>=u'0' && c<=u'9') || c==u'_' || c==u'-' || c==u'.';}))
            runtime.raise("Ljava/io/FileNotFoundException;",u"Input path is denied by the flat private-file namespace");
        leaf=narrow(name);p.require_private_root();
    }
    std::size_t slot=0;while(slot<p.input_lease->used.size() && p.input_lease->used[slot])++slot;
    if(slot==p.input_lease->used.size())bad("INPUT_STREAM_LIMIT","Session live input source limit of 16 exceeded");
    std::string snapshot;if(metadata){snapshot=p.package;snapshot.push_back(char{});}
    auto source=std::make_unique<SessionInput>(p.input_lease,slot,std::move(snapshot),metadata);
    p.input_lease->used[slot]=true;
    p.input_lease->document_slots[slot]=false;
    if(!metadata) {
        const auto opened=p.files->open(leaf,host::FileOpen{true});
        if(opened.error==host::FileError::denied) {
            ++p.metrics.denied_permissions;runtime.raise("Ljava/lang/SecurityException;",u"Private input file permission is denied");
        }
        if(opened.error==host::FileError::descriptor_limit || opened.error==host::FileError::quota)
            bad("INPUT_STREAM_LIMIT","Private input descriptor or storage quota exceeded");
        if(opened.error==host::FileError::missing && opened.value==-1)
            runtime.raise("Ljava/io/FileNotFoundException;",u"Private input file is missing");
        if(opened.error!=host::FileError::none)bad("INPUT_STREAM_UNAVAILABLE","Private input file open failed");
        if(opened.value<3 || opened.value>std::numeric_limits<int>::max()) {
            if(opened.value>=0 && opened.value<=std::numeric_limits<int>::max())(void)p.files->close(static_cast<int>(opened.value));
            bad("INPUT_STREAM_DESCRIPTOR","Private input returned an invalid descriptor");
        }
        source->descriptor(static_cast<int>(opened.value));
    }
    return source;
}
Value ActivitySession::invoke(dex::ManagedRuntime &runtime, dex::Index index, std::span<const Value> args) {
    return invoke_api(runtime, resolve(runtime.image(), index), args);
}
Value ActivitySession::invoke_api(dex::ManagedRuntime &runtime, const ApiSupport &api,
                                 std::span<const Value> args) {
    impl_->check_text_edit_observer_idle();
    auto &p = *impl_;
    if (&runtime != &p.runtime || !p.attached)
        bad("STATE", "Framework call belongs to another or closed runtime");
    ++p.metrics.api_calls;
    if (api.owner == accessibility_provider_type && api.name == "<init>")
        return Value::nothing(); // Abstract SDK base constructor only; provider methods remain unsupported.
    if (api.owner == accessibility_node_type || api.owner == accessibility_collection_type || api.owner == accessibility_item_type ||
        api.owner == accessibility_collection_builder_type)
        return p.accessibility_api(api, args);
    if (api.owner == clipboard_manager_type) return p.clipboard_api(api, args);
    if (api.owner == clip_data_type && api.name == "newPlainText") {
        if (args.size() != 2) bad("CLIPBOARD_ARGUMENT", "newPlainText requires label and text arguments");
        for (const auto argument : args)
            if (argument.kind != dex::ValueKind::reference && !(argument.kind == dex::ValueKind::word && !argument.bits))
                bad("CLIPBOARD_ARGUMENT", "newPlainText requires CharSequence references");
        if (!args[1].bits) runtime.raise("Ljava/lang/IllegalArgumentException;", u"Plain-text clip requires nonnull text");
        const std::u16string text(runtime.char_sequence(args[1].bits));
        return Value::reference(p.plain_clip(args[0].bits, text));
    }
    if (api.owner == drag_event_type || api.owner == clip_data_type || api.owner == clip_item_type ||
        api.owner == clip_description_type || api.owner == drag_permissions_type) return p.drag_api(api, args);
    if (api.owner == "Landroid/app/Activity;" && api.name == "requestDragAndDropPermissions") {
        if (args.size() != 2 || args[0].kind != dex::ValueKind::reference ||
            (args[1].kind != dex::ValueKind::reference && !(args[1].kind == dex::ValueKind::word && !args[1].bits)))
            bad("DRAG_ARGUMENT", "Drag permission request requires Activity and event references");
        return Value::reference(p.request_drag_permissions(args[0].bits, args[1].bits));
    }
    if (api.owner == input_method_manager_type) return p.soft_input_api(api, args);
    if (api.owner == component_type)
        return invoke_component(runtime, api.name, api.signature, args);
    if (api.owner == intent_type)
        return intent_api(runtime, api.name, api.signature, args);
    if (api.owner == uri_type || api.owner == abstract_uri_type || api.owner == string_uri_type)
        return invoke_uri(runtime, api.owner, api.name, api.signature, args);
    if (api.owner == intent_categories_type || api.owner == intent_categories_iterator_type)
        return invoke_intent_categories(runtime, api.owner, api.name, api.signature, args);
    if (api.owner == editor_info_type || api.owner == input_connection_type ||
        api.owner == base_input_connection_type || api.owner == editable_input_connection_type)
        return p.input_connection_api(api, args);
    if(api.owner==resolver_type)return p.resolver_api(api,args);
    if(api.name=="getContentResolver" && (api.owner=="Landroid/content/Context;" ||
            api.owner=="Landroid/content/ContextWrapper;" || api.owner==context_impl_type)) {
        if(args.size()!=1 || args[0].kind!=dex::ValueKind::reference)
            bad("CONTENT_ARGUMENT","getContentResolver requires its Context receiver");
        if(!args[0].bits)runtime.raise("Ljava/lang/NullPointerException;");
        p.context(args[0].bits);
        if(api.owner=="Landroid/content/ContextWrapper;")
            return runtime.invoke_virtual_named(p.base_context,"getContentResolver","()Landroid/content/ContentResolver;");
        return Value::reference(p.resolver_service());
    }
    if (api.owner == "Landroid/app/Activity;" && (api.name == "getIntent" || api.name == "setIntent")) {
        const bool set = api.name == "setIntent";
        if (args.size() != (set ? 2u : 1u))
            bad("ACTIVITY_INTENT", "Activity Intent method has invalid arguments");
        const auto receiver = args[0].bits;
        if (!receiver) runtime.raise("Ljava/lang/NullPointerException;");
        if (!runtime.assignable(receiver, "Landroid/app/Activity;"))
            bad("ACTIVITY_INTENT", "Intent receiver is not an Activity");
        const auto *current = dynamic_cast<const ActivityIntentState *>(runtime.host_state(receiver));
        if (!current) bad("ACTIVITY_INTENT", "Activity has no authenticated instance storage");
        if (!set) return current->references[0];
        if (args[1].bits && !runtime.assignable(args[1].bits, intent_type))
            bad("ACTIVITY_INTENT", "Activity Intent value is not an Intent");
        runtime.set_host_state(receiver, std::make_unique<ActivityIntentState>(args[1].bits));
        return Value::nothing();
    }
    if (api.owner == buffer_type || api.owner == editable_type || api.owner == "Landroid/text/Selection;" ||
        api.owner == "Ljava/lang/CharSequence;" || api.owner == "Landroid/text/GetChars;")
        return p.editable_api(api, args);
    if (api.owner == notification_builder_type || api.owner == notification_channel_type ||
        api.owner == notification_manager_type)
        return p.notification_api(api, args);
    if ((api.owner==application_type || api.owner=="Landroid/content/Context;" ||
         api.owner=="Landroid/content/ContextWrapper;" || api.owner=="Landroid/app/Activity;") &&
        (api.name=="registerComponentCallbacks" || api.name=="unregisterComponentCallbacks")) {
        if(args.size()!=2)
            bad("COMPONENT_ARGUMENT","Component registration requires receiver and callback");
        for(const auto value:args)
            if(value.kind!=dex::ValueKind::reference && !(value.kind==dex::ValueKind::word && !value.bits))
                bad("COMPONENT_ARGUMENT","Component registration requires references");
        if(!args[0].bits)runtime.raise("Ljava/lang/NullPointerException;");
        if((api.owner==application_type && args[0].bits!=p.application) ||
           (api.owner=="Landroid/app/Activity;" && args[0].bits!=p.activity) ||
           (api.owner=="Landroid/content/ContextWrapper;" && args[0].bits!=p.application && args[0].bits!=p.activity))
            bad("COMPONENT_OWNER","Component registration receiver is not this session's declared Context owner");
        if(args[1].bits && !runtime.assignable(args[1].bits,component_callbacks_type))
            bad("COMPONENT_ARGUMENT","Callback must implement ComponentCallbacks or ComponentCallbacks2");
        const auto owner=p.component_owner(args[0].bits);
        p.change_components(owner,args[1].bits,api.name=="registerComponentCallbacks");
        return Value::nothing();
    }
    if(api.owner==application_type && api.name=="onConfigurationChanged") {
        if(args.size()!=2)
            bad("COMPONENT_ARGUMENT","Application configuration callback requires receiver and Configuration");
        for(const auto value:args)
            if(value.kind!=dex::ValueKind::reference && !(value.kind==dex::ValueKind::word && !value.bits))
                bad("COMPONENT_ARGUMENT","Application configuration callback requires references");
        if(!args[0].bits || !args[1].bits)runtime.raise("Ljava/lang/NullPointerException;");
        if(args[0].bits!=p.application)
            bad("APPLICATION","Configuration callback receiver is not this session's Application");
        if(!runtime.assignable(args[1].bits,configuration_type))
            bad("COMPONENT_ARGUMENT","Application configuration callback argument is not a Configuration");
        p.dispatch_components(p.application,args[1].bits);
        return Value::nothing();
    }
    if (api.owner == "Landroid/content/res/Resources;" && api.name == "getConfiguration") {
        if (args.size() != 1 || args[0].bits != p.resource_object)
            bad("CONFIGURATION_RECEIVER", "getConfiguration requires this session's Resources");
        return Value::reference(p.configuration_object);
    }
    if (api.owner == "Landroid/app/Activity;" &&
        (api.name == "getRequestedOrientation" || api.name == "setRequestedOrientation")) {
        const bool set = api.name == "setRequestedOrientation";
        if (args.size() != (set ? 2U : 1U) ||
            (args[0].kind != dex::ValueKind::reference &&
             !(args[0].kind == dex::ValueKind::word && !args[0].bits)) ||
            (set && args[1].kind != dex::ValueKind::word))
            bad("ORIENTATION_ARGUMENT", "Orientation API requires this Activity and an exact int request");
        if (!p.activity || args[0].bits != p.activity)
            bad("ACTIVITY", "Orientation request belongs to another or inactive Activity");
        if (!set)
            return Value::word(std::bit_cast<std::uint32_t>(p.orientation_request));
        const auto requested = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[1].bits));
        if (requested != -1 && requested != 0 && requested != 1)
            runtime.raise("Ljava/lang/UnsupportedOperationException;",
                          u"AETHER_ANDROID_ORIENTATION_UNSUPPORTED: virtual display supports only unspecified(-1), landscape(0) and portrait(1)");
        if (requested != p.orientation_request) {
            p.cancel_input();
            p.orientation_request = requested;
            ++p.metrics.view_revision;
        }
        return Value::nothing();
    }
    if (api.owner == preferences_type || api.owner == preferences_editor_type) {
        if (!p.preferences) bad("PREFS_STATE", "Preferences receiver has no authenticated session store");
        const auto before = p.preferences->denials();
        struct Denials {
            PreferencesService &service; FrameworkMetrics &metrics; std::uint64_t before;
            ~Denials() { metrics.denied_permissions += service.denials() - before; }
        } denials{*p.preferences, p.metrics, before};
        const auto result = p.preferences->invoke(api.owner, api.name, api.signature, args);
        if (result) return *result;
        bad("API_UNSUPPORTED", "SharedPreferences method is outside the supported profile");
    }
    if(api.owner==application_type && (api.name=="registerActivityLifecycleCallbacks" || api.name=="unregisterActivityLifecycleCallbacks")) {
        if(args.size()!=2)bad("LIFECYCLE_SIGNATURE","Lifecycle registration requires receiver and listener");
        for(const auto value:args)
            if(value.kind!=dex::ValueKind::reference && !(value.kind==dex::ValueKind::word && !value.bits))
                bad("LIFECYCLE_ARGUMENT","Lifecycle registration requires reference arguments");
        if(args[1].bits && !runtime.assignable(args[1].bits,lifecycle_type))
            bad("LIFECYCLE_ARGUMENT","Listener does not implement ActivityLifecycleCallbacks");
    }
    if (api.owner == application_type && api.name == "getProcessName")
        return Value::reference(p.package_string());
    if (api.owner == factory_type) {
        if (args[0].bits != p.component_factory || !p.component_factory)
            bad("FACTORY_STATE", "Component factory is not this session's declared factory");
        if (api.name == "<init>") {
            if (p.factory_constructed || p.application_stage != Impl::ApplicationStage::constructing || p.application)
                bad("FACTORY_STATE", "Component factory base constructor is inactive or repeated");
            p.factory_constructed = true;
            return Value::nothing();
        }
        if (!p.factory_constructed || args[1].bits != runtime.class_loader())
            bad("FACTORY_CLASS_LOADER_UNSUPPORTED", "Factory requires the canonical held class-space loader");
        if (api.name == "instantiateClassLoader") {
            if (!p.selecting_loader || args[2].bits != p.application_info)
                bad("FACTORY_STATE", "Class loader selection requires this session's ApplicationInfo");
            return args[1];
        }
        if (api.name == "instantiateApplication") {
            if (!p.factory_application_active || args[1].bits != p.selected_loader || !args[2].bits ||
                runtime.string(args[2].bits) != p.component_name(p.application_type_name))
                bad("FACTORY_STATE", "Application factory call is outside the declared component binding");
            return Value::reference(p.construct_application());
        }
        if (api.name == "instantiateActivity") {
            if (!p.factory_activity_active || args[1].bits != p.selected_loader || !args[2].bits ||
                runtime.string(args[2].bits) != p.component_name(p.activity_type) || args[3].bits != p.launch_intent)
                bad("FACTORY_STATE", "Activity factory call is outside the actual launch binding");
            // The passed Intent is mutable app data. Its component is not
            // authority to select a different executable or class loader.
            return Value::reference(p.construct_activity());
        }
    }
    if(api.owner=="Ljava/lang/System;" && api.name=="nanoTime") {
        if(api.signature!="()J")bad("API_UNSUPPORTED","Only System.nanoTime()J is supported");
        if(!args.empty())bad("API_ARGUMENT","System.nanoTime takes no arguments");
        host::MonotonicTime time{};
        const auto status=p.time?p.time->read_uptime(time):host::TimeStatus::unavailable;
        if(status==host::TimeStatus::denied) {
            ++p.metrics.denied_permissions;
            runtime.raise("Ljava/lang/SecurityException;",u"Aether clock permission is denied");
        }
        if(status!=host::TimeStatus::ok)bad("TIME_UNAVAILABLE","Sleep-excluding uptime service is unavailable");
        // Java nanoTime has an arbitrary origin and a wrapping signed-long bit
        // pattern. Unsigned arithmetic preserves all64 bits without C++ signed
        // overflow, including negative Java values and wrap at long boundaries.
        if(time.nanoseconds>=1'000'000'000)
            bad("TIME_INVALID","Uptime nanoseconds are not normalized");
        return Value::wide(time.seconds*1'000'000'000+time.nanoseconds);
    }
    if (api.owner == "Ljava/lang/System;" && api.name == "currentTimeMillis") {
        host::EpochTime time{};
        const auto status = p.time ? p.time->read_wall_time(time) : host::TimeStatus::unavailable;
        if (status == host::TimeStatus::denied) {
            ++p.metrics.denied_permissions;
            runtime.raise("Ljava/lang/SecurityException;", u"Aether wall-clock permission is denied");
        }
        if (status != host::TimeStatus::ok)
            bad("TIME_UNAVAILABLE", "UTC epoch wall-clock service is unavailable");
        constexpr auto maximum = std::numeric_limits<std::int64_t>::max();
        constexpr auto minimum = std::numeric_limits<std::int64_t>::min();
        if (time.nanoseconds >= 1'000'000'000)
            bad("TIME_INVALID", "Wall-clock nanoseconds are out of range");
        const auto fraction = static_cast<std::int64_t>(time.nanoseconds / 1'000'000);
        std::int64_t millis = 0;
        if (time.seconds < minimum / 1000) {
            // The final negative boundary second can fit after its positive
            // fractional milliseconds are added; avoid overflowing the product.
            constexpr auto threshold = 1000 + minimum % 1000;
            if (time.seconds != minimum / 1000 - 1 || fraction < threshold)
                bad("TIME_INVALID", "Wall-clock milliseconds do not fit a signed Java long");
            millis = minimum + (fraction - threshold);
        } else {
            if (time.seconds > (maximum - fraction) / 1000)
                bad("TIME_INVALID", "Wall-clock milliseconds do not fit a signed Java long");
            millis = time.seconds * 1000 + fraction;
        }
        return Value::wide(std::bit_cast<std::uint64_t>(millis));
    }
    if (api.owner == "Landroid/text/TextUtils;") {
        if (api.name == "isEmpty" && api.signature == "(Ljava/lang/CharSequence;)Z") {
            if (args.size()!=1 || args[0].kind!=dex::ValueKind::reference)
                bad("API_ARGUMENT", "TextUtils.isEmpty requires one CharSequence reference");
            if (!args[0].bits) return Value::word(1);
            if (!runtime.assignable(args[0].bits,"Ljava/lang/CharSequence;"))
                bad("API_ARGUMENT", "TextUtils.isEmpty requires a CharSequence");
            const auto length=runtime.invoke_virtual_named(args[0].bits,"length","()I");
            return Value::word(length.bits==0);
        }
        const auto first = args[0].bits, second = args[1].bits;
        if (first == second)
            return Value::word(1);
        if (!first || !second)
            return Value::word(0);
        // These views do not allocate or call guest code. Other CharSequence
        // implementations remain explicit unsupported rather than using Object.equals.
        const auto first_text = std::u16string(runtime.char_sequence(first));
        return Value::word(first_text == runtime.char_sequence(second));
    }
    if (api.owner == activity_thread_type) {
        if (api.name == "currentApplication")
            return Value::reference(p.application_published ? p.application : 0);
        if (api.name == "currentActivityThread")
            return Value::reference(p.current_activity_thread());
        if (api.name == "getProcessName") {
            if (args.size() != 1)
                bad("API_ARGUMENT", "ActivityThread.getProcessName requires its receiver");
            if (!p.activity_thread || args[0].kind != dex::ValueKind::reference ||
                args[0].bits != p.activity_thread)
                bad("ACTIVITY_THREAD", "ActivityThread is not this session's canonical dispatcher");
            // The current session binds only the manifest package's default
            // process, before Application construction/publication.
            return Value::reference(p.package_string());
        }
    }
    if(api.owner==lifecycle_type) {
        if(api.name.starts_with("onActivityPre") || api.name.starts_with("onActivityPost"))return Value::nothing();
        bad("ABSTRACT_METHOD","Classic activity lifecycle callback requires an actual managed implementation");
    }
    if(api.owner==component_callbacks_type || api.owner==component_callbacks2_type)
        bad("ABSTRACT_METHOD","Component callback requires an actual managed implementation");
    if (api.owner == application_type) {
        if (args[0].bits != p.application || !p.application)
            bad("APPLICATION", "Application is not bound to this session");
        if(api.name=="registerActivityLifecycleCallbacks" || api.name=="unregisterActivityLifecycleCallbacks") {
            p.change_lifecycle(args[1].bits,api.name=="registerActivityLifecycleCallbacks");return Value::nothing();
        }
        if (api.name == "<init>") {
            if (p.application_stage != Impl::ApplicationStage::constructing || p.application_constructed)
                bad("APPLICATION_STATE", "Application base constructor is not active or already completed");
            p.application_constructed = true;
            return Value::nothing();
        }
        if (api.name == "onCreate") {
            if (p.application_stage != Impl::ApplicationStage::creating)
                bad("APPLICATION_STATE", "Application onCreate occurs outside application initialization");
            return Value::nothing(); // Android's base callback has no body; no super-call requirement.
        }
    }
    if (api.owner == "Landroid/content/ContextWrapper;") {
        const auto receiver = args[0].bits;
        if (api.name == "getBaseContext") {
            if (receiver == p.application && p.application)
                return Value::reference(p.application_attached ? p.base_context : 0);
            if (receiver == p.activity && p.activity)
                return Value::reference(p.activity_attached ? p.base_context : 0);
            bad("CONTEXT", "ContextWrapper is not bound to this session");
        }
        if (api.name == "attachBaseContext") {
            if (receiver != p.application || !p.application)
                bad("CONTEXT", "Application is not bound to this session");
            if (p.application_attached)
                runtime.raise("Ljava/lang/IllegalStateException;", u"Base Context is already attached");
            if (p.application_stage != Impl::ApplicationStage::attaching)
                bad("APPLICATION_STATE", "Base Context attachment is outside application initialization");
            if (args[1].bits != p.base_context)
                bad("CONTEXT", "Application must attach its supplied session base Context");
            p.application_attached = true;
            return Value::nothing();
        }
    }
    if (api.owner == file_type) {
        const auto receiver = args[0].bits;
        if (api.name == "<init>") {
            if (runtime.host_state(receiver))
                bad("FILE_STATE", "File constructor invoked twice");
            if (api.signature == "(Ljava/lang/String;)V") {
                const auto supplied = runtime.string(args[1].bits); // Null is a Java NPE.
                if (supplied.size() > 1024)
                    bad("FILE_PATH_UNSUPPORTED", "Logical File metadata exceeds its 1024-unit path bound");
                std::u16string path;
                path.reserve(supplied.size());
                for (const auto character : supplied)
                    if (character != u'/' || path.empty() || path.back() != u'/') path.push_back(character);
                if (path.size() > 1 && path.back() == u'/') path.pop_back();
                const auto data_root = p.logical_data_path();
                const auto root = data_root + u"/files";
                auto kind = PrivateFileKind::lexical_path;
                std::string relative;
                if (path == root) kind = PrivateFileKind::root_alias;
                else if (path.starts_with(root + u"/")) {
                    auto remaining = std::u16string_view(path).substr(root.size() + 1);
                    unsigned depth = 0;
                    bool valid = true;
                    while (true) {
                        const auto slash = remaining.find(u'/');
                        if (!private_file_segment(remaining.substr(0, slash)) || ++depth > 16) { valid = false; break; }
                        if (slash == std::u16string_view::npos) break;
                        remaining.remove_prefix(slash + 1);
                    }
                    if (valid) {
                        kind = PrivateFileKind::relative_path;
                        relative = narrow(std::u16string_view(path).substr(root.size() + 1));
                    }
                } else if (path.starts_with(data_root + u"/") &&
                           private_file_segment(std::u16string_view(path).substr(data_root.size() + 1))) {
                    kind = PrivateFileKind::data_path;
                    relative = narrow(std::u16string_view(path).substr(data_root.size() + 1));
                }
                runtime.set_host_state(receiver, std::make_unique<PrivateFileState>(
                    std::move(path), std::move(relative), p.base_context, kind));
                return Value::nothing();
            }
            if (!args[2].bits)
                runtime.raise("Ljava/lang/NullPointerException;");
            const auto child = runtime.string(args[2].bits);
            const auto data_root = p.logical_data_path();
            const auto root = data_root + u"/files";
            std::u16string parent;
            if (api.signature == "(Ljava/io/File;Ljava/lang/String;)V") {
                if (!args[1].bits)
                    bad("FILE_PATH_UNSUPPORTED", "Relative File paths are not supported");
                const auto *parent_state = dynamic_cast<const PrivateFileState *>(runtime.host_state(args[1].bits));
                if (!parent_state || parent_state->context() != p.base_context ||
                    (parent_state->kind == PrivateFileKind::canonical_root && args[1].bits != p.files_directory))
                    bad("FILE_STATE", "File parent is not bound to this session");
                parent = parent_state->path;
            } else {
                const auto supplied = args[1].bits ? runtime.string(args[1].bits) : std::u16string_view{};
                if (supplied.size() > 1024)
                    bad("FILE_PATH_UNSUPPORTED", "Private-file metadata exceeds its 1024-unit path bound");
                parent = supplied;
            }
            if (parent == data_root && child == u"files" && api.signature == "(Ljava/lang/String;Ljava/lang/String;)V") {
                runtime.set_host_state(receiver, std::make_unique<PrivateFileState>(
                    root, "", p.base_context, PrivateFileKind::root_alias));
                return Value::nothing();
            }
            if (!private_file_segment(child) || (parent != root && !parent.starts_with(root + u"/")))
                bad("FILE_PATH_UNSUPPORTED", "File constructor requires a bounded logical private-files path");
            std::size_t depth = 1;
            if (parent != root) {
                auto remaining = std::u16string_view(parent).substr(root.size() + 1);
                while (true) {
                    const auto slash = remaining.find(u'/');
                    if (!private_file_segment(remaining.substr(0, slash)) || ++depth > 16)
                        bad("FILE_PATH_UNSUPPORTED", "Private-file metadata exceeds its segment or depth bound");
                    if (slash == std::u16string_view::npos) break;
                    remaining.remove_prefix(slash + 1);
                }
            }
            if (parent.size() > 1024 || child.size() + 1 > 1024 - parent.size())
                bad("FILE_PATH_UNSUPPORTED", "Private-file metadata exceeds its 1024-unit path bound");
            const auto path = parent + u"/" + std::u16string(child);
            runtime.set_host_state(receiver, std::make_unique<PrivateFileState>(
                path, narrow(std::u16string_view(path).substr(root.size() + 1)), p.base_context, PrivateFileKind::relative_path));
            return Value::nothing();
        }
        const auto *state = dynamic_cast<const PrivateFileState *>(runtime.host_state(receiver));
        if (!state || state->context() != p.base_context ||
            (state->kind == PrivateFileKind::canonical_root && receiver != p.files_directory))
            bad("FILE_STATE", "File is not bound to this session's logical private-files namespace");
        if (api.name == "getAbsolutePath" && (state->path.empty() || state->path.front() != u'/'))
            bad("FILE_PATH_UNSUPPORTED", "Relative absolute-path resolution requires a logical working directory");
        if (api.name == "getPath" || api.name == "getAbsolutePath" || api.name == "toString")
            return Value::reference(runtime.new_string(state->path));
        if (api.name == "getName")
            return Value::reference(runtime.new_string(state->path.substr(state->path.find_last_of(u'/') + 1)));
        if (api.name == "getParent") {
            const auto slash = state->path.find_last_of(u'/');
            if (slash == std::u16string::npos || state->path == u"/") return Value::reference(0);
            return Value::reference(runtime.new_string(state->path.substr(0, slash ? slash : 1)));
        }
        if (api.name == "isAbsolute")
            return Value::word(!state->path.empty() && state->path.front() == u'/');
        if(api.name=="mkdir") {
            if(state->kind!=PrivateFileKind::canonical_root && state->kind!=PrivateFileKind::root_alias)
                bad("FILE_PATH_UNSUPPORTED","Directory creation outside the verified existing private root is not implemented");
            p.require_private_root();
            return Value::word(0); // The verified directory already exists; nothing was created.
        }
        if (api.name == "exists" || api.name == "isDirectory" || api.name == "isFile") {
            if (state->kind == PrivateFileKind::lexical_path)
                bad("FILE_PATH_UNSUPPORTED", "File observation has no backing in this logical namespace");
            p.require_private_root();
            if (state->kind == PrivateFileKind::data_path) {
                const auto result = p.files->observe_data_file(state->relative);
                if (result.error == host::FileError::missing && result.value == -1) return Value::word(0);
                if (result.error == host::FileError::denied) {
                    ++p.metrics.denied_permissions;
                    runtime.raise("Ljava/lang/SecurityException;", u"Aether app-data file observation is denied");
                }
                if (result.error != host::FileError::none || result.value != 1)
                    bad("FILE_OBSERVATION_UNAVAILABLE", "App-data file observation failed");
                return Value::word(api.name != "isDirectory");
            }
            if (state->kind != PrivateFileKind::relative_path)
                return Value::word(api.name != "isFile");
            if (state->relative.find('/') != std::string::npos) {
                ++p.metrics.denied_permissions;
                runtime.raise("Ljava/lang/SecurityException;", u"Aether private-files capability permits flat files only");
            }
            const auto result = p.files->open(state->relative, host::FileOpen{true});
            if (result.error == host::FileError::denied) {
                ++p.metrics.denied_permissions;
                runtime.raise("Ljava/lang/SecurityException;", u"Aether private-file observation is denied");
            }
            if (result.error == host::FileError::missing && result.value == -1)
                return Value::word(0);
            if (result.error != host::FileError::none)
                bad("FILE_OBSERVATION_UNAVAILABLE", "Broker private-file observation failed");
            if (result.value < 3 || result.value > std::numeric_limits<int>::max())
                bad("FILE_DESCRIPTOR_INVALID", "Broker returned an invalid private-file descriptor");
            const auto closed = p.files->close(static_cast<int>(result.value));
            if (closed.error == host::FileError::denied) {
                ++p.metrics.denied_permissions;
                runtime.raise("Ljava/lang/SecurityException;", u"Aether private-file close is denied");
            }
            if (closed.error != host::FileError::none || closed.value != 0)
                bad("FILE_CLOSE_UNAVAILABLE", "Broker private-file observation could not close its descriptor");
            return Value::word(api.name != "isDirectory");
        }
    }
    if (api.owner == bundle_type || api.owner == base_bundle_type)
        return invoke_bundle(runtime, api.owner, api.name, api.signature, args);
    if (api.owner == looper_type && (api.name == "getMainLooper" || api.name == "myLooper"))
        return Value::reference(api.name == "myLooper" && !runtime.is_main_thread() ? 0 : p.main_loop());
    if (api.owner == "Landroid/content/Context;" && api.name == "getMainLooper") {
        p.context(args[0].bits);
        return Value::reference(p.main_loop());
    }
    if (api.owner == looper_type && (api.name == "isCurrentThread" || api.name == "getThread")) {
        if (!p.main_looper || args[0].bits != p.main_looper)
            bad("LOOPER_STATE", "Looper is not attached to this runtime's main event loop");
        if (api.name == "getThread")
            return Value::reference(runtime.main_thread());
        return Value::word(runtime.is_main_thread() ? 1 : 0);
    }
    if (api.owner == handler_type) {
        const auto receiver = args[0].bits;
        if (api.name == "<init>") {
            if (runtime.host_state(receiver))
                bad("HANDLER_STATE", "Handler constructor invoked twice");
            if (api.signature == "()V" && !runtime.is_main_thread())
                runtime.raise("Ljava/lang/RuntimeException;");
            const auto looper = api.signature == "()V" ? p.main_loop() : args[1].bits;
            if (!looper)
                runtime.raise("Ljava/lang/NullPointerException;");
            if (looper != p.main_looper)
                bad("HANDLER_LOOPER", "Handler requires this runtime's attached main Looper");
            runtime.set_host_state(receiver, std::make_unique<HandlerState>(looper));
            return Value::nothing();
        }
        const auto *state = dynamic_cast<const HandlerState *>(runtime.host_state(receiver));
        if (!state || !p.main_looper || state->looper() != p.main_looper)
            bad("HANDLER_STATE", "Handler is not initialized for this runtime's main event loop");
        if (api.name == "getLooper")
            return Value::reference(state->looper());
    }
    const bool process_start=api.owner=="Landroid/os/Process;" && api.name=="getStartUptimeMillis";
    if (api.owner == "Landroid/os/SystemClock;" || process_start) {
        if (!args.empty())
            bad("ARGUMENTS", "Clock query takes no arguments");
        host::MonotonicTime time{};
        const auto status = !p.time ? host::TimeStatus::unavailable
                          : process_start ? p.time->read_process_start_uptime(time)
                          : api.name == "uptimeMillis" ? p.time->read_uptime(time)
                          : api.name == "elapsedRealtime" ? p.time->read_elapsed_realtime(time)
                          : p.time->read_thread_cpu(time);
        if (status == host::TimeStatus::denied) {
            ++p.metrics.denied_permissions;
            runtime.raise("Ljava/lang/SecurityException;", u"Aether clock permission is denied");
        }
        if (status != host::TimeStatus::ok)
            bad("TIME_UNAVAILABLE", std::string(api.name) + " clock service is unavailable");
        constexpr auto maximum = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
        if (time.nanoseconds >= 1'000'000'000 ||
            time.seconds > (maximum - time.nanoseconds / 1'000'000) / 1000)
            bad("TIME_INVALID", "SystemClock value does not fit nonnegative Java milliseconds");
        if(api.name=="currentThreadTimeMillis")
            return Value::wide(runtime.logical_thread_cpu_millis(time.seconds,time.nanoseconds));
        return Value::wide(time.seconds * 1000 + time.nanoseconds / 1'000'000);
    }
    const auto receiver = args[0].bits;
    const auto name = api.name;
    if (api.owner == "Landroid/app/Activity;") {
        if (receiver != p.activity)
            bad("ACTIVITY", "Activity is not attached to this application");
        if (name == "<init>")
            return Value::nothing();
        if (name == "isChangingConfigurations") return Value::word(p.changing_configuration != 0);
        if (name == "getChangingConfigurations") return Value::word(p.changing_configuration);
        if (name == "dispatchTouchEvent" || name == "dispatchKeyEvent") {
            const auto found = p.input_events.find(args[1].bits);
            if (found == p.input_events.end())
                bad("INPUT", "Input event has expired or belongs to another session");
            if (name == "dispatchTouchEvent" && found->second.pointer)
                return Value::word(p.default_pointer(*found->second.pointer));
            if (name == "dispatchKeyEvent" && found->second.key)
                return Value::word(p.default_key(args[1].bits));
            bad("INPUT", "Input event type does not match dispatch method");
        }
        if (name == "onKeyDown" || name == "onKeyUp") {
            (void)p.key_event(args[2].bits);
            if (args[1].bits == 4)
                bad("KEY_UNSUPPORTED", "Activity BACK tracking and navigation are unsupported");
            return Value::word(0);
        }
        if (name.starts_with("on")) {
            if (p.callback != name)
                bad("LIFECYCLE_STATE", "Lifecycle super-call occurs outside the matching callback");
            const bool has_argument = name == "onCreate" || name == "onSaveInstanceState" ||
                name == "onRestoreInstanceState" || name == "onPostCreate" || name == "onConfigurationChanged";
            p.normal_lifecycle(name, has_argument ? std::optional<Value>{args[1]} : std::optional<Value>{});
            return Value::nothing();
        }
        if (name == "getApplication")
            return Value::reference(p.activity_attached ? p.application : 0);
        if (name == "setContentView") {
            auto &view = p.view(args[1].bits);
            if (view.parent)
                runtime.raise("Ljava/lang/IllegalStateException;", u"Content view already has a parent");
            p.cancel_input();
            p.focus(0);
            p.content = view.object;
            p.unscrolled_bounds.clear();
            p.apply_scroll_layout();
            ++p.metrics.view_revision;
            return Value::nothing();
        }
        if (name == "findViewById") {
            std::vector<ObjectId> todo;
            if (p.content)
                todo.push_back(p.content);
            while (!todo.empty()) {
                const auto id = todo.back();
                todo.pop_back();
                const auto &view = p.view(id);
                if (view.id != -1 &&
                    view.id == std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[1].bits)))
                    return Value::reference(id);
                todo.insert(todo.end(), view.children.rbegin(), view.children.rend());
            }
            return Value::reference(0);
        }
    }
    if (api.owner == "Landroid/view/InputEvent;" || api.owner == "Landroid/view/MotionEvent;" ||
        api.owner == "Landroid/view/KeyEvent;") {
        const auto found = p.input_events.find(receiver);
        if (found == p.input_events.end())
            bad("INPUT", "Input event has expired or belongs to another session");
        const auto &event = found->second;
        if (name == "dispatch" && event.key)
            return Value::word(p.key_callback(args[1].bits, receiver));
        if (name == "getSource")
            return Value::word(event.pointer ? event.pointer->source : 0x101u);
        if (event.pointer) {
            const auto &motion = *event.pointer;
            if (name == "getX")
                return Value::word(std::bit_cast<std::uint32_t>(motion.x));
            if (name == "getY")
                return Value::word(std::bit_cast<std::uint32_t>(motion.y));
            if (name == "getAction" || name == "getActionMasked")
                return Value::word(static_cast<std::uint32_t>(motion.action));
            if (name == "getPointerCount")
                return Value::word(1);
            if (name == "getPointerId") {
                if (args[1].bits)
                    runtime.raise("Ljava/lang/IllegalArgumentException;",
                                  u"Only pointer index zero is present");
                return Value::word(0);
            }
        } else {
            if (name == "getAction")
                return Value::word(event.key->up ? 1u : 0u);
            if (name == "getKeyCode")
                return Value::word(event.key->code);
            if (name == "getMetaState")
                return Value::word(event.key->meta);
            if (name == "getRepeatCount")
                return Value::word(event.key->repeat);
            if (name == "getUnicodeChar") {
                const auto input = *event.key;
                if (input.character_status == KeyCharacterStatus::unsupported ||
                    (args.size() == 2 && static_cast<std::uint32_t>(args[1].bits) != input.meta))
                    runtime.raise("Ljava/lang/UnsupportedOperationException;",
                                  u"Unicode mapping supports only the captured ordinary BMP key and modifier state");
                return Value::word(input.unicode);
            }
        }
        bad("INPUT", "Input getter does not match the event type");
    }
    if (api.owner == "Landroid/content/Context;") {
        p.context(receiver);
        if (name == "getFilesDir")
            return Value::reference(p.private_root());
        if (name == "getExternalFilesDir")
            return Value::reference(0); // No external storage volume is hosted by Aether.
        if (name == "getSharedPreferences") {
            if (args.size() != 3) bad("API_ARGUMENT", "getSharedPreferences requires name and mode");
            const auto preference_name = runtime.string(args[1].bits);
            if (!p.preferences) p.preferences = std::make_unique<PreferencesService>(runtime, p.files);
            const auto before = p.preferences->denials();
            struct Denials {
                PreferencesService &service; FrameworkMetrics &metrics; std::uint64_t before;
                ~Denials() { metrics.denied_permissions += service.denials() - before; }
            } denials{*p.preferences, p.metrics, before};
            return Value::reference(p.preferences->open(p.base_context, preference_name,
                std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[2].bits))));
        }
        if (name == "getApplicationInfo")
            return Value::reference(p.app_info());
        if (name == "getPackageName")
            return Value::reference(runtime.new_string(unicode(p.package)));
        if (name == "getApplicationContext")
            return Value::reference(p.application_published ? p.application : 0);
        if (name == "getResources")
            return Value::reference(p.resource_object);
        if (name == "getPackageManager")
            return Value::reference(p.package_manager);
        if (name == "checkSelfPermission" || name == "checkCallingOrSelfPermission") {
            if (runtime.string(args[1].bits) == u"android.permission.POST_NOTIFICATIONS" &&
                p.notification_permission())
                return Value::word(0);
            ++p.metrics.denied_permissions;
            return Value::word(0xffffffffu);
        }
        if (name == "getSystemService") {
            const auto service = std::u16string(runtime.string(args[1].bits));
            if (service == u"clipboard") return Value::reference(p.clipboard_service());
            if (service == u"notification") return Value::reference(p.notification_service());
            if (service == u"input_method") return Value::reference(p.input_method_service());
            ++p.metrics.unsupported_services;
            runtime.raise("Ljava/lang/UnsupportedOperationException;",
                          u"Android system service is unsupported: " + service);
        }
    }
    if (api.owner == "Landroid/content/pm/PackageManager;") {
        if (receiver != p.package_manager)
            bad("PACKAGE_MANAGER", "PackageManager is not attached");
        (void)runtime.string(args[1].bits);
        if (name == "hasSystemFeature")
            return Value::word(0);
        if (name == "checkPermission") {
            if (runtime.string(args[1].bits) == u"android.permission.POST_NOTIFICATIONS" &&
                runtime.string(args[2].bits) == unicode(p.package) && p.notification_permission())
                return Value::word(0);
            (void)runtime.string(args[2].bits);
            ++p.metrics.denied_permissions;
            return Value::word(0xffffffffu);
        }
    }
    if (api.owner == "Landroid/content/res/Resources;" && receiver != p.resource_object)
        bad("RESOURCES", "Resources object is not attached");
    if ((api.owner == "Landroid/content/Context;" || api.owner == "Landroid/content/res/Resources;") &&
        (name == "getString" || name == "getText"))
        return Value::reference(runtime.new_string(
            p.resource_text(static_cast<std::uint32_t>(args[1].bits), name == "getString")));
    if (api.owner == "Landroid/content/res/Resources;" && name == "getIdentifier") {
        const auto text = [&](std::size_t at) {
            return args[at].bits ? narrow(runtime.string(args[at].bits)) : std::string{};
        };
        return Value::word(p.resources.identifier(text(1), text(2), text(3)));
    }
    if (name == "<init>" &&
        (api.owner == "Landroid/widget/LinearLayout;" || api.owner == "Landroid/widget/TextView;" ||
         api.owner == "Landroid/widget/Button;" || api.owner == compound_button_type || api.owner == checkbox_type ||
         api.owner == scroll_view_type || api.owner == edit_text_type)) {
        p.context(args[1].bits);
        if (p.views.contains(receiver))
            bad("VIEW", "View constructor called twice");
        if (p.views.size() >= 256)
            bad("VIEW_LIMIT", "Application view quota exceeded");
        ViewState view;
        view.object = receiver;
        view.kind = runtime.assignable(receiver, edit_text_type) ? ViewKind::edit_text
                    : runtime.assignable(receiver, scroll_view_type) ? ViewKind::scroll_view
                    : runtime.assignable(receiver, compound_button_type) ? ViewKind::checkbox
                    : runtime.assignable(receiver, "Landroid/widget/LinearLayout;") ? ViewKind::linear_layout
                    : runtime.assignable(receiver, "Landroid/widget/Button;")     ? ViewKind::button
                                                                                  : ViewKind::text;
        view.clickable = view.kind == ViewKind::checkbox;
        view.text_buffer_revision = view.kind == ViewKind::edit_text ? 1 : 0;
        auto metadata = std::make_unique<ViewObjectState>();
        metadata->mode = view.kind == ViewKind::edit_text ? 2 : 0;
        if (runtime.assignable(receiver, "Landroid/widget/TextView;"))
            metadata->references[2] = Value::reference(view.kind == ViewKind::edit_text
                ? p.new_editable({}, receiver, true) : runtime.new_string({}));
        runtime.set_host_state(receiver, std::move(metadata));
        p.own(receiver);
        p.views.emplace(receiver, std::move(view));
        ++p.metrics.view_revision;
        if (p.view(receiver).kind == ViewKind::edit_text) {
            Impl::EditCall call(p);
            const auto current = p.view_state(receiver).references[2].bits;
            ManagedRoot root(runtime, current);
            p.text_committed(receiver, current);
            p.view(receiver).text_mutation_base_revision = p.view(receiver).text_event_revision;
            p.selection_changed(current);
            p.text_phase(receiver, current, 1, 0, 0, 0);
        }
        return Value::nothing();
    }
    if (api.owner == "Landroid/view/View$OnClickListener;" || api.owner == checked_listener_type || api.owner == watcher_type ||
        api.owner == key_listener_type || api.owner == key_callback_type || api.owner == drag_listener_type)
        bad("LISTENER", "Abstract listener or key callback method cannot execute directly");
    auto &view = p.view(receiver);
    if (name == "getAccessibilityNodeProvider") return Value::reference(0);
    if (name == "createAccessibilityNodeInfo")
        return Value::reference(p.create_accessibility_node_info_base(receiver));
    if (name == "onInitializeAccessibilityNodeInfo") {
        if (args.size() != 2) bad("ACCESSIBILITY_ARGUMENT", "Node initialization requires its metadata object");
        (void)p.accessibility_object(args[1].bits, AccessibilityObjectState::Kind::node);
        const auto selected = p.selected(receiver);
        auto metadata = std::make_unique<AccessibilityObjectState>(
            p.accessibility_object(args[1].bits, AccessibilityObjectState::Kind::node));
        metadata->selected = selected;
        metadata->actions |= 4u | 8u; // Actual SDK base advertises both standard selection actions.
        runtime.set_host_state(args[1].bits, std::move(metadata));
        // Base collection metadata is absent. A real managed override may set it.
        return Value::nothing();
    }
    if (name == "isSelected") return Value::word(p.view_state(receiver).selected);
    if (name == "setSelected") { p.set_selected_base(receiver, args[1].bits != 0); return Value::nothing(); }
    if (name == "dispatchSetSelected") {
        p.dispatch_set_selected_base(receiver, args[1].bits != 0, api.owner == "Landroid/view/ViewGroup;");
        return Value::nothing();
    }
    if (name == "performAccessibilityAction")
        return Value::word(p.accessibility_action_base(receiver, static_cast<std::uint32_t>(args[1].bits)));
    if (name == "sendAccessibilityEvent") {
        if (args.size() != 2 || args[1].kind != dex::ValueKind::word || args[1].bits != 2048)
            runtime.raise("Ljava/lang/UnsupportedOperationException;", u"Only collection content-change accessibility invalidation is supported");
        if (p.accessibility_invalidation == UINT64_MAX)
            bad("ACCESSIBILITY_INVALIDATION", "Accessibility invalidation revision exhausted");
        ++p.accessibility_invalidation;
        return Value::nothing();
    }
    if (name == "setOnDragListener") {
        if (args.size() != 2 || (args[1].kind != dex::ValueKind::reference &&
            !(args[1].kind == dex::ValueKind::word && !args[1].bits)))
            bad("DRAG_ARGUMENT", "Drag listener requires a reference");
        if (args[1].bits && !runtime.assignable(args[1].bits, drag_listener_type))
            runtime.raise("Ljava/lang/IllegalArgumentException;", u"Drag listener does not implement View.OnDragListener");
        auto metadata = std::make_unique<ViewObjectState>(p.view_state(receiver));
        metadata->references[5] = Value::reference(args[1].bits);
        runtime.set_host_state(receiver, std::move(metadata));
        return Value::nothing();
    }
    if (name == "dispatchDragEvent" || name == "onDragEvent") {
        if (args.size() != 2 || (args[1].kind != dex::ValueKind::reference &&
            !(args[1].kind == dex::ValueKind::word && !args[1].bits)))
            bad("DRAG_ARGUMENT", "View drag delivery requires an event reference");
        (void)p.drag_object(args[1].bits, DragObjectKind::event);
        return Value::word(name == "dispatchDragEvent" && p.base_drag_dispatch(receiver, args[1].bits));
    }
    if (name == "getWindowToken") return Value::reference(p.attached_window_token(receiver));
    if (name == "getShowSoftInputOnFocus") return Value::word(p.view_state(receiver).show_soft_input_on_focus);
    if (name == "setShowSoftInputOnFocus") {
        auto metadata = std::make_unique<ViewObjectState>(p.view_state(receiver));
        metadata->show_soft_input_on_focus = args[1].bits != 0;
        runtime.set_host_state(receiver, std::move(metadata));
        return Value::nothing();
    }
    if (name == "onCheckIsTextEditor")
        return Value::word(api.owner != "Landroid/view/View;" && view.kind == ViewKind::edit_text);
    if (name == "onCreateInputConnection") {
        if (api.owner == "Landroid/view/View;" || view.kind != ViewKind::edit_text) return Value::reference(0);
        const auto info = args[1].bits;
        ManagedRoot info_root(runtime, info);
        auto metadata = std::make_unique<EditorInfoState>(p.editor_state(info));
        const auto current = p.view_state(receiver).references[2].bits;
        ManagedRoot buffer_root(runtime, current);
        metadata->input_type = 0x20001; // Explicit hosted plain multiline text profile.
        metadata->initial_start = p.selection_state(current).start;
        metadata->initial_end = p.selection_state(current).end;
        metadata->field_id = view.id;
        metadata->references[0] = Value::reference(p.package_string());
        runtime.set_host_state(info, std::move(metadata));
        return Value::reference(p.new_editable_connection(receiver));
    }
    if (name == "beginBatchEdit" || name == "endBatchEdit") {
        auto metadata = std::make_unique<ViewObjectState>(p.view_state(receiver));
        if (name == "beginBatchEdit") {
            if (metadata->batch_depth >= 32) bad("IME_BATCH_LIMIT", "TextView batch nesting quota is 32");
            ++metadata->batch_depth;
        } else if (metadata->batch_depth > 0) --metadata->batch_depth;
        runtime.set_host_state(receiver, std::move(metadata));
        return Value::nothing(); // Text watchers stay synchronous; native snapshots coalesce separately.
    }
    if (name == "setImeConsumesInput") {
        const bool value = args[1].bits != 0;
        if (p.view_state(receiver).ime_consumes_input != value) {
            auto metadata = std::make_unique<ViewObjectState>(p.view_state(receiver));
            metadata->ime_consumes_input = value;
            runtime.set_host_state(receiver, std::move(metadata));
            ++p.metrics.view_revision;
        }
        return Value::nothing(); // Cursor-visibility publication is a separate profile.
    }
    if (name == "dispatchKeyEvent")
        return Value::word(p.view_key_dispatch_base(receiver, args[1].bits, api.owner == "Landroid/view/ViewGroup;"));
    if (name == "onKeyDown" || name == "onKeyUp")
        return Value::word(p.view_key_base(receiver, static_cast<std::uint32_t>(args[1].bits), args[2].bits,
                                          api.owner == "Landroid/widget/TextView;", name == "onKeyUp"));
    if (name == "setOnKeyListener") {
        if (args[1].bits && !runtime.assignable(args[1].bits, key_listener_type))
            runtime.raise("Ljava/lang/IllegalArgumentException;", u"Listener must implement View.OnKeyListener");
        auto next = std::make_unique<ViewObjectState>(p.view_state(receiver));
        next->references[4] = args[1];
        runtime.set_host_state(receiver, std::move(next));
        return Value::nothing();
    }
    if (name == "onTextChanged" || name == "onSelectionChanged") return Value::nothing();
    if (name == "addTextChangedListener" || name == "removeTextChangedListener") {
        p.change_watchers(receiver, args[1].bits, name == "addTextChangedListener");
        return Value::nothing();
    }
    if (name == "getEditableText" || name == "getSelectionStart" || name == "getSelectionEnd" ||
        name == "setSelection" || name == "selectAll" || name == "extendSelection") {
        const auto current = p.view_state(receiver).references[2].bits;
        if (name == "getEditableText")
            return Value::reference(current && dynamic_cast<const EditableState *>(runtime.host_state(current)) ? current : 0);
        if (name == "getSelectionStart" || name == "getSelectionEnd") {
            return Value::word(std::bit_cast<std::uint32_t>(p.selection_marker(current, name == "getSelectionEnd")));
        }
        const auto selected = p.selection_text(receiver);
        ManagedRoot selected_root(runtime, selected);
        if (name == "selectAll") p.set_selection(selected, 0, static_cast<std::int32_t>(p.selection_state(selected).text.size()));
        else {
            const auto index = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[1].bits));
            const auto edge = args.size() == 3 ? std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[2].bits)) : index;
            p.set_selection(selected, index, edge, name == "extendSelection");
        }
        return Value::nothing();
    }
    if (api.owner == compound_button_type || api.owner == checkable_type) {
        (void)p.checked_state(receiver);
        if (name == "isChecked") return Value::word(view.checked);
        if (name == "setChecked") { p.set_checked(receiver, args[1].bits != 0); return Value::nothing(); }
        if (name == "toggle") { p.dispatch_set_checked(receiver, !view.checked); return Value::nothing(); }
        if (name == "setOnCheckedChangeListener") {
            if (args[1].bits && !runtime.assignable(args[1].bits, checked_listener_type))
                bad("LISTENER", "Checked-change listener has an incompatible type");
            auto next = std::make_unique<ViewObjectState>(p.checked_state(receiver));
            next->references[0] = args[1];
            runtime.set_host_state(receiver, std::move(next));
            return Value::nothing();
        }
        if (name == "performClick") return Value::word(p.perform_click_base(receiver, true));
    }
    if (name == "getScrollX") return Value::word(0);
    if (name == "getScrollY") return Value::word(static_cast<std::uint32_t>(view.scroll_y));
    if (name == "scrollTo" || name == "scrollBy") {
        const auto x = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[1].bits));
        const auto y = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[2].bits));
        if (name == "scrollTo") p.scroll_to_base(receiver, y);
        else p.scroll_by_base(receiver, x, y);
        return Value::nothing();
    }
    if (name == "getContentDescription") {
        return p.view_state(receiver).references[1];
    } else if (name == "setContentDescription") {
        const auto replacement = args[1].bits;
        const auto previous = p.view_state(receiver).references[1].bits;
        // Validate the supported type even for an identity no-op. AOSP retains
        // the supplied CharSequence; Strings compare content, builders identity.
        if (replacement) (void)runtime.char_sequence(replacement);
        p.check_descriptions(receiver, replacement);
        if (previous == replacement ||
            (previous && replacement && runtime.object_type(previous) == "Ljava/lang/String;" &&
             runtime.object_type(replacement) == "Ljava/lang/String;" &&
             runtime.string(previous) == runtime.string(replacement)))
            return Value::nothing();
        // No borrowed state or character buffer survives this allocating call.
        auto next = std::make_unique<ViewObjectState>(p.view_state(receiver));
        next->references[1] = Value::reference(replacement);
        runtime.set_host_state(receiver, std::move(next));
    } else if (name == "setOrientation") {
        if (args[1].bits > 1)
            runtime.raise("Ljava/lang/IllegalArgumentException;",
                          u"Orientation must be HORIZONTAL or VERTICAL");
        view.orientation = static_cast<std::int32_t>(args[1].bits);
    } else if (name == "addView") {
        auto &child = p.view(args[1].bits);
        if (child.kind == ViewKind::scroll_view)
            runtime.raise("Ljava/lang/UnsupportedOperationException;", u"ScrollView is supported only as the Activity content root");
        if (view.kind == ViewKind::scroll_view && !view.children.empty())
            runtime.raise("Ljava/lang/IllegalStateException;", u"ScrollView can host only one direct child");
        if (child.parent || child.object == p.content)
            runtime.raise("Ljava/lang/IllegalStateException;", u"View already belongs to a parent or window");
        for (auto parent = receiver; parent; parent = p.view(parent).parent)
            if (parent == child.object)
                runtime.raise("Ljava/lang/IllegalStateException;", u"View tree would contain a cycle");
        view.children.push_back(child.object);
        child.parent = receiver;
    } else if (name == "setText") {
        if (args.size() == 3) p.set_text_base(receiver, args[1].bits,
            view.kind == ViewKind::edit_text ? 2 : p.mode_value(args[2].bits));
        else if (api.signature == "(I)V") {
            const auto source = runtime.new_string(p.resource_text(static_cast<std::uint32_t>(args[1].bits)));
            ManagedRoot root(runtime, source);
            p.dispatch_set_text(receiver, source);
        } else p.dispatch_set_text(receiver, args[1].bits);
        return Value::nothing();
    } else if (name == "getText")
        return p.view_state(receiver).references[2];
    else if (name == "setOnClickListener") {
        runtime.retain(args[1].bits);
        runtime.release(view.listener);
        view.listener = args[1].bits;
        view.clickable = p.clickable(receiver);
    } else if (name == "performClick")
        return Value::word(p.perform_click_base(receiver, false));
    else if (name == "setEnabled") {
        view.enabled = args[1].bits != 0;
        if ((p.pointer_target && !p.enabled(p.pointer_target)) || (p.key_target && !p.enabled(p.key_target)))
            p.cancel_input();
    } else if (name == "isEnabled")
        return Value::word(view.enabled);
    else if (name == "setId") {
        const auto id = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(args[1].bits));
        if (id < -1)
            runtime.raise("Ljava/lang/IllegalArgumentException;", u"Invalid negative view ID");
        view.id = id;
    } else if (name == "getId")
        return Value::word(static_cast<std::uint32_t>(view.id));
    else
        bad("API_UNSUPPORTED",
            std::string(api.owner) + "." + std::string(api.name) + std::string(api.signature));
    ++p.metrics.view_revision;
    return Value::nothing();
}
} // namespace aether::android
