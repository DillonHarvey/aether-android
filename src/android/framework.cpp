#include "aether/android/framework.hpp"
#include "aether/common/text.hpp"
#include "bundle.hpp"
#include "preferences.hpp"
#include "aether/host/process_info.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <limits>
#include <set>

namespace aether::android {
using dex::ObjectId;
using dex::Value;
namespace {
constexpr std::string_view handler_type = "Landroid/os/Handler;", looper_type = "Landroid/os/Looper;";
constexpr std::string_view factory_type = "Landroid/app/AppComponentFactory;";
constexpr std::string_view application_info_type = "Landroid/content/pm/ApplicationInfo;";
constexpr std::string_view package_item_type = "Landroid/content/pm/PackageItemInfo;";
constexpr std::string_view intent_type = "Landroid/content/Intent;";
constexpr std::string_view file_type = "Ljava/io/File;";
constexpr std::string_view application_type = "Landroid/app/Application;";
constexpr std::string_view lifecycle_type = "Landroid/app/Application$ActivityLifecycleCallbacks;";
constexpr std::string_view context_impl_type = "Landroid/app/ContextImpl;";
constexpr std::string_view activity_thread_type = "Landroid/app/ActivityThread;";
constexpr std::string_view app_bind_type = "Landroid/app/ActivityThread$AppBindData;";
constexpr std::string_view loaded_apk_type = "Landroid/app/LoadedApk;";
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
    bool active = true;
    std::array<bool,16> used{};
    std::array<int,16> descriptors;
    explicit InputLease(host::FileService *files) : files(files) { descriptors.fill(-1); }
    host::FileResult invalidate() noexcept {
        if(!active)return {0,host::FileError::none};
        active=false;auto *service=files;files=nullptr;
        host::FileResult failure{0,host::FileError::none};
        for(std::size_t n=0;n<used.size();++n) {
            const auto descriptor=descriptors[n];descriptors[n]=-1;used[n]=false;
            if(descriptor>=0 && service) {
                const auto closed=service->close(descriptor);
                if(closed.error!=host::FileError::none || closed.value!=0)
                    failure={-1,closed.error==host::FileError::none?host::FileError::io:closed.error};
            }
        }
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
class LifecycleState final : public dex::HostObjectState {
  public:
    std::array<Value,16> callbacks{};
    std::size_t count=0;
    std::span<const Value> values()const noexcept override{return std::span<const Value>(callbacks).first(count);}
    std::size_t bytes()const noexcept override{return sizeof(*this);}
};
class LaunchIntentState final : public dex::HostObjectState {
  public:
    LaunchIntentState(std::string package, std::string component)
        : package(std::move(package)), component(std::move(component)) {}
    std::string package, component;
    std::span<const Value> values() const noexcept override { return {}; }
    std::size_t bytes() const noexcept override {
        return sizeof(LaunchIntentState) + package.capacity() + component.capacity() + 2;
    }
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
    {factory_type, "Ljava/lang/Object;"},
    {lifecycle_type, "Ljava/lang/Object;", true, true},
    {application_info_type, package_item_type},
    {package_item_type, "Ljava/lang/Object;"},
    {intent_type, "Ljava/lang/Object;"},
    {app_bind_type, "Ljava/lang/Object;"},
    {loaded_apk_type, "Ljava/lang/Object;"},
    {file_type, "Ljava/lang/Object;"},
    {"Landroid/text/TextUtils;", "Ljava/lang/Object;"},
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
    {"Landroid/content/res/Resources;", "Ljava/lang/Object;"},
    {"Landroid/content/res/Resources$NotFoundException;", "Ljava/lang/RuntimeException;"},
    {"Landroid/content/pm/PackageManager;", "Ljava/lang/Object;", true},
    {"Laether/android/PackageManager;", "Landroid/content/pm/PackageManager;"},
    {"Landroid/view/View;", "Ljava/lang/Object;"},
    {"Landroid/view/ViewGroup;", "Landroid/view/View;", true},
    {"Landroid/widget/LinearLayout;", "Landroid/view/ViewGroup;"},
    {"Landroid/widget/TextView;", "Landroid/view/View;"},
    {"Landroid/widget/Button;", "Landroid/widget/TextView;"},
    {"Landroid/view/View$OnClickListener;", "Ljava/lang/Object;", true, true}};
std::optional<dex::HostClass> class_metadata(std::string_view type) {
    if (const auto preferences = preferences_class(type)) return preferences;
    static constexpr std::array<std::string_view, 2> bundle_interfaces{"Ljava/lang/Cloneable;",
                                                                       "Landroid/os/Parcelable;"};
    if (type == "Landroid/os/Build$VERSION;")
        return dex::HostClass{"Ljava/lang/Object;", {}, false, false, true, true};
    if (type == bundle_type)
        return dex::HostClass{base_bundle_type, bundle_interfaces, false, false, true, true};
    for (const auto &entry : classes)
        if (entry.name == type)
            return dex::HostClass{entry.superclass, {}, entry.is_abstract, entry.is_interface, type != file_type, true};
    return {};
}
bool api_static(const ApiSupport &api) {
    return api.owner == "Ljava/lang/System;" || api.owner == "Landroid/os/SystemClock;" ||
           api.owner == "Landroid/text/TextUtils;" ||
           (api.owner == "Landroid/os/Process;" && api.name == "getStartUptimeMillis") ||
           (api.owner == activity_thread_type &&
            (api.name == "currentApplication" || api.name == "currentActivityThread")) ||
           (api.owner == application_type && api.name == "getProcessName") ||
           (api.owner == looper_type && (api.name == "getMainLooper" || api.name == "myLooper"));
}
bool public_api(const ApiSupport &api) {
    if (api.name == "<init>" || api.name == "<clinit>")
        return false;
    if (api.owner == "Landroid/content/ContextWrapper;" && api.name == "attachBaseContext")
        return false;
    if (api.owner == "Landroid/app/Activity;" && api.name.starts_with("on") &&
        api.name != "onWindowFocusChanged")
        return false; // These Activity lifecycle callbacks are protected.
    return true;
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
        owner = preferences_owner(owner);
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
    const host::TimeService *time;
    host::FileService *files;
    std::shared_ptr<InputLease> input_lease;
    std::unique_ptr<PreferencesService> preferences;
    bool input_cleanup_failed = false;
    ObjectId files_directory = 0;
    ObjectId application = 0, resource_object = 0, package_manager = 0, activity = 0, content = 0;
    ObjectId main_looper = 0, base_context = 0, activity_thread = 0;
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
    std::vector<std::string> events;
    std::array<std::u16string,2> standard_output;
    std::size_t output_characters=0;
    FrameworkMetrics metrics;
    struct InputData {
        std::optional<PointerInput> pointer;
        std::optional<KeyInput> key;
    };
    std::map<ObjectId, InputData> input_events;
    ObjectId pointer_target = 0, key_target = 0, focused_view = 0;
    std::uint32_t pointer_id = 0, held_key = 0;
    Lifecycle state = Lifecycle::empty;
    std::string_view callback;
    bool called_super = false, active = true, visible = true, focused = false, attached = false;
    std::uint64_t lifecycle_revision=0;
    explicit Impl(dex::ManagedRuntime &runtime, std::string package, apk::ResourceTable resources,
                  const host::TimeService *time, host::FileService *files)
        : runtime(runtime), package(std::move(package)), resources(std::move(resources)), time(time), files(files), input_lease(std::make_shared<InputLease>(files)) {
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
        if (!input_events.empty())
            bad("INPUT_REENTRANT", "Cannot dispose framework during input dispatch");
        runtime.close_tasks();
        runtime.close_main_callbacks();
        std::exception_ptr preferences_error;
        if (preferences) {
            try { preferences->close(); } catch (...) { preferences_error = std::current_exception(); }
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
        if(application)runtime.set_host_state(application,{});
        for (auto object : owned)
            runtime.release(object);
        owned.clear();
        application = resource_object = package_manager = activity = content = main_looper = files_directory = base_context = activity_thread = 0;
        bound_application = loaded_package = data_directory = 0;
        application_info = package_name = component_factory = selected_loader = launch_intent = 0;
        application_attached = activity_attached = application_published = false;
        pointer_target = key_target = focused_view = 0;
        held_key = 0;
        if (attached) {
            runtime.set_host_interface(nullptr);
            attached = false;
        }
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
    const LifecycleState &lifecycle_state() const {
        const auto *value=dynamic_cast<const LifecycleState *>(runtime.host_state(application));
        if(!value)bad("LIFECYCLE_STATE","Application callback registry is unavailable");
        return *value;
    }
    struct ListenerSnapshot {
        dex::ManagedRuntime &runtime;std::array<Value,16> values{};std::size_t count=0,pinned=0;
        ListenerSnapshot(dex::ManagedRuntime &runtime,const LifecycleState &source):runtime(runtime),values(source.callbacks),count(source.count) {
            try {for(;pinned<count;++pinned)runtime.retain(values[pinned].bits);}
            catch(...) {while(pinned)runtime.release(values[--pinned].bits);throw;}
        }
        ~ListenerSnapshot(){while(pinned)runtime.release(values[--pinned].bits);}
    };
    void change_lifecycle(ObjectId listener,bool add) {
        if(!application_constructed)bad("APPLICATION_STATE","Registration requires the initialized Application base");
        const auto revision=lifecycle_revision;
        ListenerSnapshot snapshot(runtime,lifecycle_state());
        auto next=std::make_unique<LifecycleState>();
        next->callbacks=snapshot.values;next->count=snapshot.count;
        if(add) {
            if(next->count==next->callbacks.size())bad("LIFECYCLE_LIMIT","Application lifecycle registration limit of 16 exceeded");
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
            next->callbacks[--next->count]={};
        }
        if(lifecycle_revision==std::numeric_limits<std::uint64_t>::max())bad("LIFECYCLE_LIMIT","Lifecycle registry revision exhausted");
        runtime.set_host_state(application,std::move(next));++lifecycle_revision;
    }
    static std::string_view lifecycle_suffix(std::string_view event) {
        if(event=="onCreate")return "Created";
        if(event=="onStart")return "Started";
        if(event=="onResume")return "Resumed";
        if(event=="onPause")return "Paused";
        if(event=="onStop")return "Stopped";
        if(event=="onDestroy")return "Destroyed";
        return {};
    }
    void notify_lifecycle(std::string_view event,std::string_view phase,std::optional<Value> argument={}) {
        const auto suffix=lifecycle_suffix(event);if(suffix.empty())return;
        ListenerSnapshot snapshot(runtime,lifecycle_state());
        const auto name="onActivity"+std::string(phase)+std::string(suffix);
        const bool created=event=="onCreate";
        const auto signature=created?"(Landroid/app/Activity;Landroid/os/Bundle;)V":"(Landroid/app/Activity;)V";
        const std::array<Value,2> args{Value::reference(activity),argument.value_or(Value::reference(0))};
        for(std::size_t n=0;n<snapshot.count;++n)
            (void)runtime.invoke_virtual_named(snapshot.values[n].bits,name,signature,std::span<const Value>(args).first(created?2:1));
    }
    void normal_lifecycle(std::string_view event,std::optional<Value> argument={}) {
        called_super=true;
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
                if (!called_super && name != "onWindowFocusChanged")
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
    ObjectId hit(ObjectId root, float x, float y) {
        const auto &node = view(root);
        if (!node.enabled || !node.bounds.contains(x, y))
            return 0;
        for (auto child = node.children.rbegin(); child != node.children.rend(); ++child)
            if (const auto target = hit(*child, x, y))
                return target;
        return node.listener ? root : 0;
    }
    void focus(ObjectId object) {
        if (focused_view == object)
            return;
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
            focus(pointer_target);
            view(pointer_target).pressed = true;
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
        if (inside)
            (void)perform_click(target);
        return true;
    }
    bool default_key(const KeyInput &event) {
        if (state != Lifecycle::resumed || !content)
            return false;
        if (event.code == 61 && !event.up) { // KEYCODE_TAB, with Shift traversal.
            std::vector<ObjectId> order, todo{content};
            while (!todo.empty()) {
                const auto id = todo.back();
                todo.pop_back();
                const auto &node = view(id);
                if (node.listener && enabled(id))
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
            return true;
        }
        if (event.code != 66 && event.code != 62)
            return false; // ENTER and SPACE.
        if (!event.up) {
            if (pointer_target)
                return false;
            if (!enabled(focused_view))
                return false;
            if (!event.repeat && !key_target) {
                key_target = focused_view;
                held_key = event.code;
                view(key_target).pressed = true;
                ++metrics.view_revision;
            }
            return key_target != 0;
        }
        if (!key_target || held_key != event.code)
            return false;
        const auto target = key_target;
        key_target = 0;
        held_key = 0;
        view(target).pressed = false;
        ++metrics.view_revision;
        if (target == focused_view && enabled(target))
            (void)perform_click(target);
        return true;
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
            return motion ? default_pointer(*data.pointer) : default_key(*data.key);
        } catch (...) {
            cancel_input();
            throw;
        }
    }
    bool perform_click(ObjectId object) {
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
        return true;
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
                                 apk::ResourceTable resources, const host::TimeService *time, host::FileService *files)
    : impl_(std::make_unique<Impl>(runtime, std::move(package), std::move(resources), time, files)) {
    auto &p = *impl_;
    runtime.set_host_interface(this);
    p.attached = true;
    try {
        p.base_context = p.own(runtime.new_object(context_impl_type));
        p.resource_object = p.own(runtime.new_object("Landroid/content/res/Resources;"));
        p.package_manager = p.own(runtime.new_object("Laether/android/PackageManager;"));
        p.bind_package();
    } catch (...) {
        p.cleanup(false);
        throw;
    }
}
ActivitySession::~ActivitySession() { impl_->cleanup(false); }
void ActivitySession::initialize_application(std::string_view descriptor, std::string_view factory_descriptor) {
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
void ActivitySession::launch(std::string_view descriptor) {
    auto &p = *impl_;
    if (p.state != Lifecycle::empty || !p.attached)
        bad("LIFECYCLE_STATE", "Activity can only launch once per session");
    if (p.application_stage == Impl::ApplicationStage::empty)
        initialize_application();
    if (p.application_stage != Impl::ApplicationStage::ready)
        bad("APPLICATION_STATE", "Activity requires a successfully initialized Application");
    p.activity_type = descriptor;
    try {
        p.factory_activity_active = true;
        if (p.component_factory) {
            p.launch_intent = p.own(p.runtime.new_object(intent_type));
            p.runtime.set_host_state(p.launch_intent, std::make_unique<LaunchIntentState>(p.package, p.activity_type));
            ObjectId result = 0;
            if (const auto method = p.override_method(p.runtime.object_type(p.component_factory), "instantiateActivity",
                    "(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Intent;)Landroid/app/Activity;")) {
                const auto name = p.own(p.runtime.new_string(p.component_name(descriptor)));
                const std::array args{Value::reference(p.component_factory), Value::reference(p.selected_loader),
                                      Value::reference(name), Value::reference(p.launch_intent)};
                result = p.runtime.invoke_virtual(*method, args).bits;
            } else result = p.construct_activity();
            if (!p.activity || result != p.activity)
                bad("FACTORY_ACTIVITY_UNSUPPORTED", "Factory did not return the actual declared Activity");
        } else p.construct_activity();
        p.factory_activity_active = false;
        p.activity_attached = true;
        p.deliver("onCreate", Lifecycle::created, "(Landroid/os/Bundle;)V", Value::reference(0));
        p.deliver("onStart", Lifecycle::started);
        p.deliver("onResume", Lifecycle::resumed);
    } catch (...) {
        p.factory_activity_active = false;
        p.state = Lifecycle::failed;
        throw;
    }
}
void ActivitySession::signal(WindowSignal signal) {
    auto &p = *impl_;
    if(!p.callback.empty())bad("LIFECYCLE_REENTRANT","Cannot signal during lifecycle delivery");
    if (signal == WindowSignal::close) {
        close();
        return;
    }
    if (p.state == Lifecycle::empty || p.state == Lifecycle::destroyed || p.state == Lifecycle::failed)
        bad("LIFECYCLE_STATE", "Window event cannot target an inactive activity");
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
        const bool focused = signal == WindowSignal::focus_gained;
        if (p.focused != focused) {
            if (!focused)
                p.cancel_input();
            p.focused = focused;
            p.deliver("onWindowFocusChanged", p.state, "(Z)V", Value::word(focused));
        }
        return;
    }
    case WindowSignal::close:
        return;
    }
    if ((!p.visible || !p.active) && p.state == Lifecycle::resumed)
        p.deliver("onPause", Lifecycle::paused);
    if (!p.visible && (p.state == Lifecycle::paused || p.state == Lifecycle::started))
        p.deliver("onStop", Lifecycle::stopped);
    if (p.visible && p.state == Lifecycle::stopped) {
        p.deliver("onRestart", Lifecycle::stopped);
        p.deliver("onStart", Lifecycle::started);
    }
    if (p.visible && p.active && (p.state == Lifecycle::started || p.state == Lifecycle::paused))
        p.deliver("onResume", Lifecycle::resumed);
}
bool ActivitySession::click(ObjectId object) {
    auto &p = *impl_;
    if (p.state != Lifecycle::resumed || !p.in_tree(object))
        return false;
    for (auto id = object; id; id = p.view(id).parent)
        if (!p.view(id).enabled)
            return false;
    return p.perform_click(object);
}
void ActivitySession::place_views(std::span<const ViewPlacement> placements) {
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
    bool changed = false;
    for (const auto &placement : placements) {
        auto &r = p.view(placement.view).bounds;
        changed = changed || r != placement.bounds;
        r = placement.bounds;
    }
    if (changed)
        ++p.metrics.view_revision;
}
bool ActivitySession::pointer(const PointerInput &event) {
    if (static_cast<unsigned>(event.action) > 3 || !std::isfinite(event.x) || !std::isfinite(event.y) ||
        std::abs(event.x) > 65536 || std::abs(event.y) > 65536 || event.pointer > 65535 ||
        (event.source != 0x2002 && event.source != 0x1002))
        bad("INPUT", "Invalid or unsupported pointer event");
    return impl_->dispatch_input({event, {}});
}
bool ActivitySession::key(const KeyInput &event) {
    if (event.code > 512 || event.repeat > 65535 || (event.meta & ~0x11003u))
        bad("INPUT", "Invalid or unsupported key event");
    return impl_->dispatch_input({{}, event});
}
void ActivitySession::close() {
    auto &p = *impl_;
    if(p.runtime.process_state()->exit_status()) {
        p.cleanup(false);return;
    }
    if(!p.callback.empty())bad("LIFECYCLE_REENTRANT","Cannot close during lifecycle delivery");
    if (!p.input_events.empty())
        bad("INPUT_REENTRANT", "Cannot close during input dispatch");
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
    const auto &p = *impl_;
    if (&runtime != &p.runtime || !p.attached)
        bad("STATE", "Framework field belongs to another or closed runtime");
    const auto &field = runtime.image().fields.at(index);
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
        owner = preferences_owner(current_owner);
        for (const auto &api : api_registry()) {
            if (api.owner != owner || api.name != name || !public_api(api)) continue;
            const auto expected = api_parameters(api.signature);
            if (expected.size() != parameters.size() ||
                !std::equal(expected.begin(), expected.end(), parameters.begin())) continue;
            const auto close = api.signature.find(')');
            return dex::HostMethod{std::string(api.owner), std::string(api.name),
                                   std::string(api.signature.substr(close + 1)), expected,
                                   api_static(api) ? 9u :
                                       ((api.owner==preferences_type || api.owner==preferences_editor_type || (api.owner==lifecycle_type && !api.name.starts_with("onActivityPre") && !api.name.starts_with("onActivityPost")))?0x401u:1u)};
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
    // Exact Android 15 declarations; this is a deliberately partial schema.
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
    auto &p = *impl_;
    if (&runtime != &p.runtime || !p.attached)
        bad("STATE", "Framework call belongs to another or closed runtime");
    ++p.metrics.api_calls;
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
            const auto *intent = dynamic_cast<const LaunchIntentState *>(runtime.host_state(args[3].bits));
            if (!intent || intent->package != p.package || intent->component != p.activity_type)
                bad("FACTORY_INTENT", "Launch Intent does not describe this session's requested component");
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
        return Value::word(runtime.char_sequence(first) == runtime.char_sequence(second));
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
        if (name == "dispatchTouchEvent" || name == "dispatchKeyEvent") {
            const auto found = p.input_events.find(args[1].bits);
            if (found == p.input_events.end())
                bad("INPUT", "Input event has expired or belongs to another session");
            if (name == "dispatchTouchEvent" && found->second.pointer)
                return Value::word(p.default_pointer(*found->second.pointer));
            if (name == "dispatchKeyEvent" && found->second.key)
                return Value::word(p.default_key(*found->second.key));
            bad("INPUT", "Input event type does not match dispatch method");
        }
        if (name.starts_with("on")) {
            if (p.callback != name)
                bad("LIFECYCLE_STATE", "Lifecycle super-call occurs outside the matching callback");
            p.normal_lifecycle(name,name=="onCreate"?std::optional<Value>{args[1]}:std::optional<Value>{});
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
            (void)runtime.string(args[1].bits);
            ++p.metrics.denied_permissions;
            return Value::word(0xffffffffu);
        }
        if (name == "getSystemService") {
            const auto service = std::u16string(runtime.string(args[1].bits));
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
         api.owner == "Landroid/widget/Button;")) {
        p.context(args[1].bits);
        if (p.views.contains(receiver))
            bad("VIEW", "View constructor called twice");
        if (p.views.size() >= 256)
            bad("VIEW_LIMIT", "Application view quota exceeded");
        ViewState view;
        view.object = receiver;
        view.kind = runtime.assignable(receiver, "Landroid/widget/LinearLayout;") ? ViewKind::linear_layout
                    : runtime.assignable(receiver, "Landroid/widget/Button;")     ? ViewKind::button
                                                                                  : ViewKind::text;
        p.own(receiver);
        p.views.emplace(receiver, std::move(view));
        ++p.metrics.view_revision;
        return Value::nothing();
    }
    if (api.owner == "Landroid/view/View$OnClickListener;")
        bad("LISTENER", "Abstract OnClickListener method cannot execute directly");
    auto &view = p.view(receiver);
    if (name == "setOrientation") {
        if (args[1].bits > 1)
            runtime.raise("Ljava/lang/IllegalArgumentException;",
                          u"Orientation must be HORIZONTAL or VERTICAL");
        view.orientation = static_cast<std::int32_t>(args[1].bits);
    } else if (name == "addView") {
        auto &child = p.view(args[1].bits);
        if (child.parent || child.object == p.content)
            runtime.raise("Ljava/lang/IllegalStateException;", u"View already belongs to a parent or window");
        for (auto parent = receiver; parent; parent = p.view(parent).parent)
            if (parent == child.object)
                runtime.raise("Ljava/lang/IllegalStateException;", u"View tree would contain a cycle");
        view.children.push_back(child.object);
        child.parent = receiver;
    } else if (name == "setText") {
        const auto value = api.signature == "(I)V" ? p.resource_text(static_cast<std::uint32_t>(args[1].bits))
                           : args[1].bits          ? std::u16string(runtime.char_sequence(args[1].bits))
                                                   : std::u16string{};
        if (value.size() > 65536)
            bad("TEXT_LIMIT", "View text quota exceeded");
        view.text = value;
    } else if (name == "getText")
        return Value::reference(runtime.new_string(view.text));
    else if (name == "setOnClickListener") {
        runtime.retain(args[1].bits);
        runtime.release(view.listener);
        view.listener = args[1].bits;
    } else if (name == "performClick")
        return Value::word(p.perform_click(receiver));
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
