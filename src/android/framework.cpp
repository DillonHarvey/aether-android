#include "aether/android/framework.hpp"
#include "aether/common/text.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <set>

namespace aether::android {
using dex::ObjectId;
using dex::Value;
namespace {
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
    {"Landroid/content/Context;", "Ljava/lang/Object;", true},
    {"Landroid/content/ContextWrapper;", "Landroid/content/Context;"},
    {"Landroid/view/ContextThemeWrapper;", "Landroid/content/ContextWrapper;"},
    {"Landroid/app/Activity;", "Landroid/view/ContextThemeWrapper;"},
    {"Landroid/app/Application;", "Landroid/content/ContextWrapper;"},
    {"Landroid/os/Bundle;", "Ljava/lang/Object;"},
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
    for (const auto &entry : classes)
        if (entry.name == type)
            return dex::HostClass{entry.superclass, {}, entry.is_abstract, entry.is_interface};
    return {};
}
const ApiSupport &resolve(const dex::DexImage &image, dex::Index index) {
    const auto &method = image.methods.at(index);
    const auto &signature = image.prototypes.at(method.prototype).descriptor;
    auto owner = std::string_view(image.types.at(method.owner));
    for (unsigned depth = 0; depth < 256; ++depth) {
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
    ObjectId application = 0, resource_object = 0, package_manager = 0, activity = 0, content = 0;
    std::vector<ObjectId> owned;
    std::map<ObjectId, ViewState> views;
    std::vector<std::string> events;
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
    explicit Impl(dex::ManagedRuntime &runtime, std::string package, apk::ResourceTable resources)
        : runtime(runtime), package(std::move(package)), resources(std::move(resources)) {
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
    void cleanup() {
        if (!input_events.empty())
            bad("INPUT_REENTRANT", "Cannot dispose framework during input dispatch");
        for (const auto &[id, view] : views) {
            (void)id;
            runtime.release(view.listener);
        }
        views.clear();
        for (auto object : owned)
            runtime.release(object);
        owned.clear();
        application = resource_object = package_manager = activity = content = 0;
        pointer_target = key_target = focused_view = 0;
        held_key = 0;
        if (attached) {
            runtime.set_host_interface(nullptr);
            attached = false;
        }
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
            if (const auto method = override_method(activity_type, name, signature)) {
                std::vector<Value> args{Value::reference(activity)};
                if (argument)
                    args.push_back(*argument);
                (void)runtime.invoke(*method, args);
                if (!called_super && name != "onWindowFocusChanged")
                    bad("SUPER_NOT_CALLED", "Activity callback did not call super." + std::string(name));
            }
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
        if (object != activity && object != application)
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
    std::u16string resource_text(std::uint32_t id) {
        try {
            return resources.text(id);
        } catch (const apk::InspectError &e) {
            runtime.raise("Landroid/content/res/Resources$NotFoundException;", unicode(e.what()));
        }
    }
};
ActivitySession::ActivitySession(dex::ManagedRuntime &runtime, std::string package,
                                 apk::ResourceTable resources)
    : impl_(std::make_unique<Impl>(runtime, std::move(package), std::move(resources))) {
    auto &p = *impl_;
    runtime.set_host_interface(this);
    p.attached = true;
    try {
        p.application = p.own(runtime.new_object("Landroid/app/Application;"));
        p.resource_object = p.own(runtime.new_object("Landroid/content/res/Resources;"));
        p.package_manager = p.own(runtime.new_object("Laether/android/PackageManager;"));
    } catch (...) {
        p.cleanup();
        throw;
    }
}
ActivitySession::~ActivitySession() { impl_->cleanup(); }
void ActivitySession::launch(std::string_view descriptor) {
    auto &p = *impl_;
    if (p.state != Lifecycle::empty || !p.attached)
        bad("LIFECYCLE_STATE", "Activity can only launch once per session");
    p.activity_type = descriptor;
    try {
        p.activity = p.own(p.runtime.new_object(descriptor));
        if (!p.runtime.assignable(p.activity, "Landroid/app/Activity;"))
            bad("ACTIVITY", "Launch class does not extend Activity");
        const std::array args{Value::reference(p.activity)};
        (void)p.runtime.invoke(p.runtime.lookup(descriptor, "<init>", "()V", false), args);
        p.deliver("onCreate", Lifecycle::created, "(Landroid/os/Bundle;)V", Value::reference(0));
        p.deliver("onStart", Lifecycle::started);
        p.deliver("onResume", Lifecycle::resumed);
    } catch (...) {
        p.state = Lifecycle::failed;
        throw;
    }
}
void ActivitySession::signal(WindowSignal signal) {
    auto &p = *impl_;
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
    if (!p.input_events.empty())
        bad("INPUT_REENTRANT", "Cannot close during input dispatch");
    p.cancel_input();
    try {
        if (p.state == Lifecycle::resumed)
            p.deliver("onPause", Lifecycle::paused);
        if (p.state == Lifecycle::paused || p.state == Lifecycle::started)
            p.deliver("onStop", Lifecycle::stopped);
        if (p.state == Lifecycle::stopped || p.state == Lifecycle::created)
            p.deliver("onDestroy", Lifecycle::destroyed);
    } catch (...) {
        p.cleanup();
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
const FrameworkMetrics &ActivitySession::metrics() const noexcept { return impl_->metrics; }
const apk::ResourceTable &ActivitySession::resources() const noexcept { return impl_->resources; }
std::optional<dex::HostClass> ActivitySession::class_info(std::string_view descriptor) const {
    return class_metadata(descriptor);
}
bool ActivitySession::method_is_static(const dex::DexImage &image, dex::Index method) const {
    (void)resolve(image, method);
    return false;
}
Value ActivitySession::invoke(dex::ManagedRuntime &runtime, dex::Index index, std::span<const Value> args) {
    auto &p = *impl_;
    if (&runtime != &p.runtime || !p.attached)
        bad("STATE", "Framework call belongs to another or closed runtime");
    const auto &api = resolve(runtime.image(), index);
    ++p.metrics.api_calls;
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
            p.called_super = true;
            return Value::nothing();
        }
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
        if (name == "getPackageName")
            return Value::reference(runtime.new_string(unicode(p.package)));
        if (name == "getApplicationContext")
            return Value::reference(p.application);
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
        return Value::reference(
            runtime.new_string(p.resource_text(static_cast<std::uint32_t>(args[1].bits))));
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
