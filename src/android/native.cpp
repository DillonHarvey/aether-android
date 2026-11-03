#include "aether/android/native.hpp"
#include "native_assets.hpp"
#include "native_configuration.hpp"
#include "aether/android/native_window.hpp"
#include <thread>

namespace aether::android {
namespace {
struct Entry {
    std::string_view name, unsupported;
};
// Names checked against the installed NDK r30 looper, native_window(_jni),
// configuration and asset_manager(_jni) headers. Asset and Looper operations
// use authenticated app-owned bindings; other declarations refuse invocation.
#define NATIVE_DECLARATION(name) Entry{#name, "AETHER_ANDROID_NATIVE_UNSUPPORTED: " #name}
constexpr std::array entries{
    NATIVE_DECLARATION(ALooper_wake),
    NATIVE_DECLARATION(ANativeWindow_getWidth),
    NATIVE_DECLARATION(ANativeWindow_getHeight),
    NATIVE_DECLARATION(ALooper_pollOnce),
    NATIVE_DECLARATION(AAssetManager_fromJava),
    NATIVE_DECLARATION(ALooper_acquire),
    NATIVE_DECLARATION(ALooper_addFd),
    NATIVE_DECLARATION(ALooper_forThread),
    NATIVE_DECLARATION(ALooper_release),
    NATIVE_DECLARATION(ALooper_removeFd),
    NATIVE_DECLARATION(ANativeWindow_acquire),
    NATIVE_DECLARATION(ANativeWindow_fromSurface),
    NATIVE_DECLARATION(ANativeWindow_release),
    NATIVE_DECLARATION(AConfiguration_delete),
    NATIVE_DECLARATION(AConfiguration_fromAssetManager),
    NATIVE_DECLARATION(AConfiguration_getCountry),
    NATIVE_DECLARATION(AConfiguration_getLanguage),
    NATIVE_DECLARATION(AConfiguration_new),
    NATIVE_DECLARATION(ALooper_prepare),
    NATIVE_DECLARATION(AAssetManager_open),
    NATIVE_DECLARATION(AAsset_getLength64),
    NATIVE_DECLARATION(AAsset_close),
    NATIVE_DECLARATION(AAssetManager_openDir),
    NATIVE_DECLARATION(AAssetDir_close),
    NATIVE_DECLARATION(AAsset_read),
    NATIVE_DECLARATION(AAsset_getRemainingLength64),
    NATIVE_DECLARATION(AAsset_seek64),
    NATIVE_DECLARATION(AAsset_getBuffer),
    NATIVE_DECLARATION(AAsset_getLength),
    NATIVE_DECLARATION(AAsset_getRemainingLength),
    NATIVE_DECLARATION(AAsset_seek),
    NATIVE_DECLARATION(AAsset_isAllocated),
    NATIVE_DECLARATION(AAssetDir_getNextFileName),
    NATIVE_DECLARATION(AAssetDir_rewind),
    NATIVE_DECLARATION(ALooper_pollAll),
    NATIVE_DECLARATION(ANativeWindow_getFormat),
    NATIVE_DECLARATION(AConfiguration_getMcc),
    NATIVE_DECLARATION(AConfiguration_getMnc),
    NATIVE_DECLARATION(AConfiguration_getOrientation),
    NATIVE_DECLARATION(AConfiguration_getTouchscreen),
    NATIVE_DECLARATION(AConfiguration_getDensity),
    NATIVE_DECLARATION(AConfiguration_getKeyboard),
    NATIVE_DECLARATION(AConfiguration_getNavigation),
    NATIVE_DECLARATION(AConfiguration_getKeysHidden),
    NATIVE_DECLARATION(AConfiguration_getNavHidden),
    NATIVE_DECLARATION(AConfiguration_getSdkVersion),
    NATIVE_DECLARATION(AConfiguration_getScreenSize),
    NATIVE_DECLARATION(AConfiguration_getScreenLong),
    NATIVE_DECLARATION(AConfiguration_getUiModeType),
    NATIVE_DECLARATION(AConfiguration_getUiModeNight),
    NATIVE_DECLARATION(AConfiguration_getScreenWidthDp),
    NATIVE_DECLARATION(AConfiguration_getScreenHeightDp),
    NATIVE_DECLARATION(AConfiguration_getSmallestScreenWidthDp),
    NATIVE_DECLARATION(AConfiguration_getLayoutDirection),
    NATIVE_DECLARATION(AConfiguration_getScreenRound),
    NATIVE_DECLARATION(AConfiguration_getGrammaticalGender),
    NATIVE_DECLARATION(AConfiguration_copy),
    NATIVE_DECLARATION(AConfiguration_diff),
    NATIVE_DECLARATION(ANativeActivity_finish),
    NATIVE_DECLARATION(ANativeActivity_setWindowFormat),
    NATIVE_DECLARATION(ANativeActivity_setWindowFlags),
    NATIVE_DECLARATION(ANativeActivity_showSoftInput),
    NATIVE_DECLARATION(ANativeActivity_hideSoftInput),
    NATIVE_DECLARATION(AInputQueue_attachLooper),
    NATIVE_DECLARATION(AInputQueue_detachLooper),
    NATIVE_DECLARATION(AInputQueue_hasEvents),
    NATIVE_DECLARATION(AInputQueue_getEvent),
    NATIVE_DECLARATION(AInputQueue_preDispatchEvent),
    NATIVE_DECLARATION(AInputQueue_finishEvent),
    NATIVE_DECLARATION(AInputEvent_getType),
    NATIVE_DECLARATION(AInputEvent_getSource),
    NATIVE_DECLARATION(AMotionEvent_getAction),
    NATIVE_DECLARATION(AMotionEvent_getPointerCount),
    NATIVE_DECLARATION(AMotionEvent_getPointerId),
    NATIVE_DECLARATION(AMotionEvent_getHistorySize),
    NATIVE_DECLARATION(AMotionEvent_getDownTime),
    NATIVE_DECLARATION(AMotionEvent_getEventTime),
    NATIVE_DECLARATION(AMotionEvent_getX),
    NATIVE_DECLARATION(AMotionEvent_getY),
    NATIVE_DECLARATION(AMotionEvent_getAxisValue),
    NATIVE_DECLARATION(AInputEvent_getDeviceId),
    NATIVE_DECLARATION(AKeyEvent_getAction),
    NATIVE_DECLARATION(AKeyEvent_getFlags),
    NATIVE_DECLARATION(AKeyEvent_getKeyCode),
    NATIVE_DECLARATION(AKeyEvent_getScanCode),
    NATIVE_DECLARATION(AKeyEvent_getMetaState),
    NATIVE_DECLARATION(AKeyEvent_getRepeatCount),
    NATIVE_DECLARATION(AKeyEvent_getDownTime),
    NATIVE_DECLARATION(AKeyEvent_getEventTime),
    NATIVE_DECLARATION(AMotionEvent_getFlags),
    NATIVE_DECLARATION(AMotionEvent_getMetaState),
    NATIVE_DECLARATION(AMotionEvent_getButtonState),
    NATIVE_DECLARATION(AMotionEvent_getEdgeFlags),
    NATIVE_DECLARATION(AMotionEvent_getRawX),
    NATIVE_DECLARATION(AMotionEvent_getRawY),
    NATIVE_DECLARATION(AMotionEvent_getPressure),
    NATIVE_DECLARATION(AMotionEvent_getSize),
    NATIVE_DECLARATION(AMotionEvent_getTouchMajor),
    NATIVE_DECLARATION(AMotionEvent_getTouchMinor),
    NATIVE_DECLARATION(AMotionEvent_getToolMajor),
    NATIVE_DECLARATION(AMotionEvent_getToolMinor),
    NATIVE_DECLARATION(AMotionEvent_getOrientation),
    NATIVE_DECLARATION(AMotionEvent_getXPrecision),
    NATIVE_DECLARATION(AMotionEvent_getYPrecision),
    NATIVE_DECLARATION(AMotionEvent_getToolType),
    NATIVE_DECLARATION(AMotionEvent_getHistoricalAxisValue),
    NATIVE_DECLARATION(AMotionEvent_getHistoricalEventTime),
    NATIVE_DECLARATION(AMotionEvent_getHistoricalX),
    NATIVE_DECLARATION(AMotionEvent_getHistoricalY)};
#undef NATIVE_DECLARATION
static_assert(entries.size() == 109 && entries.size() * 8 <= a64::GuestMemory::page_size);
static_assert(NativePlatformServices::first_service + entries.size() <= 0x10000);

constexpr std::uint32_t svc(std::size_t index) {
    return 0xd4000001u | ((NativePlatformServices::first_service + static_cast<std::uint32_t>(index)) << 5);
}
std::array<std::uint8_t, 8> instructions(std::size_t index) {
    const std::array words{svc(index), std::uint32_t{0xd65f03c0u}};
    std::array<std::uint8_t, 8> result{};
    for (std::size_t word = 0; word < words.size(); ++word)
        for (std::size_t byte = 0; byte < 4; ++byte)
            result[word * 4 + byte] = static_cast<std::uint8_t>(words[word] >> (byte * 8));
    return result;
}
} // namespace

struct NativePlatformServices::Impl {
    a64::GuestMemory &memory;
    const a64::AppContext &app;
    const std::uint64_t app_id;
    const std::thread::id owner = std::this_thread::get_id();
    bool owned = false, closed = false;
    std::string_view error;
    std::unique_ptr<NativeAssets> assets;
    std::unique_ptr<NativeConfiguration> configuration;
    std::shared_ptr<NativeWindows> windows;
    LooperService looper;
    std::function<std::string_view()> looper_rejection;
    LooperService input_queue;
    std::function<std::string_view()> input_rejection;
    LooperService activity_host_ops;
    std::function<std::string_view()> activity_host_rejection;
    Impl(a64::GuestMemory &space, const a64::AppContext &context)
        : memory(space), app(context), app_id(context.instance_id) {}
    ~Impl() {
        if (windows) {
            windows->clear_java_resolver();
            try { windows->shutdown(); } catch (...) { }
        }
        if (owned) {
            try { memory.unmap(trampoline_base); } catch (...) { }
        }
    }
    bool live() const noexcept {
        return owner == std::this_thread::get_id() && !closed && owned && app_id &&
            app.instance_id == app_id && app.process_state && !app.process_state->exit_status();
    }
};

NativePlatformServices::NativePlatformServices(a64::GuestMemory &memory, const a64::AppContext &app)
    : impl_(std::make_unique<Impl>(memory, app)) {
    if (!app.instance_id || !app.process_state)
        throw a64::GuestError("AETHER_ANDROID_NATIVE_IDENTITY", "Native declarations require an owned live app");
    memory.map(trampoline_base, a64::GuestMemory::page_size, a64::read_write);
    impl_->owned = true;
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto bytes = instructions(index);
        if (!memory.write(trampoline_base + index * 8, bytes))
            throw a64::GuestError("AETHER_ANDROID_NATIVE_MEMORY", "Cannot write native declaration trampolines");
    }
    memory.protect(trampoline_base, a64::read_execute);
}
NativePlatformServices::~NativePlatformServices() = default;
void NativePlatformServices::bind_windows(std::shared_ptr<NativeWindows> windows) {
    auto &p = *impl_;
    if (!p.live() || p.windows || !windows || !windows->owned_by_current_thread())
        throw a64::GuestError("AETHER_ANDROID_WINDOW_BINDING", "Windows require a live unbound native owner");
    p.windows = std::move(windows);
}
void NativePlatformServices::bind_looper(LooperService service, std::function<std::string_view()> rejection) {
    auto &p = *impl_;
    if (!p.live() || p.looper || !service || !rejection)
        throw a64::GuestError("AETHER_ANDROID_LOOPER_BINDING", "Looper requires a live unbound native owner");
    p.looper = std::move(service);
    p.looper_rejection = std::move(rejection);
}
void NativePlatformServices::bind_input_queue(LooperService service, std::function<std::string_view()> rejection) {
    auto &p=*impl_;
    if(!p.live() || p.input_queue || !service || !rejection)
        throw a64::GuestError("AETHER_ANDROID_INPUT_BINDING", "Input queues require a live unbound native owner");
    p.input_queue=std::move(service);p.input_rejection=std::move(rejection);
}
void NativePlatformServices::bind_activity_host_ops(LooperService service, std::function<std::string_view()> rejection) {
    auto &p = *impl_;
    if (!p.live() || p.activity_host_ops || !service || !rejection)
        throw a64::GuestError("AETHER_ANDROID_ACTIVITY_BINDING", "Activity work requires a live unbound native owner");
    p.activity_host_ops = std::move(service);
    p.activity_host_rejection = std::move(rejection);
}
void NativePlatformServices::bind_assets(const apk::PackageView &package,
                                        std::function<bool(a64::Address, std::uint64_t)> validate_java) {
    auto &p = *impl_;
    if (!p.live() || p.assets || !validate_java)
        throw a64::GuestError("AETHER_ANDROID_ASSET_BINDING", "Asset source requires a live unbound native owner");
    p.assets = std::make_unique<NativeAssets>(p.memory, package, std::move(validate_java));
}
void NativePlatformServices::bind_assets(const apk::PackageView &package, NativeAssetManagerAccess access) {
    auto &p = *impl_;
    if (!p.live() || p.assets || !access.from_java || !access.owns)
        throw a64::GuestError("AETHER_ANDROID_ASSET_BINDING", "Asset identity requires a live unbound owner and complete callbacks");
    p.assets = std::make_unique<NativeAssets>(p.memory, package, std::move(access));
}
void NativePlatformServices::bind_configuration(DisplayConfiguration configuration) {
    auto &p = *impl_;
    if (!p.live() || p.configuration || !p.assets)
        throw a64::GuestError("AETHER_ANDROID_CONFIGURATION_BINDING", "Configuration requires the bound app asset source");
    p.configuration = std::make_unique<NativeConfiguration>(p.memory, configuration,
        [&p](std::uint64_t manager) { return p.assets && p.assets->owns_manager(manager); });
}
std::uint64_t NativePlatformServices::publish_asset_manager(a64::Address environment, std::uint64_t java_manager) {
    auto &p = *impl_;
    if (!p.live() || !p.assets)
        throw a64::GuestError("AETHER_ANDROID_ASSET_BINDING", "Native lifecycle requires this live app's bound asset source");
    return p.assets->publish_manager(environment, java_manager);
}
void NativePlatformServices::update_configuration(DisplayConfiguration configuration) {
    auto &p = *impl_;
    if (!p.live() || !p.configuration)
        throw a64::GuestError("AETHER_ANDROID_CONFIGURATION_BINDING", "Configuration source is not bound to this live app");
    p.configuration->update(configuration);
}
bool NativePlatformServices::handles_service(std::uint32_t service) noexcept {
    return service >= first_service && service - first_service < entries.size();
}
bool NativePlatformServices::has_library(std::string_view library) const noexcept {
    return impl_->live() && (library == "libandroid.so" || library == "libOpenSLES.so");
}
std::optional<elf::GuestSymbol> NativePlatformServices::resolve(std::string_view library,
                                                               std::string_view name,
                                                               std::string_view version) const {
    // Only observed unversioned declarations are admitted. OpenSLES dependency
    // identity does not provide any function or SL_IID data declaration.
    if (!impl_->live() || library != "libandroid.so" || !version.empty()) return std::nullopt;
    for (std::size_t index = 0; index < entries.size(); ++index)
        if (entries[index].name == name)
            return elf::GuestSymbol{std::string(name), std::string(library), {},
                                     trampoline_base + index * 8, 8, 2};
    return std::nullopt;
}
a64::Fault NativePlatformServices::invoke(std::uint32_t service, a64::Address instruction,
                                          std::array<std::uint64_t, 31> &registers) noexcept {
    a64::ServiceState state;
    state.registers = registers;
    const auto fault = invoke_service(service, instruction, state, false);
    registers = state.registers;
    return fault;
}
a64::Fault NativePlatformServices::invoke_frame(std::uint32_t service, a64::Address instruction,
                                               a64::ServiceState &state) noexcept {
    return invoke_service(service, instruction, state, true);
}
a64::Fault NativePlatformServices::invoke_service(std::uint32_t service, a64::Address instruction,
                                                 a64::ServiceState &state, bool full_frame) noexcept {
    auto &registers = state.registers;
    auto &p = *impl_;
    if (p.owner != std::this_thread::get_id()) return a64::Fault::invalid_call;
    if (!p.app.process_state || !p.app_id || p.app.instance_id != p.app_id) {
        p.error = "AETHER_ANDROID_NATIVE_IDENTITY: Native declaration belongs to another app";
        return a64::Fault::invalid_call;
    }
    if (p.app.process_state->exit_status()) return a64::Fault::process_exit;
    if (!p.live() || !handles_service(service) || instruction != trampoline_base + (service - first_service) * 8) {
        p.error = "AETHER_ANDROID_NATIVE_CALLSITE: Native declaration trap is not live or registered";
        return a64::Fault::invalid_call;
    }
    const auto page = p.memory.mapping(trampoline_base);
    std::array<std::uint8_t, 8> actual{};
    const auto index = service - first_service;
    if (!page || page->address != trampoline_base || page->size != a64::GuestMemory::page_size ||
        page->permissions != a64::read_execute || !p.memory.read(instruction, actual, a64::Permission::execute) ||
        actual != instructions(index)) {
        p.error = "AETHER_ANDROID_NATIVE_CALLSITE: Native declaration trampoline mapping changed";
        return a64::Fault::invalid_call;
    }
    if (p.looper && entries[index].name.starts_with("ALooper_")) {
        try {
            const auto fault = p.looper(entries[index].name, state, full_frame);
            p.error = fault == a64::Fault::none ? std::string_view{} : p.looper_rejection();
            return fault;
        } catch (...) {
            p.error = "AETHER_ANDROID_LOOPER_SERVICE: Owned Looper dispatch failed";
            return a64::Fault::windows_service;
        }
    }
    if(p.input_queue && (entries[index].name.starts_with("AInputQueue_") || entries[index].name.starts_with("AInputEvent_") ||
                         entries[index].name.starts_with("AMotionEvent_") || entries[index].name.starts_with("AKeyEvent_"))){
        try {
            const auto fault=p.input_queue(entries[index].name,state,full_frame);
            p.error=fault==a64::Fault::none?std::string_view{}:p.input_rejection();
            return fault;
        } catch(...) {p.error="AETHER_ANDROID_INPUT_SERVICE: Owned queue dispatch failed";return a64::Fault::unsupported_service;}
    }
    if (p.activity_host_ops && entries[index].name.starts_with("ANativeActivity_")) {
        try {
            const auto fault = p.activity_host_ops(entries[index].name, state, full_frame);
            p.error = fault == a64::Fault::none ? std::string_view{} : p.activity_host_rejection();
            return fault;
        } catch (...) {
            p.error = "AETHER_ANDROID_ACTIVITY_SERVICE: Owned Activity work admission failed";
            return a64::Fault::unsupported_service;
        }
    }
    if (p.assets && (entries[index].name.starts_with("AAsset"))) {
        const auto fault = p.assets->invoke(entries[index].name, registers);
        p.error = p.assets->last_error();
        return fault;
    }
    if (p.configuration && entries[index].name.starts_with("AConfiguration_")) {
        const auto fault = p.configuration->invoke(entries[index].name, registers);
        p.error = p.configuration->last_error();
        return fault;
    }
    if (p.windows && entries[index].name.starts_with("ANativeWindow_")) {
        const auto fault = p.windows->invoke(entries[index].name, registers);
        p.error = p.windows->last_error();
        return fault;
    }
    p.error = entries[index].unsupported;
    return a64::Fault::unsupported_service;
}
std::string_view NativePlatformServices::last_error() const noexcept {
    if (impl_->owner != std::this_thread::get_id())
        return "AETHER_ANDROID_NATIVE_OWNER: Native declarations belong to another owner thread";
    return impl_->error;
}
void NativePlatformServices::shutdown() {
    auto &p = *impl_;
    if (p.owner != std::this_thread::get_id())
        throw a64::GuestError("AETHER_ANDROID_NATIVE_OWNER", "Native declaration shutdown belongs to another thread");
    p.closed = true;
    p.activity_host_ops = {};
    p.activity_host_rejection = {};
    if (p.windows) p.windows->clear_java_resolver();
    p.looper = {};
    p.looper_rejection = {};
    p.input_queue={};p.input_rejection={};
    if (p.configuration) p.configuration->shutdown();
    if (p.assets) p.assets->shutdown();
    if (p.windows) p.windows->shutdown();
    if (p.owned) {
        p.memory.unmap(trampoline_base);
        p.owned = false;
    }
}
} // namespace aether::android
