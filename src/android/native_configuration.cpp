#include "native_configuration.hpp"
#include "aether/android/profile.hpp"
#include <array>
#include <limits>
#include <stdexcept>
#include <thread>

namespace aether::android {
namespace {
using a64::Fault;
struct Failure { Fault fault; std::string_view reason; };
[[noreturn]] void fail(Fault fault, std::string_view reason) { throw Failure{fault, reason}; }
struct Value {
    std::uint32_t orientation = 0, density = 0, width = 0, height = 0, smallest = 0, sdk = 0;
};
Value snapshot(DisplayConfiguration display) {
    if (!display.valid())
        throw std::invalid_argument("AETHER_ANDROID_CONFIGURATION: actual valid display facts are required");
    return {display.orientation(), display.density_dpi, display.screen_width_dp,
            display.screen_height_dp, display.smallest_screen_width_dp, compatibility_sdk};
}
std::uint32_t difference(const Value &left, const Value &right) noexcept {
    std::uint32_t result = 0;
    if (left.orientation != right.orientation) result |= 0x0080;
    if (left.density != right.density) result |= 0x0100;
    if (left.width != right.width || left.height != right.height) result |= 0x0200;
    if (left.sdk != right.sdk) result |= 0x0400;
    if (left.smallest != right.smallest) result |= 0x2000;
    return result;
}
} // namespace

struct NativeConfiguration::Impl {
    struct Slot { std::uint64_t id = 0; Value value; };
    a64::GuestMemory &memory;
    ManagerValidator validate_manager;
    Value source;
    std::array<Slot, 64> slots{};
    std::uint64_t next = 0xac0f00000001ULL;
    const std::thread::id owner = std::this_thread::get_id();
    bool closed = false;
    std::string_view error;
    Impl(a64::GuestMemory &space, DisplayConfiguration display, ManagerValidator validate)
        : memory(space), validate_manager(std::move(validate)), source(snapshot(display)) {
        if (!validate_manager)
            throw std::invalid_argument("AETHER_ANDROID_CONFIGURATION: owned manager validation is required");
    }
    void live() const {
        if (owner != std::this_thread::get_id() || closed)
            fail(Fault::invalid_call, "native configuration belongs to a live owning thread");
    }
    Slot &slot(std::uint64_t id) {
        if (id) for (auto &entry : slots) if (entry.id == id) return entry;
        fail(Fault::invalid_call, "native configuration is stale or foreign");
    }
};

NativeConfiguration::NativeConfiguration(a64::GuestMemory &memory, DisplayConfiguration display,
                                           ManagerValidator validate)
    : impl_(std::make_unique<Impl>(memory, display, std::move(validate))) {}
NativeConfiguration::~NativeConfiguration() = default;
void NativeConfiguration::update(DisplayConfiguration display) {
    auto &p = *impl_;
    p.live();
    p.source = snapshot(display);
}
Fault NativeConfiguration::invoke(std::string_view name, std::array<std::uint64_t, 31> &r) noexcept {
    auto &p = *impl_;
    if (p.owner != std::this_thread::get_id()) return Fault::invalid_call;
    p.error = {};
    try {
        p.live();
        if (name == "AConfiguration_new") {
            for (auto &entry : p.slots) if (!entry.id) {
                if (p.next == (std::numeric_limits<std::uint64_t>::max)()) { r[0] = 0; return Fault::none; }
                entry = {p.next++, {}}; // The NDK constructor leaves all values unset.
                r[0] = entry.id;
                return Fault::none;
            }
            r[0] = 0;
            return Fault::none;
        }
        if (name == "AConfiguration_delete") {
            if (r[0]) p.slot(r[0]) = {};
            return Fault::none;
        }
        auto &out = p.slot(r[0]).value;
        if (name == "AConfiguration_fromAssetManager") {
            if (!p.validate_manager(r[1]))
                fail(Fault::invalid_call, "native configuration requires this app's published AssetManager");
            out = p.source;
            return Fault::none;
        }
        if (name == "AConfiguration_copy") {
            const auto copy = p.slot(r[1]).value;
            out = copy;
            return Fault::none;
        }
        if (name == "AConfiguration_diff") {
            r[0] = difference(out, p.slot(r[1]).value);
            return Fault::none;
        }
        if (name == "AConfiguration_getLanguage" || name == "AConfiguration_getCountry") {
            // Locale has not been configured. NDK language/country output is
            // exactly two bytes, with no additional terminator.
            const std::array<std::uint8_t, 2> unset{};
            if (!p.memory.accessible(r[1], unset.size(), a64::Permission::write) || !p.memory.write(r[1], unset))
                fail(Fault::write, "native configuration locale output is not writable");
            return Fault::none;
        }
        if (name == "AConfiguration_getOrientation") r[0] = out.orientation;
        else if (name == "AConfiguration_getDensity") r[0] = out.density;
        else if (name == "AConfiguration_getScreenWidthDp") r[0] = out.width;
        else if (name == "AConfiguration_getScreenHeightDp") r[0] = out.height;
        else if (name == "AConfiguration_getSmallestScreenWidthDp") r[0] = out.smallest;
        else if (name == "AConfiguration_getSdkVersion") r[0] = out.sdk;
        else {
            // These properties are genuinely unspecified by Aether's display
            // source. Zero is the NDK ANY/unset value, not a fabricated device.
            constexpr std::array unspecified{
                "AConfiguration_getMcc", "AConfiguration_getMnc", "AConfiguration_getTouchscreen",
                "AConfiguration_getKeyboard", "AConfiguration_getNavigation", "AConfiguration_getKeysHidden",
                "AConfiguration_getNavHidden", "AConfiguration_getScreenSize", "AConfiguration_getScreenLong",
                "AConfiguration_getScreenRound", "AConfiguration_getUiModeType", "AConfiguration_getUiModeNight",
                "AConfiguration_getLayoutDirection", "AConfiguration_getGrammaticalGender"};
            bool known = false;
            for (const auto entry : unspecified) if (name == entry) { known = true; break; }
            if (!known) fail(Fault::unsupported_service, "native configuration operation is unsupported");
            r[0] = 0;
        }
        return Fault::none;
    } catch (const Failure &failure) {
        p.error = failure.reason;
        return failure.fault;
    } catch (...) {
        p.error = "native configuration validation failed";
        return Fault::unsupported_service;
    }
}
std::string_view NativeConfiguration::last_error() const noexcept {
    return impl_->owner == std::this_thread::get_id() ? impl_->error : "native configuration belongs to another thread";
}
void NativeConfiguration::shutdown() noexcept {
    auto &p = *impl_;
    if (p.owner != std::this_thread::get_id()) return;
    p.closed = true;
    p.slots = {};
    p.validate_manager = {};
}
} // namespace aether::android
