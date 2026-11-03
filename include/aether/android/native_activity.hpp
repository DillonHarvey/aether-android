#pragma once
#include "aether/android/display_configuration.hpp"
#include "aether/android/input.hpp"
#include "aether/android/native_window.hpp"
#include "aether/dex/runtime.hpp"
#include <array>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace aether::android {
enum class NativeActivityStage {
    create, start, resume, pause, stop, destroy, configuration_changed,
    low_memory, window_focus, save_state, window_created, window_resized,
    window_destroyed, input_queue_created, input_queue_destroyed
};
// Trusted synchronous lifecycle handoff. Object IDs name the session's actual
// rooted objects; copied bytes and logical paths convey no host authority.
struct NativeActivityRequest {
    NativeActivityStage stage = NativeActivityStage::create;
    dex::ObjectId activity = 0, asset_manager = 0;
    dex::ObjectId content_view = 0;
    DisplayConfiguration configuration;
    bool focused = false;
    bool saved_state_present = false; // Preserve a genuine nonnull zero-length byte array.
    std::vector<std::uint8_t> saved_state;
    std::string internal_data_path; // Create only, after actual private-root admission.
    std::uint64_t window_generation = 0;
    std::shared_ptr<NativeWindowProducer> window_producer;
    NativeWindowGeometry window_geometry;
};
enum class NativeActivityHostOperation { finish, set_window_format, set_window_flags, show_soft_input, hide_soft_input };
struct ActivityFinishRequest {
    std::uint64_t ordinal = 0;
    dex::ObjectId activity = 0;
    std::uint64_t window_generation = 0;
};
struct NativeActivityHostWorkCredit { std::uint64_t serial = 0; bool posted = false; };
struct NativeActivityHostWorkScope {
    bool active = true;
    std::size_t outstanding = 0;
    std::array<NativeActivityHostWorkCredit, 64> credits{};
};
struct NativeActivityHostWork {
    dex::ObjectId activity = 0, content = 0;
    std::uint64_t window_generation = 0, serial = 0;
    std::uint32_t credit_slot = 0;
    NativeActivityHostOperation operation = NativeActivityHostOperation::finish;
    std::int32_t arg1 = 0, arg2 = 0;
    std::weak_ptr<NativeActivityHostWorkScope> scope;
};
using NativeActivityHostWorkFactory =
    std::function<std::unique_ptr<dex::ManagedMainEntry>(const NativeActivityHostWork &)>;
struct NativeActivityResult {
    bool saved_state_present = false;
    std::vector<std::uint8_t> saved_state;
};
using NativeActivityObserver = std::function<NativeActivityResult(const NativeActivityRequest &)>;
struct NativeActivityPointerInput {
    dex::ObjectId activity = 0, root = 0;
    std::uint64_t window_generation = 0;
    std::uint64_t input_generation = 0;
    PointerInput sample;
    bool synthetic_cancel = false, down_time_known = false;
    std::uint64_t down_time_ms = 0;
};
enum class NativeKeyStage { pre_ime, post_ime, cancel };
struct NativeActivityKeyInput {
    dex::ObjectId activity = 0;
    KeyInput sample;
    std::uint64_t request = 0;
    NativeKeyStage stage = NativeKeyStage::pre_ime;
};
using NativeActivityKeyObserver = std::function<bool(const NativeActivityKeyInput &)>;
// Trusted synchronous value publication only; no guest execution or transport I/O.
using NativeKeyCompletionObserver = std::function<void(std::uint64_t, KeyDispatchOutcome)>;
// Queue retirement invalidates posted completions without retaining its owner.
// All access is confined to the actual app owner thread.
struct NativeActivityInputScope { bool active = true; };
struct NativeActivityInputCompletion {
    std::uint64_t queue = 0, event = 0;
    NativeActivityPointerInput input;
    std::optional<NativeActivityKeyInput> key;
    bool handled = false;
    std::weak_ptr<const NativeActivityInputScope> scope;
};
using NativeActivityInputCompletionFactory =
    std::function<std::unique_ptr<dex::ManagedMainEntry>(const NativeActivityInputCompletion &)>;
// True reports queue admission, not the application's later finishEvent result.
using NativeActivityPointerObserver = std::function<bool(const NativeActivityPointerInput &)>;
} // namespace aether::android
