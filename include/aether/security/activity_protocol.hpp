#pragma once
#include "aether/android/framework.hpp"
#include "aether/jni/bridge.hpp"
#include "aether/security/protocol.hpp"

namespace aether::security {
inline constexpr std::size_t activity_command_limit = 16 * 1024;
inline constexpr std::size_t activity_state_limit = 34 * 1024 * 1024;
enum class ActivityCommandKind : std::uint64_t { refresh, place, pointer, key, signal, close };
struct ActivityCommand {
    ActivityCommandKind kind = ActivityCommandKind::refresh;
    android::WindowSignal signal = android::WindowSignal::activate;
    android::PointerInput pointer;
    android::KeyInput key;
    std::vector<android::ViewPlacement> placements;
    std::vector<std::uint8_t> encode() const;
    static ActivityCommand decode(std::span<const std::uint8_t> bytes);
};
inline constexpr std::array<std::string_view, 8> activity_probes{
    "touches", "keys", "lastSource", "lastAction", "lastKey", "lastRepeat", "lastX", "lastY"};
struct ActivityState {
    std::string apk_hash, package, activity;
    android::Lifecycle lifecycle = android::Lifecycle::empty;
    dex::ObjectId content = 0;
    std::map<dex::ObjectId, android::ViewState> views;
    std::u16string trace;
    std::array<std::uint32_t, activity_probes.size()> probes{};
    android::FrameworkMetrics framework;
    dex::RuntimeMetrics managed;
    jni::Metrics jni;
    a64::Metrics cpu;
    bool handled = false;
    std::vector<std::uint8_t> encode() const;
    static ActivityState decode(std::span<const std::uint8_t> bytes);
    void validate() const;
};
// Ordered fragments retain the existing frame bound. Reassembly validates total size,
// identity and exact contiguous offsets before allocation/copying, with no pointer fields.
Frame activity_fragment(std::span<const std::uint8_t> bytes, std::size_t offset, Operation operation,
                        std::uint64_t sequence, std::uint64_t session);
void validate_activity_read_unavailable(const Frame &frame, std::uint64_t sequence, std::uint64_t session,
                                        bool reading, bool response_started);
class ActivityReassembly {
  public:
    ActivityReassembly(Operation operation, std::uint64_t sequence, std::uint64_t session, std::size_t limit);
    void accept(const Frame &frame);
    bool complete() const noexcept;
    std::vector<std::uint8_t> take();

  private:
    Operation operation_;
    std::uint64_t sequence_, session_;
    std::size_t limit_, total_ = 0;
    std::vector<std::uint8_t> bytes_;
};
} // namespace aether::security
