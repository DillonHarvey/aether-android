#pragma once
#include "aether/dex/runtime.hpp"
#include <atomic>

namespace aether::dex {
inline constexpr std::string_view atomic_reference_type = "Ljava/util/concurrent/atomic/AtomicReference;";
inline constexpr std::string_view atomic_boolean_type = "Ljava/util/concurrent/atomic/AtomicBoolean;";
inline constexpr std::string_view atomic_integer_type = "Ljava/util/concurrent/atomic/AtomicInteger;";
inline constexpr std::string_view atomic_long_type = "Ljava/util/concurrent/atomic/AtomicLong;";
inline constexpr std::string_view number_type = "Ljava/lang/Number;";
inline constexpr std::string_view atomic_field_updater_type =
    "Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;";
inline constexpr std::string_view field_updater_implementation_type =
    "Laether/internal/AtomicReferenceFieldUpdater;";
std::optional<HostClass> atomic_class(std::string_view descriptor);
bool atomic_long_method(std::string_view name, std::string_view signature) noexcept;
class AtomicLong {
  public:
    std::optional<Value> invoke(ManagedRuntime &, std::string_view name, std::string_view signature,
                               std::span<const Value> arguments);
  private:
    std::atomic<std::uint64_t> value_{0};
    bool initialized_ = false;
};
bool field_updater_method(std::string_view name, std::string_view signature);
struct ReferenceFieldUpdater {
    Index field = no_index, receiver_type = no_index;
    Value invoke(ManagedRuntime &runtime, Value &slot, std::string_view field_type, std::string_view name,
                 std::span<const Value> args) const;
};
class AtomicReference {
  public:
    Value reference() const noexcept { return Value::reference(value_.load()); }
    std::optional<Value> invoke(std::string_view name, std::string_view signature,
                                std::span<const Value> arguments);

  private:
    std::atomic<ObjectId> value_{0};
    bool initialized_ = false;
};
class AtomicInteger {
  public:
    explicit AtomicInteger(bool boolean = false) : boolean_(boolean) {}
    std::optional<Value> invoke(ManagedRuntime &runtime, std::string_view name, std::string_view signature,
                                std::span<const Value> arguments);

  private:
    std::optional<Value> invoke_boolean(ManagedRuntime &, std::string_view, std::string_view, std::span<const Value>);
    std::atomic<std::uint32_t> value_{0};
    bool initialized_ = false, boolean_ = false;
};
} // namespace aether::dex
