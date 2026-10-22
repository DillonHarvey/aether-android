#pragma once
#include "aether/dex/runtime.hpp"

namespace aether::dex {
inline constexpr std::string_view enum_type = "Ljava/lang/Enum;";
std::optional<HostClass> enum_class(std::string_view descriptor);
bool enum_instance_method(std::string_view name, std::string_view signature);
class ManagedEnum {
  public:
    Value reference() const noexcept { return Value::reference(name_); }
    std::uint32_t ordinal() const;
    std::optional<Value> invoke(ManagedRuntime &runtime, std::string_view name, std::string_view signature,
                                std::span<const Value> args);

  private:
    ObjectId name_ = 0;
    std::uint32_t ordinal_ = 0;
    bool initialized_ = false;
};
} // namespace aether::dex
